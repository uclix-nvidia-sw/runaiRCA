package server

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// caseFold matches Python's str.casefold() (full Unicode folding), not
// strings.ToLower: "ß" folds to "ss". The agent mints novel family slugs with
// casefold, and the fingerprint is the dedup key across both paths — a
// ToLower/casefold split would mint two families for one mechanism.
var caseFold = cases.Fold()

type rcaCorrectionRequest struct {
	RootCauseFamily string   `json:"root_cause_family"`
	NewCause        string   `json:"new_cause"`
	Summary         string   `json:"summary"`
	Actions         []string `json:"actions"`
}

func novelFamilySlug(mechanism string) (string, string) {
	canonical := strings.Join(strings.Fields(caseFold.String(norm.NFKC.String(mechanism))), " ")
	var ascii strings.Builder
	for _, r := range norm.NFKD.String(canonical) {
		if r <= unicode.MaxASCII {
			ascii.WriteRune(r)
		}
	}
	slug := strings.Trim(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, ascii.String()), "_")
	if slug == "" {
		slug = "mechanism"
	}
	digest := sha256.Sum256([]byte(canonical))
	fingerprint := fmt.Sprintf("%x", digest[:])[:8]
	if len(slug) > 42 {
		slug = strings.TrimRight(slug[:42], "_")
	}
	family := "novel_" + slug + "_" + fingerprint
	if len(family) > 64 {
		family = family[:64]
	}
	return family, fingerprint
}

func compactCause(text string) string {
	return strings.Join(strings.Fields(caseFold.String(norm.NFKC.String(text))), " ")
}

func (s *Server) existingNovelFamily(mechanism, fingerprint string) string {
	needle := compactCause(mechanism)
	for _, candidate := range s.store.ListKnowledgeCandidates("") {
		if !strings.HasPrefix(candidate.RootCauseFamily, "novel_") {
			continue
		}
		if candidate.Family == "" {
			candidate.Family = candidate.RootCauseFamily
		}
		if strings.HasSuffix(candidate.Family, "_"+fingerprint) || compactCause(stringValue(candidate.Payload["mechanism"])) == needle {
			return candidate.Family
		}
	}
	for _, pkg := range s.store.ListKnowledgePackages(true) {
		if strings.HasPrefix(pkg.Family, "novel_") && (strings.HasSuffix(pkg.Family, "_"+fingerprint) || compactCause(stringValue(pkg.Payload["mechanism"])) == needle) {
			return pkg.Family
		}
	}
	return ""
}

type rcaPinRequest struct {
	Pinned *bool `json:"pinned"`
}

type incidentBulkActionRequest struct {
	IncidentIDs []string `json:"incident_ids"`
	Action      string   `json:"action"`
}

func (s *Server) handleIncidentBulkAction(w http.ResponseWriter, r *http.Request) {
	var req incidentBulkActionRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	req.Action = strings.TrimSpace(req.Action)
	seen := make(map[string]struct{}, len(req.IncidentIDs))
	ids := make([]string, 0, len(req.IncidentIDs))
	for _, id := range req.IncidentIDs {
		if id = strings.TrimSpace(id); id != "" {
			if _, exists := seen[id]; !exists {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "incident_ids is required")
		return
	}
	if req.Action != "archive" && req.Action != "unarchive" && req.Action != "restore" && req.Action != "trash" && req.Action != "delete_permanently" {
		writeError(w, http.StatusBadRequest, "invalid bulk incident action")
		return
	}

	processed := make([]string, 0, len(ids))
	failed := make([]string, 0)
	for _, id := range ids {
		var incident *Incident
		var ok bool
		switch req.Action {
		case "archive":
			incident, ok = s.store.ArchiveIncident(id, true)
		case "unarchive":
			incident, ok = s.store.ArchiveIncident(id, false)
		case "restore":
			incident, ok = s.store.RestoreIncident(id)
		case "trash":
			incident, ok = s.store.SoftDeleteIncident(id)
		case "delete_permanently":
			ok = s.store.HardDeleteIncident(id)
		}
		if !ok {
			// A permanent delete that failed to persist (Postgres error, see the
			// backend log) must not report success — the row is still there.
			failed = append(failed, id)
			continue
		}
		processed = append(processed, id)
		if req.Action == "delete_permanently" {
			s.hub.Broadcast(incidentUpdatedEvent(id, "delete_permanent", "", nil, nil))
			continue
		}
		s.hub.Broadcast(incidentUpdatedEvent(id, req.Action, incident.Status, incident.ArchivedAt, incident.DeletedAt))
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "processed_ids": processed, "failed_ids": failed})
}

func (s *Server) handleEmptyIncidentTrash(w http.ResponseWriter, _ *http.Request) {
	ids := s.store.EmptyTrash()
	for _, id := range ids {
		s.hub.Broadcast(incidentUpdatedEvent(id, "delete_permanent", "", nil, nil))
	}
	_, remaining := s.store.ListIncidentsPage(1, 0, incidentViewTrash)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "deleted_count": len(ids), "failed_count": remaining})
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if id == "" {
		writeError(w, http.StatusNotFound, "incident id required")
		return
	}
	if len(parts) == 2 && parts[1] == "feedback" {
		if _, ok := s.store.IncidentDetail(id); !ok {
			writeError(w, http.StatusNotFound, "incident not found")
			return
		}
		s.store.mu.RLock()
		summary := s.store.feedbackSummaryForActorLocked("incident", id, r.URL.Query().Get("feedback_author"))
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, envelope(summary))
		return
	}
	if len(parts) > 1 {
		writeError(w, http.StatusNotFound, "unknown incident action")
		return
	}
	if detail, ok := s.store.IncidentDetail(id); ok {
		// Prefer the set captured right after THIS incident's own analysis
		// completed (CompleteAnalysisRun / CompleteAnalysisRunWithSlackDelivery
		// schedule that refresh in the background once the run's own RCA text
		// exists to query with, and persist it on the run). It is stable and
		// already content-based, so it saves the embedding+pgvector round trip
		// below on every page view. Only live-recompute when no run has
		// produced one yet -- still analyzing, or the background refresh has
		// not landed.
		//
		// Rank the panel by the SAME retrieval the analysis cited. Embedding and
		// pgvector are network I/O that must never run under the store lock, so
		// the locked IncidentDetail build can only ever reach the sparse-identity
		// fallback -- which is how one report quoted "similarity 0.97" from the
		// dense index while the card beside it showed 78% from sparse, for the
		// same pair. Re-resolve out here, where dense can be tried first; it
		// enforces the same approved/not-deleted/not-self gates as the fallback,
		// and returns the fallback verbatim when pgvector is unavailable.
		if postAnalysis, ok := s.store.PostAnalysisSimilarIncidentsForIncident(id); ok {
			detail.SimilarIncidents = postAnalysis
		} else if len(detail.Alerts) > 0 {
			detail.SimilarIncidents = s.store.SimilarIncidentsForAlert(
				alertFromRecord(detail.Alerts[0]), id, similarIncidentLimit,
			)
		}
		if actor := r.URL.Query().Get("feedback_author"); actor != "" {
			s.store.mu.RLock()
			detail.Feedback = s.store.feedbackSummaryForActorLocked("incident", id, actor)
			for i := range detail.Alerts {
				detail.Alerts[i].Feedback = s.store.feedbackSummaryForActorLocked("alert", detail.Alerts[i].AlertID, actor)
			}
			s.store.mu.RUnlock()
		}
		writeJSON(w, http.StatusOK, envelope(detail))
		return
	}
	writeError(w, http.StatusNotFound, "incident not found")
}

// Every incident action here is POST /api/v1/incidents/{id}/{action} with
// nothing after it, so the switch used to repeat that same guard nine times.
// "comments" is deliberately absent: it owns the rest of the path and its own
// methods, and is dispatched before this table.
var incidentActions = map[string]func(*Server, http.ResponseWriter, *http.Request, string){
	"rca-correction": (*Server).incidentRCACorrection,
	"rca-pin":        (*Server).incidentRCAPin,
	"reverify":       (*Server).incidentReverify,
	"analyze":        (*Server).incidentAnalyze,
	"cancel":         (*Server).incidentCancelAnalysis,
	"resolve":        (*Server).incidentResolve,
	"feedback":       (*Server).incidentFeedback,
	"vote":           (*Server).incidentFeedback,
	"archive": func(s *Server, w http.ResponseWriter, r *http.Request, id string) {
		s.incidentArchive(w, r, id, "archive")
	},
	"unarchive": func(s *Server, w http.ResponseWriter, r *http.Request, id string) {
		s.incidentArchive(w, r, id, "unarchive")
	},
	"restore": func(s *Server, w http.ResponseWriter, r *http.Request, id string) {
		s.incidentArchive(w, r, id, "restore")
	},
}

// DELETE /api/v1/incidents/{id}; ?permanent=true skips the trash.
func (s *Server) deleteIncident(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeError(w, http.StatusNotFound, "incident id required")
		return
	}
	permanent := strings.EqualFold(r.URL.Query().Get("permanent"), "true")
	if permanent {
		if !s.store.HardDeleteIncident(id) {
			writeError(w, http.StatusNotFound, "incident not found")
			return
		}
		s.hub.Broadcast(incidentUpdatedEvent(id, "delete_permanent", "", nil, nil))
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	incident, ok := s.store.SoftDeleteIncident(id)
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	s.hub.Broadcast(incidentUpdatedEvent(id, "delete", incident.Status, incident.ArchivedAt, incident.DeletedAt))
	writeJSON(w, http.StatusOK, envelope(incident))
	return
}

// The operator overrides the RCA: a new run authored by them, not the agent.
func (s *Server) incidentRCACorrection(w http.ResponseWriter, r *http.Request, id string) {
	detail, ok := s.store.IncidentDetail(id)
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	var req rcaCorrectionRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	req.RootCauseFamily = strings.TrimSpace(req.RootCauseFamily)
	req.NewCause = strings.TrimSpace(req.NewCause)
	req.Summary = strings.TrimSpace(req.Summary)
	if req.Summary == "" {
		writeError(w, http.StatusBadRequest, "summary is required")
		return
	}
	if req.NewCause != "" && req.RootCauseFamily != "" {
		writeError(w, http.StatusBadRequest, "new_cause and root_cause_family are mutually exclusive")
		return
	}
	if len([]rune(req.NewCause)) > 200 {
		writeError(w, http.StatusBadRequest, "new_cause must be 200 characters or fewer")
		return
	}
	catalog, err := s.fetchRootCauseFamilyCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "root-cause family catalog unavailable")
		return
	}
	reused := ""
	if req.NewCause != "" {
		family, fingerprint := novelFamilySlug(req.NewCause)
		for _, known := range catalog.Families {
			if compactCause(known) == compactCause(req.NewCause) {
				family = known
				reused = known
				break
			}
		}
		if reused == "" {
			if existing := s.existingNovelFamily(req.NewCause, fingerprint); existing != "" {
				family, reused = existing, existing
			}
		}
		req.RootCauseFamily = family
	}
	if !mapContains(catalog.Families, req.RootCauseFamily) && !strings.HasPrefix(req.RootCauseFamily, "novel_") {
		writeError(w, http.StatusBadRequest, "root_cause_family must be selected from the root-cause family catalog")
		return
	}
	actions := compactCorrectionActions(req.Actions)
	detailMarkdown := renderOperatorCorrectionDetail(req.RootCauseFamily, req.Summary, actions, detail.AnalysisRunID, s.language)
	alertID := ""
	if len(detail.Alerts) > 0 {
		alertID = detail.Alerts[0].AlertID
	}
	run, created := s.store.CreateOperatorRun(id, alertID, detail.AnalysisRunID, req.RootCauseFamily, req.Summary, detailMarkdown)
	if !created {
		writeError(w, http.StatusInternalServerError, "could not persist operator RCA correction")
		return
	}
	s.broadcastAnalysisRunCompleted(run, id, alertID)
	if reused != "" {
		run.Metadata["reused_family"] = reused
	}
	writeJSON(w, http.StatusCreated, envelope(run))
}

// Pin (or unpin) the latest operator correction as the incident's answer.
func (s *Server) incidentRCAPin(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := s.store.IncidentDetail(id); !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	var req rcaPinRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	if req.Pinned == nil {
		writeError(w, http.StatusBadRequest, "pinned is required")
		return
	}
	run, ok := s.store.SetLatestOperatorRunPinned(id, *req.Pinned)
	if !ok {
		writeError(w, http.StatusNotFound, "operator RCA correction not found")
		return
	}
	writeJSON(w, http.StatusOK, envelope(run))
}

// Re-run the agent with the pinned operator correction as leading hypothesis.
func (s *Server) incidentReverify(w http.ResponseWriter, r *http.Request, id string) {
	operatorRun, ok := s.store.PinnedOperatorRun(id)
	if !ok {
		writeError(w, http.StatusNotFound, "pinned operator RCA correction not found")
		return
	}
	prompt := fmt.Sprintf(
		"Re-verify the operator RCA correction. Treat %q as the leading hypothesis, collect supporting and refuting evidence, and do not force the conclusion. Operator summary: %s",
		operatorRun.RootCauseFamily,
		operatorRun.AnalysisSummary,
	)
	run, started := s.startAnalysisRun("incident", id, "reverify", prompt)
	if !started {
		if run != nil && run.Status == "analyzing" {
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "analysis_already_running"})
			return
		}
		writeError(w, http.StatusConflict, "incident has no analyzable alerts")
		return
	}
	writeJSON(w, http.StatusAccepted, envelope(run))
}

func (s *Server) incidentAnalyze(w http.ResponseWriter, r *http.Request, id string) {
	detail, ok := s.store.IncidentDetail(id)
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	if len(detail.Alerts) == 0 {
		writeError(w, http.StatusConflict, "incident has no alerts to analyze")
		return
	}
	// One incident-scoped run per click: the agent analyzes the representative
	// firing alert with full incident context, and Slack gets exactly one
	// thread reply. The old per-alert fanout made one click on a 3-alert
	// incident produce 3 runs (and would have produced 3 Slack replies).
	run, ok := s.startAnalysisRun("incident", id, "manual", "")
	if !ok {
		if run != nil && run.Status == "analyzing" {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status": "analysis_already_running",
			})
			return
		}
		writeError(w, http.StatusConflict, "incident has no analyzable alerts")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":        "analysis_requested",
		"mode":          "incident",
		"analysis_runs": 1,
		"alert_count":   len(detail.Alerts),
	})
}

func (s *Server) incidentCancelAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	detail, ok := s.store.IncidentDetail(id)
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	runID := strings.TrimSpace(detail.ActiveAnalysisRunID)
	if runID == "" {
		runID = strings.TrimSpace(detail.AnalysisRunID)
	}
	if !detail.IsAnalyzing || runID == "" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "not_analyzing"})
		return
	}
	// Stop the agent's in-flight pipeline. The existing analysis goroutine
	// drives the run to a terminal state (clears is_analyzing + emits the SSE
	// completion) when its now-cancelled agent call returns.
	s.cancelAgentRun(runID)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "cancel_requested", "run_id": runID})
}

// Toggle operator approval, which binds (or revokes) the CaseSnapshot.
func (s *Server) incidentResolve(w http.ResponseWriter, r *http.Request, id string) {
	now := time.Now().UTC()
	s.store.mu.Lock()
	incident := s.store.incidents[id]
	if incident == nil {
		s.store.mu.Unlock()
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	if incident.UserApprovedAt == nil {
		incident.UserApprovedAt = &now
		// The approval binds a CaseSnapshot to the exact completed analysis
		// hash. Re-analysis may update the run later, but it cannot rewrite
		// this approved historical record.
		if !s.store.approveCaseSnapshotLocked(incident, now) {
			incident.UserApprovedAt = nil
			s.store.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "could not persist approved RCA snapshot")
			return
		}
		s.store.upsertApprovedIncidentMemoriesLocked(incident)
	} else {
		if !s.store.revokeCaseSnapshotsLocked(incident.IncidentID, now) {
			s.store.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "could not revoke approved RCA snapshot")
			return
		}
		incident.UserApprovedAt = nil
	}
	status := incident.Status
	resolvedAt := incident.ResolvedAt
	userApprovedAt := incident.UserApprovedAt
	s.store.persistIncidentLocked(incident)
	s.store.invalidateRecurrenceStatsLocked()
	s.store.mu.Unlock()
	s.hub.Broadcast(incidentResolvedEvent(id, status, resolvedAt, userApprovedAt))
	if userApprovedAt != nil {
		// Approval may have minted a knowledge candidate whose actions are the
		// operator's verbatim, instance-specific text. Generalize them off the
		// request path; failures leave the originals for manual curation.
		go s.refineKnowledgeCandidateActions()
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "user_approved_at": userApprovedAt})
}

func (s *Server) incidentArchive(w http.ResponseWriter, r *http.Request, id string, action string) {
	var incident *Incident
	var ok bool
	switch action {
	case "archive":
		incident, ok = s.store.ArchiveIncident(id, true)
	case "unarchive":
		incident, ok = s.store.ArchiveIncident(id, false)
	case "restore":
		incident, ok = s.store.RestoreIncident(id)
	}
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	s.hub.Broadcast(incidentUpdatedEvent(id, action, incident.Status, incident.ArchivedAt, incident.DeletedAt))
	writeJSON(w, http.StatusOK, envelope(incident))
}

func (s *Server) incidentFeedback(w http.ResponseWriter, r *http.Request, id string) {
	s.handleFeedback(w, r, "incident", id)
}

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodDelete {
		s.deleteIncident(w, r, parts[0])
		return
	}
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "unknown incident action")
		return
	}
	id, action := parts[0], parts[1]
	if action == "comments" {
		s.handleCommentAction(w, r, "incident", id, parts)
		return
	}
	handle, ok := incidentActions[action]
	if !ok || len(parts) != 2 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "unknown incident action")
		return
	}
	handle(s, w, r, id)
}

func compactCorrectionActions(actions []string) []string {
	compact := make([]string, 0, len(actions))
	for _, action := range actions {
		if action = strings.TrimSpace(action); action != "" {
			compact = append(compact, action)
		}
	}
	return compact
}

// renderOperatorCorrectionDetail builds the analysis_detail markdown for a
// manually-entered RCA correction -- the backend's OWN report builder,
// separate from the agent's. It used to hardcode Korean section headings
// unconditionally while every field label ("Root cause family:", "Operator
// conclusion:", "No recommended actions provided.", "Base analysis run:") was
// hardcoded English, so an English deployment got Korean headings and every
// deployment got a mixed-language document. Match the agent's own heading
// text (agent/app/services/pipeline.py _HEADINGS) so a correction reads the
// same as an agent-produced report.
func renderOperatorCorrectionDetail(family, summary string, actions []string, baseRunID string, language string) string {
	problemHeading, causeHeading, actionsHeading := "## 1. Problem", "## 2. Root Cause", "## 3. Recommended Actions"
	familyLabel, conclusionLabel, noActionsLine, baseRunLabel := "Root cause family", "Operator conclusion", "- No recommended actions provided.", "Base analysis run"
	if language == "ko" {
		problemHeading, causeHeading, actionsHeading = "## 1. 문제 (Problem)", "## 2. 원인 (Root Cause)", "## 3. 권장 조치 (Recommended Actions)"
		familyLabel, conclusionLabel, noActionsLine, baseRunLabel =
			"원인 계열(family)", "운영자 결론", "- 권장 조치가 제공되지 않았습니다.", "기준 분석 실행"
	}
	lines := []string{
		problemHeading,
		"",
		summary,
		"",
		causeHeading,
		"",
		fmt.Sprintf("- %s: `%s`", familyLabel, family),
		fmt.Sprintf("- %s: %s", conclusionLabel, summary),
		"",
		actionsHeading,
		"",
	}
	if len(actions) == 0 {
		lines = append(lines, noActionsLine)
	} else {
		for index, action := range actions {
			lines = append(lines, fmt.Sprintf("%d. %s", index+1, action))
		}
	}
	if baseRunID != "" {
		lines = append(lines, "", fmt.Sprintf("%s: `%s`", baseRunLabel, baseRunID))
	}
	return strings.Join(lines, "\n")
}
