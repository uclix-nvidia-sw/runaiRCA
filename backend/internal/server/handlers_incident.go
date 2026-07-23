package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type rcaCorrectionRequest struct {
	RootCauseFamily string   `json:"root_cause_family"`
	Summary         string   `json:"summary"`
	Actions         []string `json:"actions"`
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
			continue
		}
		processed = append(processed, id)
		if req.Action == "delete_permanently" {
			s.hub.Broadcast(incidentUpdatedEvent(id, "delete_permanent", "", nil, nil))
			continue
		}
		s.hub.Broadcast(incidentUpdatedEvent(id, req.Action, incident.Status, incident.ArchivedAt, incident.DeletedAt))
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "processed_ids": processed})
}

func (s *Server) handleEmptyIncidentTrash(w http.ResponseWriter, _ *http.Request) {
	ids := s.store.EmptyTrash()
	for _, id := range ids {
		s.hub.Broadcast(incidentUpdatedEvent(id, "delete_permanent", "", nil, nil))
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "deleted_count": len(ids)})
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

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodDelete {
		id := parts[0]
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
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "unknown incident action")
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "rca-correction":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
		req.Summary = strings.TrimSpace(req.Summary)
		if req.Summary == "" {
			writeError(w, http.StatusBadRequest, "summary is required")
			return
		}
		catalog, err := s.fetchRootCauseFamilyCatalog(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "root-cause family catalog unavailable")
			return
		}
		if !mapContains(catalog.Families, req.RootCauseFamily) {
			writeError(w, http.StatusBadRequest, "root_cause_family must be selected from the root-cause family catalog")
			return
		}
		actions := compactCorrectionActions(req.Actions)
		detailMarkdown := renderOperatorCorrectionDetail(req.RootCauseFamily, req.Summary, actions, detail.AnalysisRunID)
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
		writeJSON(w, http.StatusCreated, envelope(run))
	case "rca-pin":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
	case "reverify":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
	case "analyze":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
	case "cancel":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
	case "resolve":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
		writeJSON(w, http.StatusOK, map[string]any{"status": status, "user_approved_at": userApprovedAt})
	case "archive", "unarchive", "restore":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
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
	case "feedback":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
		s.handleFeedback(w, r, "incident", id)
	case "vote":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
		s.handleFeedback(w, r, "incident", id)
	case "comments":
		s.handleCommentAction(w, r, "incident", id, parts)
	default:
		writeError(w, http.StatusNotFound, "unknown incident action")
	}
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

func renderOperatorCorrectionDetail(family, summary string, actions []string, baseRunID string) string {
	lines := []string{
		"## 1. 문제",
		"",
		summary,
		"",
		"## 2. 원인",
		"",
		fmt.Sprintf("- Root cause family: `%s`", family),
		fmt.Sprintf("- Operator conclusion: %s", summary),
		"",
		"## 3. 권장 조치",
		"",
	}
	if len(actions) == 0 {
		lines = append(lines, "- No recommended actions provided.")
	} else {
		for index, action := range actions {
			lines = append(lines, fmt.Sprintf("%d. %s", index+1, action))
		}
	}
	if baseRunID != "" {
		lines = append(lines, "", fmt.Sprintf("Base analysis run: `%s`", baseRunID))
	}
	return strings.Join(lines, "\n")
}
