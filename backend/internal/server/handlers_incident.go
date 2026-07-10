package server

import (
	"net/http"
	"strings"
	"time"
)

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
