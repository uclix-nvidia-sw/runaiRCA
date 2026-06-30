package main

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
		if detail.IsAnalyzing {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status": "analysis_already_running",
			})
			return
		}
		if len(detail.Alerts) == 0 {
			writeError(w, http.StatusConflict, "incident has no alerts to analyze")
			return
		}
		if len(detail.Alerts) > maxManualAnalyzeFanout {
			if _, ok := s.startAnalysisRun("incident", id, "manual", ""); !ok {
				writeError(w, http.StatusNotFound, "analysis target not found")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":        "analysis_requested",
				"mode":          "incident",
				"analysis_runs": 1,
				"alert_count":   len(detail.Alerts),
			})
			return
		}
		started := 0
		for _, alert := range detail.Alerts {
			if _, ok := s.startAnalysisRun("alert", alert.AlertID, "manual", ""); ok {
				started++
			}
		}
		if started == 0 {
			writeError(w, http.StatusConflict, "incident has no analyzable alerts")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":        "analysis_requested",
			"mode":          "alerts",
			"analysis_runs": started,
			"alert_count":   len(detail.Alerts),
		})
	case "resolve":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown incident action")
			return
		}
		now := time.Now().UTC()
		nextStatus := "resolved"
		var resolvedAt *time.Time
		s.store.mu.Lock()
		incident := s.store.incidents[id]
		if incident == nil {
			s.store.mu.Unlock()
			writeError(w, http.StatusNotFound, "incident not found")
			return
		}
		if incident.Status == "resolved" {
			nextStatus = "firing"
			incident.Status = nextStatus
			incident.ResolvedAt = nil
		} else {
			incident.Status = nextStatus
			incident.ResolvedAt = &now
			resolvedAt = &now
		}
		s.store.persistIncidentLocked(incident)
		if memory := s.store.memories[id]; memory != nil {
			memory.Status = nextStatus
			s.store.persistMemoryLocked(memory)
		}
		s.store.mu.Unlock()
		s.hub.Broadcast(incidentResolvedEvent(id, nextStatus, resolvedAt))
		writeJSON(w, http.StatusOK, map[string]string{"status": nextStatus})
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
