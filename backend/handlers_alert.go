package main

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) handleAlertmanager(w http.ResponseWriter, r *http.Request) {
	var webhook AlertmanagerWebhook
	if status, err := decodeJSONBody(w, r, &webhook, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	if len(webhook.Alerts) > maxWebhookAlerts {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("too many alerts in webhook (max %d)", maxWebhookAlerts))
		return
	}
	accepted := 0
	ignored := 0
	autoAnalyses := 0
	autoIncidentIDs := map[string]struct{}{}
	for _, alert := range webhook.Alerts {
		if ignoredAlert(alert) {
			ignored++
			continue
		}
		result := s.store.UpsertAlertResult(webhook, alert)
		incident, record := result.Incident, result.Alert
		accepted++
		if result.Changed {
			s.hub.Broadcast(alertCreatedEvent(incident, record))
		}
		if result.NewIncident {
			autoIncidentIDs[incident.IncidentID] = struct{}{}
		}
	}
	for incidentID := range autoIncidentIDs {
		if _, ok := s.startAnalysisRun("incident", incidentID, "auto", ""); ok {
			autoAnalyses++
		}
	}
	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"status":        "accepted",
			"alerts":        accepted,
			"accepted":      accepted,
			"ignored":       ignored,
			"auto_analyses": autoAnalyses,
		},
	)
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/alerts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if len(parts) == 2 && parts[1] == "feedback" {
		if _, ok := s.store.AlertDetail(id); !ok {
			writeError(w, http.StatusNotFound, "alert not found")
			return
		}
		s.store.mu.RLock()
		summary := s.store.feedbackSummaryForActorLocked("alert", id, r.URL.Query().Get("feedback_author"))
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, envelope(summary))
		return
	}
	if len(parts) > 1 {
		writeError(w, http.StatusNotFound, "unknown alert action")
		return
	}
	if alert, ok := s.store.AlertDetail(id); ok {
		if actor := r.URL.Query().Get("feedback_author"); actor != "" {
			s.store.mu.RLock()
			alert.Feedback = s.store.feedbackSummaryForActorLocked("alert", id, actor)
			s.store.mu.RUnlock()
		}
		writeJSON(w, http.StatusOK, envelope(alert))
		return
	}
	writeError(w, http.StatusNotFound, "alert not found")
}

func (s *Server) handleAlertAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/alerts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "unknown alert action")
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "feedback":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown alert action")
			return
		}
		s.handleFeedback(w, r, "alert", id)
	case "vote":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "unknown alert action")
			return
		}
		s.handleFeedback(w, r, "alert", id)
	case "comments":
		s.handleCommentAction(w, r, "alert", id, parts)
	default:
		writeError(w, http.StatusNotFound, "unknown alert action")
	}
}
