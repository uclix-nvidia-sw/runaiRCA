package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) handleAlertmanager(w http.ResponseWriter, r *http.Request) {
	var webhook AlertmanagerWebhook
	if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	accepted := 0
	ignored := 0
	for _, alert := range webhook.Alerts {
		if ignoredAlert(alert) {
			ignored++
			continue
		}
		incident, record := s.store.UpsertAlert(webhook, alert)
		accepted++
		s.hub.Broadcast(alertCreatedEvent(incident, record))
		s.startAnalysisRun("alert", record.AlertID, "auto", "")
	}
	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{"status": "accepted", "alerts": accepted, "accepted": accepted, "ignored": ignored},
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
