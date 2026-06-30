package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"
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
	autoAlertIDs := map[string]struct{}{}
	autoAlertOrder := []string{}
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
		if status(alert.Status) != "resolved" {
			if _, queued := autoAlertIDs[record.AlertID]; !queued {
				autoAlertIDs[record.AlertID] = struct{}{}
				autoAlertOrder = append(autoAlertOrder, record.AlertID)
			}
		}
	}
	for _, alertID := range autoAlertOrder {
		if autoAnalyses >= maxAutoAnalyzeFanout {
			break
		}
		if !s.reserveAutoAnalysisSlot() {
			break
		}
		if _, ok := s.startAnalysisRun("alert", alertID, "auto", ""); ok {
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

func (s *Server) reserveAutoAnalysisSlot() bool {
	now := time.Now().UTC()
	cutoff := now.Add(-autoAnalyzeWindow)
	s.autoAnalyzeMu.Lock()
	defer s.autoAnalyzeMu.Unlock()
	kept := s.autoAnalyzeStarts[:0]
	for _, startedAt := range s.autoAnalyzeStarts {
		if startedAt.After(cutoff) {
			kept = append(kept, startedAt)
		}
	}
	s.autoAnalyzeStarts = kept
	if len(s.autoAnalyzeStarts) >= maxAutoAnalyzeFanout {
		return false
	}
	s.autoAnalyzeStarts = append(s.autoAnalyzeStarts, now)
	return true
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
