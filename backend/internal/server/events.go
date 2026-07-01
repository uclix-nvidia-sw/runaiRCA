package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	eventConnected         = "connected"
	eventAlertCreated      = "alert.created"
	eventAnalysisStarted   = "analysis.started"
	eventAnalysisCompleted = "analysis.completed"
	eventFeedbackUpdated   = "feedback.updated"
	eventIncidentResolved  = "incident.resolved"
)

type Event struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type Hub struct {
	mu      sync.Mutex
	clients map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan Event]struct{})}
}

func (h *Hub) Subscribe() chan Event {
	ch := make(chan Event, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.clients, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *Hub) Broadcast(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
		}
	}
}

func alertCreatedEvent(incident *Incident, alert *AlertRecord) Event {
	data := map[string]any{
		"incident_id": "",
		"alert_id":    "",
	}
	if incident != nil {
		data["incident_id"] = incident.IncidentID
		data["incident_status"] = incident.Status
	}
	if alert != nil {
		data["alert_id"] = alert.AlertID
		data["incident_id"] = alert.IncidentID
		data["status"] = alert.Status
		data["severity"] = alert.Severity
		data["fired_at"] = alert.FiredAt
	}
	return Event{Type: eventAlertCreated, Data: data}
}

func analysisStartedEvent(runID, source, targetType, targetID, incidentID, alertID string) Event {
	return Event{Type: eventAnalysisStarted, Data: map[string]any{
		"run_id":      runID,
		"source":      first(source, "auto"),
		"status":      "analyzing",
		"target_type": targetType,
		"target_id":   targetID,
		"incident_id": incidentID,
		"alert_id":    alertID,
	}}
}

func analysisCompletedEvent(runID, source, status, targetType, targetID, incidentID, alertID string) Event {
	return Event{Type: eventAnalysisCompleted, Data: map[string]any{
		"run_id":      runID,
		"source":      first(source, "auto"),
		"status":      first(status, "complete"),
		"target_type": targetType,
		"target_id":   targetID,
		"incident_id": incidentID,
		"alert_id":    alertID,
	}}
}

func feedbackUpdatedEvent(summary FeedbackSummary, incidentID string, alertID string) Event {
	return Event{Type: eventFeedbackUpdated, Data: map[string]any{
		"target_type":   summary.TargetType,
		"target_id":     summary.TargetID,
		"incident_id":   first(incidentID, feedbackIncidentID(summary)),
		"alert_id":      first(alertID, feedbackAlertID(summary)),
		"positive":      summary.Positive,
		"negative":      summary.Negative,
		"comment_count": len(summary.Comments),
	}}
}

func incidentResolvedEvent(incidentID string, status string, resolvedAt *time.Time) Event {
	return Event{Type: eventIncidentResolved, Data: map[string]any{
		"incident_id": incidentID,
		"status":      status,
		"resolved_at": resolvedAt,
	}}
}

func feedbackIncidentID(summary FeedbackSummary) string {
	if summary.TargetType == "incident" {
		return summary.TargetID
	}
	for _, comment := range summary.Comments {
		if comment.IncidentID != "" {
			return comment.IncidentID
		}
	}
	return ""
}

func feedbackAlertID(summary FeedbackSummary) string {
	if summary.TargetType == "alert" {
		return summary.TargetID
	}
	for _, comment := range summary.Comments {
		if comment.AlertID != "" {
			return comment.AlertID
		}
	}
	return ""
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)
	writeSSE(w, Event{Type: eventConnected, Data: map[string]any{"status": "ok"}})
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			writeSSE(w, event)
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, event Event) {
	payload, _ := json.Marshal(event)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, payload)
}
