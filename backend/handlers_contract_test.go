package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncidentAndAlertDetailContracts(t *testing.T) {
	server := NewServer()
	priorIncident, priorAlert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "prior-contract"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai",
			"workload":  "trainer-old",
		},
		Annotations: map[string]string{"summary": "Prior workload pending"},
		Fingerprint: "fp-prior-contract",
	})
	server.store.ApplyAnalysis(priorAlert.AlertID, AgentAnalysisResponse{
		AnalysisSummary: "Prior queue saturation RCA.",
		AnalysisDetail:  "GPU quota was exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	_, ok, err := server.store.AddFeedback("incident", priorIncident.IncidentID, FeedbackRequest{
		Vote:   "up",
		Author: "operator",
	})
	if err != nil || !ok {
		t.Fatalf("seed feedback failed: ok=%t err=%v", ok, err)
	}

	incident, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "current-contract"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "critical",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai",
			"workload":  "trainer-new",
		},
		Annotations: map[string]string{"summary": "Current workload pending"},
		Fingerprint: "fp-current-contract",
	})
	server.store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		AnalysisSummary: "Current queue saturation RCA.",
		AnalysisDetail:  "GPU quota is currently exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok", "postgres": "ok"},
		MissingData:     []string{"loki.logs"},
		Warnings:        []string{"partial logs"},
		Artifacts:       []Artifact{{Agent: "runai", Source: "runai.workloads", Type: "api", Status: "ok", Confidence: "high"}},
	})

	incidentRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		incidentRec,
		httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+incident.IncidentID, nil),
	)
	if incidentRec.Code != http.StatusOK {
		t.Fatalf("expected incident detail 200, got %d: %s", incidentRec.Code, incidentRec.Body.String())
	}
	var incidentEnvelope struct {
		Data IncidentDetail `json:"data"`
	}
	if err := json.Unmarshal(incidentRec.Body.Bytes(), &incidentEnvelope); err != nil {
		t.Fatalf("decode incident detail: %v", err)
	}
	detail := incidentEnvelope.Data
	if detail.IncidentID != incident.IncidentID || len(detail.Alerts) != 1 {
		t.Fatalf("unexpected incident detail: %+v", detail)
	}
	if detail.Alerts[0].IncidentID != incident.IncidentID {
		t.Fatalf("embedded alert missing incident_id: %+v", detail.Alerts[0])
	}
	if detail.Capabilities["postgres"] != "ok" || len(detail.Artifacts) != 1 {
		t.Fatalf("incident analysis fields were not stable: %+v", detail)
	}
	if detail.Feedback.TargetType != "incident" || detail.Feedback.TargetID != incident.IncidentID {
		t.Fatalf("incident feedback contract missing target metadata: %+v", detail.Feedback)
	}
	if detail.Alerts[0].Feedback.TargetType != "alert" || detail.Alerts[0].Feedback.TargetID != alert.AlertID {
		t.Fatalf("alert feedback contract missing in incident detail: %+v", detail.Alerts[0].Feedback)
	}
	if detail.SimilarIncidents == nil || detail.Alerts[0].SimilarIncidents == nil {
		t.Fatalf("similar_incidents must be present as an array: %+v", detail)
	}

	alertRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		alertRec,
		httptest.NewRequest(http.MethodGet, "/api/v1/alerts/"+alert.AlertID, nil),
	)
	if alertRec.Code != http.StatusOK {
		t.Fatalf("expected alert detail 200, got %d: %s", alertRec.Code, alertRec.Body.String())
	}
	var alertEnvelope struct {
		Data AlertRecord `json:"data"`
	}
	if err := json.Unmarshal(alertRec.Body.Bytes(), &alertEnvelope); err != nil {
		t.Fatalf("decode alert detail: %v", err)
	}
	alertDetail := alertEnvelope.Data
	if alertDetail.AlertID != alert.AlertID || alertDetail.IncidentID != incident.IncidentID {
		t.Fatalf("alert detail missing related incident navigation fields: %+v", alertDetail)
	}
	if alertDetail.Labels["queue"] != "gpu-a" || alertDetail.AlarmTitle == "" {
		t.Fatalf("alert detail missing stable display fields: %+v", alertDetail)
	}
	if alertDetail.SimilarIncidents == nil || alertDetail.Feedback.TargetType != "alert" {
		t.Fatalf("alert detail missing feedback/similar contracts: %+v", alertDetail)
	}
}

func TestAlertFeedbackCommentAndSearchEndpoints(t *testing.T) {
	server := NewServer()
	_, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "alert-feedback"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-b"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-alert-feedback",
	})
	server.store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		AnalysisSummary: "Queue gpu-b was blocked.",
		AnalysisDetail:  "Scheduler capacity was unavailable.",
		AnalysisQuality: "medium",
	})

	voteBody, _ := json.Marshal(FeedbackRequest{Vote: "up", Author: "operator"})
	voteRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		voteRec,
		httptest.NewRequest(http.MethodPost, "/api/v1/alerts/"+alert.AlertID+"/feedback", bytes.NewReader(voteBody)),
	)
	if voteRec.Code != http.StatusOK {
		t.Fatalf("expected alert feedback 200, got %d: %s", voteRec.Code, voteRec.Body.String())
	}

	commentBody, _ := json.Marshal(CommentRequest{Body: "Attach scheduler logs.", Author: "operator"})
	commentRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		commentRec,
		httptest.NewRequest(http.MethodPost, "/api/v1/alerts/"+alert.AlertID+"/comments", bytes.NewReader(commentBody)),
	)
	if commentRec.Code != http.StatusOK {
		t.Fatalf("expected alert comment 200, got %d: %s", commentRec.Code, commentRec.Body.String())
	}
	var commentEnvelope struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(commentRec.Body.Bytes(), &commentEnvelope); err != nil {
		t.Fatalf("decode comment response: %v", err)
	}
	if commentEnvelope.Data.Positive != 1 || len(commentEnvelope.Data.Comments) != 1 {
		t.Fatalf("unexpected alert feedback summary: %+v", commentEnvelope.Data)
	}

	feedbackRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		feedbackRec,
		httptest.NewRequest(http.MethodGet, "/api/v1/alerts/"+alert.AlertID+"/feedback?feedback_author=operator", nil),
	)
	if feedbackRec.Code != http.StatusOK {
		t.Fatalf("expected alert feedback get 200, got %d: %s", feedbackRec.Code, feedbackRec.Body.String())
	}

	searchBody, _ := json.Marshal(EmbeddingSearchRequest{Query: "gpu-b scheduler capacity", Limit: 2})
	searchRec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		searchRec,
		httptest.NewRequest(http.MethodPost, "/api/v1/embeddings/search", bytes.NewReader(searchBody)),
	)
	if searchRec.Code != http.StatusOK {
		t.Fatalf("expected search 200, got %d: %s", searchRec.Code, searchRec.Body.String())
	}
}

func TestAPIErrorShapeFor400And404(t *testing.T) {
	server := NewServer()
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		code   int
	}{
		{
			name:   "bad search request",
			method: http.MethodPost,
			path:   "/api/v1/embeddings/search",
			body:   `{"query":""}`,
			code:   http.StatusBadRequest,
		},
		{
			name:   "missing incident",
			method: http.MethodGet,
			path:   "/api/v1/incidents/INC-missing",
			code:   http.StatusNotFound,
		},
		{
			name:   "missing route",
			method: http.MethodGet,
			path:   "/api/v1/nope",
			code:   http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body *strings.Reader
			if tt.body == "" {
				body = strings.NewReader("")
			} else {
				body = strings.NewReader(tt.body)
			}
			rec := httptest.NewRecorder()
			server.routes().ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, body))
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
			var payload map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload["error"] == "" || len(payload) != 1 {
				t.Fatalf("expected only {error: ...}, got %+v", payload)
			}
		})
	}
}

func TestSSEPayloadContract(t *testing.T) {
	event := analysisStartedEvent("ANL-1", "chat", "incident", "INC-1", "INC-1", "ALR-1")
	var buf bytes.Buffer
	writeSSE(&buf, event)
	output := buf.String()
	if !strings.Contains(output, "event: analysis.started\n") {
		t.Fatalf("missing event name: %q", output)
	}
	dataLine := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if dataLine == "" {
		t.Fatalf("missing SSE data line: %q", output)
	}
	var payload Event
	if err := json.Unmarshal([]byte(dataLine), &payload); err != nil {
		t.Fatalf("decode SSE data: %v", err)
	}
	if payload.Type != eventAnalysisStarted ||
		payload.Data["run_id"] != "ANL-1" ||
		payload.Data["target_type"] != "incident" ||
		payload.Data["incident_id"] != "INC-1" ||
		payload.Data["alert_id"] != "ALR-1" {
		t.Fatalf("unexpected SSE payload: %+v", payload)
	}
}

func TestWebhookBroadcastsAlertAndAnalysisEvents(t *testing.T) {
	server := NewServer()
	ch := server.hub.Subscribe()
	defer server.hub.Unsubscribe(ch)

	body := AlertmanagerWebhook{
		GroupKey: "webhook-events",
		Alerts: []Alert{
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
				Annotations: map[string]string{"summary": "Queue blocked"},
				Fingerprint: "fp-webhook-events",
			},
		},
	}
	payload, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(
		rec,
		httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)),
	)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected webhook 202, got %d: %s", rec.Code, rec.Body.String())
	}

	first := receiveEvent(t, ch)
	second := receiveEvent(t, ch)
	if first.Type != eventAlertCreated || second.Type != eventAnalysisStarted {
		t.Fatalf("unexpected event order: %+v then %+v", first, second)
	}
	if first.Data["incident_id"] == "" || first.Data["alert_id"] == "" {
		t.Fatalf("alert.created missing navigation IDs: %+v", first)
	}
	if second.Data["incident_id"] != first.Data["incident_id"] || second.Data["alert_id"] != first.Data["alert_id"] {
		t.Fatalf("analysis.started did not preserve target IDs: %+v then %+v", first, second)
	}
}

func receiveEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case event := <-ch:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return Event{}
	}
}
