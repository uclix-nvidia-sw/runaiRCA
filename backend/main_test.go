package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAlertmanagerWebhookCreatesIncidentAndAlert(t *testing.T) {
	server := NewServer()
	body := AlertmanagerWebhook{
		GroupKey: "runai-test",
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIWorkloadPending",
					"severity":  "warning",
					"cluster":   "lab",
					"project":   "vision",
					"queue":     "gpu-a",
					"namespace": "runai-vision",
					"workload":  "trainer",
				},
				Annotations: map[string]string{"summary": "Workload pending"},
				Fingerprint: "fp-1",
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if len(server.store.ListIncidents()) != 1 {
		t.Fatalf("expected one incident")
	}
	if len(server.store.ListAlerts()) != 1 {
		t.Fatalf("expected one alert")
	}
}
