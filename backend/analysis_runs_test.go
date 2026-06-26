package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// analysisAgentStub spins up a fake agent /analyze endpoint with configurable
// behaviour so the failure matrix can be exercised deterministically.
func analysisAgentStub(t *testing.T, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	server := NewServer()
	agent := httptest.NewServer(handler)
	t.Cleanup(agent.Close)
	server.agentURL = agent.URL
	return server, agent
}

func seedAlert(t *testing.T, server *Server, fingerprint string) (Incident, AlertRecord) {
	t.Helper()
	incident, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: fingerprint}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: fingerprint,
	})
	return *incident, *record
}

func waitForRunStatus(t *testing.T, server *Server, source string, status string) AnalysisRun {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, run := range server.store.ListAnalysisRuns() {
			if run.Source == source && run.Status == status {
				return run
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run source=%q status=%q not reached: %+v", source, status, server.store.ListAnalysisRuns())
	return AnalysisRun{}
}

func waitForCompletedEvent(t *testing.T, ch <-chan Event, wantStatus string) Event {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-ch:
			if event.Type == eventAnalysisCompleted && event.Data["status"] == wantStatus {
				return event
			}
		case <-deadline:
			t.Fatalf("did not observe analysis.completed event with status %q", wantStatus)
			return Event{}
		}
	}
}

func TestAnalysisRunSuccessAppliesRCA(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Queue gpu-a saturated.",
			AnalysisDetail:  "## Root Cause\n\nQuota exhausted.",
			AnalysisQuality: "high",
			Capabilities:    map[string]string{"runai": "ok"},
		})
	})
	_, record := seedAlert(t, server, "fp-success")

	run, ok := server.startAnalysisRun("alert", record.AlertID, "manual", "")
	if !ok {
		t.Fatalf("expected run to start")
	}
	if run.Status != "analyzing" {
		t.Fatalf("expected analyzing on creation, got %s", run.Status)
	}

	completed := waitForRunStatus(t, server, "manual", "complete")
	if !strings.Contains(completed.AnalysisSummary, "saturated") {
		t.Fatalf("run did not capture RCA: %+v", completed)
	}
	alert, _ := server.store.AlertDetail(record.AlertID)
	if !strings.Contains(alert.AnalysisSummary, "saturated") || alert.IsAnalyzing {
		t.Fatalf("successful run did not apply RCA to alert: %+v", alert)
	}
}

func TestAnalysisRunTimeoutFailsRun(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		time.Sleep(300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{Status: "ok"})
	})
	server.agentRequestTimeout = 30 * time.Millisecond
	_, record := seedAlert(t, server, "fp-timeout")

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if len(run.Warnings) == 0 || run.Capabilities["agent"] != string(agentErrTimeout) {
		t.Fatalf("expected timeout-classified failure, got %+v", run)
	}
	if hit.Load() == 0 {
		t.Fatalf("agent was never called")
	}
}

func TestAnalysisRunNon2xxFailsRun(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("agent boom"))
	})
	_, record := seedAlert(t, server, "fp-non2xx")

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if run.Capabilities["agent"] != string(agentErrStatus) {
		t.Fatalf("expected non_2xx classification, got %+v", run)
	}
	joined := strings.Join(run.Warnings, " ")
	if !strings.Contains(joined, "500") || !strings.Contains(joined, "agent boom") {
		t.Fatalf("expected status + body in warning, got %+v", run.Warnings)
	}
}

func TestAnalysisRunInvalidJSONFailsRun(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not-json"))
	})
	_, record := seedAlert(t, server, "fp-invalid")

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if run.Capabilities["agent"] != string(agentErrInvalidJSON) {
		t.Fatalf("expected invalid_json classification, got %+v", run)
	}
}

func TestFailedRunPreservesExistingSuccessfulRCA(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	})
	_, record := seedAlert(t, server, "fp-preserve")
	server.store.ApplyAnalysis(record.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Trusted RCA: quota saturation.",
		AnalysisDetail:  "## Root Cause\n\nQuota exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})

	server.startAnalysisRun("alert", record.AlertID, "comment", "please recheck")
	waitForRunStatus(t, server, "comment", "failed")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if !strings.Contains(alert.AnalysisSummary, "Trusted RCA") {
		t.Fatalf("failed run overwrote a successful RCA: %+v", alert.AnalysisSummary)
	}
	if alert.AnalysisQuality != "high" || alert.IsAnalyzing {
		t.Fatalf("alert state corrupted by failed run: quality=%s analyzing=%t", alert.AnalysisQuality, alert.IsAnalyzing)
	}
}

func TestFailedRunWritesFallbackWhenNoPriorRCA(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	_, record := seedAlert(t, server, "fp-fallback")

	server.startAnalysisRun("alert", record.AlertID, "auto", "")
	waitForRunStatus(t, server, "auto", "failed")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.AnalysisQuality != "low" || alert.IsAnalyzing {
		t.Fatalf("expected fallback RCA surfaced on alert, got %+v", alert)
	}
	if len(alert.MissingData) == 0 || alert.MissingData[0] != "agent.response" {
		t.Fatalf("expected fallback missing_data, got %+v", alert.MissingData)
	}
}

func TestFailedRunBroadcastsCompletedEvent(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_, record := seedAlert(t, server, "fp-sse")
	ch := server.hub.Subscribe()
	defer server.hub.Unsubscribe(ch)

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	event := waitForCompletedEvent(t, ch, "failed")
	if event.Data["alert_id"] != record.AlertID {
		t.Fatalf("completed event missing alert id: %+v", event.Data)
	}
}

func TestDashboardAnalyzeCreatesAnalysisRun(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Dashboard reanalysis done.",
			AnalysisDetail:  "## Root Cause\n\nDashboard triggered.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	})
	incident, _ := seedAlert(t, server, "fp-dashboard")

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/analyze",
		nil,
	))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected dashboard analyze 202, got %d: %s", rec.Code, rec.Body.String())
	}

	run := waitForRunStatus(t, server, "manual", "complete")
	if run.TargetType != "alert" || run.IncidentID != incident.IncidentID {
		t.Fatalf("dashboard run missing target linkage: %+v", run)
	}
	if !strings.Contains(run.Title, "Dashboard analysis") {
		t.Fatalf("expected dashboard source title, got %q", run.Title)
	}
}

func TestChatContextAttachesMemoryAndFeedbackHints(t *testing.T) {
	agentReqCh := make(chan ChatRequest, 1)
	server := NewServer()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(ChatResponse{Status: "ok", Answer: "ok", ConversationID: "chat-ctx"})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	priorIncident, priorRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "ctx-prior"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Workload pending, quota exhausted"},
		Fingerprint: "fp-ctx-prior",
	})
	server.store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Queue gpu-a saturated, quota blocked.",
		AnalysisDetail:  "## Root Cause\n\nQuota exhausted in gpu-a.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	_, _, _ = server.store.AddFeedback("incident", priorIncident.IncidentID, FeedbackRequest{
		Vote:    "up",
		Comment: "Matched the quota saturation incident.",
		Author:  "operator",
	})

	currentIncident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "ctx-current"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Workload pending while waiting for GPU quota"},
		Fingerprint: "fp-ctx-current",
	})

	body, _ := json.Marshal(ChatRequest{Message: "compare with prior RCA", IncidentID: currentIncident.IncidentID})
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected chat 200, got %d: %s", rec.Code, rec.Body.String())
	}

	agentReq := <-agentReqCh
	if _, ok := agentReq.Context["rca_memory"]; !ok {
		t.Fatalf("rca_memory missing from chat context: %+v", agentReq.Context)
	}
	if _, ok := agentReq.Context["similar_incidents"]; !ok {
		t.Fatalf("similar_incidents missing from chat context: %+v", agentReq.Context)
	}
	if _, ok := agentReq.Context["feedback_hints"]; !ok {
		t.Fatalf("feedback_hints missing from chat context: %+v", agentReq.Context)
	}
}
