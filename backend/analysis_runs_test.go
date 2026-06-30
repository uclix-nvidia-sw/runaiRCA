package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func waitForRunIDStatus(t *testing.T, server *Server, runID string, status string) AnalysisRun {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, run := range server.store.ListAnalysisRuns() {
			if run.RunID == runID && run.Status == status {
				return run
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %q status=%q not reached: %+v", runID, status, server.store.ListAnalysisRuns())
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

	server.startAnalysisRun("alert", record.AlertID, "auto", "")

	run := waitForRunStatus(t, server, "auto", "failed")
	if len(run.Warnings) == 0 || run.Capabilities["agent"] != string(agentErrTimeout) {
		t.Fatalf("expected timeout-classified failure, got %+v", run)
	}
	if hit.Load() == 0 {
		t.Fatalf("agent was never called")
	}
}

func TestAutoAnalysisRunIsIncidentScopedAndIdempotent(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Auto RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nSingle automatic run.",
			AnalysisQuality: "medium",
		})
	})
	incident, _ := seedAlert(t, server, "fp-auto-idempotent")

	first, ok := server.startAnalysisRun("incident", incident.IncidentID, "auto", "")
	if !ok {
		t.Fatalf("expected first auto run to start")
	}
	second, ok := server.startAnalysisRun("incident", incident.IncidentID, "auto", "")
	if ok {
		t.Fatalf("expected second auto run to reuse existing run")
	}
	if first.RunID != second.RunID {
		t.Fatalf("expected duplicate auto request to return existing run, got first=%s second=%s", first.RunID, second.RunID)
	}
	waitForRunStatus(t, server, "auto", "complete")
	if hit.Load() != 1 {
		t.Fatalf("expected one agent call, got %d", hit.Load())
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("expected one auto analysis run, got %+v", runs)
	}
}

func TestManualAnalysisClearsRCAAndSkipsAgentTimeout(t *testing.T) {
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		time.Sleep(80 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Fresh manual RCA completed.",
			AnalysisDetail:  "## Root Cause\n\nManual reanalysis finished.",
			AnalysisQuality: "high",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	})
	server.agentRequestTimeout = 20 * time.Millisecond
	incident, record := seedAlert(t, server, "fp-manual-no-timeout")
	server.store.ApplyAnalysis(record.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Old RCA should disappear.",
		AnalysisDetail:  "## Root Cause\n\nOld analysis.",
		AnalysisQuality: "medium",
		Capabilities:    map[string]string{"analysis": "old"},
	})
	if _, ok, err := server.store.AddComment("incident", incident.IncidentID, CommentRequest{
		Body:   "Re-check queue quota before finalizing.",
		Author: "operator",
	}); !ok || err != nil {
		t.Fatalf("incident comment failed: ok=%t err=%v", ok, err)
	}
	if _, ok, err := server.store.AddComment("alert", record.AlertID, CommentRequest{
		Body:   "Inspect scheduler logs for the pending workload.",
		Author: "operator",
	}); !ok || err != nil {
		t.Fatalf("alert comment failed: ok=%t err=%v", ok, err)
	}

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.AnalysisSummary != "" || alert.AnalysisDetail != "" || !alert.IsAnalyzing {
		t.Fatalf("manual analysis did not clear visible RCA: %+v", alert)
	}
	agentReq := <-agentReqCh
	prompt := agentReq.Alert.Annotations["operator_prompt"]
	if !strings.Contains(prompt, "queue quota") || !strings.Contains(prompt, "scheduler logs") {
		t.Fatalf("operator comments were not attached to manual analysis: %q", prompt)
	}
	run := waitForRunStatus(t, server, "manual", "complete")
	if !strings.Contains(run.AnalysisSummary, "Fresh manual") {
		t.Fatalf("manual run did not complete without timeout: %+v", run)
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

func TestNewerAnalysisRunWinsOverSlowerOlderRun(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		call := hit.Add(1)
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
			_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
				Status:          "ok",
				AnalysisSummary: "Stale first RCA.",
				AnalysisDetail:  "## Root Cause\n\nOlder result finished late.",
				AnalysisQuality: "low",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Fresh second RCA.",
			AnalysisDetail:  "## Root Cause\n\nNewer result should stay visible.",
			AnalysisQuality: "high",
		})
	})
	_, record := seedAlert(t, server, "fp-newer-wins")

	firstRun, ok := server.startAnalysisRun("alert", record.AlertID, "manual", "first analysis")
	if !ok {
		t.Fatalf("expected first run to start")
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("first agent request did not start")
	}
	secondRun, ok := server.startAnalysisRun("alert", record.AlertID, "manual", "second analysis")
	if !ok {
		t.Fatalf("expected second run to start")
	}

	waitForRunIDStatus(t, server, secondRun.RunID, "complete")
	close(releaseFirst)
	waitForRunIDStatus(t, server, firstRun.RunID, "complete")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.AnalysisSummary != "Fresh second RCA." || alert.AnalysisQuality != "high" {
		t.Fatalf("late stale run overwrote newer RCA: %+v", alert)
	}
}

func TestAnalysisRunHugeAgentResponseFailsRun(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxAgentResponseBodyBytes)+1)))
	})
	_, record := seedAlert(t, server, "fp-huge-agent-response")

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if run.Capabilities["agent"] != string(agentErrBodyTooBig) {
		t.Fatalf("expected response_too_large failure, got %+v", run)
	}
	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing || alert.AnalysisQuality != "low" {
		t.Fatalf("huge response should clear analyzing with low-quality fallback, got %+v", alert)
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

func TestDashboardAnalyzeSkipsDuplicateWhenIncidentAlreadyAnalyzing(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		close(firstStarted)
		<-releaseFirst
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Manual RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nManual analysis finished.",
			AnalysisQuality: "medium",
		})
	})
	incident, _ := seedAlert(t, server, "fp-dashboard-duplicate")
	path := "/api/v1/incidents/" + incident.IncidentID + "/analyze"

	firstRec := httptest.NewRecorder()
	server.routes().ServeHTTP(firstRec, httptest.NewRequest(http.MethodPost, path, nil))
	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("expected first analyze 202, got %d: %s", firstRec.Code, firstRec.Body.String())
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("first analysis did not reach agent")
	}

	secondRec := httptest.NewRecorder()
	server.routes().ServeHTTP(secondRec, httptest.NewRequest(http.MethodPost, path, nil))
	if secondRec.Code != http.StatusAccepted {
		t.Fatalf("expected duplicate analyze 202, got %d: %s", secondRec.Code, secondRec.Body.String())
	}
	var duplicateResponse map[string]any
	if err := json.Unmarshal(secondRec.Body.Bytes(), &duplicateResponse); err != nil {
		t.Fatalf("decode duplicate response: %v", err)
	}
	if duplicateResponse["status"] != "analysis_already_running" {
		t.Fatalf("expected already running response, got %+v", duplicateResponse)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("duplicate analyze should not create another run, got %+v", runs)
	}
	close(releaseFirst)
	waitForRunStatus(t, server, "manual", "complete")
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
	}
}

func TestDashboardAnalyzeLargeIncidentUsesSingleIncidentRun(t *testing.T) {
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Large incident RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nIncident-scope analysis avoided fan-out.",
			AnalysisQuality: "medium",
		})
	})
	incident, _ := seedAlert(t, server, "fp-dashboard-large")
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	server.store.mu.Lock()
	for i := 1; i <= maxManualAnalyzeFanout+3; i++ {
		alertID := fmt.Sprintf("ALR-large-%03d", i)
		server.store.alerts[alertID] = &AlertRecord{
			AlertID:     alertID,
			IncidentID:  incident.IncidentID,
			AlarmTitle:  fmt.Sprintf("Large incident alert %03d", i),
			Severity:    "warning",
			Status:      "firing",
			FiredAt:     base.Add(time.Duration(i) * time.Minute),
			Fingerprint: fmt.Sprintf("fp-dashboard-large-%03d", i),
			ThreadTS:    "thread-" + alertID,
			Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
			Annotations: map[string]string{"summary": "Queue blocked"},
		}
	}
	server.store.incidents[incident.IncidentID].AlertCount = maxManualAnalyzeFanout + 4
	server.store.mu.Unlock()
	path := "/api/v1/incidents/" + incident.IncidentID + "/analyze"

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected large analyze 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["mode"] != "incident" || response["analysis_runs"].(float64) != 1 {
		t.Fatalf("expected single incident run response, got %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.IncidentID != incident.IncidentID {
		t.Fatalf("incident id was not forwarded: %+v", agentReq)
	}
	run := waitForRunStatus(t, server, "manual", "complete")
	if run.TargetType != "incident" || run.TargetID != incident.IncidentID {
		t.Fatalf("expected incident-scope run, got %+v", run)
	}
	alert, _ := server.store.AlertDetail(run.AlertID)
	if alert.IsAnalyzing {
		t.Fatalf("representative alert should be complete, got %+v", alert)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("large incident should create one run, got %+v", runs)
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
