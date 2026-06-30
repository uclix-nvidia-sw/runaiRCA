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

func TestWebhookAutoAnalysisFanoutCapsRunsAndAgentCallsTogether(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Auto RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nBounded auto fanout.",
			AnalysisQuality: "medium",
		})
	})
	alerts := make([]Alert, maxAutoAnalyzeFanout+3)
	for i := range alerts {
		alerts[i] = Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "RunAIWorkloadPending",
				"severity":  "warning",
				"namespace": fmt.Sprintf("runai-%02d", i),
				"workload":  fmt.Sprintf("trainer-%02d", i),
			},
			Annotations: map[string]string{"summary": "Workload pending"},
			Fingerprint: fmt.Sprintf("fp-auto-fanout-%02d", i),
		}
	}
	payload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "auto-fanout-cap", Alerts: alerts})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected webhook 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode webhook response: %v", err)
	}
	if response["auto_analyses"].(float64) != float64(maxAutoAnalyzeFanout) {
		t.Fatalf("expected capped auto analyses, got %+v", response)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hit.Load() < int32(maxAutoAnalyzeFanout) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if got := int(hit.Load()); got != maxAutoAnalyzeFanout {
		t.Fatalf("agent calls must match capped DB runs, got calls=%d", got)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != maxAutoAnalyzeFanout {
		t.Fatalf("analysis run rows must match capped agent calls, got %d", len(runs))
	}
}

func TestAnalysisRunPersistFailureSkipsAgentCall(t *testing.T) {
	state := newFakePostgresState(false)
	state.failAnalysisRuns = true
	store := NewStore()
	store.connectDatabaseWithDriver(registerFakePostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	beforeRuns := len(store.ListAnalysisRuns())
	var hit atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{Status: "ok"})
	}))
	defer agent.Close()
	server := &Server{
		store:                     store,
		hub:                       NewHub(),
		agentURL:                  agent.URL,
		agentRequestTimeout:       time.Second,
		manualAgentRequestTimeout: time.Second,
		client:                    &http.Client{},
	}
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-persist-failure",
	})

	if _, ok := server.startAnalysisRun("incident", incident.IncidentID, "auto", ""); ok {
		t.Fatalf("analysis run should not start when its DB row cannot be persisted")
	}
	time.Sleep(50 * time.Millisecond)
	if hit.Load() != 0 {
		t.Fatalf("agent was called despite analysis run persist failure")
	}
	if runs := store.ListAnalysisRuns(); len(runs) != beforeRuns {
		t.Fatalf("failed analysis run persist should not leave an in-memory run, before=%d after=%d", beforeRuns, len(runs))
	}
}

func TestAnalysisRunUpdatePersistFailureSkipsAlertRCA(t *testing.T) {
	state := newFakePostgresState(false)
	state.failAnalysisRunExecAfter = 1
	store := NewStore()
	store.connectDatabaseWithDriver(registerFakePostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	var hit atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Should not be applied.",
			AnalysisDetail:  "Agent result could not be persisted to the run row.",
			AnalysisQuality: "high",
		})
	}))
	defer agent.Close()
	server := &Server{
		store:                     store,
		hub:                       NewHub(),
		agentURL:                  agent.URL,
		agentRequestTimeout:       time.Second,
		manualAgentRequestTimeout: time.Second,
		client:                    &http.Client{},
	}
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "update-persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-update-persist-failure",
	})

	run, ok := server.startAnalysisRun("incident", incident.IncidentID, "auto", "")
	if !ok {
		t.Fatalf("expected initial analysis run persist to succeed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.Lock()
		execs := state.analysisRunExecs
		state.mu.Unlock()
		if execs >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	state.mu.Lock()
	execs := state.analysisRunExecs
	state.mu.Unlock()
	if execs < 2 {
		t.Fatalf("analysis run update persist was not attempted, execs=%d", execs)
	}
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
	}
	alert, _ := store.AlertDetail(record.AlertID)
	if alert.AnalysisSummary != "" || alert.AnalysisDetail != "" || !alert.IsAnalyzing {
		t.Fatalf("alert RCA should not apply when run update persist fails: %+v", alert)
	}
	after := waitForRunIDStatus(t, server, run.RunID, "analyzing")
	if after.AnalysisSummary != "" {
		t.Fatalf("run should be restored to analyzing without result text: %+v", after)
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

func TestOperatorPromptForTargetBoundsCommentSnapshot(t *testing.T) {
	server := NewServer()
	incident, record := seedAlert(t, server, "fp-comment-bounds")
	longAuthor := strings.Repeat("a", maxOperatorPromptAuthorBytes+20)

	addComment := func(targetType, targetID, body, author string) {
		t.Helper()
		if _, ok, err := server.store.AddComment(targetType, targetID, CommentRequest{
			Body:   body,
			Author: author,
		}); !ok || err != nil {
			t.Fatalf("add %s comment failed: ok=%t err=%v", targetType, ok, err)
		}
		time.Sleep(time.Microsecond)
	}

	for i := 0; i < maxOperatorPromptCommentsPerTarget+3; i++ {
		addComment(
			"incident",
			incident.IncidentID,
			fmt.Sprintf("incident-comment-%02d %s", i, strings.Repeat("i", maxOperatorPromptCommentBodyBytes+50)),
			"operator",
		)
	}
	for i := 0; i < maxOperatorPromptCommentsPerTarget; i++ {
		addComment(
			"alert",
			record.AlertID,
			fmt.Sprintf("alert-comment-%02d %s", i, strings.Repeat("z", maxOperatorPromptCommentBodyBytes+50)),
			longAuthor,
		)
	}

	prompt := server.store.OperatorPromptForTarget("alert", record.AlertID)
	if len(prompt) > maxOperatorPromptBytes+len("...") {
		t.Fatalf("operator prompt exceeded cap: got %d bytes", len(prompt))
	}
	if !strings.Contains(prompt, "3 older incident comment(s) omitted") {
		t.Fatalf("operator prompt did not record omitted incident comments: %q", prompt)
	}
	if strings.Contains(prompt, "incident-comment-00") {
		t.Fatalf("operator prompt kept oldest incident comment: %q", prompt)
	}
	if !strings.Contains(prompt, "incident-comment-12") || !strings.Contains(prompt, "alert-comment-09") {
		t.Fatalf("operator prompt lost latest comments: %q", prompt)
	}
	if !strings.Contains(prompt, strings.Repeat("a", maxOperatorPromptAuthorBytes)+"...") {
		t.Fatalf("operator prompt did not trim long author: %q", prompt)
	}
	if strings.Contains(prompt, strings.Repeat("z", maxOperatorPromptCommentBodyBytes+1)) {
		t.Fatalf("operator prompt did not trim long comment body: %q", prompt)
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
	incident, record := seedAlert(t, server, "fp-sse")
	ch := server.hub.Subscribe()
	defer server.hub.Unsubscribe(ch)

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	event := waitForCompletedEvent(t, ch, "failed")
	if event.Data["target_type"] != "alert" || event.Data["target_id"] != record.AlertID || event.Data["alert_id"] != record.AlertID {
		t.Fatalf("completed event missing alert id: %+v", event.Data)
	}

	server.startAnalysisRun("incident", incident.IncidentID, "manual", "")

	event = waitForCompletedEvent(t, ch, "failed")
	if event.Data["target_type"] != "incident" || event.Data["target_id"] != incident.IncidentID || event.Data["incident_id"] != incident.IncidentID {
		t.Fatalf("completed event missing incident target: %+v", event.Data)
	}
}

func TestAnalyzingRunRejectsDuplicateManualRun(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	released := false
	release := func() {
		if !released {
			close(releaseFirst)
			released = true
		}
	}
	defer release()
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		call := hit.Add(1)
		if call == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Manual RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nOnly one agent call should run.",
			AnalysisQuality: "medium",
		})
	})
	_, record := seedAlert(t, server, "fp-manual-dedupe")

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
	if ok {
		t.Fatalf("duplicate manual run should not start")
	}
	if secondRun == nil || secondRun.RunID != firstRun.RunID {
		t.Fatalf("duplicate manual run should return the in-flight run, got %+v want %s", secondRun, firstRun.RunID)
	}
	release()
	waitForRunIDStatus(t, server, firstRun.RunID, "complete")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.AnalysisSummary != "Manual RCA complete." || alert.AnalysisQuality != "medium" {
		t.Fatalf("first run result was not applied: %+v", alert)
	}
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("duplicate manual request should not create another run, got %+v", runs)
	}
}

func TestIncidentRunDedupesRepresentativeAlertRun(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	released := false
	release := func() {
		if !released {
			close(releaseFirst)
			released = true
		}
	}
	defer release()
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		if hit.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Incident RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nRepresentative alert was analyzed once.",
			AnalysisQuality: "medium",
		})
	})
	incident, _ := seedAlert(t, server, "fp-incident-alert-dedupe")

	incidentRun, ok := server.startAnalysisRun("incident", incident.IncidentID, "manual", "incident analysis")
	if !ok {
		t.Fatalf("expected incident run to start")
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("incident analysis did not reach agent")
	}
	alertRun, ok := server.startAnalysisRun("alert", incidentRun.AlertID, "manual", "alert analysis")
	if ok {
		t.Fatalf("representative alert run should not start while incident run is analyzing")
	}
	if alertRun == nil || alertRun.RunID != incidentRun.RunID {
		t.Fatalf("duplicate alert request should return the in-flight incident run, got %+v want %s", alertRun, incidentRun.RunID)
	}

	release()
	waitForRunIDStatus(t, server, incidentRun.RunID, "complete")
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
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

func TestDashboardAnalyzeStartsRemainingAlertsWhileOneIsAnalyzing(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	released := false
	release := func() {
		if !released {
			close(releaseFirst)
			released = true
		}
	}
	defer release()
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		if hit.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Manual RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nManual analysis finished.",
			AnalysisQuality: "medium",
		})
	})
	incident, first := seedAlert(t, server, "fp-dashboard-partial")
	secondID := "ALR-dashboard-partial-second"
	server.store.mu.Lock()
	server.store.alerts[secondID] = &AlertRecord{
		AlertID:     secondID,
		IncidentID:  incident.IncidentID,
		AlarmTitle:  "Second alert",
		Severity:    "warning",
		Status:      "firing",
		FiredAt:     first.FiredAt.Add(time.Minute),
		Fingerprint: "fp-dashboard-partial-second",
		ThreadTS:    "thread-" + secondID,
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Second alert blocked"},
	}
	server.store.mu.Unlock()

	firstRun, ok := server.startAnalysisRun("alert", first.AlertID, "manual", "first alert")
	if !ok {
		t.Fatalf("expected first alert run to start")
	}
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("first analysis did not reach agent")
	}

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/analyze", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected partial incident analyze 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "analysis_requested" || response["analysis_runs"].(float64) != 1 {
		t.Fatalf("expected one remaining alert run to start, got %+v", response)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hit.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if hit.Load() != 2 {
		t.Fatalf("expected second alert to reach agent, got %d calls", hit.Load())
	}
	release()
	waitForRunIDStatus(t, server, firstRun.RunID, "complete")
	if runs := server.store.ListAnalysisRuns(); len(runs) != 2 {
		t.Fatalf("expected exactly two alert runs, got %+v", runs)
	}
}

func TestDashboardAnalyzeLargeIncidentRejectsAgentFanout(t *testing.T) {
	server := NewServer()
	incident, _ := seedAlert(t, server, "fp-dashboard-large")
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	extraAlerts := 28
	server.store.mu.Lock()
	for i := 1; i <= extraAlerts; i++ {
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
	server.store.incidents[incident.IncidentID].AlertCount = extraAlerts + 1
	server.store.mu.Unlock()
	path := "/api/v1/incidents/" + incident.IncidentID + "/analyze"

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected large analyze 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 0 {
		t.Fatalf("large incident should not fan out new runs, got %+v", runs)
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
