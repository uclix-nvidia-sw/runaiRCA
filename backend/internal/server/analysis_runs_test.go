package server

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

	"github.com/brilly-bohyun/runai-rca/backend/internal/server/testsupport"
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
	if alert.IsAnalyzing {
		t.Fatalf("successful run should clear the alert analyzing flag: %+v", alert)
	}
}

func TestResolvedAnalysisRequestCarriesStoredHistoricalWindow(t *testing.T) {
	received := make(chan AgentAnalysisRequest, 1)
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		var request AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err == nil {
			received <- request
		}
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Historical window inspected.",
			AnalysisDetail:  "## Root Cause\n\nHistorical evidence retained.",
			AnalysisQuality: "high",
		})
	})
	firedAt := time.Date(2026, 7, 10, 1, 0, 0, 123456789, time.UTC)
	resolvedAt := firedAt.Add(10 * time.Minute)
	incident, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "resolved-window"}, Alert{
		Status:      "resolved",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue recovered"},
		Fingerprint: "fp-resolved-window",
		StartsAt:    firedAt.Format(time.RFC3339Nano),
		EndsAt:      resolvedAt.Format(time.RFC3339Nano),
	})

	run, ok := server.startAnalysisRun("incident", incident.IncidentID, "manual", "reanalyze")
	if !ok {
		t.Fatal("expected resolved manual analysis to start")
	}
	waitForRunIDStatus(t, server, run.RunID, "complete")

	select {
	case request := <-received:
		if request.Alert.Fingerprint != record.Fingerprint {
			t.Fatalf("expected selected stored alert, got %+v", request.Alert)
		}
		if request.Alert.StartsAt != firedAt.Format(time.RFC3339Nano) {
			t.Fatalf("expected historical startsAt, got %q", request.Alert.StartsAt)
		}
		if request.Alert.EndsAt != resolvedAt.Format(time.RFC3339Nano) {
			t.Fatalf("expected historical endsAt, got %q", request.Alert.EndsAt)
		}
	case <-time.After(time.Second):
		t.Fatal("agent request was not captured")
	}
}

func TestAnalysisRunStoresUsageAndPreservesLastGoodMetadataOnReanalysis(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "usage"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-usage",
	})
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Manual", "")
	if _, _, ok := store.AppendAnalysisProgress(run.RunID, map[string]any{
		"phase":   "planning",
		"message": "building hypotheses",
	}); !ok {
		t.Fatalf("progress append failed")
	}
	completed, ok := store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "done",
		Context: map[string]any{
			"llm_usage": map[string]any{"prompt_tokens": float64(3), "completion_tokens": float64(5), "total_tokens": float64(8)},
		},
	})
	if !ok {
		t.Fatalf("complete failed")
	}
	if completed.FirstCompletedAt == nil {
		t.Fatalf("first completion timestamp was not set: %+v", completed)
	}
	usage, ok := completed.Metadata["llm_usage"].(map[string]any)
	if !ok || usage["total_tokens"] != float64(8) {
		t.Fatalf("usage metadata missing: %+v", completed.Metadata)
	}
	progress, ok := completed.Metadata["progress_log"].([]any)
	if !ok || len(progress) != 1 {
		t.Fatalf("progress log missing after complete: %+v", completed.Metadata)
	}
	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok || detail.TokenUsage["total_tokens"] != float64(8) {
		t.Fatalf("incident detail missing token usage: ok=%t detail=%+v", ok, detail)
	}

	reused, created := store.CreateAnalysisRunIfAllowed("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Again", "")
	lastGood := analysisResultMetadata(&reused)
	if !created || reused.RunID != run.RunID || reused.FirstCompletedAt == nil ||
		lastGood["llm_usage"] == nil || reused.Metadata["progress_log"] != nil {
		t.Fatalf("reanalysis should reuse the row, retain last-good metadata, and clear attempt progress; created=%t run=%+v", created, reused)
	}
}

func TestFailedReanalysisRestoresLastGoodMetadata(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "metadata-restore"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"}, Fingerprint: "fp-metadata-restore",
	})
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Initial", "")
	run, _ = store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "trusted RCA",
		Context: map[string]any{
			"analysis_hash": "hash-good",
			"harness":       map[string]any{"verdict": "pass"},
			"llm_usage":     map[string]any{"total_tokens": float64(42)},
		},
	})
	reused, created := store.CreateAnalysisRunIfAllowed(
		"manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Retry", "",
	)
	if !created || currentAnalysisHash(&reused) != "hash-good" {
		t.Fatalf("reanalysis did not expose its last-good metadata: created=%t run=%+v", created, reused)
	}
	if _, _, ok := store.AppendAnalysisProgress(reused.RunID, map[string]any{"phase": "investigation"}); !ok {
		t.Fatal("failed to append retry progress")
	}
	failed, ok := store.FailAnalysisRun(reused.RunID, AgentAnalysisResponse{
		AnalysisSummary: "fallback must not replace the trusted RCA",
		Context: map[string]any{
			"analysis_hash": "hash-failed-attempt",
			"harness":       map[string]any{"verdict": "failed"},
		},
	})
	if !ok || currentAnalysisHash(&failed) != "hash-good" || failed.Metadata[previousSuccessMetadataKey] != nil {
		t.Fatalf("failed retry did not restore last-good metadata: ok=%t run=%+v", ok, failed)
	}
	harness, _ := failed.Metadata["harness"].(map[string]any)
	usage, _ := failed.Metadata["llm_usage"].(map[string]any)
	progress, _ := failed.Metadata["progress_log"].([]any)
	if harness["verdict"] != "pass" || usage["total_tokens"] != float64(42) || len(progress) != 1 {
		t.Fatalf("restored metadata or failed-attempt progress is incomplete: %+v", failed.Metadata)
	}
	detail, _ := store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisHash != "hash-good" || detail.Harness["verdict"] != "pass" || detail.TokenUsage["total_tokens"] != float64(42) {
		t.Fatalf("incident detail lost last-good verification metadata: %+v", detail)
	}
}

func TestStaleReanalysisRestoresLastGoodMetadata(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "metadata-reap"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"}, Fingerprint: "fp-metadata-reap",
	})
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Initial", "")
	store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "trusted RCA",
		Context:         map[string]any{"analysis_hash": "hash-before-restart", "harness": map[string]any{"verdict": "pass"}},
	})
	store.CreateAnalysisRunIfAllowed("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Retry", "")

	if reaped := store.ReapStaleAnalyzingRuns(0, 0); reaped != 1 {
		t.Fatalf("expected one stale retry to be reaped, got %d", reaped)
	}
	after, _ := store.AnalysisRun(run.RunID)
	if after.Status != "failed" || currentAnalysisHash(&after) != "hash-before-restart" || after.Metadata[previousSuccessMetadataKey] != nil {
		t.Fatalf("stale retry lost its last-good metadata: %+v", after)
	}
}

func TestAnalysisProgressHandlerAppendsAndBroadcasts(t *testing.T) {
	server := NewServer()
	ch := server.hub.Subscribe()
	defer server.hub.Unsubscribe(ch)
	incident, alert := seedAlert(t, server, "fp-progress")
	run := server.store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "Manual", "")

	body, _ := json.Marshal(map[string]any{
		"phase":   "planning",
		"message": "hypothesis check",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/analysis-runs/"+run.RunID+"/progress", bytes.NewReader(body))
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	event := receiveEvent(t, ch)
	if event.Type != eventAnalysisProgress ||
		event.Data["run_id"] != run.RunID ||
		event.Data["incident_id"] != incident.IncidentID ||
		event.Data["alert_id"] != alert.AlertID ||
		event.Data["phase"] != "planning" ||
		usageInt(event.Data["seq"]) != 1 {
		t.Fatalf("unexpected progress event: %+v", event)
	}
	stored := waitForRunIDStatus(t, server, run.RunID, "analyzing")
	progress, ok := stored.Metadata["progress_log"].([]any)
	if !ok || len(progress) != 1 {
		t.Fatalf("progress was not stored in metadata: %+v", stored.Metadata)
	}
}

func TestAnalysisProgressCapsLogAndRejectsTerminalRuns(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "cap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-progress-cap",
	})
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Manual", "")
	for i := 0; i < maxProgressLogEntries+5; i++ {
		if _, _, ok := store.AppendAnalysisProgress(run.RunID, map[string]any{"message": fmt.Sprintf("step-%03d", i)}); !ok {
			t.Fatalf("append %d failed", i)
		}
	}
	stored := store.ListAnalysisRuns()[0]
	log, ok := stored.Metadata["progress_log"].([]any)
	if !ok || len(log) != maxProgressLogEntries {
		t.Fatalf("progress log cap failed: len=%d metadata=%+v", len(log), stored.Metadata)
	}
	firstEntry := log[0].(map[string]any)
	lastEntry := log[len(log)-1].(map[string]any)
	if usageInt(firstEntry["seq"]) != 6 || usageInt(lastEntry["seq"]) != maxProgressLogEntries+5 {
		t.Fatalf("unexpected progress seq window: first=%+v last=%+v", firstEntry, lastEntry)
	}

	store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "done"})
	if _, _, ok := store.AppendAnalysisProgress(run.RunID, map[string]any{"message": "late"}); ok {
		t.Fatalf("terminal run accepted progress")
	}
}

func TestAnalysisProgressHandlerReturnsConflictForNonAnalyzingRun(t *testing.T) {
	server := NewServer()
	incident, alert := seedAlert(t, server, "fp-progress-conflict")
	run := server.store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "Manual", "")
	server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "done"})

	body := []byte(`{"message":"late"}`)
	for _, path := range []string{
		"/api/v1/analysis-runs/" + run.RunID + "/progress",
		"/api/v1/analysis-runs/ANL-missing/progress",
	} {
		rec := httptest.NewRecorder()
		server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("expected 409 for %s, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestAnalysisRunGetReturnsExactRun(t *testing.T) {
	server := NewServer()
	incident, alert := seedAlert(t, server, "fp-run-get")
	run := server.store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "Manual", "")

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis-runs/"+run.RunID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("exact run status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data AnalysisRun `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil || body.Data.RunID != run.RunID {
		t.Fatalf("exact run response mismatch err=%v body=%+v", err, body)
	}

	rec = httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis-runs/ANL-missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing exact run status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIncidentDetailSeparatesActiveRunFromLastGoodRCA(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "active-vs-last-good"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"}, Fingerprint: "fp-active-vs-last-good",
	})
	lastGood := store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "Alert analysis", "")
	lastGood, _ = store.CompleteAnalysisRun(lastGood.RunID, AgentAnalysisResponse{AnalysisSummary: "last good"})
	active := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Incident reanalysis", "")

	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok || detail.AnalysisRunID != lastGood.RunID || detail.ActiveAnalysisRunID != active.RunID {
		t.Fatalf("active and last-good runs were not separated: ok=%t detail=%+v", ok, detail)
	}
	store.CompleteAnalysisRun(active.RunID, AgentAnalysisResponse{AnalysisSummary: "new good"})
	detail, _ = store.IncidentDetail(incident.IncidentID)
	if detail.ActiveAnalysisRunID != "" || detail.AnalysisRunID != active.RunID || detail.AnalysisSummary != "new good" {
		t.Fatalf("completed active run did not replace last-good RCA: %+v", detail)
	}
}

func TestKPIStatsUsesFirstCompletedAt(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	firedAt := now.Add(-2 * time.Hour)
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "kpi"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-kpi",
		StartsAt:    firedAt.Format(time.RFC3339),
	})
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Manual", "")
	store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "done"})
	firstCompletedAt := firedAt.Add(15 * time.Minute)
	resolvedAt := firedAt.Add(60 * time.Minute)
	store.mu.Lock()
	store.analysisRuns[run.RunID].FirstCompletedAt = &firstCompletedAt
	store.analysisRuns[run.RunID].UpdatedAt = firedAt.Add(90 * time.Minute)
	store.incidents[incident.IncidentID].ResolvedAt = &resolvedAt
	store.incidents[incident.IncidentID].Status = "resolved"
	store.mu.Unlock()

	stats := store.KPIStats(7, now)

	if stats.TimeToRCA.Count != 1 || stats.TimeToRCA.AvgMinutes != 15 {
		t.Fatalf("expected 15m time-to-RCA from first_completed_at, got %+v", stats.TimeToRCA)
	}
	if stats.TimeToResolve.Count != 1 || stats.TimeToResolve.AvgMinutes != 60 {
		t.Fatalf("expected 60m time-to-resolve, got %+v", stats.TimeToResolve)
	}
	if stats.Daily[len(stats.Daily)-1].TimeToRCA.Count != 1 {
		t.Fatalf("expected KPI in latest day bucket, got %+v", stats.Daily)
	}
}

func TestLLMSpendStatsAggregatesUsageMetadata(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "spend"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-spend",
	})
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Manual", "")
	store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "done",
		Context: map[string]any{
			"llm_usage": map[string]any{
				"calls":               float64(2),
				"calls_without_usage": float64(1),
				"failed_calls":        float64(1),
				"prompt_tokens":       float64(30),
				"completion_tokens":   float64(20),
				"total_tokens":        float64(50),
				"cost_usd":            float64(0.25),
				"by_model": map[string]any{
					"cheap": map[string]any{
						"calls":             float64(1),
						"prompt_tokens":     float64(10),
						"completion_tokens": float64(5),
						"total_tokens":      float64(15),
						"cost_usd":          float64(0.05),
					},
					"smart": map[string]any{
						"calls":             float64(1),
						"failed_calls":      float64(1),
						"prompt_tokens":     float64(20),
						"completion_tokens": float64(15),
						"total_tokens":      float64(35),
						"cost_usd":          float64(0.20),
					},
				},
			},
		},
	})
	oldRun := store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "Old", "")
	store.FailAnalysisRun(oldRun.RunID, AgentAnalysisResponse{
		AnalysisSummary: "old",
		Context: map[string]any{
			"llm_usage": map[string]any{
				"calls":        float64(99),
				"total_tokens": float64(99),
				"cost_usd":     float64(99),
			},
		},
	})
	store.mu.Lock()
	store.analysisRuns[run.RunID].UpdatedAt = now
	store.analysisRuns[oldRun.RunID].UpdatedAt = now.AddDate(0, 0, -10)
	store.mu.Unlock()

	stats := store.LLMSpendStats(7, now)

	if stats.Calls != 2 || stats.CallsWithoutUsage != 1 || stats.FailedCalls != 1 ||
		stats.PromptTokens != 30 || stats.CompletionTokens != 20 || stats.TotalTokens != 50 ||
		stats.CostUSD != 0.25 {
		t.Fatalf("unexpected spend stats: %+v", stats)
	}
	if stats.ByModel["cheap"].TotalTokens != 15 || stats.ByModel["smart"].FailedCalls != 1 {
		t.Fatalf("unexpected model breakdown: %+v", stats.ByModel)
	}
	if stats.Daily[len(stats.Daily)-1].TotalTokens != 50 {
		t.Fatalf("expected spend in latest day bucket, got %+v", stats.Daily)
	}
}

func TestAnalysisRunCompactsSimilarIncidentsForAgent(t *testing.T) {
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})
	})
	priorIncident, priorRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "compact-prior"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
			"large":     strings.Repeat("label", 200),
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-compact-prior",
	})
	server.store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: strings.Repeat("summary ", 200),
		AnalysisDetail:  strings.Repeat("detail ", 500),
		RootCauseFamily: "runai_scheduling_quota",
	})
	approveIncidentForTest(t, server.store, priorIncident.IncidentID)
	_, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "compact-current"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked again"},
		Fingerprint: "fp-compact-current",
	})

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	agentReq := <-agentReqCh
	if len(agentReq.SimilarIncidents) != 1 || agentReq.SimilarIncidents[0].IncidentID != priorIncident.IncidentID {
		t.Fatalf("expected compact prior incident, got %+v", agentReq.SimilarIncidents)
	}
	similar := agentReq.SimilarIncidents[0]
	if similar.AnalysisDetail != "" || similar.Labels != nil {
		t.Fatalf("similar incident detail/labels should not be sent to agent: %+v", similar)
	}
	if similar.RootCauseFamily != "runai_scheduling_quota" || !similar.Approved {
		t.Fatalf("similar incident provenance should be preserved for the agent: %+v", similar)
	}
	if len(similar.AnalysisSummary) > 803 || !strings.HasSuffix(similar.AnalysisSummary, "...") {
		t.Fatalf("similar incident summary should be capped, got len=%d", len(similar.AnalysisSummary))
	}
}

func TestAnalysisRunCompactsAlertMapValuesForAgent(t *testing.T) {
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})
	})
	_, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "compact-alert-map"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"large":     strings.Repeat("label", maxAgentMapValueBytes+200),
		},
		Annotations: map[string]string{"summary": strings.Repeat("summary", maxAgentMapValueBytes+200)},
		Fingerprint: "fp-compact-alert-map",
	})

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	agentReq := <-agentReqCh
	if len(agentReq.Alert.Labels["large"]) > maxAgentMapValueBytes+len("...") ||
		!strings.HasSuffix(agentReq.Alert.Labels["large"], "...") {
		t.Fatalf("large label should be capped, got len=%d", len(agentReq.Alert.Labels["large"]))
	}
	if len(agentReq.Alert.Annotations["summary"]) > maxAgentMapValueBytes+len("...") ||
		!strings.HasSuffix(agentReq.Alert.Annotations["summary"], "...") {
		t.Fatalf("large annotation should be capped, got len=%d", len(agentReq.Alert.Annotations["summary"]))
	}
	stored, _ := server.store.AlertDetail(record.AlertID)
	if len(stored.Annotations["summary"]) <= maxAgentMapValueBytes+len("...") {
		t.Fatalf("stored alert annotation should not be compacted")
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

func TestAgentDeadlineTerminalResponseFailsFirstRunAndSurfacesDiagnosis(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "failed",
			TerminalReason:  "deadline_exceeded",
			AnalysisSummary: "Analysis was stopped after exceeding the 1000s deadline.",
			AnalysisDetail:  "Evidence gathering exceeded the hard deadline; retry the analysis.",
			AnalysisQuality: "degraded",
			Warnings:        []string{"analysis exceeded the 1000s deadline and was stopped"},
		})
	})
	incident, record := seedAlert(t, server, "fp-agent-terminal-deadline")

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if run.AnalysisQuality != "degraded" ||
		!strings.Contains(run.AnalysisSummary, "1000s deadline") ||
		!strings.Contains(run.AnalysisDetail, "hard deadline") {
		t.Fatalf("first terminal attempt did not retain the degraded diagnosis: %+v", run)
	}
	detail, ok := server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.AnalysisQuality != "degraded" ||
		!strings.Contains(detail.AnalysisSummary, "1000s deadline") {
		t.Fatalf("first terminal attempt was not exposed on the incident: ok=%t detail=%+v", ok, detail)
	}
}

func TestAgentDeadlineTerminalResponsePreservesLastGoodRCAAndMetadata(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "failed",
			TerminalReason:  "deadline_exceeded",
			AnalysisSummary: "deadline fallback must not replace trusted RCA",
			AnalysisDetail:  "terminal attempt exceeded its deadline",
			AnalysisQuality: "degraded",
			Context: map[string]any{
				"analysis_hash": "hash-deadline-attempt",
				"harness":       map[string]any{"verdict": "failed"},
			},
		})
	})
	incident, record := seedAlert(t, server, "fp-agent-terminal-preserve")
	prior := server.store.CreateAnalysisRun(
		"manual",
		"alert",
		record.AlertID,
		incident.IncidentID,
		record.AlertID,
		"Initial trusted analysis",
		"",
	)
	prior, ok := server.store.CompleteAnalysisRun(prior.RunID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Trusted RCA: queue quota saturation.",
		AnalysisDetail:  "## Root Cause\n\nQueue quota exhausted.",
		AnalysisQuality: "high",
		Context: map[string]any{
			"analysis_hash": "hash-last-good",
			"harness":       map[string]any{"verdict": "pass"},
			"llm_usage":     map[string]any{"total_tokens": float64(42)},
		},
	})
	if !ok {
		t.Fatal("failed to seed last-good analysis")
	}

	reused, started := server.startAnalysisRun("alert", record.AlertID, "manual", "")
	if !started || reused.RunID != prior.RunID {
		t.Fatalf("expected terminal retry to reuse last-good row: started=%t run=%+v", started, reused)
	}
	failed := waitForRunIDStatus(t, server, prior.RunID, "failed")
	if failed.AnalysisSummary != prior.AnalysisSummary ||
		failed.AnalysisDetail != prior.AnalysisDetail ||
		failed.AnalysisQuality != "high" ||
		currentAnalysisHash(&failed) != "hash-last-good" {
		t.Fatalf("terminal retry overwrote the last-good RCA or metadata: %+v", failed)
	}
	harness, _ := failed.Metadata["harness"].(map[string]any)
	usage, _ := failed.Metadata["llm_usage"].(map[string]any)
	if harness["verdict"] != "pass" || usage["total_tokens"] != float64(42) ||
		failed.Metadata[previousSuccessMetadataKey] != nil {
		t.Fatalf("terminal retry did not restore last-good metadata: %+v", failed.Metadata)
	}
	detail, ok := server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.AnalysisSummary != prior.AnalysisSummary ||
		detail.AnalysisHash != "hash-last-good" {
		t.Fatalf("incident lost last-good RCA after terminal retry: ok=%t detail=%+v", ok, detail)
	}
}

func TestAutoAnalysisRunIsAlertScopedAndIdempotent(t *testing.T) {
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
	_, record := seedAlert(t, server, "fp-auto-idempotent")

	first, ok := server.startAnalysisRun("alert", record.AlertID, "auto", "")
	if !ok {
		t.Fatalf("expected first auto run to start")
	}
	second, ok := server.startAnalysisRun("alert", record.AlertID, "auto", "")
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
	} else if runs[0].TargetType != "alert" || runs[0].TargetID != record.AlertID {
		t.Fatalf("expected alert-scoped auto run, got %+v", runs[0])
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

func TestWebhookAutoAnalysisCapsAcrossPayloads(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Auto RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nGlobal auto cap.",
			AnalysisQuality: "medium",
		})
	})
	makeAlerts := func(prefix string, count int) []Alert {
		alerts := make([]Alert, count)
		for i := range alerts {
			alerts[i] = Alert{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIWorkloadPending",
					"severity":  "warning",
					"namespace": fmt.Sprintf("%s-%02d", prefix, i),
					"workload":  fmt.Sprintf("trainer-%02d", i),
				},
				Annotations: map[string]string{"summary": "Workload pending"},
				Fingerprint: fmt.Sprintf("fp-%s-%02d", prefix, i),
			}
		}
		return alerts
	}
	firstPayload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "auto-global-cap-1", Alerts: makeAlerts("global-a", maxAutoAnalyzeFanout)})
	firstRec := httptest.NewRecorder()
	server.routes().ServeHTTP(firstRec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(firstPayload)))
	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("expected first webhook 202, got %d: %s", firstRec.Code, firstRec.Body.String())
	}
	secondPayload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "auto-global-cap-2", Alerts: makeAlerts("global-b", 3)})
	secondRec := httptest.NewRecorder()
	server.routes().ServeHTTP(secondRec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(secondPayload)))
	if secondRec.Code != http.StatusAccepted {
		t.Fatalf("expected second webhook 202, got %d: %s", secondRec.Code, secondRec.Body.String())
	}
	var secondResponse map[string]any
	if err := json.Unmarshal(secondRec.Body.Bytes(), &secondResponse); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if secondResponse["auto_analyses"].(float64) != 0 {
		t.Fatalf("second webhook should be globally capped, got %+v", secondResponse)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != maxAutoAnalyzeFanout {
		t.Fatalf("global cap should keep run count bounded, got %d", len(runs))
	}
}

func TestAnalysisRunLimitsConcurrentAgentCalls(t *testing.T) {
	var hit atomic.Int32
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		current := inFlight.Add(1)
		for {
			seen := maxInFlight.Load()
			if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
				break
			}
		}
		hit.Add(1)
		started <- struct{}{}
		<-release
		inFlight.Add(-1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "ok",
			AnalysisQuality: "high",
		})
	})
	server.agentSlots = make(chan struct{}, 1)
	_, first := seedAlert(t, server, "agent-limit-a")
	_, second := seedAlert(t, server, "agent-limit-b")

	if _, ok := server.startAnalysisRun("alert", first.AlertID, "auto", ""); !ok {
		t.Fatal("expected first run to start")
	}
	if _, ok := server.startAnalysisRun("alert", second.AlertID, "auto", ""); !ok {
		t.Fatal("expected second run to queue")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first agent call did not start")
	}
	time.Sleep(50 * time.Millisecond)
	if got := hit.Load(); got != 1 {
		t.Fatalf("expected only one agent call before release, got %d", got)
	}
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		completed := 0
		for _, run := range server.store.ListAnalysisRuns() {
			if run.Status == "complete" {
				completed++
			}
		}
		if completed == 2 {
			if got := maxInFlight.Load(); got != 1 {
				t.Fatalf("expected max in-flight agent calls to be 1, got %d", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("runs did not complete: %+v", server.store.ListAnalysisRuns())
}

func TestAnalysisRunFailsWhenAgentSlotUnavailable(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "should not run",
			AnalysisQuality: "high",
		})
	})
	server.agentSlots = make(chan struct{}, 1)
	server.agentSlots <- struct{}{}
	server.agentRequestTimeout = 10 * time.Millisecond
	_, record := seedAlert(t, server, "agent-limit-timeout")

	run, ok := server.startAnalysisRun("alert", record.AlertID, "auto", "")
	if !ok {
		t.Fatal("expected run to start before waiting for an agent slot")
	}
	failed := waitForRunIDStatus(t, server, run.RunID, "failed")
	if failed.Capabilities["agent"] != string(agentErrBusy) {
		t.Fatalf("expected busy failure, got %+v", failed.Capabilities)
	}
	if got := hit.Load(); got != 0 {
		t.Fatalf("agent was called despite unavailable slot: %d", got)
	}
	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing {
		t.Fatal("alert remained analyzing after slot timeout")
	}
}

func TestAnalysisRunPersistFailureSkipsAgentCall(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	state.SetFailAnalysisRuns(true)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
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
	_, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-persist-failure",
	})

	if run, ok := server.startAnalysisRun("alert", record.AlertID, "auto", ""); ok || run != nil {
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
	state := testsupport.NewPostgresState(false)
	state.SetFailAnalysisRunExecAfter(1)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
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
	_, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "update-persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-update-persist-failure",
	})

	run, ok := server.startAnalysisRun("alert", record.AlertID, "auto", "")
	if !ok {
		t.Fatalf("expected initial analysis run persist to succeed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		execs := state.AnalysisRunExecs()
		if execs >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	execs := state.AnalysisRunExecs()
	if execs < 2 {
		t.Fatalf("analysis run update persist was not attempted, execs=%d", execs)
	}
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
	}
	alert, _ := store.AlertDetail(record.AlertID)
	if !alert.IsAnalyzing {
		t.Fatalf("alert should stay analyzing when the run update persist fails: %+v", alert)
	}
	after := waitForRunIDStatus(t, server, run.RunID, "analyzing")
	if after.AnalysisSummary != "" {
		t.Fatalf("run should be restored to analyzing without result text: %+v", after)
	}
}

func TestAlertPersistFailureKeepsRCAOnRun(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	_, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "alert-persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-alert-persist-failure",
	})
	state.SetFailAlertExecAfter(2)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "RCA should not look successful.",
			AnalysisDetail:  "## Root Cause\n\nPersist fails.",
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

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	// The RCA is durably stored on the run (CompleteAnalysisRun); an alert-flag
	// persist failure marks the run failed but must NOT lose the analysis.
	if !strings.Contains(run.AnalysisSummary, "RCA should not look successful") {
		t.Fatalf("alert persist failure should preserve the run RCA, got %+v", run)
	}
	alert, _ := store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing {
		t.Fatalf("failed run should clear the alert analyzing state: %+v", alert)
	}
}

func TestReapPersistFailureKeepsRunAnalyzing(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "reap-persist-failure"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-reap-persist-failure",
	})
	run := store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "stale", "")
	state.SetFailAnalysisRunExecAfter(1)

	reaped := store.ReapStaleAnalyzingRuns(0, 0)

	if reaped != 0 {
		t.Fatalf("failed reap persist should not count as reaped, got %d", reaped)
	}
	after := store.ListAnalysisRuns()[0]
	if after.RunID != run.RunID || after.Status != "analyzing" || after.Capabilities["agent"] == "interrupted" {
		t.Fatalf("failed reap persist should keep run analyzing, got %+v", after)
	}
}

func TestManualAnalysisKeepsRCAAndSkipsAgentTimeout(t *testing.T) {
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
	if !alert.IsAnalyzing {
		t.Fatalf("manual analysis should mark the alert analyzing: %+v", alert)
	}
	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if !strings.Contains(detail.AnalysisSummary, "Old RCA") {
		t.Fatalf("manual analysis should keep the last RCA visible while analyzing: %q", detail.AnalysisSummary)
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

func TestFailedManualRunPreservesExistingSuccessfulRCA(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	})
	_, record := seedAlert(t, server, "fp-manual-preserve")
	server.store.ApplyAnalysis(record.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Trusted manual RCA: quota saturation.",
		AnalysisDetail:  "## Root Cause\n\nQuota exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})

	server.startAnalysisRun("alert", record.AlertID, "manual", "")
	waitForRunStatus(t, server, "manual", "failed")

	alert, _ := server.store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing {
		t.Fatalf("failed manual run should clear the alert analyzing flag: %+v", alert)
	}
	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if !strings.Contains(detail.AnalysisSummary, "Trusted manual RCA") || detail.AnalysisQuality != "high" {
		t.Fatalf("failed manual run overwrote the successful RCA: summary=%q quality=%s", detail.AnalysisSummary, detail.AnalysisQuality)
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
	if alert.IsAnalyzing {
		t.Fatalf("failed run should clear the alert analyzing flag: %+v", alert)
	}
	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if !strings.Contains(detail.AnalysisSummary, "Trusted RCA") || detail.AnalysisQuality != "high" {
		t.Fatalf("failed run overwrote a successful RCA: summary=%q quality=%s", detail.AnalysisSummary, detail.AnalysisQuality)
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
	if alert.IsAnalyzing {
		t.Fatalf("failed run should clear the alert analyzing flag: %+v", alert)
	}
	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if detail.AnalysisQuality != "low" {
		t.Fatalf("expected fallback RCA surfaced on the incident, got quality=%s", detail.AnalysisQuality)
	}
	if len(detail.MissingData) == 0 || detail.MissingData[0] != "agent.response" {
		t.Fatalf("expected fallback missing_data, got %+v", detail.MissingData)
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

	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if detail.AnalysisSummary != "Manual RCA complete." || detail.AnalysisQuality != "medium" {
		t.Fatalf("first run result was not applied: %+v", detail)
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
	if alert.IsAnalyzing {
		t.Fatalf("huge response should clear the alert analyzing flag, got %+v", alert)
	}
	detail, _ := server.store.IncidentDetail(record.IncidentID)
	if detail.AnalysisQuality != "low" {
		t.Fatalf("huge response should surface a low-quality fallback, got quality=%s", detail.AnalysisQuality)
	}
}

func TestAnalysisRunHugeAgentRequestFailsBeforeCall(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{Status: "ok"})
	})
	annotations := map[string]string{"summary": "Queue blocked"}
	for i := 0; i < 2*int(maxAgentRequestBodyBytes)/maxAgentMapValueBytes; i++ {
		annotations[fmt.Sprintf("extra_%03d", i)] = strings.Repeat("x", maxAgentMapValueBytes+200)
	}
	incident, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "huge-agent-request"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
		},
		Annotations: annotations,
		Fingerprint: "fp-huge-agent-request",
	})
	if incident == nil || record == nil {
		t.Fatalf("seed huge request alert failed")
	}

	server.startAnalysisRun("alert", record.AlertID, "manual", "")

	run := waitForRunStatus(t, server, "manual", "failed")
	if run.Capabilities["agent"] != string(agentErrRequestTooBig) {
		t.Fatalf("expected request_too_large failure, got %+v", run)
	}
	if hit.Load() != 0 {
		t.Fatalf("oversized request should not call agent, got %d calls", hit.Load())
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
	if run.TargetType != "incident" || run.IncidentID != incident.IncidentID || run.AlertID == "" {
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

func TestDashboardAnalyzeStartsIncidentRunWhileAlertRunInFlight(t *testing.T) {
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

func TestDashboardAnalyzeLargeIncidentStartsSingleRun(t *testing.T) {
	var hit atomic.Int32
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Large incident RCA complete.",
			AnalysisDetail:  "## Root Cause\n\nCapped large incident analysis.",
			AnalysisQuality: "medium",
		})
	})
	incident, _ := seedAlert(t, server, "fp-dashboard-large")
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	extraAlerts := maxManualAnalyzeFanout + 3
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
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected large analyze 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "analysis_requested" ||
		response["mode"] != "incident" ||
		response["analysis_runs"].(float64) != 1 {
		t.Fatalf("expected single incident analysis, got %+v", response)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("large incident should start exactly one run, got %+v", runs)
	}
	waitForRunStatus(t, server, "manual", "complete")
	if hit.Load() != 1 {
		t.Fatalf("expected exactly one agent call, got %d", hit.Load())
	}
}

func TestAlertIDsNeedingAnalysisSeverityFilterAvoidsStarvation(t *testing.T) {
	store := NewStore()
	_, warn := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "w"}, Alert{
		Status: "firing", Fingerprint: "fp-w",
		Labels: map[string]string{"alertname": "A", "severity": "warning"},
	})
	store.UpsertAlert(AlertmanagerWebhook{GroupKey: "n"}, Alert{
		Status: "firing", Fingerprint: "fp-n",
		Labels: map[string]string{"alertname": "B", "severity": "none"},
	})
	allow := func(sev string) bool { return sev == "warning" || sev == "critical" }
	// The never-analyzable none alert must be filtered at the source so it can't fill
	// the batch and starve the eligible warning alert.
	ids := store.AlertIDsNeedingAnalysis(10, 0, time.Now().UTC(), allow)
	if len(ids) != 1 || ids[0] != warn.AlertID {
		t.Fatalf("expected only the warning alert, got %+v", ids)
	}
	if all := store.AlertIDsNeedingAnalysis(10, 0, time.Now().UTC(), nil); len(all) != 2 {
		t.Fatalf("nil predicate should return both severities, got %+v", all)
	}
}

func TestAlertIDsNeedingAnalysis(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	addAlert := func(id, status string, analyzing bool) {
		store.alerts[id] = &AlertRecord{AlertID: id, Status: status, IsAnalyzing: analyzing}
	}
	addRun := func(alertID, runStatus string, updated time.Time) {
		rid := "run-" + alertID
		store.analysisRuns[rid] = &AnalysisRun{RunID: rid, AlertID: alertID, Status: runStatus, UpdatedAt: updated}
	}
	addAlert("never", "firing", false) // no run -> include
	addAlert("done", "firing", false)
	addRun("done", "complete", now) // completed -> exclude
	addAlert("failedold", "firing", false)
	addRun("failedold", "failed", now.Add(-time.Hour)) // failed, cooled -> include
	addAlert("failednew", "firing", false)
	addRun("failednew", "failed", now.Add(-time.Minute)) // failed, hot -> exclude
	addAlert("resolved", "resolved", false)              // resolved -> exclude
	addAlert("inflight", "firing", true)                 // analyzing -> exclude

	got := store.AlertIDsNeedingAnalysis(10, 15*time.Minute, now, nil)
	set := map[string]bool{}
	for _, id := range got {
		set[id] = true
	}
	for _, want := range []string{"never", "failedold"} {
		if !set[want] {
			t.Fatalf("expected %q in candidates, got %v", want, got)
		}
	}
	for _, bad := range []string{"done", "failednew", "resolved", "inflight"} {
		if set[bad] {
			t.Fatalf("%q must be excluded, got %v", bad, got)
		}
	}
}

func TestBackfillPausesWhenAgentUnhealthy(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // /healthz and everything else -> down
	})
	seedAlert(t, server, "fp-backfill-agent-down")
	if started := server.backfillOnce(); started != 0 {
		t.Fatalf("backfill must pause when the agent is unhealthy, started %d", started)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 0 {
		t.Fatalf("no runs should be created while the agent is down, got %d", len(runs))
	}
}

func TestBackfillStartsRunForMissingAlert(t *testing.T) {
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Backfilled RCA.",
			AnalysisDetail:  "## Root Cause\n\nBackfill.",
			AnalysisQuality: "medium",
		})
	})
	_, record := seedAlert(t, server, "fp-backfill-missing")
	if started := server.backfillOnce(); started < 1 {
		t.Fatalf("backfill should start a run for the un-analyzed alert, started %d", started)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if detail, ok := server.store.IncidentDetail(record.IncidentID); ok && detail.AnalysisSummary != "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("backfill run never produced an RCA for the incident")
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
	approveIncidentForTest(t, server.store, priorIncident.IncidentID)
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

func TestReusedManualRunBecomesLatestSoItsResultApplies(t *testing.T) {
	// Production bug: manual re-analysis reuses its old run row IN PLACE, and the
	// "latest run" guard compares CreatedAt — so once ANY later run row existed for
	// the same alert (e.g. a comment reanalysis), every reused manual run finished
	// only to be rejected as stale ("alert RCA persistence failed"), forever.
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "fp-reuse"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "ReuseLatest"},
		Fingerprint: "fp-reuse",
	})
	alertID := record.AlertID
	incidentID := incident.IncidentID

	// 1) A manual alert-targeted run completes.
	runA, created := store.CreateAnalysisRunIfAllowed(
		"manual", "alert", alertID, incidentID, alertID, "manual", "")
	if !created {
		t.Fatalf("first manual run should be created")
	}
	store.CompleteAnalysisRun(runA.RunID, AgentAnalysisResponse{AnalysisSummary: "old", AnalysisDetail: "old"})

	// 2) A later run row for the SAME alert but a different target (comment
	//    reanalysis on the incident) is created and completes — newer CreatedAt.
	runB, created := store.CreateAnalysisRunIfAllowed(
		"comment", "incident", incidentID, incidentID, alertID, "comment", "")
	if !created {
		t.Fatalf("comment run should be created as its own row")
	}
	store.CompleteAnalysisRun(runB.RunID, AgentAnalysisResponse{AnalysisSummary: "b", AnalysisDetail: "b"})

	// 3) The operator clicks Analyze on the alert again: the manual row is reused.
	reused, created := store.CreateAnalysisRunIfAllowed(
		"manual", "alert", alertID, incidentID, alertID, "manual again", "")
	if !created {
		t.Fatalf("re-analysis should reuse and restart the manual run")
	}
	if reused.RunID != runA.RunID {
		t.Fatalf("expected in-place reuse of %s, got %s", runA.RunID, reused.RunID)
	}

	// 4) Its completed RCA must APPLY — it is the newest analysis.
	fresh := AgentAnalysisResponse{AnalysisSummary: "fresh", AnalysisDetail: "fresh"}
	store.CompleteAnalysisRun(reused.RunID, fresh)
	if !store.ApplyAnalysisForRun(reused.RunID, alertID, fresh) {
		t.Fatalf("reused run result must apply as the newest analysis, not be rejected as stale")
	}
}
