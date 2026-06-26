package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestAgentRequestTimeoutConfig(t *testing.T) {
	t.Setenv("AGENT_REQUEST_TIMEOUT_SECONDS", "7")
	server := NewServer()

	if server.agentRequestTimeout != 7*time.Second {
		t.Fatalf("expected agent request timeout from env, got %s", server.agentRequestTimeout)
	}
	if server.client.Timeout != 7*time.Second {
		t.Fatalf("expected http client timeout from env, got %s", server.client.Timeout)
	}
}

func TestChatRouteProxiesContextualRCARequestToAgent(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan ChatRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat" {
			t.Fatalf("unexpected agent path: %s", r.URL.Path)
		}
		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent chat request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(ChatResponse{
			Status:         "ok",
			Answer:         "Agent compared this with prior gpu-a quota RCA.",
			ConversationID: "chat-agent",
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai",
			"workload":  "trainer",
		},
		Annotations: map[string]string{"summary": "Workload pending"},
		Fingerprint: "fp-chat",
	})
	server.store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:AI queue gpu-a is saturated.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota is exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	body, _ := json.Marshal(ChatRequest{
		Message:    "유사 RCA랑 비교해줘",
		IncidentID: incident.IncidentID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if response.ConversationID != "chat-agent" || !strings.Contains(response.Answer, "prior gpu-a") {
		t.Fatalf("unexpected chat response: %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.IncidentID != incident.IncidentID {
		t.Fatalf("incident id was not forwarded: %+v", agentReq)
	}
	if !strings.Contains(agentReq.IncidentContent, "gpu-a is saturated") {
		t.Fatalf("incident RCA content was not attached: %s", agentReq.IncidentContent)
	}
	if _, ok := agentReq.Context["rca_memory"]; !ok {
		t.Fatalf("expected RCA memory context, got %+v", agentReq.Context)
	}
}

func TestCommentCreatesAnalysisRun(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Comment-driven RCA refined the queue diagnosis.",
			AnalysisDetail:  "## Root Cause\n\nOperator comment was included in reanalysis.",
			AnalysisQuality: "high",
			Capabilities:    map[string]string{"analysis": "ok", "runai": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "comment-run"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-comment-run",
	})
	payload, _ := json.Marshal(CommentRequest{
		Body:   "Please re-check runai-backend scheduler logs before finalizing.",
		Author: "operator",
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/comments",
		bytes.NewReader(payload),
	)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected comment 200, got %d: %s", rec.Code, rec.Body.String())
	}
	agentReq := <-agentReqCh
	if agentReq.AnalysisType != "comment" {
		t.Fatalf("expected comment analysis type, got %+v", agentReq)
	}
	if !strings.Contains(agentReq.Alert.Annotations["operator_prompt"], "scheduler logs") {
		t.Fatalf("operator comment was not sent to agent: %+v", agentReq.Alert.Annotations)
	}
	run := waitForAnalysisRun(t, server, "comment")
	if run.Status != "complete" || !strings.Contains(run.AnalysisSummary, "Comment-driven") {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestChatAnalysisRequestCreatesAnalysisRun(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Chat-requested RCA completed.",
			AnalysisDetail:  "## Root Cause\n\nChat requested a separate analysis item.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat-run"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-chat-run",
	})
	payload, _ := json.Marshal(ChatRequest{
		Message:    "이 RCA 분석 다시 돌려줘",
		IncidentID: incident.IncidentID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected chat 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if response.AnalysisRun == nil || response.AnalysisRun.Source != "chat" {
		t.Fatalf("expected chat analysis run in response: %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.AnalysisType != "chat" {
		t.Fatalf("expected chat analysis type, got %+v", agentReq)
	}
	run := waitForAnalysisRun(t, server, "chat")
	if run.Status != "complete" || !strings.Contains(run.AnalysisSummary, "Chat-requested") {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestFeedbackAndSimilarIncidentMemory(t *testing.T) {
	store := NewStore()
	priorAlert := Alert{
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
		Annotations: map[string]string{"summary": "Workload pending because GPU quota is exhausted"},
		Fingerprint: "fp-prior",
	}
	priorIncident, priorRecord := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "prior"}, priorAlert)
	store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:ai queue gpu-a was saturated and quota blocked scheduling.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota was exhausted in queue gpu-a.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	summary, ok, err := store.AddFeedback("incident", priorIncident.IncidentID, FeedbackRequest{
		Vote:    "up",
		Comment: "Matched the quota saturation incident we saw last week.",
		Author:  "operator",
	})
	if err != nil || !ok {
		t.Fatalf("feedback failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || len(summary.Comments) != 1 {
		t.Fatalf("unexpected feedback summary: %+v", summary)
	}

	currentAlert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer-v2",
		},
		Annotations: map[string]string{"summary": "Workload pending while waiting for GPU quota"},
		Fingerprint: "fp-current",
	}
	currentIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "current"}, currentAlert)
	similar := store.SimilarIncidentsForAlert(currentAlert, currentIncident.IncidentID, 5)
	if len(similar) == 0 {
		t.Fatalf("expected similar incident")
	}
	if similar[0].IncidentID != priorIncident.IncidentID {
		t.Fatalf("expected prior incident first, got %+v", similar[0])
	}
	if similar[0].PositiveFeedback != 1 || similar[0].CommentCount != 1 {
		t.Fatalf("expected feedback metadata on similar result, got %+v", similar[0])
	}
	hints := store.FeedbackHintsForAlert(currentAlert, currentIncident.IncidentID, 5)
	if len(hints) == 0 {
		t.Fatalf("expected feedback hints")
	}
	foundComment := false
	for _, hint := range hints {
		if strings.Contains(hint.Text, "quota saturation") {
			foundComment = true
			break
		}
	}
	if !foundComment {
		t.Fatalf("expected operator comment in feedback hints, got %+v", hints)
	}
	search := store.SearchIncidentMemory("gpu quota saturated scheduling", 5)
	if len(search) == 0 || search[0].IncidentID != priorIncident.IncidentID {
		t.Fatalf("expected embedding search to return prior incident, got %+v", search)
	}
}

func TestDenseEmbeddingIsDeterministicAndNormalized(t *testing.T) {
	text := "Run:AI GPU quota saturated scheduling blocked"
	a := denseEmbedding(text)
	b := denseEmbedding(text)
	if len(a) != embeddingDim {
		t.Fatalf("expected embedding dimension %d, got %d", embeddingDim, len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("embedding is not deterministic at index %d: %v vs %v", i, a[i], b[i])
		}
	}
	var norm float64
	for _, v := range a {
		norm += float64(v) * float64(v)
	}
	if math.Abs(norm-1) > 1e-5 {
		t.Fatalf("embedding should be L2-normalized, got norm^2=%v", norm)
	}
	if literal := embeddingLiteral(a); literal[0] != '[' || literal[len(literal)-1] != ']' {
		t.Fatalf("embedding literal must be bracketed for pgvector, got %q", literal)
	}
	if empty := denseEmbedding(""); len(empty) != embeddingDim {
		t.Fatalf("empty text should still yield a zero vector of the right dim, got %d", len(empty))
	}
}

func TestReapStaleAnalyzingRunsMarksFailed(t *testing.T) {
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "reap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-reap",
	})
	// Simulate a run left "analyzing" by a previous process (no goroutine ran).
	stale := store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	done := store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	store.CompleteAnalysisRun(done.RunID, AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})

	reaped := store.ReapStaleAnalyzingRuns()
	if reaped != 1 {
		t.Fatalf("expected exactly 1 stale run reaped, got %d", reaped)
	}

	var staleAfter, doneAfter AnalysisRun
	for _, run := range store.ListAnalysisRuns() {
		switch run.RunID {
		case stale.RunID:
			staleAfter = run
		case done.RunID:
			doneAfter = run
		}
	}
	if staleAfter.Status != "failed" {
		t.Fatalf("stale run should be failed, got %q", staleAfter.Status)
	}
	if len(staleAfter.Warnings) == 0 || staleAfter.Capabilities["agent"] != "interrupted" {
		t.Fatalf("stale run missing interruption warning/capability: %+v", staleAfter)
	}
	if doneAfter.Status != "complete" {
		t.Fatalf("completed run must be untouched, got %q", doneAfter.Status)
	}

	alert, _ := store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing {
		t.Fatalf("alert is_analyzing flag should be cleared after reap")
	}
	if detail, ok := store.IncidentDetail(incident.IncidentID); !ok || detail.IsAnalyzing {
		t.Fatalf("incident is_analyzing flag should be cleared after reap")
	}
}

func waitForAnalysisRun(t *testing.T, server *Server, source string) AnalysisRun {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, run := range server.store.ListAnalysisRuns() {
			if run.Source == source && run.Status != "analyzing" {
				return run
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("analysis run with source %q did not complete: %+v", source, server.store.ListAnalysisRuns())
	return AnalysisRun{}
}

func TestAlertListIncludesSimilarIncidentMemory(t *testing.T) {
	server := NewServer()
	priorIncident, priorRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "list-prior"}, Alert{
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
		Annotations: map[string]string{"summary": "Workload pending because GPU quota is exhausted"},
		Fingerprint: "fp-list-prior",
	})
	server.store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:AI queue gpu-a was saturated and quota blocked scheduling.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota was exhausted in queue gpu-a.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	_, currentRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "list-current"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer-v2",
		},
		Annotations: map[string]string{"summary": "Workload pending while waiting for GPU quota"},
		Fingerprint: "fp-list-current",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data []AlertRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode alert list response: %v", err)
	}
	foundCurrent := false
	for _, alert := range response.Data {
		if alert.AlertID != currentRecord.AlertID {
			continue
		}
		foundCurrent = true
		if len(alert.SimilarIncidents) == 0 {
			t.Fatalf("expected similar incidents in alert list response")
		}
		if alert.SimilarIncidents[0].IncidentID != priorIncident.IncidentID {
			t.Fatalf("expected prior incident first, got %+v", alert.SimilarIncidents[0])
		}
	}
	if !foundCurrent {
		t.Fatalf("current alert missing from list response")
	}
}

func TestFeedbackVoteToggleCancelsSameActorVote(t *testing.T) {
	store := NewStore()
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "toggle"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-toggle",
	})

	summary, ok, err := store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "up",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("upvote failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || summary.Negative != 0 || summary.MyVote != "up" {
		t.Fatalf("unexpected upvote summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "none",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("cancel failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 0 || summary.Negative != 0 || summary.MyVote != "" {
		t.Fatalf("unexpected cancel summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "down",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("downvote failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 0 || summary.Negative != 1 || summary.MyVote != "down" {
		t.Fatalf("unexpected downvote summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "up",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("switch failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || summary.Negative != 0 || summary.MyVote != "up" {
		t.Fatalf("unexpected switched summary: %+v", summary)
	}
}

func TestFeedbackRoutesReturnSummary(t *testing.T) {
	server := NewServer()
	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "route"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "critical",
			"namespace": "runai",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-route",
	})
	payload, _ := json.Marshal(FeedbackRequest{
		Vote:    "down",
		Comment: "Need scheduler logs before trusting this RCA.",
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/feedback",
		bytes.NewReader(payload),
	)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode feedback response: %v", err)
	}
	if response.Data.Negative != 1 || len(response.Data.Comments) != 1 {
		t.Fatalf("unexpected feedback response: %+v", response.Data)
	}
	commentID := response.Data.Comments[0].CommentID

	updatePayload, _ := json.Marshal(CommentRequest{Body: "Scheduler logs showed a different queue path."})
	updateReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/incidents/"+incident.IncidentID+"/comments/"+commentID,
		bytes.NewReader(updatePayload),
	)
	updateRec := httptest.NewRecorder()

	server.routes().ServeHTTP(updateRec, updateReq)

	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected comment update 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	var updateResponse struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(updateRec.Body.Bytes(), &updateResponse); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updateResponse.Data.Comments[0].Body != "Scheduler logs showed a different queue path." {
		t.Fatalf("comment was not updated: %+v", updateResponse.Data.Comments[0])
	}

	deleteReq := httptest.NewRequest(
		http.MethodDelete,
		"/api/v1/incidents/"+incident.IncidentID+"/comments/"+commentID,
		nil,
	)
	deleteRec := httptest.NewRecorder()

	server.routes().ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected comment delete 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	searchBody, _ := json.Marshal(EmbeddingSearchRequest{Query: "queue blocked scheduler", Limit: 3})
	searchReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/embeddings/search",
		bytes.NewReader(searchBody),
	)
	searchRec := httptest.NewRecorder()

	server.routes().ServeHTTP(searchRec, searchReq)

	if searchRec.Code != http.StatusOK {
		t.Fatalf("expected embedding search 200, got %d: %s", searchRec.Code, searchRec.Body.String())
	}
}
