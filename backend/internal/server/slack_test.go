package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSlackAnalysisLabel(t *testing.T) {
	cases := map[int]string{
		1:  "Initial Analysis",
		2:  "2nd Analysis",
		3:  "3rd Analysis",
		4:  "4th Analysis",
		11: "11th Analysis",
		12: "12th Analysis",
		21: "21st Analysis",
		22: "22nd Analysis",
	}
	for seq, want := range cases {
		if got := slackAnalysisLabel(seq); got != want {
			t.Fatalf("slackAnalysisLabel(%d) = %q, want %q", seq, got, want)
		}
	}
}

func TestToSlackMarkdown(t *testing.T) {
	in := "## Root Cause\n\n**Bad** node\n```\n**keep**\n```"
	want := "*Root Cause*\n\n*Bad* node\n```\n**keep**\n```"
	if got := toSlackMarkdown(in); got != want {
		t.Fatalf("toSlackMarkdown = %q, want %q", got, want)
	}
}

func TestRecommendedActionsExcerpt(t *testing.T) {
	detail := "## Root Cause\n\nMIG enabled.\n\n## Recommended Actions\n\n- fix expected count\n- uncordon node\n\n## Evidence\n\nlogs"
	want := "- fix expected count\n- uncordon node"
	if got := recommendedActionsExcerpt(detail); got != want {
		t.Fatalf("recommendedActionsExcerpt = %q, want %q", got, want)
	}
	if got := recommendedActionsExcerpt("## Root Cause\n\nonly"); got != "" {
		t.Fatalf("expected empty excerpt without heading, got %q", got)
	}
}

func TestSlackValidateSuccess(t *testing.T) {
	logs := captureLogs(t)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-valid" {
			t.Fatalf("Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "team": "SRE", "user": "runai-rca"})
	}))
	defer stub.Close()

	n := &SlackNotifier{botToken: "xoxb-valid", authTestURL: stub.URL, client: stub.Client()}
	if err := n.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, "slack: bot token valid (team=SRE user=runai-rca)") {
		t.Fatalf("expected identity log, got %q", got)
	}
	if health := n.Health(); health.Auth != "ok" || health.LastOKAt == "" {
		t.Fatalf("expected ok health after validate, got %+v", health)
	}
}

func TestSlackValidateInvalidAuth(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
	}))
	defer stub.Close()

	n := &SlackNotifier{botToken: "xoxb-dead", authTestURL: stub.URL, client: stub.Client()}
	err := n.Validate()
	if err == nil {
		t.Fatal("expected invalid_auth error")
	}
	msg := err.Error()
	for _, want := range []string{"SLACK_BOT_TOKEN", "invalid_auth", "reinstalled", "reissued"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
	if health := n.Health(); health.Auth != "failed" || health.ConsecutiveFailures != 1 || !strings.Contains(health.LastError, "invalid_auth") {
		t.Fatalf("expected failed health after invalid_auth, got %+v", health)
	}
}

func TestSlackValidateDetectsAppTokenInBotSlot(t *testing.T) {
	var called bool
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer stub.Close()

	n := &SlackNotifier{botToken: "xapp-wrong", authTestURL: stub.URL, client: stub.Client()}
	err := n.Validate()
	if err == nil {
		t.Fatal("expected token shape error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "SLACK_BOT_TOKEN does not look like a bot token (xoxb-)") ||
		!strings.Contains(msg, "app-level token (xapp-) was pasted into the bot-token slot") {
		t.Fatalf("unexpected shape error: %q", msg)
	}
	if called {
		t.Fatal("Validate should not call Slack when the bot token shape is xapp-")
	}
	if health := n.Health(); health.BotTokenShape != "xapp" || health.Auth != "failed" {
		t.Fatalf("expected xapp/failed health, got %+v", health)
	}
}

// TestSlackRootThenReplyFlow drives the full delivery contract: first completed
// analysis posts the channel root message and stores its thread_ts, a manual
// re-analysis replies into that thread as "2nd Analysis", and auto follow-ups
// plus failed runs never reach Slack.
func TestSlackRootThenReplyFlow(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		payloads = append(payloads, msg)
		count := len(payloads)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": fmt.Sprintf("1710000000.%06d", count)})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		hub:   NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", appToken: "xapp-test", channelID: "C1", dashboard: "https://rca.example.com", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-flow")

	run := AnalysisRun{
		RunID:           "ANL-slack-1",
		Source:          "auto",
		Status:          "complete",
		TargetType:      "alert",
		TargetID:        record.AlertID,
		IncidentID:      incident.IncidentID,
		AlertID:         record.AlertID,
		AnalysisSummary: "GPU count drift from MIG.",
		AnalysisDetail:  "## Root Cause\n\nMIG enabled.\n\n## Recommended Actions\n\n- fix expected count",
		AnalysisQuality: "high",
	}
	server.deliverSlackAnalysis(run, incident.IncidentID)

	if len(payloads) != 1 {
		t.Fatalf("expected root message, got %d payloads", len(payloads))
	}
	root := payloads[0]
	if root["channel"] != "C1" || root["thread_ts"] != nil {
		t.Fatalf("root message should hit the channel without thread_ts: %+v", root)
	}
	if !strings.Contains(root["text"].(string), "Initial Analysis") {
		t.Fatalf("root fallback text should carry the label, got %q", root["text"])
	}
	// The Open Incident button must deep-link to the incident detail view; the
	// path shape is owned by the frontend's hash router (routeFromHash).
	rootJSON, _ := json.Marshal(root)
	wantURL := "https://rca.example.com/#/incidents/incidents/" + incident.IncidentID
	if !strings.Contains(string(rootJSON), wantURL) {
		t.Fatalf("root message should carry incident deep link %q: %s", wantURL, rootJSON)
	}
	// With an app token, the root message also carries the Re-analyze button
	// whose value routes the Socket Mode click back to this incident.
	if !strings.Contains(string(rootJSON), slackReanalyzeActionID) {
		t.Fatalf("root message should carry the Re-analyze button: %s", rootJSON)
	}
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.SlackThreadTS == "" || detail.AnalysisSeq != 1 {
		t.Fatalf("root delivery should store thread_ts and seq=1, got %+v", detail.Incident)
	}
	rootTS := detail.SlackThreadTS

	manual := run
	manual.Source = "manual"
	server.deliverSlackAnalysis(manual, incident.IncidentID)
	if len(payloads) != 2 {
		t.Fatalf("expected thread reply, got %d payloads", len(payloads))
	}
	reply := payloads[1]
	if reply["thread_ts"] != rootTS {
		t.Fatalf("reply should thread under root ts %q, got %+v", rootTS, reply)
	}
	if !strings.Contains(reply["text"].(string), "2nd Analysis") {
		t.Fatalf("reply fallback text should carry the ordinal, got %q", reply["text"])
	}

	autoFollowUp := run
	server.deliverSlackAnalysis(autoFollowUp, incident.IncidentID)
	if len(payloads) != 2 {
		t.Fatalf("auto follow-up should be skipped, got %d payloads", len(payloads))
	}

	failed := manual
	failed.Status = "failed"
	server.notifySlackAnalysis(failed, incident.IncidentID)
	if len(payloads) != 2 {
		t.Fatalf("failed run should be skipped, got %d payloads", len(payloads))
	}
	detail, _ = server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 2 {
		t.Fatalf("only notified analyses should bump seq, got %d", detail.AnalysisSeq)
	}
}

func TestSlackResolvedWebhookRepliesInInitialAnalysisThreadOnce(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		payloads = append(payloads, msg)
		count := len(payloads)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": fmt.Sprintf("1710000000.%06d", count)})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		hub:   NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	fingerprint := "fp-slack-resolved"
	incident, record := seedAlert(t, server, fingerprint)
	server.deliverSlackAnalysis(AnalysisRun{
		RunID: "ANL-resolved-root", Source: "auto", Status: "complete",
		IncidentID: incident.IncidentID, AlertID: record.AlertID,
		AnalysisSummary: "Queue quota blocked scheduling.", AnalysisQuality: "high",
	}, incident.IncidentID)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	rootTS := detail.SlackThreadTS

	resolvedAt := time.Now().UTC().Truncate(time.Second)
	webhook := AlertmanagerWebhook{GroupKey: fingerprint, Alerts: []Alert{{
		Status:      "resolved",
		Labels:      record.Labels,
		Annotations: map[string]string{"summary": "Queue recovered"},
		Fingerprint: fingerprint,
		StartsAt:    record.FiredAt.Format(time.RFC3339),
		EndsAt:      resolvedAt.Format(time.RFC3339),
	}}}
	postWebhook := func() {
		body, _ := json.Marshal(webhook)
		rec := httptest.NewRecorder()
		server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(body)))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("resolved webhook status = %d: %s", rec.Code, rec.Body.String())
		}
	}
	postWebhook()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		count := len(payloads)
		mu.Unlock()
		if count >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	payloadCount := len(payloads)
	if payloadCount != 2 {
		mu.Unlock()
		t.Fatalf("expected analysis root + resolved reply, got %d", payloadCount)
	}
	resolved := payloads[1]
	mu.Unlock()
	if resolved["thread_ts"] != rootTS {
		t.Fatalf("resolved message should reply under initial analysis %q: %+v", rootTS, resolved)
	}
	if text, _ := resolved["text"].(string); !strings.Contains(text, "Resolved") {
		t.Fatalf("resolved reply fallback text missing state: %+v", resolved)
	}

	// Alertmanager retries must not create repeated resolved comments.
	postWebhook()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("duplicate resolved webhook should be silent, got %d payloads", len(payloads))
	}
}

func TestSlackResolutionWaitsForSlowInitialAnalysis(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		payloads = append(payloads, msg)
		count := len(payloads)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": fmt.Sprintf("1720000000.%06d", count)})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		hub:   NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	fingerprint := "fp-resolved-before-analysis"
	incident, record := seedAlert(t, server, fingerprint)
	result := server.store.UpsertAlertResult(AlertmanagerWebhook{GroupKey: fingerprint}, Alert{
		Status: "resolved", Labels: record.Labels, Annotations: record.Annotations,
		Fingerprint: fingerprint, StartsAt: record.FiredAt.Format(time.RFC3339),
		EndsAt: time.Now().UTC().Format(time.RFC3339),
	})
	if !result.IncidentResolved {
		t.Fatal("expected firing to resolved transition")
	}

	// Race the resolved delivery against completion of the initial analysis.
	// Whichever takes the Slack lock first, the result must be one root and one
	// threaded resolved reply.
	server.notifySlackResolution(incident.IncidentID)
	server.deliverSlackAnalysis(AnalysisRun{
		RunID: "ANL-slow-root", Source: "auto", Status: "complete",
		IncidentID: incident.IncidentID, AlertID: record.AlertID,
		AnalysisSummary: "Analysis finished after recovery.", AnalysisQuality: "medium",
	}, incident.IncidentID)

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		count := len(payloads)
		mu.Unlock()
		if count >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 {
		t.Fatalf("expected one root and one caught-up resolved reply, got %d: %+v", len(payloads), payloads)
	}
	if payloads[0]["thread_ts"] != nil || payloads[1]["thread_ts"] != "1720000000.000001" {
		t.Fatalf("expected resolved reply under delayed root: %+v", payloads)
	}
}

func TestSlackHealthReflectsFailedAndRecoveredPosts(t *testing.T) {
	calls := 0
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000001"})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	if _, err := server.slack.post(map[string]any{"channel": "C1", "text": "one"}); err == nil {
		t.Fatal("expected failed post")
	}
	failed := getHealth(t, server).Slack
	if failed.Auth != "failed" || failed.BotTokenShape != "xoxb" || failed.ConsecutiveFailures != 1 || failed.LastErrorAt == "" {
		t.Fatalf("expected failed slack health, got %+v", failed)
	}

	if _, err := server.slack.post(map[string]any{"channel": "C1", "text": "two"}); err != nil {
		t.Fatalf("expected recovered post: %v", err)
	}
	ok := getHealth(t, server).Slack
	if ok.Auth != "ok" || ok.ConsecutiveFailures != 0 || ok.LastOKAt == "" {
		t.Fatalf("expected ok slack health after success, got %+v", ok)
	}
}

func TestSlackTransitionLogsOncePerStateChange(t *testing.T) {
	logs := captureLogs(t)
	calls := 0
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 3 {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000003"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
	}))
	defer stub.Close()

	n := &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()}
	for i := 0; i < 4; i++ {
		_, _ = n.post(map[string]any{"channel": "C1", "text": fmt.Sprintf("msg-%d", i)})
	}
	got := logs.String()
	if count := strings.Count(got, "slack: notifications are FAILING (invalid_auth)"); count != 2 {
		t.Fatalf("expected 2 failing transition logs, got %d: %s", count, got)
	}
	if count := strings.Count(got, "slack: notifications recovered"); count != 1 {
		t.Fatalf("expected 1 recovery log, got %d: %s", count, got)
	}
}

func TestSlackFailedPostDoesNotBurnAnalysisSequence(t *testing.T) {
	var payloads []map[string]any
	calls := 0
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		payloads = append(payloads, msg)
		calls++
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000002"})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		hub:   NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-failed-seq")
	run := AnalysisRun{
		RunID:           "ANL-slack-seq",
		Source:          "auto",
		Status:          "complete",
		IncidentID:      incident.IncidentID,
		AlertID:         record.AlertID,
		AnalysisSummary: "first try fails",
		AnalysisQuality: "high",
	}

	server.deliverSlackAnalysis(run, incident.IncidentID)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 0 || detail.SlackThreadTS != "" {
		t.Fatalf("failed delivery should not advance Slack state, got %+v", detail.Incident)
	}

	server.deliverSlackAnalysis(run, incident.IncidentID)
	detail, _ = server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 1 || detail.SlackThreadTS == "" {
		t.Fatalf("successful retry should store first Slack delivery, got %+v", detail.Incident)
	}
	if len(payloads) != 2 || !strings.Contains(payloads[1]["text"].(string), "Initial Analysis") {
		t.Fatalf("retry should still be labeled Initial Analysis, got %+v", payloads)
	}
}

func TestSlackQueuedDeliveryRetriesWithStableClientMessageID(t *testing.T) {
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		payloads = append(payloads, msg)
		if len(payloads) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "service_unavailable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000099"})
	}))
	defer stub.Close()

	server := &Server{
		store: NewStore(),
		hub:   NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-durable-retry")
	run := server.store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "")
	run, ok := server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "durable retry root cause",
		AnalysisDetail:  "## Recommended Actions\n\n- retry safely",
		AnalysisQuality: "high",
	})
	if !ok {
		t.Fatal("failed to complete analysis run")
	}
	delivery, ok := server.store.QueueSlackAnalysisDelivery(run.RunID, incident.IncidentID)
	if !ok || !delivery.Tracked {
		t.Fatalf("delivery was not durably queued: %+v", delivery)
	}

	server.deliverSlackAnalysisDelivery(delivery)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 0 || detail.SlackThreadTS != "" {
		t.Fatalf("failed attempt advanced incident Slack state: %+v", detail.Incident)
	}
	if pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC(), 10); len(pending) != 0 {
		t.Fatalf("delivery should respect retry backoff, got %+v", pending)
	}

	server.retryPendingSlackAnalysisDeliveries(time.Now().UTC().Add(slackDeliveryRetryPeriod + time.Second))
	detail, _ = server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 1 || detail.SlackThreadTS != "1710000000.000099" {
		t.Fatalf("successful retry did not commit root thread state: %+v", detail.Incident)
	}
	if len(payloads) != 2 || payloads[0]["client_msg_id"] == "" || payloads[0]["client_msg_id"] != payloads[1]["client_msg_id"] {
		t.Fatalf("retry must reuse a stable client_msg_id: %+v", payloads)
	}
	if pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC().Add(24*time.Hour), 10); len(pending) != 0 {
		t.Fatalf("delivered outbox entry remained pending: %+v", pending)
	}
	if server.store.BeginSlackAnalysisDelivery(run.RunID, delivery.ID) {
		t.Fatal("a concurrent stale retry was allowed to reopen a delivered outbox entry")
	}
}

func TestSlackPendingSnapshotSurvivesReusedAnalysisRun(t *testing.T) {
	server := &Server{store: NewStore(), hub: NewHub(), slack: &SlackNotifier{}}
	incident, record := seedAlert(t, server, "fp-slack-reused-run")
	run := server.store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "")
	run, _ = server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "first attempt result"})
	if _, ok := server.store.QueueSlackAnalysisDelivery(run.RunID, incident.IncidentID); !ok {
		t.Fatal("failed to queue first attempt")
	}

	reused, created := server.store.CreateAnalysisRunIfAllowed(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "reanalyze",
	)
	if !created || reused.RunID != run.RunID {
		t.Fatalf("expected run reuse, got %+v created=%v", reused, created)
	}
	if _, ok := server.store.CompleteAnalysisRun(reused.RunID, AgentAnalysisResponse{AnalysisSummary: "second attempt result"}); !ok {
		t.Fatal("failed to complete reused run")
	}

	pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC(), 10)
	if len(pending) != 1 || pending[0].Run.AnalysisSummary != "first attempt result" {
		t.Fatalf("pending delivery lost its original analysis snapshot: %+v", pending)
	}
}

func TestSlackCompletionSnapshotQueuesAfterSameRunStartsNextAttempt(t *testing.T) {
	server := &Server{store: NewStore(), hub: NewHub(), slack: &SlackNotifier{}}
	incident, record := seedAlert(t, server, "fp-slack-complete-reuse-race")
	first := server.store.CreateAnalysisRun(
		"auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "",
	)
	first, ok := server.store.CompleteAnalysisRun(first.RunID, AgentAnalysisResponse{
		AnalysisSummary: "first immutable completion",
	})
	if !ok {
		t.Fatal("failed to complete first attempt")
	}

	// Reproduce the production interleaving: CompleteAnalysisRun returned its
	// snapshot, then another request reused the row before notifySlackAnalysis
	// had a chance to queue the completed attempt.
	reused, created := server.store.CreateAnalysisRunIfAllowed(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID,
		"Manual", "reanalyze immediately",
	)
	if !created || reused.RunID != first.RunID || reused.Status != "analyzing" {
		t.Fatalf("expected the same row to start its next attempt: %+v created=%v", reused, created)
	}

	delivery, queued := server.store.QueueSlackAnalysisDeliverySnapshot(first, incident.IncidentID)
	if !queued || !delivery.Tracked {
		t.Fatalf("completed attempt was not queued after row reuse: %+v queued=%v", delivery, queued)
	}
	if delivery.Run.AnalysisSummary != "first immutable completion" || delivery.Run.Status != "complete" {
		t.Fatalf("delivery used the mutable next-attempt row instead of completion snapshot: %+v", delivery.Run)
	}
	if duplicate, queuedAgain := server.store.QueueSlackAnalysisDeliverySnapshot(first, incident.IncidentID); !queuedAgain || duplicate.ID != delivery.ID {
		t.Fatalf("same completion did not resolve to its existing outbox entry: %+v queued=%v", duplicate, queuedAgain)
	}
	pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC(), 10)
	if len(pending) != 1 || pending[0].ID != delivery.ID ||
		pending[0].Run.AnalysisSummary != "first immutable completion" {
		t.Fatalf("completion must be queued exactly once with its own snapshot: %+v", pending)
	}
	current, ok := server.store.AnalysisRun(first.RunID)
	if !ok || current.Status != "analyzing" || current.Prompt != "reanalyze immediately" {
		t.Fatalf("queueing the old completion corrupted the active attempt: %+v", current)
	}
}

func TestCompleteAnalysisRunAtomicallyPersistsSlackOutboxSnapshot(t *testing.T) {
	server := &Server{store: NewStore(), hub: NewHub(), slack: &SlackNotifier{}}
	incident, record := seedAlert(t, server, "fp-slack-complete-atomic")
	run := server.store.CreateAnalysisRun(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "",
	)
	completed, delivery, ok := server.store.CompleteAnalysisRunWithSlackDelivery(
		run.RunID,
		AgentAnalysisResponse{AnalysisSummary: "durable completion snapshot"},
		incident.IncidentID,
	)
	if !ok || delivery.ID == "" || !delivery.Tracked {
		t.Fatalf("completion and outbox were not committed together: run=%+v delivery=%+v ok=%v", completed, delivery, ok)
	}
	// No explicit QueueSlackAnalysisDelivery call follows. This is the exact
	// state a restart observes if the process exits immediately after completion.
	pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC(), 10)
	if len(pending) != 1 || pending[0].ID != delivery.ID ||
		pending[0].Run.AnalysisSummary != "durable completion snapshot" {
		t.Fatalf("completed run did not already contain its retryable snapshot: %+v", pending)
	}
	stored, exists := server.store.AnalysisRun(run.RunID)
	if !exists || stored.Status != "complete" || len(slackOutboxEntries(stored.Metadata)) != 1 {
		t.Fatalf("completion/outbox persist boundary is not atomic in the stored row: %+v", stored)
	}
}

func TestFailedApplySkipsAtomicallyQueuedSlackCompletion(t *testing.T) {
	server := &Server{store: NewStore(), hub: NewHub(), slack: &SlackNotifier{}}
	incident, record := seedAlert(t, server, "fp-slack-complete-not-applied")
	run := server.store.CreateAnalysisRun(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "",
	)
	completed, delivery, ok := server.store.CompleteAnalysisRunWithSlackDelivery(
		run.RunID,
		AgentAnalysisResponse{AnalysisSummary: "result that cannot be applied"},
		incident.IncidentID,
	)
	if !ok || delivery.ID == "" {
		t.Fatal("failed to atomically queue completion")
	}
	if _, ok := server.store.FailAnalysisRun(completed.RunID, AgentAnalysisResponse{
		AnalysisSummary: "analysis persistence failed",
	}); !ok {
		t.Fatal("failed to mark unapplied completion failed")
	}
	if pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC().Add(time.Hour), 10); len(pending) != 0 {
		t.Fatalf("unapplied completion remained eligible for Slack delivery: %+v", pending)
	}
	stored, _ := server.store.AnalysisRun(run.RunID)
	entries := slackOutboxEntries(stored.Metadata)
	if len(entries) != 1 || stringValue(entries[0]["status"]) != slackDeliverySkipped {
		t.Fatalf("unapplied completion was not durably skipped: %+v", entries)
	}
}

func TestDeletedIncidentSlackDeliveryDoesNotStarveRetryQueue(t *testing.T) {
	server := &Server{store: NewStore(), hub: NewHub(), slack: &SlackNotifier{}}
	incident, record := seedAlert(t, server, "fp-slack-deleted-incident")
	run := server.store.CreateAnalysisRun(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "",
	)
	_, delivery, ok := server.store.CompleteAnalysisRunWithSlackDelivery(
		run.RunID,
		AgentAnalysisResponse{AnalysisSummary: "result for deleted incident"},
		incident.IncidentID,
	)
	if !ok || delivery.ID == "" {
		t.Fatal("failed to queue completion")
	}
	if _, ok := server.store.SoftDeleteIncident(incident.IncidentID); !ok {
		t.Fatal("failed to move incident to trash")
	}

	server.deliverSlackAnalysisDelivery(delivery)
	if pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC().Add(24*time.Hour), 10); len(pending) != 0 {
		t.Fatalf("terminal deleted-incident delivery remained in retry queue: %+v", pending)
	}
	stored, _ := server.store.AnalysisRun(run.RunID)
	entries := slackOutboxEntries(stored.Metadata)
	if len(entries) != 1 || stringValue(entries[0]["status"]) != slackDeliverySkipped {
		t.Fatalf("deleted incident delivery was not marked terminal: %+v", entries)
	}
}

func TestDelayedEarlierAutoCompletionIsNotDroppedAfterLaterManualRoot(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	posted := make(chan struct{}, 2)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		payloads = append(payloads, msg)
		count := len(payloads)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"ts": fmt.Sprintf("1710000000.%06d", count),
		})
		posted <- struct{}{}
	}))
	defer stub.Close()
	server := &Server{
		store: NewStore(), hub: NewHub(),
		slack: &SlackNotifier{
			botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client(),
		},
	}
	incident, record := seedAlert(t, server, "fp-slack-delayed-auto")
	first := server.store.CreateAnalysisRun(
		"auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "",
	)
	first, _ = server.store.CompleteAnalysisRun(first.RunID, AgentAnalysisResponse{
		AnalysisSummary: "earlier automatic result",
	})

	manual, created := server.store.CreateAnalysisRunIfAllowed(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID,
		"Manual", "reanalyze",
	)
	if !created {
		t.Fatal("failed to start later manual attempt")
	}
	manual, _ = server.store.CompleteAnalysisRun(manual.RunID, AgentAnalysisResponse{
		AnalysisSummary: "later manual result",
	})
	manualDelivery, ok := server.store.QueueSlackAnalysisDeliverySnapshot(manual, incident.IncidentID)
	if !ok {
		t.Fatal("failed to queue later manual result")
	}
	server.deliverSlackAnalysisDelivery(manualDelivery)
	<-posted

	// notifySlackAnalysis used to return before queueing here merely because the
	// later manual result had already created a thread.
	server.notifySlackAnalysis(first, incident.IncidentID)
	select {
	case <-posted:
	case <-time.After(2 * time.Second):
		t.Fatal("earlier automatic completion was silently dropped after manual root")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 2 || payloads[1]["thread_ts"] != "1710000000.000001" {
		t.Fatalf("delayed earlier completion was not retained as a thread reply: %+v", payloads)
	}
	replyJSON, _ := json.Marshal(payloads[1])
	if !strings.Contains(string(replyJSON), "earlier automatic result") {
		t.Fatalf("thread reply did not use the earlier immutable snapshot: %+v", payloads[1])
	}
}

func TestSlackPendingDeliveriesStayInIncidentAttemptOrder(t *testing.T) {
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		payloads = append(payloads, msg)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": fmt.Sprintf("1710000000.%06d", len(payloads))})
	}))
	defer stub.Close()
	server := &Server{
		store: NewStore(), hub: NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-delivery-order")
	firstRun := server.store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "")
	firstRun, _ = server.store.CompleteAnalysisRun(firstRun.RunID, AgentAnalysisResponse{AnalysisSummary: "first result"})
	firstDelivery, ok := server.store.QueueSlackAnalysisDelivery(firstRun.RunID, incident.IncidentID)
	if !ok {
		t.Fatal("failed to queue first delivery")
	}

	secondRun, created := server.store.CreateAnalysisRunIfAllowed(
		"manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "reanalyze",
	)
	if !created {
		t.Fatal("failed to start reused analysis run")
	}
	secondRun, _ = server.store.CompleteAnalysisRun(secondRun.RunID, AgentAnalysisResponse{AnalysisSummary: "second result"})
	secondDelivery, ok := server.store.QueueSlackAnalysisDelivery(secondRun.RunID, incident.IncidentID)
	if !ok || secondDelivery.ID == firstDelivery.ID {
		t.Fatalf("failed to queue distinct second delivery: first=%+v second=%+v", firstDelivery, secondDelivery)
	}

	server.deliverSlackAnalysisDelivery(secondDelivery)
	if len(payloads) != 0 {
		t.Fatalf("later analysis overtook pending earlier delivery: %+v", payloads)
	}
	server.deliverSlackAnalysisDelivery(firstDelivery)
	server.deliverSlackAnalysisDelivery(secondDelivery)
	if len(payloads) != 2 || !strings.Contains(payloads[0]["text"].(string), "Initial Analysis") ||
		!strings.Contains(payloads[1]["text"].(string), "2nd Analysis") {
		t.Fatalf("deliveries were not emitted in analysis order: %+v", payloads)
	}
	if payloads[1]["thread_ts"] != payloads[0]["ts"] && payloads[1]["thread_ts"] != "1710000000.000001" {
		t.Fatalf("second delivery was not threaded under the first: %+v", payloads)
	}
}

func TestSlackMissingPersistedParentRetriesAsReplacementRoot(t *testing.T) {
	var payloads []map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		payloads = append(payloads, msg)
		if len(payloads) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "thread_not_found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000888"})
	}))
	defer stub.Close()
	server := &Server{
		store: NewStore(), hub: NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-missing-parent")
	server.store.mu.Lock()
	server.store.incidents[incident.IncidentID].SlackThreadTS = "1700000000.000001"
	server.store.incidents[incident.IncidentID].AnalysisSeq = 3
	server.store.mu.Unlock()
	run := server.store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "")
	run, _ = server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "fresh result"})
	delivery, _ := server.store.QueueSlackAnalysisDelivery(run.RunID, incident.IncidentID)

	server.deliverSlackAnalysisDelivery(delivery)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.SlackThreadTS != "" || detail.AnalysisSeq != 0 {
		t.Fatalf("missing parent was not cleared for recovery: %+v", detail.Incident)
	}
	server.retryPendingSlackAnalysisDeliveries(time.Now().UTC().Add(slackDeliveryRetryPeriod + time.Second))
	detail, _ = server.store.IncidentDetail(incident.IncidentID)
	if detail.SlackThreadTS != "1710000000.000888" || detail.AnalysisSeq != 1 {
		t.Fatalf("replacement root was not committed: %+v", detail.Incident)
	}
	if len(payloads) != 2 || payloads[1]["thread_ts"] != nil ||
		!strings.Contains(payloads[1]["text"].(string), "Initial Analysis") {
		t.Fatalf("retry did not become a replacement root: %+v", payloads)
	}
}

func TestSlackSuccessWithoutTimestampKeepsDeliveryPending(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer stub.Close()
	server := &Server{
		store: NewStore(), hub: NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-missing-ts")
	run := server.store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Auto", "")
	run, _ = server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "root cause"})
	delivery, ok := server.store.QueueSlackAnalysisDelivery(run.RunID, incident.IncidentID)
	if !ok {
		t.Fatal("failed to queue delivery")
	}

	server.deliverSlackAnalysisDelivery(delivery)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 0 || detail.SlackThreadTS != "" {
		t.Fatalf("timestamp-less response committed Slack state: %+v", detail.Incident)
	}
	if pending := server.store.PendingSlackAnalysisDeliveries(time.Now().UTC().Add(time.Hour), 10); len(pending) != 1 {
		t.Fatalf("timestamp-less response should remain retryable: %+v", pending)
	}
}

func TestSlackMissingLegacyThreadStartsNewVisibleSequence(t *testing.T) {
	var payload map[string]any
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&payload)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "1710000000.000777"})
	}))
	defer stub.Close()
	server := &Server{
		store: NewStore(), hub: NewHub(),
		slack: &SlackNotifier{botToken: "xoxb-test", channelID: "C1", apiURL: stub.URL, client: stub.Client()},
	}
	incident, record := seedAlert(t, server, "fp-slack-legacy-thread")
	server.store.mu.Lock()
	server.store.incidents[incident.IncidentID].AnalysisSeq = 4
	server.store.mu.Unlock()
	run := server.store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "Manual", "")
	run, _ = server.store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "new root"})
	delivery, _ := server.store.QueueSlackAnalysisDelivery(run.RunID, incident.IncidentID)

	server.deliverSlackAnalysisDelivery(delivery)
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisSeq != 1 || detail.SlackThreadTS != "1710000000.000777" {
		t.Fatalf("replacement root did not reset visible sequence: %+v", detail.Incident)
	}
	if !strings.Contains(payload["text"].(string), "Initial Analysis") {
		t.Fatalf("replacement root used an orphaned sequence label: %+v", payload)
	}
}

// TestSlackReanalyzeButtonClick drives the Socket Mode interactive payload end
// to end: button click → manual incident run → immediate thread note → the
// completed re-analysis replying into the same thread.
func TestSlackReanalyzeButtonClick(t *testing.T) {
	var mu sync.Mutex
	var payloads []map[string]any
	slackStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		_ = json.NewDecoder(r.Body).Decode(&msg)
		mu.Lock()
		payloads = append(payloads, msg)
		count := len(payloads)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": fmt.Sprintf("1710000000.%06d", count)})
	}))
	defer slackStub.Close()
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, 0, len(payloads))
		for _, p := range payloads {
			raw, _ := json.Marshal(p)
			out = append(out, string(raw))
		}
		return out
	}

	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Re-analysis via Slack button.",
			AnalysisDetail:  "## Root Cause\n\nStill MIG drift.",
			AnalysisQuality: "high",
		})
	})
	server.slack = &SlackNotifier{botToken: "xoxb-test", appToken: "xapp-test", channelID: "C1", apiURL: slackStub.URL, client: slackStub.Client()}
	incident, record := seedAlert(t, server, "fp-slack-button")

	// Root message exists (first analysis already delivered).
	server.deliverSlackAnalysis(AnalysisRun{
		RunID: "ANL-root", Source: "auto", Status: "complete",
		IncidentID: incident.IncidentID, AlertID: record.AlertID,
		AnalysisSummary: "Initial cause.", AnalysisQuality: "high",
	}, incident.IncidentID)

	click := fmt.Sprintf(`{
		"type": "block_actions",
		"user": {"username": "bohyun"},
		"actions": [{"action_id": %q, "value": %q}]
	}`, slackReanalyzeActionID, incident.IncidentID)
	server.handleSlackInteractive(json.RawMessage(click))

	run := waitForRunStatus(t, server, "manual", "complete")
	if run.TargetType != "incident" || run.IncidentID != incident.IncidentID {
		t.Fatalf("button click should start an incident run, got %+v", run)
	}

	// Expect 3 messages total: root, started-note, completion reply (note and
	// reply are async relative to each other, so match by content).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(snapshot()) < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	msgs := snapshot()
	if len(msgs) != 3 {
		t.Fatalf("expected root + note + reply, got %d: %v", len(msgs), msgs)
	}
	var sawNote, sawReply bool
	for _, raw := range msgs[1:] {
		if strings.Contains(raw, "Re-analysis started by @bohyun") {
			sawNote = true
		}
		if strings.Contains(raw, "2nd Analysis") {
			sawReply = true
		}
		if !strings.Contains(raw, "thread_ts") {
			t.Fatalf("follow-up message should be threaded: %s", raw)
		}
	}
	if !sawNote || !sawReply {
		t.Fatalf("expected started note and 2nd Analysis reply, got %v", msgs[1:])
	}

	// An unrelated action id must be ignored.
	server.handleSlackInteractive(json.RawMessage(`{"type":"block_actions","actions":[{"action_id":"other","value":"x"}]}`))
	if len(snapshot()) != 3 {
		t.Fatalf("unrelated actions should not post messages")
	}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func getHealth(t *testing.T, server *Server) struct {
	Slack SlackHealth `json:"slack"`
} {
	t.Helper()
	rr := httptest.NewRecorder()
	server.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rr.Code)
	}
	var body struct {
		Slack SlackHealth `json:"slack"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	return body
}
