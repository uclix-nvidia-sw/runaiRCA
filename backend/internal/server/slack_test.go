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
