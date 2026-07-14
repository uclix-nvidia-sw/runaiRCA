// Slack notifier: incident-level analysis summaries only, into one channel.
//
// Delivery rules:
//   - The FIRST completed analysis of an incident posts a root channel message
//     ("Initial Analysis") and stores its thread_ts on the incident row, so
//     threading survives restarts.
//   - Later completed operator-driven re-analyses (manual/comment/feedback/chat)
//     reply into that thread ("2nd Analysis", "3rd Analysis", ...).
//   - Alertmanager firing -> resolved transitions reply into the initial
//     analysis thread instead of creating another channel-level message.
//   - Follow-up auto/backfill completions and failed runs never reach Slack:
//     raw alert notifications already arrive via other channels, and the
//     dashboard keeps the full per-alert history.
//
// A bot token (not an incoming webhook) is required because chat.postMessage
// returns the message ts needed to thread replies.
//
// The root message also carries a "Re-analyze" button when SLACK_APP_TOKEN is
// set; clicks arrive over Socket Mode (slack_socket.go) and start a manual
// incident run whose result lands in the thread like any other re-analysis.
//
// Env:
//
//	SLACK_BOT_TOKEN  - xoxb- bot token with chat:write (invite the bot to the channel)
//	SLACK_CHANNEL_ID - channel to post incident summaries into
//	SLACK_APP_TOKEN  - optional xapp- app-level token (connections:write); enables
//	                   the in-message Re-analyze button via Socket Mode
//	DASHBOARD_URL    - optional external dashboard URL; adds an "Open Incident" button
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type SlackNotifier struct {
	botToken           string
	appToken           string
	channelID          string
	dashboard          string
	apiURL             string
	authTestURL        string
	connectionsOpenURL string
	client             *http.Client
	// ponytail: one global mutex serializes deliveries so the root message is
	// created exactly once per incident; per-incident locks if volume matters.
	mu sync.Mutex
	// lastResolvedNotification deduplicates the race between a resolved webhook
	// and a still-finishing initial analysis. Access is protected by mu.
	lastResolvedNotification map[string]string

	stateMu             sync.Mutex
	lastOKAt            time.Time
	lastErr             string
	lastErrAt           time.Time
	consecutiveFailures int
}

type SlackHealth struct {
	Configured          bool   `json:"configured"`
	BotTokenShape       string `json:"bot_token_shape"`
	Auth                string `json:"auth"`
	LastError           string `json:"last_error"`
	LastErrorAt         string `json:"last_error_at"`
	LastOKAt            string `json:"last_ok_at"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
}

func NewSlackNotifierFromEnv() *SlackNotifier {
	return &SlackNotifier{
		botToken:           strings.TrimSpace(os.Getenv("SLACK_BOT_TOKEN")),
		appToken:           strings.TrimSpace(os.Getenv("SLACK_APP_TOKEN")),
		channelID:          strings.TrimSpace(os.Getenv("SLACK_CHANNEL_ID")),
		dashboard:          strings.TrimSpace(os.Getenv("DASHBOARD_URL")),
		apiURL:             "https://slack.com/api/chat.postMessage",
		authTestURL:        "https://slack.com/api/auth.test",
		connectionsOpenURL: "https://slack.com/api/apps.connections.open",
		client:             &http.Client{Timeout: 10 * time.Second},
	}
}

// IsConfigured is nil-safe so tests building Server literals never notify.
func (n *SlackNotifier) IsConfigured() bool {
	return n != nil && n.botToken != "" && n.channelID != ""
}

func (n *SlackNotifier) Validate() error {
	if n == nil {
		return nil
	}
	if n.appToken != "" && !strings.HasPrefix(n.appToken, "xapp-") {
		log.Printf("slack: SLACK_APP_TOKEN does not look like an app-level token (xapp-)")
	}
	if n.botToken == "" {
		return nil
	}
	if !strings.HasPrefix(n.botToken, "xoxb-") {
		msg := "SLACK_BOT_TOKEN does not look like a bot token (xoxb-)"
		if strings.HasPrefix(n.botToken, "xapp-") {
			msg += "; an app-level token (xapp-) was pasted into the bot-token slot"
		}
		err := errors.New(msg)
		n.recordSlackFailure(err)
		return err
	}
	req, err := http.NewRequest(http.MethodPost, first(n.authTestURL, "https://slack.com/api/auth.test"), nil)
	if err != nil {
		err = fmt.Errorf("validate SLACK_BOT_TOKEN with Slack: %w", err)
		n.recordSlackFailure(err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.botToken)
	resp, err := n.httpClient().Do(req)
	if err != nil {
		err = fmt.Errorf("validate SLACK_BOT_TOKEN with Slack: %w", err)
		n.recordSlackFailure(err)
		return err
	}
	defer resp.Body.Close()
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
		User  string `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		err = fmt.Errorf("validate SLACK_BOT_TOKEN with Slack: parse auth.test response: %w", err)
		n.recordSlackFailure(err)
		return err
	}
	if !parsed.OK {
		err := fmt.Errorf("SLACK_BOT_TOKEN rejected by Slack (%s) — if the Slack app was reinstalled the xoxb- token was reissued; update the secret", first(parsed.Error, "unknown"))
		n.recordSlackFailure(err)
		return err
	}
	n.recordSlackOK(time.Now().UTC())
	log.Printf("slack: bot token valid (team=%s user=%s)", parsed.Team, parsed.User)
	return nil
}

func (n *SlackNotifier) Health() SlackHealth {
	if n == nil {
		return SlackHealth{BotTokenShape: "missing", Auth: "unknown"}
	}
	h := SlackHealth{
		Configured:    n.IsConfigured(),
		BotTokenShape: n.botTokenShape(),
		Auth:          "unknown",
	}
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if !n.lastOKAt.IsZero() {
		h.LastOKAt = n.lastOKAt.UTC().Format(time.RFC3339)
	}
	if !n.lastErrAt.IsZero() {
		h.LastError = n.lastErr
		h.LastErrorAt = n.lastErrAt.UTC().Format(time.RFC3339)
	}
	h.ConsecutiveFailures = n.consecutiveFailures
	switch {
	case n.failingLocked():
		h.Auth = "failed"
	case !n.lastOKAt.IsZero():
		h.Auth = "ok"
	}
	return h
}

func (n *SlackNotifier) botTokenShape() string {
	switch {
	case n == nil || n.botToken == "":
		return "missing"
	case strings.HasPrefix(n.botToken, "xoxb-"):
		return "xoxb"
	case strings.HasPrefix(n.botToken, "xapp-"):
		return "xapp"
	default:
		return "other"
	}
}

// slackReplySources are run sources that represent an operator asking for a
// fresh analysis; only these become thread replies after the root message.
var slackReplySources = map[string]bool{"manual": true, "comment": true, "feedback": true, "chat": true}

// notifySlackAnalysis posts a completed run to Slack per the rules above.
// Fire-and-forget: errors are logged and never affect run persistence.
func (s *Server) notifySlackAnalysis(run AnalysisRun, incidentID string) {
	if !s.slack.IsConfigured() || incidentID == "" || run.Status != "complete" {
		return
	}
	go s.deliverSlackAnalysis(run, incidentID)
}

func (s *Server) deliverSlackAnalysis(run AnalysisRun, incidentID string) {
	s.slack.mu.Lock()
	defer s.slack.mu.Unlock()
	detail, ok := s.store.IncidentDetail(incidentID)
	if !ok {
		return
	}
	threadTS := detail.SlackThreadTS
	if threadTS != "" && !slackReplySources[run.Source] {
		return
	}
	seq := detail.AnalysisSeq + 1
	msg := s.slack.buildAnalysisMessage(detail, run, seq, threadTS)
	ts, err := s.slack.post(msg)
	if err != nil {
		log.Printf("slack notify failed for incident %s: %v", incidentID, err)
		return
	}
	if _, ok := s.store.BumpIncidentAnalysisSeq(incidentID); !ok {
		return
	}
	if threadTS == "" {
		s.store.SetIncidentSlackThread(incidentID, ts)
		detail.SlackThreadTS = ts
		// Short-lived alerts may resolve before their initial analysis finishes.
		// Once the root exists, catch up the pending resolved state in its thread.
		if detail.Status == "resolved" {
			s.deliverSlackResolutionLocked(detail)
		}
	}
}

// notifySlackResolution posts only the transition detected by Store. It is
// intentionally fire-and-forget, matching analysis notification delivery.
func (s *Server) notifySlackResolution(incidentID string) {
	if !s.slack.IsConfigured() || incidentID == "" {
		return
	}
	go s.deliverSlackResolution(incidentID)
}

func (s *Server) deliverSlackResolution(incidentID string) {
	s.slack.mu.Lock()
	defer s.slack.mu.Unlock()
	detail, ok := s.store.IncidentDetail(incidentID)
	if !ok {
		return
	}
	s.deliverSlackResolutionLocked(detail)
}

func (s *Server) deliverSlackResolutionLocked(detail *IncidentDetail) {
	if detail.Status != "resolved" || detail.SlackThreadTS == "" {
		return
	}
	resolvedKey := "unknown"
	if detail.ResolvedAt != nil {
		resolvedKey = detail.ResolvedAt.UTC().Format(time.RFC3339Nano)
	}
	if s.slack.lastResolvedNotification[detail.IncidentID] == resolvedKey {
		return
	}
	if _, err := s.slack.post(s.slack.buildResolutionMessage(detail)); err != nil {
		log.Printf("slack resolved notify failed for incident %s: %v", detail.IncidentID, err)
		return
	}
	if s.slack.lastResolvedNotification == nil {
		s.slack.lastResolvedNotification = make(map[string]string)
	}
	s.slack.lastResolvedNotification[detail.IncidentID] = resolvedKey
}

func (n *SlackNotifier) post(msg map[string]any) (string, error) {
	payload, err := json.Marshal(msg)
	if err != nil {
		err = fmt.Errorf("marshal slack message: %w", err)
		n.recordSlackFailure(err)
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, n.apiURL, bytes.NewReader(payload))
	if err != nil {
		n.recordSlackFailure(err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.botToken)
	resp, err := n.httpClient().Do(req)
	if err != nil {
		n.recordSlackFailure(err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		n.recordSlackFailure(err)
		return "", err
	}
	var parsed struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		err = fmt.Errorf("parse slack response: %w", err)
		n.recordSlackFailure(err)
		return "", err
	}
	if !parsed.OK {
		err := fmt.Errorf("slack API error: %s", first(parsed.Error, "unknown"))
		n.recordSlackFailure(err)
		return "", err
	}
	n.recordSlackOK(time.Now().UTC())
	return parsed.TS, nil
}

func (n *SlackNotifier) httpClient() *http.Client {
	if n.client != nil {
		return n.client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (n *SlackNotifier) recordSlackOK(at time.Time) {
	n.stateMu.Lock()
	wasFailing := n.failingLocked()
	n.lastOKAt = at
	n.consecutiveFailures = 0
	n.stateMu.Unlock()
	if wasFailing {
		log.Printf("slack: notifications recovered at %s", at.UTC().Format(time.RFC3339))
	}
}

func (n *SlackNotifier) recordSlackFailure(err error) {
	at := time.Now().UTC()
	n.stateMu.Lock()
	wasFailing := n.failingLocked()
	n.lastErr = err.Error()
	n.lastErrAt = at
	n.consecutiveFailures++
	n.stateMu.Unlock()
	if !wasFailing {
		log.Printf("slack: notifications are FAILING (%s) since %s — check SLACK_BOT_TOKEN (see docs/OPERATIONS.md runbook)", slackFailureReason(err), at.Format(time.RFC3339))
	}
}

func (n *SlackNotifier) failingLocked() bool {
	return !n.lastErrAt.IsZero() && (n.lastOKAt.IsZero() || !n.lastOKAt.After(n.lastErrAt))
}

func slackFailureReason(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid_auth"):
		return "invalid_auth"
	case strings.Contains(msg, "does not look like a bot token"):
		return "token_shape"
	default:
		return "request_failed"
	}
}

// buildAnalysisMessage renders a root message (big title + severity color
// bar) when threadTS is empty, or a purple thread reply otherwise. Only the
// summary and the first recommended actions ship to Slack; the full report
// stays on the dashboard.
func (n *SlackNotifier) buildAnalysisMessage(detail *IncidentDetail, run AnalysisRun, seq int, threadTS string) map[string]any {
	label := slackAnalysisLabel(seq)
	rep := representativeAlert(detail, run.AlertID)
	color, emoji := slackSeverityStyle(detail.Severity, detail.Status)

	rootCause := strings.TrimSpace(first(run.AnalysisSummary, detail.AnalysisSummary))
	if rootCause == "" {
		rootCause = "_analysis produced no summary — see the dashboard for details_"
	}

	att := []any{}
	if threadTS != "" {
		color = "#6f42c1"
		att = append(att, slackSection(fmt.Sprintf("*🔁 %s* · %s", label, sourceTitle(run.Source))))
	}
	att = append(att, slackSection("*🧠 Root Cause*\n"+toSlackMarkdown(excerpt(rootCause, 600))))
	if threadTS == "" {
		att = append(att, slackFields(detail, rep))
	}
	if rec := recommendedActionsExcerpt(first(run.AnalysisDetail, detail.AnalysisDetail)); rec != "" {
		att = append(att, slackSection("*🛠 Recommended Action*\n"+toSlackMarkdown(excerpt(rec, 500))))
	}
	if buttons := n.actionButtons(detail.IncidentID); len(buttons) > 0 && threadTS == "" {
		att = append(att, map[string]any{"type": "actions", "elements": buttons})
	}
	att = append(att, slackContext(fmt.Sprintf(
		"runai-rca · quality: %s · %s",
		first(run.AnalysisQuality, "n/a"),
		time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	)))

	msg := map[string]any{
		"channel":      n.channelID,
		"text":         fmt.Sprintf("%s %s — %s", emoji, detail.Title, label),
		"unfurl_links": false,
		"attachments":  []any{map[string]any{"color": color, "blocks": att}},
	}
	if threadTS != "" {
		msg["thread_ts"] = threadTS
		return msg
	}
	contextLine := fmt.Sprintf("`%s` · *%s*", detail.IncidentID, label)
	if cluster := rep.Labels["cluster"]; cluster != "" {
		contextLine += " · " + cluster
	}
	msg["blocks"] = []any{
		map[string]any{"type": "header", "text": slackPlainText(emoji + " " + excerpt(detail.Title, 140))},
		slackContext(contextLine),
	}
	return msg
}

func (n *SlackNotifier) buildResolutionMessage(detail *IncidentDetail) map[string]any {
	resolvedAt := time.Now().UTC()
	if detail.ResolvedAt != nil {
		resolvedAt = detail.ResolvedAt.UTC()
	}
	contextLine := fmt.Sprintf("`%s` · resolved at %s", detail.IncidentID, resolvedAt.Format("2006-01-02 15:04 UTC"))
	if elapsed := resolvedAt.Sub(detail.FiredAt); elapsed >= 0 {
		contextLine += " · active for " + elapsed.Round(time.Second).String()
	}
	return map[string]any{
		"channel":      n.channelID,
		"thread_ts":    detail.SlackThreadTS,
		"text":         fmt.Sprintf("✅ %s — Resolved", detail.Title),
		"unfurl_links": false,
		"attachments": []any{map[string]any{
			"color": "#2eb886",
			"blocks": []any{
				slackSection("*✅ Incident Resolved*"),
				slackContext(contextLine),
			},
		}},
	}
}

// actionButtons builds the root-message buttons: Re-analyze needs Socket Mode
// (app token) to receive the click, Open Incident needs an external URL.
func (n *SlackNotifier) actionButtons(incidentID string) []any {
	buttons := []any{}
	if n.appToken != "" {
		buttons = append(buttons, map[string]any{
			"type":      "button",
			"action_id": slackReanalyzeActionID,
			"value":     incidentID,
			"text":      slackPlainText("🔁 Re-analyze"),
		})
	}
	if n.dashboard != "" {
		buttons = append(buttons, map[string]any{
			"type": "button",
			"text": slackPlainText("🔍 Open Incident"),
			"url":  slackIncidentURL(n.dashboard, incidentID),
		})
	}
	return buttons
}

// postThreadNote drops a small plain-text reply into an incident thread.
func (n *SlackNotifier) postThreadNote(threadTS string, text string) error {
	_, err := n.post(map[string]any{
		"channel":   n.channelID,
		"thread_ts": threadTS,
		"text":      text,
	})
	return err
}

// representativeAlert prefers the alert the run actually analyzed, falling
// back to the incident's newest alert (detail.Alerts is sorted newest first).
func representativeAlert(detail *IncidentDetail, alertID string) AlertRecord {
	for _, alert := range detail.Alerts {
		if alert.AlertID == alertID {
			return alert
		}
	}
	if len(detail.Alerts) > 0 {
		return detail.Alerts[0]
	}
	return AlertRecord{Labels: map[string]string{}}
}

func slackFields(detail *IncidentDetail, rep AlertRecord) map[string]any {
	firing := 0
	for _, alert := range detail.Alerts {
		if alert.Status != "resolved" {
			firing++
		}
	}
	fields := []any{}
	if ns := rep.Labels["namespace"]; ns != "" {
		fields = append(fields, slackMrkdwn("*Namespace*\n"+ns))
	}
	if node := first(rep.Labels["node"], rep.Labels["nodename"], rep.Labels["hostname"], rep.Labels["instance"]); node != "" {
		fields = append(fields, slackMrkdwn("*Node*\n"+node))
	}
	fields = append(fields,
		slackMrkdwn("*Severity*\n"+first(detail.Severity, "unknown")),
		slackMrkdwn(fmt.Sprintf("*Alerts*\n%d (%d firing)", len(detail.Alerts), firing)),
	)
	return map[string]any{"type": "section", "fields": fields}
}

func slackMrkdwn(text string) map[string]any {
	return map[string]any{"type": "mrkdwn", "text": text}
}

func slackPlainText(text string) map[string]any {
	return map[string]any{"type": "plain_text", "text": text, "emoji": true}
}

func slackSection(md string) map[string]any {
	return map[string]any{"type": "section", "text": slackMrkdwn(md)}
}

func slackContext(md string) map[string]any {
	return map[string]any{"type": "context", "elements": []any{slackMrkdwn(md)}}
}

// slackIncidentURL builds the frontend hash-route deep link for an incident.
func slackIncidentURL(dashboardURL, incidentID string) string {
	return strings.TrimRight(dashboardURL, "/") + "/#/incidents/incidents/" + url.PathEscape(incidentID)
}

// slackAnalysisLabel names the n-th Slack-notified analysis of an incident.
func slackAnalysisLabel(seq int) string {
	if seq <= 1 {
		return "Initial Analysis"
	}
	suffix := "th"
	switch {
	case seq%100 >= 11 && seq%100 <= 13:
	case seq%10 == 1:
		suffix = "st"
	case seq%10 == 2:
		suffix = "nd"
	case seq%10 == 3:
		suffix = "rd"
	}
	return fmt.Sprintf("%d%s Analysis", seq, suffix)
}

func slackSeverityStyle(severity, status string) (string, string) {
	if status == "resolved" {
		return "#36a64f", "✅"
	}
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "#dc3545", "🔥"
	case "warning", "medium":
		return "#ffc107", "⚠️"
	default:
		return "#17a2b8", "ℹ️"
	}
}

// toSlackMarkdown converts common agent markdown to Slack mrkdwn: **bold** →
// *bold*, "## Heading" → *Heading*. Fenced code blocks pass through untouched.
func toSlackMarkdown(text string) string {
	lines := strings.Split(text, "\n")
	inCode := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			continue
		}
		if trimmed := strings.TrimLeft(line, "#"); trimmed != line && strings.HasPrefix(trimmed, " ") {
			line = "*" + strings.TrimSpace(strings.ReplaceAll(trimmed, "**", "")) + "*"
		} else {
			line = strings.ReplaceAll(line, "**", "*")
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// recommendedActionsExcerpt pulls the first few lines under a "Recommended
// Actions" (or Korean equivalent) heading so the Slack card carries the next
// step without shipping the whole report.
func recommendedActionsExcerpt(detail string) string {
	lines := strings.Split(detail, "\n")
	start := -1
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		heading := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "# ")))
		if strings.HasPrefix(heading, "recommended action") || strings.HasPrefix(heading, "권장 조치") || strings.HasPrefix(heading, "권고") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	out := []string{}
	for _, line := range lines[start:] {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			break
		}
		if trimmed == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, trimmed)
		if len(out) >= 4 {
			break
		}
	}
	return strings.Join(out, "\n")
}
