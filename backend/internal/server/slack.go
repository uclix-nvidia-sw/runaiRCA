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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
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

const (
	slackOutboxMetadataKey   = "slack_analysis_outbox"
	slackDeliveryPending     = "pending"
	slackDeliveryDelivered   = "delivered"
	slackDeliverySkipped     = "skipped"
	slackDeliveryRetryPeriod = 30 * time.Second
	maxSlackOutboxEntries    = 32
)

// SlackAnalysisDelivery is a durable snapshot of one completed analysis. A
// run row is reused for manual re-analysis, so retrying from the live run alone
// could send the next attempt's RCA instead of the one that originally failed.
type SlackAnalysisDelivery struct {
	ID            string
	IncidentID    string
	Run           AnalysisRun
	Attempts      int
	QueuedAt      time.Time
	LastAttemptAt time.Time
	Tracked       bool
}

// notifySlackAnalysis posts a completed run to Slack per the rules above.
// The analysis itself remains successful when Slack is down; delivery is first
// recorded in the run metadata and retried by runSlackDeliveryRetry.
func (s *Server) notifySlackAnalysis(run AnalysisRun, incidentID string) {
	if !s.slack.IsConfigured() || incidentID == "" || run.Status != "complete" {
		return
	}
	if _, ok := s.store.IncidentDetail(incidentID); !ok {
		return
	}
	delivery, shouldDeliver := s.store.QueueSlackAnalysisDeliverySnapshot(run, incidentID)
	if !shouldDeliver {
		if delivery.ID == "" {
			log.Printf("slack delivery could not be queued for analysis %s", run.RunID)
		}
		return
	}
	go s.deliverSlackAnalysisDelivery(delivery)
}

func (s *Server) deliverSlackAnalysis(run AnalysisRun, incidentID string) {
	delivery := SlackAnalysisDelivery{
		ID:         slackAnalysisDeliveryID(run),
		IncidentID: incidentID,
		Run:        run,
	}
	s.deliverSlackAnalysisDelivery(delivery)
}

func (s *Server) deliverSlackAnalysisDelivery(delivery SlackAnalysisDelivery) {
	s.slack.mu.Lock()
	defer s.slack.mu.Unlock()
	detail, ok := s.store.IncidentDetail(delivery.IncidentID)
	if !ok || detail.DeletedAt != nil {
		// A deleted incident cannot become deliverable without an explicit
		// restore/re-analysis. Keeping attempts=0 here made old trash entries
		// occupy the retry batch forever and starve newer Slack notifications.
		s.store.SkipSlackAnalysisDelivery(delivery.Run.RunID, delivery.ID, "incident no longer exists")
		return
	}
	threadTS := detail.SlackThreadTS
	if threadTS != "" && !slackReplySources[delivery.Run.Source] &&
		!s.store.SlackAnalysisDeliveryPredatesThread(delivery.IncidentID, threadTS, delivery.Run) {
		s.store.SkipSlackAnalysisDelivery(delivery.Run.RunID, delivery.ID, "automatic follow-up is not posted after the root analysis")
		return
	}
	if delivery.Tracked && !s.store.BeginSlackAnalysisDelivery(delivery.Run.RunID, delivery.ID) {
		return
	}
	seq := detail.AnalysisSeq + 1
	if threadTS == "" {
		// A legacy row can have a sequence but no persisted parent timestamp.
		// Starting a replacement root also starts a new visible thread sequence.
		seq = 1
	}
	msg := s.slack.buildAnalysisMessage(detail, delivery.Run, seq, threadTS)
	msg["client_msg_id"] = delivery.ID
	ts, err := s.slack.post(msg)
	if err != nil {
		if threadTS != "" && slackThreadMissingError(err) {
			if s.store.ResetIncidentSlackThread(delivery.IncidentID, threadTS) {
				log.Printf("slack thread %s no longer exists for incident %s; next retry will create a replacement root", threadTS, delivery.IncidentID)
			}
		}
		s.store.FailSlackAnalysisDelivery(delivery.Run.RunID, delivery.ID, err.Error())
		log.Printf("slack notify failed for incident %s: %v", delivery.IncidentID, err)
		return
	}
	if delivery.Tracked {
		if _, ok := s.store.CompleteSlackAnalysisDelivery(delivery.Run.RunID, delivery.ID, delivery.IncidentID, threadTS == "", ts); !ok {
			log.Printf("slack delivery state commit failed for incident %s; leaving delivery pending for retry", delivery.IncidentID)
			return
		}
	} else {
		if _, ok := s.store.BumpIncidentAnalysisSeq(delivery.IncidentID); !ok {
			return
		}
		if threadTS == "" {
			s.store.SetIncidentSlackThread(delivery.IncidentID, ts)
		}
	}
	if threadTS == "" {
		detail.SlackThreadTS = ts
		// Short-lived alerts may resolve before their initial analysis finishes.
		// Once the root exists, catch up the pending resolved state in its thread.
		if detail.Status == "resolved" {
			s.deliverSlackResolutionLocked(detail)
		}
	}
}

func (s *Server) runSlackDeliveryRetry(ctx context.Context) {
	if !s.slack.IsConfigured() {
		return
	}
	s.retryPendingSlackAnalysisDeliveries(time.Now().UTC())
	ticker := time.NewTicker(slackDeliveryRetryPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.retryPendingSlackAnalysisDeliveries(now.UTC())
		}
	}
}

func (s *Server) retryPendingSlackAnalysisDeliveries(now time.Time) {
	for _, delivery := range s.store.PendingSlackAnalysisDeliveries(now, 50) {
		s.deliverSlackAnalysisDelivery(delivery)
	}
}

func slackAnalysisDeliveryID(run AnalysisRun) string {
	attemptStarted := run.CreatedAt.UTC().Format(time.RFC3339Nano)
	// A manual re-analysis reuses its durable run row. CreatedAt usually
	// distinguishes attempts, but coarse host clocks can assign two attempts the
	// same timestamp. Include the immutable completed payload too, so an older
	// automatic completion never aliases the later manual delivery in the outbox.
	completedAt := run.UpdatedAt.UTC().Format(time.RFC3339Nano)
	payload := strings.Join([]string{
		"runai-rca/slack", run.RunID, attemptStarted, completedAt,
		run.Source, run.Title, run.AnalysisSummary, run.AnalysisDetail,
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	// Slack accepts a client-generated UUID as client_msg_id. Make this a stable
	// RFC 4122-shaped v5 identifier so a retry is deduplicated server-side.
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	hex := fmt.Sprintf("%x", sum[:16])
	return hex[:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

func slackRunSnapshot(run AnalysisRun) map[string]any {
	actionDetail := recommendedActionsExcerpt(run.AnalysisDetail)
	if actionDetail != "" {
		actionDetail = "## Recommended Actions\n\n" + excerpt(actionDetail, 700)
	}
	return map[string]any{
		"run_id": run.RunID, "source": run.Source, "status": run.Status,
		"target_type": run.TargetType, "target_id": run.TargetID,
		"incident_id": run.IncidentID, "alert_id": run.AlertID,
		"title": run.Title, "analysis_summary": excerpt(run.AnalysisSummary, 900),
		"analysis_detail": actionDetail, "analysis_quality": run.AnalysisQuality,
		"created_at": run.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func slackRunFromSnapshot(snapshot map[string]any) AnalysisRun {
	createdAt, _ := time.Parse(time.RFC3339Nano, stringValue(snapshot["created_at"]))
	return AnalysisRun{
		RunID: stringValue(snapshot["run_id"]), Source: stringValue(snapshot["source"]),
		Status: stringValue(snapshot["status"]), TargetType: stringValue(snapshot["target_type"]),
		TargetID: stringValue(snapshot["target_id"]), IncidentID: stringValue(snapshot["incident_id"]),
		AlertID: stringValue(snapshot["alert_id"]), Title: stringValue(snapshot["title"]),
		AnalysisSummary: stringValue(snapshot["analysis_summary"]), AnalysisDetail: stringValue(snapshot["analysis_detail"]),
		AnalysisQuality: stringValue(snapshot["analysis_quality"]), CreatedAt: createdAt,
	}
}

func slackOutboxEntries(metadata map[string]any) []map[string]any {
	if metadata == nil {
		return nil
	}
	raw, ok := metadata[slackOutboxMetadataKey].([]any)
	if !ok {
		return nil
	}
	entries := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, cloneAnyMap(entry))
		}
	}
	return entries
}

func metadataWithSlackOutbox(metadata map[string]any, entries []map[string]any) map[string]any {
	out := cloneAnyMap(metadata)
	if out == nil {
		out = map[string]any{}
	}
	if len(entries) > maxSlackOutboxEntries {
		pending := make([]map[string]any, 0, len(entries))
		delivered := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			if stringValue(entry["status"]) == slackDeliveryPending {
				pending = append(pending, entry)
			} else {
				delivered = append(delivered, entry)
			}
		}
		remaining := maxSlackOutboxEntries - len(pending)
		if remaining > 0 && len(delivered) > remaining {
			delivered = delivered[len(delivered)-remaining:]
		}
		entries = append(delivered, pending...)
	}
	raw := make([]any, 0, len(entries))
	for _, entry := range entries {
		raw = append(raw, cloneAnyMap(entry))
	}
	out[slackOutboxMetadataKey] = raw
	return out
}

func metadataSkippingSlackAnalysisDelivery(metadata map[string]any, deliveryID string, reason string) map[string]any {
	entries := slackOutboxEntries(metadata)
	changed := false
	for _, entry := range entries {
		if stringValue(entry["delivery_id"]) != deliveryID ||
			stringValue(entry["status"]) != slackDeliveryPending {
			continue
		}
		entry["status"] = slackDeliverySkipped
		entry["last_error"] = excerpt(strings.TrimSpace(reason), 500)
		changed = true
	}
	if !changed {
		return metadata
	}
	return metadataWithSlackOutbox(metadata, entries)
}

func slackDeliveryFromEntry(entry map[string]any, tracked bool) SlackAnalysisDelivery {
	snapshot, _ := entry["run"].(map[string]any)
	queuedAt, _ := time.Parse(time.RFC3339Nano, stringValue(entry["queued_at"]))
	lastAttemptAt, _ := time.Parse(time.RFC3339Nano, stringValue(entry["last_attempt_at"]))
	return SlackAnalysisDelivery{
		ID: stringValue(entry["delivery_id"]), IncidentID: stringValue(entry["incident_id"]),
		Run: slackRunFromSnapshot(snapshot), Attempts: usageInt(entry["attempts"]),
		QueuedAt: queuedAt, LastAttemptAt: lastAttemptAt, Tracked: tracked,
	}
}

func slackRetryDelay(attempts int) time.Duration {
	if attempts <= 1 {
		return slackDeliveryRetryPeriod
	}
	shift := attempts - 1
	if shift > 4 {
		shift = 4
	}
	return slackDeliveryRetryPeriod * time.Duration(1<<shift)
}

func (s *Store) QueueSlackAnalysisDelivery(runID string, incidentID string) (SlackAnalysisDelivery, bool) {
	s.mu.RLock()
	run := s.analysisRuns[runID]
	if run == nil {
		s.mu.RUnlock()
		return SlackAnalysisDelivery{}, false
	}
	snapshot := cloneAnalysisRun(run)
	s.mu.RUnlock()
	return s.QueueSlackAnalysisDeliverySnapshot(snapshot, incidentID)
}

// QueueSlackAnalysisDeliverySnapshot persists the immutable completion result
// supplied by requestAnalysisRun. Analysis rows are reused for later attempts,
// so looking the run up again here can observe the next attempt's "analyzing"
// state (or, worse, its later completed payload) and lose/mislabel this reply.
func (s *Store) QueueSlackAnalysisDeliverySnapshot(snapshot AnalysisRun, incidentID string) (SlackAnalysisDelivery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queueSlackAnalysisDeliverySnapshotLocked(snapshot, incidentID, true)
}

// queueSlackAnalysisDeliverySnapshotLocked mutates the current reusable row
// while retaining the immutable completed payload. Callers that are already
// completing the run pass persist=false and include the outbox in that same
// analysis_runs write; standalone/retry callers persist the metadata here.
func (s *Store) queueSlackAnalysisDeliverySnapshotLocked(snapshot AnalysisRun, incidentID string, persist bool) (SlackAnalysisDelivery, bool) {
	run := s.analysisRuns[snapshot.RunID]
	if run == nil || snapshot.Status != "complete" || incidentID == "" {
		return SlackAnalysisDelivery{}, false
	}
	deliveryID := slackAnalysisDeliveryID(snapshot)
	entries := slackOutboxEntries(run.Metadata)
	for _, entry := range entries {
		if stringValue(entry["delivery_id"]) != deliveryID {
			continue
		}
		delivery := slackDeliveryFromEntry(entry, true)
		return delivery, stringValue(entry["status"]) == slackDeliveryPending
	}
	entry := map[string]any{
		"delivery_id": deliveryID, "incident_id": incidentID, "status": slackDeliveryPending,
		"attempts": 0, "last_error": "", "queued_at": time.Now().UTC().Format(time.RFC3339Nano),
		"last_attempt_at": "", "run": slackRunSnapshot(snapshot),
	}
	before := cloneAnyMap(run.Metadata)
	run.Metadata = metadataWithSlackOutbox(run.Metadata, append(entries, entry))
	if persist && !s.persistAnalysisRunLocked(run) {
		run.Metadata = before
		return SlackAnalysisDelivery{}, false
	}
	return slackDeliveryFromEntry(entry, true), true
}

func (s *Store) PendingSlackAnalysisDeliveries(now time.Time, limit int) []SlackAnalysisDelivery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]SlackAnalysisDelivery, 0)
	for _, run := range s.analysisRuns {
		if run == nil {
			continue
		}
		for _, entry := range slackOutboxEntries(run.Metadata) {
			if stringValue(entry["status"]) != slackDeliveryPending {
				continue
			}
			delivery := slackDeliveryFromEntry(entry, true)
			if delivery.Attempts > 0 && now.Sub(delivery.LastAttemptAt) < slackRetryDelay(delivery.Attempts) {
				continue
			}
			items = append(items, delivery)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].QueuedAt.Before(items[j].QueuedAt)
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// SlackAnalysisDeliveryPredatesThread distinguishes a delayed initial
// automatic completion from an ordinary automatic follow-up. The latter stays
// suppressed once a thread exists; the former must still be delivered when a
// later manual attempt happened to create the visible root first.
func (s *Store) SlackAnalysisDeliveryPredatesThread(incidentID string, threadTS string, snapshot AnalysisRun) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if snapshot.CreatedAt.IsZero() {
		return false
	}
	for _, run := range s.analysisRuns {
		if run == nil {
			continue
		}
		for _, entry := range slackOutboxEntries(run.Metadata) {
			if stringValue(entry["incident_id"]) != incidentID ||
				stringValue(entry["status"]) != slackDeliveryDelivered ||
				usageInt(entry["sequence"]) != 1 ||
				stringValue(entry["message_ts"]) != threadTS {
				continue
			}
			root := slackDeliveryFromEntry(entry, true).Run
			// Analysis attempts can be created within the same clock tick. In that
			// case the immutable completion snapshot is the only ordering signal
			// available here, so keep it rather than silently losing a delayed
			// automatic result behind the manual root.
			return !root.CreatedAt.IsZero() && !snapshot.CreatedAt.After(root.CreatedAt)
		}
	}
	// Legacy roots have no attempt provenance. Preserve the historical policy
	// and suppress non-reply sources rather than guessing their order.
	return false
}

func (s *Store) updateSlackDelivery(runID string, deliveryID string, update func(map[string]any)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return false
	}
	entries := slackOutboxEntries(run.Metadata)
	for index, entry := range entries {
		if stringValue(entry["delivery_id"]) != deliveryID {
			continue
		}
		before := cloneAnyMap(run.Metadata)
		update(entry)
		entries[index] = entry
		run.Metadata = metadataWithSlackOutbox(run.Metadata, entries)
		if !s.persistAnalysisRunLocked(run) {
			run.Metadata = before
			return false
		}
		return true
	}
	return false
}

func (s *Store) BeginSlackAnalysisDelivery(runID string, deliveryID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return false
	}
	entries := slackOutboxEntries(run.Metadata)
	var candidate map[string]any
	for _, entry := range entries {
		if stringValue(entry["delivery_id"]) == deliveryID && stringValue(entry["status"]) == slackDeliveryPending {
			candidate = entry
			break
		}
	}
	if candidate == nil {
		return false
	}
	candidateIncidentID := stringValue(candidate["incident_id"])
	candidateQueuedAt, _ := time.Parse(time.RFC3339Nano, stringValue(candidate["queued_at"]))
	for _, currentRun := range s.analysisRuns {
		if currentRun == nil {
			continue
		}
		for _, entry := range slackOutboxEntries(currentRun.Metadata) {
			if stringValue(entry["delivery_id"]) == deliveryID ||
				stringValue(entry["status"]) != slackDeliveryPending ||
				stringValue(entry["incident_id"]) != candidateIncidentID {
				continue
			}
			queuedAt, _ := time.Parse(time.RFC3339Nano, stringValue(entry["queued_at"]))
			if queuedAt.Before(candidateQueuedAt) ||
				(queuedAt.Equal(candidateQueuedAt) && stringValue(entry["delivery_id"]) < deliveryID) {
				return false
			}
		}
	}
	for index, entry := range entries {
		if stringValue(entry["delivery_id"]) != deliveryID ||
			stringValue(entry["status"]) != slackDeliveryPending {
			continue
		}
		before := cloneAnyMap(run.Metadata)
		entry["attempts"] = usageInt(entry["attempts"]) + 1
		entry["last_attempt_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		entry["last_error"] = ""
		entries[index] = entry
		run.Metadata = metadataWithSlackOutbox(run.Metadata, entries)
		if !s.persistAnalysisRunLocked(run) {
			run.Metadata = before
			return false
		}
		return true
	}
	return false
}

func (s *Store) ResetIncidentSlackThread(incidentID string, expectedThreadTS string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[incidentID]
	if incident == nil || incidentDeleted(incident) || incident.SlackThreadTS != expectedThreadTS {
		return false
	}
	before := *incident
	incident.SlackThreadTS = ""
	incident.AnalysisSeq = 0
	if !s.persistIncidentLocked(incident) {
		*incident = before
		return false
	}
	return true
}

func slackThreadMissingError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "thread_not_found") || strings.Contains(message, "message_not_found")
}

func (s *Store) FailSlackAnalysisDelivery(runID string, deliveryID string, message string) {
	_ = s.updateSlackDelivery(runID, deliveryID, func(entry map[string]any) {
		if stringValue(entry["status"]) == slackDeliveryPending {
			entry["last_error"] = excerpt(strings.TrimSpace(message), 500)
		}
	})
}

func (s *Store) SkipSlackAnalysisDelivery(runID string, deliveryID string, reason string) {
	_ = s.updateSlackDelivery(runID, deliveryID, func(entry map[string]any) {
		if stringValue(entry["status"]) == slackDeliveryPending {
			entry["status"] = slackDeliverySkipped
			entry["last_error"] = excerpt(strings.TrimSpace(reason), 500)
		}
	})
}

func (s *Store) CompleteSlackAnalysisDelivery(runID string, deliveryID string, incidentID string, root bool, messageTS string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	incident := s.incidents[incidentID]
	if run == nil || incident == nil || incidentDeleted(incident) {
		return 0, false
	}
	entries := slackOutboxEntries(run.Metadata)
	entryIndex := -1
	for index, entry := range entries {
		if stringValue(entry["delivery_id"]) == deliveryID {
			entryIndex = index
			if stringValue(entry["status"]) == slackDeliveryDelivered {
				return incident.AnalysisSeq, true
			}
			break
		}
	}
	if entryIndex < 0 {
		return 0, false
	}
	beforeMetadata := cloneAnyMap(run.Metadata)
	beforeIncident := *incident
	if root && incident.SlackThreadTS == "" {
		incident.AnalysisSeq = 1
		incident.SlackThreadTS = messageTS
	} else {
		incident.AnalysisSeq++
	}
	entries[entryIndex]["status"] = slackDeliveryDelivered
	entries[entryIndex]["message_ts"] = messageTS
	entries[entryIndex]["delivered_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	entries[entryIndex]["last_error"] = ""
	entries[entryIndex]["sequence"] = incident.AnalysisSeq
	run.Metadata = metadataWithSlackOutbox(run.Metadata, entries)
	if !s.persistSlackAnalysisDeliveryLocked(run, incident) {
		run.Metadata = beforeMetadata
		*incident = beforeIncident
		return 0, false
	}
	return incident.AnalysisSeq, true
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
	if strings.TrimSpace(parsed.TS) == "" {
		err := errors.New("slack API success response omitted message timestamp")
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
