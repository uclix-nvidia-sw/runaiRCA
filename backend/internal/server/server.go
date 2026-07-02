package server

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

type AlertmanagerWebhook struct {
	GroupKey          string            `json:"groupKey"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     string            `json:"startsAt"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

type Artifact struct {
	Agent      string `json:"agent"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	Query      string `json:"query,omitempty"`
	Result     any    `json:"result,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

type SimilarIncident struct {
	IncidentID       string            `json:"incident_id"`
	AlertID          string            `json:"alert_id,omitempty"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Status           string            `json:"status"`
	Similarity       float64           `json:"similarity"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail,omitempty"`
	PositiveFeedback int               `json:"positive_feedback"`
	NegativeFeedback int               `json:"negative_feedback"`
	CommentCount     int               `json:"comment_count"`
	Labels           map[string]string `json:"labels,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

type FeedbackHint struct {
	SourceID  string  `json:"source_id"`
	Sentiment string  `json:"sentiment"`
	Weight    float64 `json:"weight"`
	Text      string  `json:"text"`
}

type FeedbackRecord struct {
	FeedbackID string    `json:"feedback_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	IncidentID string    `json:"incident_id,omitempty"`
	AlertID    string    `json:"alert_id,omitempty"`
	Vote       string    `json:"vote"`
	Comment    string    `json:"comment,omitempty"`
	Author     string    `json:"author,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type CommentRecord struct {
	CommentID  string    `json:"comment_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	IncidentID string    `json:"incident_id,omitempty"`
	AlertID    string    `json:"alert_id,omitempty"`
	Body       string    `json:"body"`
	Author     string    `json:"author,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type FeedbackSummary struct {
	TargetType    string          `json:"target_type"`
	TargetID      string          `json:"target_id"`
	Positive      int             `json:"positive"`
	Negative      int             `json:"negative"`
	MyVote        string          `json:"my_vote,omitempty"`
	Comments      []CommentRecord `json:"comments"`
	LearningHints []FeedbackHint  `json:"learning_hints,omitempty"`
}

type FeedbackRequest struct {
	Vote     string `json:"vote"`
	VoteType string `json:"vote_type,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Author   string `json:"author,omitempty"`
}

type CommentRequest struct {
	Body   string `json:"body"`
	Author string `json:"author,omitempty"`
}

type EmbeddingSearchRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type EmbeddingSearchResponse struct {
	Model   string            `json:"model"`
	Results []SimilarIncident `json:"results"`
}

type Incident struct {
	IncidentID       string     `json:"incident_id"`
	CorrelationKey   string     `json:"correlation_key"`
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	Status           string     `json:"status"`
	FiredAt          time.Time  `json:"fired_at"`
	ResolvedAt       *time.Time `json:"resolved_at"`
	AlertCount       int        `json:"alert_count"`
	IsAnalyzing      bool       `json:"is_analyzing"`
	LatestActivityAt time.Time  `json:"-"`
}

type AlertRecord struct {
	AlertID          string            `json:"alert_id"`
	IncidentID       string            `json:"incident_id"`
	AlarmTitle       string            `json:"alarm_title"`
	Severity         string            `json:"severity"`
	Status           string            `json:"status"`
	FiredAt          time.Time         `json:"fired_at"`
	ResolvedAt       *time.Time        `json:"resolved_at"`
	Fingerprint      string            `json:"fingerprint"`
	OccurrenceCount  int               `json:"occurrence_count"`
	OccurrencePods   []string          `json:"occurrence_pods"`
	ThreadTS         string            `json:"thread_ts"`
	Labels           map[string]string `json:"labels"`
	Annotations      map[string]string `json:"annotations"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail"`
	AnalysisQuality  string            `json:"analysis_quality"`
	Capabilities     map[string]string `json:"capabilities"`
	MissingData      []string          `json:"missing_data"`
	Warnings         []string          `json:"warnings"`
	Artifacts        []Artifact        `json:"artifacts"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents"`
	Feedback         FeedbackSummary   `json:"feedback"`
	IsAnalyzing      bool              `json:"is_analyzing"`
}

type IncidentDetail struct {
	Incident
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail"`
	AnalysisQuality  string            `json:"analysis_quality"`
	Capabilities     map[string]string `json:"capabilities"`
	MissingData      []string          `json:"missing_data"`
	Warnings         []string          `json:"warnings"`
	Artifacts        []Artifact        `json:"artifacts"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents"`
	Feedback         FeedbackSummary   `json:"feedback"`
	Alerts           []AlertRecord     `json:"alerts"`
}

type Server struct {
	store                     *Store
	hub                       *Hub
	agentURL                  string
	language                  string
	agentRequestTimeout       time.Duration
	manualAgentRequestTimeout time.Duration
	client                    *http.Client
	agentSlots                chan struct{}
	autoAnalyzeMu             sync.Mutex
	autoAnalyzeStarts         []time.Time
	autoAnalyzeFanout         int
	backfillInterval          time.Duration
	backfillBatch             int
	backfillRetryCooldown     time.Duration
}

const (
	similarIncidentLimit   = 3
	flappingGroupWindow    = 30 * time.Minute
	maxListLimit           = 200
	maxJSONBodyBytes       = 1 << 20
	maxEmbeddingQueryBytes = 4000
	maxWebhookAlerts       = 500
	// Default caps; overridable via MAX_AUTO_ANALYZE_FANOUT / MAX_CONCURRENT_AGENT_RUNS.
	maxAutoAnalyzeFanout   = 50
	maxManualAnalyzeFanout = 50
	maxConcurrentAgentRuns = maxManualAnalyzeFanout
	autoAnalyzeWindow      = time.Minute
)

// autoFanoutLimit is the effective per-webhook / per-window auto-analysis cap.
// Falls back to the const default when unset (e.g. tests that build Server literals).
func (s *Server) autoFanoutLimit() int {
	if s.autoAnalyzeFanout > 0 {
		return s.autoAnalyzeFanout
	}
	return maxAutoAnalyzeFanout
}

func Run() {
	port := getenv("PORT", "8080")
	server := NewServer()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: server.routes(),
		// No WriteTimeout: the /api/v1/events SSE stream is long-lived.
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go server.runBackfill(ctx)

	go func() {
		log.Printf("Run:AI RCA backend listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	stop()
	log.Printf("shutdown signal received, draining connections")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func NewServer() *Server {
	store := NewStore()
	agentRequestTimeout := time.Duration(getenvInt("AGENT_REQUEST_TIMEOUT_SECONDS", 180)) * time.Second
	if agentRequestTimeout <= 0 {
		agentRequestTimeout = 180 * time.Second
	}
	manualAgentRequestTimeout := time.Duration(getenvInt("MANUAL_AGENT_REQUEST_TIMEOUT_SECONDS", 900)) * time.Second
	if manualAgentRequestTimeout <= 0 {
		manualAgentRequestTimeout = 900 * time.Second
	}
	store.ConnectDatabase(
		first(os.Getenv("DATABASE_URL"), os.Getenv("POSTGRES_DSN")),
		time.Duration(getenvInt("DATABASE_CONNECT_TIMEOUT_SECONDS", 5))*time.Second,
	)
	if reaped := store.ReapStaleAnalyzingRuns(agentRequestTimeout, manualAgentRequestTimeout); reaped > 0 {
		log.Printf("reaped %d stale analyzing run(s) left by a previous process", reaped)
	}
	concurrency := getenvInt("MAX_CONCURRENT_AGENT_RUNS", maxConcurrentAgentRuns)
	if concurrency <= 0 {
		concurrency = maxConcurrentAgentRuns
	}
	autoFanout := getenvInt("MAX_AUTO_ANALYZE_FANOUT", maxAutoAnalyzeFanout)
	if autoFanout <= 0 {
		autoFanout = maxAutoAnalyzeFanout
	}
	backfillBatch := getenvInt("ANALYSIS_BACKFILL_BATCH", 10)
	if backfillBatch <= 0 {
		backfillBatch = 10
	}
	return &Server{
		store:                     store,
		hub:                       NewHub(),
		agentURL:                  strings.TrimRight(getenv("AGENT_URL", "http://localhost:8000"), "/"),
		language:                  getenv("LANGUAGE", "en"),
		agentRequestTimeout:       agentRequestTimeout,
		manualAgentRequestTimeout: manualAgentRequestTimeout,
		client:                    &http.Client{},
		agentSlots:                make(chan struct{}, concurrency),
		autoAnalyzeFanout:         autoFanout,
		// Backfill re-drives alerts left without a completed RCA (dropped by the
		// caps, or a prior failed run). Interval 0 disables it.
		backfillInterval:      time.Duration(getenvInt("ANALYSIS_BACKFILL_INTERVAL_SECONDS", 300)) * time.Second,
		backfillBatch:         backfillBatch,
		backfillRetryCooldown: time.Duration(getenvInt("ANALYSIS_BACKFILL_RETRY_COOLDOWN_SECONDS", 900)) * time.Second,
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return cors(mux)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/":
		writeJSON(w, http.StatusOK, map[string]string{"service": "runai-rca-backend", "status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/ping":
		_, _ = w.Write([]byte("pong"))
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"database": s.store.databaseHealth(),
		})
	case r.Method == http.MethodPost && r.URL.Path == "/webhook/alertmanager":
		s.handleAlertmanager(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/incidents":
		s.handleIncidentList(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncident(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncidentAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/alerts":
		s.handleAlertList(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlert(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlertAction(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/embeddings/search":
		s.handleEmbeddingSearch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/analysis-runs":
		s.handleAnalysisRunList(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/events":
		s.handleEvents(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/chat":
		s.handleChat(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleIncidentList(w http.ResponseWriter, r *http.Request) {
	page, err := paginationFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total := s.store.ListIncidentsPage(page.Limit, page.Offset)
	writeJSON(w, http.StatusOK, paginatedEnvelope(items, page, total))
}

func (s *Server) handleAlertList(w http.ResponseWriter, r *http.Request) {
	page, err := paginationFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total := s.store.ListAlertsPage(page.Limit, page.Offset)
	writeJSON(w, http.StatusOK, paginatedEnvelope(items, page, total))
}

func (s *Server) handleAnalysisRunList(w http.ResponseWriter, r *http.Request) {
	page, err := paginationFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, total := s.store.ListAnalysisRunsPage(page.Limit, page.Offset)
	writeJSON(w, http.StatusOK, paginatedEnvelope(items, page, total))
}

func correlationKey(webhook AlertmanagerWebhook, alert Alert) string {
	labels := alert.Labels
	cluster := first(labels["cluster"], labels["runai_cluster"], labels["runai.io/cluster"])
	if group, ok := diskPressureGroup(alert); ok {
		return strings.Join([]string{
			"flap",
			"node-pressure",
			keyPart(first(cluster, "cluster-unknown")),
			keyPart(first(group.Node, "node-unknown")),
			keyPart(group.Reason),
		}, ":")
	}
	namespace := first(labels["namespace"], labels["kubernetes_namespace"])
	workload := workloadIdentity(alert)
	alertName := first(labels["alertname"], labels["alert_name"])
	if namespace != "" && workload != "" && alertName != "" {
		return strings.Join([]string{
			"flap",
			keyPart(first(cluster, "cluster-unknown")),
			keyPart(namespace),
			keyPart(workload),
			keyPart(alertName),
		}, ":")
	}
	if alert.Fingerprint != "" {
		return "fingerprint:" + alert.Fingerprint
	}
	if webhook.GroupKey != "" {
		return "group:" + webhook.GroupKey
	}
	return fmt.Sprintf("adhoc:%d", time.Now().UnixNano())
}

type diskPressureGroupInfo struct {
	Node   string
	Reason string
}

func diskPressureGroup(alert Alert) (diskPressureGroupInfo, bool) {
	labels := alert.Labels
	annotations := alert.Annotations
	text := strings.ToLower(strings.Join([]string{
		labels["alertname"],
		labels["alert_name"],
		labels["reason"],
		labels["condition"],
		annotations["summary"],
		annotations["description"],
		annotations["message"],
	}, " "))

	reason := ""
	switch {
	case strings.Contains(text, "diskpressure"), strings.Contains(text, "disk pressure"):
		reason = "disk-pressure"
	case strings.Contains(text, "evicted"), strings.Contains(text, "evict"):
		reason = "evicted"
	default:
		return diskPressureGroupInfo{}, false
	}

	node := first(
		labels["node"],
		labels["node_name"],
		labels["nodename"],
		labels["kubernetes_node"],
		labels["instance"],
	)
	return diskPressureGroupInfo{Node: node, Reason: reason}, true
}

func groupedIncidentTitle(alert Alert, alertCount int) string {
	group, ok := diskPressureGroup(alert)
	if !ok {
		return incidentTitle(alert)
	}
	node := first(group.Node, "unknown node")
	if alertCount > 1 {
		return fmt.Sprintf("Node %s %s affected %d alert(s)", node, strings.ReplaceAll(group.Reason, "-", " "), alertCount)
	}
	return fmt.Sprintf("Node %s %s", node, strings.ReplaceAll(group.Reason, "-", " "))
}

func incidentTitle(alert Alert) string {
	return first(alert.Annotations["summary"], alert.Labels["alertname"], "Run:AI incident")
}

// workloadIdentity returns a stable identifier for the workload behind an alert.
// Controllers recreate pods under new, randomized names (a Deployment rollout, a
// StatefulSet restart, a CrashLoop churn), so keying flapping correlation on the
// raw pod name makes every occurrence look unique and floods the store. Explicit
// workload/owner labels win when present; otherwise the pod name is normalized to
// its workload prefix.
func workloadIdentity(alert Alert) string {
	labels := alert.Labels
	if w := first(
		labels["workload"],
		labels["workload_name"],
		labels["runai_job_name"],
		labels["deployment"],
		labels["statefulset"],
		labels["daemonset"],
		labels["job_name"],
		labels["created_by_name"],
		labels["owner_name"],
	); w != "" {
		return normalizePodName(w)
	}
	pod := first(labels["pod"], labels["pod_name"], labels["kubernetes_pod_name"])
	return normalizePodName(pod)
}

var (
	podRandomSuffixRe   = regexp.MustCompile(`-[a-z0-9]{5}$`)
	podReplicaSetHashRe = regexp.MustCompile(`-[a-z0-9]{8,10}$`)
	podOrdinalSuffixRe  = regexp.MustCompile(`-\d+$`)
)

// normalizePodName strips the controller-generated suffixes from a pod name so
// pods of the same workload collapse to one identity:
//   - Deployment:  <name>-<replicaset-hash>-<random5>
//   - DaemonSet:   <name>-<random5>
//   - StatefulSet: <name>-<ordinal>
func normalizePodName(pod string) string {
	pod = strings.TrimSpace(pod)
	if pod == "" {
		return ""
	}
	if podRandomSuffixRe.MatchString(pod) {
		stripped := podRandomSuffixRe.ReplaceAllString(pod, "")
		if podReplicaSetHashRe.MatchString(stripped) {
			return podReplicaSetHashRe.ReplaceAllString(stripped, "")
		}
		return stripped
	}
	if podOrdinalSuffixRe.MatchString(pod) {
		return podOrdinalSuffixRe.ReplaceAllString(pod, "")
	}
	return pod
}

// maxOccurrencePods bounds the distinct concrete pod names retained on a grouped
// alert row. The OccurrenceCount still reflects the true total; only the forensic
// name list is capped so a perpetually flapping workload cannot bloat the row.
const maxOccurrencePods = 25

// podName extracts the concrete pod name behind an alert occurrence.
func podName(alert Alert) string {
	return first(alert.Labels["pod"], alert.Labels["pod_name"], alert.Labels["kubernetes_pod_name"])
}

// appendOccurrencePod records the concrete pod behind one occurrence, keeping the
// most-recent distinct names (most recent last) within the cap.
func appendOccurrencePod(pods []string, pod string) []string {
	pod = strings.TrimSpace(pod)
	if pod == "" {
		return pods
	}
	out := make([]string, 0, len(pods)+1)
	for _, existing := range pods {
		if existing != pod {
			out = append(out, existing)
		}
	}
	out = append(out, pod)
	if len(out) > maxOccurrencePods {
		out = out[len(out)-maxOccurrencePods:]
	}
	return out
}

func alertIdentity(alert Alert) string {
	if fingerprint := strings.TrimSpace(alert.Fingerprint); fingerprint != "" {
		return fingerprint
	}
	labels := make([]string, 0, len(alert.Labels))
	for key, value := range alert.Labels {
		labels = append(labels, key+"="+value)
	}
	sort.Strings(labels)
	raw := strings.Join([]string{
		alert.StartsAt,
		alert.GeneratorURL,
		strings.Join(labels, "\x1f"),
	}, "\x00")
	sum := sha1.Sum([]byte(raw))
	return "synthetic:" + hex.EncodeToString(sum[:])
}

func alertStorageKey(webhook AlertmanagerWebhook, alert Alert, correlation string) string {
	if key := strings.TrimSpace(correlation); key != "" {
		return "correlation:" + key
	}
	return "identity:" + alertIdentity(alert)
}

func keyPart(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "\t", "-", "\n", "-", ":", "-", "/", "-")
	return replacer.Replace(value)
}

func severity(alert Alert) string {
	value := strings.ToLower(first(alert.Labels["severity"], "warning"))
	if value == "information" {
		return "info"
	}
	return value
}

func ignoredAlert(alert Alert) bool {
	switch strings.ToLower(severity(alert)) {
	case "info", "information":
		return true
	default:
		return false
	}
}

func status(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "resolved") {
		return "resolved"
	}
	return "firing"
}

func maxSeverity(a, b string) string {
	rank := map[string]int{"info": 1, "warning": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstTime(raw string, fallback time.Time) time.Time {
	if raw == "" {
		return fallback
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fallback
	}
	return t.UTC()
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIncident(in *Incident) *Incident {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneAlert(in *AlertRecord) *AlertRecord {
	if in == nil {
		return nil
	}
	out := *in
	out.Labels = cloneMap(in.Labels)
	out.Annotations = cloneMap(in.Annotations)
	out.OccurrencePods = cloneStrings(in.OccurrencePods)
	out.Capabilities = cloneMap(in.Capabilities)
	out.MissingData = cloneStrings(in.MissingData)
	out.Warnings = cloneStrings(in.Warnings)
	out.Artifacts = cloneArtifacts(in.Artifacts)
	out.SimilarIncidents = cloneSimilar(in.SimilarIncidents)
	out.Feedback = cloneFeedbackSummary(in.Feedback)
	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return append([]string{}, in...)
}

func cloneArtifacts(in []Artifact) []Artifact {
	if in == nil {
		return []Artifact{}
	}
	return append([]Artifact{}, in...)
}

func cloneSimilar(in []SimilarIncident) []SimilarIncident {
	if in == nil {
		return []SimilarIncident{}
	}
	out := make([]SimilarIncident, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Labels = cloneMap(item.Labels)
	}
	return out
}

func cloneFeedbackSummary(in FeedbackSummary) FeedbackSummary {
	out := in
	if out.Comments == nil {
		out.Comments = []CommentRecord{}
	} else {
		out.Comments = append([]CommentRecord{}, in.Comments...)
	}
	if out.LearningHints != nil {
		out.LearningHints = append([]FeedbackHint{}, in.LearningHints...)
	}
	return out
}

func cloneAnalysisRun(in *AnalysisRun) AnalysisRun {
	if in == nil {
		return AnalysisRun{}
	}
	out := *in
	out.Capabilities = cloneMap(in.Capabilities)
	out.MissingData = cloneStrings(in.MissingData)
	out.Warnings = cloneStrings(in.Warnings)
	out.Artifacts = cloneArtifacts(in.Artifacts)
	return out
}

func cloneComment(in *CommentRecord) *CommentRecord {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func alertFromRecord(record AlertRecord) Alert {
	return Alert{
		Status:      record.Status,
		Labels:      cloneMap(record.Labels),
		Annotations: cloneMap(record.Annotations),
		Fingerprint: record.Fingerprint,
	}
}

func normalizeVote(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "up", "like", "positive", "helpful":
		return "up"
	case "down", "dislike", "negative", "unhelpful":
		return "down"
	default:
		return ""
	}
}

func feedbackActor(author string) string {
	author = strings.TrimSpace(author)
	if author == "" {
		return "anonymous"
	}
	return author
}

func nextID(prefix string, seq int64) string {
	return fmt.Sprintf("%s-%d-%06d", prefix, time.Now().UTC().UnixNano(), seq)
}

func excerpt(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return strings.TrimSpace(value[:end]) + "..."
}

func mustJSON(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		return []byte("null")
	}
	return payload
}

func pathPart(path, prefix string) string {
	return strings.Trim(strings.TrimPrefix(path, prefix), "/")
}

func envelope(data any) map[string]any {
	return map[string]any{"status": "ok", "data": data}
}

type paginationRequest struct {
	Limit  int
	Offset int
}

type paginationInfo struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

func paginatedEnvelope(data any, page paginationRequest, total int) map[string]any {
	payload := envelope(data)
	offset := page.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	limit := page.Limit
	if limit <= 0 {
		limit = total - offset
	}
	payload["pagination"] = paginationInfo{
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+limit < total,
	}
	return payload
}

func paginationFromRequest(r *http.Request) (paginationRequest, error) {
	query := r.URL.Query()
	limit, err := nonNegativeQueryInt(query.Get("limit"), 0)
	if err != nil {
		return paginationRequest{}, fmt.Errorf("invalid limit")
	}
	offset, err := nonNegativeQueryInt(query.Get("offset"), 0)
	if err != nil {
		return paginationRequest{}, fmt.Errorf("invalid offset")
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	return paginationRequest{Limit: limit, Offset: offset}, nil
}

func nonNegativeQueryInt(raw string, fallback int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("value must be non-negative")
	}
	return value, nil
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) (int, error) {
	body := r.Body
	if maxBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("request body too large (max %d bytes)", maxErr.Limit)
		}
		return http.StatusBadRequest, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				return http.StatusRequestEntityTooLarge, fmt.Errorf("request body too large (max %d bytes)", maxErr.Limit)
			}
			return http.StatusBadRequest, err
		}
		return http.StatusBadRequest, fmt.Errorf("request body must contain a single JSON value")
	}
	return http.StatusOK, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
