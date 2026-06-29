package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	store                      *Store
	hub                        *Hub
	agentURL                   string
	language                   string
	agentRequestTimeout        time.Duration
	manualAgentRequestTimeout  time.Duration
	client                     *http.Client
}

const (
	similarIncidentLimit = 3
	flappingGroupWindow  = 30 * time.Minute
)

func main() {
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
	store.ConnectDatabase(
		first(os.Getenv("DATABASE_URL"), os.Getenv("POSTGRES_DSN")),
		time.Duration(getenvInt("DATABASE_CONNECT_TIMEOUT_SECONDS", 5))*time.Second,
	)
	if reaped := store.ReapStaleAnalyzingRuns(); reaped > 0 {
		log.Printf("reaped %d stale analyzing run(s) left by a previous process", reaped)
	}
	agentRequestTimeout := time.Duration(getenvInt("AGENT_REQUEST_TIMEOUT_SECONDS", 180)) * time.Second
	if agentRequestTimeout <= 0 {
		agentRequestTimeout = 180 * time.Second
	}
	manualAgentRequestTimeout := time.Duration(getenvInt("MANUAL_AGENT_REQUEST_TIMEOUT_SECONDS", 900)) * time.Second
	if manualAgentRequestTimeout <= 0 {
		manualAgentRequestTimeout = 900 * time.Second
	}
	return &Server{
		store:                     store,
		hub:                       NewHub(),
		agentURL:                  strings.TrimRight(getenv("AGENT_URL", "http://localhost:8000"), "/"),
		language:                  getenv("LANGUAGE", "en"),
		agentRequestTimeout:       agentRequestTimeout,
		manualAgentRequestTimeout: manualAgentRequestTimeout,
		client:                    &http.Client{},
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
		writeJSON(w, http.StatusOK, envelope(s.store.ListIncidents()))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncident(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncidentAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/alerts":
		writeJSON(w, http.StatusOK, envelope(s.store.ListAlerts()))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlert(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlertAction(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/embeddings/search":
		s.handleEmbeddingSearch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/analysis-runs":
		writeJSON(w, http.StatusOK, envelope(s.store.ListAnalysisRuns()))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/events":
		s.handleEvents(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/chat":
		s.handleChat(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func correlationKey(webhook AlertmanagerWebhook, alert Alert) string {
	labels := alert.Labels
	cluster := first(labels["cluster"], labels["runai_cluster"], labels["runai.io/cluster"])
	namespace := first(labels["namespace"], labels["kubernetes_namespace"])
	pod := first(labels["pod"], labels["pod_name"], labels["kubernetes_pod_name"])
	alertName := first(labels["alertname"], labels["alert_name"])
	if cluster != "" && namespace != "" && pod != "" && alertName != "" {"
		return strings.Join([]string{"flap", cluster, namespace, pod, alertName}, ":")
	}
	if alert.Fingerprint != "" {
		return "fingerprint:" + alert.Fingerprint
	}
	if webhook.GroupKey != "" {
		return "group:" + webhook.GroupKey
	}
	return fmt.Sprintf("adhoc:%d", time.Now().UnixNano())
}

func incidentTitle(alert Alert) string {
	return first(alert.Annotations["summary"], alert.Labels["alertname"], "Run:AI incident")
}

func severity(alert Alert) string {
	return first(alert.Labels["severity"], "warning")
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
	if value == "resolved" {
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
	if len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
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
