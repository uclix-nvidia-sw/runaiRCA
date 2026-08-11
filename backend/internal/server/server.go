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
	EvidenceID string `json:"evidence_id,omitempty"`
	Agent      string `json:"agent"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	Query      string `json:"query,omitempty"`
	Result     any    `json:"result,omitempty"`
	Summary    string `json:"summary,omitempty"`
	// Human-facing card title (e.g. "파드 조회"); the UI falls back to Type.
	Title string `json:"title,omitempty"`
	// Problem signals the agent extracted from Result; the UI marks them in red.
	Highlights []string `json:"highlights,omitempty"`
}

// retrieval_kind values for SimilarIncident.RetrievalKind. Named once here so
// the producers (dbSearchMemoryExcluding's dense tagging in store_postgres.go,
// the sparse paths in memory.go) and the dense-vs-sparse preference check in
// SimilarIncidentsForAlert can't drift apart via a typo in a duplicated literal.
const (
	retrievalKindDenseSemantic  = "dense-semantic"  // real embedding model (remote basis)
	retrievalKindDenseLexical   = "dense-lexical"   // signed feature hashing, no IDF
	retrievalKindSparseIdentity = "sparse-identity" // in-memory IDF-weighted cosine + label blend
)

type SimilarIncident struct {
	IncidentID       string            `json:"incident_id"`
	AlertID          string            `json:"alert_id,omitempty"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Status           string            `json:"status"`
	Similarity       float64           `json:"similarity"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail,omitempty"`
	RootCauseFamily  string            `json:"root_cause_family,omitempty"`
	Approved         bool              `json:"approved,omitempty"`
	PositiveFeedback int               `json:"positive_feedback"`
	NegativeFeedback int               `json:"negative_feedback"`
	CommentCount     int               `json:"comment_count"`
	Labels           map[string]string `json:"labels,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	RetrievalKind    string            `json:"retrieval_kind,omitempty"`
}

type FeedbackHint struct {
	SourceID  string    `json:"source_id"`
	Sentiment string    `json:"sentiment"`
	Weight    float64   `json:"weight"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at,omitempty"`
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
	// The incident asking. Held out of the results so a mid-analysis re-search
	// cannot match the incident against its own stored memory row.
	ExcludeIncidentID string `json:"exclude_incident_id,omitempty"`
}

type EmbeddingSearchResponse struct {
	Model   string            `json:"model"`
	Results []SimilarIncident `json:"results"`
}

type Incident struct {
	IncidentID     string     `json:"incident_id"`
	CorrelationKey string     `json:"correlation_key"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	FiredAt        time.Time  `json:"fired_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	UserApprovedAt *time.Time `json:"user_approved_at,omitempty"`
	ArchivedAt     *time.Time `json:"archived_at,omitempty"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
	AlertCount     int        `json:"alert_count"`
	IsAnalyzing    bool       `json:"is_analyzing"`
	// AnalysisSeq counts Slack-notified analyses (1 = Initial Analysis). Runs
	// are updated in place on re-analysis, so rows can't be counted instead.
	AnalysisSeq   int    `json:"analysis_seq"`
	SlackThreadTS string `json:"-"`
	// LatestActivityAt is alert activity (fire/resolve). On the wire it carries
	// the EFFECTIVE activity the list is ordered by — cloneIncident folds in
	// FiredAt and AnalysisActivityAt — so the dashboard column can explain the
	// order instead of the sort running on fields the browser never sees.
	// Internal readers (the flapping window) must use the stored incident.
	LatestActivityAt time.Time `json:"last_activity_at"`
	// AnalysisActivityAt stamps when an analysis last STARTED, and exists only to
	// order the incident list. It is deliberately NOT folded into
	// LatestActivityAt: that field anchors the flapping-correlation window
	// (shouldReuseIncidentForAlertLocked), so re-dating it to analysis time makes
	// a staggered-StartsAt workload fail the window check and split into twins.
	AnalysisActivityAt time.Time `json:"-"`
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
	SimilarIncidents []SimilarIncident `json:"similar_incidents"`
	Feedback         FeedbackSummary   `json:"feedback"`
	IsAnalyzing      bool              `json:"is_analyzing"`
}

type IncidentDetail struct {
	Incident
	AnalysisRunID         string            `json:"analysis_run_id,omitempty"`
	ActiveAnalysisRunID   string            `json:"active_analysis_run_id,omitempty"`
	AnalysisHash          string            `json:"analysis_hash,omitempty"`
	AnalysisSummary       string            `json:"analysis_summary"`
	AnalysisDetail        string            `json:"analysis_detail"`
	AnalysisQuality       string            `json:"analysis_quality"`
	RootCauseFamily       string            `json:"root_cause_family"`
	Capabilities          map[string]string `json:"capabilities"`
	MissingData           []string          `json:"missing_data"`
	Warnings              []string          `json:"warnings"`
	Artifacts             []Artifact        `json:"artifacts"`
	SimilarIncidents      []SimilarIncident `json:"similar_incidents"`
	SimilarRecentCount    int               `json:"similar_recent_count"`
	TokenUsage            map[string]any    `json:"token_usage,omitempty"`
	Harness               map[string]any    `json:"harness,omitempty"`
	ConfidenceDiagnostics map[string]any    `json:"confidence_diagnostics,omitempty"`
	OntologyReasoning     map[string]any    `json:"ontology_reasoning,omitempty"`
	// EvidenceTrace stays internal to the incident-detail projection used by
	// chat; the dashboard keeps owning full artifact/raw-result rendering.
	EvidenceTrace map[string]any  `json:"-"`
	Feedback      FeedbackSummary `json:"feedback"`
	Alerts        []AlertRecord   `json:"alerts"`
}

type RecurrenceDay struct {
	Date     string  `json:"date"`
	Total    int     `json:"total"`
	Recurred int     `json:"recurred"`
	Rate     float64 `json:"rate"`
}

type RecurrenceStats struct {
	Days     int             `json:"days"`
	Rate     float64         `json:"rate"`
	Total    int             `json:"total"`
	Recurred int             `json:"recurred"`
	Daily    []RecurrenceDay `json:"daily"`
}

type LLMSpendBucket struct {
	Calls             int     `json:"calls"`
	CallsWithoutUsage int     `json:"calls_without_usage"`
	FailedCalls       int     `json:"failed_calls"`
	PromptTokens      int     `json:"prompt_tokens"`
	CompletionTokens  int     `json:"completion_tokens"`
	TotalTokens       int     `json:"total_tokens"`
	CostUSD           float64 `json:"cost_usd"`
}

type LLMSpendDay struct {
	Date string `json:"date"`
	LLMSpendBucket
}

type LLMSpendStats struct {
	Days int `json:"days"`
	LLMSpendBucket
	ByModel map[string]LLMSpendBucket `json:"by_model"`
	Daily   []LLMSpendDay             `json:"daily"`
	// HostedEstimates prices the SAME token volume against hosted vendors. The
	// local LLM really is $0; this answers "what would this have cost".
	HostedEstimates []HostedCostEstimate `json:"hosted_estimates"`
	FX              FXRate               `json:"fx"`
}

// HostedCostEstimate is one vendor model's price for the measured token volume.
type HostedCostEstimate struct {
	Provider string  `json:"provider"`
	Model    string  `json:"model"`
	CostUSD  float64 `json:"cost_usd"`
}

// hostedRates are published list prices in USD per 1M tokens, input then output.
// Vendors reprice often, so these are estimate inputs rather than billing
// figures — recheck them against each vendor's pricing page:
//
//	Anthropic  platform.claude.com/docs/en/pricing
//	OpenAI     developers.openai.com/api/docs/pricing
//	Google     ai.google.dev/gemini-api/docs/pricing
//
// Prices below were read from those pages on 2026-07-31. Google's Pro tier
// charges more above a 200k-token prompt; the cheaper band is used here because
// a single RCA call never reaches it.
// Sonnet 5: the $2/$10 introductory price was made permanent on 2026-08-10
// (anthropic.com/news/claude-sonnet-5 edit; the $3/$15 rate scheduled for
// Sept 1 was withdrawn) — the docs pricing page may lag that announcement.
var hostedRates = []struct {
	Provider string
	Model    string
	In       float64
	Out      float64
}{
	{"Anthropic", "Claude Opus 5", 5.00, 25.00},
	{"Anthropic", "Claude Sonnet 5", 2.00, 10.00},
	{"Anthropic", "Claude Haiku 4.5", 1.00, 5.00},
	{"OpenAI", "GPT-5.6 Sol", 5.00, 30.00},
	{"OpenAI", "GPT-5.6 Terra", 2.00, 12.00},
	{"OpenAI", "GPT-5.6 Luna", 0.20, 1.20},
	{"Google", "Gemini 3.1 Pro", 2.00, 12.00},
	{"Google", "Gemini 3.6 Flash", 1.50, 7.50},
	{"Google", "Gemini 3.5 Flash-Lite", 0.30, 2.50},
}

func hostedCostEstimates(promptTokens, completionTokens int) []HostedCostEstimate {
	const perMillion = 1_000_000.0
	out := make([]HostedCostEstimate, 0, len(hostedRates))
	for _, rate := range hostedRates {
		out = append(out, HostedCostEstimate{
			Provider: rate.Provider,
			Model:    rate.Model,
			CostUSD:  (float64(promptTokens)*rate.In + float64(completionTokens)*rate.Out) / perMillion,
		})
	}
	return out
}

type KPIBucket struct {
	Count      int     `json:"count"`
	AvgMinutes float64 `json:"avg_minutes"`
	P50Minutes float64 `json:"p50_minutes"`
	P90Minutes float64 `json:"p90_minutes"`
}

type KPIDay struct {
	Date          string    `json:"date"`
	TimeToRCA     KPIBucket `json:"time_to_rca"`
	TimeToResolve KPIBucket `json:"time_to_resolve"`
}

type KPIStats struct {
	Days          int       `json:"days"`
	TimeToRCA     KPIBucket `json:"time_to_rca"`
	TimeToResolve KPIBucket `json:"time_to_resolve"`
	Daily         []KPIDay  `json:"daily"`
}

type Server struct {
	store                     *Store
	hub                       *Hub
	agentURL                  string
	knowledgeValidatorURL     string
	language                  string
	agentRequestTimeout       time.Duration
	manualAgentRequestTimeout time.Duration
	agentResponseMaxBytes     int64
	client                    *http.Client
	agentSlots                chan struct{}
	// The family catalog changes only when the agent redeploys, but it used to
	// be fetched from the agent on EVERY evaluation save — the whole perceived
	// save latency whenever the agent was busy analyzing.
	familyCatalogMu        sync.Mutex
	familyCatalog          RootCauseFamilyCatalog
	familyCatalogFetchedAt time.Time
	autoAnalyzeMu          sync.Mutex
	autoAnalyzeStarts      []time.Time
	autoAnalyzeFanout      int
	// Severities eligible for AUTO analysis. nil = every ingested severity (except
	// info, dropped by ignoredAlert). Manual analysis is never gated by this.
	autoAnalyzeSeverities map[string]bool
	backfillInterval      time.Duration
	backfillBatch         int
	backfillRetryCooldown time.Duration
	trashRetention        time.Duration
	slack                 *SlackNotifier
	fxRateURL             string
	fxMu                  sync.RWMutex
	fx                    FXRate
}

const (
	similarIncidentLimit = 3
	// Blended scale with an IDF-weighted cosine (see idfWeight / blendedSimilarity).
	// Measured end to end through SimilarIncidentsForAlert on this package's own
	// fixtures, with identity labels held IDENTICAL so only content differs:
	//
	//   genuine same-root-cause match ............ 0.8840
	//   same-alertname, different root cause ..... 0.5620
	//
	// 0.70 sits mid-gap, ~0.14 clear of both. It is not a restored guess: the
	// bar briefly went to 0.60 while idfWeightedVector still charged the query
	// for tokens no stored document has, which taxed every score and made the
	// same pair score lower as the corpus grew. Dropping those tokens removed
	// the tax, and the measurement above is on the corrected formula.
	minFeedbackHintSimilarity = 0.70
	// Recurrence counting still runs the additive identity formula, so it keeps
	// the original bar. Sharing one constant across two scales would silently
	// loosen "did this fire again in 7d".
	minRecurrenceSimilarity = 0.80
	flappingGroupWindow     = 30 * time.Minute
	maxListLimit            = 200
	maxJSONBodyBytes        = 1 << 20
	maxProgressBodyBytes    = 64 << 10
	maxEmbeddingQueryBytes  = 4000
	maxWebhookAlerts        = 500
	// Default caps; overridable via MAX_AUTO_ANALYZE_FANOUT / MAX_CONCURRENT_AGENT_RUNS.
	maxAutoAnalyzeFanout      = 50
	maxManualAnalyzeFanout    = 50
	maxConcurrentAgentRuns    = maxManualAnalyzeFanout
	autoAnalyzeWindow         = time.Minute
	defaultTrashRetentionDays = 30
)

// autoFanoutLimit is the effective per-webhook / per-window auto-analysis cap.
// Falls back to the const default when unset (e.g. tests that build Server literals).
func (s *Server) autoFanoutLimit() int {
	if s.autoAnalyzeFanout > 0 {
		return s.autoAnalyzeFanout
	}
	return maxAutoAnalyzeFanout
}

// parseAutoAnalyzeSeverities parses AUTO_ANALYZE_SEVERITIES (e.g. "warning,critical").
// Empty / "all" / "*" -> nil, meaning no severity gating (auto-analyze every ingested
// severity). Otherwise only the listed severities are auto-analyzed.
func parseAutoAnalyzeSeverities(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "all") || raw == "*" {
		return nil
	}
	set := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if v := strings.ToLower(strings.TrimSpace(part)); v != "" {
			set[v] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// severityAutoAnalyzable reports whether a severity is eligible for AUTO analysis
// (webhook fan-out + backfill). Manual/comment re-analysis is never gated by this.
func (s *Server) severityAutoAnalyzable(sev string) bool {
	if s.autoAnalyzeSeverities == nil {
		return true
	}
	return s.autoAnalyzeSeverities[strings.ToLower(strings.TrimSpace(sev))]
}

func (s *Server) autoAnalyzeAllowed(alert Alert) bool {
	return s.severityAutoAnalyzable(severity(alert))
}

func Run() {
	port := getenv("PORT", "8080")
	server := NewServer()

	if os.Getenv("RCA_DEV_SEED") == "1" {
		server.store.SeedDevFixtures()
		log.Printf("RCA_DEV_SEED=1: injected dev knowledge-review fixtures (not for production)")
	}

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

	if err := server.slack.Validate(); err != nil {
		log.Printf("slack: startup validation failed: %v", err)
	}

	go server.runBackfill(ctx)
	go server.runStaleRunReaper(ctx)
	go server.runTrashPurge(ctx)
	go server.runSlackDeliveryRetry(ctx)
	go server.runSlackSocketMode(ctx)
	go server.runFXRefresh(ctx)

	go func() {
		log.Printf("Run:AI RCA backend listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	stop()
	server.store.stopEmbeddingBackfill()
	log.Printf("shutdown signal received, draining connections")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func NewServer() *Server {
	store := NewStore()
	// Defaults must exceed the agent's ANALYSIS_DEADLINE_SECONDS (900): the agent
	// works up to that budget then returns a graceful degraded report — hanging up
	// earlier loses the report and leaves the alert with a useless fallback.
	agentRequestTimeout := time.Duration(getenvInt("AGENT_REQUEST_TIMEOUT_SECONDS", 960)) * time.Second
	if agentRequestTimeout <= 0 {
		agentRequestTimeout = 1560 * time.Second
	}
	manualAgentRequestTimeout := time.Duration(getenvInt("MANUAL_AGENT_REQUEST_TIMEOUT_SECONDS", 960)) * time.Second
	if manualAgentRequestTimeout <= 0 {
		manualAgentRequestTimeout = 1560 * time.Second
	}
	agentResponseMaxBytes := int64(getenvInt("AGENT_MAX_RESPONSE_BODY_BYTES", int(maxAgentResponseBodyBytes)))
	if agentResponseMaxBytes <= 0 {
		agentResponseMaxBytes = maxAgentResponseBodyBytes
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
	trashRetentionDays := getenvInt("TRASH_RETENTION_DAYS", defaultTrashRetentionDays)
	if trashRetentionDays < 0 {
		trashRetentionDays = defaultTrashRetentionDays
	}
	agentURL := strings.TrimRight(getenv("AGENT_URL", "http://localhost:8000"), "/")
	return &Server{
		store:    store,
		hub:      NewHub(),
		agentURL: agentURL,
		// KNOWLEDGE_VALIDATOR_URL is the Agent service base URL. The approval
		// flow consistently appends /knowledge/validate, avoiding a deployment
		// dependency on the public analysis route or a duplicated path suffix.
		knowledgeValidatorURL:     strings.TrimRight(first(os.Getenv("KNOWLEDGE_VALIDATOR_URL"), os.Getenv("AGENT_INTERNAL_URL"), agentURL), "/"),
		language:                  getenv("LANGUAGE", "en"),
		agentRequestTimeout:       agentRequestTimeout,
		manualAgentRequestTimeout: manualAgentRequestTimeout,
		agentResponseMaxBytes:     agentResponseMaxBytes,
		client:                    &http.Client{},
		agentSlots:                make(chan struct{}, concurrency),
		autoAnalyzeFanout:         autoFanout,
		autoAnalyzeSeverities:     parseAutoAnalyzeSeverities(getenv("AUTO_ANALYZE_SEVERITIES", "")),
		// Backfill re-drives alerts left without a completed RCA (dropped by the
		// caps, or a prior failed run). Interval 0 disables it.
		backfillInterval:      time.Duration(getenvInt("ANALYSIS_BACKFILL_INTERVAL_SECONDS", 300)) * time.Second,
		backfillBatch:         backfillBatch,
		backfillRetryCooldown: time.Duration(getenvInt("ANALYSIS_BACKFILL_RETRY_COOLDOWN_SECONDS", 900)) * time.Second,
		trashRetention:        time.Duration(trashRetentionDays) * 24 * time.Hour,
		slack:                 NewSlackNotifierFromEnv(),
		// ECB reference rates, no API key. The .dev/v1 host is where the older
		// frankfurter.app URL redirects — naming it directly skips the hop. A
		// cluster without egress keeps the configured fallback so the won
		// figures still render, flagged as a fallback in the UI.
		fxRateURL: getenv("FX_RATE_URL", "https://api.frankfurter.dev/v1/latest?from=USD&to=KRW"),
		fx:        FXRate{USDKRW: fallbackUSDKRW(), Fallback: true},
	}
}

// fallbackUSDKRW is the rate used until the first successful fetch, and for the
// lifetime of a deployment that cannot reach the feed at all. The default is a
// recent observed rate, not a floor — a blocked cluster should override it.
func fallbackUSDKRW() float64 {
	const recentObservedRate = 1452 // 2026-07-29, ECB reference
	rate := getenvInt("FX_USD_KRW_FALLBACK", recentObservedRate)
	if rate <= 0 {
		rate = recentObservedRate
	}
	return float64(rate)
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
			"slack":    s.slack.Health(),
		})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/openapi.json":
		s.handleOpenAPISpec(w, r)
	case r.Method == http.MethodGet && (r.URL.Path == "/api-docs" || r.URL.Path == "/api-docs/"):
		s.handleAPIDocs(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/webhook/alertmanager":
		s.handleAlertmanager(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/incidents":
		s.handleIncidentList(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/incidents/bulk":
		s.handleIncidentBulkAction(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/incidents/trash":
		s.handleEmptyIncidentTrash(w, r)
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
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/knowledge/runtime-snapshot":
		s.handleKnowledgeRuntimeSnapshot(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/knowledge/probe-metrics":
		s.handleProbeMetrics(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/knowledge/families":
		s.handleRootCauseFamilies(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/knowledge/family-suggestions":
		s.handleFamilySuggestions(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/knowledge-candidates") || strings.HasPrefix(r.URL.Path, "/api/v1/knowledge-packages"):
		s.handleKnowledge(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPut) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/analysis-runs/"):
		s.handleAnalysisRunEvaluation(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/analysis-runs/"):
		s.handleAnalysisRunAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stats/recurrence":
		s.handleRecurrenceStats(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stats/llm-spend":
		s.handleLLMSpendStats(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/stats/kpi":
		s.handleKPIStats(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/events":
		s.handleEvents(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/chat/conversations"):
		s.handleChatConversations(w, r)
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
	view := first(r.URL.Query().Get("view"), incidentViewActive)
	if !validIncidentView(view) {
		writeError(w, http.StatusBadRequest, "invalid incident view")
		return
	}
	filter := IncidentListFilter{
		Status:        strings.TrimSpace(r.URL.Query().Get("status")),
		Severity:      strings.TrimSpace(r.URL.Query().Get("severity")),
		FinalDecision: strings.TrimSpace(r.URL.Query().Get("final_decision")),
		Search:        strings.TrimSpace(r.URL.Query().Get("q")),
		Sort:          strings.TrimSpace(r.URL.Query().Get("sort")),
		Ascending:     r.URL.Query().Get("order") == "asc",
	}
	if !validIncidentSort(filter.Sort) {
		writeError(w, http.StatusBadRequest, "invalid incident sort")
		return
	}
	if !validIncidentStatusFilter(filter.Status) {
		writeError(w, http.StatusBadRequest, "invalid incident status filter")
		return
	}
	if !validIncidentSeverityFilter(filter.Severity) {
		writeError(w, http.StatusBadRequest, "invalid incident severity filter")
		return
	}
	if !validIncidentFinalDecisionFilter(filter.FinalDecision) {
		writeError(w, http.StatusBadRequest, "invalid incident final decision filter")
		return
	}
	items, total, counts := s.store.ListIncidentsPageFilteredWithCounts(page.Limit, page.Offset, view, filter)
	writeJSON(w, http.StatusOK, paginatedEnvelope(items, page, total, &counts))
}

func (s *Server) handleAlertList(w http.ResponseWriter, r *http.Request) {
	page, err := paginationFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filter := AlertListFilter{
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Search:   strings.TrimSpace(r.URL.Query().Get("q")),
	}
	if !validIncidentStatusFilter(filter.Status) {
		writeError(w, http.StatusBadRequest, "invalid alert status filter")
		return
	}
	if !validIncidentSeverityFilter(filter.Severity) {
		writeError(w, http.StatusBadRequest, "invalid alert severity filter")
		return
	}
	items, total := s.store.ListAlertsPageFiltered(page.Limit, page.Offset, filter)
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

func (s *Server) handleRecurrenceStats(w http.ResponseWriter, r *http.Request) {
	days, ok := daysFromRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, envelope(s.store.RecurrenceStats(days, time.Now().UTC())))
}

func (s *Server) handleLLMSpendStats(w http.ResponseWriter, r *http.Request) {
	days, ok := daysFromRequest(w, r)
	if !ok {
		return
	}
	stats := s.store.LLMSpendStats(days, time.Now().UTC())
	// The rate travels once and the dashboard multiplies, so every dollar figure
	// on the panel converts against the same number.
	stats.FX = s.fxRate()
	writeJSON(w, http.StatusOK, envelope(stats))
}

func (s *Server) handleKPIStats(w http.ResponseWriter, r *http.Request) {
	days, ok := daysFromRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, envelope(s.store.KPIStats(days, time.Now().UTC())))
}

func daysFromRequest(w http.ResponseWriter, r *http.Request) (int, bool) {
	days := 7
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid days")
			return 0, false
		}
		days = parsed
	}
	if days < 1 {
		days = 1
	}
	if days > 90 {
		days = 90
	}
	return days, true
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
	alertName := first(labels["alertname"], labels["alert_name"])
	// The subject is whatever the alert is actually about. A pod/workload wins;
	// node-scoped alerts (XID, node unschedulable) carry no pod, so they key on the
	// node and dgx01 stays apart from dgx02. Target/service-level alerts
	// (TargetDown) have neither — they key on the namespace alone, so a namespace
	// whose scrape targets all go down is ONE incident instead of a row per target.
	// Requiring a workload here used to drop every one of those into the
	// per-fingerprint bucket below, where the flapping window never runs.
	subject := first(workloadIdentity(alert), nodeIdentity(alert))
	if alertName != "" && (namespace != "" || subject != "") {
		return strings.Join([]string{
			"flap",
			keyPart(first(cluster, "cluster-unknown")),
			keyPart(namespace),
			keyPart(subject),
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

	return diskPressureGroupInfo{Node: nodeIdentity(alert), Reason: reason}, true
}

// nodeIdentity returns the node an alert is about, for alerts that name no pod.
func nodeIdentity(alert Alert) string {
	labels := alert.Labels
	return first(
		labels["node"],
		labels["node_name"],
		labels["nodename"],
		labels["kubernetes_node"],
		labels["instance"],
	)
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

// workloadKindLabels mirror the agent's resolve_target: kube-state-metrics names
// the failing object in a workload-KIND label (daemonset/deployment/…), and on
// those metric families the `pod` label is the KSM EXPORTER pod that served the
// metric, NOT a subject pod. `job` is deliberately excluded (in Prometheus that
// is the scrape job, e.g. job="kube-state-metrics"); the KSM Job object uses
// `job_name`.
var workloadKindLabels = []string{
	"daemonset",
	"deployment",
	"statefulset",
	"replicaset",
	"cronjob",
	"job_name",
}

// podName extracts the concrete pod name behind an alert occurrence. When a
// workload-kind label named the subject, the `pod` label is the KSM exporter and
// is dropped — the real workload pods are discovered later by the agent and
// applied in ApplyAnalysisForRun. Direct pod alerts (no workload-kind label)
// keep the `pod` label, which is the real subject.
func podName(alert Alert) string {
	for _, key := range workloadKindLabels {
		if strings.TrimSpace(alert.Labels[key]) != "" || strings.TrimSpace(alert.Annotations[key]) != "" {
			return ""
		}
	}
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

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if child, ok := v.(map[string]any); ok {
			out[k] = cloneAnyMap(child)
			continue
		}
		out[k] = v
	}
	return out
}

func firstAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

func cloneIncident(in *Incident) *Incident {
	if in == nil {
		return nil
	}
	out := *in
	// Only clones leave the store, so folding here makes every serialization
	// agree with the list order without ever touching the stored field.
	out.LatestActivityAt = incidentActivityAt(in)
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
	out.Metadata = cloneAnyMap(in.Metadata)
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
	startsAt := ""
	if !record.FiredAt.IsZero() {
		startsAt = record.FiredAt.UTC().Format(time.RFC3339Nano)
	}
	endsAt := ""
	if record.ResolvedAt != nil && !record.ResolvedAt.IsZero() {
		endsAt = record.ResolvedAt.UTC().Format(time.RFC3339Nano)
	}
	return Alert{
		Status:      record.Status,
		Labels:      cloneMap(record.Labels),
		Annotations: cloneMap(record.Annotations),
		StartsAt:    startsAt,
		EndsAt:      endsAt,
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
	Total   int                 `json:"total"`
	Limit   int                 `json:"limit"`
	Offset  int                 `json:"offset"`
	HasMore bool                `json:"has_more"`
	Counts  *IncidentListCounts `json:"counts,omitempty"`
}

func paginatedEnvelope(data any, page paginationRequest, total int, counts ...*IncidentListCounts) map[string]any {
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
	if len(counts) > 0 && counts[0] != nil {
		pageInfo := payload["pagination"].(paginationInfo)
		pageInfo.Counts = counts[0]
		payload["pagination"] = pageInfo
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
