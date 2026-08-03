package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// embeddingDim is the default dimensionality of the dense vectors stored in the
// pgvector `embedding` column. The backend has no embedding model dependency by
// default (it must run offline next to the NeMo agent), so dense vectors are
// produced deterministically from text with the feature-hashing trick. When a
// real embedding model is configured (EMBEDDING_URL), its dimension is read
// from EMBEDDING_DIM instead. Changing this value invalidates previously
// persisted vectors of a different dimension — mixed-dim vectors can't be
// compared, so switching embedding modes requires re-embedding existing rows.
const (
	embeddingDim             = 384
	maxFeedbackHintTextBytes = 800
)

// embedder produces dense vectors for similarity search. When endpoint is set
// (EMBEDDING_URL), it calls an OpenAI-compatible {endpoint}/embeddings API and
// uses the returned multilingual vector; otherwise (or on any failure) it falls
// back to the deterministic feature-hashing denseEmbedding so the backend keeps
// working fully offline. dim is the stored pgvector column dimension and must
// match the model's output when the endpoint is set.
type embedder struct {
	endpoint string
	model    string
	apiKey   string
	dim      int
	client   *http.Client
}

type embeddingBasis string

const (
	embeddingBasisHash   embeddingBasis = "hash"
	embeddingBasisRemote embeddingBasis = "remote"
)

type embedResult struct {
	vector []float32
	basis  embeddingBasis
	err    error
}

// newEmbedder reads embedding config from the environment. With no EMBEDDING_URL
// it returns a hash-only embedder (default, offline). Kept out of NewServer so
// the Store owns the config that its embed() calls depend on.
func newEmbedder() *embedder {
	dim := getenvInt("EMBEDDING_DIM", embeddingDim)
	if dim <= 0 {
		dim = embeddingDim
	}
	endpoint := strings.TrimRight(strings.TrimSpace(os.Getenv("EMBEDDING_URL")), "/")
	if endpoint == "" {
		// ponytail: hash fallback ignores EMBEDDING_DIM to keep the historically
		// fixed offline dim; only a real model needs a matching custom dim.
		dim = embeddingDim
	}
	return &embedder{
		endpoint: endpoint,
		model:    strings.TrimSpace(os.Getenv("EMBEDDING_MODEL")),
		apiKey:   strings.TrimSpace(os.Getenv("EMBEDDING_API_KEY")),
		dim:      dim,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// embed produces the stored dense vector for text via the store's embedder,
// tolerating a nil embedder (e.g. Store literals in tests) by using the hash.
func (s *Store) embed(text string) []float32 {
	result := s.embedResult(text)
	if result.err != nil {
		log.Printf("WARNING: embedding endpoint failed, falling back to hash embedding: %v", result.err)
	}
	return result.vector
}

func (s *Store) embedResult(text string) embedResult {
	if s.embedder == nil {
		return embedResult{vector: denseEmbedding(text, embeddingDim), basis: embeddingBasisHash}
	}
	return s.embedder.embedResult(text)
}

// embeddingDim is the pgvector column dimension the store persists and queries.
func (s *Store) embeddingDim() int {
	if s.embedder == nil {
		return embeddingDim
	}
	return s.embedder.dim
}

// embed returns an L2-normalized dense vector of length e.dim. It calls the
// configured OpenAI-compatible endpoint when set, and falls back to the
// hash embedding on any error so an incident write/search is never blocked.
func (e *embedder) embed(text string) []float32 {
	return e.embedContext(context.Background(), text)
}

func (e *embedder) embedContext(ctx context.Context, text string) []float32 {
	result := e.embedResultContext(ctx, text)
	if result.err != nil {
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("WARNING: embedding endpoint failed, falling back to hash embedding: %v", result.err)
	}
	return result.vector
}

func (e *embedder) embedResult(text string) embedResult {
	return e.embedResultContext(context.Background(), text)
}

func (e *embedder) embedResultContext(ctx context.Context, text string) embedResult {
	if e == nil || e.endpoint == "" {
		return embedResult{vector: denseEmbedding(text, embeddingDim), basis: embeddingBasisHash}
	}
	vector, err := e.remoteEmbedContext(ctx, text)
	if err != nil {
		if ctx.Err() != nil {
			return embedResult{basis: embeddingBasisHash, err: err}
		}
		return embedResult{vector: denseEmbedding(text, e.dim), basis: embeddingBasisHash, err: err}
	}
	return embedResult{vector: normalize(vector), basis: embeddingBasisRemote}
}

// remoteEmbed POSTs to {endpoint}/embeddings and returns the raw model vector.
// The response follows the OpenAI embeddings schema: {"data":[{"embedding":[...]}]}.
func (e *embedder) remoteEmbed(text string) ([]float32, error) {
	return e.remoteEmbedContext(context.Background(), text)
}

func (e *embedder) remoteEmbedContext(parent context.Context, text string) ([]float32, error) {
	body, err := json.Marshal(map[string]any{"model": e.model, "input": text})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embeddings endpoint status %d", resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embeddings endpoint returned no vector")
	}
	got := parsed.Data[0].Embedding
	if len(got) != e.dim {
		return nil, fmt.Errorf("embedding dim mismatch: got %d, EMBEDDING_DIM=%d", len(got), e.dim)
	}
	return got, nil
}

type IncidentMemory struct {
	IncidentID      string
	AlertID         string
	Title           string
	Severity        string
	Status          string
	AnalysisSummary string
	AnalysisDetail  string
	Labels          map[string]string
	CreatedAt       time.Time
	Vector          map[string]float64
}

func (s *Store) SimilarIncidentsForAlert(alert Alert, incidentID string, limit int) []SimilarIncident {
	limit = capSimilarIncidentLimit(limit)
	// Read the query text under a brief lock and release it before searching:
	// embedding and pgvector are network I/O and must never run under the store
	// lock.
	s.mu.RLock()
	query := s.similarIncidentQueryLocked(alert, incidentID)
	s.mu.RUnlock()
	// Prefer the dense index only when it is actually semantic (a real embedding
	// model, remote basis). Without EMBEDDING_URL configured -- the chart
	// default -- pgvector still answers, but "dense-lexical" is signed feature
	// hashing over the same bag of words the sparse path already has, now IDF-
	// weighted; the hash has no IDF, so it is the WEAKER of the two, not the
	// stronger. retrieval_kind carries the basis: all rows from one dbSearch
	// call share it, so checking results[0] is enough.
	if results, ok := s.dbSearchSimilarIncidents(query, incidentID, limit); ok && len(results) > 0 && results[0].RetrievalKind == retrievalKindDenseSemantic {
		return results
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.similarIncidentsLocked(alert, incidentID, limit)
}

// similarIncidentQueryLocked builds the search text the way memoryText builds
// the stored document, so the two sides are comparable.
//
// Querying with the alert alone made the panel rank by how alike the ALERTS
// look: the stored document carries the other incident's RCA, but the query
// carried none of this incident's, so an identical alertname outscored an
// identical root cause — the OOM incident whose diagnosis matched word for word
// lost to one that only shared a title. Once this incident has an RCA of its
// own, compare diagnosis to diagnosis. Before analysis lands, the alert is all
// there is.
func (s *Store) similarIncidentQueryLocked(alert Alert, incidentID string) string {
	parts := []string{alertSearchText(alert)}
	if run := s.latestAnalysisRunForIncidentLocked(incidentID); run != nil {
		for _, value := range []string{run.AnalysisSummary, run.AnalysisDetail} {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
	}
	return strings.Join(parts, " ")
}

func (s *Store) FeedbackHintsForAlert(alert Alert, incidentID string, limit int) []FeedbackHint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit = capSimilarIncidentLimit(limit)
	similar := s.similarIncidentsLocked(alert, incidentID, limit)
	hints := make([]FeedbackHint, 0, limit)
	seenComments := map[string]struct{}{}
	for _, item := range similar {
		// Only import another incident's feedback/comments when it is GENUINELY
		// similar. similarIncidentsLocked returns the top-N with no floor, so with
		// the lexical (jsonb) fallback an unrelated incident's comments leaked into
		// every analysis as "learning hints" and polluted the report.
		if item.Similarity < minFeedbackHintSimilarity {
			continue
		}
		if item.PositiveFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "positive",
				Weight:    item.Similarity,
				Text:      excerpt(fmt.Sprintf("Operators found this prior RCA useful: %s", item.AnalysisSummary), maxFeedbackHintTextBytes),
				CreatedAt: item.CreatedAt,
			})
			if len(hints) >= limit {
				return hints
			}
		}
		if item.NegativeFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "negative",
				Weight:    item.Similarity,
				Text:      excerpt(fmt.Sprintf("Operators pushed back on this prior RCA: %s", item.AnalysisSummary), maxFeedbackHintTextBytes),
				CreatedAt: item.CreatedAt,
			})
			if len(hints) >= limit {
				return hints
			}
		}
		for _, comment := range s.commentsForTargetLocked("incident", item.IncidentID) {
			if _, ok := seenComments[comment.CommentID]; ok {
				continue
			}
			seenComments[comment.CommentID] = struct{}{}
			if len(hints) >= limit {
				return hints
			}
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "comment",
				Weight:    item.Similarity,
				Text:      excerpt(comment.Body, maxFeedbackHintTextBytes),
				CreatedAt: comment.CreatedAt,
			})
			if len(hints) >= limit {
				return hints
			}
		}
		if len(hints) >= limit {
			return hints
		}
	}
	return hints
}

func capSimilarIncidentLimit(limit int) int {
	if limit <= 0 || limit > similarIncidentLimit {
		return similarIncidentLimit
	}
	return limit
}

func (s *Store) SearchIncidentMemory(query string, limit int) []SimilarIncident {
	return s.SearchIncidentMemoryExcluding(query, "", limit)
}

// SearchIncidentMemoryExcluding is the same search with one incident held out.
// The analysing incident must never match itself: the agent re-runs this search
// mid-analysis with its own collected evidence as the query, and its own memory
// row (if it has one from an earlier run) is by construction the closest text in
// the corpus. Chat and the operator search pass "" and are unaffected.
func (s *Store) SearchIncidentMemoryExcluding(
	query, excludedIncidentID string,
	limit int,
) []SimilarIncident {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	if results, ok := s.dbSearchMemoryExcluding(query, excludedIncidentID, limit); ok && len(results) > 0 {
		return results
	}
	queryVector := textVector(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	df, corpusSize := corpusDocFreqLocked(s.memories)
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil || !incidentUserApproved(s.incidents[memory.IncidentID]) || incidentDeleted(s.incidents[memory.IncidentID]) {
			continue
		}
		if excludedIncidentID != "" && memory.IncidentID == excludedIncidentID {
			continue
		}
		score := idfCosineSimilarity(queryVector, memory.Vector, df, corpusSize)
		if score <= 0.05 {
			continue
		}
		summary := s.feedbackSummaryLocked("incident", memory.IncidentID)
		results = append(results, SimilarIncident{
			IncidentID:       memory.IncidentID,
			AlertID:          memory.AlertID,
			Title:            memory.Title,
			Severity:         memory.Severity,
			Status:           memory.Status,
			Similarity:       math.Round(score*1000) / 1000,
			AnalysisSummary:  memory.AnalysisSummary,
			AnalysisDetail:   excerpt(memory.AnalysisDetail, 900),
			PositiveFeedback: summary.Positive,
			NegativeFeedback: summary.Negative,
			CommentCount:     len(summary.Comments),
			Labels:           cloneMap(memory.Labels),
			CreatedAt:        memory.CreatedAt,
			RetrievalKind:    retrievalKindSparseIdentity,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Similarity == results[j].Similarity {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		}
		return results[i].Similarity > results[j].Similarity
	})
	return dedupeSimilarByIncident(results, limit)
}

func (s *Store) ApplyAnalysis(alertID string, response AgentAnalysisResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil {
		return
	}
	s.applyAnalysisLocked(alert, response)
	// Test-only helper: mirror production, where every applied analysis is backed by
	// a completed analysis_run. IncidentDetail sources the incident RCA from the run.
	now := time.Now().UTC()
	runID := "RUN-" + alertID
	s.analysisRuns[runID] = &AnalysisRun{
		RunID:           runID,
		Status:          "complete",
		TargetType:      "alert",
		TargetID:        alertID,
		IncidentID:      alert.IncidentID,
		AlertID:         alertID,
		AnalysisSummary: response.AnalysisSummary,
		AnalysisDetail:  first(response.AnalysisDetail, response.Analysis),
		AnalysisQuality: response.AnalysisQuality,
		RootCauseFamily: response.RootCauseFamily,
		Capabilities:    response.Capabilities,
		MissingData:     response.MissingData,
		Warnings:        response.Warnings,
		Artifacts:       response.Artifacts,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// IsSupersededAnalysisRun reports whether a fresher analysis run has been started
// for the alert since runID — i.e. this run's result is stale and will not be
// applied. Lets callers distinguish "superseded" from a real persistence failure.
func (s *Store) IsSupersededAnalysisRun(runID string, alertID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.alerts[alertID] != nil && !s.isLatestAnalysisRunForAlertLocked(runID, alertID)
}

// ApplyAnalysisForRun applies a completed RCA only when this run is still the
// newest analysis run for the alert. Slow older runs may finish after a fresher
// operator-triggered run; those stale results remain auditable in analysis_runs
// but must not overwrite the visible RCA.
func (s *Store) ApplyAnalysisForRun(runID string, alertID string, response AgentAnalysisResponse) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil || !s.isLatestAnalysisRunForAlertLocked(runID, alertID) {
		return false
	}
	// The RCA itself lives on the analysis run (CompleteAnalysisRun); here we
	// clear the analyzing flag, apply the agent-discovered affected pods, and
	// refresh the incident's aggregate state. The `response` is otherwise
	// retained on the run, not duplicated onto the alert.
	before := cloneAlert(alert)
	alert.IsAnalyzing = false
	// Fold the real workload pods the agent discovered for the alert subject into
	// the occurrence list (dedup + cap). Because ingestion no longer seeds the
	// kube-state-metrics exporter for workload-kind alerts, the KSM case starts
	// empty and ends up holding only the real pods; direct pod alerts keep their
	// cross-firing history and simply re-affirm the current pod. Empty means the
	// investigation was unscoped, so nothing changes.
	for _, pod := range response.AffectedPods {
		alert.OccurrencePods = appendOccurrencePod(alert.OccurrencePods, pod)
	}
	if !s.persistAlertLocked(alert) {
		*alert = *before
		alert.IsAnalyzing = false
		if incident := s.incidents[alert.IncidentID]; incident != nil {
			s.refreshIncidentAnalyzingLocked(incident.IncidentID)
			s.persistIncidentLocked(incident)
		}
		s.persistAlertLocked(alert)
		return false
	}
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		s.refreshIncidentAnalyzingLocked(incident.IncidentID)
		s.persistIncidentLocked(incident)
	}
	s.invalidateRecurrenceStatsLocked()
	return true
}

func (s *Store) applyAnalysisLocked(alert *AlertRecord, response AgentAnalysisResponse) {
	// RCA lives on the analysis run now; this only clears the analyzing flag.
	_ = response
	alert.IsAnalyzing = false
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		s.refreshIncidentAnalyzingLocked(incident.IncidentID)
		s.persistIncidentLocked(incident)
	}
	s.persistAlertLocked(alert)
	s.invalidateRecurrenceStatsLocked()
}

func (s *Store) MarkAnalyzing(incidentID string, analyzing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = analyzing
	}
}

// BeginAnalyzing flags the incident and alert as analyzing so the dashboard can
// render an in-progress state for the whole lifecycle, and records the start as
// incident activity. Starting an analysis IS activity, so the ordinary
// newest-activity-first order floats the row the operator is waiting on — the
// incident list needs no separate analyzing-first sort branch.
func (s *Store) BeginAnalyzing(incidentID string, alertID string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = true
		incident.AnalysisActivityAt = now
		s.persistIncidentLocked(incident)
	}
	if alert := s.alerts[alertID]; alert != nil {
		alert.IsAnalyzing = true
		s.persistAlertLocked(alert)
	}
}

// BeginManualAnalysis marks a dashboard-triggered reanalysis in progress. The
// last good RCA stays visible because CreateAnalysisRunIfAllowed keeps it on the
// reused run, not because this does anything different from BeginAnalyzing.
func (s *Store) BeginManualAnalysis(incidentID string, alertID string) {
	s.BeginAnalyzing(incidentID, alertID)
}

// ApplyFallbackAnalysisIfAbsent implements the overwrite policy for failed runs:
// a successful RCA already attached to the alert is always preserved, and the
// fallback RCA is only surfaced on the alert when there is nothing to keep. It
// returns true when the fallback was written. The analyzing flags are cleared in
// both cases. Fallback RCA is never written to incident memory.
func (s *Store) ApplyFallbackAnalysisIfAbsent(alertID string, response AgentAnalysisResponse) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil {
		return false
	}
	return s.applyFallbackAnalysisIfAbsentLocked(alert, response)
}

// ApplyFallbackAnalysisIfAbsentForRun is the guarded version used by async run
// completion. It prevents an older failed run from clearing the analyzing state
// or surfacing fallback text after a newer run has already started.
func (s *Store) ApplyFallbackAnalysisIfAbsentForRun(runID string, alertID string, response AgentAnalysisResponse) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil || !s.isLatestAnalysisRunForAlertLocked(runID, alertID) {
		return false
	}
	return s.applyFallbackAnalysisIfAbsentLocked(alert, response)
}

func (s *Store) applyFallbackAnalysisIfAbsentLocked(alert *AlertRecord, response AgentAnalysisResponse) bool {
	// The fallback RCA is already stored on the failed run (FailAnalysisRun), and
	// latestAnalysisRunForIncidentLocked prefers a `complete` run over a failed one —
	// so the "keep the successful RCA, only surface fallback if nothing else" policy
	// is handled by run selection. Here we just clear the analyzing state.
	_ = response
	alert.IsAnalyzing = false
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		s.refreshIncidentAnalyzingLocked(incident.IncidentID)
		s.persistIncidentLocked(incident)
	}
	s.persistAlertLocked(alert)
	s.invalidateRecurrenceStatsLocked()
	return true
}

func (s *Store) isLatestAnalysisRunForAlertLocked(runID string, alertID string) bool {
	if runID == "" || alertID == "" {
		return true
	}
	current := s.analysisRuns[runID]
	if current == nil {
		return false
	}
	for _, other := range s.analysisRuns {
		if other == nil || other.RunID == current.RunID || other.AlertID != alertID {
			continue
		}
		if other.CreatedAt.After(current.CreatedAt) ||
			(other.CreatedAt.Equal(current.CreatedAt) && other.RunID > current.RunID) {
			return false
		}
	}
	return true
}

func (s *Store) refreshIncidentAnalyzingLocked(incidentID string) {
	incident := s.incidents[incidentID]
	if incident == nil {
		return
	}
	incident.IsAnalyzing = false
	for _, alert := range s.alerts {
		if alert != nil && alert.IncidentID == incidentID && alert.IsAnalyzing {
			incident.IsAnalyzing = true
			return
		}
	}
}

func (s *Store) upsertMemoryLocked(incident *Incident, alert *AlertRecord) {
	if incident == nil || alert == nil || !incidentUserApproved(incident) {
		return
	}
	run := s.latestAnalysisRunForIncidentLocked(incident.IncidentID)
	if run == nil {
		return
	}
	// Incident-scoped, not alert-scoped: key by incident so a changed representative
	// alert across re-approvals updates the one row instead of accumulating dupes.
	// AlertID stays empty -> map key = IncidentID, DB unique (incident_id, '') = 1/incident.
	memory := &IncidentMemory{
		IncidentID:      incident.IncidentID,
		AlertID:         "",
		Title:           incident.Title,
		Severity:        incident.Severity,
		Status:          incident.Status,
		AnalysisSummary: run.AnalysisSummary,
		AnalysisDetail:  run.AnalysisDetail,
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
	}
	memory.Vector = textVector(memoryText(*memory))
	s.memories[first(memory.AlertID, memory.IncidentID)] = memory
	// The remote embedding call (up to 15s) plus the DB upsert must not run
	// under the global store mutex: one approve used to stall every read and
	// write behind the lock, which surfaced as "approve and the incident list
	// are slow". The row is an idempotent upsert of an immutable value, and
	// the in-memory entry above is already visible, so persistence is safe to
	// finish asynchronously.
	snapshot := *memory
	snapshot.Labels = cloneMap(memory.Labels)
	snapshot.Vector = make(map[string]float64, len(memory.Vector))
	for token, weight := range memory.Vector {
		snapshot.Vector[token] = weight
	}
	go s.persistMemory(&snapshot)
	s.invalidateRecurrenceStatsLocked()
}

func (s *Store) upsertApprovedIncidentMemoriesLocked(incident *Incident) {
	if !incidentUserApproved(incident) {
		return
	}
	// One memory per incident, keyed to the analyzed alert (the run's target), so
	// approving doesn't fan out identical embeddings across sibling alerts.
	run := s.latestAnalysisRunForIncidentLocked(incident.IncidentID)
	if run == nil {
		return
	}
	alert := s.alerts[run.AlertID]
	if alert == nil {
		for _, member := range s.alerts {
			if member != nil && member.IncidentID == incident.IncidentID {
				alert = member
				break
			}
		}
	}
	s.upsertMemoryLocked(incident, alert)
}

func (s *Store) similarIncidentsLocked(
	alert Alert,
	currentIncidentID string,
	limit int,
) []SimilarIncident {
	limit = capSimilarIncidentLimit(limit)
	queryVector := textVector(s.similarIncidentQueryLocked(alert, currentIncidentID))
	df, corpusSize := corpusDocFreqLocked(s.memories)
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil {
			continue
		}
		incident := s.incidents[memory.IncidentID]
		if !incidentUserApproved(incident) || memory.IncidentID == currentIncidentID || incidentDeleted(incident) {
			continue
		}
		score := blendedSimilarity(queryVector, memory.Vector, alert.Labels, memory.Labels, df, corpusSize)
		if score <= 0.05 {
			continue
		}
		if score > 1 {
			score = 1
		}
		summary := s.feedbackSummaryLocked("incident", memory.IncidentID)
		rootCauseFamily := ""
		if run := s.latestAnalysisRunForIncidentLocked(memory.IncidentID); run != nil {
			rootCauseFamily = run.RootCauseFamily
		}
		results = append(results, SimilarIncident{
			IncidentID:       memory.IncidentID,
			AlertID:          memory.AlertID,
			Title:            memory.Title,
			Severity:         memory.Severity,
			Status:           memory.Status,
			Similarity:       math.Round(score*1000) / 1000,
			AnalysisSummary:  memory.AnalysisSummary,
			AnalysisDetail:   excerpt(memory.AnalysisDetail, 900),
			RootCauseFamily:  rootCauseFamily,
			Approved:         incident.UserApprovedAt != nil,
			PositiveFeedback: summary.Positive,
			NegativeFeedback: summary.Negative,
			CommentCount:     len(summary.Comments),
			Labels:           cloneMap(memory.Labels),
			CreatedAt:        memory.CreatedAt,
			RetrievalKind:    retrievalKindSparseIdentity,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Similarity == results[j].Similarity {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		}
		return results[i].Similarity > results[j].Similarity
	})
	return dedupeSimilarByIncident(results, limit)
}

func (s *Store) similarRecentCountLocked(
	alert Alert,
	currentIncidentID string,
	since time.Time,
	before *time.Time,
) int {
	queryVector := textVector(alertSearchText(alert))
	seen := map[string]struct{}{}
	for _, memory := range s.memories {
		if memory == nil || !incidentUserApproved(s.incidents[memory.IncidentID]) || memory.IncidentID == currentIncidentID {
			continue
		}
		incident := s.incidents[memory.IncidentID]
		if incident == nil || incidentDeleted(incident) || incident.FiredAt.Before(since) {
			continue
		}
		if before != nil && !incident.FiredAt.Before(*before) {
			continue
		}
		// Recurrence COUNTING, not ranking: the question is "did this same thing
		// fire again", so exact identity on the controlled label keys is the
		// signal, not a thumb on a relevance score. The bonus stays here.
		score := cosineSimilarity(queryVector, memory.Vector)
		score += labelSimilarityBonus(alert.Labels, memory.Labels)
		if score >= minRecurrenceSimilarity {
			seen[memory.IncidentID] = struct{}{}
		}
	}
	return len(seen)
}

func dedupeSimilarByIncident(results []SimilarIncident, limit int) []SimilarIncident {
	deduped := results[:0]
	seen := map[string]struct{}{}
	for _, result := range results {
		if _, ok := seen[result.IncidentID]; ok {
			continue
		}
		seen[result.IncidentID] = struct{}{}
		deduped = append(deduped, result)
		if len(deduped) >= limit {
			break
		}
	}
	return deduped
}

func alertSearchText(alert Alert) string {
	// incidentTitle falls back to the summary annotation, so those two are the
	// same sentence whenever one exists — emitting both counted the alert's
	// boilerplate twice, weighting it against the text that actually tells two
	// incidents apart.
	parts := dedupeStrings(
		incidentTitle(alert),
		severity(alert),
		alert.Annotations["summary"],
		alert.Annotations["description"],
	)
	// No "pod": pod names are ephemeral high-entropy tokens, so they add noise to
	// the query without identifying anything a rerun would share. The workload
	// labels carry the stable identity.
	for _, key := range []string{
		"alertname",
		"cluster",
		"project",
		"queue",
		"namespace",
		"workload",
		"workload_name",
		"node",
	} {
		if value := alert.Labels[key]; value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(dedupeStrings(parts...), " ")
}

// dedupeStrings keeps the first occurrence of each non-empty value. Repeated
// values are extra weight in a bag-of-words vector, never extra signal.
func dedupeStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func memoryText(memory IncidentMemory) string {
	values := []string{
		memory.Title,
		memory.Severity,
		memory.Status,
		memory.AnalysisSummary,
		memory.AnalysisDetail,
	}
	for _, value := range memory.Labels {
		values = append(values, value)
	}
	return strings.Join(values, " ")
}

func textVector(text string) map[string]float64 {
	vector := map[string]float64{}
	for _, token := range tokenize(text) {
		vector[token]++
	}
	return vector
}

// denseEmbedding maps free text to a dim-dimensional dense vector using signed
// feature hashing (Weinberger et al.). Each token is hashed to a dimension and a
// sign, so token counts accumulate into a dense vector whose inner products are
// unbiased estimates of the sparse bag-of-words inner products. The result is
// L2-normalized so pgvector cosine distance (`<=>`) is a meaningful similarity.
// It is deterministic and requires no model, keeping the backend self-contained.
func denseEmbedding(text string, dim int) []float32 {
	if dim <= 0 {
		dim = embeddingDim
	}
	vector := make([]float32, dim)
	for _, token := range tokenize(text) {
		h := fnv.New64a()
		_, _ = h.Write([]byte(token))
		sum := h.Sum64()
		idx := sum % uint64(dim)
		if sum&(1<<63) != 0 {
			vector[idx]--
		} else {
			vector[idx]++
		}
	}
	return normalize(vector)
}

// normalize L2-normalizes a dense vector in place and returns it, so cosine
// distance stays valid regardless of the embedding source. A zero vector is
// returned unchanged.
func normalize(vector []float32) []float32 {
	var norm float64
	for _, v := range vector {
		norm += float64(v) * float64(v)
	}
	if norm == 0 {
		return vector
	}
	inv := float32(1 / math.Sqrt(norm))
	for i := range vector {
		vector[i] *= inv
	}
	return vector
}

// embeddingLiteral renders a dense vector in the textual form pgvector accepts
// for a `vector` value, e.g. "[0.1,0.2,...]".
func embeddingLiteral(vector []float32) string {
	if len(vector) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range vector {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(v), 'f', 6, 32))
	}
	b.WriteByte(']')
	return b.String()
}

func tokenize(text string) []string {
	// Split on any non-letter/non-number rune, keeping ALL Unicode letters — the
	// old a-z/0-9-only predicate dropped Hangul/CJK entirely, so Korean reports
	// were compared on a handful of ASCII scraps (IP octets, "dns", "io") and even
	// near-identical incidents scored ~50%. unicode.IsLetter keeps Korean eojeols.
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		tokens = append(tokens, wordTokens(field)...)
	}
	return tokens
}

// wordTokens yields tokens for one whitespace-delimited field. Space-delimited
// scripts (Latin, Korean eojeols) pass through as one token; scripts written
// without spaces (Han/Hiragana/Katakana) are emitted as character bigrams so a
// run still contributes overlapping features instead of one giant unique token.
// ponytail: bigrams are a cheap CJK-segmentation stand-in; swap for a real
// tokenizer only if non-Korean CJK similarity matters.
func wordTokens(field string) []string {
	runes := []rune(field)
	if len(runes) < 2 {
		return nil
	}
	hanCount := 0
	for _, r := range runes {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) {
			hanCount++
		}
	}
	// Korean (Hangul) has spaces between words, so keep the eojeol whole; only the
	// space-less CJK scripts need bigram splitting.
	if hanCount < 2 {
		return []string{field}
	}
	out := make([]string, 0, len(runes)-1)
	for i := 0; i+1 < len(runes); i++ {
		out = append(out, string(runes[i:i+2]))
	}
	return out
}

func cosineSimilarity(a, b map[string]float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for key, value := range a {
		normA += value * value
		dot += value * b[key]
	}
	for _, value := range b {
		normB += value * value
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// corpusDocFreqLocked computes document frequency (how many memories contain
// each token at least once) and the corpus size over s.memories. Callers
// compute this ONCE per query/search call, before the per-candidate ranking
// loop, and pass the result down -- not per comparison. A search is already an
// O(len(s.memories)) pass (cosine + feedback lookups per candidate); this is a
// second pass of the same order, not a new complexity class. Caching it across
// calls (e.g. keyed on a corpus generation counter) would add invalidation
// bookkeeping at every upsert/hard-delete/reload site to save work that is
// already cheap -- not worth it unless the corpus size becomes a real problem.
func corpusDocFreqLocked(memories map[string]*IncidentMemory) (df map[string]int, corpusSize int) {
	df = make(map[string]int, 64)
	for _, memory := range memories {
		if memory == nil {
			continue
		}
		corpusSize++
		for token := range memory.Vector {
			df[token]++
		}
	}
	return df, corpusSize
}

// idfWeight is the smoothed inverse-document-frequency of a token appearing in
// df of corpusSize documents: ln((1+N)/(1+df)) + 1, the same smoothing
// scikit-learn's TfidfVectorizer uses by default. It is always >= 1, so it
// never zeroes out a vector and never divides by zero:
//   - corpusSize == 0 (nothing stored yet): every token gets the neutral
//     weight 1 -- IDF has no corpus to reason about, so this is plain term
//     counts.
//   - a token in EVERY document (df == corpusSize), e.g. the Alertmanager
//     boilerplate every incident of the same alertname shares: weight bottoms
//     out at exactly the floor, 1 -- never zero, but the smallest possible
//     weight, so it cannot outweigh a token that sets one document apart from
//     the rest.
//   - a single-document corpus (corpusSize == 1): its only document's tokens
//     all have df == corpusSize == 1, so they all sit at the floor too -- one
//     document gives IDF no basis to call anything rare, so this degrades to
//     unweighted term-count cosine rather than collapsing to an all-zero
//     vector.
func idfWeight(df, corpusSize int) float64 {
	if corpusSize <= 0 {
		return 1
	}
	return math.Log(float64(1+corpusSize)/float64(1+df)) + 1
}

// idfWeightedVector scales each term count by its corpus IDF weight. Applied at
// COMPARE time to both the query and the stored vector -- textVector and the
// persisted memory documents are untouched, so this needs no re-storing and no
// migration.
func idfWeightedVector(vector map[string]float64, df map[string]int, corpusSize int) map[string]float64 {
	if len(vector) == 0 {
		return vector
	}
	weighted := make(map[string]float64, len(vector))
	for token, count := range vector {
		// df == 0 means no stored document contains this token, so it can never
		// enter the dot product -- keeping it at the MAX idf weight would only
		// inflate the vector norm. Worse, that tax grows with the corpus, so the
		// same pair scored LOWER as unrelated incidents were approved (measured:
		// 0.1277 at n=1, 0.0921 at n=3, versus a stable 0.5000 when dropped) and
		// every fixed threshold silently tightened over time. Dropping it is what
		// sklearn's transform does, and it changes no ranking: the norm is the
		// same constant for every candidate of one query.
		if df[token] == 0 {
			continue
		}
		weighted[token] = count * idfWeight(df[token], corpusSize)
	}
	return weighted
}

// idfCosineSimilarity is cosineSimilarity with both sides IDF-weighted first.
// idfWeight is always >= 1 (never negative), so the weighted vectors stay
// non-negative and the result stays a normalized similarity in [0,1] --
// comparable with the dense path's 1-distance.
func idfCosineSimilarity(a, b map[string]float64, df map[string]int, corpusSize int) float64 {
	return cosineSimilarity(idfWeightedVector(a, df, corpusSize), idfWeightedVector(b, df, corpusSize))
}

// The controlled label keys that identify a recurrence. No "pod": an ephemeral
// name never repeats across occurrences, so it can only ever withhold identity
// credit from a genuine recurrence.
var identityLabelKeys = []string{
	"alertname", "cluster", "project", "queue", "namespace", "workload",
}

// blendedSimilarity ranks a candidate by content AND identity on ONE scale.
//
// A flat additive bonus could not do that. Every label value is also a token in
// alertSearchText and memoryText, so labels already move the cosine -- but the
// stored document is a full RCA while the query is a short alert, so those few
// tokens used to be diluted to nearly nothing by plain term-count cosine. (Drop
// the correction outright under the OLD unweighted cosine and a genuine
// recurrence falls under the 0.05 floor; a test pinned that.) The old
// correction was +0.035 per matching key -- up to +0.21 added to a [0,1] cosine,
// wider than the gap between a same-alertname match and a same-root-cause one.
// That is how a kube-scheduler predicate failure outranked a GPU-shortage
// incident for a Run:ai fractional-GPU alert.
//
// content is now idfCosineSimilarity, not plain cosineSimilarity: the shared
// Alertmanager boilerplate every same-alertname incident carries is now
// downweighted by document frequency instead of counting equally with the
// terms that actually separate two root causes, so content alone carries much
// more of the identity signal than it used to. The label blend stays anyway --
// it is a hard, controlled-vocabulary signal (exact key match, not textual
// similarity), and keeping it means identity is never entirely a function of
// which words happen to survive tokenization.
//
// Blending two NORMALIZED signals keeps identity load-bearing without letting it
// outvote content: labelWeight of the score is the share of the alert's OWN
// controlled label keys that matched, and the rest is cosine. Keys the alert
// does not carry are not counted against a candidate.
const labelWeight = 0.25

func blendedSimilarity(
	queryVector, memoryVector map[string]float64,
	alertLabels, memoryLabels map[string]string,
	df map[string]int, corpusSize int,
) float64 {
	content := idfCosineSimilarity(queryVector, memoryVector, df, corpusSize)
	present, matched := 0, 0
	for _, key := range identityLabelKeys {
		if alertLabels[key] == "" {
			continue
		}
		present++
		if alertLabels[key] == memoryLabels[key] {
			matched++
		}
	}
	if present == 0 {
		return content
	}
	return (1-labelWeight)*content + labelWeight*(float64(matched)/float64(present))
}

func labelSimilarityBonus(alertLabels, memoryLabels map[string]string) float64 {
	score := 0.0
	for _, key := range identityLabelKeys {
		if alertLabels[key] != "" && alertLabels[key] == memoryLabels[key] {
			score += 0.035
		}
	}
	return score
}
