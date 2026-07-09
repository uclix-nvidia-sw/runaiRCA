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
	if s.embedder == nil {
		return denseEmbedding(text, embeddingDim)
	}
	return s.embedder.embed(text)
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
	if e == nil || e.endpoint == "" {
		return denseEmbedding(text, embeddingDim)
	}
	vector, err := e.remoteEmbed(text)
	if err != nil {
		log.Printf("embedding endpoint failed, falling back to hash embedding: %v", err)
		return denseEmbedding(text, e.dim)
	}
	return normalize(vector)
}

// remoteEmbed POSTs to {endpoint}/embeddings and returns the raw model vector.
// The response follows the OpenAI embeddings schema: {"data":[{"embedding":[...]}]}.
func (e *embedder) remoteEmbed(text string) ([]float32, error) {
	body, err := json.Marshal(map[string]any{"model": e.model, "input": text})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.similarIncidentsLocked(alert, incidentID, capSimilarIncidentLimit(limit))
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
	if results, ok := s.dbSearchMemory(query, limit); ok && len(results) > 0 {
		return results
	}
	queryVector := textVector(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil || !incidentUserApproved(s.incidents[memory.IncidentID]) || incidentDeleted(s.incidents[memory.IncidentID]) {
			continue
		}
		score := cosineSimilarity(queryVector, memory.Vector)
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
	// The RCA itself lives on the analysis run (CompleteAnalysisRun); here we only
	// clear the analyzing flag and refresh the incident's aggregate state. The
	// `response` is retained on the run, not duplicated onto the alert.
	before := cloneAlert(alert)
	alert.IsAnalyzing = false
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
// render an in-progress state for the whole lifecycle.
func (s *Store) BeginAnalyzing(incidentID string, alertID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = true
		s.persistIncidentLocked(incident)
	}
	if alert := s.alerts[alertID]; alert != nil {
		alert.IsAnalyzing = true
		s.persistAlertLocked(alert)
	}
}

// BeginManualAnalysis marks a dashboard-triggered reanalysis in progress while
// keeping the last good RCA visible until a fresh result replaces it.
func (s *Store) BeginManualAnalysis(incidentID string, alertID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = true
		s.persistIncidentLocked(incident)
	}
	if alert := s.alerts[alertID]; alert != nil {
		alert.IsAnalyzing = true
		s.persistAlertLocked(alert)
	}
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
	s.persistMemoryLocked(memory)
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
	queryVector := textVector(alertSearchText(alert))
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil || !incidentUserApproved(s.incidents[memory.IncidentID]) || memory.IncidentID == currentIncidentID || incidentDeleted(s.incidents[memory.IncidentID]) {
			continue
		}
		score := cosineSimilarity(queryVector, memory.Vector)
		score += labelSimilarityBonus(alert.Labels, memory.Labels)
		if score <= 0.05 {
			continue
		}
		if score > 1 {
			score = 1
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
		score := cosineSimilarity(queryVector, memory.Vector)
		score += labelSimilarityBonus(alert.Labels, memory.Labels)
		if score >= minFeedbackHintSimilarity {
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
	parts := []string{
		incidentTitle(alert),
		severity(alert),
		alert.Annotations["summary"],
		alert.Annotations["description"],
	}
	for _, key := range []string{
		"alertname",
		"cluster",
		"project",
		"queue",
		"namespace",
		"workload",
		"workload_name",
		"pod",
		"node",
	} {
		if value := alert.Labels[key]; value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " ")
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

func labelSimilarityBonus(alertLabels, memoryLabels map[string]string) float64 {
	keys := []string{"alertname", "cluster", "project", "queue", "namespace", "workload", "pod"}
	score := 0.0
	for _, key := range keys {
		if alertLabels[key] != "" && alertLabels[key] == memoryLabels[key] {
			score += 0.035
		}
	}
	return score
}
