package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// embeddingDim is the fixed dimensionality of the dense vectors stored in the
// pgvector `embedding` column. The backend has no embedding model dependency
// (it must run offline next to the NeMo agent), so dense vectors are produced
// deterministically from text with the feature-hashing trick. Changing this
// value invalidates previously persisted vectors of a different dimension.
const embeddingDim = 384

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
		if item.PositiveFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "positive",
				Weight:    item.Similarity,
				Text:      fmt.Sprintf("Operators found this prior RCA useful: %s", item.AnalysisSummary),
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
				Text:      fmt.Sprintf("Operators pushed back on this prior RCA: %s", item.AnalysisSummary),
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
				Text:      comment.Body,
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
		if memory == nil {
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
	s.applyAnalysisLocked(alert, response)
	return true
}

func (s *Store) applyAnalysisLocked(alert *AlertRecord, response AgentAnalysisResponse) {
	alert.AnalysisSummary = response.AnalysisSummary
	alert.AnalysisDetail = response.AnalysisDetail
	if alert.AnalysisDetail == "" {
		alert.AnalysisDetail = response.Analysis
	}
	alert.AnalysisQuality = response.AnalysisQuality
	alert.Capabilities = response.Capabilities
	alert.MissingData = response.MissingData
	alert.Warnings = response.Warnings
	alert.Artifacts = response.Artifacts
	alert.IsAnalyzing = false
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		s.refreshIncidentAnalyzingLocked(incident.IncidentID)
		s.upsertMemoryLocked(incident, alert)
		s.persistIncidentLocked(incident)
	}
	s.persistAlertLocked(alert)
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
	hasExistingRCA := strings.TrimSpace(alert.AnalysisSummary) != "" ||
		strings.TrimSpace(alert.AnalysisDetail) != ""
	if hasExistingRCA {
		alert.IsAnalyzing = false
		if incident := s.incidents[alert.IncidentID]; incident != nil {
			s.refreshIncidentAnalyzingLocked(incident.IncidentID)
			s.persistIncidentLocked(incident)
		}
		s.persistAlertLocked(alert)
		return false
	}
	alert.AnalysisSummary = response.AnalysisSummary
	alert.AnalysisDetail = response.AnalysisDetail
	if alert.AnalysisDetail == "" {
		alert.AnalysisDetail = response.Analysis
	}
	alert.AnalysisQuality = first(response.AnalysisQuality, "low")
	alert.Capabilities = response.Capabilities
	alert.MissingData = response.MissingData
	alert.Warnings = response.Warnings
	alert.Artifacts = response.Artifacts
	alert.IsAnalyzing = false
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		s.refreshIncidentAnalyzingLocked(incident.IncidentID)
		s.persistIncidentLocked(incident)
	}
	s.persistAlertLocked(alert)
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
	if strings.TrimSpace(alert.AnalysisSummary) == "" && strings.TrimSpace(alert.AnalysisDetail) == "" {
		return
	}
	memory := &IncidentMemory{
		IncidentID:      incident.IncidentID,
		AlertID:         alert.AlertID,
		Title:           incident.Title,
		Severity:        incident.Severity,
		Status:          incident.Status,
		AnalysisSummary: alert.AnalysisSummary,
		AnalysisDetail:  alert.AnalysisDetail,
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
	}
	memory.Vector = textVector(memoryText(*memory))
	s.memories[first(memory.AlertID, memory.IncidentID)] = memory
	s.persistMemoryLocked(memory)
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
		if memory == nil || memory.IncidentID == currentIncidentID {
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

// denseEmbedding maps free text to a fixed-dimension dense vector using signed
// feature hashing (Weinberger et al.). Each token is hashed to a dimension and a
// sign, so token counts accumulate into a dense vector whose inner products are
// unbiased estimates of the sparse bag-of-words inner products. The result is
// L2-normalized so pgvector cosine distance (`<=>`) is a meaningful similarity.
// It is deterministic and requires no model, keeping the backend self-contained.
func denseEmbedding(text string) []float32 {
	vector := make([]float32, embeddingDim)
	for _, token := range tokenize(text) {
		h := fnv.New64a()
		_, _ = h.Write([]byte(token))
		sum := h.Sum64()
		idx := sum % embeddingDim
		if sum&(1<<63) != 0 {
			vector[idx]--
		} else {
			vector[idx]++
		}
	}
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
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		if len([]rune(field)) >= 2 {
			tokens = append(tokens, field)
		}
	}
	return tokens
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
