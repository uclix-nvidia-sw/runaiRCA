package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

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
	return s.similarIncidentsLocked(alert, incidentID, limit)
}

func (s *Store) FeedbackHintsForAlert(alert Alert, incidentID string, limit int) []FeedbackHint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	similar := s.similarIncidentsLocked(alert, incidentID, limit)
	hints := make([]FeedbackHint, 0, limit)
	for _, item := range similar {
		if item.PositiveFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "positive",
				Weight:    item.Similarity,
				Text:      fmt.Sprintf("Operators found this prior RCA useful: %s", item.AnalysisSummary),
			})
		}
		if item.NegativeFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "negative",
				Weight:    item.Similarity,
				Text:      fmt.Sprintf("Operators pushed back on this prior RCA: %s", item.AnalysisSummary),
			})
		}
		for _, comment := range s.commentsForTargetLocked("incident", item.IncidentID) {
			if len(hints) >= limit {
				return hints
			}
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "comment",
				Weight:    item.Similarity,
				Text:      comment.Body,
			})
		}
		if len(hints) >= limit {
			return hints
		}
	}
	return hints
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
	if len(results) > limit {
		return results[:limit]
	}
	return results
}

func (s *Store) ApplyAnalysis(alertID string, response AgentAnalysisResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil {
		return
	}
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
		incident.IsAnalyzing = false
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
	s.memories[memory.IncidentID] = memory
	s.persistMemoryLocked(memory)
}

func (s *Store) similarIncidentsLocked(
	alert Alert,
	currentIncidentID string,
	limit int,
) []SimilarIncident {
	if limit <= 0 {
		limit = 5
	}
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
	if len(results) > limit {
		return results[:limit]
	}
	return results
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
