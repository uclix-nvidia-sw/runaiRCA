package server

import (
	"errors"
	"sort"
	"strings"
	"time"
)

var evaluationDimensions = []string{
	"evidence_grounding",
	"diagnostic_reasoning",
	"investigation_plan",
	"uncertainty_calibration",
	"operational_usefulness",
	"tool_efficiency",
	"safety",
}

type EvaluationReview struct {
	ReviewID          string          `json:"review_id"`
	RunID             string          `json:"run_id"`
	AnalysisHash      string          `json:"analysis_hash"`
	Reviewer          string          `json:"reviewer"`
	CaseType          string          `json:"case_type"`
	ExpectedFamily    string          `json:"expected_family,omitempty"`
	Scores            map[string]int  `json:"scores"`
	HardGates         map[string]bool `json:"hard_gates"`
	ResolutionOutcome string          `json:"resolution_outcome"`
	EffectiveAction   string          `json:"effective_action,omitempty"`
	Notes             string          `json:"notes,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type EvaluationReviewRequest struct {
	Author            string          `json:"author"`
	AnalysisHash      string          `json:"analysis_hash"`
	CaseType          string          `json:"case_type"`
	ExpectedFamily    string          `json:"expected_family"`
	Scores            map[string]int  `json:"scores"`
	HardGates         map[string]bool `json:"hard_gates"`
	ResolutionOutcome string          `json:"resolution_outcome"`
	EffectiveAction   string          `json:"effective_action"`
	Notes             string          `json:"notes"`
}

type EvaluationView struct {
	RunID        string             `json:"run_id"`
	AnalysisHash string             `json:"analysis_hash"`
	Harness      map[string]any     `json:"harness,omitempty"`
	MyReview     *EvaluationReview  `json:"my_review,omitempty"`
	Reviews      []EvaluationReview `json:"reviews"`
	AverageScore float64            `json:"average_score"`
}

func evaluationKey(runID, hash, reviewer string) string {
	return runID + "\x00" + hash + "\x00" + reviewer
}

func currentAnalysisHash(run *AnalysisRun) string {
	if run == nil || run.Metadata == nil {
		return ""
	}
	hash, _ := run.Metadata["analysis_hash"].(string)
	return hash
}

func normalizeEvaluationRequest(req EvaluationReviewRequest, allowedFamilies []string) (EvaluationReviewRequest, error) {
	req.Author = feedbackActor(req.Author)
	req.AnalysisHash = strings.TrimSpace(req.AnalysisHash)
	req.CaseType = strings.TrimSpace(req.CaseType)
	req.ExpectedFamily = strings.TrimSpace(req.ExpectedFamily)
	req.ResolutionOutcome = strings.TrimSpace(req.ResolutionOutcome)
	req.EffectiveAction = strings.TrimSpace(req.EffectiveAction)
	req.Notes = strings.TrimSpace(req.Notes)
	if req.AnalysisHash == "" || req.CaseType == "" {
		return req, errors.New("analysis_hash and case_type are required")
	}
	if !mapContains([]string{"known", "compositional", "novel", "tool_degraded"}, req.CaseType) {
		return req, errors.New("invalid case_type")
	}
	if req.CaseType == "novel" {
		req.ExpectedFamily = ""
	} else if req.ExpectedFamily != "" && !mapContains(allowedFamilies, req.ExpectedFamily) {
		return req, errors.New("expected_family must be selected from the root-cause family catalog")
	}
	if req.ResolutionOutcome == "" {
		req.ResolutionOutcome = "unknown"
	}
	if !mapContains([]string{"resolved", "mitigated", "ineffective", "unknown"}, req.ResolutionOutcome) {
		return req, errors.New("invalid resolution_outcome")
	}
	if len(req.Notes) > maxStoredCommentBodyBytes || len(req.EffectiveAction) > 1000 {
		return req, errors.New("evaluation text is too long")
	}
	if req.Scores == nil {
		req.Scores = map[string]int{}
	}
	for _, dimension := range evaluationDimensions {
		score, ok := req.Scores[dimension]
		if !ok || score < 0 || score > 5 {
			return req, errors.New("every evaluation score must be an integer from 0 to 5")
		}
	}
	return req, nil
}

func mapContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func reviewScore(scores map[string]int) float64 {
	if len(scores) == 0 {
		return 0
	}
	total := 0
	for _, dimension := range evaluationDimensions {
		total += scores[dimension]
	}
	return float64(total) / float64(len(evaluationDimensions))
}

func (s *Store) EvaluationForRun(runID, author string) (EvaluationView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return EvaluationView{}, false
	}
	hash := currentAnalysisHash(run)
	view := EvaluationView{RunID: runID, AnalysisHash: hash, Reviews: []EvaluationReview{}}
	if harness, ok := run.Metadata["harness"].(map[string]any); ok {
		view.Harness = cloneAnyMap(harness)
	}
	for _, review := range s.evaluationReviews {
		if review.RunID != runID || review.AnalysisHash != hash {
			continue
		}
		copy := cloneEvaluationReview(*review)
		view.Reviews = append(view.Reviews, copy)
		view.AverageScore += reviewScore(copy.Scores)
		if review.Reviewer == feedbackActor(author) {
			view.MyReview = &copy
		}
	}
	sort.Slice(view.Reviews, func(i, j int) bool { return view.Reviews[i].UpdatedAt.After(view.Reviews[j].UpdatedAt) })
	if len(view.Reviews) > 0 {
		view.AverageScore /= float64(len(view.Reviews))
	}
	return view, true
}

func (s *Store) UpsertEvaluationReview(runID string, req EvaluationReviewRequest, allowedFamilies []string) (EvaluationReview, bool, error) {
	req, err := normalizeEvaluationRequest(req, allowedFamilies)
	if err != nil {
		return EvaluationReview{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return EvaluationReview{}, false, nil
	}
	if hash := currentAnalysisHash(run); hash == "" || hash != req.AnalysisHash {
		return EvaluationReview{}, false, errors.New("analysis has changed; refresh before evaluating")
	}
	key := evaluationKey(runID, req.AnalysisHash, req.Author)
	now := time.Now().UTC()
	review := s.evaluationReviews[key]
	if review == nil {
		review = &EvaluationReview{
			ReviewID:  nextID("EVR", s.evaluationSeq.Add(1)),
			RunID:     runID,
			CreatedAt: now,
		}
		s.evaluationReviews[key] = review
	}
	review.AnalysisHash = req.AnalysisHash
	review.Reviewer = req.Author
	review.CaseType = req.CaseType
	review.ExpectedFamily = req.ExpectedFamily
	review.Scores = cloneIntMap(req.Scores)
	review.HardGates = cloneBoolMap(req.HardGates)
	review.ResolutionOutcome = req.ResolutionOutcome
	review.EffectiveAction = req.EffectiveAction
	review.Notes = req.Notes
	review.UpdatedAt = now
	s.persistEvaluationReviewLocked(review)
	// A successful operator outcome is commonly recorded after the immutable
	// CaseSnapshot was approved. Re-scan that exact run/hash now so eligible
	// knowledge does not depend on review timing.
	if review.ResolutionOutcome == "resolved" || review.ResolutionOutcome == "mitigated" {
		s.generateKnowledgeCandidateForReviewedRunLocked(review.RunID, review.AnalysisHash)
	}
	return cloneEvaluationReview(*review), true, nil
}

func (s *Store) generateKnowledgeCandidateForReviewedRunLocked(runID, analysisHash string) {
	for _, snapshot := range s.caseSnapshots {
		if snapshot == nil || snapshot.ApprovalState != "active" || snapshot.RunID != runID || snapshot.AnalysisHash != analysisHash {
			continue
		}
		candidate := s.knowledgeCandidateForSnapshotLocked(snapshot)
		if candidate == nil {
			continue
		}
		existing := s.knowledgeCandidates[candidate.CandidateID]
		link := candidate
		if existing != nil {
			copy := cloneKnowledgeCandidate(existing)
			copy.CaseID, copy.CreatedAt = snapshot.CaseID, time.Now().UTC()
			link = &copy
		}
		event := s.newKnowledgeEventLocked(candidate.CandidateID, "", "candidate_generated", "system", "operator outcome recorded", time.Now().UTC())
		if !s.persistNewKnowledgeCandidateLocked(link, event) {
			continue
		}
		if existing != nil {
			if !containsString(existing.SupportingCaseIDs, snapshot.CaseID) {
				existing.SupportingCaseIDs = append(existing.SupportingCaseIDs, snapshot.CaseID)
				existing.SupportingCaseCount = len(existing.SupportingCaseIDs)
			}
		} else {
			s.knowledgeCandidates[candidate.CandidateID] = candidate
		}
		s.knowledgeEvents[event.EventID] = event
	}
}

func cloneEvaluationReview(review EvaluationReview) EvaluationReview {
	review.Scores = cloneIntMap(review.Scores)
	review.HardGates = cloneBoolMap(review.HardGates)
	return review
}

func cloneIntMap(in map[string]int) map[string]int {
	out := map[string]int{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := map[string]bool{}
	for key, value := range in {
		out[key] = value
	}
	return out
}
