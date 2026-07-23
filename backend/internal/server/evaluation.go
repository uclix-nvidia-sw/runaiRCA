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
	OperatorConfirmed bool            `json:"operator_confirmed,omitempty"`
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
	OperatorConfirmed bool            `json:"operator_confirmed"`
}

type EvaluationView struct {
	RunID            string                    `json:"run_id"`
	AnalysisHash     string                    `json:"analysis_hash"`
	Harness          map[string]any            `json:"harness,omitempty"`
	MyReview         *EvaluationReview         `json:"my_review,omitempty"`
	Reviews          []EvaluationReview        `json:"reviews"`
	AverageScore     float64                   `json:"average_score"`
	KnowledgePreview KnowledgePromotionPreview `json:"knowledge_preview"`
}

// KnowledgePromotionPreview is a non-persisted dry-run of whether this run's
// approved snapshot would become a knowledge candidate. It reuses the exact
// promotion gates so operators see the ingestion outcome (and the precise block
// reason) at evaluation time instead of discovering it later in the Knowledge queue.
type KnowledgePromotionPreview struct {
	Outcome       string `json:"outcome"` // ready | validation_failed | blocked | not_approved
	Reason        string `json:"reason,omitempty"`
	Family        string `json:"family,omitempty"`
	EvidenceCount int    `json:"evidence_count"`
	ProbeCount    int    `json:"probe_count"`
	CandidateID   string `json:"candidate_id,omitempty"`
}

// knowledgePromotionPreviewLocked dry-runs promotion for a run/hash. Callers must
// already hold s.mu (read lock is sufficient); it only reads store state and pure
// functions and never persists.
func (s *Store) knowledgePromotionPreviewLocked(runID, hash string) KnowledgePromotionPreview {
	if strings.TrimSpace(hash) == "" {
		return KnowledgePromotionPreview{Outcome: "blocked", Reason: "analysis has no result hash yet"}
	}
	var snapshot *CaseSnapshot
	for _, snap := range s.caseSnapshots {
		if snap != nil && snap.ApprovalState == "active" && snap.RunID == runID && snap.AnalysisHash == hash {
			snapshot = snap
			break
		}
	}
	if snapshot == nil {
		return KnowledgePromotionPreview{Outcome: "not_approved", Reason: "approve the RCA to evaluate whether it becomes runtime knowledge"}
	}
	hasReviews, allows := s.caseReviewAllowsKnowledgePromotionLocked(snapshot)
	if !hasReviews {
		return KnowledgePromotionPreview{Outcome: "blocked", Reason: "save an evaluation review for this analysis first"}
	}
	if !allows {
		return KnowledgePromotionPreview{Outcome: "blocked", Reason: "evaluation must confirm the analysis root-cause family with a resolved or mitigated outcome and pass the quality floor"}
	}
	candidate := knowledgeCandidateForSnapshotWithOutcome(snapshot, true, s.operatorConfirmedForSnapshotLocked(snapshot))
	if candidate == nil {
		return KnowledgePromotionPreview{Outcome: "blocked", Reason: "analysis has no v3 reasoning trace to promote"}
	}
	preview := KnowledgePromotionPreview{
		Family:        first(candidate.RootCauseFamily, snapshot.RootCauseFamily),
		EvidenceCount: len(candidate.EvidenceSummaries),
		ProbeCount:    len(candidate.ProbeTemplateIDs),
		CandidateID:   candidate.CandidateID,
	}
	if candidate.Status == knowledgeCandidateValidationFailed {
		preview.Outcome = "validation_failed"
		preview.Reason = candidate.ValidationError
	} else {
		preview.Outcome = "ready"
	}
	return preview
}

func evaluationKey(runID, hash, reviewer string) string {
	return runID + "\x00" + hash + "\x00" + reviewer
}

func currentAnalysisHash(run *AnalysisRun) string {
	metadata := analysisResultMetadata(run)
	if metadata == nil {
		return ""
	}
	hash, _ := metadata["analysis_hash"].(string)
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
	switch req.CaseType {
	case "novel":
		req.ExpectedFamily = ""
	case "known", "compositional", "tool_degraded":
		// A reviewer may score the analysis without claiming an answer key. When
		// supplied, the family is catalog-bound and becomes a semantic gate; an
		// empty value never confirms the model-selected family by implication.
		if req.ExpectedFamily != "" && !mapContains(allowedFamilies, req.ExpectedFamily) {
			return req, errors.New("expected_family must be selected from the root-cause family catalog")
		}
	}
	if req.ResolutionOutcome == "" {
		req.ResolutionOutcome = "unknown"
	}
	if !mapContains([]string{"resolved", "mitigated", "ineffective", "unknown"}, req.ResolutionOutcome) {
		return req, errors.New("invalid resolution_outcome")
	}
	if req.OperatorConfirmed {
		// Confirming a diagnosis for a non-reproducible incident is a deliberate,
		// accountable override: it must name the family, record a rationale, and
		// assert a successful outcome. The evidence floor is still enforced later by
		// the promotion validator, so this cannot fabricate evidence-free knowledge.
		if !mapContains([]string{"known", "compositional"}, req.CaseType) {
			return req, errors.New("operator confirmation requires a known or compositional case type")
		}
		if req.ExpectedFamily == "" {
			return req, errors.New("operator confirmation requires the confirmed root-cause family")
		}
		if !mapContains([]string{"resolved", "mitigated"}, req.ResolutionOutcome) {
			return req, errors.New("operator confirmation requires a resolved or mitigated outcome")
		}
		if req.Notes == "" {
			return req, errors.New("operator confirmation requires a rationale in notes")
		}
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
	if harness, ok := analysisResultMetadata(run)["harness"].(map[string]any); ok {
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
	view.KnowledgePreview = s.knowledgePromotionPreviewLocked(runID, hash)
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
	review.OperatorConfirmed = req.OperatorConfirmed
	review.UpdatedAt = now
	s.persistEvaluationReviewLocked(review)
	// A review is mutable operator truth. If it no longer confirms the exact
	// snapshot family/outcome, withdraw every candidate/package derived from
	// that run/hash before the runtime catalog can serve it again.
	s.invalidateKnowledgeForReviewLocked(review.RunID, review.AnalysisHash, now)
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
		// A candidate's ID is content-derived, so a failed→ready transition (e.g. an
		// operator confirmation makes a previously unpromotable analysis eligible)
		// mints a NEW id and would otherwise leave the stale failed candidate behind
		// as a confusing duplicate. Supersede any other non-decided candidate for the
		// same case before recording the fresh one.
		s.supersedeStaleCaseCandidatesLocked(snapshot.CaseID, candidate.CandidateID, time.Now().UTC())
		existing := s.knowledgeCandidates[candidate.CandidateID]
		if existing != nil && existing.Status == knowledgeCandidateValidationFailed && candidate.Status == knowledgeCandidateValidationFailed {
			now := time.Now().UTC()
			refreshed := cloneKnowledgeCandidate(existing)
			refreshed.ValidationError = candidate.ValidationError
			refreshed.Trace = cloneCaseSnapshotPayload(candidate.Trace)
			refreshed.Payload = cloneCaseSnapshotPayload(candidate.Payload)
			refreshed.UpdatedAt = now
			hydrateKnowledgeCandidate(&refreshed)
			event := s.newKnowledgeEventLocked(
				refreshed.CandidateID,
				"",
				"candidate_validation_refreshed",
				"system",
				"candidate validation reason refreshed after operator evaluation",
				now,
			)
			if s.persistKnowledgeCandidateValidationRefreshLocked(&refreshed, event) {
				*existing = refreshed
				s.knowledgeEvents[event.EventID] = event
			}
			continue
		}
		if existing != nil &&
			existing.Status == knowledgeCandidateValidationFailed &&
			existing.ValidationError == knowledgeReviewInvalidationError &&
			candidate.Status == knowledgeCandidateReady {
			if !s.knowledgeCandidateSupportsValidSnapshotsLocked(existing) {
				continue
			}
			now := time.Now().UTC()
			revalidated := cloneKnowledgeCandidate(existing)
			revalidated.Status = knowledgeCandidateReady
			revalidated.PackageID = ""
			revalidated.ValidationError = ""
			revalidated.Trace = cloneCaseSnapshotPayload(candidate.Trace)
			revalidated.Payload = cloneCaseSnapshotPayload(candidate.Payload)
			revalidated.DecidedAt = nil
			revalidated.DecidedBy = ""
			revalidated.DecisionNote = ""
			revalidated.UpdatedAt = now
			hydrateKnowledgeCandidate(&revalidated)
			event := s.newKnowledgeEventLocked(
				revalidated.CandidateID,
				"",
				"candidate_revalidated",
				"system",
				"operator evaluation again confirms this analysis; review required",
				now,
			)
			if !s.persistKnowledgeReviewRevalidationLocked(&revalidated, event) {
				continue
			}
			*existing = revalidated
			s.knowledgeEvents[event.EventID] = event
			continue
		}
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

// A review correction may restore a withdrawn candidate only after every case
// currently supporting that candidate independently passes the exact
// hash/family gate again. The old package remains retired; an operator must
// explicitly review and approve the restored candidate before runtime reuse.
func (s *Store) knowledgeCandidateSupportsValidSnapshotsLocked(candidate *KnowledgeCandidate) bool {
	if candidate == nil {
		return false
	}
	seen := map[string]bool{}
	for _, caseID := range append([]string{candidate.CaseID}, candidate.SupportingCaseIDs...) {
		if caseID == "" || seen[caseID] {
			continue
		}
		seen[caseID] = true
		validated := s.knowledgeCandidateForSnapshotLocked(s.caseSnapshots[caseID])
		if validated == nil || validated.Status != knowledgeCandidateReady || validated.ContentHash != candidate.ContentHash {
			return false
		}
	}
	return len(seen) > 0
}

func (s *Store) invalidateKnowledgeForReviewLocked(runID, analysisHash string, now time.Time) {
	invalidCases := map[string]bool{}
	for _, snapshot := range s.caseSnapshots {
		if snapshot == nil || snapshot.RunID != runID || snapshot.AnalysisHash != analysisHash {
			continue
		}
		if s.knowledgeCandidateForSnapshotLocked(snapshot) == nil {
			invalidCases[snapshot.CaseID] = true
		}
	}
	if len(invalidCases) == 0 {
		return
	}
	for _, candidate := range s.knowledgeCandidates {
		if candidate == nil || !candidateSupportsAnyCase(candidate, invalidCases) {
			continue
		}
		switch candidate.Status {
		case knowledgeCandidateRejected, knowledgeCandidateSuperseded, knowledgeCandidateValidationFailed:
			continue
		}
		updatedCandidate := cloneKnowledgeCandidate(candidate)
		updatedCandidate.Status = knowledgeCandidateValidationFailed
		updatedCandidate.ValidationError = knowledgeReviewInvalidationError
		updatedCandidate.UpdatedAt = now
		updatedCandidate.DecidedAt = &now
		updatedCandidate.DecidedBy = "system"
		updatedCandidate.DecisionNote = "operator evaluation changed or retracted"
		if updatedCandidate.Payload == nil {
			updatedCandidate.Payload = map[string]any{}
		}
		updatedCandidate.Payload["runtime_status"] = knowledgePackageRetired
		hydrateKnowledgeCandidate(&updatedCandidate)

		var updatedPackage *KnowledgePackage
		if pkg := s.knowledgePackages[candidate.PackageID]; pkg != nil && (pkg.Status == knowledgePackageActive || pkg.Status == knowledgePackageShadow) {
			copy := cloneKnowledgePackage(pkg)
			copy.Status = knowledgePackageRetired
			copy.RetiredAt, copy.RetiredBy, copy.RetirementNote = &now, "system", "operator evaluation changed or retracted"
			if copy.Payload == nil {
				copy.Payload = map[string]any{}
			}
			copy.Payload["runtime_status"] = knowledgePackageRetired
			hydrateKnowledgePackage(&copy)
			updatedPackage = &copy
		}
		event := s.newKnowledgeEventLocked(
			candidate.CandidateID,
			candidate.PackageID,
			"candidate_invalidated",
			"system",
			"operator evaluation changed or retracted",
			now,
		)
		if !s.persistKnowledgeReviewInvalidationLocked(&updatedCandidate, updatedPackage, event) {
			continue
		}
		*candidate = updatedCandidate
		if updatedPackage != nil {
			*s.knowledgePackages[updatedPackage.PackageID] = *updatedPackage
		}
		s.knowledgeEvents[event.EventID] = event
	}
}

// supersedeStaleCaseCandidatesLocked marks every non-decided candidate for a case
// (other than keepID) as superseded. Used when a newer content-derived candidate
// replaces an older one for the same analysis, so the review queue never shows a
// stale failed candidate next to its promoted successor.
func (s *Store) supersedeStaleCaseCandidatesLocked(caseID, keepID string, now time.Time) {
	for _, candidate := range s.knowledgeCandidates {
		if candidate == nil || candidate.CandidateID == keepID {
			continue
		}
		if candidate.CaseID != caseID && !containsString(candidate.SupportingCaseIDs, caseID) {
			continue
		}
		if candidate.Status != knowledgeCandidateGenerated && candidate.Status != knowledgeCandidateValidationFailed {
			continue
		}
		updated := cloneKnowledgeCandidate(candidate)
		updated.Status = knowledgeCandidateSuperseded
		updated.UpdatedAt = now
		updated.DecidedAt = &now
		updated.DecidedBy = "system"
		updated.DecisionNote = "superseded by a newer candidate for the same analysis"
		event := s.newKnowledgeEventLocked(candidate.CandidateID, "", "candidate_superseded", "system", "superseded by a newer candidate for the same analysis", now)
		if !s.persistKnowledgeReviewInvalidationLocked(&updated, nil, event) {
			continue
		}
		*candidate = updated
		s.knowledgeEvents[event.EventID] = event
	}
}

func candidateSupportsAnyCase(candidate *KnowledgeCandidate, cases map[string]bool) bool {
	if candidate == nil {
		return false
	}
	if cases[candidate.CaseID] {
		return true
	}
	for _, caseID := range candidate.SupportingCaseIDs {
		if cases[caseID] {
			return true
		}
	}
	return false
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
