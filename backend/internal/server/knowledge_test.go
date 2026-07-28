package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type knowledgeRoundTripper func(*http.Request) (*http.Response, error)

func (fn knowledgeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func qualifyingKnowledgeReviewScores() map[string]int {
	scores := map[string]int{}
	for _, dimension := range evaluationDimensions {
		scores[dimension] = 5
	}
	return scores
}

func eligibleKnowledgeSnapshot() *CaseSnapshot {
	return &CaseSnapshot{
		CaseID: "ANL-knowledge:hash", IncidentID: "INC-knowledge", RunID: "ANL-knowledge",
		AnalysisHash:    "hash",
		RootCauseFamily: "scheduler_capacity", ApprovedAt: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
		Snapshot: map[string]any{
			"analysis_summary": "safe result summary", "analysis_detail": "safe result detail",
			"case_card": map[string]any{"context": map[string]string{"cluster": "lab", "queue": "gpu-a"}, "operator_resolution_outcomes": []any{"resolved"}},
			"metadata": map[string]any{
				"harness": map[string]any{"overall_score": 90, "hard_gates": map[string]any{"unsupported_high_confidence": false, "invalid_evidence_links": false}},
				"reasoning_trace_v3": map[string]any{
					"schema_version": 3,
					"hypotheses":     []any{map[string]any{"hypothesis_id": "H-1", "family": "scheduler_capacity", "mechanism": "quota exhausted", "status": "selected", "confidence": 0.91, "evidence_for": []any{"E-1", "E-2"}, "evidence_against": []any{}}},
					"evidence": []any{
						map[string]any{"evidence_id": "E-1", "observation_window": map[string]any{"start": "2026-07-12T00:00:00Z", "end": "2026-07-12T00:05:00Z"}, "entity": "queue/gpu-a", "source": "runai", "source_group": "control-plane", "predicate": "quota_exhausted", "polarity": "present", "coverage": "scoped", "quality": "high", "raw_query": "must not survive"},
						map[string]any{"evidence_id": "E-2", "observation_window": map[string]any{"start": "2026-07-12T00:01:00Z", "end": "2026-07-12T00:06:00Z"}, "entity": "scheduler/gpu-a", "source": "kubernetes", "source_group": "scheduler", "predicate": "insufficient_quota", "polarity": "present", "coverage": "scoped", "quality": "high"},
					},
					"probe_executions": []any{map[string]any{"execution_id": "P-1", "template_id": "k8s_troubleshooting:scheduling_capacity:p01", "tool": "runai", "verdict": "confirmed", "executed_at": "2026-07-12T00:04:00Z", "hypothesis_ids": []any{"H-1"}, "evidence_ids": []any{"E-1", "E-2"}, "arguments": "must not survive"}},
					"stop_reason":      "sufficient_evidence",
				},
			},
		},
	}
}

func confirmKnowledgeSnapshot(store *Store, snapshot *CaseSnapshot) {
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, "operator")] = &EvaluationReview{
		ReviewID:          "EVR-" + snapshot.RunID,
		RunID:             snapshot.RunID,
		AnalysisHash:      snapshot.AnalysisHash,
		Reviewer:          "operator",
		CaseType:          "known",
		ExpectedFamily:    snapshot.RootCauseFamily,
		Scores:            qualifyingKnowledgeReviewScores(),
		ResolutionOutcome: "resolved",
	}
}

func TestOperatorExpectedFamilyGatesKnowledgeGenerationAndPromotion(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	store.caseSnapshots[snapshot.CaseID] = snapshot
	review := &EvaluationReview{
		ReviewID: "EVR-1", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "operator", CaseType: "known", ExpectedFamily: snapshot.RootCauseFamily,
		Scores:            qualifyingKnowledgeReviewScores(),
		ResolutionOutcome: "resolved",
	}
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, review.Reviewer)] = review
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, "scorer")] = &EvaluationReview{
		ReviewID: "EVR-2", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "scorer", CaseType: "known", Scores: qualifyingKnowledgeReviewScores(), ResolutionOutcome: "resolved",
	}

	candidate := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("matching operator family should preserve existing safety-gated candidate: %+v", candidate)
	}
	store.knowledgeCandidates[candidate.CandidateID] = candidate

	// A later correction on the same immutable analysis hash must both prevent
	// new generation and block a previously generated candidate at promotion.
	review.ExpectedFamily = "gpu_hardware_error"
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got != nil {
		t.Fatalf("wrong-family review generated snapshot family candidate: %+v", got)
	}
	if _, _, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err == nil {
		t.Fatal("wrong-family review did not block candidate promotion")
	}
}

func TestKnowledgePromotionPreviewSurfacesIngestionOutcome(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.caseSnapshots[snapshot.CaseID] = snapshot

	// No approved snapshot for that run/hash: the RCA has not been approved yet.
	if got := store.knowledgePromotionPreviewLocked("ANL-missing", "hash"); got.Outcome != "not_approved" {
		t.Fatalf("unknown run should be not_approved, got %+v", got)
	}
	// Approved but not yet evaluated: blocked pending a review.
	if got := store.knowledgePromotionPreviewLocked(snapshot.RunID, snapshot.AnalysisHash); got.Outcome != "blocked" {
		t.Fatalf("missing review should block, got %+v", got)
	}
	// A qualifying, family-matching review makes it ready with a concrete family/evidence/probe.
	confirmKnowledgeSnapshot(store, snapshot)
	ready := store.knowledgePromotionPreviewLocked(snapshot.RunID, snapshot.AnalysisHash)
	if ready.Outcome != "ready" || ready.Family != snapshot.RootCauseFamily || ready.EvidenceCount == 0 || ready.ProbeCount == 0 {
		t.Fatalf("qualifying review should preview ready with detail: %+v", ready)
	}
	// A family-mismatched review fails closed exactly like the real promotion gate.
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, "operator")].ExpectedFamily = "gpu_hardware_error"
	if got := store.knowledgePromotionPreviewLocked(snapshot.RunID, snapshot.AnalysisHash); got.Outcome != "blocked" {
		t.Fatalf("family mismatch should block, got %+v", got)
	}
}

func TestKnowledgePromotionPreviewNamesTheHashlessRunState(t *testing.T) {
	store := NewStore()
	cases := []struct {
		status string
		want   string
	}{
		{"analyzing", "analysis is still running; evaluate after it completes"},
		{"failed", "analysis failed and produced no result to evaluate"},
		{"complete", "this run predates result hashing; re-run the analysis to make it evaluable"},
	}
	for _, tc := range cases {
		runID := "ANL-" + tc.status
		store.analysisRuns[runID] = &AnalysisRun{RunID: runID, Status: tc.status}
		got := store.knowledgePromotionPreviewLocked(runID, "")
		if got.Outcome != "blocked" || got.Reason != tc.want {
			t.Fatalf("status %q: got %+v", tc.status, got)
		}
	}
	// Unknown run keeps the generic reason.
	if got := store.knowledgePromotionPreviewLocked("ANL-unknown", ""); got.Reason != "analysis has no result hash yet" {
		t.Fatalf("unknown run reason changed: %+v", got)
	}
}

func TestValidationFailedCandidateStaysIdentifiable(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	// Break the v3 trace so no supported hypothesis matches the final root cause.
	trace := snapshot.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)
	trace["hypotheses"] = []any{}

	candidate := knowledgeCandidateForSnapshotWithOutcome(snapshot, true, false)
	if candidate == nil || candidate.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("expected a validation_failed candidate, got %+v", candidate)
	}
	if candidate.ValidationError == "" {
		t.Fatal("failed candidate must carry the validation reason")
	}
	// The reviewer must still be able to tell which incident/family/analysis failed.
	if candidate.RootCauseFamily != snapshot.RootCauseFamily || candidate.Title == "" ||
		candidate.AnalysisRunID != snapshot.RunID || candidate.AnalysisHash != snapshot.AnalysisHash {
		t.Fatalf("failed candidate lost its incident identity: %+v", candidate)
	}
	// It must never look promotable: no compiled failure modes / probes.
	if len(candidate.ProbeTemplateIDs) != 0 || candidate.Kind != "" {
		t.Fatalf("failed candidate must not carry compiled knowledge: %+v", candidate)
	}
}

func TestOperatorConfirmationOverridesUnsupportedHypothesis(t *testing.T) {
	// A non-reproducible incident: the sole family-matching hypothesis never reached
	// "supported" (probes stayed inconclusive) but is still evidence-backed.
	base := func() *CaseSnapshot {
		snap := eligibleKnowledgeSnapshot()
		snap.ApprovalState = "active"
		hyp := snap.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)["hypotheses"].([]any)[0].(map[string]any)
		hyp["status"] = "uncertain"
		hyp["confidence"] = 0.4
		return snap
	}

	// Without confirmation it fails closed exactly as today.
	if c := knowledgeCandidateForSnapshotWithOutcome(base(), true, false); c == nil || c.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("unconfirmed unsupported hypothesis must fail: %+v", c)
	}
	// With confirmation it promotes — it still carries real evidence + a linked probe.
	if c := knowledgeCandidateForSnapshotWithOutcome(base(), true, true); c == nil || c.Status != knowledgeCandidateReady {
		t.Fatalf("operator confirmation should promote an evidence-backed hypothesis: %+v", c)
	}
	// The evidence floor is NOT relaxed: strip supporting evidence and confirmation cannot save it.
	noEvidence := base()
	noEvidence.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)["hypotheses"].([]any)[0].(map[string]any)["evidence_for"] = []any{}
	if c := knowledgeCandidateForSnapshotWithOutcome(noEvidence, true, true); c == nil || c.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("confirmation must not fabricate evidence-free knowledge: %+v", c)
	}

	// Store gate: an operator_confirmed review flips the full gated path to ready,
	// but only when it names the snapshot family and clears the quality floor.
	store := NewStore()
	snap := base()
	store.caseSnapshots[snap.CaseID] = snap
	review := &EvaluationReview{
		ReviewID: "EVR-c", RunID: snap.RunID, AnalysisHash: snap.AnalysisHash, Reviewer: "operator",
		CaseType: "known", ExpectedFamily: snap.RootCauseFamily, Scores: qualifyingKnowledgeReviewScores(),
		ResolutionOutcome: "resolved", Notes: "reproduced manually offline", OperatorConfirmed: true,
	}
	store.evaluationReviews[evaluationKey(snap.RunID, snap.AnalysisHash, "operator")] = review
	if c := store.knowledgeCandidateForSnapshotLocked(snap); c == nil || c.Status != knowledgeCandidateReady {
		t.Fatalf("confirmed review should promote through the full gate: %+v", c)
	}
	review.ExpectedFamily = "gpu_hardware_error"
	if store.operatorConfirmedForSnapshotLocked(snap) {
		t.Fatal("confirmation must match the snapshot family, not an arbitrary one")
	}
}

func TestOperatorConfirmSupersedesFailedCandidateThroughReview(t *testing.T) {
	s := NewStore()
	s.SeedDevFixtures()
	scores := map[string]int{}
	for _, d := range evaluationDimensions {
		scores[d] = 5
	}
	base := EvaluationReviewRequest{
		Author: "op", AnalysisHash: "devhash01", CaseType: "known",
		ExpectedFamily: "workload_startup_error", Scores: scores, ResolutionOutcome: "resolved",
	}
	allowed := []string{"workload_startup_error"}

	// A plain review yields one validation_failed candidate that still names its incident.
	if _, _, err := s.UpsertEvaluationReview("ANL-DEV-000001", base, allowed); err != nil {
		t.Fatal(err)
	}
	failed := s.ListKnowledgeCandidates("")
	if len(failed) != 1 || failed[0].Status != knowledgeCandidateValidationFailed ||
		failed[0].RootCauseFamily != "workload_startup_error" || failed[0].Title == "" {
		t.Fatalf("expected one identifiable validation_failed candidate, got %+v", failed)
	}

	// Operator confirmation promotes it; the stale failed candidate is superseded, not duplicated.
	confirmed := base
	confirmed.OperatorConfirmed = true
	confirmed.Notes = "reproduced offline"
	if _, _, err := s.UpsertEvaluationReview("ANL-DEV-000001", confirmed, allowed); err != nil {
		t.Fatal(err)
	}
	var ready, superseded int
	for _, c := range s.ListKnowledgeCandidates("") {
		switch c.Status {
		case knowledgeCandidateReady:
			ready++
		case knowledgeCandidateSuperseded:
			superseded++
		}
	}
	if ready != 1 || superseded != 1 {
		t.Fatalf("confirmation should leave 1 ready + 1 superseded, got ready=%d superseded=%d", ready, superseded)
	}
}

func TestOperatorReviewQualityVetoesKnowledgeGeneration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EvaluationReview)
	}{
		{
			name: "score below 80 equivalent",
			mutate: func(review *EvaluationReview) {
				for _, dimension := range evaluationDimensions {
					review.Scores[dimension] = 4
				}
				review.Scores["evidence_grounding"] = 3 // total 27/35, below 80%
			},
		},
		{
			name: "hard gate violation",
			mutate: func(review *EvaluationReview) {
				review.HardGates = map[string]bool{"invalid_evidence_links": true}
			},
		},
		{
			name: "ineffective outcome",
			mutate: func(review *EvaluationReview) {
				review.ResolutionOutcome = "ineffective"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewStore()
			snapshot := eligibleKnowledgeSnapshot()
			review := &EvaluationReview{
				ReviewID:          "EVR-quality",
				RunID:             snapshot.RunID,
				AnalysisHash:      snapshot.AnalysisHash,
				Reviewer:          "operator",
				CaseType:          "known",
				ExpectedFamily:    snapshot.RootCauseFamily,
				Scores:            qualifyingKnowledgeReviewScores(),
				ResolutionOutcome: "resolved",
			}
			test.mutate(review)
			store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, review.Reviewer)] = review
			if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got != nil {
				t.Fatalf("unsafe operator review generated runtime knowledge: %+v", got)
			}
			if review.ExpectedFamily != snapshot.RootCauseFamily {
				t.Fatalf("knowledge veto erased the independent evaluation label: %+v", review)
			}
		})
	}
}

func TestOperatorReviewAt80EquivalentRemainsEligible(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	scores := map[string]int{}
	for _, dimension := range evaluationDimensions {
		scores[dimension] = 4
	}
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, "operator")] = &EvaluationReview{
		ReviewID:          "EVR-threshold",
		RunID:             snapshot.RunID,
		AnalysisHash:      snapshot.AnalysisHash,
		Reviewer:          "operator",
		CaseType:          "known",
		ExpectedFamily:    snapshot.RootCauseFamily,
		Scores:            scores,
		ResolutionOutcome: "resolved",
	}
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got == nil || got.Status != knowledgeCandidateReady {
		t.Fatalf("80-equivalent operator review should meet the promotion floor: %+v", got)
	}
}

func TestNoReviewCannotRevalidateAlreadyLinkedLegacyCandidate(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got != nil {
		t.Fatalf("no-review snapshot generated new model-family knowledge: %+v", got)
	}

	legacy := knowledgeCandidateForSnapshot(snapshot)
	if legacy == nil || legacy.Status != knowledgeCandidateReady {
		t.Fatalf("invalid legacy test fixture: %+v", legacy)
	}
	store.knowledgeCandidates[legacy.CandidateID] = legacy
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got != nil {
		t.Fatalf("legacy candidate bypassed the operator family gate: %+v", got)
	}
	store.caseSnapshots[snapshot.CaseID] = snapshot
	if _, _, err := store.ApproveKnowledgeCandidate(legacy.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err == nil {
		t.Fatal("legacy candidate without expected_family review was promoted")
	}
}

func TestOperatorCaseTypeGatesKnowledgePromotion(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	review := &EvaluationReview{
		ReviewID: "EVR-1", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "operator", CaseType: "tool_degraded", ExpectedFamily: snapshot.RootCauseFamily,
		Scores:            qualifyingKnowledgeReviewScores(),
		ResolutionOutcome: "resolved",
	}
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, review.Reviewer)] = review
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got != nil {
		t.Fatalf("tool-degraded evidence must not become runtime knowledge: %+v", got)
	}

	novel := cloneCaseSnapshot(snapshot)
	novel.RootCauseFamily = "novel_scheduler_capacity_race_1234abcd"
	knowledgeTraceForTest(&novel)["hypotheses"].([]any)[0].(map[string]any)["family"] = novel.RootCauseFamily
	review.CaseType, review.ExpectedFamily = "novel", ""
	if got := store.knowledgeCandidateForSnapshotLocked(&novel); got == nil || got.Status != knowledgeCandidateReady {
		t.Fatalf("resolved novel review should confirm a novel-family snapshot: %+v", got)
	}
	conflictKey := evaluationKey(snapshot.RunID, snapshot.AnalysisHash, "known-reviewer")
	store.evaluationReviews[conflictKey] = &EvaluationReview{
		ReviewID: "EVR-2", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "known-reviewer", CaseType: "known", Scores: qualifyingKnowledgeReviewScores(), ResolutionOutcome: "resolved",
	}
	if got := store.knowledgeCandidateForSnapshotLocked(&novel); got != nil {
		t.Fatalf("known/novel review disagreement must block promotion: %+v", got)
	}
	delete(store.evaluationReviews, conflictKey)

	review.CaseType = "compositional"
	review.ExpectedFamily = snapshot.RootCauseFamily
	if got := store.knowledgeCandidateForSnapshotLocked(snapshot); got == nil || got.Status != knowledgeCandidateReady {
		t.Fatalf("compositional primary-family match should remain eligible: %+v", got)
	}
}

func TestKnowledgeCandidateRequiresEligibleTraceV3AndCompilesSafePayload(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected ready candidate, got %+v", candidate)
	}
	if candidate.Payload["hypothesis_id"] != "H-1" || candidate.Payload["mechanism"] != "quota exhausted" {
		t.Fatalf("expected exact v3 hypothesis details, got %+v", candidate.Payload)
	}
	if candidate.Kind != "failure_mode" || len(candidate.EvidenceSummaries) != 2 || candidate.EvidenceSummaries[0].SourceGroup == "" || candidate.EvidenceSummaries[0].Entity == "" || candidate.EvidenceSummaries[0].Coverage != "scoped" || len(candidate.ProbeTemplateIDs) != 1 || candidate.ProbeTemplateIDs[0] != "k8s_troubleshooting:scheduling_capacity:p01" || len(candidate.ProbeBindings) != 1 || candidate.ProbeBindings[0].CandidateProbeID != candidate.CandidateID+":"+candidate.ProbeBindings[0].ProbeLocalID || candidate.ProbeBindings[0].ActiveProbeID != "" {
		t.Fatalf("candidate review DTO omitted sanitized corroboration details: %+v", candidate)
	}
	partialCoverage := cloneCaseSnapshot(snapshot)
	knowledgeTraceForTest(&partialCoverage)["evidence"].([]any)[1].(map[string]any)["coverage"] = "partial"
	if candidate := knowledgeCandidateForSnapshot(&partialCoverage); candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("present partial evidence must remain eligible, got %+v", candidate)
	}
	encoded := string(mustJSON(candidate))
	if bytes.Contains([]byte(encoded), []byte("must not survive")) || bytes.Contains([]byte(encoded), []byte("analysis_detail")) {
		t.Fatalf("candidate exposed raw trace or analysis content: %s", encoded)
	}
	legacy := cloneCaseSnapshot(snapshot)
	legacy.Snapshot["metadata"] = map[string]any{"reasoning_trace_v2": map[string]any{"mechanism": "legacy"}}
	if candidate := knowledgeCandidateForSnapshot(&legacy); candidate != nil {
		t.Fatalf("legacy trace must not create candidate graph data: %+v", candidate)
	}
	withoutOutcome := cloneCaseSnapshot(snapshot)
	withoutOutcome.Snapshot["case_card"] = map[string]any{}
	if candidate := knowledgeCandidateForSnapshot(&withoutOutcome); candidate != nil {
		t.Fatalf("unknown operator outcome must not create candidate: %+v", candidate)
	}
	invalid := cloneCaseSnapshot(snapshot)
	trace := invalid.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)
	trace["hypotheses"] = []any{map[string]any{"hypothesis_id": "H-1", "family": "scheduler_capacity", "mechanism": "quota exhausted", "status": "selected", "confidence": 0.91, "evidence_for": []any{"E-1"}, "evidence_against": []any{"E-1"}}}
	if candidate := knowledgeCandidateForSnapshot(&invalid); candidate == nil || candidate.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("contradictory v3 trace must fail validation, got %+v", candidate)
	}
}

func TestKnowledgeCandidateEligibilityFailsClosedOnPlanGates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CaseSnapshot)
	}{
		{"quality below 80", func(snapshot *CaseSnapshot) {
			snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)["overall_score"] = 79
		}},
		{"missing hard gates", func(snapshot *CaseSnapshot) {
			delete(snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any), "hard_gates")
		}},
		{"failed hard gate", func(snapshot *CaseSnapshot) {
			snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)["hard_gates"] = map[string]any{"invalid_evidence_links": true}
		}},
		{"noncanonical polarity", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["polarity"] = "positive"
		}},
		{"noncanonical coverage", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["coverage"] = "complete"
		}},
		{"missing entity", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["entity"] = ""
		}},
		{"missing source group", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["source_group"] = ""
		}},
		{"missing observation window", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["observation_window"].(map[string]any)["end"] = ""
		}},
		{"single source group", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["evidence"].([]any)[1].(map[string]any)["source_group"] = "control-plane"
		}},
		{"unlinked probe", func(snapshot *CaseSnapshot) {
			knowledgeTraceForTest(snapshot)["probe_executions"].([]any)[0].(map[string]any)["hypothesis_ids"] = []any{"H-other"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneCaseSnapshot(eligibleKnowledgeSnapshot())
			test.mutate(&snapshot)
			candidate := knowledgeCandidateForSnapshot(&snapshot)
			if candidate == nil || candidate.Status != knowledgeCandidateValidationFailed || candidate.ValidationError == "" {
				t.Fatalf("expected validation_failed candidate, got %+v", candidate)
			}
		})
	}
}

func TestCompiledSymptomKeywordsAreObservedTermsNotFragments(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	trace := knowledgeTraceForTest(snapshot)
	// The live INC-000008 candidate: machine predicates only, no observed
	// terms, tokenized into "kubernetes container error" fragments that would
	// substring-match every future incident.
	trace["evidence"].([]any)[0].(map[string]any)["predicate"] = "kubernetes_target_container_lifecycle"
	trace["evidence"].([]any)[0].(map[string]any)["observed_terms"] = []any{"CreateContainerConfigError"}
	trace["evidence"].([]any)[1].(map[string]any)["predicate"] = "alert_signature:workload_startup_error"
	snapshot.Snapshot["case_card"].(map[string]any)["context"] = map[string]string{"alert_name": "KubeContainerWaiting"}

	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected ready candidate, got %+v", candidate)
	}
	symptom := candidate.Payload["compiled"].(map[string]any)["failure_modes"].([]any)[0].(map[string]any)["symptoms"].([]any)[0].(map[string]any)
	keywords := symptom["keywords"].([]string)
	for _, fragment := range []string{"error", "container", "kubernetes", "alert", "signature"} {
		for _, keyword := range keywords {
			if keyword == fragment {
				t.Fatalf("generic fragment %q survived as a matcher keyword: %+v", fragment, keywords)
			}
		}
	}
	got := map[string]bool{}
	for _, keyword := range keywords {
		got[keyword] = true
	}
	// Observed term + alert name, whole and lowercased; the legacy predicate
	// stays whole (a dead phrase, not a universal fragment).
	for _, want := range []string{"kubecontainerwaiting", "createcontainerconfigerror", "alert_signature:workload_startup_error"} {
		if !got[want] {
			t.Fatalf("expected keyword %q, got %+v", want, keywords)
		}
	}
}

func TestHarnessClaimMechanismPrefersTraceHypothesisOverHeadline(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.Mechanism = ""
	snapshot.Snapshot["analysis_summary"] = "대상에서 KubeContainerWaiting 알림이 발생했습니다. 구체적으로는 ConfigMap이 없습니다."
	harness := snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)
	harness["diagnosis_state"] = "supported"
	harness["claims"] = []any{map[string]any{
		"family": snapshot.RootCauseFamily, "kind": "root_cause", "claim_id": "C01",
		"confidence": "medium", "supporting_evidence": []any{"E-1"}, "contradicting_evidence": []any{},
	}}
	trace := knowledgeTraceForTest(snapshot)
	trace["hypotheses"].([]any)[0].(map[string]any)["evidence_for"] = []any{}
	delete(trace, "probe_executions")

	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected ready candidate, got %+v", candidate)
	}
	// The trace hypothesis for the family carries the causal statement; the
	// summary's first sentence is the alert headline and says nothing causal.
	if candidate.Payload["mechanism"] != "quota exhausted" {
		t.Fatalf("harness path took the headline over the trace mechanism: %v", candidate.Payload["mechanism"])
	}
}

func TestHarnessClaimEvidenceFallbackCompilesKnowledge(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	harness := snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)
	harness["diagnosis_state"] = "supported"
	harness["claims"] = []any{map[string]any{
		"family":                 snapshot.RootCauseFamily,
		"kind":                   "root_cause",
		"claim_id":               "C01",
		"confidence":             "medium",
		"supporting_evidence":    []any{"E-1"},
		"contradicting_evidence": []any{},
	}}
	trace := knowledgeTraceForTest(snapshot)
	trace["hypotheses"].([]any)[0].(map[string]any)["evidence_for"] = []any{}
	delete(trace, "probe_executions")

	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("harness claim support should compile when the trace ledger is empty: %+v", candidate)
	}
	if candidate.Payload["evidence_source"] != "harness_claim" {
		t.Fatalf("fallback payload is missing audit marker: %+v", candidate.Payload)
	}
	if got := candidate.Payload["supporting_evidence_ids"].([]string); len(got) != 1 || got[0] != "E-1" {
		t.Fatalf("fallback support IDs were not preserved: %+v", got)
	}
	if got := candidate.Payload["compiled"].(map[string]any)["probe_template_ids"].(map[string]any)[snapshot.RootCauseFamily].([]string); len(got) != 0 {
		t.Fatalf("harness claim path must not invent probes: %+v", got)
	}
	provenance := candidate.Payload["provenance"].(map[string]any)
	if provenance["promotion_path"] != "harness_claim" {
		t.Fatalf("harness claim path missing provenance marker: %+v", provenance)
	}
}

func TestHarnessClaimFallbackRetainsOnlyFamilyLinkedProbe(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	harness := snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)
	harness["diagnosis_state"] = "supported"
	harness["claims"] = []any{map[string]any{
		"family": snapshot.RootCauseFamily, "kind": "root_cause", "claim_id": "C01",
		"confidence": "medium", "supporting_evidence": []any{"E-1"}, "contradicting_evidence": []any{},
	}}
	trace := knowledgeTraceForTest(snapshot)
	trace["hypotheses"].([]any)[0].(map[string]any)["evidence_for"] = []any{}
	trace["hypotheses"] = append(trace["hypotheses"].([]any), map[string]any{
		"hypothesis_id": "H-other", "family": "gpu_hardware_error",
	})
	trace["probe_executions"] = append(trace["probe_executions"].([]any), map[string]any{
		"execution_id": "P-other", "template_id": "gpu:xid:p01", "verdict": "supports",
		"hypothesis_ids": []any{"H-other"}, "evidence_ids": []any{"E-1"},
	})

	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("harness fallback should remain ready: %+v", candidate)
	}
	if got := candidate.ProbeTemplateIDs; len(got) != 1 || got[0] != "k8s_troubleshooting:scheduling_capacity:p01" {
		t.Fatalf("fallback retained an unlinked or wrong-family probe: %+v", got)
	}
}

func TestKnowledgeApprovalUpgradesLegacyCandidateWithMissingProbeIDs(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || len(candidate.ProbeTemplateIDs) != 1 {
		t.Fatalf("fixture must include a linked probe: %+v", candidate)
	}
	legacyPayload := cloneCaseSnapshotPayload(candidate.Payload)
	legacyPayload["compiled"].(map[string]any)["probe_template_ids"] = map[string]any{snapshot.RootCauseFamily: []string{}}
	candidate.Payload = legacyPayload
	candidate.ContentHash = knowledgeContentHash(candidate.Trace, candidate.Payload)
	hydrateKnowledgeCandidate(candidate)
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.knowledgeCandidates[candidate.CandidateID] = candidate
	confirmKnowledgeSnapshot(store, snapshot)

	updated, pkg, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"})
	if err != nil || len(updated.ProbeTemplateIDs) != 1 || len(pkg.ProbeTemplateIDs) != 1 || pkg.ProbeTemplateIDs[0] != "k8s_troubleshooting:scheduling_capacity:p01" {
		t.Fatalf("legacy candidate did not receive its trace-derived probe on approval: candidate=%+v package=%+v err=%v", updated, pkg, err)
	}
}

func TestHarnessClaimEvidenceFallbackFailsClosedWithoutCleanSupport(t *testing.T) {
	tests := []struct {
		name    string
		family  string
		support []any
		against []any
	}{
		{name: "empty claim support", family: "scheduler_capacity", support: []any{}, against: []any{}},
		{name: "claim contradiction", family: "scheduler_capacity", support: []any{"E-1"}, against: []any{"E-2"}},
		{name: "family mismatch", family: "gpu_hardware_error", support: []any{"E-1", "E-2"}, against: []any{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := eligibleKnowledgeSnapshot()
			harness := snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)
			harness["claims"] = []any{map[string]any{
				"family":                 test.family,
				"supporting_evidence":    test.support,
				"contradicting_evidence": test.against,
			}}
			knowledgeTraceForTest(snapshot)["hypotheses"].([]any)[0].(map[string]any)["evidence_for"] = []any{}

			candidate := knowledgeCandidateForSnapshot(snapshot)
			if candidate == nil || candidate.Status != knowledgeCandidateValidationFailed || candidate.ValidationError != "missing supporting evidence" {
				t.Fatalf("unsafe harness fallback should fail closed: %+v", candidate)
			}
		})
	}
}

func TestHarnessClaimPathRejectsUnsafeClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CaseSnapshot)
	}{
		{
			name: "contradicting evidence",
			mutate: func(snapshot *CaseSnapshot) {
				harnessClaimForTest(snapshot)["contradicting_evidence"] = []any{"E-2"}
			},
		},
		{
			name: "family mismatch",
			mutate: func(snapshot *CaseSnapshot) {
				harnessClaimForTest(snapshot)["family"] = "gpu_hardware_error"
			},
		},
		{
			name: "unknown evidence ID",
			mutate: func(snapshot *CaseSnapshot) {
				harnessClaimForTest(snapshot)["supporting_evidence"] = []any{"E-unknown"}
			},
		},
		{
			name: "noncanonical evidence",
			mutate: func(snapshot *CaseSnapshot) {
				harnessClaimForTest(snapshot)["supporting_evidence"] = []any{"E-1"}
				knowledgeTraceForTest(snapshot)["evidence"].([]any)[0].(map[string]any)["polarity"] = "absent"
			},
		},
		{
			name: "diagnosis not supported",
			mutate: func(snapshot *CaseSnapshot) {
				snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)["diagnosis_state"] = "provisional"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := harnessClaimSnapshotForTest()
			test.mutate(snapshot)
			candidate := knowledgeCandidateForSnapshot(snapshot)
			if candidate == nil || candidate.Status != knowledgeCandidateValidationFailed {
				t.Fatalf("unsafe harness claim should fail closed: %+v", candidate)
			}
			if candidate.ValidationError != "expected exactly one supported trace-v3 hypothesis matching final root cause" {
				t.Fatalf("path 1 error should be preserved, got %q", candidate.ValidationError)
			}
		})
	}
}

func TestCompleteLedgerRemainsThePrimaryPromotionPath(t *testing.T) {
	candidate := knowledgeCandidateForSnapshot(eligibleKnowledgeSnapshot())
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("complete ledger should remain eligible: %+v", candidate)
	}
	if _, ok := candidate.Payload["evidence_source"]; ok {
		t.Fatalf("complete ledger must not be marked as harness claim: %+v", candidate.Payload)
	}
}

func TestValidationFailedCandidateRefreshesItsLatestReason(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	trace := knowledgeTraceForTest(snapshot)
	trace["hypotheses"] = []any{}
	delete(trace, "probe_executions")
	latest := knowledgeCandidateForSnapshotWithOutcome(snapshot, true, false)
	if latest == nil || latest.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("invalid fixture: %+v", latest)
	}
	stale := cloneKnowledgeCandidate(latest)
	stale.ValidationError = "stale validation reason"
	stale.UpdatedAt = time.Unix(1, 0).UTC()
	oldUpdatedAt := stale.UpdatedAt
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.knowledgeCandidates[stale.CandidateID] = &stale
	confirmKnowledgeSnapshot(store, snapshot)

	store.generateKnowledgeCandidateForReviewedRunLocked(snapshot.RunID, snapshot.AnalysisHash)
	refreshed := store.knowledgeCandidates[stale.CandidateID]
	if refreshed == nil || refreshed.ValidationError != latest.ValidationError {
		t.Fatalf("candidate validation reason was not refreshed: %+v", refreshed)
	}
	if !refreshed.UpdatedAt.After(oldUpdatedAt) {
		t.Fatalf("candidate updated_at was not refreshed: old=%s new=%s", oldUpdatedAt, refreshed.UpdatedAt)
	}
	foundEvent := false
	for _, event := range store.knowledgeEvents {
		if event.CandidateID == stale.CandidateID && event.Type == "candidate_validation_refreshed" {
			foundEvent = true
			break
		}
	}
	if !foundEvent {
		t.Fatal("candidate validation refresh did not create an audit event")
	}
}

func harnessClaimSnapshotForTest() *CaseSnapshot {
	snapshot := eligibleKnowledgeSnapshot()
	metadata := snapshot.Snapshot["metadata"].(map[string]any)
	harness := metadata["harness"].(map[string]any)
	harness["diagnosis_state"] = "supported"
	harness["claims"] = []any{map[string]any{
		"claim_id":               "C01",
		"kind":                   "root_cause",
		"family":                 snapshot.RootCauseFamily,
		"confidence":             "medium",
		"supporting_evidence":    []any{"E-1"},
		"contradicting_evidence": []any{},
	}}
	trace := knowledgeTraceForTest(snapshot)
	trace["hypotheses"] = []any{}
	delete(trace, "probe_executions")
	return snapshot
}

func harnessClaimForTest(snapshot *CaseSnapshot) map[string]any {
	return snapshot.Snapshot["metadata"].(map[string]any)["harness"].(map[string]any)["claims"].([]any)[0].(map[string]any)
}

func knowledgeTraceForTest(snapshot *CaseSnapshot) map[string]any {
	return snapshot.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)
}

func TestKnowledgePublicLifecycleAndRuntimeETag(t *testing.T) {
	server := NewServer()
	server.knowledgeValidatorURL = "http://agent.internal"
	server.client = &http.Client{Transport: knowledgeRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.String() != "http://agent.internal/knowledge/validate" {
			t.Fatalf("unexpected validator request: %s %s", req.Method, req.URL)
		}
		body, _ := io.ReadAll(req.Body)
		if bytes.Contains(body, []byte("safe result detail")) || bytes.Contains(body, []byte("must not survive")) {
			t.Fatalf("validator received unsafe data: %s", body)
		}
		var snapshot struct {
			Revision string `json:"revision"`
			Packages []struct {
				PackageID string         `json:"package_id"`
				Status    string         `json:"status"`
				Compiled  map[string]any `json:"compiled"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(body, &snapshot); err != nil || snapshot.Revision == "" || len(snapshot.Packages) != 1 || snapshot.Packages[0].PackageID == "" || snapshot.Packages[0].Status != "active" || len(snapshot.Packages[0].Compiled) == 0 {
			t.Fatalf("validator did not receive runtime package contract: %s", body)
		}
		byFamily, ok := snapshot.Packages[0].Compiled["probe_template_ids"].(map[string]any)
		if !ok || len(byFamily["scheduler_capacity"].([]any)) != 1 {
			t.Fatalf("validator did not receive family-keyed probe template IDs: %s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"valid":true}`))}, nil
	})}
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	server.store.mu.Lock()
	server.store.caseSnapshots[snapshot.CaseID] = snapshot
	server.store.knowledgeCandidates[candidate.CandidateID] = candidate
	confirmKnowledgeSnapshot(server.store, snapshot)
	server.store.mu.Unlock()

	decision, _ := json.Marshal(map[string]string{"action": "approve", "reason": "reviewed"})
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-candidates/"+candidate.CandidateID+"/decision", bytes.NewReader(decision)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("approve endpoint returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := server.store.KnowledgePackage("KPK-" + snapshot.CaseID); !ok {
		t.Fatal("approval did not publish a package")
	}
	published, _ := server.store.KnowledgePackage("KPK-" + snapshot.CaseID)
	if published.MirrorStatus != "pending" || published.MirrorUpdatedAt == nil {
		t.Fatalf("new package mirror state should be pending: %+v", published)
	}
	if updated, err := server.store.UpdateKnowledgePackageMirror(published.PackageID, "synced", "", time.Now().UTC()); err != nil || updated.MirrorStatus != "synced" {
		t.Fatalf("mirror update failed: package=%+v err=%v", updated, err)
	}

	runtime := httptest.NewRecorder()
	server.routes().ServeHTTP(runtime, httptest.NewRequest(http.MethodGet, "/api/v1/knowledge/runtime-snapshot", nil))
	if runtime.Code != http.StatusOK || runtime.Header().Get("ETag") == "" {
		t.Fatalf("runtime response missing ETag: code=%d headers=%v", runtime.Code, runtime.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(runtime.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["revision"]; !ok || len(body) != 2 {
		t.Fatalf("runtime must be direct revision/packages contract: %s", runtime.Body.String())
	}
	if _, ok := body["packages"].([]any); !ok {
		t.Fatalf("runtime packages missing: %s", runtime.Body.String())
	}
	packages := body["packages"].([]any)
	pkg := packages[0].(map[string]any)
	if pkg["kind"] != "failure_mode" {
		t.Fatalf("runtime package must expose review kind: %s", runtime.Body.String())
	}
	compiled, ok := pkg["compiled"].(map[string]any)
	if !ok || len(compiled["failure_modes"].([]any)) != 1 {
		t.Fatalf("runtime package must expose registry-ready compiled failure modes: %s", runtime.Body.String())
	}
	if ids, ok := pkg["probe_template_ids"].([]any); !ok || len(ids) != 1 || ids[0] != "k8s_troubleshooting:scheduling_capacity:p01" {
		t.Fatalf("runtime package must expose deterministic template identifiers: %s", runtime.Body.String())
	}
	evidence, ok := pkg["evidence_summaries"].([]any)
	if !ok || len(evidence) != 2 || evidence[0].(map[string]any)["source_group"] == "" || evidence[0].(map[string]any)["entity"] == "" || evidence[0].(map[string]any)["coverage"] == "" {
		t.Fatalf("runtime package omitted safe evidence review fields: %s", runtime.Body.String())
	}
	bindings, ok := pkg["probe_bindings"].([]any)
	if !ok || len(bindings) != 1 {
		t.Fatalf("runtime package omitted active probe binding: %s", runtime.Body.String())
	}
	binding := bindings[0].(map[string]any)
	if binding["template_id"] != "k8s_troubleshooting:scheduling_capacity:p01" || binding["active_probe_id"] != pkg["package_id"].(string)+":v1:"+binding["probe_local_id"].(string) || binding["candidate_probe_id"] != nil || bytes.Contains(runtime.Body.Bytes(), []byte("arguments")) {
		t.Fatalf("runtime probe binding leaked executable data or is not deterministic: %s", runtime.Body.String())
	}

	notModified := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/knowledge/runtime-snapshot", nil)
	request.Header.Set("If-None-Match", runtime.Header().Get("ETag"))
	server.routes().ServeHTTP(notModified, request)
	if notModified.Code != http.StatusNotModified {
		t.Fatalf("expected conditional runtime 304, got %d", notModified.Code)
	}

}

func TestKnowledgeApprovalValidatorFailureDoesNotChangeState(t *testing.T) {
	server := NewServer()
	server.knowledgeValidatorURL = "http://agent.internal"
	server.client = &http.Client{Transport: knowledgeRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"valid":false}`))}, nil
	})}
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	server.store.mu.Lock()
	server.store.caseSnapshots[snapshot.CaseID] = snapshot
	server.store.knowledgeCandidates[candidate.CandidateID] = candidate
	server.store.mu.Unlock()
	decision, _ := json.Marshal(map[string]string{"action": "approve"})
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-candidates/"+candidate.CandidateID+"/decision", bytes.NewReader(decision)))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected validator rejection 422, got %d: %s", recorder.Code, recorder.Body.String())
	}
	stored, _ := server.store.KnowledgeCandidate(candidate.CandidateID)
	if stored.Status != knowledgeCandidateValidationFailed || stored.ValidationError == "" {
		t.Fatalf("validator semantic rejection did not fail candidate: %+v", stored)
	}
	if _, ok := server.store.KnowledgePackage("KPK-" + snapshot.CaseID); ok {
		t.Fatal("validator failure published a package")
	}
}

func TestKnowledgeApprovalValidatorUnavailablePreservesReadyCandidate(t *testing.T) {
	server := NewServer()
	server.knowledgeValidatorURL = "http://agent.internal"
	server.client = &http.Client{Transport: knowledgeRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })}
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	server.store.mu.Lock()
	server.store.caseSnapshots[snapshot.CaseID] = snapshot
	server.store.knowledgeCandidates[candidate.CandidateID] = candidate
	server.store.mu.Unlock()
	decision, _ := json.Marshal(map[string]string{"action": "approve"})
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-candidates/"+candidate.CandidateID+"/decision", bytes.NewReader(decision)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable validator 503, got %d", recorder.Code)
	}
	stored, _ := server.store.KnowledgeCandidate(candidate.CandidateID)
	if stored.Status != knowledgeCandidateReady {
		t.Fatalf("transport failure changed candidate: %+v", stored)
	}
}

func TestKnowledgeApprovalValidatorHTTP4xxPreservesReadyCandidate(t *testing.T) {
	server := NewServer()
	server.knowledgeValidatorURL = "http://agent.internal"
	server.client = &http.Client{Transport: knowledgeRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"error":"unauthorized"}`))}, nil
	})}
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	server.store.mu.Lock()
	server.store.caseSnapshots[snapshot.CaseID] = snapshot
	server.store.knowledgeCandidates[candidate.CandidateID] = candidate
	server.store.mu.Unlock()
	decision, _ := json.Marshal(map[string]string{"action": "approve"})
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-candidates/"+candidate.CandidateID+"/decision", bytes.NewReader(decision)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 4xx validator response to be unavailable, got %d", recorder.Code)
	}
	stored, _ := server.store.KnowledgeCandidate(candidate.CandidateID)
	if stored.Status != knowledgeCandidateReady {
		t.Fatalf("4xx validator response changed candidate: %+v", stored)
	}
}

func TestKnowledgeFingerprintCoalescesExactContentAndReplacesChangedContent(t *testing.T) {
	firstSnapshot := eligibleKnowledgeSnapshot()
	first := knowledgeCandidateForSnapshot(firstSnapshot)
	exactSnapshot := cloneCaseSnapshot(firstSnapshot)
	exactSnapshot.CaseID, exactSnapshot.IncidentID, exactSnapshot.RunID = "ANL-knowledge-2:hash", "INC-knowledge-2", "ANL-knowledge-2"
	exact := knowledgeCandidateForSnapshot(&exactSnapshot)
	if first.KnowledgeFingerprint == "" || first.CandidateID != exact.CandidateID || first.ContentHash != exact.ContentHash {
		t.Fatalf("identical compiled knowledge must coalesce: first=%+v exact=%+v", first, exact)
	}

	replacementSnapshot := cloneCaseSnapshot(firstSnapshot)
	replacementSnapshot.CaseID, replacementSnapshot.IncidentID, replacementSnapshot.RunID = "ANL-knowledge-3:hash", "INC-knowledge-3", "ANL-knowledge-3"
	trace := replacementSnapshot.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)
	trace["evidence"].([]any)[0].(map[string]any)["predicate"] = "quota_capacity_exhausted"
	replacement := knowledgeCandidateForSnapshot(&replacementSnapshot)
	if replacement.KnowledgeFingerprint != first.KnowledgeFingerprint || replacement.ContentHash == first.ContentHash || replacement.CandidateID == first.CandidateID {
		t.Fatalf("changed content must create a replacement under the same fingerprint: first=%+v replacement=%+v", first, replacement)
	}

	store := NewStore()
	store.caseSnapshots[firstSnapshot.CaseID], store.caseSnapshots[replacementSnapshot.CaseID] = firstSnapshot, &replacementSnapshot
	store.knowledgeCandidates[first.CandidateID], store.knowledgeCandidates[replacement.CandidateID] = first, replacement
	confirmKnowledgeSnapshot(store, firstSnapshot)
	confirmKnowledgeSnapshot(store, &replacementSnapshot)
	if _, _, err := store.ApproveKnowledgeCandidate(first.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("approve first candidate: %v", err)
	}
	if _, _, err := store.ApproveKnowledgeCandidate(replacement.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("approve replacement candidate: %v", err)
	}
	firstAfter, _ := store.KnowledgeCandidate(first.CandidateID)
	if firstAfter.Status != knowledgeCandidateSuperseded {
		t.Fatalf("first candidate was not superseded: %+v", firstAfter)
	}
	packages := store.ListKnowledgePackages(true)
	active, retired := 0, 0
	for _, pkg := range packages {
		if pkg.Status == knowledgePackageActive {
			active++
		}
		if pkg.Status == knowledgePackageRetired {
			retired++
		}
	}
	if active != 1 || retired != 1 {
		t.Fatalf("replacement must atomically leave one active and one retired package: %+v", packages)
	}
}

func TestKnowledgeProbeBindingsUseCanonicalTemplateLocalIDs(t *testing.T) {
	templates := []string{"k8s_troubleshooting:scheduling_capacity:p01", "k8s_troubleshooting:storage_capacity:p01"}
	candidateBindings := candidateProbeBindings("KNC-1", templates)
	activeBindings := activeProbeBindings("KPK-1", templates)
	if candidateBindings[0].ProbeLocalID != "scheduling_capacity:p01" || candidateBindings[1].ProbeLocalID != "storage_capacity:p01" || candidateBindings[0].CandidateProbeID != "KNC-1:scheduling_capacity:p01" || candidateBindings[1].CandidateProbeID != "KNC-1:storage_capacity:p01" {
		t.Fatalf("candidate bindings must preserve canonical unique local IDs: %+v", candidateBindings)
	}
	if activeBindings[0].ActiveProbeID != "KPK-1:v1:scheduling_capacity:p01" || activeBindings[1].ActiveProbeID != "KPK-1:v1:storage_capacity:p01" {
		t.Fatalf("active bindings must preserve canonical unique local IDs: %+v", activeBindings)
	}
}

func TestKnowledgeRuntimeSnapshotIncludesValidatedShadowAndRevisionChanges(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.knowledgeCandidates[candidate.CandidateID] = candidate
	confirmKnowledgeSnapshot(store, snapshot)

	shadowed, shadow, err := store.ShadowKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator", Note: "observe first"})
	if err != nil || shadowed.Status != knowledgeCandidateShadow || shadow.Status != knowledgePackageShadow {
		t.Fatalf("shadow package was not created: candidate=%+v package=%+v err=%v", shadowed, shadow, err)
	}
	shadowSnapshot := store.KnowledgeRuntimeSnapshot()
	if len(shadowSnapshot.Packages) != 1 || shadowSnapshot.Packages[0].Status != knowledgePackageShadow || shadowSnapshot.Packages[0].RuntimeStatus != knowledgePackageShadow {
		t.Fatalf("validated shadow package must enter runtime snapshot with its status: %+v", shadowSnapshot.Packages)
	}
	if packages := store.ListKnowledgePackages(true); len(packages) != 1 || packages[0].Status != knowledgePackageShadow {
		t.Fatalf("shadow package must remain reviewable: %+v", packages)
	}

	active, pkg, err := store.ActivateShadowKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator", Note: "canary accepted"})
	if err != nil || active.Status != knowledgeCandidateActive || pkg.Status != knowledgePackageActive {
		t.Fatalf("shadow package was not activated: candidate=%+v package=%+v err=%v", active, pkg, err)
	}
	activeSnapshot := store.KnowledgeRuntimeSnapshot()
	if len(activeSnapshot.Packages) != 1 || activeSnapshot.Packages[0].PackageID != pkg.PackageID || activeSnapshot.Packages[0].RuntimeStatus != knowledgePackageActive {
		t.Fatalf("activated package must enter runtime snapshot: %+v", activeSnapshot.Packages)
	}
	if shadowSnapshot.Revision == activeSnapshot.Revision {
		t.Fatalf("runtime revision must change when package status changes: shadow=%s active=%s", shadowSnapshot.Revision, activeSnapshot.Revision)
	}

	rejectedStore := NewStore()
	rejectedSnapshot := eligibleKnowledgeSnapshot()
	rejectedCandidate := knowledgeCandidateForSnapshot(rejectedSnapshot)
	rejectedStore.caseSnapshots[rejectedSnapshot.CaseID] = rejectedSnapshot
	rejectedStore.knowledgeCandidates[rejectedCandidate.CandidateID] = rejectedCandidate
	confirmKnowledgeSnapshot(rejectedStore, rejectedSnapshot)
	if _, _, err := rejectedStore.ShadowKnowledgeCandidate(rejectedCandidate.CandidateID, KnowledgeDecisionRequest{}); err != nil {
		t.Fatalf("create rejectable shadow: %v", err)
	}
	rejected, retired, err := rejectedStore.RejectShadowKnowledgeCandidate(rejectedCandidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator", Note: "canary mismatch"})
	if err != nil || rejected.Status != knowledgeCandidateRejected || retired.Status != knowledgePackageRetired || len(rejectedStore.KnowledgeRuntimeSnapshot().Packages) != 0 {
		t.Fatalf("shadow rejection must retire without runtime exposure: candidate=%+v package=%+v err=%v", rejected, retired, err)
	}
}

func TestKnowledgeShadowAndActivateDecisionActions(t *testing.T) {
	server := NewServer()
	server.knowledgeValidatorURL = "http://agent.internal"
	server.client = &http.Client{Transport: knowledgeRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"valid":true}`))}, nil
	})}
	snapshot := eligibleKnowledgeSnapshot()
	candidate := knowledgeCandidateForSnapshot(snapshot)
	server.store.caseSnapshots[snapshot.CaseID] = snapshot
	server.store.knowledgeCandidates[candidate.CandidateID] = candidate
	confirmKnowledgeSnapshot(server.store, snapshot)

	for _, action := range []string{"shadow", "activate"} {
		body, _ := json.Marshal(map[string]string{"action": action, "actor": "operator"})
		recorder := httptest.NewRecorder()
		server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/knowledge-candidates/"+candidate.CandidateID+"/decision", bytes.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s decision failed: %d %s", action, recorder.Code, recorder.Body.String())
		}
	}
	if packages := server.store.KnowledgeRuntimeSnapshot().Packages; len(packages) != 1 || packages[0].Status != knowledgePackageActive {
		t.Fatalf("activate decision did not publish runtime package: %+v", packages)
	}
}

func TestProbeMetricsUseOnlyActiveTraceV3Snapshots(t *testing.T) {
	store := NewStore()
	first := eligibleKnowledgeSnapshot()
	first.ApprovalState = "active"
	second := cloneCaseSnapshot(eligibleKnowledgeSnapshot())
	second.CaseID, second.IncidentID, second.ApprovalState = "ANL-probe:hash", "INC-probe", "active"
	secondTrace := knowledgeTraceForTest(&second)
	secondTrace["probe_executions"].([]any)[0].(map[string]any)["verdict"] = "refutes"
	secondTrace["probe_executions"] = append(secondTrace["probe_executions"].([]any), map[string]any{
		"execution_id": "P-2", "template_id": "k8s_troubleshooting:storage_capacity:p01", "verdict": "unknown",
		"hypothesis_ids": []any{"H-other"}, "evidence_ids": []any{"E-1"},
	})
	revoked := cloneCaseSnapshot(eligibleKnowledgeSnapshot())
	revoked.CaseID, revoked.ApprovalState = "ANL-revoked:hash", "revoked"
	store.caseSnapshots[first.CaseID], store.caseSnapshots[second.CaseID], store.caseSnapshots[revoked.CaseID] = first, &second, &revoked

	metrics := store.ProbeMetrics()
	if metrics.CaseCount != 2 || len(metrics.Metrics) != 2 {
		t.Fatalf("expected only two active trace-v3 cases and two templates: %+v", metrics)
	}
	capacity := metrics.Metrics[0]
	if capacity.TemplateID != "k8s_troubleshooting:scheduling_capacity:p01" || capacity.CaseCount != 2 || capacity.Executions != 2 || capacity.Supports != 1 || capacity.Refutes != 1 || capacity.LinkedEvidenceCount != 4 || capacity.FinalDiagnosisTests != 2 || capacity.FinalDiagnosisSupported != 1 {
		t.Fatalf("unexpected scheduler probe efficiency metric: %+v", capacity)
	}
	storage := metrics.Metrics[1]
	if storage.TemplateID != "k8s_troubleshooting:storage_capacity:p01" || storage.Inconclusive != 1 || storage.FinalDiagnosisTests != 0 {
		t.Fatalf("unexpected storage probe efficiency metric: %+v", storage)
	}

	server := NewServer()
	server.store = store
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/knowledge/probe-metrics", nil))
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"template_id":"k8s_troubleshooting:scheduling_capacity:p01"`)) {
		t.Fatalf("probe metrics endpoint did not expose metrics: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestOperatorEffectiveActionBecomesTheLearnedSymptomRemediation(t *testing.T) {
	// The evaluation form records what actually fixed the incident
	// (EffectiveAction -> case card successful_actions). The compiled symptom
	// must carry it as its resolved_by edge: a learned symptom without actions
	// is a matcher that can never help an operator.
	snapshot := eligibleKnowledgeSnapshot()
	card := snapshot.Snapshot["case_card"].(map[string]any)
	card["successful_actions"] = []any{"raise the project quota", "retried after quota bump"}
	card["failed_actions"] = []any{"retried after quota bump", "restarted the scheduler"}

	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected ready candidate, got %+v", candidate)
	}
	compiled := candidate.Payload["compiled"].(map[string]any)
	symptom := compiled["failure_modes"].([]any)[0].(map[string]any)["symptoms"].([]any)[0].(map[string]any)
	actions := symptom["actions"].([]string)
	if len(actions) != 1 || actions[0] != "raise the project quota" {
		t.Fatalf("expected the confirmed-effective action only (ineffective ones excluded), got %v", actions)
	}

	// No recorded effective action -> empty, never invented.
	bare := cloneCaseSnapshot(snapshot)
	bareCard := bare.Snapshot["case_card"].(map[string]any)
	delete(bareCard, "successful_actions")
	delete(bareCard, "failed_actions")
	bareCandidate := knowledgeCandidateForSnapshot(&bare)
	if bareCandidate == nil {
		t.Fatalf("expected candidate without actions to still compile")
	}
	bareCompiled := bareCandidate.Payload["compiled"].(map[string]any)
	bareSymptom := bareCompiled["failure_modes"].([]any)[0].(map[string]any)["symptoms"].([]any)[0].(map[string]any)
	if got := bareSymptom["actions"].([]string); len(got) != 0 {
		t.Fatalf("expected no fabricated actions, got %v", got)
	}
}

func readyCandidateWithRawAction(t *testing.T, store *Store) *KnowledgeCandidate {
	t.Helper()
	snapshot := eligibleKnowledgeSnapshot()
	card := snapshot.Snapshot["case_card"].(map[string]any)
	card["successful_actions"] = []any{"kubectl get secret nonexistent-secret -n default 를 실행하여 확인하라"}
	store.caseSnapshots[snapshot.CaseID] = snapshot
	confirmKnowledgeSnapshot(store, snapshot)
	candidate := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected ready candidate, got %+v", candidate)
	}
	store.knowledgeCandidates[candidate.CandidateID] = candidate
	return candidate
}

func TestEditKnowledgeCandidateActionsCuratesAndSurvivesActivation(t *testing.T) {
	store := NewStore()
	candidate := readyCandidateWithRawAction(t, store)

	curated := "누락된 <secret-name> Secret을 생성하거나 참조를 수정하라"
	edited, err := store.EditKnowledgeCandidateActions(candidate.CandidateID, []string{" " + curated + " ", ""}, "reviewer")
	if err != nil {
		t.Fatalf("edit failed: %v", err)
	}
	actions, ok := compiledCandidateActions(edited.Payload)
	if !ok || len(actions) != 1 || actions[0] != curated {
		t.Fatalf("edited actions not applied: %v", actions)
	}
	provenance, _ := edited.Payload["provenance"].(map[string]any)
	raw := sanitizeStringSlice(provenance["raw_actions"])
	if len(raw) != 1 || raw[0] != "kubectl get secret nonexistent-secret -n default 를 실행하여 확인하라" {
		t.Fatalf("original operator wording must be preserved: %v", provenance["raw_actions"])
	}
	if stringValue(provenance["actions_curated_by"]) != "reviewer" {
		t.Fatalf("curation actor missing: %v", provenance["actions_curated_by"])
	}

	// The curated wording must survive content-hash revalidation and ship in
	// the published package: identity hashes the snapshot-derived compilation,
	// not the curated overlay.
	_, pkg, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"})
	if err != nil {
		t.Fatalf("approval after edit failed: %v", err)
	}
	pkgActions, ok := compiledCandidateActions(pkg.Payload)
	if !ok || len(pkgActions) != 1 || pkgActions[0] != curated {
		t.Fatalf("package must carry curated actions: %v", pkgActions)
	}
}

func TestRefineKnowledgeCandidateActionsNeverClobbersHumanEdit(t *testing.T) {
	store := NewStore()
	candidate := readyCandidateWithRawAction(t, store)
	original, _ := compiledCandidateActions(candidate.Payload)

	if pending := store.KnowledgeCandidatesPendingActionRefinement(); len(pending) != 1 {
		t.Fatalf("fresh candidate must be pending refinement, got %d", len(pending))
	}

	if _, err := store.EditKnowledgeCandidateActions(candidate.CandidateID, []string{"curated by human"}, "reviewer"); err != nil {
		t.Fatalf("edit failed: %v", err)
	}
	// A stale LLM result computed from the pre-edit text must be discarded.
	if store.RefineKnowledgeCandidateActions(candidate.CandidateID, original, []string{"llm version"}) {
		t.Fatal("stale refinement must not apply over a human edit")
	}
	actions, _ := compiledCandidateActions(store.knowledgeCandidates[candidate.CandidateID].Payload)
	if len(actions) != 1 || actions[0] != "curated by human" {
		t.Fatalf("human edit must win: %v", actions)
	}
	// Curated candidates never re-enter the refinement queue.
	if pending := store.KnowledgeCandidatesPendingActionRefinement(); len(pending) != 0 {
		t.Fatalf("curated candidate must not be pending refinement: %d", len(pending))
	}
}

func TestRefineKnowledgeCandidateActionsAppliesAndStampsMarker(t *testing.T) {
	store := NewStore()
	candidate := readyCandidateWithRawAction(t, store)
	original, _ := compiledCandidateActions(candidate.Payload)

	if !store.RefineKnowledgeCandidateActions(candidate.CandidateID, original, []string{"generalized action"}) {
		t.Fatal("refinement should apply to an uncurated candidate")
	}
	updated := store.knowledgeCandidates[candidate.CandidateID]
	actions, _ := compiledCandidateActions(updated.Payload)
	if len(actions) != 1 || actions[0] != "generalized action" {
		t.Fatalf("refined actions not applied: %v", actions)
	}
	provenance, _ := updated.Payload["provenance"].(map[string]any)
	if got := sanitizeStringSlice(provenance["raw_actions"]); len(got) != 1 || got[0] != original[0] {
		t.Fatalf("raw actions must be preserved: %v", provenance["raw_actions"])
	}
	if pending := store.KnowledgeCandidatesPendingActionRefinement(); len(pending) != 0 {
		t.Fatalf("refined candidate must leave the pending queue: %d", len(pending))
	}
}

// A Ready candidate is a cached projection of the incident's live evaluation.
// Withdrawing the operator confirmation must withdraw the candidate from the
// review queue too; before this test the queue kept advertising Ready while
// approval failed with a misleading "content-hash revalidation" error.
func TestWithdrawnConfirmationWithdrawsReadyCandidate(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	// Compile succeeds only through the operator-confirmed override: demote
	// the trace hypothesis out of selected/supported status.
	trace := snapshot.Snapshot["metadata"].(map[string]any)["reasoning_trace_v3"].(map[string]any)
	trace["hypotheses"].([]any)[0].(map[string]any)["status"] = "rejected"
	store.caseSnapshots[snapshot.CaseID] = snapshot

	review := &EvaluationReview{
		ReviewID: "EVR-1", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "operator", CaseType: "known", ExpectedFamily: snapshot.RootCauseFamily,
		Scores: qualifyingKnowledgeReviewScores(), ResolutionOutcome: "resolved",
		OperatorConfirmed: true,
	}
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, review.Reviewer)] = review
	candidate := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("expected confirmed-override candidate to be ready, got %+v", candidate)
	}
	store.knowledgeCandidates[candidate.CandidateID] = candidate

	// The operator re-saves the evaluation without the confirmation tick.
	review.OperatorConfirmed = false
	store.invalidateKnowledgeForReviewLocked(snapshot.RunID, snapshot.AnalysisHash, time.Now().UTC())
	stored := store.knowledgeCandidates[candidate.CandidateID]
	if stored.Status != knowledgeCandidateValidationFailed || stored.ValidationError != knowledgeReviewInvalidationError {
		t.Fatalf("unconfirmed candidate must be withdrawn from review, got %s (%q)", stored.Status, stored.ValidationError)
	}
	if _, _, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err == nil {
		t.Fatal("approving a withdrawn candidate must fail")
	}

	// Re-confirming restores the same candidate for review.
	review.OperatorConfirmed = true
	store.generateKnowledgeCandidateForReviewedRunLocked(snapshot.RunID, snapshot.AnalysisHash)
	if restored := store.knowledgeCandidates[candidate.CandidateID]; restored.Status != knowledgeCandidateReady {
		t.Fatalf("re-confirmation must restore the candidate, got %s", restored.Status)
	}
	if _, _, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("approval after re-confirmation failed: %v", err)
	}
}

// The operator-confirm path exists for runs the harness underrates: probes
// came back inconclusive, the harness deducted points (e.g. 76), and the UI
// promises "운영자가 확정" with a required confirmation note. The quality floor
// must yield to that confirmation — the reviewer's own >=80% evaluation gate
// already vetted it — while an unconfirmed low-quality run stays rejected.
func TestOperatorConfirmationOverridesHarnessQualityFloor(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	metadata := snapshot.Snapshot["metadata"].(map[string]any)
	metadata["harness"].(map[string]any)["overall_score"] = 76
	store.caseSnapshots[snapshot.CaseID] = snapshot

	review := &EvaluationReview{
		ReviewID: "EVR-1", RunID: snapshot.RunID, AnalysisHash: snapshot.AnalysisHash,
		Reviewer: "operator", CaseType: "known", ExpectedFamily: snapshot.RootCauseFamily,
		Scores: qualifyingKnowledgeReviewScores(), ResolutionOutcome: "resolved",
	}
	store.evaluationReviews[evaluationKey(snapshot.RunID, snapshot.AnalysisHash, review.Reviewer)] = review

	unconfirmed := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if unconfirmed == nil || unconfirmed.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("sub-80 harness without confirmation must fail validation, got %+v", unconfirmed)
	}
	if unconfirmed.ValidationError != "quality score must be at least 80" {
		t.Fatalf("unexpected validation error: %q", unconfirmed.ValidationError)
	}

	review.OperatorConfirmed = true
	review.Notes = "의도적으로 재현한 OOM 테스트: describe로 OOMKilled/exit 137 확인"
	confirmed := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if confirmed == nil || confirmed.Status != knowledgeCandidateReady {
		t.Fatalf("operator confirmation must lift the harness quality floor, got %+v", confirmed)
	}
	if got := stringValue(confirmed.Payload["quality_source"]); got != "operator_confirmed_review" {
		t.Fatalf("quality source must record the override, got %q", got)
	}
	if score, _ := numberToInt(confirmed.Payload["quality_score"]); score != 76 {
		t.Fatalf("payload must keep the honest harness score, got %v", confirmed.Payload["quality_score"])
	}
}
