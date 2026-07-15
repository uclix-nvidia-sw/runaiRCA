package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func completeScores(value int) map[string]int {
	scores := map[string]int{}
	for _, dimension := range evaluationDimensions {
		scores[dimension] = value
	}
	return scores
}

func TestEvaluationReviewIsBoundToCurrentAnalysisHash(t *testing.T) {
	store := NewStore()
	store.analysisRuns["ANL-1"] = &AnalysisRun{
		RunID: "ANL-1",
		Metadata: map[string]any{
			"analysis_hash": "current",
			"harness":       map[string]any{"status": "pass"},
		},
	}
	review, ok, err := store.UpsertEvaluationReview("ANL-1", EvaluationReviewRequest{
		Author:            "operator-a",
		AnalysisHash:      "current",
		CaseType:          "novel",
		Scores:            completeScores(4),
		HardGates:         map[string]bool{},
		ResolutionOutcome: "unknown",
	}, nil)
	if err != nil || !ok || review.ReviewID == "" {
		t.Fatalf("upsert review = %+v ok=%t err=%v", review, ok, err)
	}
	view, ok := store.EvaluationForRun("ANL-1", "operator-a")
	if !ok || view.MyReview == nil || view.MyReview.ReviewID != review.ReviewID {
		t.Fatalf("current review missing: %+v", view)
	}

	store.analysisRuns["ANL-1"].Metadata["analysis_hash"] = "newer"
	if _, ok, err := store.UpsertEvaluationReview("ANL-1", EvaluationReviewRequest{
		Author: "operator-a", AnalysisHash: "current", CaseType: "novel", Scores: completeScores(4),
	}, nil); ok || err == nil {
		t.Fatalf("stale hash review should be rejected, ok=%t err=%v", ok, err)
	}
}

func TestEvaluationExpectedFamilyUsesAgentCatalog(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/knowledge/families" {
			t.Fatalf("unexpected agent path %s", r.URL.Path)
		}
		writeJSON(w, http.StatusOK, RootCauseFamilyCatalog{Families: []string{"gpu_hardware_error", "k8s_storage_error"}})
	}))
	defer agent.Close()

	server := NewServer()
	server.agentURL = agent.URL
	server.store.analysisRuns["ANL-1"] = &AnalysisRun{RunID: "ANL-1", Metadata: map[string]any{"analysis_hash": "current"}}

	catalog := httptest.NewRecorder()
	server.routes().ServeHTTP(catalog, httptest.NewRequest(http.MethodGet, "/api/v1/knowledge/families", nil))
	if catalog.Code != http.StatusOK || !strings.Contains(catalog.Body.String(), `"gpu_hardware_error"`) {
		t.Fatalf("family catalog endpoint = %d %s", catalog.Code, catalog.Body.String())
	}

	payload := EvaluationReviewRequest{
		Author: "operator-a", AnalysisHash: "current", CaseType: "known",
		ExpectedFamily: "made_up_family", Scores: completeScores(4), ResolutionOutcome: "unknown",
	}
	body, _ := json.Marshal(payload)
	invalid := httptest.NewRecorder()
	server.routes().ServeHTTP(invalid, httptest.NewRequest(http.MethodPut, "/api/v1/analysis-runs/ANL-1/evaluation", bytes.NewReader(body)))
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "must be selected") {
		t.Fatalf("arbitrary expected family = %d %s", invalid.Code, invalid.Body.String())
	}

	payload.ExpectedFamily = "gpu_hardware_error"
	body, _ = json.Marshal(payload)
	valid := httptest.NewRecorder()
	server.routes().ServeHTTP(valid, httptest.NewRequest(http.MethodPut, "/api/v1/analysis-runs/ANL-1/evaluation", bytes.NewReader(body)))
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"expected_family":"gpu_hardware_error"`) {
		t.Fatalf("catalog expected family = %d %s", valid.Code, valid.Body.String())
	}
}

func TestNovelEvaluationCannotPersistExpectedFamily(t *testing.T) {
	store := NewStore()
	store.analysisRuns["ANL-1"] = &AnalysisRun{RunID: "ANL-1", Metadata: map[string]any{"analysis_hash": "current"}}
	review, ok, err := store.UpsertEvaluationReview("ANL-1", EvaluationReviewRequest{
		Author: "operator-a", AnalysisHash: "current", CaseType: "novel",
		ExpectedFamily: "made_up_family", Scores: completeScores(4),
	}, nil)
	if err != nil || !ok || review.ExpectedFamily != "" {
		t.Fatalf("novel review retained expected family: review=%+v ok=%t err=%v", review, ok, err)
	}
}

func TestEvaluationExpectedFamilySemanticsByCaseType(t *testing.T) {
	base := EvaluationReviewRequest{
		Author: "operator-a", AnalysisHash: "current", Scores: completeScores(4),
	}
	for _, caseType := range []string{"known", "compositional"} {
		req := base
		req.CaseType = caseType
		normalized, err := normalizeEvaluationRequest(req, nil)
		if err != nil || normalized.ExpectedFamily != "" {
			t.Fatalf("%s must allow a scoring-only review: req=%+v err=%v", caseType, normalized, err)
		}
	}

	degraded := base
	degraded.CaseType = "tool_degraded"
	normalized, err := normalizeEvaluationRequest(degraded, nil)
	if err != nil || normalized.ExpectedFamily != "" {
		t.Fatalf("tool-degraded review must allow an unknown family: req=%+v err=%v", normalized, err)
	}
	degraded.ExpectedFamily = "gpu_hardware_error"
	normalized, err = normalizeEvaluationRequest(degraded, []string{"gpu_hardware_error"})
	if err != nil || normalized.ExpectedFamily != "gpu_hardware_error" {
		t.Fatalf("tool-degraded review lost its optional operator label: req=%+v err=%v", normalized, err)
	}
}

func TestResolvedReviewGeneratesCandidateOnlyForMatchingFamily(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.analysisRuns[snapshot.RunID] = &AnalysisRun{
		RunID:    snapshot.RunID,
		Metadata: map[string]any{"analysis_hash": snapshot.AnalysisHash},
	}
	req := EvaluationReviewRequest{
		Author: "operator-a", AnalysisHash: snapshot.AnalysisHash, CaseType: "known",
		Scores:            completeScores(5),
		ResolutionOutcome: "resolved",
	}
	allowed := []string{snapshot.RootCauseFamily, "gpu_hardware_error"}
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("scoring-only review upsert failed unexpectedly: ok=%t err=%v", ok, err)
	}
	if len(store.knowledgeCandidates) != 0 {
		t.Fatalf("unlabeled review implicitly confirmed model family: %+v", store.knowledgeCandidates)
	}

	req.ExpectedFamily = "gpu_hardware_error"
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("wrong-family review upsert failed unexpectedly: ok=%t err=%v", ok, err)
	}
	if len(store.knowledgeCandidates) != 0 {
		t.Fatalf("wrong-family review generated knowledge: %+v", store.knowledgeCandidates)
	}

	req.ExpectedFamily = snapshot.RootCauseFamily
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("matching review upsert failed: ok=%t err=%v", ok, err)
	}
	if len(store.knowledgeCandidates) != 1 {
		t.Fatalf("matching resolved review did not generate eligible knowledge: %+v", store.knowledgeCandidates)
	}
}

func TestCorrectedFamilyReviewWithdrawsActiveRuntimeKnowledge(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.analysisRuns[snapshot.RunID] = &AnalysisRun{
		RunID:    snapshot.RunID,
		Metadata: map[string]any{"analysis_hash": snapshot.AnalysisHash},
	}
	req := EvaluationReviewRequest{
		Author:            "operator-a",
		AnalysisHash:      snapshot.AnalysisHash,
		CaseType:          "known",
		ExpectedFamily:    snapshot.RootCauseFamily,
		Scores:            completeScores(5),
		ResolutionOutcome: "resolved",
	}
	allowed := []string{snapshot.RootCauseFamily, "gpu_hardware_error"}
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("matching review upsert failed: ok=%t err=%v", ok, err)
	}
	var candidate *KnowledgeCandidate
	for _, item := range store.knowledgeCandidates {
		candidate = item
	}
	if candidate == nil {
		t.Fatal("matching review did not generate a candidate")
	}
	approved, pkg, err := store.ApproveKnowledgeCandidate(
		candidate.CandidateID,
		KnowledgeDecisionRequest{Actor: "operator-a"},
	)
	if err != nil || approved.Status != knowledgeCandidateActive || pkg.Status != knowledgePackageActive {
		t.Fatalf("candidate activation failed: candidate=%+v package=%+v err=%v", approved, pkg, err)
	}
	if len(store.KnowledgeRuntimeSnapshot().Packages) != 1 {
		t.Fatal("active package was not exposed before the correction")
	}

	req.ExpectedFamily = "gpu_hardware_error"
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("corrected review upsert failed: ok=%t err=%v", ok, err)
	}
	storedCandidate, _ := store.KnowledgeCandidate(candidate.CandidateID)
	storedPackage, _ := store.KnowledgePackage(pkg.PackageID)
	if storedCandidate.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("corrected review left candidate promotable: %+v", storedCandidate)
	}
	if storedPackage.Status != knowledgePackageRetired {
		t.Fatalf("corrected review left package active: %+v", storedPackage)
	}
	if packages := store.KnowledgeRuntimeSnapshot().Packages; len(packages) != 0 {
		t.Fatalf("corrected family remained in runtime knowledge: %+v", packages)
	}

	// Correcting the mutable review back to the analysis family must not
	// silently reactivate previously withdrawn runtime knowledge. It restores
	// only a clean reviewable candidate and leaves the package retired.
	req.ExpectedFamily = snapshot.RootCauseFamily
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("re-confirming review upsert failed: ok=%t err=%v", ok, err)
	}
	storedCandidate, _ = store.KnowledgeCandidate(candidate.CandidateID)
	storedPackage, _ = store.KnowledgePackage(pkg.PackageID)
	if storedCandidate.Status != knowledgeCandidateReady || storedCandidate.PackageID != "" || storedCandidate.ValidationError != "" || storedCandidate.DecidedAt != nil || storedCandidate.DecidedBy != "" || storedCandidate.DecisionNote != "" {
		t.Fatalf("re-confirmed review did not restore a clean reviewable candidate: %+v", storedCandidate)
	}
	if storedPackage.Status != knowledgePackageRetired {
		t.Fatalf("re-confirmed review silently reactivated package: %+v", storedPackage)
	}
	if packages := store.KnowledgeRuntimeSnapshot().Packages; len(packages) != 0 {
		t.Fatalf("re-confirmed review bypassed explicit knowledge approval: %+v", packages)
	}
	revalidatedEvent := false
	for _, event := range store.knowledgeEvents {
		if event != nil && event.CandidateID == candidate.CandidateID && event.Type == "candidate_revalidated" {
			revalidatedEvent = true
			break
		}
	}
	if !revalidatedEvent {
		t.Fatal("re-confirmed review did not record the required revalidation event")
	}

	reapproved, republished, err := store.ApproveKnowledgeCandidate(
		candidate.CandidateID,
		KnowledgeDecisionRequest{Actor: "operator-a", Note: "reviewed corrected label"},
	)
	if err != nil || reapproved.Status != knowledgeCandidateActive || republished.Status != knowledgePackageActive {
		t.Fatalf("revalidated candidate could not be explicitly approved: candidate=%+v package=%+v err=%v", reapproved, republished, err)
	}
	if packages := store.KnowledgeRuntimeSnapshot().Packages; len(packages) != 1 {
		t.Fatalf("explicit reapproval did not restore runtime knowledge: %+v", packages)
	}
}

func TestMatchingReviewDoesNotEraseAgentSemanticValidationFailure(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.analysisRuns[snapshot.RunID] = &AnalysisRun{
		RunID:    snapshot.RunID,
		Metadata: map[string]any{"analysis_hash": snapshot.AnalysisHash},
	}
	req := EvaluationReviewRequest{
		Author:            "operator-a",
		AnalysisHash:      snapshot.AnalysisHash,
		CaseType:          "known",
		ExpectedFamily:    snapshot.RootCauseFamily,
		Scores:            completeScores(5),
		ResolutionOutcome: "resolved",
	}
	allowed := []string{snapshot.RootCauseFamily}
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("matching review upsert failed: ok=%t err=%v", ok, err)
	}
	var candidate *KnowledgeCandidate
	for _, item := range store.knowledgeCandidates {
		candidate = item
	}
	if candidate == nil {
		t.Fatal("matching review did not generate a candidate")
	}
	failed, err := store.FailKnowledgeCandidateValidation(candidate.CandidateID)
	if err != nil || failed.Status != knowledgeCandidateValidationFailed {
		t.Fatalf("semantic validation failure was not recorded: candidate=%+v err=%v", failed, err)
	}
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("matching review resave failed: ok=%t err=%v", ok, err)
	}
	stored, _ := store.KnowledgeCandidate(candidate.CandidateID)
	if stored.Status != knowledgeCandidateValidationFailed || stored.ValidationError != "agent semantic validation rejected compiled package" {
		t.Fatalf("review resave erased independent semantic validation failure: %+v", stored)
	}
}

func TestLowQualityReviewBlocksCandidateReactivationAndRuntimeExposure(t *testing.T) {
	store := NewStore()
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.analysisRuns[snapshot.RunID] = &AnalysisRun{
		RunID:    snapshot.RunID,
		Metadata: map[string]any{"analysis_hash": snapshot.AnalysisHash},
	}
	req := EvaluationReviewRequest{
		Author:            "operator-a",
		AnalysisHash:      snapshot.AnalysisHash,
		CaseType:          "known",
		ExpectedFamily:    snapshot.RootCauseFamily,
		Scores:            completeScores(5),
		ResolutionOutcome: "resolved",
	}
	allowed := []string{snapshot.RootCauseFamily, "gpu_hardware_error"}
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("qualifying review upsert failed: ok=%t err=%v", ok, err)
	}
	var candidate *KnowledgeCandidate
	for _, item := range store.knowledgeCandidates {
		candidate = item
	}
	if candidate == nil {
		t.Fatal("qualifying review did not generate candidate")
	}
	approved, pkg, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator-a"})
	if err != nil || approved.Status != knowledgeCandidateActive || pkg.Status != knowledgePackageActive {
		t.Fatalf("candidate activation failed: candidate=%+v package=%+v err=%v", approved, pkg, err)
	}

	// First withdraw via a family correction, then restore the family label with
	// a below-80 review. The label remains stored for evaluation, but the
	// candidate must not be reactivated.
	req.ExpectedFamily = "gpu_hardware_error"
	if _, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed); err != nil || !ok {
		t.Fatalf("family correction failed: ok=%t err=%v", ok, err)
	}
	req.ExpectedFamily = snapshot.RootCauseFamily
	req.Scores = completeScores(4)
	req.Scores["evidence_grounding"] = 3 // 27/35, below the 80% floor
	review, ok, err := store.UpsertEvaluationReview(snapshot.RunID, req, allowed)
	if err != nil || !ok || review.ExpectedFamily != snapshot.RootCauseFamily {
		t.Fatalf("low-quality labeled review was not retained: review=%+v ok=%t err=%v", review, ok, err)
	}
	storedCandidate, _ := store.KnowledgeCandidate(candidate.CandidateID)
	storedPackage, _ := store.KnowledgePackage(pkg.PackageID)
	if storedCandidate.Status != knowledgeCandidateValidationFailed || storedPackage.Status != knowledgePackageRetired {
		t.Fatalf("low-quality review reactivated withdrawn knowledge: candidate=%+v package=%+v", storedCandidate, storedPackage)
	}

	// Runtime listing independently revalidates the review gates. Simulate stale
	// persisted active state to ensure a missed transition still cannot leak it.
	store.knowledgeCandidates[candidate.CandidateID].Status = knowledgeCandidateActive
	store.knowledgePackages[pkg.PackageID].Status = knowledgePackageActive
	if packages := store.KnowledgeRuntimeSnapshot().Packages; len(packages) != 0 {
		t.Fatalf("runtime exposed package despite current low-quality review: %+v", packages)
	}
}
