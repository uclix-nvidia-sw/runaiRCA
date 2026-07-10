package server

import "testing"

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
	})
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
	}); ok || err == nil {
		t.Fatalf("stale hash review should be rejected, ok=%t err=%v", ok, err)
	}
}
