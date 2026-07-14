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
