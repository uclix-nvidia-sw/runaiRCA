package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCaseMechanismUsesExactSelectedTraceV3Hypothesis(t *testing.T) {
	metadata := map[string]any{
		"reasoning_trace_v3": map[string]any{
			"schema_version":         3,
			"selected_hypothesis_id": "H-exact",
			"hypotheses": []any{
				map[string]any{"hypothesis_id": "H-other", "mechanism": "wrong"},
				map[string]any{
					"hypothesis_id":         "H-exact",
					"mechanism":             "CSI attach race",
					"mechanism_fingerprint": "a13f9c2d",
				},
			},
		},
		"reasoning_trace_v2": map[string]any{
			"mechanism": "legacy mechanism",
		},
	}

	mechanism, fingerprint := caseMechanismFromMetadata(metadata)
	if mechanism != "CSI attach race" || fingerprint != "a13f9c2d" {
		t.Fatalf("expected exact v3 selection, got mechanism=%q fingerprint=%q", mechanism, fingerprint)
	}

	metadata["reasoning_trace_v3"].(map[string]any)["selected_hypothesis_id"] = "H-missing"
	mechanism, fingerprint = caseMechanismFromMetadata(metadata)
	if mechanism != "" || fingerprint != "" {
		t.Fatalf("v2 must not be a mechanism fallback, got mechanism=%q fingerprint=%q", mechanism, fingerprint)
	}
}

func TestCaseMechanismFallsBackToHistoricalOntologyReasoning(t *testing.T) {
	mechanism, fingerprint := caseMechanismFromMetadata(map[string]any{
		"reasoning_trace_v3": map[string]any{
			"schema_version":         3,
			"selected_hypothesis_id": "H-duplicate",
			"hypotheses": []any{
				map[string]any{"hypothesis_id": "H-duplicate", "mechanism": "one"},
				map[string]any{"hypothesis_id": "H-duplicate", "mechanism": "two"},
			},
		},
		"ontology_reasoning": map[string]any{
			"mechanism":             "historical mechanism",
			"mechanism_fingerprint": "historical-fingerprint",
		},
	})
	if mechanism != "historical mechanism" || fingerprint != "historical-fingerprint" {
		t.Fatalf("expected ontology fallback, got mechanism=%q fingerprint=%q", mechanism, fingerprint)
	}
}

func TestApprovalCreatesImmutableHashBoundCaseSnapshot(t *testing.T) {
	server := NewServer()
	incident, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "case-snapshot"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
		},
		Annotations: map[string]string{"summary": "CSI attach race"},
		Fingerprint: "case-snapshot-fingerprint",
	})
	now := time.Now().UTC()
	run := &AnalysisRun{
		RunID:           "ANL-case-snapshot",
		Status:          "complete",
		TargetType:      "incident",
		TargetID:        incident.IncidentID,
		IncidentID:      incident.IncidentID,
		AlertID:         alert.AlertID,
		AnalysisSummary: "CSI attach race caused FailedMount.",
		AnalysisDetail:  "Original immutable detail.",
		RootCauseFamily: "novel_csi_attach_race_a13f9c2d",
		Artifacts:       []Artifact{{EvidenceID: "E1", Source: "kubernetes", Summary: "FailedMount"}},
		Metadata: map[string]any{
			"analysis_hash": "hash-original",
			"harness": map[string]any{
				"overall_score": 92,
				"claims": []any{map[string]any{
					"kind":                "root_cause",
					"supporting_evidence": []any{"E1"},
				}},
			},
			"ontology_reasoning": map[string]any{
				"mechanism":             "CSI attach race",
				"mechanism_fingerprint": "a13f9c2d",
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	server.store.mu.Lock()
	server.store.analysisRuns[run.RunID] = run
	server.store.mu.Unlock()

	approve := httptest.NewRecorder()
	server.routes().ServeHTTP(
		approve,
		httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/resolve", nil),
	)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approve.Code, approve.Body.String())
	}
	snapshot, ok := server.store.ApprovedCaseSnapshot(incident.IncidentID)
	if !ok {
		t.Fatal("expected active approved snapshot")
	}
	if snapshot.CaseID != run.RunID+":hash-original" || snapshot.RootCauseFamily != run.RootCauseFamily {
		t.Fatalf("unexpected case snapshot: %+v", snapshot)
	}
	if snapshot.Mechanism != "CSI attach race" || snapshot.MechanismFingerprint != "a13f9c2d" {
		t.Fatalf("novel mechanism was not captured: %+v", snapshot)
	}
	card, ok := snapshot.Snapshot["case_card"].(map[string]any)
	if !ok || card["quality_score"] != 92 || card["approval_analysis_hash"] != "hash-original" {
		t.Fatalf("case card must preserve grounded approval data: %#v", snapshot.Snapshot["case_card"])
	}
	support, ok := card["supporting_evidence_by_source"].(map[string]any)
	items, itemsOK := support["kubernetes"].([]any)
	if !ok || !itemsOK || len(items) != 1 {
		t.Fatalf("case card support must come from linked artifacts: %#v", card["supporting_evidence_by_source"])
	}
	first, firstOK := items[0].(map[string]any)
	if !firstOK || first["evidence_id"] != "E1" {
		t.Fatalf("case card support must come from linked artifacts: %#v", card["supporting_evidence_by_source"])
	}

	// A later re-analysis must not rewrite the historical approved payload.
	server.store.mu.Lock()
	run.AnalysisSummary = "Different re-analysis summary"
	run.Metadata["analysis_hash"] = "hash-new"
	server.store.mu.Unlock()
	stillApproved, ok := server.store.ApprovedCaseSnapshot(incident.IncidentID)
	if !ok || stillApproved.AnalysisHash != "hash-original" {
		t.Fatalf("approval should remain bound to original hash: %+v", stillApproved)
	}
	if got := stillApproved.Snapshot["analysis_summary"]; got != "CSI attach race caused FailedMount." {
		t.Fatalf("snapshot payload was mutated by re-analysis: %q", got)
	}

	revoke := httptest.NewRecorder()
	server.routes().ServeHTTP(
		revoke,
		httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/resolve", nil),
	)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if _, ok := server.store.ApprovedCaseSnapshot(incident.IncidentID); ok {
		t.Fatal("revoked snapshot must not be returned as an approved prior")
	}
}
