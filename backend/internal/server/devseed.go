package server

import "time"

// SeedDevFixtures injects one approved, analyzed-but-not-yet-promotable incident
// so the knowledge-review UX (ingestion preview, failed-candidate identity,
// operator-confirm override) can be exercised end-to-end without the LLM agent.
//
// ponytail: dev-only fixture, never called in production. Run() invokes it only
// when RCA_DEV_SEED=1. The seeded analysis has a family-matching hypothesis that
// never reached "supported" (probes stayed inconclusive), so it previews as
// validation_failed until an operator confirms it.
func (s *Store) SeedDevFixtures() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Date(2026, 7, 16, 9, 19, 0, 0, time.UTC)
	approved := now.Add(10 * time.Minute)
	const (
		incidentID = "INC-DEV-000001"
		runID      = "ANL-DEV-000001"
		hash       = "devhash01"
		family     = "workload_startup_error"
	)
	caseID := runID + ":" + hash

	harness := map[string]any{
		"status": "pass", "overall_score": 85, "repair_attempts": 1,
		"hard_gates": map[string]any{"unsupported_high_confidence": false, "invalid_evidence_links": false},
	}
	traceV3 := map[string]any{
		"schema_version":         3,
		"selected_hypothesis_id": "H-1",
		"hypotheses": []any{map[string]any{
			"hypothesis_id": "H-1", "family": family, "mechanism": "container OOM on startup",
			"mechanism_fingerprint": "dev-oom-startup",
			"status":                "uncertain", "confidence": 0.45,
			"evidence_for": []any{"E-1", "E-2"}, "evidence_against": []any{},
		}},
		"evidence": []any{
			map[string]any{"evidence_id": "E-1", "observation_window": map[string]any{"start": "2026-07-16T09:12:00Z", "end": "2026-07-16T09:17:00Z"}, "entity": "pod/memory-stress", "source": "kubernetes", "source_group": "workload", "predicate": "container_oomkilled", "polarity": "present", "coverage": "scoped", "quality": "high"},
			map[string]any{"evidence_id": "E-2", "observation_window": map[string]any{"start": "2026-07-16T09:13:00Z", "end": "2026-07-16T09:18:00Z"}, "entity": "pod/memory-stress", "source": "prometheus", "source_group": "metrics", "predicate": "container_memory_at_limit", "polarity": "present", "coverage": "scoped", "quality": "high"},
		},
		"probe_executions": []any{map[string]any{"execution_id": "P-1", "template_id": "k8s_troubleshooting:pod_crashing:p01", "tool": "kubernetes", "verdict": "inconclusive", "executed_at": "2026-07-16T09:16:00Z", "hypothesis_ids": []any{"H-1"}, "evidence_ids": []any{"E-1", "E-2"}}},
	}

	s.incidents[incidentID] = &Incident{
		IncidentID: incidentID, CorrelationKey: "KubePodCrashLooping/memory-stress",
		Title: "Pod is crash looping.", Severity: "warning", Status: "resolved",
		FiredAt: now, UserApprovedAt: &approved, AlertCount: 0, LatestActivityAt: approved,
	}
	s.analysisRuns[runID] = &AnalysisRun{
		RunID: runID, Source: "webhook", Status: "complete", TargetType: "incident", TargetID: incidentID,
		IncidentID: incidentID, Title: "Pod is crash looping.",
		AnalysisSummary: "memory-stress pod OOMKilled on startup; workload-local fault.",
		AnalysisDetail:  "The container exceeded its memory limit during startup and was OOMKilled repeatedly; probes could not confirm within the window.",
		AnalysisQuality: "high", RootCauseFamily: family,
		Capabilities:     map[string]string{"kubernetes": "ok"},
		Metadata:         map[string]any{"analysis_hash": hash, "harness": harness, "reasoning_trace_v3": traceV3},
		FirstCompletedAt: &approved, CreatedAt: now, UpdatedAt: approved,
	}
	s.caseSnapshots[caseID] = &CaseSnapshot{
		CaseID: caseID, IncidentID: incidentID, RunID: runID, AnalysisHash: hash,
		ApprovalState: "active", RootCauseFamily: family, Mechanism: "container OOM on startup",
		ApprovedAt: approved,
		Snapshot: map[string]any{
			"analysis_summary": "memory-stress pod OOMKilled on startup; workload-local fault.",
			"analysis_detail":  "The container exceeded its memory limit during startup and was OOMKilled repeatedly.",
			"case_card":        map[string]any{"family": family, "operator_resolution_outcomes": []any{"resolved"}},
			"metadata":         map[string]any{"harness": harness, "reasoning_trace_v3": traceV3},
		},
	}
	s.activeCaseByIncident[incidentID] = caseID
}
