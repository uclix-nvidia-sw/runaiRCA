package server

import (
	"strings"
	"testing"
)

func TestMetadataFromAgentContextFiltersAnswerMode(t *testing.T) {
	harness := map[string]any{"verdict": "pass"}
	got := metadataFromAgentContext(map[string]any{
		"answer_mode": "knowledge_only",
		"harness":     harness,
	})
	if got["answer_mode"] != "knowledge_only" {
		t.Fatalf("answer_mode metadata missing: %+v", got)
	}
	if gotHarness, ok := got["harness"].(map[string]any); !ok || gotHarness["verdict"] != "pass" {
		t.Fatalf("existing allowlisted metadata changed: %+v", got)
	}

	for name, value := range map[string]any{
		"non-string": 1,
		"empty":      "",
		"oversized":  strings.Repeat("x", 65),
	} {
		t.Run(name, func(t *testing.T) {
			got := metadataFromAgentContext(map[string]any{"answer_mode": value, "harness": harness})
			if _, ok := got["answer_mode"]; ok {
				t.Fatalf("invalid answer_mode was retained: %+v", got)
			}
			if _, ok := got["harness"]; !ok {
				t.Fatalf("existing allowlisted metadata was dropped: %+v", got)
			}
		})
	}
}

func TestApprovedIncidentMemorySkipsKnowledgeOnlyRun(t *testing.T) {
	for _, test := range []struct {
		name       string
		metadata   map[string]any
		wantMemory bool
	}{
		{name: "knowledge only", metadata: map[string]any{"answer_mode": "knowledge_only"}},
		{name: "normal", wantMemory: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewStore()
			incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: test.name}, Alert{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
				Annotations: map[string]string{"summary": "Queue blocked"},
				Fingerprint: "fp-" + test.name,
			})
			store.mu.Lock()
			store.analysisRuns["RUN-"+test.name] = &AnalysisRun{
				RunID: "RUN-" + test.name, Status: "complete", IncidentID: incident.IncidentID, AlertID: alert.AlertID,
				AnalysisSummary: "Quota exhaustion RCA.", AnalysisDetail: "GPU quota is exhausted.", Metadata: test.metadata,
			}
			store.mu.Unlock()

			approveIncidentForTest(t, store, incident.IncidentID)
			_, gotMemory := store.memories[incident.IncidentID]
			if gotMemory != test.wantMemory {
				t.Fatalf("memory presence = %t, want %t: %+v", gotMemory, test.wantMemory, store.memories)
			}
		})
	}
}

func TestKnowledgeOnlyAnswerCannotBePromoted(t *testing.T) {
	snapshot := eligibleKnowledgeSnapshot()
	if candidate := knowledgeCandidateForSnapshot(snapshot); candidate == nil || candidate.Status != knowledgeCandidateReady {
		t.Fatalf("baseline snapshot should pass promotion gates: %+v", candidate)
	}
	snapshot.Snapshot["metadata"].(map[string]any)["answer_mode"] = "knowledge_only"
	candidate := knowledgeCandidateForSnapshot(snapshot)
	if candidate == nil || candidate.Status != knowledgeCandidateValidationFailed || candidate.ValidationError != "knowledge-only answers cannot be promoted" {
		t.Fatalf("knowledge-only veto was not surfaced: %+v", candidate)
	}
}
