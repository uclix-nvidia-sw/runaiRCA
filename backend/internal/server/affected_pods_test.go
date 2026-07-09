package server

import (
	"reflect"
	"testing"
)

func TestPodNameDropsExporterForWorkloadKindAlert(t *testing.T) {
	// kube-state-metrics alerts name the exporter in the `pod` label while the
	// real subject is a workload-kind label. The exporter must not be seeded as an
	// occurrence pod — the agent discovers the real pods later.
	ksm := Alert{Labels: map[string]string{
		"alertname": "RunaiDaemonSetUnavailableOnNodes",
		"daemonset": "runai-container-toolkit",
		"namespace": "runai",
		"pod":       "prometheus-kube-state-metrics-76f7f4dd55-4lj5q",
		"job":       "kube-state-metrics",
	}}
	if got := podName(ksm); got != "" {
		t.Fatalf("expected exporter pod to be dropped for workload-kind alert, got %q", got)
	}

	// A direct pod alert (no workload-kind label) keeps its real pod.
	direct := Alert{Labels: map[string]string{
		"alertname": "KubePodCrashLooping",
		"namespace": "monitoring",
		"pod":       "loki-read-7d9f8c6b5-x2k4p",
	}}
	if got := podName(direct); got != "loki-read-7d9f8c6b5-x2k4p" {
		t.Fatalf("expected direct pod label to be kept, got %q", got)
	}
}

func TestApplyAnalysisReplacesExporterWithDiscoveredPods(t *testing.T) {
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "fp-ksm"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunaiDaemonSetUnavailableOnNodes",
			"daemonset": "runai-container-toolkit",
			"namespace": "runai",
			"pod":       "prometheus-kube-state-metrics-76f7f4dd55-4lj5q",
			"job":       "kube-state-metrics",
		},
		Fingerprint: "fp-ksm",
	})
	alertID := record.AlertID
	incidentID := incident.IncidentID

	// The exporter must never have been recorded at ingestion.
	if len(record.OccurrencePods) != 0 {
		t.Fatalf("expected no occurrence pods seeded for KSM alert, got %v", record.OccurrencePods)
	}

	run, created := store.CreateAnalysisRunIfAllowed(
		"manual", "alert", alertID, incidentID, alertID, "manual", "")
	if !created {
		t.Fatalf("run should be created")
	}
	discovered := []string{"runai-container-toolkit-vttmr", "runai-container-toolkit-8kd2p"}
	response := AgentAnalysisResponse{
		AnalysisSummary: "GPU Operator toolkit pods are unavailable.",
		AnalysisDetail:  "detail",
		AffectedPods:    discovered,
	}
	store.CompleteAnalysisRun(run.RunID, response)
	if !store.ApplyAnalysisForRun(run.RunID, alertID, response) {
		t.Fatalf("analysis should apply as the newest run")
	}

	got := store.ListAlerts()
	if len(got) != 1 {
		t.Fatalf("expected one alert row, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0].OccurrencePods, discovered) {
		t.Fatalf("expected occurrence pods %v, got %v", discovered, got[0].OccurrencePods)
	}
}

func TestApplyAnalysisWithoutAffectedPodsLeavesOccurrencePods(t *testing.T) {
	// Unscoped investigations return no affected pods; a direct pod alert's
	// ingestion-seeded name must survive.
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "fp-direct"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "KubePodCrashLooping",
			"namespace": "monitoring",
			"pod":       "loki-read-7d9f8c6b5-x2k4p",
		},
		Fingerprint: "fp-direct",
	})
	alertID := record.AlertID
	incidentID := incident.IncidentID
	if len(record.OccurrencePods) != 1 {
		t.Fatalf("expected the real pod to be seeded, got %v", record.OccurrencePods)
	}

	run, _ := store.CreateAnalysisRunIfAllowed(
		"manual", "alert", alertID, incidentID, alertID, "manual", "")
	response := AgentAnalysisResponse{AnalysisSummary: "s", AnalysisDetail: "d"}
	store.CompleteAnalysisRun(run.RunID, response)
	if !store.ApplyAnalysisForRun(run.RunID, alertID, response) {
		t.Fatalf("analysis should apply")
	}
	got := store.ListAlerts()
	if len(got) != 1 || !reflect.DeepEqual(got[0].OccurrencePods, []string{"loki-read-7d9f8c6b5-x2k4p"}) {
		t.Fatalf("expected the seeded pod to survive, got %v", got[0].OccurrencePods)
	}
}
