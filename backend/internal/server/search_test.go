package server

import "testing"

// TestListAlertsPageFilteredSearch verifies the server-side alert search matches
// case-insensitively across the alert title AND label/annotation values (where
// the human-readable description lives), not just the title.
func TestListAlertsPageFilteredSearch(t *testing.T) {
	store := NewStore()
	mkAlert := func(name, namespace, summary string) Alert {
		return Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": name,
				"severity":  "critical",
				"namespace": namespace,
			},
			Annotations: map[string]string{"summary": summary},
			Fingerprint: "fp-" + name,
		}
	}
	_, toolkit := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "g-toolkit"},
		mkAlert("RunaiDaemonSetUnavailableOnNodes", "runai", "runai-container-toolkit DaemonSet unavailable"))
	_, queue := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "g-queue"},
		mkAlert("RunAIQueueBlocked", "runai-vision", "Queue is blocked for projects"))

	// Title match, case-insensitive.
	items, total := store.ListAlertsPageFiltered(0, 0, AlertListFilter{Search: "daemonset"})
	if total != 1 || len(items) != 1 || items[0].AlertID != toolkit.AlertID {
		t.Fatalf("title search failed: total=%d items=%+v", total, items)
	}

	// Annotation (description) match — not present in the title.
	items, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Search: "container-toolkit"})
	if total != 1 || len(items) != 1 || items[0].AlertID != toolkit.AlertID {
		t.Fatalf("annotation search failed: total=%d items=%+v", total, items)
	}

	// Label value match.
	items, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Search: "RUNAI-VISION"})
	if total != 1 || len(items) != 1 || items[0].AlertID != queue.AlertID {
		t.Fatalf("label search failed: total=%d items=%+v", total, items)
	}

	// Blank search returns everything.
	_, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Search: "   "})
	if total != 2 {
		t.Fatalf("blank search should match all, got total=%d", total)
	}

	// No match.
	_, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Search: "nonexistent-xyz"})
	if total != 0 {
		t.Fatalf("expected no matches, got total=%d", total)
	}
}

// TestListIncidentsPageFilteredSearch verifies incident search folds in the
// latest analysis run's RCA content plus member-alert label/annotation values.
func TestListIncidentsPageFilteredSearch(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "g-inc"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunaiDaemonSetUnavailableOnNodes",
			"severity":  "critical",
			"namespace": "runai",
		},
		Annotations: map[string]string{"summary": "toolkit down"},
		Fingerprint: "fp-inc",
	})
	other, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "g-other"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "SomethingElse", "severity": "warning"},
		Annotations: map[string]string{"summary": "unrelated"},
		Fingerprint: "fp-other",
	})

	run := store.CreateAnalysisRun("manual", "incident", incident.IncidentID, incident.IncidentID, alert.AlertID, "Manual", "")
	if _, ok := store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{
		AnalysisSummary: "GPU operator upgrade drained the device plugin pods",
		AnalysisDetail:  "The gpu-operator helm release was mid-upgrade",
		RootCauseFamily: "lifecycle_change",
	}); !ok {
		t.Fatalf("complete analysis run failed")
	}

	// Match by RCA content (family) — not in the incident title.
	items, total := store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{Search: "lifecycle_change"})
	if total != 1 || len(items) != 1 || items[0].IncidentID != incident.IncidentID {
		t.Fatalf("RCA family search failed: total=%d items=%+v", total, items)
	}

	// Match by analysis summary text, case-insensitive.
	items, total = store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{Search: "GPU OPERATOR"})
	if total != 1 || len(items) != 1 || items[0].IncidentID != incident.IncidentID {
		t.Fatalf("RCA summary search failed: total=%d items=%+v", total, items)
	}

	// Match by member-alert annotation value.
	items, total = store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{Search: "toolkit down"})
	if total != 1 || len(items) != 1 || items[0].IncidentID != incident.IncidentID {
		t.Fatalf("member-alert annotation search failed: total=%d items=%+v", total, items)
	}

	// Blank search returns both incidents.
	_, total = store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{Search: ""})
	if total != 2 {
		t.Fatalf("blank search should match all incidents, got total=%d", total)
	}
	_ = other
}
