package server

import (
	"testing"
	"time"
)

func TestCreateAutoAnalysisRunSkipsWithinCooldown(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "auto-cooldown-a"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "AutoCooldownA"}, Fingerprint: "auto-cooldown-a",
	})
	first, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "first", "")
	if !created {
		t.Fatal("expected first auto analysis run to be created")
	}
	if _, ok := store.CompleteAnalysisRun(first.RunID, AgentAnalysisResponse{}); !ok {
		t.Fatal("expected first auto analysis run to complete")
	}

	second, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "second", "")
	if created || second.RunID != first.RunID {
		t.Fatalf("expected auto run within cooldown to be skipped and return %s, got %+v created=%t", first.RunID, second, created)
	}
}

func TestCreateAutoAnalysisRunReusesAfterCooldown(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "auto-cooldown-b"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "AutoCooldownB"}, Fingerprint: "auto-cooldown-b",
	})
	first, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "first", "")
	if !created {
		t.Fatal("expected first auto analysis run to be created")
	}
	if _, ok := store.CompleteAnalysisRun(first.RunID, AgentAnalysisResponse{}); !ok {
		t.Fatal("expected first auto analysis run to complete")
	}
	oldCreatedAt := time.Now().UTC().Add(-8 * time.Hour)
	store.mu.Lock()
	store.analysisRuns[first.RunID].CreatedAt = oldCreatedAt
	store.analysisRuns[first.RunID].UpdatedAt = time.Now().UTC().Add(-7 * time.Hour)
	store.mu.Unlock()

	second, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "second", "")
	if !created {
		t.Fatal("expected auto analysis after cooldown to restart")
	}
	if second.RunID != first.RunID {
		t.Fatalf("expected auto re-analysis to reuse %s, got %s", first.RunID, second.RunID)
	}
	if !second.CreatedAt.After(oldCreatedAt) {
		t.Fatalf("expected reused run CreatedAt to advance beyond %s, got %s", oldCreatedAt, second.CreatedAt)
	}
	if runs := store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("expected auto re-analysis to keep one row, got %d", len(runs))
	}
}

func TestCreateAutoAnalysisRunDoesNotReuseManualRun(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "auto-fresh-run"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "AutoFreshRun"}, Fingerprint: "auto-fresh-run",
	})
	manual, created := store.CreateAnalysisRunIfAllowed("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "manual", "")
	if !created {
		t.Fatal("expected manual analysis run to be created")
	}
	if _, ok := store.CompleteAnalysisRun(manual.RunID, AgentAnalysisResponse{}); !ok {
		t.Fatal("expected manual analysis run to complete")
	}

	auto, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "auto", "")
	if !created || auto.RunID == manual.RunID {
		t.Fatalf("expected fresh auto analysis run distinct from manual run %s, got %+v created=%t", manual.RunID, auto, created)
	}
	storedManual, ok := store.AnalysisRun(manual.RunID)
	if !ok || storedManual.Status != "complete" {
		t.Fatalf("expected completed manual run to remain untouched, got %+v ok=%t", storedManual, ok)
	}
}

func TestCreateAutoAnalysisRunCooldownDisabledPreservesOnceEver(t *testing.T) {
	store := NewStore()
	store.autoReanalyzeCooldown = 0
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "auto-cooldown-c"}, Alert{
		Status: "firing", Labels: map[string]string{"alertname": "AutoCooldownC"}, Fingerprint: "auto-cooldown-c",
	})
	first, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "first", "")
	if !created {
		t.Fatal("expected first auto analysis run to be created")
	}
	if _, ok := store.CompleteAnalysisRun(first.RunID, AgentAnalysisResponse{}); !ok {
		t.Fatal("expected first auto analysis run to complete")
	}

	second, created := store.CreateAnalysisRunIfAllowed("auto", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "second", "")
	if created || second.RunID != first.RunID {
		t.Fatalf("expected disabled cooldown to preserve once-ever behavior for %s, got %+v created=%t", first.RunID, second, created)
	}
}

func TestListIncidentsPageFilteredSortsByLatestActivity(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	store.incidents["INC-A"] = &Incident{
		IncidentID: "INC-A", Status: "firing", FiredAt: now.Add(-2 * time.Hour), LatestActivityAt: now,
	}
	store.incidents["INC-B"] = &Incident{
		IncidentID: "INC-B", Status: "firing", FiredAt: now.Add(-time.Hour),
	}

	items, total := store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{})
	if total != 2 || len(items) != 2 || items[0].IncidentID != "INC-A" || items[1].IncidentID != "INC-B" {
		t.Fatalf("expected active incident to sort ahead by latest activity, total=%d items=%+v", total, items)
	}
}
