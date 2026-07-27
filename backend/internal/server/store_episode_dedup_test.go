package server

import (
	"testing"
	"time"
)

// The live bug behind the 2026-07-26 twin incidents: LatestActivityAt advances
// whenever the operator reanalyzes an incident, and the flap-window check
// compared it against the resent alert's ORIGINAL StartsAt. Any still-firing
// alert re-sent by Alertmanager after a reanalysis then minted an identical
// duplicate incident.

func flapAlert(startsAt string) Alert {
	return Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "KubeContainerWaiting",
			"severity":  "warning",
			"namespace": "default",
			"workload":  "secret",
		},
		Annotations: map[string]string{"summary": "Pod container waiting"},
		Fingerprint: "fp-episode",
		StartsAt:    startsAt,
	}
}

func TestSameEpisodeResendReusesIncidentDespiteActivityDrift(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "episode"}
	incident, _ := store.UpsertAlert(webhook, flapAlert("2026-07-24T05:58:37Z"))

	// Reanalysis two days later bumps LatestActivityAt far past the flap window.
	store.mu.Lock()
	store.incidents[incident.IncidentID].LatestActivityAt = time.Date(2026, 7, 26, 4, 0, 0, 0, time.UTC)
	store.mu.Unlock()

	resend := store.UpsertAlertResult(webhook, flapAlert("2026-07-24T05:58:37Z"))
	if resend.NewIncident || resend.Incident.IncidentID != incident.IncidentID {
		t.Fatalf("same-episode resend must reuse its incident, got %+v", resend)
	}
	if _, total := store.ListIncidentsPage(0, 0); total != 1 {
		t.Fatalf("expected exactly one incident, got %d", total)
	}

	// The resolve notification of that episode closes the same incident.
	resolved := flapAlert("2026-07-24T05:58:37Z")
	resolved.Status = "resolved"
	resolved.EndsAt = "2026-07-26T08:00:00Z"
	done := store.UpsertAlertResult(webhook, resolved)
	if done.NewIncident || done.Incident.IncidentID != incident.IncidentID || done.Incident.Status != "resolved" {
		t.Fatalf("episode resolve must close the same incident, got %+v", done)
	}
}

func TestNewEpisodeOutsideFlapWindowStillCreatesNewIncident(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "episode"}
	incident, _ := store.UpsertAlert(webhook, flapAlert("2026-07-24T05:58:37Z"))

	next := store.UpsertAlertResult(webhook, flapAlert("2026-07-24T09:00:00Z"))
	if !next.NewIncident || next.Incident.IncidentID == incident.IncidentID {
		t.Fatalf("a firing episode outside the flap window should create a new incident, got %+v", next)
	}
}

func TestHardDeletedEpisodeResendIsDropped(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "episode"}
	incident, _ := store.UpsertAlert(webhook, flapAlert("2026-07-24T05:58:37Z"))
	if !store.HardDeleteIncident(incident.IncidentID) {
		t.Fatalf("hard delete failed")
	}

	// Alertmanager keeps re-sending the still-firing alert with its original
	// StartsAt; the purged episode must stay gone.
	for i := 0; i < 3; i++ {
		if result := store.UpsertAlertResult(webhook, flapAlert("2026-07-24T05:58:37Z")); !result.Dropped {
			t.Fatalf("resend %d of a purged episode must be dropped, got %+v", i, result)
		}
	}
	if _, total := store.ListIncidentsPage(0, 0); total != 0 {
		t.Fatalf("purged episode resurrected, total=%d", total)
	}

	// A NEW episode is a new occurrence: tombstone spent, incident created.
	fresh := store.UpsertAlertResult(webhook, flapAlert("2026-07-26T10:00:00Z"))
	if !fresh.NewIncident {
		t.Fatalf("new episode after purge should create an incident, got %+v", fresh)
	}
	store.mu.RLock()
	_, tombstoned := store.deletedEpisodes["fp-episode"]
	store.mu.RUnlock()
	if tombstoned {
		t.Fatalf("newer episode should spend the tombstone")
	}
}

func TestHardDeletedEpisodeResolveClearsTombstone(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "episode"}
	incident, _ := store.UpsertAlert(webhook, flapAlert("2026-07-24T05:58:37Z"))
	if !store.HardDeleteIncident(incident.IncidentID) {
		t.Fatalf("hard delete failed")
	}

	resolved := flapAlert("2026-07-24T05:58:37Z")
	resolved.Status = "resolved"
	if result := store.UpsertAlertResult(webhook, resolved); !result.Dropped {
		t.Fatalf("resolve of a purged episode must be dropped, got %+v", result)
	}
	store.mu.RLock()
	_, tombstoned := store.deletedEpisodes["fp-episode"]
	store.mu.RUnlock()
	if tombstoned {
		t.Fatalf("resolve should clear the tombstone — the episode is over")
	}
	if _, total := store.ListIncidentsPage(0, 0); total != 0 {
		t.Fatalf("resolve of a purged episode must not create an incident, total=%d", total)
	}
}

func TestTrashPurgePrunesExpiredTombstones(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	store.mu.Lock()
	store.deletedEpisodes["fp-old"] = deletedEpisode{FiredAt: now, DeletedAt: now.Add(-deletedEpisodeRetention - time.Hour)}
	store.deletedEpisodes["fp-recent"] = deletedEpisode{FiredAt: now, DeletedAt: now.Add(-time.Hour)}
	store.mu.Unlock()

	store.PurgeExpiredTrash(30*24*time.Hour, now)

	store.mu.RLock()
	defer store.mu.RUnlock()
	if _, ok := store.deletedEpisodes["fp-old"]; ok {
		t.Fatalf("expired tombstone should be pruned")
	}
	if _, ok := store.deletedEpisodes["fp-recent"]; !ok {
		t.Fatalf("recent tombstone should be retained")
	}
}
