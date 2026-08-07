package server

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brilly-bohyun/runai-rca/backend/internal/server/testsupport"
)

// dbLatency is a conservative round-trip to a Postgres in the same cluster.
const dbLatency = 2 * time.Millisecond

// The webhook's two statements get DIFFERENT durations so the three possible
// shapes are distinguishable from the outside: sequential costs both, correct
// concurrency costs the slower one, and forgetting to wait costs the faster.
const (
	incidentWriteLatency = 20 * time.Millisecond
	alertWriteLatency    = 60 * time.Millisecond
)

func storeWithSlowPostgres(t testing.TB) (*Store, *testsupport.PostgresState) {
	t.Helper()
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	t.Cleanup(func() { _ = store.db.Close() })
	state.SetExecLatency(dbLatency)
	return store, state
}

// TestWebhookWriteOverlapsItsTwoRoundTripsUnderTheStoreLock pins the three facts
// that make the alert webhook — the hottest write path — both fast and safe:
// both rows are written, the two statements overlap, and the caller still waits
// for both before releasing the store lock.
//
// It does NOT assert a reader-latency bound. An earlier version moved these
// writes off the store lock entirely and asserted readers no longer waited; that
// optimisation was withdrawn (see UpsertAlertResult) because a clone committed
// after a concurrent trash/approve silently reverted it in Postgres. Overlapping
// them WITHOUT releasing the lock keeps that ordering guarantee and still halves
// the hold time, which is what the bounds below encode.
func TestWebhookWriteOverlapsItsTwoRoundTripsUnderTheStoreLock(t *testing.T) {
	store, state := storeWithSlowPostgres(t)
	state.SetExecLatencyFor("INSERT INTO incidents", incidentWriteLatency)
	state.SetExecLatencyFor("INSERT INTO alerts", alertWriteLatency)

	var worst atomic.Int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	stop := make(chan struct{})
	record := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		if d.Nanoseconds() > worst.Load() {
			worst.Store(d.Nanoseconds())
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				start := time.Now()
				store.ListIncidentsPage(20, 0)
				record(time.Since(start))
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)

	start := time.Now()
	store.UpsertAlertResult(AlertmanagerWebhook{}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "KubePodNotReady", "namespace": "runai", "pod": "p1"},
		Annotations: map[string]string{"summary": "pod not ready"},
		StartsAt:    time.Now().UTC().Format(time.RFC3339),
	})
	elapsed := time.Since(start)
	close(stop)
	wg.Wait()

	// The write happened at all. Without these the test passes with both
	// persists deleted, which is how the withdrawn version stayed green.
	if !state.Executed("INSERT INTO incidents") || !state.Executed("INSERT INTO alerts") {
		t.Fatalf("the webhook did not write both rows: %v", state.Execs())
	}
	// Slower than the slower statement: the caller waited for BOTH. Dropping the
	// wg.Wait() lands here at ~20ms, with the alert row committed after the lock
	// was already released — the exact ordering hole the withdrawn version had.
	if elapsed < alertWriteLatency-incidentWriteLatency/2 {
		t.Fatalf("write took %v, less than its %v alert round trip — it did not wait for both statements",
			elapsed, alertWriteLatency)
	}
	// Faster than both added up: they actually overlapped. Making them sequential
	// again lands at ~80ms.
	if elapsed >= incidentWriteLatency+alertWriteLatency {
		t.Fatalf("write took %v, as much as %v + %v — the two statements ran sequentially",
			elapsed, incidentWriteLatency, alertWriteLatency)
	}
	t.Logf("webhook write %v (max(%v, %v), not the sum) | worst concurrent read %v | GOMAXPROCS=%d",
		elapsed.Round(time.Millisecond), incidentWriteLatency, alertWriteLatency,
		time.Duration(worst.Load()).Round(100*time.Microsecond), runtime.GOMAXPROCS(0))
}

// TestConcurrentWriterCannotLandInsideAWebhooksPersistWindow is the test the
// withdrawn optimisation needed and did not have.
//
// UpsertAlertResult writes its two rows with s.mu released. The hazard that
// forced the first revert is a SECOND writer mutating and persisting the same
// incident inside that window: its row lands first, the webhook's older row
// lands on top, and deleted_at / archived_at / user_approved_at is silently
// reverted in Postgres with nothing wrong in memory.
//
// Every writer of the incident row is covered, not just the soft delete that
// was named in the revert. incidentResolve is here because it is a Server
// method that reaches past the Store and takes the store lock itself — it was
// the one writer with no writeMu at all, and the invariant test's first version
// could not see it.
//
// The latencies are deliberately lopsided. With both statements equally slow
// the second writer cannot interleave no matter what the locking does — it is
// issued later and therefore finishes later — and the test passes with writeMu
// removed, which is exactly how the first version of this was vacuous. A short
// incidents write and a long alerts write open a real window to fall into.
func TestConcurrentWriterCannotLandInsideAWebhooksPersistWindow(t *testing.T) {
	firing := Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "KubePodNotReady", "namespace": "runai", "pod": "p1"},
		Annotations: map[string]string{"summary": "pod not ready"},
		StartsAt:    time.Now().UTC().Format(time.RFC3339),
	}

	// Stashed by the ApplyAnalysisForRun case: creating and completing the run
	// are writers themselves, so doing them inside act would take writeMu, wait
	// out the whole webhook, and leave nothing for act's own writeMu to guard.
	var preparedRun string

	cases := []struct {
		name string
		// prepare runs before the webhook starts; act is the competing writer.
		prepare func(t *testing.T, store *Store, incidentID, alertID string)
		act     func(t *testing.T, store *Store, incidentID, alertID string)
	}{
		{
			name: "SoftDeleteIncident",
			act: func(t *testing.T, store *Store, incidentID, _ string) {
				if _, ok := store.SoftDeleteIncident(incidentID); !ok {
					t.Error("soft delete did not apply")
				}
			},
		},
		{
			name: "ArchiveIncident",
			act: func(t *testing.T, store *Store, incidentID, _ string) {
				if _, ok := store.ArchiveIncident(incidentID, true); !ok {
					t.Error("archive did not apply")
				}
			},
		},
		{
			name: "RestoreIncident",
			prepare: func(t *testing.T, store *Store, incidentID, _ string) {
				if _, ok := store.ArchiveIncident(incidentID, true); !ok {
					t.Fatal("could not archive before restoring")
				}
			},
			act: func(t *testing.T, store *Store, incidentID, _ string) {
				if _, ok := store.RestoreIncident(incidentID); !ok {
					t.Error("restore did not apply")
				}
			},
		},
		{
			name: "ApplyAnalysisForRun",
			prepare: func(t *testing.T, store *Store, incidentID, alertID string) {
				run := store.CreateAnalysisRun("manual", "alert", alertID, incidentID, alertID, "x", "")
				store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{AnalysisSummary: "s", AnalysisDetail: "d"})
				preparedRun = run.RunID
			},
			act: func(t *testing.T, store *Store, _, alertID string) {
				response := AgentAnalysisResponse{AnalysisSummary: "s", AnalysisDetail: "d"}
				if !store.ApplyAnalysisForRun(preparedRun, alertID, response) {
					t.Error("apply did not land")
				}
			},
		},
		{
			name: "incidentResolve",
			act: func(t *testing.T, store *Store, incidentID, _ string) {
				server := &Server{store: store, hub: NewHub()}
				recorder := httptest.NewRecorder()
				server.incidentResolve(recorder, httptest.NewRequest(http.MethodPost, "/", nil), incidentID)
				if recorder.Code != http.StatusOK && recorder.Code != http.StatusNoContent {
					t.Errorf("resolve returned %d: %s", recorder.Code, recorder.Body.String())
				}
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, state := storeWithSlowPostgres(t)
			seeded := store.UpsertAlertResult(AlertmanagerWebhook{}, firing)
			incidentID, alertID := seeded.Incident.IncidentID, seeded.Alert.AlertID
			if testCase.prepare != nil {
				testCase.prepare(t, store, incidentID, alertID)
			}
			// Set the latencies only now: the setup above would pay them too.
			state.SetExecLatencyFor("INSERT INTO incidents", 50*time.Millisecond)
			state.SetExecLatencyFor("INSERT INTO alerts", 400*time.Millisecond)
			before := len(state.ExecTimings())

			done := make(chan struct{})
			go func() {
				defer close(done)
				store.UpsertAlertResult(AlertmanagerWebhook{}, firing)
			}()

			// Past the webhook's incidents write (50ms), well inside its alerts
			// write (400ms) — the gap the competing writer would fall into.
			time.Sleep(120 * time.Millisecond)
			testCase.act(t, store, incidentID, alertID)
			<-done

			// Required order: the webhook's incidents row, the webhook's alerts
			// row, then anything the competing writer wrote. If its write lands
			// second, the webhook is still holding a pre-change copy of the
			// incident and nothing rewrites the column after that.
			var incidents, alerts []int
			for i, statement := range state.Execs()[before:] {
				switch {
				case strings.Contains(statement, "INSERT INTO incidents"):
					incidents = append(incidents, i)
				case strings.Contains(statement, "INSERT INTO alerts"):
					alerts = append(alerts, i)
				}
			}
			// The webhook issues exactly two statements, and they are the first
			// two to start. Everything after them is the competing writer's, and
			// none of it may OVERLAP the webhook's pair: writeMu is what makes
			// its first statement start only once both of the webhook's have
			// come back.
			//
			// Intervals, not positions. ApplyAnalysisForRun's first write is the
			// same slow alerts insert the webhook is running, so it can never
			// finish earlier no matter what the locking does, and an
			// order-based assertion passes on it with writeMu removed.
			timings := state.ExecTimings()[before:]
			if len(timings) < 3 {
				t.Fatalf("expected the webhook's two writes plus the competing one, got %d", len(timings))
			}
			webhookDone := timings[0].End
			if timings[1].End.After(webhookDone) {
				webhookDone = timings[1].End
			}
			if timings[2].Start.Before(webhookDone) {
				t.Fatalf("%s started a write %v BEFORE the webhook's persists finished — it is inside the "+
					"window, so the webhook is holding a pre-change copy and its older row reverts the "+
					"column in Postgres", testCase.name, webhookDone.Sub(timings[2].Start))
			}
		})
	}
}
