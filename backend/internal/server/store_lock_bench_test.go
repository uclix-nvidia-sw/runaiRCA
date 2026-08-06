package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brilly-bohyun/runai-rca/backend/internal/server/testsupport"
)

// dbLatency is a conservative round-trip to a Postgres in the same cluster.
const dbLatency = 2 * time.Millisecond

func storeWithSlowPostgres(t testing.TB) (*Store, *testsupport.PostgresState) {
	t.Helper()
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	t.Cleanup(func() { _ = store.db.Close() })
	state.SetExecLatency(dbLatency)
	return store, state
}

// TestWritePathsStallConcurrentReaders measures, for the paths that actually
// run on every webhook and every analysis, how long readers are shut out. Each
// persist happens under the single store mutex, so a caller's stall is the SUM
// of its round trips.
func TestWritePathsStallConcurrentReaders(t *testing.T) {
	var benchAlertID string
	for _, tc := range []struct {
		name string
		// offLock is true for writes commitAfterUnlock runs with the store lock
		// released. The rest deliberately hold it: they roll their in-memory
		// change back when the write fails, which is only sound while no other
		// goroutine can observe the state in between.
		offLock bool
		setup   func(*Store)
		write   func(*Store)
	}{
		{
			name:    "alertmanager webhook",
			offLock: true,
			setup:   func(*Store) {},
			write: func(s *Store) {
				s.UpsertAlertResult(AlertmanagerWebhook{}, Alert{
					Status:      "firing",
					Labels:      map[string]string{"alertname": "KubePodNotReady", "namespace": "runai", "pod": "p1"},
					Annotations: map[string]string{"summary": "pod not ready"},
					StartsAt:    time.Now().UTC().Format(time.RFC3339),
				})
			},
		},
		{
			name: "analysis completed",
			setup: func(s *Store) {
				s.UpsertAlertResult(AlertmanagerWebhook{}, Alert{
					Status:   "firing",
					Labels:   map[string]string{"alertname": "KubePodNotReady", "namespace": "runai", "pod": "p2"},
					StartsAt: time.Now().UTC().Format(time.RFC3339),
				})
				for id := range s.alerts {
					s.analysisRuns["ANL-9"] = &AnalysisRun{RunID: "ANL-9", AlertID: id, IncidentID: s.alerts[id].IncidentID, Status: "analyzing"}
					benchAlertID = id
					break
				}
			},
			write: func(s *Store) {
				s.ApplyAnalysisForRun("ANL-9", benchAlertID, AgentAnalysisResponse{
					AnalysisSummary: "root cause", AnalysisDetail: "detail", RootCauseFamily: "workload_runtime_error",
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, state := storeWithSlowPostgres(t)
			state.SetExecLatency(0)
			tc.setup(store)
			state.SetExecLatency(dbLatency)

			var worst atomic.Int64
			var wg sync.WaitGroup
			stop := make(chan struct{})
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
						if waited := time.Since(start).Nanoseconds(); waited > worst.Load() {
							worst.Store(waited)
						}
					}
				}()
			}
			time.Sleep(5 * time.Millisecond)
			start := time.Now()
			tc.write(store)
			elapsed := time.Since(start)
			close(stop)
			wg.Wait()
			stall := time.Duration(worst.Load())
			t.Logf("%-20s write %6v | worst concurrent read %6v | one round-trip %v",
				tc.name, elapsed.Round(100*time.Microsecond), stall.Round(100*time.Microsecond), dbLatency)
			if tc.offLock && stall > dbLatency/2 {
				t.Fatalf("readers waited %v for a write that does not hold the store lock; "+
					"a persist call moved back under s.mu", stall)
			}
		})
	}
}

// TestEvaluationSaveStallsConcurrentReaders measures how long readers are shut
// out while one operator saves an evaluation. Every persist inside that save
// happens under the single store mutex, so the stall is the sum of its round
// trips, not one of them.
func TestEvaluationSaveStallsConcurrentReaders(t *testing.T) {
	store, _ := storeWithSlowPostgres(t)
	store.analysisRuns["ANL-1"] = &AnalysisRun{
		RunID:      "ANL-1",
		IncidentID: "INC-1",
		Metadata: map[string]any{
			"analysis_hash": "current",
			"harness":       map[string]any{"status": "pass"},
		},
	}

	var worst atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
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
				if waited := time.Since(start).Nanoseconds(); waited > worst.Load() {
					worst.Store(waited)
				}
			}
		}()
	}
	time.Sleep(5 * time.Millisecond) // let the readers spin up

	saveStart := time.Now()
	if _, ok, err := store.UpsertEvaluationReview("ANL-1", EvaluationReviewRequest{
		Author:            "operator-a",
		AnalysisHash:      "current",
		CaseType:          "novel",
		Scores:            completeScores(4),
		HardGates:         map[string]bool{},
		ResolutionOutcome: "resolved",
		EffectiveAction:   "restarted the daemonset",
	}, nil); err != nil || !ok {
		t.Fatalf("upsert review ok=%t err=%v", ok, err)
	}
	saveElapsed := time.Since(saveStart)
	close(stop)
	wg.Wait()

	t.Logf("evaluation save took %v (db round-trip %v)", saveElapsed, dbLatency)
	t.Logf("worst concurrent read latency %v", time.Duration(worst.Load()))
}
