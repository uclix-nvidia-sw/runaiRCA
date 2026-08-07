package server

import (
	"runtime"
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
