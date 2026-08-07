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

func storeWithSlowPostgres(t testing.TB) (*Store, *testsupport.PostgresState) {
	t.Helper()
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	t.Cleanup(func() { _ = store.db.Close() })
	state.SetExecLatency(dbLatency)
	return store, state
}

// TestWebhookWriteCostsTwoRoundTripsUnderTheStoreLock records what the alert
// webhook — the hottest write path — costs every reader, and pins the two facts
// that matter: the write actually happens, and it pays for both of its round
// trips.
//
// It does NOT assert a reader-latency bound. An earlier version moved these
// writes off the store lock and asserted readers no longer waited; that
// optimisation was withdrawn (see UpsertAlertResult) because a clone committed
// after a concurrent trash/approve silently reverted it in Postgres. The number
// below is the cost of the safe design, logged so a future change to it is
// visible rather than assumed.
func TestWebhookWriteCostsTwoRoundTripsUnderTheStoreLock(t *testing.T) {
	store, state := storeWithSlowPostgres(t)

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
	if elapsed < 2*dbLatency {
		t.Fatalf("write took %v, less than its two %v round trips — a persist call was skipped",
			elapsed, dbLatency)
	}
	t.Logf("webhook write %v (2 x %v round trip) | worst concurrent read %v | GOMAXPROCS=%d",
		elapsed.Round(100*time.Microsecond), dbLatency,
		time.Duration(worst.Load()).Round(100*time.Microsecond), runtime.GOMAXPROCS(0))
}
