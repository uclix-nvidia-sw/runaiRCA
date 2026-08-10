package server

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brilly-bohyun/runai-rca/backend/internal/server/testsupport"
)

// The store serializes EVERYTHING on one mutex, and the Postgres writes happen
// while it is held. These benchmarks measure what that costs a reader — the
// incident list the UI polls — while webhooks are arriving, because that is the
// pairing an operator actually experiences and the only number that can justify
// changing the locking.
//
// Run:
//
//	go test ./internal/server/ -run xxx -bench Contention -benchtime 3s
//	go test ./internal/server/ -run xxx -bench Contention -mutexprofile mu.out
//	go tool pprof -top -nodecount=15 mu.out

const benchDBLatency = 700 * time.Microsecond // one local Postgres round trip

func benchStore(tb testing.TB, latency time.Duration) *Store {
	tb.Helper()
	state := testsupport.NewPostgresState(false)
	store := NewStore()
	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	tb.Cleanup(func() { _ = store.db.Close() })
	// Latency is set AFTER connect so schema creation stays instant.
	state.SetExecLatency(latency)
	return store
}

func seedIncidents(store *Store, n int) {
	for i := range n {
		store.UpsertAlert(
			AlertmanagerWebhook{GroupKey: fmt.Sprintf("bench-%d", i)},
			Alert{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
				Annotations: map[string]string{"summary": "bench"},
				Fingerprint: fmt.Sprintf("fp-bench-%d", i),
				StartsAt:    time.Now().UTC().Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			},
		)
	}
}

// BenchmarkContentionReadDuringWebhooks reports the incident-list latency a
// reader sees while `writers` webhook goroutines persist under the same lock.
func BenchmarkContentionReadDuringWebhooks(b *testing.B) {
	for _, writers := range []int{0, 1, 4, 16} {
		b.Run(fmt.Sprintf("writers=%d", writers), func(b *testing.B) {
			store := benchStore(b, benchDBLatency)
			seedIncidents(store, 200)

			stop := make(chan struct{})
			var wg sync.WaitGroup
			var written atomic.Int64
			for w := range writers {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for n := 0; ; n++ {
						select {
						case <-stop:
							return
						default:
						}
						store.UpsertAlertResult(
							AlertmanagerWebhook{GroupKey: fmt.Sprintf("live-%d", w)},
							Alert{
								Status:      "firing",
								Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
								Fingerprint: fmt.Sprintf("fp-live-%d-%d", w, n%50),
								StartsAt:    time.Now().UTC().Format(time.RFC3339),
							},
						)
						written.Add(1)
					}
				}(w)
			}

			samples := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for range b.N {
				start := time.Now()
				store.ListIncidentsPageFilteredWithCounts(50, 0, incidentViewActive, IncidentListFilter{})
				samples = append(samples, time.Since(start))
			}
			b.StopTimer()

			close(stop)
			wg.Wait()
			reportLatency(b, samples)
			b.ReportMetric(float64(written.Load()), "webhooks")
		})
	}
}

// BenchmarkContentionWebhookThroughput is the write side of the same picture:
// how many webhooks per second get through as concurrency rises. Every one of
// them waits for the two serialized Postgres round trips.
func BenchmarkContentionWebhookThroughput(b *testing.B) {
	for _, writers := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("writers=%d", writers), func(b *testing.B) {
			store := benchStore(b, benchDBLatency)
			seedIncidents(store, 50)
			var n atomic.Int64
			b.SetParallelism(writers)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				id := n.Add(1)
				for i := 0; pb.Next(); i++ {
					store.UpsertAlertResult(
						AlertmanagerWebhook{GroupKey: fmt.Sprintf("tput-%d", id)},
						Alert{
							Status:      "firing",
							Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
							Fingerprint: fmt.Sprintf("fp-tput-%d-%d", id, i%50),
							StartsAt:    time.Now().UTC().Format(time.RFC3339),
						},
					)
				}
			})
		})
	}
}

func reportLatency(b *testing.B, samples []time.Duration) {
	b.Helper()
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	at := func(q float64) float64 {
		idx := int(float64(len(samples)-1) * q)
		return float64(samples[idx].Microseconds())
	}
	b.ReportMetric(at(0.50), "p50-us")
	b.ReportMetric(at(0.99), "p99-us")
}
