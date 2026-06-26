package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPostgresConnectReportsPGVectorEnabledAndLoadsState(t *testing.T) {
	state := newFakePostgresState(false)
	store := NewStore()

	store.connectDatabaseWithDriver(registerFakePostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()

	if !store.dbReady || !store.pgvectorReady {
		t.Fatalf("expected postgres and pgvector ready, got health=%+v", store.databaseHealth())
	}
	if store.pgvectorStatus() != pgvectorStatusEnabled || store.pgvectorLogState() != "pgvector=enabled" {
		t.Fatalf("unexpected pgvector status: %s %s", store.pgvectorStatus(), store.pgvectorLogState())
	}
	if health := store.databaseHealth(); health["pgvector"] != true || health["pgvector_status"] != pgvectorStatusEnabled {
		t.Fatalf("expected pgvector health compatibility fields, got %+v", health)
	}
	if !state.executed("CREATE EXTENSION IF NOT EXISTS vector") ||
		!state.executed("CREATE TABLE IF NOT EXISTS incident_embeddings") {
		t.Fatalf("expected pgvector extension and embeddings schema statements, got %+v", state.execs)
	}

	assertLoadedPostgresMemory(t, store)
}

func TestPostgresConnectFallsBackToJSONBWhenPGVectorUnavailable(t *testing.T) {
	state := newFakePostgresState(true)
	store := NewStore()

	store.connectDatabaseWithDriver(registerFakePostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()

	if !store.dbReady {
		t.Fatalf("postgres should remain enabled when only pgvector is unavailable")
	}
	if store.pgvectorReady || store.pgvectorStatus() != pgvectorStatusUnavailable {
		t.Fatalf("expected pgvector unavailable, got health=%+v", store.databaseHealth())
	}
	if store.pgvectorLogState() != "pgvector=unavailable, fallback=jsonb" {
		t.Fatalf("unexpected pgvector log state: %s", store.pgvectorLogState())
	}
	health := store.databaseHealth()
	if health["pgvector"] != false ||
		health["pgvector_status"] != pgvectorStatusUnavailable ||
		health["fallback"] != vectorFallbackJSONB ||
		health["similarity_search"] != similaritySearchJSONB {
		t.Fatalf("expected JSONB fallback health, got %+v", health)
	}

	assertLoadedPostgresMemory(t, store)
}

func TestInMemoryStoreHealthReportsNoPostgres(t *testing.T) {
	health := NewStore().databaseHealth()
	if health["postgres"] != false ||
		health["pgvector"] != false ||
		health["pgvector_status"] != pgvectorStatusDisabled ||
		health["similarity_search"] != similaritySearchMemory {
		t.Fatalf("unexpected in-memory health: %+v", health)
	}
	if _, ok := health["fallback"]; ok {
		t.Fatalf("in-memory store should not report a pgvector fallback: %+v", health)
	}
}

func assertLoadedPostgresMemory(t *testing.T, store *Store) {
	t.Helper()

	detail, ok := store.IncidentDetail("INC-db")
	if !ok {
		t.Fatalf("expected incident to reload from postgres")
	}
	if detail.Feedback.Positive != 1 || len(detail.Feedback.Comments) != 1 {
		t.Fatalf("expected feedback and comments to reload, got %+v", detail.Feedback)
	}

	search := store.SearchIncidentMemory("gpu quota scheduling", 5)
	if len(search) == 0 {
		t.Fatalf("expected JSONB sparse vector search result")
	}
	if search[0].IncidentID != "INC-db" || search[0].PositiveFeedback != 1 || search[0].CommentCount != 1 {
		t.Fatalf("expected feedback metadata on search result, got %+v", search[0])
	}

	runs := store.ListAnalysisRuns()
	if len(runs) != 1 || runs[0].RunID != "ANL-db" || runs[0].Status != "complete" {
		t.Fatalf("expected analysis run to reload, got %+v", runs)
	}
}

var fakePostgresDriverSeq atomic.Int64

func registerFakePostgresDriver(state *fakePostgresState) string {
	name := fmt.Sprintf("fakepostgres%d", fakePostgresDriverSeq.Add(1))
	sql.Register(name, &fakePostgresDriver{state: state})
	return name
}

type fakePostgresState struct {
	mu               sync.Mutex
	failCreateVector bool
	execs            []string
	queries          []string
	now              time.Time
	labelsJSON       []byte
	annotationsJSON  []byte
	capabilitiesJSON []byte
	missingDataJSON  []byte
	warningsJSON     []byte
	artifactsJSON    []byte
	memoryVectorJSON []byte
	emptyObjectJSON  []byte
	emptyArrayJSON   []byte
}

func newFakePostgresState(failCreateVector bool) *fakePostgresState {
	return &fakePostgresState{
		failCreateVector: failCreateVector,
		now:              time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC),
		labelsJSON:       []byte(`{"alertname":"RunAIWorkloadPending","severity":"warning","cluster":"lab","project":"vision","queue":"gpu-a","namespace":"runai","workload":"trainer"}`),
		annotationsJSON:  []byte(`{"summary":"Workload pending because GPU quota is exhausted"}`),
		capabilitiesJSON: []byte(`{"runai":"ok"}`),
		missingDataJSON:  []byte(`[]`),
		warningsJSON:     []byte(`[]`),
		artifactsJSON:    []byte(`[]`),
		memoryVectorJSON: []byte(`{"gpu":2,"quota":2,"scheduling":1,"runai":1}`),
		emptyObjectJSON:  []byte(`{}`),
		emptyArrayJSON:   []byte(`[]`),
	}
}

func (s *fakePostgresState) executed(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

type fakePostgresDriver struct {
	state *fakePostgresState
}

func (d *fakePostgresDriver) Open(string) (driver.Conn, error) {
	return &fakePostgresConn{state: d.state}, nil
}

type fakePostgresConn struct {
	state *fakePostgresState
}

func (c *fakePostgresConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented")
}

func (c *fakePostgresConn) Close() error {
	return nil
}

func (c *fakePostgresConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not implemented")
}

func (c *fakePostgresConn) Ping(context.Context) error {
	return nil
}

func (c *fakePostgresConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.state.mu.Lock()
	c.state.execs = append(c.state.execs, query)
	c.state.mu.Unlock()

	if c.state.failCreateVector && strings.Contains(query, "CREATE EXTENSION IF NOT EXISTS vector") {
		return nil, errors.New("extension vector is not installed")
	}
	return driver.RowsAffected(1), nil
}

func (c *fakePostgresConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	c.state.queries = append(c.state.queries, query)
	c.state.mu.Unlock()

	return c.state.rowsFor(query), nil
}

func (s *fakePostgresState) rowsFor(query string) driver.Rows {
	lowered := strings.ToLower(query)
	switch {
	case strings.Contains(lowered, "from incidents"):
		return &fakeRows{
			columns: []string{"incident_id", "correlation_key", "title", "severity", "status", "fired_at", "resolved_at", "alert_count"},
			values: [][]driver.Value{{
				"INC-db", "group:db", "Prior GPU quota saturation", "warning", "firing", s.now, nil, int64(1),
			}},
		}
	case strings.Contains(lowered, "from alerts"):
		return &fakeRows{
			columns: []string{
				"alert_id", "incident_id", "alarm_title", "severity", "status", "fired_at",
				"resolved_at", "fingerprint", "thread_ts", "labels", "annotations",
				"analysis_summary", "analysis_detail", "analysis_quality", "capabilities",
				"missing_data", "warnings", "artifacts",
			},
			values: [][]driver.Value{{
				"ALR-db", "INC-db", "RunAIWorkloadPending", "warning", "firing", s.now,
				nil, "fp-db", "thread-db", s.labelsJSON, s.annotationsJSON,
				"Run:AI queue gpu-a was saturated.", "GPU quota blocked scheduling.", "high", s.capabilitiesJSON,
				s.missingDataJSON, s.warningsJSON, s.artifactsJSON,
			}},
		}
	case strings.Contains(lowered, "from incident_embeddings"):
		return &fakeRows{
			columns: []string{
				"incident_id", "alert_id", "title", "severity", "status", "analysis_summary",
				"analysis_detail", "labels", "vector_json", "created_at",
			},
			values: [][]driver.Value{{
				"INC-db", "ALR-db", "Prior GPU quota saturation", "warning", "firing",
				"Run:AI queue gpu-a was saturated.", "GPU quota blocked scheduling.",
				s.labelsJSON, s.memoryVectorJSON, s.now,
			}},
		}
	case strings.Contains(lowered, "from rca_feedback"):
		return &fakeRows{
			columns: []string{"feedback_id", "target_type", "target_id", "incident_id", "alert_id", "vote", "comment", "author", "created_at"},
			values: [][]driver.Value{{
				"FDB-db", "incident", "INC-db", "INC-db", "", "up", "This matched the prior quota issue.", "operator", s.now,
			}},
		}
	case strings.Contains(lowered, "from rca_comments"):
		return &fakeRows{
			columns: []string{"comment_id", "target_type", "target_id", "incident_id", "alert_id", "body", "author", "created_at"},
			values: [][]driver.Value{{
				"CMT-db", "incident", "INC-db", "INC-db", "", "Persisted operator comment.", "operator", s.now,
			}},
		}
	case strings.Contains(lowered, "from analysis_runs"):
		return &fakeRows{
			columns: []string{
				"run_id", "source", "status", "target_type", "target_id", "incident_id",
				"alert_id", "title", "prompt", "analysis_summary", "analysis_detail",
				"analysis_quality", "capabilities", "missing_data", "warnings", "artifacts",
				"created_at", "updated_at",
			},
			values: [][]driver.Value{{
				"ANL-db", "comment", "complete", "incident", "INC-db", "INC-db",
				"", "Comment reanalysis", "check scheduler logs", "Reanalysis completed.",
				"Scheduler logs confirmed quota saturation.", "high", s.capabilitiesJSON,
				s.emptyArrayJSON, s.emptyArrayJSON, s.emptyArrayJSON, s.now, s.now,
			}},
		}
	default:
		return &fakeRows{}
	}
}

type fakeRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *fakeRows) Columns() []string {
	return r.columns
}

func (r *fakeRows) Close() error {
	return nil
}

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
