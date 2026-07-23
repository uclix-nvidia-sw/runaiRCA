package testsupport

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
	"time"
)

var fakePostgresDriverSeq atomic.Int64

func RegisterPostgresDriver(state *PostgresState) string {
	name := fmt.Sprintf("fakepostgres%d", fakePostgresDriverSeq.Add(1))
	sql.Register(name, &fakePostgresDriver{state: state})
	return name
}

type PostgresState struct {
	mu                       sync.Mutex
	failCreateVector         bool
	failAnalysisRuns         bool
	failAnalysisRunExecAfter int
	analysisRunExecs         int
	failAlertExecAfter       int
	alertExecs               int
	execs                    []string
	queries                  []string
	now                      time.Time
	labelsJSON               []byte
	annotationsJSON          []byte
	capabilitiesJSON         []byte
	missingDataJSON          []byte
	warningsJSON             []byte
	artifactsJSON            []byte
	memoryVectorJSON         []byte
	emptyObjectJSON          []byte
	emptyArrayJSON           []byte
	execsNoDeadline          int
	queriesNoDeadline        int
	txBegins                 int
	txCommits                int
	txRollbacks              int
	pgvectorSearchLimit      int64
	incidentDeletedAt        any
}

func NewPostgresState(failCreateVector bool) *PostgresState {
	return &PostgresState{
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

func (s *PostgresState) SetFailAnalysisRuns(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAnalysisRuns = value
}

func (s *PostgresState) SetFailAnalysisRunExecAfter(value int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAnalysisRunExecAfter = value
}

func (s *PostgresState) SetFailAlertExecAfter(value int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAlertExecAfter = value
}

func (s *PostgresState) SetLabelsJSON(value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labelsJSON = append([]byte(nil), value...)
}

func (s *PostgresState) SetIncidentDeletedAt(value time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidentDeletedAt = value
}

func (s *PostgresState) AnalysisRunExecs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.analysisRunExecs
}

func (s *PostgresState) Execs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.execs...)
}

func (s *PostgresState) Executed(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

func (s *PostgresState) Queried(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.queries {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

func (s *PostgresState) ExecIndex(fragment string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return i
		}
	}
	return -1
}

func (s *PostgresState) DeadlineMisses() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execsNoDeadline, s.queriesNoDeadline
}

func (s *PostgresState) TxCounts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txBegins, s.txCommits, s.txRollbacks
}

func (s *PostgresState) RecordedPGVectorSearchLimit() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pgvectorSearchLimit
}

type fakePostgresDriver struct {
	state *PostgresState
}

func (d *fakePostgresDriver) Open(string) (driver.Conn, error) {
	return &fakePostgresConn{state: d.state}, nil
}

type fakePostgresConn struct {
	state *PostgresState
}

func (c *fakePostgresConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented")
}

func (c *fakePostgresConn) Close() error {
	return nil
}

func (c *fakePostgresConn) CheckNamedValue(*driver.NamedValue) error {
	return nil
}

func (c *fakePostgresConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *fakePostgresConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	c.state.mu.Lock()
	if _, ok := ctx.Deadline(); !ok {
		c.state.execsNoDeadline++
	}
	c.state.txBegins++
	c.state.mu.Unlock()
	return &fakePostgresTx{state: c.state}, nil
}

func (c *fakePostgresConn) Ping(context.Context) error {
	return nil
}

// maxDollarPlaceholder returns the highest N among the query's $N placeholders
// (0 if none) — the parameter count Postgres binds for the statement.
func maxDollarPlaceholder(query string) int {
	max := 0
	for i := 0; i < len(query); i++ {
		if query[i] != '$' {
			continue
		}
		j, n := i+1, 0
		for j < len(query) && query[j] >= '0' && query[j] <= '9' {
			n = n*10 + int(query[j]-'0')
			j++
		}
		if j > i+1 && n > max {
			max = n
		}
	}
	return max
}

func (c *fakePostgresConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	// Mimic Postgres bind semantics: it binds exactly the number of $N params the
	// statement references. Passing extra args (a real bug that fails at runtime)
	// used to silently "work" against this fake driver.
	if want := maxDollarPlaceholder(query); len(args) != want {
		return nil, fmt.Errorf("bind message supplies %d parameters, but statement requires %d", len(args), want)
	}
	failAnalysisRun := false
	c.state.mu.Lock()
	if _, ok := ctx.Deadline(); !ok {
		c.state.execsNoDeadline++
	}
	c.state.execs = append(c.state.execs, query)
	if strings.Contains(query, "INSERT INTO analysis_runs") {
		c.state.analysisRunExecs++
		failAnalysisRun = c.state.failAnalysisRuns ||
			(c.state.failAnalysisRunExecAfter > 0 && c.state.analysisRunExecs > c.state.failAnalysisRunExecAfter)
	}
	failAlert := false
	if strings.Contains(query, "INSERT INTO alerts") {
		c.state.alertExecs++
		failAlert = c.state.failAlertExecAfter > 0 && c.state.alertExecs > c.state.failAlertExecAfter
	}
	failCreateVector := c.state.failCreateVector
	c.state.mu.Unlock()

	if failCreateVector && strings.Contains(query, "CREATE EXTENSION IF NOT EXISTS vector") {
		return nil, errors.New(`extension "vector" is not available`)
	}
	if failAnalysisRun {
		return nil, errors.New("analysis run write failed")
	}
	if failAlert {
		return nil, errors.New("alert write failed")
	}
	return driver.RowsAffected(1), nil
}

func (c *fakePostgresConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	if _, ok := ctx.Deadline(); !ok {
		c.state.queriesNoDeadline++
	}
	c.state.queries = append(c.state.queries, query)
	if strings.Contains(query, "<=>") && len(args) >= 2 {
		switch value := args[1].Value.(type) {
		case int64:
			c.state.pgvectorSearchLimit = value
		case int:
			c.state.pgvectorSearchLimit = int64(value)
		}
	}
	c.state.mu.Unlock()

	return c.state.rowsFor(query), nil
}

type fakePostgresTx struct {
	state *PostgresState
}

func (tx *fakePostgresTx) Commit() error {
	tx.state.mu.Lock()
	defer tx.state.mu.Unlock()
	tx.state.txCommits++
	return nil
}

func (tx *fakePostgresTx) Rollback() error {
	tx.state.mu.Lock()
	defer tx.state.mu.Unlock()
	tx.state.txRollbacks++
	return nil
}

func (s *PostgresState) rowsFor(query string) driver.Rows {
	s.mu.Lock()
	defer s.mu.Unlock()
	lowered := strings.ToLower(query)
	switch {
	case strings.Contains(lowered, "<=>"):
		return &fakeRows{
			columns: []string{
				"incident_id", "alert_id", "title", "severity", "status",
				"analysis_summary", "analysis_detail", "labels", "created_at", "distance",
			},
			values: [][]driver.Value{{
				"INC-db", "ALR-db", "Prior GPU quota saturation", "warning", "resolved",
				"Run:AI queue gpu-a was saturated.", "GPU quota blocked scheduling.",
				s.labelsJSON, s.now, float64(0.1),
			}},
		}
	case strings.Contains(lowered, "from incidents"):
		return &fakeRows{
			columns: []string{"incident_id", "correlation_key", "title", "severity", "status", "fired_at", "resolved_at", "user_approved_at", "archived_at", "deleted_at", "alert_count", "analysis_seq", "slack_thread_ts"},
			values: [][]driver.Value{{
				"INC-db", "group:db", "Prior GPU quota saturation", "warning", "firing", s.now, nil, s.now, nil, s.incidentDeletedAt, int64(1), int64(0), "",
			}},
		}
	case strings.Contains(lowered, "from alerts"):
		return &fakeRows{
			columns: []string{
				"alert_id", "incident_id", "alarm_title", "severity", "status", "fired_at",
				"resolved_at", "fingerprint", "occurrence_count", "occurrence_pods", "thread_ts",
				"labels", "annotations",
			},
			values: [][]driver.Value{{
				"ALR-db", "INC-db", "RunAIWorkloadPending", "warning", "firing", s.now,
				nil, "fp-db", int64(1), s.emptyArrayJSON, "thread-db", s.labelsJSON, s.annotationsJSON,
			}},
		}
	case strings.Contains(lowered, "from incident_embeddings"):
		return &fakeRows{
			columns: []string{
				"incident_id", "alert_id", "title", "severity", "status", "analysis_summary",
				"analysis_detail", "labels", "vector_json", "created_at",
			},
			values: [][]driver.Value{{
				"INC-db", "ALR-db", "Prior GPU quota saturation", "warning", "resolved",
				"Run:AI queue gpu-a was saturated.", "GPU quota blocked scheduling.",
				s.labelsJSON, s.memoryVectorJSON, s.now,
			}},
		}
	case strings.Contains(lowered, "from rca_feedback") && strings.Contains(lowered, "kind = 'comment'"):
		return &fakeRows{
			columns: []string{"feedback_id", "target_type", "target_id", "incident_id", "alert_id", "body", "author", "created_at"},
			values: [][]driver.Value{{
				"CMT-db", "incident", "INC-db", "INC-db", "", "Persisted operator comment.", "operator", s.now,
			}},
		}
	case strings.Contains(lowered, "from rca_feedback"):
		return &fakeRows{
			columns: []string{"feedback_id", "target_type", "target_id", "incident_id", "alert_id", "vote", "body", "author", "created_at"},
			values: [][]driver.Value{{
				"FDB-db", "incident", "INC-db", "INC-db", "", "up", "", "operator", s.now,
			}},
		}
	case strings.Contains(lowered, "from analysis_runs"):
		return &fakeRows{
			columns: []string{
				"run_id", "source", "status", "target_type", "target_id", "incident_id",
				"alert_id", "title", "prompt", "analysis_summary", "analysis_detail",
				"analysis_quality", "root_cause_family", "capabilities", "missing_data", "warnings", "artifacts",
				"metadata", "first_completed_at", "created_at", "updated_at",
			},
			values: [][]driver.Value{{
				"ANL-db", "comment", "complete", "incident", "INC-db", "INC-db",
				"", "Comment reanalysis", "check scheduler logs", "Reanalysis completed.",
				"Scheduler logs confirmed quota saturation.", "high", "", s.capabilitiesJSON,
				s.emptyArrayJSON, s.emptyArrayJSON, s.emptyArrayJSON, s.emptyObjectJSON, s.now, s.now, s.now,
			}},
		}
	case strings.Contains(lowered, "from chat_conversations"):
		return &fakeRows{
			columns: []string{
				"conversation_id", "title", "context_label", "incident_id", "alert_id",
				"messages", "created_at", "updated_at",
			},
			values: [][]driver.Value{{
				"chat-db", "Why is the queue blocked?", "Incident INC-db", "INC-db", "",
				[]byte(`[{"id":"msg-user","role":"user","content":"Why is the queue blocked?","created_at":"2026-06-26T12:00:00Z"},{"id":"msg-assistant","role":"assistant","content":"GPU quota is saturated.","created_at":"2026-06-26T12:00:01Z"}]`),
				s.now, s.now,
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
