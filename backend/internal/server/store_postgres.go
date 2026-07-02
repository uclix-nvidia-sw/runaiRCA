package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresOperationTimeout = 5 * time.Second

func (s *Store) ConnectDatabase(databaseURL string, connectTimeout time.Duration) {
	s.connectDatabaseWithDriver("pgx", databaseURL, connectTimeout)
}

func (s *Store) connectDatabaseWithDriver(driverName string, databaseURL string, connectTimeout time.Duration) {
	databaseURL = strings.TrimSpace(databaseURL)
	if databaseURL == "" {
		return
	}
	if connectTimeout <= 0 {
		connectTimeout = 5 * time.Second
	}
	db, err := sql.Open(driverName, databaseURL)
	if err != nil {
		log.Printf("Postgres store disabled: open failed: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		if isMissingDatabaseError(err) && ensureDatabaseExists(driverName, databaseURL, connectTimeout) {
			_ = db.Close()
			if db, err = sql.Open(driverName, databaseURL); err != nil {
				log.Printf("Postgres store disabled: reopen failed: %v", err)
				return
			}
			retryCtx, retryCancel := context.WithTimeout(context.Background(), connectTimeout)
			err = db.PingContext(retryCtx)
			retryCancel()
		}
		if err != nil {
			_ = db.Close()
			log.Printf("Postgres store disabled: ping failed: %v", err)
			return
		}
	}
	s.db = db
	s.dbReady = true
	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), connectTimeout)
	defer schemaCancel()
	s.pgvectorReady = s.ensurePostgresSchema(schemaCtx)
	if !s.dbReady {
		_ = db.Close()
		s.db = nil
		s.pgvectorReady = false
		log.Printf("Postgres store disabled: schema initialization failed")
		return
	}
	s.loadDatabaseState(schemaCtx)
	log.Printf(
		"Postgres store enabled for incidents, embeddings, feedback, comments, and analysis runs; %s",
		s.pgvectorLogState(),
	)
}

// isMissingDatabaseError reports whether err is Postgres SQLSTATE 3D000
// (invalid_catalog_name), which is returned when the target database does not
// yet exist on an otherwise reachable server.
func isMissingDatabaseError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr != nil {
		return pgErr.Code == "3D000"
	}
	return strings.Contains(strings.ToLower(err.Error()), "does not exist")
}

// ensureDatabaseExists connects to the server's maintenance database and creates
// the target database only when it is missing. Existing databases on the same
// server are never modified; the only DDL issued is CREATE DATABASE for the
// requested name. Returns true when the database exists or was created.
func ensureDatabaseExists(driverName, databaseURL string, connectTimeout time.Duration) bool {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return false
	}
	dbName, err := url.PathUnescape(strings.Trim(u.Path, "/"))
	if err != nil || dbName == "" {
		return false
	}
	admin := *u
	admin.Path = "/postgres"
	conn, err := sql.Open(driverName, admin.String())
	if err != nil {
		log.Printf("auto-create database: connect to maintenance db failed: %v", err)
		return false
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
		log.Printf("auto-create database: existence check failed: %v", err)
		return false
	}
	if exists {
		return true
	}
	stmt := fmt.Sprintf(`CREATE DATABASE %s`, quoteIdentifier(dbName))
	if _, err := conn.ExecContext(ctx, stmt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr != nil && pgErr.Code == "42P04" {
			if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err == nil && exists {
				log.Printf("auto-create database %q skipped: database already exists", dbName)
				return true
			}
		}
		log.Printf("auto-create database %q failed: %v", dbName, err)
		return false
	}
	log.Printf("auto-created database %q on existing Postgres server", dbName)
	return true
}

// quoteIdentifier safely double-quotes a Postgres identifier, escaping embedded
// double quotes so the database name cannot break out of the CREATE DATABASE
// statement.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func postgresOperationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), postgresOperationTimeout)
}

func (s *Store) execPostgres(query string, args ...any) (sql.Result, error) {
	ctx, cancel := postgresOperationContext()
	defer cancel()
	return s.db.ExecContext(ctx, query, args...)
}

func (s *Store) ensurePostgresSchema(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	pgvectorReady := true
	if _, err := s.db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		pgvectorReady = false
		s.pgvectorDetail = classifyPGVectorError(err)
		log.Printf(
			"WARNING: pgvector disabled, using JSONB sparse-vector fallback for similar-incident search. "+
				"Reason: %v. Remediation: %s",
			err, s.pgvectorDetail,
		)
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS incidents (
			incident_id TEXT PRIMARY KEY,
			correlation_key TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			fired_at TIMESTAMPTZ NOT NULL,
			resolved_at TIMESTAMPTZ,
			alert_count INTEGER NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			alert_id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			alarm_title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			fired_at TIMESTAMPTZ NOT NULL,
			resolved_at TIMESTAMPTZ,
			fingerprint TEXT NOT NULL,
			occurrence_count INTEGER NOT NULL DEFAULT 1,
			occurrence_pods JSONB NOT NULL DEFAULT '[]'::jsonb,
			thread_ts TEXT NOT NULL,
			labels JSONB NOT NULL DEFAULT '{}'::jsonb,
			annotations JSONB NOT NULL DEFAULT '{}'::jsonb,
			analysis_summary TEXT NOT NULL DEFAULT '',
			analysis_detail TEXT NOT NULL DEFAULT '',
			analysis_quality TEXT NOT NULL DEFAULT '',
			capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
			missing_data JSONB NOT NULL DEFAULT '[]'::jsonb,
			warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
			artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_pods JSONB NOT NULL DEFAULT '[]'::jsonb`,
		`CREATE TABLE IF NOT EXISTS incident_embeddings (
			incident_id TEXT NOT NULL,
			alert_id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL,
			analysis_summary TEXT NOT NULL,
			analysis_detail TEXT NOT NULL,
			labels JSONB NOT NULL DEFAULT '{}'::jsonb,
			vector_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE incident_embeddings DROP CONSTRAINT IF EXISTS incident_embeddings_pkey`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_embeddings_incident_alert ON incident_embeddings (incident_id, alert_id)`,
		`DO $$
		BEGIN
			IF to_regclass('public.incident_memories') IS NOT NULL THEN
				EXECUTE '
					INSERT INTO incident_embeddings (
						incident_id, alert_id, title, severity, status,
						analysis_summary, analysis_detail, labels, vector_json,
						created_at, updated_at
					)
					SELECT
						incident_id, alert_id, title, severity, status,
						analysis_summary, analysis_detail, labels, vector_json,
						created_at, updated_at
					FROM incident_memories
					ON CONFLICT DO NOTHING
				';
			END IF;
		END $$`,
		`CREATE TABLE IF NOT EXISTS rca_feedback (
			feedback_id TEXT PRIMARY KEY,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			incident_id TEXT,
			alert_id TEXT,
			vote TEXT NOT NULL,
			comment TEXT NOT NULL DEFAULT '',
			author TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS rca_comments (
			comment_id TEXT PRIMARY KEY,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			incident_id TEXT,
			alert_id TEXT,
			body TEXT NOT NULL,
			author TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS analysis_runs (
			run_id TEXT PRIMARY KEY,
			source TEXT NOT NULL,
			status TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			incident_id TEXT,
			alert_id TEXT,
			title TEXT NOT NULL,
			prompt TEXT NOT NULL DEFAULT '',
			analysis_summary TEXT NOT NULL DEFAULT '',
			analysis_detail TEXT NOT NULL DEFAULT '',
			analysis_quality TEXT NOT NULL DEFAULT '',
			capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
			missing_data JSONB NOT NULL DEFAULT '[]'::jsonb,
			warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
			artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts (incident_id)`,
		`CREATE INDEX IF NOT EXISTS idx_feedback_target ON rca_feedback (target_type, target_id)`,
		`CREATE INDEX IF NOT EXISTS idx_comments_target ON rca_comments (target_type, target_id)`,
		`CREATE INDEX IF NOT EXISTS idx_analysis_runs_created_at ON analysis_runs (created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_analysis_runs_target ON analysis_runs (target_type, target_id)`,
		`UPDATE analysis_runs
			SET status = 'failed',
				analysis_quality = COALESCE(NULLIF(analysis_quality, ''), 'low'),
				capabilities = capabilities || '{"agent":"deduplicated"}'::jsonb,
				warnings = warnings || '["duplicate analyzing run was closed before enforcing alert uniqueness"]'::jsonb,
				updated_at = now()
			WHERE run_id IN (
				SELECT run_id
				FROM (
					SELECT run_id, row_number() OVER (
						PARTITION BY alert_id
						ORDER BY updated_at DESC, created_at DESC, run_id DESC
					) AS rn
					FROM analysis_runs
					WHERE status = 'analyzing' AND alert_id IS NOT NULL AND alert_id <> ''
				) ranked
				WHERE rn > 1
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_runs_one_analyzing_alert ON analysis_runs (alert_id) WHERE status = 'analyzing' AND alert_id IS NOT NULL AND alert_id <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_embeddings_created_at ON incident_embeddings (created_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			log.Printf("Postgres schema statement failed: %v", err)
			s.dbReady = false
			return pgvectorReady
		}
	}
	if pgvectorReady {
		s.ensureVectorColumn(ctx)
	}
	return pgvectorReady
}

// ensureVectorColumn adds the dense pgvector column and a cosine index used by
// similarity search. It runs only when the extension is available and is
// deliberately non-fatal: if the column or index cannot be created (e.g. an
// older pgvector without HNSW), the backend keeps the JSONB sparse vectors and
// in-process cosine fallback rather than failing startup.
func (s *Store) ensureVectorColumn(ctx context.Context) {
	statements := []string{
		fmt.Sprintf(
			`ALTER TABLE incident_embeddings ADD COLUMN IF NOT EXISTS embedding vector(%d)`,
			s.embeddingDim(),
		),
		`CREATE INDEX IF NOT EXISTS idx_embeddings_vector
			ON incident_embeddings USING hnsw (embedding vector_cosine_ops)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			log.Printf("pgvector column/index setup skipped: %v", err)
			return
		}
	}
}

// classifyPGVectorError turns a failed `CREATE EXTENSION vector` into an
// actionable remediation hint for operators, distinguishing the two common
// causes on an existing/external Postgres: the extension binary is not installed
// on the server, or the application database user lacks the privilege to create
// it. The hint is logged at startup and surfaced in /healthz so the JSONB
// fallback is never silent.
func classifyPGVectorError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "must be superuser"):
		return "the database user lacks privilege to create the extension; " +
			"have a superuser run `CREATE EXTENSION vector;` in this database once (or grant the privilege)"
	case strings.Contains(msg, "is not available"),
		strings.Contains(msg, "could not open extension control file"),
		strings.Contains(msg, "no such file"):
		return "the pgvector extension is not installed on the Postgres server; " +
			"install the pgvector package/image on the server, then `CREATE EXTENSION vector;`"
	default:
		return "verify pgvector is installed on the server and the app user may `CREATE EXTENSION vector;`"
	}
}

func (s *Store) loadDatabaseState(ctx context.Context) {
	if s.db == nil || !s.dbReady {
		return
	}
	s.loadIncidents(ctx)
	s.loadAlerts(ctx)
	s.loadMemories(ctx)
	s.loadFeedback(ctx)
	s.loadComments(ctx)
	s.loadAnalysisRuns(ctx)
}

func (s *Store) loadIncidents(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT incident_id, correlation_key, title, severity, status, fired_at,
		        resolved_at, alert_count
		   FROM incidents`,
	)
	if err != nil {
		log.Printf("Failed to load incidents: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var incident Incident
		if err := rows.Scan(
			&incident.IncidentID,
			&incident.CorrelationKey,
			&incident.Title,
			&incident.Severity,
			&incident.Status,
			&incident.FiredAt,
			&incident.ResolvedAt,
			&incident.AlertCount,
		); err != nil {
			log.Printf("Failed to scan incident: %v", err)
			continue
		}
		s.incidents[incident.IncidentID] = &incident
		s.incidentByKey[incident.CorrelationKey] = incident.IncidentID
	}
}

func (s *Store) loadAlerts(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT alert_id, incident_id, alarm_title, severity, status, fired_at,
		        resolved_at, fingerprint, occurrence_count, occurrence_pods, thread_ts, labels, annotations,
		        analysis_summary, analysis_detail, analysis_quality, capabilities,
		        missing_data, warnings, artifacts
		   FROM alerts`,
	)
	if err != nil {
		log.Printf("Failed to load alerts: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var alert AlertRecord
		var labelsRaw, annotationsRaw, capabilitiesRaw, missingRaw, warningsRaw, artifactsRaw []byte
		var occurrencePodsRaw []byte
		if err := rows.Scan(
			&alert.AlertID,
			&alert.IncidentID,
			&alert.AlarmTitle,
			&alert.Severity,
			&alert.Status,
			&alert.FiredAt,
			&alert.ResolvedAt,
			&alert.Fingerprint,
			&alert.OccurrenceCount,
			&occurrencePodsRaw,
			&alert.ThreadTS,
			&labelsRaw,
			&annotationsRaw,
			&alert.AnalysisSummary,
			&alert.AnalysisDetail,
			&alert.AnalysisQuality,
			&capabilitiesRaw,
			&missingRaw,
			&warningsRaw,
			&artifactsRaw,
		); err != nil {
			log.Printf("Failed to scan alert: %v", err)
			continue
		}
		_ = json.Unmarshal(labelsRaw, &alert.Labels)
		_ = json.Unmarshal(annotationsRaw, &alert.Annotations)
		_ = json.Unmarshal(occurrencePodsRaw, &alert.OccurrencePods)
		_ = json.Unmarshal(capabilitiesRaw, &alert.Capabilities)
		_ = json.Unmarshal(missingRaw, &alert.MissingData)
		_ = json.Unmarshal(warningsRaw, &alert.Warnings)
		_ = json.Unmarshal(artifactsRaw, &alert.Artifacts)
		if alert.OccurrenceCount <= 0 {
			alert.OccurrenceCount = 1
		}
		s.alerts[alert.AlertID] = &alert
		if alert.Fingerprint != "" {
			s.alertByFinger[alert.Fingerprint] = alert.AlertID
		}
		if incident := s.incidents[alert.IncidentID]; incident != nil && incident.CorrelationKey != "" {
			s.alertByGroup["correlation:"+incident.CorrelationKey] = alert.AlertID
		}
	}
	for _, alert := range s.alerts {
		incident := s.incidents[alert.IncidentID]
		if incident == nil {
			continue
		}
		if alert.FiredAt.After(incident.LatestActivityAt) {
			incident.LatestActivityAt = alert.FiredAt
		}
		if alert.ResolvedAt != nil && alert.ResolvedAt.After(incident.LatestActivityAt) {
			incident.LatestActivityAt = *alert.ResolvedAt
		}
	}
}

func (s *Store) loadMemories(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT incident_id, alert_id, title, severity, status, analysis_summary,
		        analysis_detail, labels, vector_json, created_at
		   FROM incident_embeddings`,
	)
	if err != nil {
		log.Printf("Failed to load incident memories: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var memory IncidentMemory
		var labelsRaw, vectorRaw []byte
		if err := rows.Scan(
			&memory.IncidentID,
			&memory.AlertID,
			&memory.Title,
			&memory.Severity,
			&memory.Status,
			&memory.AnalysisSummary,
			&memory.AnalysisDetail,
			&labelsRaw,
			&vectorRaw,
			&memory.CreatedAt,
		); err != nil {
			log.Printf("Failed to scan incident memory: %v", err)
			continue
		}
		_ = json.Unmarshal(labelsRaw, &memory.Labels)
		_ = json.Unmarshal(vectorRaw, &memory.Vector)
		if memory.Labels == nil {
			memory.Labels = map[string]string{}
		}
		if memory.Vector == nil {
			memory.Vector = textVector(memoryText(memory))
		}
		s.memories[first(memory.AlertID, memory.IncidentID)] = &memory
	}
}

// dbSearchMemory runs the free-text similarity search inside Postgres using the
// pgvector cosine distance operator (`<=>`) against the dense `embedding`
// column, then enriches each hit with feedback metadata held in memory. It
// returns (results, true) when pgvector served the query, or (nil, false) to
// signal the caller to fall back to the in-process sparse-vector search (when
// the extension is unavailable or the query errors).
func (s *Store) dbSearchMemory(query string, limit int) ([]SimilarIncident, bool) {
	if s.db == nil || !s.dbReady || !s.pgvectorReady {
		return nil, false
	}
	literal := embeddingLiteral(s.embed(query))
	queryLimit := limit * 3
	ctx, cancel := postgresOperationContext()
	defer cancel()
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT incident_id, alert_id, title, severity, status, analysis_summary,
		        analysis_detail, labels, created_at, (embedding <=> $1::vector) AS distance
		   FROM incident_embeddings
		  WHERE embedding IS NOT NULL
		  ORDER BY embedding <=> $1::vector
		  LIMIT $2`,
		literal, queryLimit,
	)
	if err != nil {
		log.Printf("pgvector similarity search failed, falling back to jsonb: %v", err)
		return nil, false
	}
	defer rows.Close()
	results := make([]SimilarIncident, 0, limit)
	for rows.Next() {
		var item SimilarIncident
		var detail string
		var labelsRaw []byte
		var distance float64
		if err := rows.Scan(
			&item.IncidentID,
			&item.AlertID,
			&item.Title,
			&item.Severity,
			&item.Status,
			&item.AnalysisSummary,
			&detail,
			&labelsRaw,
			&item.CreatedAt,
			&distance,
		); err != nil {
			log.Printf("Failed to scan pgvector search row: %v", err)
			return nil, false
		}
		similarity := 1 - distance
		if similarity <= 0.05 {
			continue
		}
		_ = json.Unmarshal(labelsRaw, &item.Labels)
		if item.Labels == nil {
			item.Labels = map[string]string{}
		}
		item.Similarity = math.Round(similarity*1000) / 1000
		item.AnalysisDetail = excerpt(detail, 900)
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		log.Printf("pgvector similarity search iteration failed: %v", err)
		return nil, false
	}
	s.mu.RLock()
	for i := range results {
		summary := s.feedbackSummaryLocked("incident", results[i].IncidentID)
		results[i].PositiveFeedback = summary.Positive
		results[i].NegativeFeedback = summary.Negative
		results[i].CommentCount = len(summary.Comments)
	}
	s.mu.RUnlock()
	return dedupeSimilarByIncident(results, limit), true
}

func (s *Store) loadFeedback(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT feedback_id, target_type, target_id, incident_id, alert_id, vote,
		        comment, author, created_at
		   FROM rca_feedback`,
	)
	if err != nil {
		log.Printf("Failed to load feedback: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var record FeedbackRecord
		if err := rows.Scan(
			&record.FeedbackID,
			&record.TargetType,
			&record.TargetID,
			&record.IncidentID,
			&record.AlertID,
			&record.Vote,
			&record.Comment,
			&record.Author,
			&record.CreatedAt,
		); err != nil {
			log.Printf("Failed to scan feedback: %v", err)
			continue
		}
		s.feedback[record.FeedbackID] = &record
	}
}

func (s *Store) loadComments(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT comment_id, target_type, target_id, incident_id, alert_id, body,
		        author, created_at
		   FROM rca_comments`,
	)
	if err != nil {
		log.Printf("Failed to load comments: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var record CommentRecord
		if err := rows.Scan(
			&record.CommentID,
			&record.TargetType,
			&record.TargetID,
			&record.IncidentID,
			&record.AlertID,
			&record.Body,
			&record.Author,
			&record.CreatedAt,
		); err != nil {
			log.Printf("Failed to scan comment: %v", err)
			continue
		}
		s.comments[record.CommentID] = &record
	}
}

func (s *Store) loadAnalysisRuns(ctx context.Context) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT run_id, source, status, target_type, target_id, incident_id,
		        alert_id, title, prompt, analysis_summary, analysis_detail,
		        analysis_quality, capabilities, missing_data, warnings, artifacts,
		        created_at, updated_at
		   FROM analysis_runs`,
	)
	if err != nil {
		log.Printf("Failed to load analysis runs: %v", err)
		return
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var run AnalysisRun
		var capabilitiesRaw, missingRaw, warningsRaw, artifactsRaw []byte
		if err := rows.Scan(
			&run.RunID,
			&run.Source,
			&run.Status,
			&run.TargetType,
			&run.TargetID,
			&run.IncidentID,
			&run.AlertID,
			&run.Title,
			&run.Prompt,
			&run.AnalysisSummary,
			&run.AnalysisDetail,
			&run.AnalysisQuality,
			&capabilitiesRaw,
			&missingRaw,
			&warningsRaw,
			&artifactsRaw,
			&run.CreatedAt,
			&run.UpdatedAt,
		); err != nil {
			log.Printf("Failed to scan analysis run: %v", err)
			continue
		}
		_ = json.Unmarshal(capabilitiesRaw, &run.Capabilities)
		_ = json.Unmarshal(missingRaw, &run.MissingData)
		_ = json.Unmarshal(warningsRaw, &run.Warnings)
		_ = json.Unmarshal(artifactsRaw, &run.Artifacts)
		s.analysisRuns[run.RunID] = &run
	}
}

func (s *Store) persistIncidentLocked(incident *Incident) bool {
	if s.db == nil || !s.dbReady || incident == nil {
		return true
	}
	_, err := s.execPostgres(
		`INSERT INTO incidents (
			incident_id, correlation_key, title, severity, status, fired_at,
			resolved_at, alert_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (incident_id) DO UPDATE SET
			correlation_key = EXCLUDED.correlation_key,
			title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			fired_at = EXCLUDED.fired_at,
			resolved_at = EXCLUDED.resolved_at,
			alert_count = EXCLUDED.alert_count,
			updated_at = now()`,
		incident.IncidentID,
		incident.CorrelationKey,
		incident.Title,
		incident.Severity,
		incident.Status,
		incident.FiredAt,
		incident.ResolvedAt,
		incident.AlertCount,
	)
	if err != nil {
		log.Printf("Failed to persist incident %s: %v", incident.IncidentID, err)
		return false
	}
	return true
}

func (s *Store) persistAlertLocked(alert *AlertRecord) bool {
	if s.db == nil || !s.dbReady || alert == nil {
		return true
	}
	_, err := s.execPostgres(
		`INSERT INTO alerts (
			alert_id, incident_id, alarm_title, severity, status, fired_at,
			resolved_at, fingerprint, occurrence_count, occurrence_pods, thread_ts, labels, annotations,
			analysis_summary, analysis_detail, analysis_quality, capabilities,
			missing_data, warnings, artifacts, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20, now()
		)
		ON CONFLICT (alert_id) DO UPDATE SET
			incident_id = EXCLUDED.incident_id,
			alarm_title = EXCLUDED.alarm_title,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			fired_at = EXCLUDED.fired_at,
			resolved_at = EXCLUDED.resolved_at,
			fingerprint = EXCLUDED.fingerprint,
			occurrence_count = EXCLUDED.occurrence_count,
			occurrence_pods = EXCLUDED.occurrence_pods,
			thread_ts = EXCLUDED.thread_ts,
			labels = EXCLUDED.labels,
			annotations = EXCLUDED.annotations,
			analysis_summary = EXCLUDED.analysis_summary,
			analysis_detail = EXCLUDED.analysis_detail,
			analysis_quality = EXCLUDED.analysis_quality,
			capabilities = EXCLUDED.capabilities,
			missing_data = EXCLUDED.missing_data,
			warnings = EXCLUDED.warnings,
			artifacts = EXCLUDED.artifacts,
			updated_at = now()`,
		alert.AlertID,
		alert.IncidentID,
		alert.AlarmTitle,
		alert.Severity,
		alert.Status,
		alert.FiredAt,
		alert.ResolvedAt,
		alert.Fingerprint,
		alert.OccurrenceCount,
		mustJSON(alert.OccurrencePods),
		alert.ThreadTS,
		mustJSON(alert.Labels),
		mustJSON(alert.Annotations),
		alert.AnalysisSummary,
		alert.AnalysisDetail,
		alert.AnalysisQuality,
		mustJSON(alert.Capabilities),
		mustJSON(alert.MissingData),
		mustJSON(alert.Warnings),
		mustJSON(alert.Artifacts),
	)
	if err != nil {
		log.Printf("Failed to persist alert %s: %v", alert.AlertID, err)
		return false
	}
	return true
}

func (s *Store) persistMemoryLocked(memory *IncidentMemory) {
	if s.db == nil || !s.dbReady || memory == nil {
		return
	}
	if s.pgvectorReady {
		_, err := s.execPostgres(
			`INSERT INTO incident_embeddings (
				incident_id, alert_id, title, severity, status, analysis_summary,
				analysis_detail, labels, vector_json, embedding, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::vector, $11, now())
			ON CONFLICT (incident_id, alert_id) DO UPDATE SET
				alert_id = EXCLUDED.alert_id,
				title = EXCLUDED.title,
				severity = EXCLUDED.severity,
				status = EXCLUDED.status,
				analysis_summary = EXCLUDED.analysis_summary,
				analysis_detail = EXCLUDED.analysis_detail,
				labels = EXCLUDED.labels,
				vector_json = EXCLUDED.vector_json,
				embedding = EXCLUDED.embedding,
				updated_at = now()`,
			memory.IncidentID,
			memory.AlertID,
			memory.Title,
			memory.Severity,
			memory.Status,
			memory.AnalysisSummary,
			memory.AnalysisDetail,
			mustJSON(memory.Labels),
			mustJSON(memory.Vector),
			embeddingLiteral(s.embed(memoryText(*memory))),
			memory.CreatedAt,
		)
		if err == nil {
			return
		}
		log.Printf("Failed to persist incident memory %s with pgvector, falling back to jsonb: %v", memory.IncidentID, err)
	}
	_, err := s.execPostgres(
		`INSERT INTO incident_embeddings (
			incident_id, alert_id, title, severity, status, analysis_summary,
			analysis_detail, labels, vector_json, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
		ON CONFLICT (incident_id, alert_id) DO UPDATE SET
			alert_id = EXCLUDED.alert_id,
			title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			analysis_summary = EXCLUDED.analysis_summary,
			analysis_detail = EXCLUDED.analysis_detail,
			labels = EXCLUDED.labels,
			vector_json = EXCLUDED.vector_json,
			updated_at = now()`,
		memory.IncidentID,
		memory.AlertID,
		memory.Title,
		memory.Severity,
		memory.Status,
		memory.AnalysisSummary,
		memory.AnalysisDetail,
		mustJSON(memory.Labels),
		mustJSON(memory.Vector),
		memory.CreatedAt,
	)
	if err != nil {
		log.Printf("Failed to persist incident memory %s: %v", memory.IncidentID, err)
	}
}

func (s *Store) persistFeedbackLocked(record *FeedbackRecord) {
	if s.db == nil || !s.dbReady || record == nil {
		return
	}
	_, err := s.execPostgres(
		`INSERT INTO rca_feedback (
			feedback_id, target_type, target_id, incident_id, alert_id, vote,
			comment, author, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (feedback_id) DO NOTHING`,
		record.FeedbackID,
		record.TargetType,
		record.TargetID,
		record.IncidentID,
		record.AlertID,
		record.Vote,
		record.Comment,
		record.Author,
		record.CreatedAt,
	)
	if err != nil {
		log.Printf("Failed to persist feedback %s: %v", record.FeedbackID, err)
	}
}

func (s *Store) persistFeedbackDeleteForActorLocked(targetType string, targetID string, author string) {
	if s.db == nil || !s.dbReady {
		return
	}
	if _, err := s.execPostgres(
		`DELETE FROM rca_feedback
		  WHERE target_type = $1 AND target_id = $2 AND author = $3`,
		targetType,
		targetID,
		feedbackActor(author),
	); err != nil {
		log.Printf("Failed to delete feedback for %s/%s: %v", targetType, targetID, err)
	}
}

func (s *Store) persistCommentLocked(record *CommentRecord) {
	if s.db == nil || !s.dbReady || record == nil {
		return
	}
	_, err := s.execPostgres(
		`INSERT INTO rca_comments (
			comment_id, target_type, target_id, incident_id, alert_id, body,
			author, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (comment_id) DO NOTHING`,
		record.CommentID,
		record.TargetType,
		record.TargetID,
		record.IncidentID,
		record.AlertID,
		record.Body,
		record.Author,
		record.CreatedAt,
	)
	if err != nil {
		log.Printf("Failed to persist comment %s: %v", record.CommentID, err)
	}
}

func (s *Store) persistCommentUpdateLocked(record *CommentRecord) {
	if s.db == nil || !s.dbReady || record == nil {
		return
	}
	_, err := s.execPostgres(
		`UPDATE rca_comments
		    SET body = $1, author = $2
		  WHERE comment_id = $3`,
		record.Body,
		record.Author,
		record.CommentID,
	)
	if err != nil {
		log.Printf("Failed to update comment %s: %v", record.CommentID, err)
	}
}

func (s *Store) persistCommentDeleteLocked(commentID string) {
	if s.db == nil || !s.dbReady || commentID == "" {
		return
	}
	if _, err := s.execPostgres(`DELETE FROM rca_comments WHERE comment_id = $1`, commentID); err != nil {
		log.Printf("Failed to delete comment %s: %v", commentID, err)
	}
}

func (s *Store) persistAnalysisRunLocked(run *AnalysisRun) bool {
	if s.db == nil || !s.dbReady || run == nil {
		return true
	}
	_, err := s.execPostgres(
		`INSERT INTO analysis_runs (
			run_id, source, status, target_type, target_id, incident_id, alert_id,
			title, prompt, analysis_summary, analysis_detail, analysis_quality,
			capabilities, missing_data, warnings, artifacts, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18
		)
		ON CONFLICT (run_id) DO UPDATE SET
			source = EXCLUDED.source,
			status = EXCLUDED.status,
			target_type = EXCLUDED.target_type,
			target_id = EXCLUDED.target_id,
			incident_id = EXCLUDED.incident_id,
			alert_id = EXCLUDED.alert_id,
			title = EXCLUDED.title,
			prompt = EXCLUDED.prompt,
			analysis_summary = EXCLUDED.analysis_summary,
			analysis_detail = EXCLUDED.analysis_detail,
			analysis_quality = EXCLUDED.analysis_quality,
			capabilities = EXCLUDED.capabilities,
			missing_data = EXCLUDED.missing_data,
			warnings = EXCLUDED.warnings,
			artifacts = EXCLUDED.artifacts,
			updated_at = EXCLUDED.updated_at`,
		run.RunID,
		run.Source,
		run.Status,
		run.TargetType,
		run.TargetID,
		run.IncidentID,
		run.AlertID,
		run.Title,
		run.Prompt,
		run.AnalysisSummary,
		run.AnalysisDetail,
		run.AnalysisQuality,
		mustJSON(run.Capabilities),
		mustJSON(run.MissingData),
		mustJSON(run.Warnings),
		mustJSON(run.Artifacts),
		run.CreatedAt,
		run.UpdatedAt,
	)
	if err != nil {
		log.Printf("Failed to persist analysis run %s: %v", run.RunID, err)
		return false
	}
	return true
}
