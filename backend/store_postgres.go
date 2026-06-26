package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

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
		_ = db.Close()
		log.Printf("Postgres store disabled: ping failed: %v", err)
		return
	}
	s.db = db
	s.dbReady = true
	s.pgvectorReady = s.ensurePostgresSchema(ctx)
	if !s.dbReady {
		_ = db.Close()
		s.db = nil
		s.pgvectorReady = false
		log.Printf("Postgres store disabled: schema initialization failed")
		return
	}
	s.loadDatabaseState(ctx)
	log.Printf(
		"Postgres store enabled for incidents, embeddings, feedback, comments, and analysis runs; %s",
		s.pgvectorLogState(),
	)
}

func (s *Store) ensurePostgresSchema(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	pgvectorReady := true
	if _, err := s.db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		pgvectorReady = false
		log.Printf("pgvector=unavailable, fallback=jsonb: CREATE EXTENSION vector failed: %v", err)
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
		`CREATE TABLE IF NOT EXISTS incident_embeddings (
			incident_id TEXT PRIMARY KEY,
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
					ON CONFLICT (incident_id) DO NOTHING
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
		`CREATE INDEX IF NOT EXISTS idx_embeddings_created_at ON incident_embeddings (created_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			log.Printf("Postgres schema statement failed: %v", err)
			s.dbReady = false
			return pgvectorReady
		}
	}
	return pgvectorReady
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
		        resolved_at, fingerprint, thread_ts, labels, annotations,
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
		if err := rows.Scan(
			&alert.AlertID,
			&alert.IncidentID,
			&alert.AlarmTitle,
			&alert.Severity,
			&alert.Status,
			&alert.FiredAt,
			&alert.ResolvedAt,
			&alert.Fingerprint,
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
		_ = json.Unmarshal(capabilitiesRaw, &alert.Capabilities)
		_ = json.Unmarshal(missingRaw, &alert.MissingData)
		_ = json.Unmarshal(warningsRaw, &alert.Warnings)
		_ = json.Unmarshal(artifactsRaw, &alert.Artifacts)
		s.alerts[alert.AlertID] = &alert
		if alert.Fingerprint != "" {
			s.alertByFinger[alert.Fingerprint] = alert.AlertID
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
		s.memories[memory.IncidentID] = &memory
	}
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

func (s *Store) persistIncidentLocked(incident *Incident) {
	if s.db == nil || !s.dbReady || incident == nil {
		return
	}
	_, err := s.db.ExecContext(
		context.Background(),
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
	}
}

func (s *Store) persistAlertLocked(alert *AlertRecord) {
	if s.db == nil || !s.dbReady || alert == nil {
		return
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`INSERT INTO alerts (
			alert_id, incident_id, alarm_title, severity, status, fired_at,
			resolved_at, fingerprint, thread_ts, labels, annotations,
			analysis_summary, analysis_detail, analysis_quality, capabilities,
			missing_data, warnings, artifacts, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, now()
		)
		ON CONFLICT (alert_id) DO UPDATE SET
			incident_id = EXCLUDED.incident_id,
			alarm_title = EXCLUDED.alarm_title,
			severity = EXCLUDED.severity,
			status = EXCLUDED.status,
			fired_at = EXCLUDED.fired_at,
			resolved_at = EXCLUDED.resolved_at,
			fingerprint = EXCLUDED.fingerprint,
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
	}
}

func (s *Store) persistMemoryLocked(memory *IncidentMemory) {
	if s.db == nil || !s.dbReady || memory == nil {
		return
	}
	_, err := s.db.ExecContext(
		context.Background(),
		`INSERT INTO incident_embeddings (
			incident_id, alert_id, title, severity, status, analysis_summary,
			analysis_detail, labels, vector_json, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
		ON CONFLICT (incident_id) DO UPDATE SET
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
	_, err := s.db.ExecContext(
		context.Background(),
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
	if _, err := s.db.ExecContext(
		context.Background(),
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
	_, err := s.db.ExecContext(
		context.Background(),
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
	_, err := s.db.ExecContext(
		context.Background(),
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
	if _, err := s.db.ExecContext(context.Background(), `DELETE FROM rca_comments WHERE comment_id = $1`, commentID); err != nil {
		log.Printf("Failed to delete comment %s: %v", commentID, err)
	}
}

func (s *Store) persistAnalysisRunLocked(run *AnalysisRun) {
	if s.db == nil || !s.dbReady || run == nil {
		return
	}
	_, err := s.db.ExecContext(
		context.Background(),
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
	}
}
