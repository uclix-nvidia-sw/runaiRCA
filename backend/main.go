package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type AlertmanagerWebhook struct {
	GroupKey          string            `json:"groupKey"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     string            `json:"startsAt"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

type Artifact struct {
	Agent      string `json:"agent"`
	Source     string `json:"source"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	Query      string `json:"query,omitempty"`
	Result     any    `json:"result,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

type SimilarIncident struct {
	IncidentID       string            `json:"incident_id"`
	AlertID          string            `json:"alert_id,omitempty"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Status           string            `json:"status"`
	Similarity       float64           `json:"similarity"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail,omitempty"`
	PositiveFeedback int               `json:"positive_feedback"`
	NegativeFeedback int               `json:"negative_feedback"`
	CommentCount     int               `json:"comment_count"`
	Labels           map[string]string `json:"labels,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

type FeedbackHint struct {
	SourceID  string  `json:"source_id"`
	Sentiment string  `json:"sentiment"`
	Weight    float64 `json:"weight"`
	Text      string  `json:"text"`
}

type FeedbackRecord struct {
	FeedbackID string    `json:"feedback_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	IncidentID string    `json:"incident_id,omitempty"`
	AlertID    string    `json:"alert_id,omitempty"`
	Vote       string    `json:"vote"`
	Comment    string    `json:"comment,omitempty"`
	Author     string    `json:"author,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type CommentRecord struct {
	CommentID  string    `json:"comment_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	IncidentID string    `json:"incident_id,omitempty"`
	AlertID    string    `json:"alert_id,omitempty"`
	Body       string    `json:"body"`
	Author     string    `json:"author,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type FeedbackSummary struct {
	TargetType    string          `json:"target_type"`
	TargetID      string          `json:"target_id"`
	Positive      int             `json:"positive"`
	Negative      int             `json:"negative"`
	MyVote        string          `json:"my_vote,omitempty"`
	Comments      []CommentRecord `json:"comments"`
	LearningHints []FeedbackHint  `json:"learning_hints,omitempty"`
}

type AnalysisRun struct {
	RunID           string            `json:"run_id"`
	Source          string            `json:"source"`
	Status          string            `json:"status"`
	TargetType      string            `json:"target_type"`
	TargetID        string            `json:"target_id"`
	IncidentID      string            `json:"incident_id,omitempty"`
	AlertID         string            `json:"alert_id,omitempty"`
	Title           string            `json:"title"`
	Prompt          string            `json:"prompt,omitempty"`
	AnalysisSummary string            `json:"analysis_summary"`
	AnalysisDetail  string            `json:"analysis_detail"`
	AnalysisQuality string            `json:"analysis_quality"`
	Capabilities    map[string]string `json:"capabilities"`
	MissingData     []string          `json:"missing_data"`
	Warnings        []string          `json:"warnings"`
	Artifacts       []Artifact        `json:"artifacts"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type FeedbackRequest struct {
	Vote     string `json:"vote"`
	VoteType string `json:"vote_type,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Author   string `json:"author,omitempty"`
}

type CommentRequest struct {
	Body   string `json:"body"`
	Author string `json:"author,omitempty"`
}

type EmbeddingSearchRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type EmbeddingSearchResponse struct {
	Model   string            `json:"model"`
	Results []SimilarIncident `json:"results"`
}

type IncidentMemory struct {
	IncidentID      string
	AlertID         string
	Title           string
	Severity        string
	Status          string
	AnalysisSummary string
	AnalysisDetail  string
	Labels          map[string]string
	CreatedAt       time.Time
	Vector          map[string]float64
}

type Incident struct {
	IncidentID     string     `json:"incident_id"`
	CorrelationKey string     `json:"correlation_key"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	FiredAt        time.Time  `json:"fired_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AlertCount     int        `json:"alert_count"`
	IsAnalyzing    bool       `json:"is_analyzing"`
}

type AlertRecord struct {
	AlertID          string            `json:"alert_id"`
	IncidentID       string            `json:"incident_id"`
	AlarmTitle       string            `json:"alarm_title"`
	Severity         string            `json:"severity"`
	Status           string            `json:"status"`
	FiredAt          time.Time         `json:"fired_at"`
	ResolvedAt       *time.Time        `json:"resolved_at"`
	Fingerprint      string            `json:"fingerprint"`
	ThreadTS         string            `json:"thread_ts"`
	Labels           map[string]string `json:"labels"`
	Annotations      map[string]string `json:"annotations"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail"`
	AnalysisQuality  string            `json:"analysis_quality"`
	Capabilities     map[string]string `json:"capabilities"`
	MissingData      []string          `json:"missing_data"`
	Warnings         []string          `json:"warnings"`
	Artifacts        []Artifact        `json:"artifacts"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents,omitempty"`
	Feedback         FeedbackSummary   `json:"feedback"`
	IsAnalyzing      bool              `json:"is_analyzing"`
}

type IncidentDetail struct {
	Incident
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail"`
	AnalysisQuality  string            `json:"analysis_quality"`
	Capabilities     map[string]string `json:"capabilities"`
	MissingData      []string          `json:"missing_data"`
	Warnings         []string          `json:"warnings"`
	Artifacts        []Artifact        `json:"artifacts"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents,omitempty"`
	Feedback         FeedbackSummary   `json:"feedback"`
	Alerts           []AlertRecord     `json:"alerts"`
}

type AgentAnalysisRequest struct {
	Alert            Alert             `json:"alert"`
	ThreadTS         string            `json:"thread_ts"`
	IncidentID       string            `json:"incident_id,omitempty"`
	AnalysisType     string            `json:"analysis_type,omitempty"`
	Language         string            `json:"language,omitempty"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents,omitempty"`
	FeedbackHints    []FeedbackHint    `json:"feedback_hints,omitempty"`
}

type AgentAnalysisResponse struct {
	Status          string            `json:"status"`
	ThreadTS        string            `json:"thread_ts"`
	Analysis        string            `json:"analysis"`
	AnalysisSummary string            `json:"analysis_summary"`
	AnalysisDetail  string            `json:"analysis_detail"`
	AnalysisType    string            `json:"analysis_type"`
	AnalysisQuality string            `json:"analysis_quality"`
	MissingData     []string          `json:"missing_data"`
	Warnings        []string          `json:"warnings"`
	Capabilities    map[string]string `json:"capabilities"`
	Context         map[string]any    `json:"context"`
	Artifacts       []Artifact        `json:"artifacts"`
}

type ChatRequest struct {
	Message         string         `json:"message"`
	ConversationID  string         `json:"conversation_id,omitempty"`
	Language        string         `json:"language,omitempty"`
	Page            string         `json:"page,omitempty"`
	Auto            bool           `json:"auto,omitempty"`
	IncidentID      string         `json:"incident_id,omitempty"`
	AlertID         string         `json:"alert_id,omitempty"`
	IncidentTitle   string         `json:"incident_title,omitempty"`
	IncidentContent string         `json:"incident_content,omitempty"`
	AlertTitle      string         `json:"alert_title,omitempty"`
	AlertContent    string         `json:"alert_content,omitempty"`
	Context         map[string]any `json:"context,omitempty"`
}

type ChatResponse struct {
	Status         string       `json:"status"`
	Answer         string       `json:"answer"`
	Message        string       `json:"message,omitempty"`
	Response       string       `json:"response,omitempty"`
	ConversationID string       `json:"conversation_id"`
	AnalysisRun    *AnalysisRun `json:"analysis_run,omitempty"`
}

type Event struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type Store struct {
	mu             sync.RWMutex
	incidentSeq    atomic.Int64
	alertSeq       atomic.Int64
	feedbackSeq    atomic.Int64
	commentSeq     atomic.Int64
	analysisRunSeq atomic.Int64
	incidents      map[string]*Incident
	incidentByKey  map[string]string
	alerts         map[string]*AlertRecord
	alertByFinger  map[string]string
	memories       map[string]*IncidentMemory
	feedback       map[string]*FeedbackRecord
	comments       map[string]*CommentRecord
	analysisRuns   map[string]*AnalysisRun
	db             *sql.DB
	dbReady        bool
	pgvectorReady  bool
}

func NewStore() *Store {
	return &Store{
		incidents:     make(map[string]*Incident),
		incidentByKey: make(map[string]string),
		alerts:        make(map[string]*AlertRecord),
		alertByFinger: make(map[string]string),
		memories:      make(map[string]*IncidentMemory),
		feedback:      make(map[string]*FeedbackRecord),
		comments:      make(map[string]*CommentRecord),
		analysisRuns:  make(map[string]*AnalysisRun),
	}
}

func (s *Store) ConnectDatabase(databaseURL string, connectTimeout time.Duration) {
	databaseURL = strings.TrimSpace(databaseURL)
	if databaseURL == "" {
		return
	}
	if connectTimeout <= 0 {
		connectTimeout = 5 * time.Second
	}
	db, err := sql.Open("pgx", databaseURL)
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
	s.loadDatabaseState(ctx)
	log.Printf(
		"Postgres store enabled for incidents, embeddings, feedback, comments, and analysis runs; pgvector=%t",
		s.pgvectorReady,
	)
}

func (s *Store) ensurePostgresSchema(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	pgvectorReady := true
	if _, err := s.db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		pgvectorReady = false
		log.Printf("pgvector extension is unavailable; using JSONB memory vectors: %v", err)
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

func (s *Store) UpsertAlert(webhook AlertmanagerWebhook, alert Alert) (*Incident, *AlertRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.Labels == nil {
		alert.Labels = map[string]string{}
	}
	if alert.Annotations == nil {
		alert.Annotations = map[string]string{}
	}
	key := correlationKey(webhook, alert)
	incidentID := s.incidentByKey[key]
	now := time.Now().UTC()
	if incidentID == "" {
		incidentID = nextID("INC", s.incidentSeq.Add(1))
		s.incidentByKey[key] = incidentID
		s.incidents[incidentID] = &Incident{
			IncidentID:     incidentID,
			CorrelationKey: key,
			Title:          incidentTitle(alert),
			Severity:       severity(alert),
			Status:         "firing",
			FiredAt:        firstTime(alert.StartsAt, now),
		}
	}
	incident := s.incidents[incidentID]
	incident.AlertCount++
	incident.Severity = maxSeverity(incident.Severity, severity(alert))
	if alert.Status == "resolved" && incident.ResolvedAt == nil {
		t := firstTime(alert.EndsAt, now)
		incident.ResolvedAt = &t
		incident.Status = "resolved"
	}

	alertID := s.alertByFinger[alert.Fingerprint]
	if alertID == "" {
		alertID = nextID("ALR", s.alertSeq.Add(1))
		s.alertByFinger[alert.Fingerprint] = alertID
	}
	record := s.alerts[alertID]
	if record == nil {
		record = &AlertRecord{AlertID: alertID}
		s.alerts[alertID] = record
	}
	record.IncidentID = incidentID
	record.AlarmTitle = incidentTitle(alert)
	record.Severity = severity(alert)
	record.Status = status(alert.Status)
	record.FiredAt = firstTime(alert.StartsAt, now)
	record.Fingerprint = alert.Fingerprint
	record.ThreadTS = "thread-" + alertID
	record.Labels = cloneMap(alert.Labels)
	record.Annotations = cloneMap(alert.Annotations)
	record.IsAnalyzing = true
	if alert.Status == "resolved" {
		t := firstTime(alert.EndsAt, now)
		record.ResolvedAt = &t
	}
	s.persistIncidentLocked(incident)
	s.persistAlertLocked(record)
	return cloneIncident(incident), cloneAlert(record)
}

func (s *Store) ListIncidents() []Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		items = append(items, *cloneIncident(incident))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FiredAt.After(items[j].FiredAt) })
	return items
}

func (s *Store) ListAlerts() []AlertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AlertRecord, 0, len(s.alerts))
	for _, alert := range s.alerts {
		copied := cloneAlert(alert)
		copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, 5)
		items = append(items, *copied)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FiredAt.After(items[j].FiredAt) })
	return items
}

func (s *Store) ListAnalysisRuns() []AnalysisRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AnalysisRun, 0, len(s.analysisRuns))
	for _, run := range s.analysisRuns {
		items = append(items, cloneAnalysisRun(run))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
}

func (s *Store) CreateAnalysisRun(
	source string,
	targetType string,
	targetID string,
	incidentID string,
	alertID string,
	title string,
	prompt string,
) AnalysisRun {
	now := time.Now().UTC()
	run := &AnalysisRun{
		RunID:        nextID("ANL", s.analysisRunSeq.Add(1)),
		Source:       first(source, "manual"),
		Status:       "analyzing",
		TargetType:   targetType,
		TargetID:     targetID,
		IncidentID:   incidentID,
		AlertID:      alertID,
		Title:        first(title, "RCA analysis request"),
		Prompt:       strings.TrimSpace(prompt),
		Capabilities: map[string]string{},
		MissingData:  []string{},
		Warnings:     []string{},
		Artifacts:    []Artifact{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analysisRuns[run.RunID] = run
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run)
}

func (s *Store) CompleteAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
	run.Status = "complete"
	run.AnalysisSummary = response.AnalysisSummary
	run.AnalysisDetail = response.AnalysisDetail
	if run.AnalysisDetail == "" {
		run.AnalysisDetail = response.Analysis
	}
	run.AnalysisQuality = response.AnalysisQuality
	run.Capabilities = response.Capabilities
	run.MissingData = response.MissingData
	run.Warnings = response.Warnings
	run.Artifacts = response.Artifacts
	run.UpdatedAt = time.Now().UTC()
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run), true
}

func (s *Store) FailAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
	run.Status = "failed"
	run.AnalysisSummary = response.AnalysisSummary
	run.AnalysisDetail = response.AnalysisDetail
	if run.AnalysisDetail == "" {
		run.AnalysisDetail = response.Analysis
	}
	run.AnalysisQuality = first(response.AnalysisQuality, "low")
	run.Capabilities = response.Capabilities
	run.MissingData = response.MissingData
	run.Warnings = response.Warnings
	run.Artifacts = response.Artifacts
	run.UpdatedAt = time.Now().UTC()
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run), true
}

func (s *Store) AnalysisTarget(targetType string, targetID string) (Alert, string, string, string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch targetType {
	case "alert":
		alert := s.alerts[targetID]
		if alert == nil {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*alert), alert.IncidentID, alert.AlertID, alert.ThreadTS, alert.AlarmTitle, true
	case "incident":
		incident := s.incidents[targetID]
		if incident == nil {
			return Alert{}, "", "", "", "", false
		}
		var selected *AlertRecord
		for _, alert := range s.alerts {
			if alert.IncidentID != targetID {
				continue
			}
			if selected == nil || alert.FiredAt.After(selected.FiredAt) {
				selected = alert
			}
		}
		if selected == nil {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*selected), incident.IncidentID, selected.AlertID, selected.ThreadTS, incident.Title, true
	default:
		return Alert{}, "", "", "", "", false
	}
}

func (s *Store) IncidentDetail(id string) (*IncidentDetail, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	incident := s.incidents[id]
	if incident == nil {
		return nil, false
	}
	detail := &IncidentDetail{Incident: *cloneIncident(incident)}
	detail.Capabilities = map[string]string{}
	for _, alert := range s.alerts {
		if alert.IncidentID != id {
			continue
		}
		copied := cloneAlert(alert)
		detail.Alerts = append(detail.Alerts, *copied)
		if detail.AnalysisSummary == "" && copied.AnalysisSummary != "" {
			detail.AnalysisSummary = copied.AnalysisSummary
			detail.AnalysisDetail = copied.AnalysisDetail
			detail.AnalysisQuality = copied.AnalysisQuality
			detail.Capabilities = cloneMap(copied.Capabilities)
			detail.MissingData = append([]string{}, copied.MissingData...)
			detail.Warnings = append([]string{}, copied.Warnings...)
			detail.Artifacts = append([]Artifact{}, copied.Artifacts...)
		}
	}
	sort.Slice(detail.Alerts, func(i, j int) bool {
		return detail.Alerts[i].FiredAt.After(detail.Alerts[j].FiredAt)
	})
	detail.Feedback = s.feedbackSummaryLocked("incident", id)
	if len(detail.Alerts) > 0 {
		detail.SimilarIncidents = s.similarIncidentsLocked(
			alertFromRecord(detail.Alerts[0]),
			id,
			5,
		)
	}
	return detail, true
}

func (s *Store) AlertDetail(id string) (*AlertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert := s.alerts[id]
	if alert == nil {
		return nil, false
	}
	copied := cloneAlert(alert)
	copied.Feedback = s.feedbackSummaryLocked("alert", id)
	copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, 5)
	return copied, true
}

func (s *Store) AddFeedback(
	targetType string,
	targetID string,
	req FeedbackRequest,
) (FeedbackSummary, bool, error) {
	rawVote := strings.TrimSpace(first(req.Vote, req.VoteType))
	vote := normalizeVote(rawVote)
	actor := feedbackActor(req.Author)
	if strings.EqualFold(rawVote, "none") {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
			return FeedbackSummary{}, false, nil
		}
		s.deleteFeedbackForActorLocked(targetType, targetID, actor)
		return s.feedbackSummaryForActorLocked(targetType, targetID, actor), true, nil
	}
	if vote == "" {
		return FeedbackSummary{}, false, errors.New("vote must be up or down")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incidentID, alertID, ok := s.targetIDsLocked(targetType, targetID)
	if !ok {
		return FeedbackSummary{}, false, nil
	}
	s.deleteFeedbackForActorLocked(targetType, targetID, actor)
	record := &FeedbackRecord{
		FeedbackID: nextID("FDB", s.feedbackSeq.Add(1)),
		TargetType: targetType,
		TargetID:   targetID,
		IncidentID: incidentID,
		AlertID:    alertID,
		Vote:       vote,
		Comment:    strings.TrimSpace(req.Comment),
		Author:     actor,
		CreatedAt:  time.Now().UTC(),
	}
	s.feedback[record.FeedbackID] = record
	s.persistFeedbackLocked(record)
	if record.Comment != "" {
		comment := &CommentRecord{
			CommentID:  nextID("CMT", s.commentSeq.Add(1)),
			TargetType: targetType,
			TargetID:   targetID,
			IncidentID: incidentID,
			AlertID:    alertID,
			Body:       record.Comment,
			Author:     record.Author,
			CreatedAt:  record.CreatedAt,
		}
		s.comments[comment.CommentID] = comment
		s.persistCommentLocked(comment)
	}
	return s.feedbackSummaryForActorLocked(targetType, targetID, actor), true, nil
}

func (s *Store) AddComment(
	targetType string,
	targetID string,
	req CommentRequest,
) (FeedbackSummary, bool, error) {
	body := strings.TrimSpace(req.Body)
	if body == "" {
		return FeedbackSummary{}, false, errors.New("comment body is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incidentID, alertID, ok := s.targetIDsLocked(targetType, targetID)
	if !ok {
		return FeedbackSummary{}, false, nil
	}
	comment := &CommentRecord{
		CommentID:  nextID("CMT", s.commentSeq.Add(1)),
		TargetType: targetType,
		TargetID:   targetID,
		IncidentID: incidentID,
		AlertID:    alertID,
		Body:       body,
		Author:     strings.TrimSpace(req.Author),
		CreatedAt:  time.Now().UTC(),
	}
	s.comments[comment.CommentID] = comment
	s.persistCommentLocked(comment)
	return s.feedbackSummaryLocked(targetType, targetID), true, nil
}

func (s *Store) UpdateComment(
	targetType string,
	targetID string,
	commentID string,
	req CommentRequest,
) (FeedbackSummary, bool, error) {
	body := strings.TrimSpace(req.Body)
	if body == "" {
		return FeedbackSummary{}, false, errors.New("comment body is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
		return FeedbackSummary{}, false, nil
	}
	comment := s.comments[commentID]
	if comment == nil || comment.TargetType != targetType || comment.TargetID != targetID {
		return FeedbackSummary{}, false, nil
	}
	comment.Body = body
	if author := strings.TrimSpace(req.Author); author != "" {
		comment.Author = author
	}
	s.persistCommentUpdateLocked(comment)
	return s.feedbackSummaryLocked(targetType, targetID), true, nil
}

func (s *Store) DeleteComment(
	targetType string,
	targetID string,
	commentID string,
) (FeedbackSummary, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
		return FeedbackSummary{}, false
	}
	comment := s.comments[commentID]
	if comment == nil || comment.TargetType != targetType || comment.TargetID != targetID {
		return FeedbackSummary{}, false
	}
	delete(s.comments, commentID)
	s.persistCommentDeleteLocked(commentID)
	return s.feedbackSummaryLocked(targetType, targetID), true
}

func (s *Store) SimilarIncidentsForAlert(alert Alert, incidentID string, limit int) []SimilarIncident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.similarIncidentsLocked(alert, incidentID, limit)
}

func (s *Store) FeedbackHintsForAlert(alert Alert, incidentID string, limit int) []FeedbackHint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	similar := s.similarIncidentsLocked(alert, incidentID, limit)
	hints := make([]FeedbackHint, 0, limit)
	for _, item := range similar {
		if item.PositiveFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "positive",
				Weight:    item.Similarity,
				Text:      fmt.Sprintf("Operators found this prior RCA useful: %s", item.AnalysisSummary),
			})
		}
		if item.NegativeFeedback > 0 {
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "negative",
				Weight:    item.Similarity,
				Text:      fmt.Sprintf("Operators pushed back on this prior RCA: %s", item.AnalysisSummary),
			})
		}
		for _, comment := range s.commentsForTargetLocked("incident", item.IncidentID) {
			if len(hints) >= limit {
				return hints
			}
			hints = append(hints, FeedbackHint{
				SourceID:  item.IncidentID,
				Sentiment: "comment",
				Weight:    item.Similarity,
				Text:      comment.Body,
			})
		}
		if len(hints) >= limit {
			return hints
		}
	}
	return hints
}

func (s *Store) SearchIncidentMemory(query string, limit int) []SimilarIncident {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	queryVector := textVector(query)
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil {
			continue
		}
		score := cosineSimilarity(queryVector, memory.Vector)
		if score <= 0.05 {
			continue
		}
		summary := s.feedbackSummaryLocked("incident", memory.IncidentID)
		results = append(results, SimilarIncident{
			IncidentID:       memory.IncidentID,
			AlertID:          memory.AlertID,
			Title:            memory.Title,
			Severity:         memory.Severity,
			Status:           memory.Status,
			Similarity:       math.Round(score*1000) / 1000,
			AnalysisSummary:  memory.AnalysisSummary,
			AnalysisDetail:   excerpt(memory.AnalysisDetail, 900),
			PositiveFeedback: summary.Positive,
			NegativeFeedback: summary.Negative,
			CommentCount:     len(summary.Comments),
			Labels:           cloneMap(memory.Labels),
			CreatedAt:        memory.CreatedAt,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Similarity == results[j].Similarity {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		}
		return results[i].Similarity > results[j].Similarity
	})
	if len(results) > limit {
		return results[:limit]
	}
	return results
}

func (s *Store) ApplyAnalysis(alertID string, response AgentAnalysisResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[alertID]
	if alert == nil {
		return
	}
	alert.AnalysisSummary = response.AnalysisSummary
	alert.AnalysisDetail = response.AnalysisDetail
	if alert.AnalysisDetail == "" {
		alert.AnalysisDetail = response.Analysis
	}
	alert.AnalysisQuality = response.AnalysisQuality
	alert.Capabilities = response.Capabilities
	alert.MissingData = response.MissingData
	alert.Warnings = response.Warnings
	alert.Artifacts = response.Artifacts
	alert.IsAnalyzing = false
	if incident := s.incidents[alert.IncidentID]; incident != nil {
		incident.IsAnalyzing = false
		s.upsertMemoryLocked(incident, alert)
		s.persistIncidentLocked(incident)
	}
	s.persistAlertLocked(alert)
}

func (s *Store) MarkAnalyzing(incidentID string, analyzing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = analyzing
	}
}

func (s *Store) upsertMemoryLocked(incident *Incident, alert *AlertRecord) {
	if strings.TrimSpace(alert.AnalysisSummary) == "" && strings.TrimSpace(alert.AnalysisDetail) == "" {
		return
	}
	memory := &IncidentMemory{
		IncidentID:      incident.IncidentID,
		AlertID:         alert.AlertID,
		Title:           incident.Title,
		Severity:        incident.Severity,
		Status:          incident.Status,
		AnalysisSummary: alert.AnalysisSummary,
		AnalysisDetail:  alert.AnalysisDetail,
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
	}
	memory.Vector = textVector(memoryText(*memory))
	s.memories[memory.IncidentID] = memory
	s.persistMemoryLocked(memory)
}

func (s *Store) similarIncidentsLocked(
	alert Alert,
	currentIncidentID string,
	limit int,
) []SimilarIncident {
	if limit <= 0 {
		limit = 5
	}
	queryVector := textVector(alertSearchText(alert))
	results := make([]SimilarIncident, 0, len(s.memories))
	for _, memory := range s.memories {
		if memory == nil || memory.IncidentID == currentIncidentID {
			continue
		}
		score := cosineSimilarity(queryVector, memory.Vector)
		score += labelSimilarityBonus(alert.Labels, memory.Labels)
		if score <= 0.05 {
			continue
		}
		if score > 1 {
			score = 1
		}
		summary := s.feedbackSummaryLocked("incident", memory.IncidentID)
		results = append(results, SimilarIncident{
			IncidentID:       memory.IncidentID,
			AlertID:          memory.AlertID,
			Title:            memory.Title,
			Severity:         memory.Severity,
			Status:           memory.Status,
			Similarity:       math.Round(score*1000) / 1000,
			AnalysisSummary:  memory.AnalysisSummary,
			AnalysisDetail:   excerpt(memory.AnalysisDetail, 900),
			PositiveFeedback: summary.Positive,
			NegativeFeedback: summary.Negative,
			CommentCount:     len(summary.Comments),
			Labels:           cloneMap(memory.Labels),
			CreatedAt:        memory.CreatedAt,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Similarity == results[j].Similarity {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		}
		return results[i].Similarity > results[j].Similarity
	})
	if len(results) > limit {
		return results[:limit]
	}
	return results
}

func (s *Store) feedbackSummaryLocked(targetType string, targetID string) FeedbackSummary {
	summary := FeedbackSummary{
		TargetType: targetType,
		TargetID:   targetID,
		Comments:   s.commentsForTargetLocked(targetType, targetID),
	}
	for _, record := range s.feedback {
		if record.TargetType != targetType || record.TargetID != targetID {
			continue
		}
		switch record.Vote {
		case "up":
			summary.Positive++
		case "down":
			summary.Negative++
		}
	}
	if summary.Positive > 0 {
		summary.LearningHints = append(summary.LearningHints, FeedbackHint{
			SourceID:  targetID,
			Sentiment: "positive",
			Weight:    float64(summary.Positive),
			Text:      "Operators marked this RCA as useful.",
		})
	}
	if summary.Negative > 0 {
		summary.LearningHints = append(summary.LearningHints, FeedbackHint{
			SourceID:  targetID,
			Sentiment: "negative",
			Weight:    float64(summary.Negative),
			Text:      "Operators marked this RCA as needing correction.",
		})
	}
	return summary
}

func (s *Store) feedbackSummaryForActorLocked(targetType string, targetID string, author string) FeedbackSummary {
	summary := s.feedbackSummaryLocked(targetType, targetID)
	if record := s.feedbackForActorLocked(targetType, targetID, author); record != nil {
		summary.MyVote = record.Vote
	}
	return summary
}

func (s *Store) feedbackForActorLocked(targetType string, targetID string, author string) *FeedbackRecord {
	actor := feedbackActor(author)
	for _, record := range s.feedback {
		if record.TargetType == targetType && record.TargetID == targetID && feedbackActor(record.Author) == actor {
			return record
		}
	}
	return nil
}

func (s *Store) deleteFeedbackForActorLocked(targetType string, targetID string, author string) {
	actor := feedbackActor(author)
	for feedbackID, record := range s.feedback {
		if record.TargetType == targetType && record.TargetID == targetID && feedbackActor(record.Author) == actor {
			delete(s.feedback, feedbackID)
		}
	}
	s.persistFeedbackDeleteForActorLocked(targetType, targetID, actor)
}

func (s *Store) commentsForTargetLocked(targetType string, targetID string) []CommentRecord {
	items := []CommentRecord{}
	for _, comment := range s.comments {
		if comment.TargetType == targetType && comment.TargetID == targetID {
			items = append(items, *cloneComment(comment))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items
}

func (s *Store) targetIDsLocked(targetType string, targetID string) (string, string, bool) {
	switch targetType {
	case "incident":
		if s.incidents[targetID] == nil {
			return "", "", false
		}
		return targetID, "", true
	case "alert":
		alert := s.alerts[targetID]
		if alert == nil {
			return "", "", false
		}
		return alert.IncidentID, alert.AlertID, true
	default:
		return "", "", false
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

type Hub struct {
	mu      sync.Mutex
	clients map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan Event]struct{})}
}

func (h *Hub) Subscribe() chan Event {
	ch := make(chan Event, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	delete(h.clients, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *Hub) Broadcast(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
		}
	}
}

type Server struct {
	store    *Store
	hub      *Hub
	agentURL string
	language string
	client   *http.Client
}

func main() {
	port := getenv("PORT", "8080")
	server := NewServer()
	log.Printf("Run:AI RCA backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, server.routes()); err != nil {
		log.Fatal(err)
	}
}

func NewServer() *Server {
	store := NewStore()
	store.ConnectDatabase(
		first(os.Getenv("DATABASE_URL"), os.Getenv("POSTGRES_DSN")),
		time.Duration(getenvInt("DATABASE_CONNECT_TIMEOUT_SECONDS", 5))*time.Second,
	)
	return &Server{
		store:    store,
		hub:      NewHub(),
		agentURL: strings.TrimRight(getenv("AGENT_URL", "http://localhost:8000"), "/"),
		language: getenv("LANGUAGE", "en"),
		client:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return cors(mux)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/":
		writeJSON(w, http.StatusOK, map[string]string{"service": "runai-rca-backend", "status": "ok"})
	case r.Method == http.MethodGet && r.URL.Path == "/ping":
		_, _ = w.Write([]byte("pong"))
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.Method == http.MethodPost && r.URL.Path == "/webhook/alertmanager":
		s.handleAlertmanager(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/incidents":
		writeJSON(w, http.StatusOK, envelope(s.store.ListIncidents()))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncident(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncidentAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/alerts":
		writeJSON(w, http.StatusOK, envelope(s.store.ListAlerts()))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlert(w, r)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlertAction(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/embeddings/search":
		s.handleEmbeddingSearch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/analysis-runs":
		writeJSON(w, http.StatusOK, envelope(s.store.ListAnalysisRuns()))
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/events":
		s.handleEvents(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/chat":
		s.handleChat(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *Server) handleAlertmanager(w http.ResponseWriter, r *http.Request) {
	var webhook AlertmanagerWebhook
	if err := json.NewDecoder(r.Body).Decode(&webhook); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	created := 0
	for _, alert := range webhook.Alerts {
		incident, record := s.store.UpsertAlert(webhook, alert)
		created++
		s.hub.Broadcast(Event{Type: "alert.created", Data: map[string]any{
			"incident_id": incident.IncidentID,
			"alert_id":    record.AlertID,
		}})
		go s.requestAnalysis(alert, incident.IncidentID, record.AlertID, record.ThreadTS)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "alerts": created})
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if id == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident id required"})
		return
	}
	if len(parts) == 2 && parts[1] == "feedback" {
		if _, ok := s.store.IncidentDetail(id); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		s.store.mu.RLock()
		summary := s.store.feedbackSummaryForActorLocked("incident", id, r.URL.Query().Get("feedback_author"))
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, envelope(summary))
		return
	}
	if len(parts) > 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
		return
	}
	if detail, ok := s.store.IncidentDetail(id); ok {
		if actor := r.URL.Query().Get("feedback_author"); actor != "" {
			s.store.mu.RLock()
			detail.Feedback = s.store.feedbackSummaryForActorLocked("incident", id, actor)
			for i := range detail.Alerts {
				detail.Alerts[i].Feedback = s.store.feedbackSummaryForActorLocked("alert", detail.Alerts[i].AlertID, actor)
			}
			s.store.mu.RUnlock()
		}
		writeJSON(w, http.StatusOK, envelope(detail))
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
}

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "analyze":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
			return
		}
		detail, ok := s.store.IncidentDetail(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		s.store.MarkAnalyzing(id, true)
		for _, alert := range detail.Alerts {
			go s.requestAnalysis(Alert{
				Status:      alert.Status,
				Labels:      alert.Labels,
				Annotations: alert.Annotations,
				Fingerprint: alert.Fingerprint,
			}, id, alert.AlertID, alert.ThreadTS)
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "analysis_requested"})
	case "resolve":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
			return
		}
		now := time.Now().UTC()
		s.store.mu.Lock()
		if incident := s.store.incidents[id]; incident != nil {
			incident.Status = "resolved"
			incident.ResolvedAt = &now
			s.store.persistIncidentLocked(incident)
			if memory := s.store.memories[id]; memory != nil {
				memory.Status = "resolved"
				s.store.persistMemoryLocked(memory)
			}
		}
		s.store.mu.Unlock()
		s.hub.Broadcast(Event{Type: "incident.resolved", Data: map[string]any{"incident_id": id}})
		writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
	case "feedback":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
			return
		}
		s.handleFeedback(w, r, "incident", id)
	case "vote":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
			return
		}
		s.handleFeedback(w, r, "incident", id)
	case "comments":
		s.handleCommentAction(w, r, "incident", id, parts)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
	}
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/alerts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if len(parts) == 2 && parts[1] == "feedback" {
		if _, ok := s.store.AlertDetail(id); !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
			return
		}
		s.store.mu.RLock()
		summary := s.store.feedbackSummaryForActorLocked("alert", id, r.URL.Query().Get("feedback_author"))
		s.store.mu.RUnlock()
		writeJSON(w, http.StatusOK, envelope(summary))
		return
	}
	if len(parts) > 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown alert action"})
		return
	}
	if alert, ok := s.store.AlertDetail(id); ok {
		if actor := r.URL.Query().Get("feedback_author"); actor != "" {
			s.store.mu.RLock()
			alert.Feedback = s.store.feedbackSummaryForActorLocked("alert", id, actor)
			s.store.mu.RUnlock()
		}
		writeJSON(w, http.StatusOK, envelope(alert))
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
}

func (s *Server) handleAlertAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/alerts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown alert action"})
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "feedback":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown alert action"})
			return
		}
		s.handleFeedback(w, r, "alert", id)
	case "vote":
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown alert action"})
			return
		}
		s.handleFeedback(w, r, "alert", id)
	case "comments":
		s.handleCommentAction(w, r, "alert", id, parts)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown alert action"})
	}
}

func (s *Server) handleFeedback(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
) {
	var req FeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Author) == "" {
		req.Author = r.URL.Query().Get("feedback_author")
	}
	summary, ok, err := s.store.AddFeedback(targetType, targetID, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	s.hub.Broadcast(Event{Type: "feedback.updated", Data: map[string]any{
		"target_type": targetType,
		"target_id":   targetID,
	}})
	if strings.TrimSpace(req.Comment) != "" {
		s.startAnalysisRun(targetType, targetID, "feedback", req.Comment)
	}
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleComment(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
) {
	var req CommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	summary, ok, err := s.store.AddComment(targetType, targetID, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	s.hub.Broadcast(Event{Type: "feedback.updated", Data: map[string]any{
		"target_type": targetType,
		"target_id":   targetID,
	}})
	s.startAnalysisRun(targetType, targetID, "comment", req.Body)
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleCommentAction(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	parts []string,
) {
	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		s.handleComment(w, r, targetType, targetID)
	case len(parts) == 3 && r.Method == http.MethodPut:
		s.handleCommentUpdate(w, r, targetType, targetID, parts[2])
	case len(parts) == 3 && r.Method == http.MethodDelete:
		s.handleCommentDelete(w, r, targetType, targetID, parts[2])
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown comment action"})
	}
}

func (s *Server) handleCommentUpdate(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	commentID string,
) {
	var req CommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	summary, ok, err := s.store.UpdateComment(targetType, targetID, commentID, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "comment not found"})
		return
	}
	s.hub.Broadcast(Event{Type: "feedback.updated", Data: map[string]any{
		"target_type": targetType,
		"target_id":   targetID,
	}})
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleCommentDelete(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	commentID string,
) {
	summary, ok := s.store.DeleteComment(targetType, targetID, commentID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "comment not found"})
		return
	}
	s.hub.Broadcast(Event{Type: "feedback.updated", Data: map[string]any{
		"target_type": targetType,
		"target_id":   targetID,
	}})
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleEmbeddingSearch(w http.ResponseWriter, r *http.Request) {
	var req EmbeddingSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query is required"})
		return
	}
	results := s.store.SearchIncidentMemory(query, req.Limit)
	writeJSON(w, http.StatusOK, envelope(EmbeddingSearchResponse{
		Model:   "local-term-frequency",
		Results: results,
	}))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)
	writeSSE(w, Event{Type: "connected", Data: map[string]any{"status": "ok"}})
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			writeSSE(w, event)
			flusher.Flush()
		}
	}
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message is required"})
		return
	}
	req = s.enrichChatRequest(req)
	if wantsAnalysisRun(req.Message) {
		targetType, targetID := chatAnalysisTarget(req)
		if targetType == "" || targetID == "" {
			answer := ChatResponse{
				Status:         "ok",
				Answer:         "분석을 새로 만들 대상 incident나 alert를 먼저 지정해줘. 현재 RCA detail 화면에서 요청하거나, 채팅 컨텍스트에 Incident/Alert ID를 넣으면 Analysis Dashboard에 새 분석 아이템을 생성할게.",
				ConversationID: req.ConversationID,
			}
			if answer.ConversationID == "" {
				answer.ConversationID = fmt.Sprintf("chat-%d", time.Now().UnixNano())
			}
			answer.Message = answer.Answer
			answer.Response = answer.Answer
			writeJSON(w, http.StatusOK, answer)
			return
		}
		run, ok := s.startAnalysisRun(targetType, targetID, "chat", req.Message)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "analysis target not found"})
			return
		}
		answer := ChatResponse{
			Status:         "ok",
			Answer:         fmt.Sprintf("새 분석 아이템 `%s`를 만들었고 에이전트 재분석을 시작했어. Analysis Dashboard에서 상태와 결과를 이어서 볼 수 있어.", run.RunID),
			ConversationID: req.ConversationID,
			AnalysisRun:    run,
		}
		if answer.ConversationID == "" {
			answer.ConversationID = fmt.Sprintf("chat-%d", time.Now().UnixNano())
		}
		answer.Message = answer.Answer
		answer.Response = answer.Answer
		writeJSON(w, http.StatusAccepted, answer)
		return
	}
	answer, err := s.requestChat(req)
	if err != nil {
		answer = fallbackChatResponse(req, err)
	}
	if answer.ConversationID == "" {
		answer.ConversationID = req.ConversationID
	}
	if answer.ConversationID == "" {
		answer.ConversationID = fmt.Sprintf("chat-%d", time.Now().UnixNano())
	}
	if answer.Message == "" {
		answer.Message = answer.Answer
	}
	if answer.Response == "" {
		answer.Response = answer.Answer
	}
	writeJSON(w, http.StatusOK, answer)
}

func (s *Server) enrichChatRequest(req ChatRequest) ChatRequest {
	if req.Context == nil {
		req.Context = map[string]any{}
	}
	req.IncidentID = strings.TrimSpace(first(req.IncidentID, stringFromContext(req.Context, "incident_id")))
	req.AlertID = strings.TrimSpace(first(req.AlertID, stringFromContext(req.Context, "alert_id")))

	if req.AlertID != "" {
		if alert, ok := s.store.AlertDetail(req.AlertID); ok {
			if req.IncidentID == "" {
				req.IncidentID = alert.IncidentID
			}
			if req.AlertTitle == "" {
				req.AlertTitle = alert.AlarmTitle
			}
			if req.AlertContent == "" {
				req.AlertContent = alertChatContent(alert)
			}
			req.Context["alert"] = alertChatContext(alert)
		}
	}
	if req.IncidentID != "" {
		if detail, ok := s.store.IncidentDetail(req.IncidentID); ok {
			if req.IncidentTitle == "" {
				req.IncidentTitle = detail.Title
			}
			if req.IncidentContent == "" {
				req.IncidentContent = incidentChatContent(detail)
			}
			req.Context["incident"] = incidentChatContext(detail)
		}
	}

	memoryQuery := strings.Join(
		[]string{req.Message, req.IncidentTitle, req.AlertTitle, req.IncidentContent, req.AlertContent},
		"\n",
	)
	req.Context["rca_memory"] = s.store.SearchIncidentMemory(memoryQuery, 5)
	req.Context["page"] = req.Page
	return req
}

func wantsAnalysisRun(message string) bool {
	lowered := strings.ToLower(strings.TrimSpace(message))
	if lowered == "" {
		return false
	}
	if strings.Contains(lowered, "re-analyze") ||
		strings.Contains(lowered, "reanalyze") ||
		strings.Contains(lowered, "run analysis") ||
		strings.Contains(lowered, "start analysis") ||
		strings.Contains(lowered, "create analysis") {
		return true
	}
	if strings.Contains(lowered, "analyze") && strings.Contains(lowered, "rca") {
		return true
	}
	if !strings.Contains(message, "분석") {
		return false
	}
	for _, token := range []string{"해줘", "돌려", "진행", "요청", "다시", "새로", "시작", "만들"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func chatAnalysisTarget(req ChatRequest) (string, string) {
	if req.AlertID != "" {
		return "alert", req.AlertID
	}
	if req.IncidentID != "" {
		return "incident", req.IncidentID
	}
	targetType := stringFromContext(req.Context, "target_type")
	switch targetType {
	case "alert":
		if id := stringFromContext(req.Context, "alert_id"); id != "" {
			return "alert", id
		}
	case "incident":
		if id := stringFromContext(req.Context, "incident_id"); id != "" {
			return "incident", id
		}
	}
	return "", ""
}

func (s *Server) requestChat(req ChatRequest) (ChatResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return ChatResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.agentURL+"/chat",
		bytes.NewReader(payload),
	)
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return ChatResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return ChatResponse{}, errors.New(string(body))
	}
	var answer ChatResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		return ChatResponse{}, err
	}
	return answer, nil
}

func fallbackChatResponse(req ChatRequest, err error) ChatResponse {
	entity := first(req.IncidentID, req.AlertID, "current RCA workspace")
	content := first(req.AlertContent, req.IncidentContent, "No RCA content is attached yet.")
	answer := fmt.Sprintf(
		"Agent chat is unavailable for %s: %v\n\nCurrent RCA context:\n%s",
		entity,
		err,
		excerpt(content, 1200),
	)
	return ChatResponse{
		Status:         "ok",
		Answer:         answer,
		Message:        answer,
		Response:       answer,
		ConversationID: req.ConversationID,
	}
}

func incidentChatContent(detail *IncidentDetail) string {
	if detail == nil {
		return ""
	}
	alerts := make([]string, 0, len(detail.Alerts))
	for _, alert := range detail.Alerts {
		alerts = append(alerts, fmt.Sprintf(
			"%s %s %s %s",
			alert.AlertID,
			alert.AlarmTitle,
			alert.Severity,
			alert.Status,
		))
	}
	return strings.Join([]string{
		"Title: " + detail.Title,
		"Incident ID: " + detail.IncidentID,
		"Status: " + detail.Status,
		"Severity: " + detail.Severity,
		"Analysis summary: " + detail.AnalysisSummary,
		"Analysis detail: " + excerpt(detail.AnalysisDetail, 4000),
		"Missing data: " + strings.Join(detail.MissingData, ", "),
		"Warnings: " + strings.Join(detail.Warnings, ", "),
		"Alerts: " + strings.Join(alerts, " | "),
	}, "\n")
}

func alertChatContent(alert *AlertRecord) string {
	if alert == nil {
		return ""
	}
	labels, _ := json.Marshal(alert.Labels)
	annotations, _ := json.Marshal(alert.Annotations)
	return strings.Join([]string{
		"Title: " + alert.AlarmTitle,
		"Alert ID: " + alert.AlertID,
		"Incident ID: " + alert.IncidentID,
		"Status: " + alert.Status,
		"Severity: " + alert.Severity,
		"Labels: " + string(labels),
		"Annotations: " + string(annotations),
		"Analysis summary: " + alert.AnalysisSummary,
		"Analysis detail: " + excerpt(alert.AnalysisDetail, 4000),
		"Missing data: " + strings.Join(alert.MissingData, ", "),
		"Warnings: " + strings.Join(alert.Warnings, ", "),
	}, "\n")
}

func incidentChatContext(detail *IncidentDetail) map[string]any {
	if detail == nil {
		return map[string]any{}
	}
	return map[string]any{
		"incident_id":       detail.IncidentID,
		"title":             detail.Title,
		"severity":          detail.Severity,
		"status":            detail.Status,
		"analysis_summary":  detail.AnalysisSummary,
		"analysis_quality":  detail.AnalysisQuality,
		"capabilities":      detail.Capabilities,
		"missing_data":      detail.MissingData,
		"warnings":          detail.Warnings,
		"similar_incidents": detail.SimilarIncidents,
		"feedback":          detail.Feedback,
		"alerts":            detail.Alerts,
	}
}

func alertChatContext(alert *AlertRecord) map[string]any {
	if alert == nil {
		return map[string]any{}
	}
	return map[string]any{
		"alert_id":          alert.AlertID,
		"incident_id":       alert.IncidentID,
		"title":             alert.AlarmTitle,
		"severity":          alert.Severity,
		"status":            alert.Status,
		"labels":            alert.Labels,
		"annotations":       alert.Annotations,
		"analysis_summary":  alert.AnalysisSummary,
		"analysis_quality":  alert.AnalysisQuality,
		"capabilities":      alert.Capabilities,
		"missing_data":      alert.MissingData,
		"warnings":          alert.Warnings,
		"similar_incidents": alert.SimilarIncidents,
		"feedback":          alert.Feedback,
		"artifacts":         alert.Artifacts,
	}
}

func stringFromContext(context map[string]any, key string) string {
	value, ok := context[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func (s *Server) requestAnalysis(alert Alert, incidentID, alertID, threadTS string) {
	req := AgentAnalysisRequest{
		Alert:            alert,
		ThreadTS:         threadTS,
		IncidentID:       incidentID,
		AnalysisType:     status(alert.Status),
		Language:         s.language,
		SimilarIncidents: s.store.SimilarIncidentsForAlert(alert, incidentID, 5),
		FeedbackHints:    s.store.FeedbackHintsForAlert(alert, incidentID, 5),
	}
	payload, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		s.agentURL+"/analyze",
		bytes.NewReader(payload),
	)
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		s.store.ApplyAnalysis(alertID, fallbackAnalysis(alert, err))
		s.hub.Broadcast(Event{Type: "analysis.completed", Data: map[string]any{"incident_id": incidentID, "alert_id": alertID}})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		s.store.ApplyAnalysis(alertID, fallbackAnalysis(alert, errors.New(string(body))))
		s.hub.Broadcast(Event{Type: "analysis.completed", Data: map[string]any{"incident_id": incidentID, "alert_id": alertID}})
		return
	}
	var analysis AgentAnalysisResponse
	if err := json.Unmarshal(body, &analysis); err != nil {
		s.store.ApplyAnalysis(alertID, fallbackAnalysis(alert, err))
	} else {
		s.store.ApplyAnalysis(alertID, analysis)
	}
	s.hub.Broadcast(Event{Type: "analysis.completed", Data: map[string]any{"incident_id": incidentID, "alert_id": alertID}})
}

func (s *Server) startAnalysisRun(targetType string, targetID string, source string, prompt string) (*AnalysisRun, bool) {
	alert, incidentID, alertID, threadTS, title, ok := s.store.AnalysisTarget(targetType, targetID)
	if !ok {
		return nil, false
	}
	run := s.store.CreateAnalysisRun(
		source,
		targetType,
		targetID,
		incidentID,
		alertID,
		fmt.Sprintf("%s: %s", sourceTitle(source), title),
		prompt,
	)
	s.hub.Broadcast(Event{Type: "analysis.started", Data: map[string]any{
		"run_id":      run.RunID,
		"source":      run.Source,
		"target_type": targetType,
		"target_id":   targetID,
		"incident_id": incidentID,
		"alert_id":    alertID,
	}})
	go s.requestAnalysisRun(run.RunID, alert, incidentID, alertID, threadTS, source, prompt)
	return &run, true
}

func (s *Server) requestAnalysisRun(
	runID string,
	alert Alert,
	incidentID string,
	alertID string,
	threadTS string,
	source string,
	prompt string,
) {
	if alert.Annotations == nil {
		alert.Annotations = map[string]string{}
	}
	alert.Annotations["analysis_run_id"] = runID
	alert.Annotations["analysis_request_source"] = source
	alert.Annotations["operator_prompt"] = prompt
	req := AgentAnalysisRequest{
		Alert:            alert,
		ThreadTS:         threadTS,
		IncidentID:       incidentID,
		AnalysisType:     source,
		Language:         s.language,
		SimilarIncidents: s.store.SimilarIncidentsForAlert(alert, incidentID, 5),
		FeedbackHints:    s.store.FeedbackHintsForAlert(alert, incidentID, 5),
	}
	payload, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		s.agentURL+"/analyze",
		bytes.NewReader(payload),
	)
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		run, _ := s.store.FailAnalysisRun(runID, fallbackAnalysis(alert, err))
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		run, _ := s.store.FailAnalysisRun(runID, fallbackAnalysis(alert, errors.New(string(body))))
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	var analysis AgentAnalysisResponse
	if err := json.Unmarshal(body, &analysis); err != nil {
		run, _ := s.store.FailAnalysisRun(runID, fallbackAnalysis(alert, err))
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	run, _ := s.store.CompleteAnalysisRun(runID, analysis)
	s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
}

func (s *Server) broadcastAnalysisRunCompleted(run AnalysisRun, incidentID string, alertID string) {
	s.hub.Broadcast(Event{Type: "analysis.completed", Data: map[string]any{
		"run_id":      run.RunID,
		"source":      run.Source,
		"status":      run.Status,
		"incident_id": incidentID,
		"alert_id":    alertID,
	}})
}

func sourceTitle(source string) string {
	switch source {
	case "comment":
		return "Comment reanalysis"
	case "feedback":
		return "Feedback reanalysis"
	case "chat":
		return "Chat analysis"
	default:
		return "Analysis"
	}
}

func fallbackAnalysis(alert Alert, err error) AgentAnalysisResponse {
	name := alert.Labels["alertname"]
	if name == "" {
		name = "Run:AI alert"
	}
	summary := fmt.Sprintf("%s accepted, but agent analysis is unavailable: %v", name, err)
	return AgentAnalysisResponse{
		Status:          "ok",
		Analysis:        "## Root Cause\n\nAgent analysis is unavailable.\n\n## Recommended Actions\n\nCheck Agent service health and configured integrations.",
		AnalysisSummary: summary,
		AnalysisDetail:  "## Root Cause\n\nAgent analysis is unavailable.\n\n## Recommended Actions\n\nCheck Agent service health and configured integrations.",
		AnalysisQuality: "low",
		Capabilities:    map[string]string{"agent": "unavailable"},
		MissingData:     []string{"agent.response"},
		Warnings:        []string{err.Error()},
	}
}

func correlationKey(webhook AlertmanagerWebhook, alert Alert) string {
	labels := alert.Labels
	cluster := first(labels["cluster"], labels["runai_cluster"], labels["runai.io/cluster"])
	project := first(labels["project"], labels["runai_project"], labels["runai.io/project"])
	queue := first(labels["queue"], labels["runai_queue"], labels["runai.io/queue"])
	namespace := first(labels["namespace"], labels["kubernetes_namespace"])
	workload := first(labels["workload"], labels["workload_name"], labels["runai_workload_name"], labels["pod"])
	node := first(labels["node"], labels["node_name"])
	if cluster != "" && project != "" && queue != "" && namespace != "" && workload != "" {
		return strings.Join([]string{"workload", cluster, project, queue, namespace, workload}, ":")
	}
	if cluster != "" && node != "" {
		return strings.Join([]string{"node", cluster, node}, ":")
	}
	if webhook.GroupKey != "" {
		return "group:" + webhook.GroupKey
	}
	if alert.Fingerprint != "" {
		return "fingerprint:" + alert.Fingerprint
	}
	return fmt.Sprintf("adhoc:%d", time.Now().UnixNano())
}

func incidentTitle(alert Alert) string {
	return first(alert.Annotations["summary"], alert.Labels["alertname"], "Run:AI incident")
}

func severity(alert Alert) string {
	return first(alert.Labels["severity"], "warning")
}

func status(value string) string {
	if value == "resolved" {
		return "resolved"
	}
	return "firing"
}

func maxSeverity(a, b string) string {
	rank := map[string]int{"info": 1, "warning": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstTime(raw string, fallback time.Time) time.Time {
	if raw == "" {
		return fallback
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fallback
	}
	return t.UTC()
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIncident(in *Incident) *Incident {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneAlert(in *AlertRecord) *AlertRecord {
	if in == nil {
		return nil
	}
	out := *in
	out.Labels = cloneMap(in.Labels)
	out.Annotations = cloneMap(in.Annotations)
	out.Capabilities = cloneMap(in.Capabilities)
	out.MissingData = append([]string{}, in.MissingData...)
	out.Warnings = append([]string{}, in.Warnings...)
	out.Artifacts = append([]Artifact{}, in.Artifacts...)
	out.SimilarIncidents = cloneSimilar(in.SimilarIncidents)
	out.Feedback = cloneFeedbackSummary(in.Feedback)
	return &out
}

func cloneSimilar(in []SimilarIncident) []SimilarIncident {
	out := make([]SimilarIncident, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Labels = cloneMap(item.Labels)
	}
	return out
}

func cloneFeedbackSummary(in FeedbackSummary) FeedbackSummary {
	out := in
	out.Comments = append([]CommentRecord{}, in.Comments...)
	out.LearningHints = append([]FeedbackHint{}, in.LearningHints...)
	return out
}

func cloneAnalysisRun(in *AnalysisRun) AnalysisRun {
	if in == nil {
		return AnalysisRun{}
	}
	out := *in
	out.Capabilities = cloneMap(in.Capabilities)
	out.MissingData = append([]string{}, in.MissingData...)
	out.Warnings = append([]string{}, in.Warnings...)
	out.Artifacts = append([]Artifact{}, in.Artifacts...)
	return out
}

func cloneComment(in *CommentRecord) *CommentRecord {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func alertFromRecord(record AlertRecord) Alert {
	return Alert{
		Status:      record.Status,
		Labels:      cloneMap(record.Labels),
		Annotations: cloneMap(record.Annotations),
		Fingerprint: record.Fingerprint,
	}
}

func normalizeVote(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "up", "like", "positive", "helpful":
		return "up"
	case "down", "dislike", "negative", "unhelpful":
		return "down"
	default:
		return ""
	}
}

func feedbackActor(author string) string {
	author = strings.TrimSpace(author)
	if author == "" {
		return "anonymous"
	}
	return author
}

func nextID(prefix string, seq int64) string {
	return fmt.Sprintf("%s-%d-%06d", prefix, time.Now().UTC().UnixNano(), seq)
}

func alertSearchText(alert Alert) string {
	parts := []string{
		incidentTitle(alert),
		severity(alert),
		alert.Annotations["summary"],
		alert.Annotations["description"],
	}
	for _, key := range []string{
		"alertname",
		"cluster",
		"project",
		"queue",
		"namespace",
		"workload",
		"workload_name",
		"pod",
		"node",
	} {
		if value := alert.Labels[key]; value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " ")
}

func memoryText(memory IncidentMemory) string {
	values := []string{
		memory.Title,
		memory.Severity,
		memory.Status,
		memory.AnalysisSummary,
		memory.AnalysisDetail,
	}
	for _, value := range memory.Labels {
		values = append(values, value)
	}
	return strings.Join(values, " ")
}

func textVector(text string) map[string]float64 {
	vector := map[string]float64{}
	for _, token := range tokenize(text) {
		vector[token]++
	}
	return vector
}

func tokenize(text string) []string {
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		if len([]rune(field)) >= 2 {
			tokens = append(tokens, field)
		}
	}
	return tokens
}

func cosineSimilarity(a, b map[string]float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for key, value := range a {
		normA += value * value
		dot += value * b[key]
	}
	for _, value := range b {
		normB += value * value
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

func labelSimilarityBonus(alertLabels, memoryLabels map[string]string) float64 {
	keys := []string{"alertname", "cluster", "project", "queue", "namespace", "workload", "pod"}
	score := 0.0
	for _, key := range keys {
		if alertLabels[key] != "" && alertLabels[key] == memoryLabels[key] {
			score += 0.035
		}
	}
	return score
}

func excerpt(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
}

func mustJSON(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		return []byte("null")
	}
	return payload
}

func pathPart(path, prefix string) string {
	return strings.Trim(strings.TrimPrefix(path, prefix), "/")
}

func envelope(data any) map[string]any {
	return map[string]any{"status": "ok", "data": data}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeSSE(w io.Writer, event Event) {
	payload, _ := json.Marshal(event)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, payload)
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
