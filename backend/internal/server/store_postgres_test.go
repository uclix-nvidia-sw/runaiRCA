package server

import (
	"strings"
	"testing"
	"time"

	"github.com/brilly-bohyun/runai-rca/backend/internal/server/testsupport"
)

func TestPostgresConnectReportsPGVectorEnabledAndLoadsState(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
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
	if !state.Executed("CREATE EXTENSION IF NOT EXISTS vector") ||
		!state.Executed("CREATE TABLE IF NOT EXISTS incident_embeddings") {
		t.Fatalf("expected pgvector extension and embeddings schema statements, got %+v", state.Execs())
	}
	if !state.Executed("idx_incident_embeddings_incident_alert") {
		t.Fatalf("expected alert-scoped incident embedding uniqueness DDL, got %+v", state.Execs())
	}
	if !state.Executed("idx_analysis_runs_one_analyzing_alert") {
		t.Fatalf("expected alert-scoped analyzing run uniqueness DDL, got %+v", state.Execs())
	}
	for _, ddl := range []string{
		"ADD COLUMN IF NOT EXISTS user_approved_at",
		"ADD COLUMN IF NOT EXISTS archived_at",
		"ADD COLUMN IF NOT EXISTS deleted_at",
		"ADD COLUMN IF NOT EXISTS metadata",
	} {
		if !state.Executed(ddl) {
			t.Fatalf("expected DDL %q, got %+v", ddl, state.Execs())
		}
	}
	cleanupIndex := state.ExecIndex("duplicate analyzing run was closed before enforcing alert uniqueness")
	uniqueIndex := state.ExecIndex("idx_analysis_runs_one_analyzing_alert")
	if cleanupIndex < 0 || uniqueIndex < 0 || cleanupIndex > uniqueIndex {
		t.Fatalf("expected duplicate analyzing cleanup before unique index, cleanup=%d unique=%d", cleanupIndex, uniqueIndex)
	}
	if !state.Executed("ADD COLUMN IF NOT EXISTS embedding vector(") ||
		!state.Executed("USING hnsw (embedding vector_cosine_ops)") {
		t.Fatalf("expected pgvector column and cosine index DDL, got %+v", state.Execs())
	}
	if health := store.databaseHealth(); health["similarity_search"] != similaritySearchPGVector {
		t.Fatalf("expected pgvector cosine search path, got %+v", health)
	}

	assertLoadedPostgresMemory(t, store)
	if got := state.RecordedPGVectorSearchLimit(); got != 15 {
		t.Fatalf("expected pgvector search to overfetch before dedupe, got limit %d", got)
	}
}

func TestPostgresConnectFallsBackToJSONBWhenPGVectorUnavailable(t *testing.T) {
	state := testsupport.NewPostgresState(true)
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
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
	detail, ok := health["pgvector_detail"].(string)
	if !ok || !strings.Contains(detail, "not installed") {
		t.Fatalf("expected actionable pgvector_detail remediation hint, got %+v", health["pgvector_detail"])
	}

	assertLoadedPostgresMemory(t, store)
}

func TestPostgresLoadRestoresGroupAlertIndex(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	state.SetLabelsJSON([]byte(`{"alertname":"RunAIQueueBlocked","severity":"warning"}`))
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()

	_, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "db"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue still blocked"},
	})

	if alert.AlertID != "ALR-db" {
		t.Fatalf("expected group-key alert to reuse loaded row, got %s", alert.AlertID)
	}
	if alerts := store.ListAlerts(); len(alerts) != 1 {
		t.Fatalf("expected one alert after reload upsert, got %+v", alerts)
	}
}

func TestPostgresLoadSkipsDeletedIncidentIndexes(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	state.SetIncidentDeletedAt(time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()

	if active := store.ListIncidents(); len(active) != 0 {
		t.Fatalf("deleted incident should not load into active view: %+v", active)
	}
	if trash, total := store.ListIncidentsPage(0, 0, incidentViewTrash); total != 1 || len(trash) != 1 {
		t.Fatalf("deleted incident should load only in trash view, total=%d items=%+v", total, trash)
	}
	_, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "db"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue still blocked"},
		Fingerprint: "fp-db",
	})
	if alert.AlertID == "ALR-db" {
		t.Fatalf("loaded deleted incident alert index should not be reused")
	}
}

func TestPostgresHardDeleteUsesSingleTransaction(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	beforeBegins, beforeCommits, beforeRollbacks := state.TxCounts()

	if !store.HardDeleteIncident("INC-db") {
		t.Fatalf("expected hard delete to succeed")
	}
	afterBegins, afterCommits, afterRollbacks := state.TxCounts()
	if afterBegins != beforeBegins+1 || afterCommits != beforeCommits+1 || afterRollbacks != beforeRollbacks {
		t.Fatalf("expected one committed hard-delete transaction, before=%d/%d/%d after=%d/%d/%d",
			beforeBegins, beforeCommits, beforeRollbacks, afterBegins, afterCommits, afterRollbacks)
	}
	for _, fragment := range []string{
		"DELETE FROM analysis_runs",
		"DELETE FROM rca_comments",
		"DELETE FROM rca_feedback",
		"DELETE FROM incident_embeddings",
		"DELETE FROM alerts",
		"DELETE FROM incidents",
	} {
		if !state.Executed(fragment) {
			t.Fatalf("expected hard delete statement %q, got %+v", fragment, state.Execs())
		}
	}
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

func TestPostgresRuntimeOperationsUseDeadlines(t *testing.T) {
	state := testsupport.NewPostgresState(false)
	store := NewStore()

	store.connectDatabaseWithDriver(testsupport.RegisterPostgresDriver(state), "fake://runai_rca", time.Second)
	defer store.db.Close()
	if execs, queries := state.DeadlineMisses(); execs != 0 || queries != 0 {
		t.Fatalf("startup database calls should all carry deadlines, got execs=%d queries=%d", execs, queries)
	}

	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "deadline"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-deadline",
	})
	store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Queue gpu-a saturated.",
		AnalysisDetail:  "Quota was exhausted.",
		AnalysisQuality: "high",
	})
	_, _, _ = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{Vote: "up", Author: "operator"})
	summary, _, _ := store.AddComment("incident", incident.IncidentID, CommentRequest{Body: "Check scheduler logs.", Author: "operator"})
	if len(summary.Comments) == 0 {
		t.Fatalf("expected comment to be created")
	}
	_, _, _ = store.UpdateComment("incident", incident.IncidentID, summary.Comments[0].CommentID, CommentRequest{Body: "Updated scheduler note."})
	store.DeleteComment("incident", incident.IncidentID, summary.Comments[0].CommentID)
	run := store.CreateAnalysisRun("manual", "alert", alert.AlertID, incident.IncidentID, alert.AlertID, "deadline run", "")
	store.CompleteAnalysisRun(run.RunID, AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})
	store.SearchIncidentMemory("gpu quota scheduling", 5)

	if execs, queries := state.DeadlineMisses(); execs != 0 || queries != 0 {
		t.Fatalf("runtime database calls should all carry deadlines, got execs=%d queries=%d", execs, queries)
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
