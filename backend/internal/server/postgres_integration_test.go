package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests need a REAL Postgres: the fake driver reports every UPDATE as one
// affected row, so a status guard that matches nothing still looks like success.
// That blind spot is what shipped "could not persist knowledge candidate
// approval" to operators. CI provides the service; locally, run
//
//	docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=rca -e POSTGRES_USER=rca \
//	  -e POSTGRES_DB=rcatest pgvector/pgvector:pg16
//	RCA_TEST_POSTGRES_DSN='postgres://rca:rca@localhost:55432/rcatest?sslmode=disable' \
//	  go test ./internal/server/ -run Postgres
func postgresTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("RCA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("RCA_TEST_POSTGRES_DSN not set")
	}
	// The database outlives a single run, and ConnectDatabase loads existing rows
	// into memory — so wipe before connecting, not after.
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if _, err := admin.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	_ = admin.Close()
	store := NewStore()
	store.ConnectDatabase(dsn, 15*time.Second)
	if !store.dbReady {
		t.Fatal("postgres did not become ready")
	}
	return store
}

// An operator retry of a candidate the Agent validator rejected must actually
// land in Postgres. The in-memory gate admits that row (the retry re-asks the
// validator), so the UPDATE guard has to admit it too.
func TestPostgresValidatorRetryApprovalPersists(t *testing.T) {
	store := postgresTestStore(t)
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.mu.Lock()
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.activeCaseByIncident[snapshot.IncidentID] = snapshot.CaseID
	if !store.persistNewCaseSnapshotLocked(snapshot) {
		store.mu.Unlock()
		t.Fatal("case snapshot did not persist")
	}
	confirmKnowledgeSnapshot(store, snapshot)
	candidate := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if candidate == nil {
		store.mu.Unlock()
		t.Fatal("snapshot produced no candidate")
	}
	store.knowledgeCandidates[candidate.CandidateID] = candidate
	event := store.newKnowledgeEventLocked(candidate.CandidateID, "", "candidate_generated", "system", "", time.Now().UTC())
	if !store.persistNewKnowledgeCandidateLocked(candidate, event) {
		store.mu.Unlock()
		t.Fatal("candidate did not persist")
	}
	store.mu.Unlock()

	if _, err := store.FailKnowledgeCandidateValidation(candidate.CandidateID, errKnowledgeValidatorRejected.Error()+": missing mechanism"); err != nil {
		t.Fatalf("validation failure not recorded: %v", err)
	}
	if _, _, err := store.ApproveKnowledgeCandidate(candidate.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("operator retry of a validator-rejected candidate failed: %v", err)
	}
	var status, packageID, validationError string
	if err := store.db.QueryRow(
		`SELECT status, package_id, validation_error FROM knowledge_candidates WHERE candidate_id = $1`,
		candidate.CandidateID,
	).Scan(&status, &packageID, &validationError); err != nil {
		t.Fatalf("candidate row query: %v", err)
	}
	// The row must not stay red either: the validator has just accepted it.
	if status != knowledgeCandidateActive || packageID == "" || validationError != "" {
		t.Fatalf("postgres row not activated: status=%s package=%q error=%q", status, packageID, validationError)
	}
}

// A changed re-analysis releases the operator approval — in memory AND in
// Postgres — and withdraws the knowledge derived from the superseded review.
func TestPostgresReanalysisReleasesApproval(t *testing.T) {
	var hash atomic.Value
	hash.Store("hash-1")
	server, _ := analysisAgentStub(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Queue gpu-a saturated.",
			AnalysisDetail:  "## Root Cause\n\nQuota exhausted.",
			AnalysisQuality: "high",
			RootCauseFamily: "scheduler_capacity",
			Context:         knowledgeEligibleAgentContext(hash.Load().(string)),
		})
	})
	server.store = postgresTestStore(t)
	incident, _ := seedAlert(t, server, "fp-postgres-reanalysis")

	first, ok := server.startAnalysisRun("incident", incident.IncidentID, "manual", "")
	if !ok {
		t.Fatal("first analysis did not start")
	}
	waitForRunIDStatus(t, server, first.RunID, "complete")

	// The operator evaluation that makes this analysis knowledge-eligible.
	server.store.mu.Lock()
	server.store.evaluationReviews[evaluationKey(first.RunID, "hash-1", "operator")] = &EvaluationReview{
		ReviewID: "EVR-postgres", RunID: first.RunID, AnalysisHash: "hash-1", Reviewer: "operator",
		CaseType: "known", ExpectedFamily: "scheduler_capacity",
		Scores: qualifyingKnowledgeReviewScores(), ResolutionOutcome: "resolved",
	}
	server.store.mu.Unlock()

	approve := httptest.NewRecorder()
	server.routes().ServeHTTP(approve, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/resolve", nil))
	if approve.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approve.Code, approve.Body.String())
	}
	snapshot, ok := server.store.ApprovedCaseSnapshot(incident.IncidentID)
	if !ok {
		t.Fatal("approval did not create an active case snapshot")
	}
	candidates := server.store.ListKnowledgeCandidates("")
	if len(candidates) != 1 || candidates[0].Status != knowledgeCandidateReady {
		t.Fatalf("approval did not mint a ready knowledge candidate: %+v", candidates)
	}
	if _, _, err := server.store.ApproveKnowledgeCandidate(candidates[0].CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("knowledge activation failed: %v", err)
	}

	hash.Store("hash-2")
	reanalyze := httptest.NewRecorder()
	server.routes().ServeHTTP(reanalyze, httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incident.IncidentID+"/analyze", nil))
	if reanalyze.Code != http.StatusAccepted {
		t.Fatalf("re-analysis status=%d body=%s", reanalyze.Code, reanalyze.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		detail, _ := server.store.IncidentDetail(incident.IncidentID)
		if detail.AnalysisHash == "hash-2" && detail.UserApprovedAt == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	detail, _ := server.store.IncidentDetail(incident.IncidentID)
	if detail.AnalysisHash != "hash-2" || detail.UserApprovedAt != nil {
		t.Fatalf("approval not released: hash=%q approved=%v", detail.AnalysisHash, detail.UserApprovedAt)
	}

	var approvedAt *time.Time
	if err := server.store.db.QueryRow(`SELECT user_approved_at FROM incidents WHERE incident_id = $1`, incident.IncidentID).Scan(&approvedAt); err != nil {
		t.Fatalf("incident row query: %v", err)
	}
	var approvalState string
	if err := server.store.db.QueryRow(`SELECT approval_state FROM rca_case_snapshots WHERE case_id = $1`, snapshot.CaseID).Scan(&approvalState); err != nil {
		t.Fatalf("snapshot row query: %v", err)
	}
	if approvedAt != nil || approvalState != "revoked" {
		t.Fatalf("postgres still holds the approval: user_approved_at=%v snapshot=%q", approvedAt, approvalState)
	}
	var candidateStatus, packageStatus string
	if err := server.store.db.QueryRow(`SELECT status FROM knowledge_candidates WHERE candidate_id = $1`, candidates[0].CandidateID).Scan(&candidateStatus); err != nil {
		t.Fatalf("candidate row query: %v", err)
	}
	if err := server.store.db.QueryRow(`SELECT status FROM knowledge_packages WHERE candidate_id = $1`, candidates[0].CandidateID).Scan(&packageStatus); err != nil {
		t.Fatalf("package row query: %v", err)
	}
	if candidateStatus != knowledgeCandidateValidationFailed || packageStatus != knowledgePackageRetired {
		t.Fatalf("derived knowledge survived the superseded review: candidate=%s package=%s", candidateStatus, packageStatus)
	}
}

// knowledgeEligibleAgentContext returns the agent context (harness + trace v3)
// that compiles into a promotable candidate, bound to one analysis hash.
func knowledgeEligibleAgentContext(hash string) map[string]any {
	metadata, _ := eligibleKnowledgeSnapshot().Snapshot["metadata"].(map[string]any)
	context := map[string]any{"analysis_hash": hash}
	for key, value := range metadata {
		context[key] = value
	}
	return context
}

// Re-evaluating the same analysis mints a new (content-derived) candidate for the
// SAME case, and the package id is case-derived. That new candidate must be able
// to publish over its own retired predecessor instead of dead-ending the
// operator on "could not persist knowledge candidate approval".
func TestPostgresReactivationAfterRetirementPersists(t *testing.T) {
	store := postgresTestStore(t)
	snapshot := eligibleKnowledgeSnapshot()
	snapshot.ApprovalState = "active"
	store.mu.Lock()
	store.caseSnapshots[snapshot.CaseID] = snapshot
	store.activeCaseByIncident[snapshot.IncidentID] = snapshot.CaseID
	if !store.persistNewCaseSnapshotLocked(snapshot) {
		store.mu.Unlock()
		t.Fatal("case snapshot did not persist")
	}
	confirmKnowledgeSnapshot(store, snapshot)
	first := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if first == nil {
		store.mu.Unlock()
		t.Fatal("snapshot produced no candidate")
	}
	store.knowledgeCandidates[first.CandidateID] = first
	if !store.persistNewKnowledgeCandidateLocked(first, store.newKnowledgeEventLocked(first.CandidateID, "", "candidate_generated", "system", "", time.Now().UTC())) {
		store.mu.Unlock()
		t.Fatal("first candidate did not persist")
	}
	store.mu.Unlock()
	if _, _, err := store.ApproveKnowledgeCandidate(first.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	if _, err := store.RetireKnowledgePackage("KPK-"+snapshot.CaseID, KnowledgeDecisionRequest{Actor: "operator", Note: "superseded by a new evaluation"}); err != nil {
		t.Fatalf("retirement failed: %v", err)
	}

	// The operator records an effective action, so the recompute is a different
	// candidate for the same case — the shape a re-evaluation produces.
	store.mu.Lock()
	card, _ := snapshot.Snapshot["case_card"].(map[string]any)
	card["successful_actions"] = []any{"restart the scheduler"}
	second := store.knowledgeCandidateForSnapshotLocked(snapshot)
	if second == nil || second.CandidateID == first.CandidateID {
		store.mu.Unlock()
		t.Fatalf("expected a distinct re-evaluated candidate, got %+v", second)
	}
	store.knowledgeCandidates[second.CandidateID] = second
	if !store.persistNewKnowledgeCandidateLocked(second, store.newKnowledgeEventLocked(second.CandidateID, "", "candidate_generated", "system", "", time.Now().UTC())) {
		store.mu.Unlock()
		t.Fatal("second candidate did not persist")
	}
	store.mu.Unlock()
	if _, _, err := store.ApproveKnowledgeCandidate(second.CandidateID, KnowledgeDecisionRequest{Actor: "operator"}); err != nil {
		t.Fatalf("re-evaluated candidate could not be activated: %v", err)
	}
	var candidateID, status string
	if err := store.db.QueryRow(`SELECT candidate_id, status FROM knowledge_packages WHERE package_id = $1`, "KPK-"+snapshot.CaseID).Scan(&candidateID, &status); err != nil {
		t.Fatalf("package row query: %v", err)
	}
	if candidateID != second.CandidateID || status != knowledgePackageActive {
		t.Fatalf("package not republished: candidate=%s status=%s", candidateID, status)
	}
}

// The alert webhook's writes now run AFTER the store lock is released
// (commitAfterUnlock). Against the fake driver that is invisible: it accepts
// anything. Against a real Postgres, prove both halves of the contract.
//
// Each firing carries a strictly newer StartsAt, so every one is a NEW episode
// that bumps FiredAt and the occurrence count — which is what makes commit
// ORDER observable. dbMu is taken while s.mu is still held precisely so the
// last writer to hold the store lock is also the last to commit; drop that and
// a slow early writer can overwrite a fast later one, leaving the row stale.
func TestPostgresWebhookWritesLandAfterUnlockInLockOrder(t *testing.T) {
	store := postgresTestStore(t)
	webhook := AlertmanagerWebhook{}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	firing := func(i int) Alert {
		return Alert{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "KubePodNotReady", "namespace": "runai", "pod": "p1"},
			Annotations: map[string]string{"summary": "pod not ready"},
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
		}
	}
	first := store.UpsertAlertResult(webhook, firing(0))
	if first.Alert.AlertID == "" || first.Incident.IncidentID == "" {
		t.Fatalf("upsert produced no ids: %+v", first)
	}

	var wg sync.WaitGroup
	for i := 1; i <= 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store.UpsertAlertResult(webhook, firing(i))
		}(i)
	}
	wg.Wait()

	// Reload a fresh Store from Postgres alone and compare with memory.
	reloaded := NewStore()
	reloaded.ConnectDatabase(os.Getenv("RCA_TEST_POSTGRES_DSN"), 15*time.Second)
	if !reloaded.dbReady {
		t.Fatal("reload store did not become ready")
	}
	store.mu.RLock()
	wantAlert := cloneAlert(store.alerts[first.Alert.AlertID])
	wantIncident := cloneIncident(store.incidents[first.Incident.IncidentID])
	store.mu.RUnlock()
	if wantAlert == nil || wantIncident == nil {
		t.Fatal("in-memory rows disappeared")
	}
	if wantAlert.OccurrenceCount < 2 {
		t.Fatalf("fixture did not produce competing writers: occurrence_count=%d", wantAlert.OccurrenceCount)
	}

	reloaded.mu.RLock()
	gotAlert := reloaded.alerts[first.Alert.AlertID]
	gotIncident := reloaded.incidents[first.Incident.IncidentID]
	reloaded.mu.RUnlock()
	if gotAlert == nil {
		t.Fatalf("alert %s never reached Postgres", first.Alert.AlertID)
	}
	if gotIncident == nil {
		t.Fatalf("incident %s never reached Postgres", first.Incident.IncidentID)
	}
	if !gotAlert.FiredAt.Equal(wantAlert.FiredAt) {
		t.Fatalf("persisted alert is stale: fired_at db=%v memory=%v (a later writer committed first)",
			gotAlert.FiredAt, wantAlert.FiredAt)
	}
	if gotAlert.OccurrenceCount != wantAlert.OccurrenceCount {
		t.Fatalf("persisted alert is stale: occurrence_count db=%d memory=%d",
			gotAlert.OccurrenceCount, wantAlert.OccurrenceCount)
	}
	if gotIncident.AlertCount != wantIncident.AlertCount {
		t.Fatalf("persisted incident is stale: alert_count db=%d memory=%d",
			gotIncident.AlertCount, wantIncident.AlertCount)
	}
}
