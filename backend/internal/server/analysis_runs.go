package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// AnalysisRun is a single lifecycle record for an analysis request. Automatic
// webhook analysis is alert-scoped and idempotent; explicit operator requests
// still create their own runs so manual follow-up remains auditable.
type AnalysisRun struct {
	RunID            string            `json:"run_id"`
	Source           string            `json:"source"`
	Status           string            `json:"status"`
	TargetType       string            `json:"target_type"`
	TargetID         string            `json:"target_id"`
	IncidentID       string            `json:"incident_id,omitempty"`
	AlertID          string            `json:"alert_id,omitempty"`
	Title            string            `json:"title"`
	Prompt           string            `json:"prompt,omitempty"`
	AnalysisSummary  string            `json:"analysis_summary"`
	AnalysisDetail   string            `json:"analysis_detail"`
	AnalysisQuality  string            `json:"analysis_quality"`
	RootCauseFamily  string            `json:"root_cause_family"`
	Capabilities     map[string]string `json:"capabilities"`
	MissingData      []string          `json:"missing_data"`
	Warnings         []string          `json:"warnings"`
	Artifacts        []Artifact        `json:"artifacts"`
	Metadata         map[string]any    `json:"metadata,omitempty"`
	FirstCompletedAt *time.Time        `json:"first_completed_at,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// startAnalysisRun resolves the analysis target, creates an analyzing run when
// allowed, marks the target as analyzing, emits the started SSE event, and
// kicks off the agent call asynchronously.
func (s *Server) startAnalysisRun(targetType string, targetID string, source string, prompt string) (*AnalysisRun, bool) {
	alert, incidentID, alertID, threadTS, title, ok := s.store.AnalysisTarget(targetType, targetID)
	if !ok {
		return nil, false
	}
	if source == "auto" && status(alert.Status) == "resolved" {
		return nil, false
	}
	if source == "manual" && strings.TrimSpace(prompt) == "" {
		prompt = s.store.OperatorPromptForTarget(targetType, targetID)
	}
	run, created := s.store.CreateAnalysisRunIfAllowed(
		source,
		targetType,
		targetID,
		incidentID,
		alertID,
		fmt.Sprintf("%s: %s", sourceTitle(source), title),
		prompt,
	)
	if !created {
		if run.RunID == "" {
			return nil, false
		}
		return &run, false
	}
	if source == "manual" {
		s.store.BeginManualAnalysis(incidentID, alertID)
	} else {
		s.store.BeginAnalyzing(incidentID, alertID)
	}
	s.hub.Broadcast(analysisStartedEvent(run.RunID, run.Source, targetType, targetID, incidentID, alertID))
	go s.requestAnalysisRun(run.RunID, alert, incidentID, alertID, threadTS, source, prompt)
	return &run, true
}

// requestAnalysisRun performs the agent call for a run and drives the run to a
// terminal state. On success the alert RCA is overwritten with the fresh
// analysis. On failure the run is marked failed with a warning, an SSE
// completion event is still emitted, and the fallback RCA is only written to the
// alert when there is no prior successful RCA to preserve.
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
	if strings.TrimSpace(prompt) != "" {
		alert.Annotations["operator_prompt"] = prompt
	}

	releaseAgentSlot, ok := s.acquireAgentSlot(s.analysisRequestTimeout(source))
	if !ok {
		fallback := fallbackAnalysis(alert, &AgentError{Kind: agentErrBusy, Err: errors.New("too many analysis requests are already running")})
		run, ok := s.store.FailAnalysisRun(runID, fallback)
		if !ok {
			return
		}
		s.store.ApplyFallbackAnalysisIfAbsentForRun(runID, alertID, fallback)
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	defer releaseAgentSlot()

	occurrencePods, occurrenceCount := s.store.OccurrenceSummaryForTarget(incidentID, alertID)
	req := AgentAnalysisRequest{
		Alert:            compactAgentAlert(alert),
		ThreadTS:         threadTS,
		IncidentID:       incidentID,
		AnalysisType:     first(source, status(alert.Status)),
		Language:         s.language,
		OccurrenceCount:  occurrenceCount,
		OccurrencePods:   occurrencePods,
		SimilarIncidents: compactAgentSimilarIncidents(s.store.SimilarIncidentsForAlert(alert, incidentID, similarIncidentLimit)),
		FeedbackHints:    s.store.FeedbackHintsForAlert(alert, incidentID, similarIncidentLimit),
	}

	analysis, err := s.callAnalyze(req, s.analysisRequestTimeout(source))
	if err != nil {
		fallback := fallbackAnalysis(alert, err)
		run, ok := s.store.FailAnalysisRun(runID, fallback)
		if !ok {
			return
		}
		s.store.ApplyFallbackAnalysisIfAbsentForRun(runID, alertID, fallback)
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	run, ok := s.store.CompleteAnalysisRun(runID, analysis)
	if !ok {
		return
	}
	if !s.store.ApplyAnalysisForRun(runID, alertID, analysis) {
		// Distinguish "a newer run superseded this one" (normal when an operator
		// re-triggers Analyze mid-run) from a real Postgres persistence failure —
		// the persistence message told operators to check Postgres for a non-problem.
		failure := analysisPersistenceFailure(alert)
		if s.store.IsSupersededAnalysisRun(runID, alertID) {
			failure = analysisSupersededResult(alert)
		}
		if failedRun, ok := s.store.FailAnalysisRun(runID, failure); ok {
			run = failedRun
		}
		s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
		return
	}
	s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
	s.notifySlackAnalysis(run, incidentID)
}

// runBackfill periodically re-drives alerts that never produced a completed RCA:
// alerts dropped by the per-webhook fan-out / rate caps (no run was ever created)
// and alerts whose only run failed (retried after a cooldown). It pauses the whole
// cycle when the agent is unhealthy, so a pod-down / outage is never hammered.
// Interval <= 0 disables the loop entirely.
func (s *Server) runBackfill(ctx context.Context) {
	if s.backfillInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.backfillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.backfillOnce()
		}
	}
}

// runStaleRunReaper periodically re-runs the startup reaper. The startup pass
// alone leaves a hole: a run orphaned by a backend restart (its goroutine died
// with the old process) that is still YOUNGER than its request timeout survives
// the startup reap — and nothing ever reaped it again, so its alert/incident
// stayed "analyzing" forever. Reaping is safe on a live system: only runs older
// than their own request timeout are touched, and by then the HTTP call driving
// them has necessarily given up.
func (s *Server) runStaleRunReaper(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if reaped := s.store.ReapStaleAnalyzingRuns(s.agentRequestTimeout, s.manualAgentRequestTimeout); reaped > 0 {
				log.Printf("reaped %d stale analyzing run(s)", reaped)
			}
		}
	}
}

func (s *Server) runTrashPurge(ctx context.Context) {
	purge := func() {
		if purged := s.store.PurgeExpiredTrash(s.trashRetention, time.Now().UTC()); purged > 0 {
			log.Printf("purged %d expired trash incident(s)", purged)
		}
	}
	purge()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

func (s *Server) backfillOnce() int {
	if !s.agentHealthy() {
		return 0 // agent down / outage — do not queue more work onto it
	}
	batch := s.backfillBatch
	if batch <= 0 {
		batch = 10
	}
	ids := s.store.AlertIDsNeedingAnalysis(batch, s.backfillRetryCooldown, time.Now().UTC())
	started := 0
	for _, id := range ids {
		if _, ok := s.startAnalysisRun("alert", id, "backfill", ""); ok {
			started++
		}
	}
	if started > 0 {
		log.Printf("backfill started %d analysis run(s) for alerts without a completed RCA", started)
	}
	return started
}

// agentHealthy is the circuit breaker for backfill: a fast GET on the agent's
// /healthz. A failure (pod down, network) means "outage" — skip this cycle.
func (s *Server) agentHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.agentURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

const maxAgentMapValueBytes = 4000

func compactAgentAlert(alert Alert) Alert {
	alert.Labels = compactAgentStringMap(alert.Labels)
	alert.Annotations = compactAgentStringMap(alert.Annotations)
	return alert
}

func compactAgentStringMap(in map[string]string) map[string]string {
	out := cloneMap(in)
	for key, value := range out {
		out[key] = excerpt(value, maxAgentMapValueBytes)
	}
	return out
}

func compactAgentSimilarIncidents(items []SimilarIncident) []SimilarIncident {
	out := make([]SimilarIncident, 0, len(items))
	for _, item := range items {
		item.Title = excerpt(item.Title, 120)
		item.AnalysisSummary = excerpt(item.AnalysisSummary, 800)
		item.AnalysisDetail = ""
		item.Labels = nil
		out = append(out, item)
	}
	return out
}

func analysisSupersededResult(alert Alert) AgentAnalysisResponse {
	name := first(alert.Labels["alertname"], "Run:AI alert")
	summary := fmt.Sprintf("%s analysis was superseded by a newer run", name)
	detail := strings.Join([]string{
		"## Root Cause",
		"",
		"A newer analysis run was started for this alert before this one finished, so this result was not applied.",
		"",
		"## Recommended Actions",
		"",
		"No action needed — see the newest analysis run for the current RCA.",
	}, "\n")
	return AgentAnalysisResponse{
		Status:          "superseded",
		Analysis:        detail,
		AnalysisSummary: summary,
		AnalysisDetail:  detail,
		AnalysisQuality: "low",
		Capabilities:    map[string]string{"analysis": "superseded_by_newer_run"},
		Warnings:        []string{"analysis superseded by a newer run for this alert"},
	}
}

func analysisPersistenceFailure(alert Alert) AgentAnalysisResponse {
	name := first(alert.Labels["alertname"], "Run:AI alert")
	summary := fmt.Sprintf("%s analysis completed, but alert RCA could not be persisted", name)
	detail := strings.Join([]string{
		"## Root Cause",
		"",
		"Agent analysis completed, but the backend could not persist the RCA to the alert row.",
		"",
		"## Recommended Actions",
		"",
		"Check Postgres health and retry the analysis.",
	}, "\n")
	return AgentAnalysisResponse{
		Status:          "error",
		Analysis:        detail,
		AnalysisSummary: summary,
		AnalysisDetail:  detail,
		AnalysisQuality: "low",
		Capabilities:    map[string]string{"database": "alert_persist_failed"},
		MissingData:     []string{"alerts.persistence"},
		Warnings:        []string{"alert RCA persistence failed"},
	}
}

func (s *Server) analysisRequestTimeout(source string) time.Duration {
	if source == "manual" {
		return s.manualAgentRequestTimeout
	}
	return s.agentRequestTimeout
}

func (s *Server) acquireAgentSlot(timeout time.Duration) (func(), bool) {
	if s.agentSlots == nil {
		return func() {}, true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case s.agentSlots <- struct{}{}:
		return func() { <-s.agentSlots }, true
	case <-timer.C:
		return nil, false
	}
}

func (s *Server) broadcastAnalysisRunCompleted(run AnalysisRun, incidentID string, alertID string) {
	status := first(run.Status, "complete")
	s.hub.Broadcast(analysisCompletedEvent(run.RunID, run.Source, status, run.TargetType, run.TargetID, incidentID, alertID))
}

func sourceTitle(source string) string {
	switch source {
	case "auto":
		return "Automatic analysis"
	case "manual":
		return "Dashboard analysis"
	case "comment":
		return "Comment reanalysis"
	case "feedback":
		return "Feedback reanalysis"
	case "backfill":
		return "Backfill analysis"
	case "chat":
		return "Chat analysis"
	default:
		return "Analysis"
	}
}

// fallbackAnalysis builds a low-quality placeholder RCA that records why the
// agent call failed. The typed AgentError kind is surfaced through capabilities,
// missing_data, and warnings so operators can see the failure category.
func fallbackAnalysis(alert Alert, err error) AgentAnalysisResponse {
	name := alert.Labels["alertname"]
	if name == "" {
		name = "Run:AI alert"
	}
	kind := agentErrorKind("unavailable")
	var agentErr *AgentError
	if errors.As(err, &agentErr) && agentErr != nil {
		kind = agentErr.Kind
	}
	summary := fmt.Sprintf("%s accepted, but agent analysis failed (%s): %v", name, kind, err)
	detail := strings.Join([]string{
		"## Root Cause",
		"",
		"Agent analysis is unavailable.",
		fmt.Sprintf("Failure category: `%s`.", kind),
		"",
		"## Recommended Actions",
		"",
		"Check Agent service health, timeouts, and configured integrations, then retry the analysis.",
	}, "\n")
	return AgentAnalysisResponse{
		Status:          "error",
		Analysis:        detail,
		AnalysisSummary: summary,
		AnalysisDetail:  detail,
		AnalysisQuality: "low",
		Capabilities:    map[string]string{"agent": string(kind)},
		MissingData:     []string{"agent.response"},
		Warnings:        []string{err.Error()},
	}
}
