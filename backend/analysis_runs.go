package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// AnalysisRun is a single lifecycle record for an analysis request. Automatic
// webhook analysis is incident-scoped and idempotent; explicit operator
// requests still create their own runs so manual follow-up remains auditable.
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

// startAnalysisRun resolves the analysis target, creates an analyzing run when
// allowed, marks the target as analyzing, emits the started SSE event, and
// kicks off the agent call asynchronously.
func (s *Server) startAnalysisRun(targetType string, targetID string, source string, prompt string) (*AnalysisRun, bool) {
	alert, incidentID, alertID, threadTS, title, ok := s.store.AnalysisTarget(targetType, targetID)
	if !ok {
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

	occurrencePods, occurrenceCount := s.store.OccurrenceSummaryForTarget(incidentID, alertID)
	req := AgentAnalysisRequest{
		Alert:            alert,
		ThreadTS:         threadTS,
		IncidentID:       incidentID,
		AnalysisType:     first(source, status(alert.Status)),
		Language:         s.language,
		OccurrenceCount:  occurrenceCount,
		OccurrencePods:   occurrencePods,
		SimilarIncidents: s.store.SimilarIncidentsForAlert(alert, incidentID, similarIncidentLimit),
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
	s.store.ApplyAnalysisForRun(runID, alertID, analysis)
	s.broadcastAnalysisRunCompleted(run, incidentID, alertID)
}

func (s *Server) analysisRequestTimeout(source string) time.Duration {
	if source == "manual" {
		return s.manualAgentRequestTimeout
	}
	return s.agentRequestTimeout
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
