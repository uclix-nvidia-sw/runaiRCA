package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

// AgentAnalysisRequest is the payload the backend sends to the agent /analyze endpoint.
type AgentAnalysisRequest struct {
	Alert            Alert             `json:"alert"`
	ThreadTS         string            `json:"thread_ts"`
	IncidentID       string            `json:"incident_id,omitempty"`
	AnalysisType     string            `json:"analysis_type,omitempty"`
	Language         string            `json:"language,omitempty"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents,omitempty"`
	FeedbackHints    []FeedbackHint    `json:"feedback_hints,omitempty"`
}

// AgentAnalysisResponse is the structured RCA returned by the agent /analyze endpoint.
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

// agentErrorKind classifies why an agent call failed so callers can attach a
// consistent warning to the analysis run and fallback RCA.
type agentErrorKind string

const (
	agentErrEncode      agentErrorKind = "encode"
	agentErrTimeout     agentErrorKind = "timeout"
	agentErrNetwork     agentErrorKind = "network"
	agentErrStatus      agentErrorKind = "non_2xx"
	agentErrInvalidJSON agentErrorKind = "invalid_json"
)

// AgentError is a typed error describing an agent call failure.
type AgentError struct {
	Kind   agentErrorKind
	Status int
	Err    error
}

func (e *AgentError) Error() string {
	if e == nil {
		return ""
	}
	switch e.Kind {
	case agentErrTimeout:
		return fmt.Sprintf("agent request timed out: %v", e.Err)
	case agentErrNetwork:
		return fmt.Sprintf("agent network error: %v", e.Err)
	case agentErrStatus:
		return fmt.Sprintf("agent returned status %d: %v", e.Status, e.Err)
	case agentErrInvalidJSON:
		return fmt.Sprintf("agent returned invalid JSON: %v", e.Err)
	case agentErrEncode:
		return fmt.Sprintf("failed to build agent request: %v", e.Err)
	default:
		return fmt.Sprintf("agent error: %v", e.Err)
	}
}

func (e *AgentError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// classifyDoError maps a transport-level error onto a timeout or network kind.
func classifyDoError(ctx context.Context, err error) *AgentError {
	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && ctx.Err() == context.DeadlineExceeded) {
		return &AgentError{Kind: agentErrTimeout, Err: err}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &AgentError{Kind: agentErrTimeout, Err: err}
	}
	return &AgentError{Kind: agentErrNetwork, Err: err}
}

// callAnalyze posts an analysis request to the agent and returns a structured
// response or a typed *AgentError describing the failure.
func (s *Server) callAnalyze(req AgentAnalysisRequest) (AgentAnalysisResponse, error) {
	body, err := s.postAgent("/analyze", req)
	if err != nil {
		return AgentAnalysisResponse{}, err
	}
	var analysis AgentAnalysisResponse
	if err := json.Unmarshal(body, &analysis); err != nil {
		return AgentAnalysisResponse{}, &AgentError{Kind: agentErrInvalidJSON, Err: err}
	}
	return analysis, nil
}

// callChat posts a chat request to the agent and returns a structured response
// or a typed *AgentError describing the failure.
func (s *Server) callChat(req ChatRequest) (ChatResponse, error) {
	body, err := s.postAgent("/chat", req)
	if err != nil {
		return ChatResponse{}, err
	}
	var answer ChatResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		return ChatResponse{}, &AgentError{Kind: agentErrInvalidJSON, Err: err}
	}
	return answer, nil
}

// postAgent performs a JSON POST against the agent and returns the raw body or a
// typed *AgentError. JSON decoding of the body is left to the caller so the
// invalid-JSON case can be classified per endpoint.
func (s *Server) postAgent(path string, payload any) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, &AgentError{Kind: agentErrEncode, Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.agentRequestTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.agentURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, &AgentError{Kind: agentErrEncode, Err: err}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, classifyDoError(ctx, err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		detail := excerpt(string(body), 500)
		if detail == "" && readErr != nil {
			detail = readErr.Error()
		}
		return nil, &AgentError{Kind: agentErrStatus, Status: resp.StatusCode, Err: errors.New(detail)}
	}
	if readErr != nil {
		return nil, classifyDoError(ctx, readErr)
	}
	return body, nil
}
