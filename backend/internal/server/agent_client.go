package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// AgentAnalysisRequest is the payload the backend sends to the agent /analyze endpoint.
type AgentAnalysisRequest struct {
	Alert            Alert             `json:"alert"`
	ThreadTS         string            `json:"thread_ts"`
	IncidentID       string            `json:"incident_id,omitempty"`
	AnalysisType     string            `json:"analysis_type,omitempty"`
	Language         string            `json:"language,omitempty"`
	OccurrenceCount  int               `json:"occurrence_count,omitempty"`
	OccurrencePods   []string          `json:"occurrence_pods,omitempty"`
	SimilarIncidents []SimilarIncident `json:"similar_incidents,omitempty"`
	FeedbackHints    []FeedbackHint    `json:"feedback_hints,omitempty"`
}

// AgentAnalysisResponse is the structured RCA returned by the agent /analyze endpoint.
type AgentAnalysisResponse struct {
	Status          string            `json:"status"`
	TerminalReason  string            `json:"terminal_reason,omitempty"`
	ThreadTS        string            `json:"thread_ts"`
	Analysis        string            `json:"analysis"`
	AnalysisSummary string            `json:"analysis_summary"`
	AnalysisDetail  string            `json:"analysis_detail"`
	AnalysisType    string            `json:"analysis_type"`
	AnalysisQuality string            `json:"analysis_quality"`
	RootCauseFamily string            `json:"root_cause_family"`
	MissingData     []string          `json:"missing_data"`
	Warnings        []string          `json:"warnings"`
	Capabilities    map[string]string `json:"capabilities"`
	Context         map[string]any    `json:"context"`
	Artifacts       []Artifact        `json:"artifacts"`
	// AffectedPods are the concrete workload pod names the agent discovered for
	// the alert subject (empty for unscoped alerts). Used to replace the
	// kube-state-metrics exporter pod named in the raw alert payload.
	AffectedPods []string `json:"affected_pods,omitempty"`
}

// agentErrorKind classifies why an agent call failed so callers can attach a
// consistent warning to the analysis run and fallback RCA.
type agentErrorKind string

const (
	agentErrEncode        agentErrorKind = "encode"
	agentErrTimeout       agentErrorKind = "timeout"
	agentErrNetwork       agentErrorKind = "network"
	agentErrStatus        agentErrorKind = "non_2xx"
	agentErrInvalidJSON   agentErrorKind = "invalid_json"
	agentErrRequestTooBig agentErrorKind = "request_too_large"
	agentErrBodyTooBig    agentErrorKind = "response_too_large"
	agentErrBusy          agentErrorKind = "busy"
)

const (
	maxAgentRequestBodyBytes  int64 = 256 << 10
	maxAgentResponseBodyBytes int64 = 2 << 20
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
	case agentErrRequestTooBig:
		return fmt.Sprintf("agent request exceeded limit: %v", e.Err)
	case agentErrBodyTooBig:
		return fmt.Sprintf("agent response exceeded limit: %v", e.Err)
	case agentErrBusy:
		return fmt.Sprintf("agent concurrency limit reached: %v", e.Err)
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
func (s *Server) callAnalyze(req AgentAnalysisRequest, timeout time.Duration) (AgentAnalysisResponse, error) {
	body, err := s.postAgent("/analyze", req, timeout)
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
	body, err := s.postAgent("/chat", req, s.agentRequestTimeout)
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
func (s *Server) postAgent(path string, payload any, timeout time.Duration) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, &AgentError{Kind: agentErrEncode, Err: err}
	}
	if int64(len(encoded)) > maxAgentRequestBodyBytes {
		return nil, &AgentError{
			Kind: agentErrRequestTooBig,
			Err:  fmt.Errorf("body exceeded %d bytes", maxAgentRequestBodyBytes),
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}
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
	responseLimit := s.agentResponseBodyLimit()
	body, truncated, readErr := readLimitedBody(resp.Body, responseLimit)
	if resp.StatusCode >= 300 {
		detail := excerpt(string(body), 500)
		if truncated {
			detail = first(detail, "response body") + fmt.Sprintf(" (truncated at %d bytes)", responseLimit)
		}
		if detail == "" && readErr != nil {
			detail = readErr.Error()
		}
		return nil, &AgentError{Kind: agentErrStatus, Status: resp.StatusCode, Err: errors.New(detail)}
	}
	if readErr != nil {
		return nil, classifyDoError(ctx, readErr)
	}
	if truncated {
		return nil, &AgentError{
			Kind: agentErrBodyTooBig,
			Err:  fmt.Errorf("body exceeded %d bytes", responseLimit),
		}
	}
	return body, nil
}

func (s *Server) agentResponseBodyLimit() int64 {
	if s != nil && s.agentResponseMaxBytes > 0 {
		return s.agentResponseMaxBytes
	}
	return maxAgentResponseBodyBytes
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		data, err := io.ReadAll(body)
		return data, false, err
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if int64(len(data)) <= limit {
		return data, false, err
	}
	return data[:limit], true, err
}
