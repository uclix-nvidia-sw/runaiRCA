package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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
	SimilarIncidents []SimilarIncident `json:"similar_incidents"`
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
	SimilarIncidents []SimilarIncident `json:"similar_incidents"`
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

type Server struct {
	store               *Store
	hub                 *Hub
	agentURL            string
	language            string
	agentRequestTimeout time.Duration
	client              *http.Client
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
	agentRequestTimeout := time.Duration(getenvInt("AGENT_REQUEST_TIMEOUT_SECONDS", 180)) * time.Second
	if agentRequestTimeout <= 0 {
		agentRequestTimeout = 180 * time.Second
	}
	return &Server{
		store:               store,
		hub:                 NewHub(),
		agentURL:            strings.TrimRight(getenv("AGENT_URL", "http://localhost:8000"), "/"),
		language:            getenv("LANGUAGE", "en"),
		agentRequestTimeout: agentRequestTimeout,
		client:              &http.Client{Timeout: agentRequestTimeout},
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
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"database": s.store.databaseHealth(),
		})
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
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
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
			writeError(w, http.StatusNotFound, "analysis target not found")
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
	ctx, cancel := context.WithTimeout(context.Background(), s.agentRequestTimeout)
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

func (s *Server) requestAnalysis(alert Alert, incidentID, alertID, threadTS string, source string) {
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
		s.hub.Broadcast(analysisCompletedEvent("", source, "complete", incidentID, alertID))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		s.store.ApplyAnalysis(alertID, fallbackAnalysis(alert, errors.New(string(body))))
		s.hub.Broadcast(analysisCompletedEvent("", source, "complete", incidentID, alertID))
		return
	}
	var analysis AgentAnalysisResponse
	if err := json.Unmarshal(body, &analysis); err != nil {
		s.store.ApplyAnalysis(alertID, fallbackAnalysis(alert, err))
	} else {
		s.store.ApplyAnalysis(alertID, analysis)
	}
	s.hub.Broadcast(analysisCompletedEvent("", source, "complete", incidentID, alertID))
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
	s.hub.Broadcast(analysisStartedEvent(run.RunID, run.Source, targetType, targetID, incidentID, alertID))
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
	s.hub.Broadcast(analysisCompletedEvent(run.RunID, run.Source, run.Status, incidentID, alertID))
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
	out.MissingData = cloneStrings(in.MissingData)
	out.Warnings = cloneStrings(in.Warnings)
	out.Artifacts = cloneArtifacts(in.Artifacts)
	out.SimilarIncidents = cloneSimilar(in.SimilarIncidents)
	out.Feedback = cloneFeedbackSummary(in.Feedback)
	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return append([]string{}, in...)
}

func cloneArtifacts(in []Artifact) []Artifact {
	if in == nil {
		return []Artifact{}
	}
	return append([]Artifact{}, in...)
}

func cloneSimilar(in []SimilarIncident) []SimilarIncident {
	if in == nil {
		return []SimilarIncident{}
	}
	out := make([]SimilarIncident, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Labels = cloneMap(item.Labels)
	}
	return out
}

func cloneFeedbackSummary(in FeedbackSummary) FeedbackSummary {
	out := in
	if out.Comments == nil {
		out.Comments = []CommentRecord{}
	} else {
		out.Comments = append([]CommentRecord{}, in.Comments...)
	}
	if out.LearningHints != nil {
		out.LearningHints = append([]FeedbackHint{}, in.LearningHints...)
	}
	return out
}

func cloneAnalysisRun(in *AnalysisRun) AnalysisRun {
	if in == nil {
		return AnalysisRun{}
	}
	out := *in
	out.Capabilities = cloneMap(in.Capabilities)
	out.MissingData = cloneStrings(in.MissingData)
	out.Warnings = cloneStrings(in.Warnings)
	out.Artifacts = cloneArtifacts(in.Artifacts)
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

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
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
