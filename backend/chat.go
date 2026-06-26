package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ChatRequest is the operator chat payload accepted by /api/v1/chat.
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

// ChatResponse is the chat answer, optionally carrying a freshly created
// analysis run when the operator asked to (re)run an analysis.
type ChatResponse struct {
	Status         string       `json:"status"`
	Answer         string       `json:"answer"`
	Message        string       `json:"message,omitempty"`
	Response       string       `json:"response,omitempty"`
	ConversationID string       `json:"conversation_id"`
	AnalysisRun    *AnalysisRun `json:"analysis_run,omitempty"`
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
			finalizeChatResponse(&answer, req)
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
		finalizeChatResponse(&answer, req)
		writeJSON(w, http.StatusAccepted, answer)
		return
	}
	answer, err := s.callChat(req)
	if err != nil {
		answer = fallbackChatResponse(req, err)
	}
	finalizeChatResponse(&answer, req)
	writeJSON(w, http.StatusOK, answer)
}

// finalizeChatResponse ensures the conversation id and mirror fields used by the
// frontend (message/response) are always populated.
func finalizeChatResponse(answer *ChatResponse, req ChatRequest) {
	if answer.ConversationID == "" {
		answer.ConversationID = req.ConversationID
	}
	if answer.ConversationID == "" {
		answer.ConversationID = fmt.Sprintf("chat-%d", time.Now().UnixNano())
	}
	if answer.Status == "" {
		answer.Status = "ok"
	}
	if answer.Message == "" {
		answer.Message = answer.Answer
	}
	if answer.Response == "" {
		answer.Response = answer.Answer
	}
}

// enrichChatRequest hydrates the chat payload with the incident/alert RCA, the
// similar-incident memory, and the feedback hints so the agent always sees the
// full operator context.
func (s *Server) enrichChatRequest(req ChatRequest) ChatRequest {
	if req.Context == nil {
		req.Context = map[string]any{}
	}
	req.IncidentID = strings.TrimSpace(first(req.IncidentID, stringFromContext(req.Context, "incident_id")))
	req.AlertID = strings.TrimSpace(first(req.AlertID, stringFromContext(req.Context, "alert_id")))

	var contextAlert *Alert
	var contextIncidentID string

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
			resolved := alertFromRecord(*alert)
			contextAlert = &resolved
			contextIncidentID = alert.IncidentID
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
			if contextIncidentID == "" {
				contextIncidentID = detail.IncidentID
			}
		}
	}

	// Fall back to a representative alert for the incident so similar-incident
	// and feedback context is available even when chatting at incident scope.
	if contextAlert == nil && req.IncidentID != "" {
		if alert, incidentID, _, _, _, ok := s.store.AnalysisTarget("incident", req.IncidentID); ok {
			contextAlert = &alert
			contextIncidentID = incidentID
		}
	}

	if contextAlert != nil {
		req.Context["similar_incidents"] = s.store.SimilarIncidentsForAlert(*contextAlert, contextIncidentID, 5)
		req.Context["feedback_hints"] = s.store.FeedbackHintsForAlert(*contextAlert, contextIncidentID, 5)
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
