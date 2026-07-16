package server

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

type ChatMessageRecord struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type ChatConversation struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	ContextLabel string              `json:"context_label"`
	IncidentID   string              `json:"incident_id,omitempty"`
	AlertID      string              `json:"alert_id,omitempty"`
	Messages     []ChatMessageRecord `json:"messages"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
}

const (
	dashboardChatRecentLimit = 5
	maxChatMessageBytes      = 8000
	maxChatMetadataBytes     = 256
	maxChatHistoryMessages   = 200
)

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req ChatRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	if len(req.Message) > maxChatMessageBytes {
		writeError(w, http.StatusBadRequest, "message is too long")
		return
	}
	userMessageAt := time.Now().UTC()
	req = s.enrichChatRequest(req)
	if wantsAnalysisRun(req.Message) {
		targetType, targetID, inferred := s.chatAnalysisTarget(req)
		adHoc := false
		if targetType == "" || targetID == "" {
			// Alertmanager never caught this problem, but the operator still wants
			// an analysis (e.g. "dgx02 노드가 이상해, 분석해줘" with no matching
			// alert). Create an ad-hoc incident from the request so the pipeline
			// has a real target and the work shows up in the incident list; the
			// chat message travels as the operator guidance steering the analysis.
			fp := fmt.Sprintf("chat-adhoc-%d", time.Now().UnixNano())
			_, record := s.store.UpsertAlert(AlertmanagerWebhook{GroupKey: fp}, Alert{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "OperatorRequestedAnalysis",
					"severity":  "info",
					"source":    "chat",
				},
				Annotations: map[string]string{"summary": excerpt(req.Message, 160)},
				Fingerprint: fp,
			})
			targetType, targetID = "alert", record.AlertID
			adHoc = true
		}
		run, ok := s.startAnalysisRun(targetType, targetID, "chat", req.Message)
		if !ok {
			if run != nil && run.Status == "analyzing" {
				answer := ChatResponse{
					Status:         "ok",
					Answer:         analysisAlreadyRunningAnswer(run, inferred),
					ConversationID: req.ConversationID,
					AnalysisRun:    run,
				}
				finalizeChatResponse(&answer, req)
				s.store.SaveChatExchange(req, answer, userMessageAt)
				writeJSON(w, http.StatusAccepted, answer)
				return
			}
			writeError(w, http.StatusNotFound, "analysis target not found")
			return
		}
		startedAnswer := analysisStartedAnswer(run, inferred)
		if adHoc {
			startedAnswer = adHocAnalysisStartedAnswer(run)
		}
		answer := ChatResponse{
			Status:         "ok",
			Answer:         startedAnswer,
			ConversationID: req.ConversationID,
			AnalysisRun:    run,
		}
		finalizeChatResponse(&answer, req)
		s.store.SaveChatExchange(req, answer, userMessageAt)
		writeJSON(w, http.StatusAccepted, answer)
		return
	}
	answer, err := s.callChat(req)
	if err != nil {
		answer = fallbackChatResponse(req, err)
	}
	finalizeChatResponse(&answer, req)
	s.store.SaveChatExchange(req, answer, userMessageAt)
	writeJSON(w, http.StatusOK, answer)
}

func (s *Server) handleChatConversations(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/chat/conversations":
		page, err := paginationFromRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, total := s.store.ListChatConversationsPage(page.Limit, page.Offset)
		writeJSON(w, http.StatusOK, paginatedEnvelope(items, page, total))
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/chat/conversations/"):
		id := pathPart(r.URL.Path, "/api/v1/chat/conversations/")
		if id == "" {
			writeError(w, http.StatusNotFound, "conversation not found")
			return
		}
		if !s.store.DeleteChatConversation(id) {
			writeError(w, http.StatusNotFound, "conversation not found")
			return
		}
		writeJSON(w, http.StatusOK, envelope(map[string]string{"id": id}))
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
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
	incomingContext := req.Context
	if incomingContext == nil {
		incomingContext = map[string]any{}
	}
	req.IncidentID = strings.TrimSpace(first(req.IncidentID, stringFromContext(incomingContext, "incident_id")))
	req.AlertID = strings.TrimSpace(first(req.AlertID, stringFromContext(incomingContext, "alert_id")))
	req.ConversationID = excerpt(req.ConversationID, maxChatMetadataBytes)
	req.Language = excerpt(req.Language, maxChatMetadataBytes)
	req.Page = excerpt(req.Page, maxChatMetadataBytes)
	req.IncidentTitle = ""
	req.IncidentContent = ""
	req.AlertTitle = ""
	req.AlertContent = ""
	req.Context = map[string]any{}
	req.Context["dashboard_state"] = s.dashboardChatState()
	req.Context["agent_runtime"] = s.agentRuntimeContext()

	var contextAlert *Alert
	var contextIncidentID string

	if req.AlertID != "" {
		if alert, ok := s.store.AlertDetail(req.AlertID); ok {
			req.IncidentID = alert.IncidentID
			req.AlertTitle = alert.AlarmTitle
			req.AlertContent = alertChatContent(alert)
			req.Context["alert"] = alertChatContext(alert)
			resolved := alertFromRecord(*alert)
			contextAlert = &resolved
			contextIncidentID = alert.IncidentID
		} else {
			req.AlertID = ""
		}
	}
	if req.IncidentID != "" {
		if detail, ok := s.store.IncidentDetail(req.IncidentID); ok {
			req.IncidentTitle = detail.Title
			req.IncidentContent = incidentChatContent(detail)
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
		req.Context["similar_incidents"] = compactSimilarIncidentContext(s.store.SimilarIncidentsForAlert(*contextAlert, contextIncidentID, similarIncidentLimit))
		req.Context["feedback_hints"] = s.store.FeedbackHintsForAlert(*contextAlert, contextIncidentID, similarIncidentLimit)
	}

	// Explicit conversation scope for the agent: with no incident/alert selected
	// the operator is deliberately asking about the whole live cluster, and the
	// agent must not present dashboard alert-history stats as cluster inventory.
	scope := "cluster"
	if req.AlertID != "" {
		scope = "alert"
	} else if req.IncidentID != "" {
		scope = "incident"
	}
	req.Context["scope"] = scope

	memoryQuery := strings.Join(
		[]string{req.Message, req.IncidentTitle, req.AlertTitle, req.IncidentContent, req.AlertContent},
		"\n",
	)
	req.Context["rca_memory"] = compactSimilarIncidentContext(s.store.SearchIncidentMemory(memoryQuery, 5))
	req.Context["page"] = req.Page
	return req
}

func (s *Server) dashboardChatState() map[string]any {
	snapshot := s.store.DashboardSnapshot(dashboardChatRecentLimit)
	state := map[string]any{
		"incident_count":      snapshot.IncidentCount,
		"alert_count":         snapshot.AlertCount,
		"analysis_run_count":  snapshot.AnalysisRunCount,
		"open_incident_count": snapshot.OpenIncidentCount,
		"firing_alert_count":  snapshot.FiringAlertCount,
		"analysis_statuses":   snapshot.AnalysisStatuses,
		"recent_alerts":       recentAlertSummaries(snapshot.RecentAlerts, dashboardChatRecentLimit),
		"recent_runs":         recentRunSummaries(snapshot.RecentRuns, dashboardChatRecentLimit),
	}
	if len(snapshot.RecentAlerts) > 0 {
		state["latest_alert"] = alertSummary(snapshot.RecentAlerts[0])
	}
	if len(snapshot.RecentRuns) > 0 {
		state["latest_run"] = runSummary(snapshot.RecentRuns[0])
	}
	return state
}

func (s *Server) agentRuntimeContext() map[string]any {
	return map[string]any{
		"agent_url":                       s.agentURL,
		"agent_request_timeout_seconds":   int(s.agentRequestTimeout.Seconds()),
		"database":                        s.store.databaseHealth(),
		"chat_mode":                       "deterministic_context",
		"chat_llm_runtime":                "not_directly_used",
		"analysis_runtime_failure_source": "analysis_runs.capabilities.agent and warnings",
	}
}

func recentAlertSummaries(alerts []AlertRecord, limit int) []map[string]any {
	if limit > len(alerts) {
		limit = len(alerts)
	}
	items := make([]map[string]any, 0, limit)
	for _, alert := range alerts[:limit] {
		items = append(items, alertSummary(alert))
	}
	return items
}

func recentRunSummaries(runs []AnalysisRun, limit int) []map[string]any {
	if limit > len(runs) {
		limit = len(runs)
	}
	items := make([]map[string]any, 0, limit)
	for _, run := range runs[:limit] {
		items = append(items, runSummary(run))
	}
	return items
}

func alertSummary(alert AlertRecord) map[string]any {
	return map[string]any{
		"alert_id":         alert.AlertID,
		"incident_id":      alert.IncidentID,
		"title":            excerpt(alert.AlarmTitle, 120),
		"severity":         alert.Severity,
		"status":           alert.Status,
		"fired_at":         alert.FiredAt,
		"is_analyzing":     alert.IsAnalyzing,
	}
}

func runSummary(run AnalysisRun) map[string]any {
	return map[string]any{
		"run_id":           run.RunID,
		"source":           run.Source,
		"status":           run.Status,
		"target_type":      run.TargetType,
		"target_id":        run.TargetID,
		"incident_id":      run.IncidentID,
		"alert_id":         run.AlertID,
		"title":            excerpt(run.Title, 120),
		"analysis_quality": run.AnalysisQuality,
		"capabilities":     run.Capabilities,
		"missing_data":     run.MissingData,
		"warnings":         run.Warnings,
		"artifact_count":   len(run.Artifacts),
		"created_at":       run.CreatedAt,
		"updated_at":       run.UpdatedAt,
	}
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
		strings.Contains(lowered, "create analysis") ||
		strings.Contains(lowered, "new analysis") {
		return true
	}
	// Verb "analyze" + "again" = re-run ("analyze this again"); the noun form
	// ("show the analysis again") is a replay and does not contain "analyze".
	if strings.Contains(lowered, "analyze") && strings.Contains(lowered, "again") {
		return true
	}
	if strings.Contains(lowered, "analyze") && strings.Contains(lowered, "rca") {
		return true
	}
	if strings.Contains(message, "재분석") {
		return true
	}
	if !strings.Contains(message, "분석") {
		return false
	}
	// "다시" alone is NOT a token: "분석 결과 다시 보여줘" is a replay request,
	// not a re-analysis ("다시 분석해줘" already matches via 해줘/돌려).
	for _, token := range []string{"해줘", "돌려", "진행", "요청", "새로", "시작", "만들"} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

func (s *Server) chatAnalysisTarget(req ChatRequest) (string, string, bool) {
	if req.AlertID != "" {
		return "alert", req.AlertID, false
	}
	if req.IncidentID != "" {
		return "incident", req.IncidentID, false
	}
	// Only guess "the latest alert" when the message actually refers to existing
	// alerts ("지금 알람 분석해줘"). An ad-hoc question about something Alertmanager
	// never caught must NOT silently hijack an unrelated alert — the caller creates
	// a fresh ad-hoc incident for it instead.
	if referencesExistingAlerts(req.Message) {
		if alertID := s.latestAlertTarget(); alertID != "" {
			return "alert", alertID, true
		}
	}
	return "", "", false
}

func referencesExistingAlerts(message string) bool {
	lowered := strings.ToLower(message)
	for _, token := range []string{
		"알람", "알림", "경보", "인시던트", "지금", "최근", "현재",
		"alert", "incident", "latest", "current",
	} {
		if strings.Contains(lowered, token) {
			return true
		}
	}
	return false
}

func (s *Server) latestAlertTarget() string {
	return s.store.LatestAlertID()
}

func analysisStartedAnswer(run *AnalysisRun, inferred bool) string {
	target := fmt.Sprintf("%s `%s`", run.TargetType, run.TargetID)
	if inferred {
		target = fmt.Sprintf("latest available %s `%s`", run.TargetType, run.TargetID)
	}
	return fmt.Sprintf(
		"새 분석 아이템 `%s`를 만들었고 %s 대상으로 에이전트 재분석을 시작했어. "+
			"Agent 연결 실패, timeout, non-2xx 같은 문제는 이 run이 곧 `failed`로 바뀌면서 warnings/capabilities에 기록돼. "+
			"Analysis Dashboard에서 상태와 결과를 이어서 볼 수 있어.",
		run.RunID,
		target,
	)
}

func adHocAnalysisStartedAnswer(run *AnalysisRun) string {
	return fmt.Sprintf(
		"이 요청과 맞는 Alertmanager 알림이 없어서 새 인시던트 `%s`를 만들고 분석 run `%s`를 시작했어. "+
			"요청 내용은 분석 지침(operator guidance)으로 에이전트에 전달돼. Incident 목록에서 진행 상황을 볼 수 있어.",
		run.IncidentID,
		run.RunID,
	)
}

func analysisAlreadyRunningAnswer(run *AnalysisRun, inferred bool) string {
	target := fmt.Sprintf("%s `%s`", run.TargetType, run.TargetID)
	if inferred {
		target = fmt.Sprintf("latest available %s `%s`", run.TargetType, run.TargetID)
	}
	return fmt.Sprintf("이미 분석 run `%s`가 %s 대상으로 진행 중이야. 새 Agent 요청은 보내지 않았고, Analysis Dashboard에서 이어서 보면 돼.", run.RunID, target)
}

func anyInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
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
	alerts := make([]string, 0, min(len(detail.Alerts), dashboardChatRecentLimit))
	for _, alert := range detail.Alerts[:min(len(detail.Alerts), dashboardChatRecentLimit)] {
		alerts = append(alerts, fmt.Sprintf(
			"%s %s %s %s",
			alert.AlertID,
			excerpt(alert.AlarmTitle, 120),
			alert.Severity,
			alert.Status,
		))
	}
	if omitted := len(detail.Alerts) - len(alerts); omitted > 0 {
		alerts = append(alerts, fmt.Sprintf("+%d more alerts", omitted))
	}
	return strings.Join([]string{
		"Title: " + excerpt(detail.Title, 120),
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
		"Title: " + excerpt(alert.AlarmTitle, 120),
		"Alert ID: " + alert.AlertID,
		"Incident ID: " + alert.IncidentID,
		"Status: " + alert.Status,
		"Severity: " + alert.Severity,
		"Labels: " + excerpt(string(labels), 1200),
		"Annotations: " + excerpt(string(annotations), 1200),
		// RCA is incident-level now (see incidentChatContext); the alert carries no analysis.
	}, "\n")
}

func incidentChatContext(detail *IncidentDetail) map[string]any {
	if detail == nil {
		return map[string]any{}
	}
	alerts := make([]map[string]any, 0, min(len(detail.Alerts), dashboardChatRecentLimit))
	for _, alert := range detail.Alerts[:min(len(detail.Alerts), dashboardChatRecentLimit)] {
		alerts = append(alerts, map[string]any{
			"alert_id": alert.AlertID,
			"title":    excerpt(alert.AlarmTitle, 120),
			"severity": alert.Severity,
			"status":   alert.Status,
		})
	}
	return map[string]any{
		"incident_id":       detail.IncidentID,
		"title":             excerpt(detail.Title, 120),
		"severity":          detail.Severity,
		"status":            detail.Status,
		"analysis_summary":  detail.AnalysisSummary,
		"analysis_quality":  detail.AnalysisQuality,
		"capabilities":      detail.Capabilities,
		"missing_data":      detail.MissingData,
		"warnings":          detail.Warnings,
		"similar_incidents": compactSimilarIncidentContext(detail.SimilarIncidents),
		"feedback":          feedbackChatContext(detail.Feedback),
		"alerts":            alerts,
		"omitted_alerts":    max(0, len(detail.Alerts)-len(alerts)),
	}
}

func alertChatContext(alert *AlertRecord) map[string]any {
	if alert == nil {
		return map[string]any{}
	}
	return map[string]any{
		"alert_id":          alert.AlertID,
		"incident_id":       alert.IncidentID,
		"title":             excerpt(alert.AlarmTitle, 120),
		"severity":          alert.Severity,
		"status":            alert.Status,
		"similar_incidents": compactSimilarIncidentContext(alert.SimilarIncidents),
		"feedback":          feedbackChatContext(alert.Feedback),
	}
}

func compactSimilarIncidentContext(items []SimilarIncident) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]any{
			"incident_id":       item.IncidentID,
			"alert_id":          item.AlertID,
			"title":             excerpt(item.Title, 120),
			"severity":          item.Severity,
			"status":            item.Status,
			"similarity":        item.Similarity,
			"analysis_summary":  excerpt(item.AnalysisSummary, 800),
			"positive_feedback": item.PositiveFeedback,
			"negative_feedback": item.NegativeFeedback,
			"comment_count":     item.CommentCount,
			"created_at":        item.CreatedAt,
		})
	}
	return out
}

func feedbackChatContext(feedback FeedbackSummary) map[string]any {
	return map[string]any{
		"positive":      feedback.Positive,
		"negative":      feedback.Negative,
		"my_vote":       feedback.MyVote,
		"comment_count": len(feedback.Comments),
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
