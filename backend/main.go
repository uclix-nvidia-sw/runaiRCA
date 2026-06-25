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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	AlertID         string            `json:"alert_id"`
	IncidentID      string            `json:"incident_id"`
	AlarmTitle      string            `json:"alarm_title"`
	Severity        string            `json:"severity"`
	Status          string            `json:"status"`
	FiredAt         time.Time         `json:"fired_at"`
	ResolvedAt      *time.Time        `json:"resolved_at"`
	Fingerprint     string            `json:"fingerprint"`
	ThreadTS        string            `json:"thread_ts"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	AnalysisSummary string            `json:"analysis_summary"`
	AnalysisDetail  string            `json:"analysis_detail"`
	AnalysisQuality string            `json:"analysis_quality"`
	Capabilities    map[string]string `json:"capabilities"`
	MissingData     []string          `json:"missing_data"`
	Warnings        []string          `json:"warnings"`
	Artifacts       []Artifact        `json:"artifacts"`
	IsAnalyzing     bool              `json:"is_analyzing"`
}

type IncidentDetail struct {
	Incident
	AnalysisSummary string            `json:"analysis_summary"`
	AnalysisDetail  string            `json:"analysis_detail"`
	AnalysisQuality string            `json:"analysis_quality"`
	Capabilities    map[string]string `json:"capabilities"`
	MissingData     []string          `json:"missing_data"`
	Warnings        []string          `json:"warnings"`
	Artifacts       []Artifact        `json:"artifacts"`
	Alerts          []AlertRecord     `json:"alerts"`
}

type AgentAnalysisRequest struct {
	Alert        Alert  `json:"alert"`
	ThreadTS     string `json:"thread_ts"`
	IncidentID   string `json:"incident_id,omitempty"`
	AnalysisType string `json:"analysis_type,omitempty"`
	Language     string `json:"language,omitempty"`
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
	Message        string         `json:"message"`
	ConversationID string         `json:"conversation_id,omitempty"`
	Context        map[string]any `json:"context,omitempty"`
}

type ChatResponse struct {
	Status         string `json:"status"`
	Answer         string `json:"answer"`
	ConversationID string `json:"conversation_id"`
}

type Event struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type Store struct {
	mu            sync.RWMutex
	incidentSeq   atomic.Int64
	alertSeq      atomic.Int64
	incidents     map[string]*Incident
	incidentByKey map[string]string
	alerts        map[string]*AlertRecord
	alertByFinger map[string]string
}

func NewStore() *Store {
	return &Store{
		incidents:     make(map[string]*Incident),
		incidentByKey: make(map[string]string),
		alerts:        make(map[string]*AlertRecord),
		alertByFinger: make(map[string]string),
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
		incidentID = fmt.Sprintf("INC-%06d", s.incidentSeq.Add(1))
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
		alertID = fmt.Sprintf("ALR-%06d", s.alertSeq.Add(1))
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
		items = append(items, *cloneAlert(alert))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FiredAt.After(items[j].FiredAt) })
	return items
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
	return detail, true
}

func (s *Store) AlertDetail(id string) (*AlertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert := s.alerts[id]
	if alert == nil {
		return nil, false
	}
	return cloneAlert(alert), true
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
	}
}

func (s *Store) MarkAnalyzing(incidentID string, analyzing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident := s.incidents[incidentID]; incident != nil {
		incident.IsAnalyzing = analyzing
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
	return &Server{
		store:    NewStore(),
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
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/incidents/"):
		s.handleIncidentAction(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/alerts":
		writeJSON(w, http.StatusOK, envelope(s.store.ListAlerts()))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/alerts/"):
		s.handleAlert(w, r)
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
	id := pathPart(r.URL.Path, "/api/v1/incidents/")
	if id == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident id required"})
		return
	}
	if detail, ok := s.store.IncidentDetail(id); ok {
		writeJSON(w, http.StatusOK, envelope(detail))
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
}

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/incidents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
		return
	}
	id, action := parts[0], parts[1]
	switch action {
	case "analyze":
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
		now := time.Now().UTC()
		s.store.mu.Lock()
		if incident := s.store.incidents[id]; incident != nil {
			incident.Status = "resolved"
			incident.ResolvedAt = &now
		}
		s.store.mu.Unlock()
		s.hub.Broadcast(Event{Type: "incident.resolved", Data: map[string]any{"incident_id": id}})
		writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown incident action"})
	}
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	id := pathPart(r.URL.Path, "/api/v1/alerts/")
	if alert, ok := s.store.AlertDetail(id); ok {
		writeJSON(w, http.StatusOK, envelope(alert))
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
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
	answer := ChatResponse{
		Status:         "ok",
		Answer:         "Use the unified RCA workspace to inspect Run:ai, Kubernetes, Postgres, Prometheus, and Loki evidence for this context.",
		ConversationID: req.ConversationID,
	}
	if answer.ConversationID == "" {
		answer.ConversationID = fmt.Sprintf("chat-%d", time.Now().UnixNano())
	}
	writeJSON(w, http.StatusOK, answer)
}

func (s *Server) requestAnalysis(alert Alert, incidentID, alertID, threadTS string) {
	req := AgentAnalysisRequest{
		Alert:        alert,
		ThreadTS:     threadTS,
		IncidentID:   incidentID,
		AnalysisType: status(alert.Status),
		Language:     s.language,
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
	return &out
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
