package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAlertmanagerWebhookCreatesIncidentAndAlert(t *testing.T) {
	server := NewServer()
	body := AlertmanagerWebhook{
		GroupKey: "runai-test",
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIWorkloadPending",
					"severity":  "warning",
					"cluster":   "lab",
					"project":   "vision",
					"queue":     "gpu-a",
					"namespace": "runai-vision",
					"workload":  "trainer",
				},
				Annotations: map[string]string{"summary": "Workload pending"},
				Fingerprint: "fp-1",
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	if len(server.store.ListIncidents()) != 1 {
		t.Fatalf("expected one incident")
	}
	if len(server.store.ListAlerts()) != 1 {
		t.Fatalf("expected one alert")
	}
}

func TestAlertmanagerWebhookGroupsDiskPressureStormIntoOneAutoAnalysis(t *testing.T) {
	server := NewServer()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Node disk pressure is evicting Loki read pods.",
			AnalysisDetail:  "Disk pressure eviction storm was grouped into one RCA.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"kubernetes": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	alerts := make([]Alert, 0, 3)
	for i, pod := range []string{"loki-read-a", "loki-read-b", "loki-read-c"} {
		alerts = append(alerts, Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "KubePodEvicted",
				"severity":  "warning",
				"cluster":   "lab",
				"namespace": "monitoring",
				"pod":       pod,
				"node":      "k8s-lb-02",
				"reason":    "Evicted",
			},
			Annotations: map[string]string{
				"summary":     "Pod was evicted",
				"description": "The node had disk pressure.",
			},
			Fingerprint: "fp-disk-pressure-" + strconv.Itoa(i),
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
		})
	}
	payload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "disk-pressure-storm", Alerts: alerts})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["accepted"].(float64) != 3 || response["auto_analyses"].(float64) != 1 {
		t.Fatalf("unexpected webhook response: %+v", response)
	}
	incidents := server.store.ListIncidents()
	if len(incidents) != 1 || incidents[0].AlertCount != 3 {
		t.Fatalf("expected one grouped incident with three alerts, got %+v", incidents)
	}
	if !strings.Contains(strings.ToLower(incidents[0].Title), "disk pressure") {
		t.Fatalf("expected disk pressure grouped title, got %q", incidents[0].Title)
	}
	groupedAlerts := server.store.ListAlerts()
	if len(groupedAlerts) != 1 || groupedAlerts[0].OccurrenceCount != 3 {
		t.Fatalf("expected one grouped alert row with three occurrences, got %+v", groupedAlerts)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 || runs[0].TargetType != "incident" {
		t.Fatalf("expected one incident-level analysis run, got %+v", runs)
	}
}

func TestAlertmanagerWebhookDoesNotCreateAnalysisForRepeatedAlert(t *testing.T) {
	server := NewServer()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Repeated alert was deduplicated.",
			AnalysisDetail:  "Only the first webhook created an automatic RCA run.",
			AnalysisQuality: "medium",
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	alert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "KubePodEvicted",
			"severity":  "warning",
			"namespace": "monitoring",
			"pod":       "loki-read-a",
			"node":      "k8s-lb-02",
			"reason":    "Evicted",
		},
		Annotations: map[string]string{"summary": "Pod was evicted"},
		StartsAt:    "2026-06-30T10:00:00Z",
	}
	payload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "repeat-no-fingerprint", Alerts: []Alert{alert}})

	server.routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))
	server.routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	incidents := server.store.ListIncidents()
	if len(incidents) != 1 || incidents[0].AlertCount != 1 {
		t.Fatalf("expected repeated alert to upsert, got incidents=%+v", incidents)
	}
	alerts := server.store.ListAlerts()
	if len(alerts) != 1 || alerts[0].OccurrenceCount != 1 {
		t.Fatalf("expected one synthetic alert identity without counting resends, got %+v", alerts)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("expected one auto analysis run for repeated webhook, got %+v", runs)
	}
}

func TestAlertmanagerWebhookGroupsPodSuffixFlappingIntoOneAutoAnalysis(t *testing.T) {
	server := NewServer()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Loki read pods are crash-looping under one workload.",
			AnalysisDetail:  "Pod-suffix flapping was grouped into one RCA.",
			AnalysisQuality: "medium",
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	// Same workload (loki-read), but the controller keeps recreating the pod under a
	// new randomized name. Each occurrence carries its own fingerprint, exactly the
	// Loki flapping shape that flooded the store.
	pods := []string{
		"loki-read-7d9f8c6b5-x2k4p",
		"loki-read-7d9f8c6b5-a1b2c",
		"loki-read-7d9f8c6b5-z9y8x",
		"loki-read-7d9f8c6b5-q7w8e",
	}
	alerts := make([]Alert, 0, len(pods))
	for i, pod := range pods {
		alerts = append(alerts, Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "KubePodCrashLooping",
				"severity":  "warning",
				"cluster":   "lab",
				"namespace": "monitoring",
				"pod":       pod,
			},
			Annotations: map[string]string{"summary": "Loki read pod is crash looping"},
			Fingerprint: "fp-loki-flap-" + strconv.Itoa(i),
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
		})
	}
	payload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "loki-crashloop", Alerts: alerts})

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	incidents := server.store.ListIncidents()
	if len(incidents) != 1 || incidents[0].AlertCount != len(pods) {
		t.Fatalf("expected one grouped incident covering every pod, got %+v", incidents)
	}
	groupedAlerts := server.store.ListAlerts()
	if len(groupedAlerts) != 1 || groupedAlerts[0].OccurrenceCount != len(pods) {
		t.Fatalf("expected one grouped alert row with %d occurrences, got %+v", len(pods), groupedAlerts)
	}
	// The row is grouped by workload, but every concrete pod name stays on record.
	gotPods := append([]string{}, groupedAlerts[0].OccurrencePods...)
	sort.Strings(gotPods)
	wantPods := append([]string{}, pods...)
	sort.Strings(wantPods)
	if !reflect.DeepEqual(gotPods, wantPods) {
		t.Fatalf("expected occurrence pods %v, got %v", wantPods, gotPods)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("expected one auto analysis run for the grouped workload, got %d", len(runs))
	}

	// A second webhook of the same flapping workload must not create new rows.
	rec = httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))
	if got := len(server.store.ListAlerts()); got != 1 {
		t.Fatalf("expected resend to stay on one alert row, got %d", got)
	}
	if got := len(server.store.ListAnalysisRuns()); got != 1 {
		t.Fatalf("expected resend to not add analysis runs, got %d", got)
	}
}

func TestNormalizePodName(t *testing.T) {
	cases := map[string]string{
		"loki-read-7d9f8c6b5-x2k4p": "loki-read",    // Deployment: hash + random suffix
		"loki-read-x2k4p":           "loki-read",    // DaemonSet: random suffix only
		"trainer-0":                 "trainer",      // StatefulSet ordinal
		"trainer-12":                "trainer",      // StatefulSet ordinal (multi-digit)
		"gpu-operator":              "gpu-operator", // already a bare workload name
		"":                          "",             // empty stays empty
	}
	for pod, want := range cases {
		if got := normalizePodName(pod); got != want {
			t.Fatalf("normalizePodName(%q) = %q, want %q", pod, got, want)
		}
	}
}

func TestListAlertsSupportsPagination(t *testing.T) {
	server := NewServer()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	// Distinct workloads so each upserts its own alert row (grouping collapses
	// same-workload pods into one occurrence-counted row, which is tested elsewhere).
	workloads := []string{"queue-controller", "gpu-feeder", "scheduler"}
	for i, workload := range workloads {
		server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "page-test-" + strconv.Itoa(i)}, Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "RunAIQueueBlocked",
				"severity":  "warning",
				"namespace": "monitoring",
				"pod":       workload + "-" + strconv.Itoa(i),
			},
			Annotations: map[string]string{"summary": "Run:AI queue blocked"},
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Fingerprint: "fp-page-" + strconv.Itoa(i),
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?limit=1&offset=1", nil)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var response struct {
		Status     string         `json:"status"`
		Data       []AlertRecord  `json:"data"`
		Pagination paginationInfo `json:"pagination"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("expected one alert page item, got %d", len(response.Data))
	}
	if response.Pagination.Total != 3 || response.Pagination.Limit != 1 || response.Pagination.Offset != 1 || !response.Pagination.HasMore {
		t.Fatalf("unexpected pagination: %+v", response.Pagination)
	}
}

func TestListAlertsPaginationClampsOffsetBeyondTotal(t *testing.T) {
	server := NewServer()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	for i, workload := range []string{"scheduler", "queue-controller"} {
		server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "page-clamp-" + strconv.Itoa(i)}, Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "RunAIQueueBlocked",
				"severity":  "warning",
				"namespace": "monitoring",
				"pod":       workload + "-" + strconv.Itoa(i),
			},
			Annotations: map[string]string{"summary": "Run:AI queue blocked"},
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			Fingerprint: "fp-page-clamp-" + strconv.Itoa(i),
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?limit=1&offset=99", nil)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var response struct {
		Status     string         `json:"status"`
		Data       []AlertRecord  `json:"data"`
		Pagination paginationInfo `json:"pagination"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 0 {
		t.Fatalf("expected empty page past the end, got %d item(s)", len(response.Data))
	}
	if response.Pagination.Total != 2 || response.Pagination.Limit != 1 || response.Pagination.Offset != 2 || response.Pagination.HasMore {
		t.Fatalf("unexpected pagination: %+v", response.Pagination)
	}
}

func TestDashboardSnapshotCountsAllRowsButBoundsRecentItems(t *testing.T) {
	store := NewStore()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	alertIDs := []string{}
	incidentIDs := []string{}
	for i := 0; i < 8; i++ {
		status := "firing"
		if i%3 == 0 {
			status = "resolved"
		}
		incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "snapshot-" + strconv.Itoa(i)}, Alert{
			Status: status,
			Labels: map[string]string{
				"alertname": "RunAIQueueBlocked",
				"severity":  "warning",
				"namespace": "runai",
				"workload":  "trainer_" + strconv.Itoa(i),
			},
			Annotations: map[string]string{"summary": "Queue blocked"},
			Fingerprint: "fp-snapshot-" + strconv.Itoa(i),
			StartsAt:    base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			EndsAt:      base.Add(time.Duration(i+1) * time.Minute).Format(time.RFC3339),
		})
		alertIDs = append(alertIDs, alert.AlertID)
		incidentIDs = append(incidentIDs, incident.IncidentID)
	}
	complete := store.CreateAnalysisRun("manual", "alert", alertIDs[0], incidentIDs[0], alertIDs[0], "complete", "")
	store.CompleteAnalysisRun(complete.RunID, AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})
	failed := store.CreateAnalysisRun("comment", "alert", alertIDs[1], incidentIDs[1], alertIDs[1], "failed", "")
	store.FailAnalysisRun(failed.RunID, AgentAnalysisResponse{Status: "error", AnalysisSummary: "failed"})
	store.CreateAnalysisRun("chat", "alert", alertIDs[2], incidentIDs[2], alertIDs[2], "running", "")

	snapshot := store.DashboardSnapshot(3)

	if snapshot.IncidentCount != 8 || snapshot.AlertCount != 8 || snapshot.AnalysisRunCount != 3 {
		t.Fatalf("snapshot counts should include all rows, got %+v", snapshot)
	}
	if snapshot.FiringAlertCount != 5 || snapshot.OpenIncidentCount != 5 {
		t.Fatalf("snapshot status counts are wrong: %+v", snapshot)
	}
	if len(snapshot.RecentAlerts) != 3 || len(snapshot.RecentRuns) != 3 {
		t.Fatalf("snapshot recent rows should be capped at 3, got alerts=%d runs=%d", len(snapshot.RecentAlerts), len(snapshot.RecentRuns))
	}
	if snapshot.RecentAlerts[0].Fingerprint != "fp-snapshot-7" {
		t.Fatalf("expected latest alert first, got %+v", snapshot.RecentAlerts[0])
	}
	if snapshot.AnalysisStatuses["complete"] != 1 ||
		snapshot.AnalysisStatuses["failed"] != 1 ||
		snapshot.AnalysisStatuses["analyzing"] != 1 {
		t.Fatalf("unexpected analysis status counts: %+v", snapshot.AnalysisStatuses)
	}
}

func TestLatestAlertIDPrefersNewestFiringAlert(t *testing.T) {
	store := NewStore()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	_, firing := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "latest-firing"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"namespace": "runai",
			"workload":  "trainer-firing",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-latest-firing",
		StartsAt:    base.Format(time.RFC3339),
	})
	_, resolved := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "latest-resolved"}, Alert{
		Status: "resolved",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"namespace": "runai",
			"workload":  "trainer-resolved",
		},
		Annotations: map[string]string{"summary": "Queue recovered"},
		Fingerprint: "fp-latest-resolved",
		StartsAt:    base.Add(time.Hour).Format(time.RFC3339),
		EndsAt:      base.Add(time.Hour).Format(time.RFC3339),
	})

	if got := store.LatestAlertID(); got != firing.AlertID {
		t.Fatalf("expected latest firing alert to win over newer resolved alert, got %s", got)
	}
	store.mu.Lock()
	store.alerts[firing.AlertID].Status = "resolved"
	store.mu.Unlock()
	if got := store.LatestAlertID(); got != resolved.AlertID {
		t.Fatalf("expected newest resolved alert when no firing alert remains, got %s", got)
	}
}

func TestAlertmanagerWebhookIgnoresInfoAlerts(t *testing.T) {
	server := NewServer()
	body := AlertmanagerWebhook{
		GroupKey: "runai-info",
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIInfoOnly",
					"severity":  "info",
					"namespace": "runai",
				},
				Annotations: map[string]string{"summary": "Informational only"},
				Fingerprint: "fp-info",
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["alerts"].(float64) != 0 || response["ignored"].(float64) != 1 {
		t.Fatalf("unexpected webhook counts: %+v", response)
	}
	if len(server.store.ListIncidents()) != 0 || len(server.store.ListAlerts()) != 0 {
		t.Fatalf("info alert should not create incident or alert")
	}
	if len(server.store.ListAnalysisRuns()) != 0 {
		t.Fatalf("info alert should not create analysis runs")
	}
}

func TestAlertmanagerWebhookReportsAcceptedAndIgnoredCounts(t *testing.T) {
	server := NewServer()
	body := AlertmanagerWebhook{
		GroupKey: "runai-mixed",
		Alerts: []Alert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIInfoOnly",
					"severity":  "information",
					"namespace": "runai",
				},
				Annotations: map[string]string{"summary": "Informational only"},
				Fingerprint: "fp-mixed-info",
			},
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname": "RunAIWorkloadPending",
					"severity":  "warning",
					"namespace": "runai",
					"workload":  "trainer",
				},
				Annotations: map[string]string{"summary": "Workload pending"},
				Fingerprint: "fp-mixed-warning",
			},
		},
	}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["alerts"].(float64) != 1 || response["accepted"].(float64) != 1 || response["ignored"].(float64) != 1 {
		t.Fatalf("unexpected webhook counts: %+v", response)
	}
	if len(server.store.ListIncidents()) != 1 || len(server.store.ListAlerts()) != 1 {
		t.Fatalf("expected only warning alert to be stored")
	}
	if len(server.store.ListAnalysisRuns()) != 1 {
		t.Fatalf("expected one auto analysis run")
	}
}

func TestAlertmanagerWebhookRejectsTooManyAlerts(t *testing.T) {
	server := NewServer()
	alerts := make([]Alert, maxWebhookAlerts+1)
	for i := range alerts {
		alerts[i] = Alert{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
			Annotations: map[string]string{"summary": "Workload pending"},
			Fingerprint: "fp-too-many-" + strconv.Itoa(i),
		}
	}
	payload, _ := json.Marshal(AlertmanagerWebhook{GroupKey: "too-many", Alerts: alerts})
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(server.store.ListIncidents()) != 0 || len(server.store.ListAnalysisRuns()) != 0 {
		t.Fatalf("rejected webhook should not mutate store")
	}
}

func TestAgentRequestTimeoutConfig(t *testing.T) {
	t.Setenv("AGENT_REQUEST_TIMEOUT_SECONDS", "7")
	server := NewServer()

	if server.agentRequestTimeout != 7*time.Second {
		t.Fatalf("expected agent request timeout from env, got %s", server.agentRequestTimeout)
	}
	if server.client.Timeout != 0 {
		t.Fatalf("expected http client to rely on per-request contexts, got %s", server.client.Timeout)
	}
}

func TestChatRejectsOversizedBody(t *testing.T) {
	server := NewServer()
	payload := []byte(`{"message":"` + strings.Repeat("x", int(maxJSONBodyBytes)+1) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChatRouteProxiesContextualRCARequestToAgent(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan ChatRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat" {
			t.Fatalf("unexpected agent path: %s", r.URL.Path)
		}
		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent chat request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(ChatResponse{
			Status:         "ok",
			Answer:         "Agent compared this with prior gpu-a quota RCA.",
			ConversationID: "chat-agent",
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai",
			"workload":  "trainer",
		},
		Annotations: map[string]string{"summary": "Workload pending"},
		Fingerprint: "fp-chat",
	})
	server.store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:AI queue gpu-a is saturated.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota is exhausted.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	body, _ := json.Marshal(ChatRequest{
		Message:    "유사 RCA랑 비교해줘",
		IncidentID: incident.IncidentID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if response.ConversationID != "chat-agent" || !strings.Contains(response.Answer, "prior gpu-a") {
		t.Fatalf("unexpected chat response: %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.IncidentID != incident.IncidentID {
		t.Fatalf("incident id was not forwarded: %+v", agentReq)
	}
	if !strings.Contains(agentReq.IncidentContent, "gpu-a is saturated") {
		t.Fatalf("incident RCA content was not attached: %s", agentReq.IncidentContent)
	}
	if _, ok := agentReq.Context["rca_memory"]; !ok {
		t.Fatalf("expected RCA memory context, got %+v", agentReq.Context)
	}
	if _, ok := agentReq.Context["dashboard_state"]; !ok {
		t.Fatalf("expected dashboard state context, got %+v", agentReq.Context)
	}
	if _, ok := agentReq.Context["agent_runtime"]; !ok {
		t.Fatalf("expected agent runtime context, got %+v", agentReq.Context)
	}
}

func TestCommentCreatesAnalysisRun(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Comment-driven RCA refined the queue diagnosis.",
			AnalysisDetail:  "## Root Cause\n\nOperator comment was included in reanalysis.",
			AnalysisQuality: "high",
			Capabilities:    map[string]string{"analysis": "ok", "runai": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "comment-run"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-comment-run",
	})
	payload, _ := json.Marshal(CommentRequest{
		Body:   "Please re-check runai-backend scheduler logs before finalizing.",
		Author: "operator",
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/comments",
		bytes.NewReader(payload),
	)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected comment 200, got %d: %s", rec.Code, rec.Body.String())
	}
	agentReq := <-agentReqCh
	if agentReq.AnalysisType != "comment" {
		t.Fatalf("expected comment analysis type, got %+v", agentReq)
	}
	if !strings.Contains(agentReq.Alert.Annotations["operator_prompt"], "scheduler logs") {
		t.Fatalf("operator comment was not sent to agent: %+v", agentReq.Alert.Annotations)
	}
	run := waitForAnalysisRun(t, server, "comment")
	if run.Status != "complete" || !strings.Contains(run.AnalysisSummary, "Comment-driven") {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestCommentUpdateCreatesAnalysisRun(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 2)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Comment update RCA refined the diagnosis.",
			AnalysisDetail:  "## Root Cause\n\nUpdated operator comment was included.",
			AnalysisQuality: "high",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "comment-update-run"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-comment-update-run",
	})
	createPayload, _ := json.Marshal(CommentRequest{Body: "Initial comment.", Author: "operator"})
	createRec := httptest.NewRecorder()
	server.routes().ServeHTTP(createRec, httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/comments",
		bytes.NewReader(createPayload),
	))
	if createRec.Code != http.StatusOK {
		t.Fatalf("expected comment create 200, got %d: %s", createRec.Code, createRec.Body.String())
	}
	var createResponse struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResponse); err != nil {
		t.Fatalf("decode comment create response: %v", err)
	}
	if len(createResponse.Data.Comments) != 1 {
		t.Fatalf("expected created comment, got %+v", createResponse.Data)
	}
	<-agentReqCh

	updatePayload, _ := json.Marshal(CommentRequest{
		Body:   "Use scheduler logs instead of quota as the primary cause.",
		Author: "operator",
	})
	updateRec := httptest.NewRecorder()
	server.routes().ServeHTTP(updateRec, httptest.NewRequest(
		http.MethodPut,
		"/api/v1/incidents/"+incident.IncidentID+"/comments/"+createResponse.Data.Comments[0].CommentID,
		bytes.NewReader(updatePayload),
	))
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected comment update 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	agentReq := <-agentReqCh
	if agentReq.AnalysisType != "comment" {
		t.Fatalf("expected comment analysis type, got %+v", agentReq)
	}
	if !strings.Contains(agentReq.Alert.Annotations["operator_prompt"], "scheduler logs") {
		t.Fatalf("updated operator comment was not sent to agent: %+v", agentReq.Alert.Annotations)
	}
}

func TestChatAnalysisRequestCreatesAnalysisRun(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Chat-requested RCA completed.",
			AnalysisDetail:  "## Root Cause\n\nChat requested a separate analysis item.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat-run"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-chat-run",
	})
	payload, _ := json.Marshal(ChatRequest{
		Message:    "이 RCA 분석 다시 돌려줘",
		IncidentID: incident.IncidentID,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected chat 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if response.AnalysisRun == nil || response.AnalysisRun.Source != "chat" {
		t.Fatalf("expected chat analysis run in response: %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.AnalysisType != "chat" {
		t.Fatalf("expected chat analysis type, got %+v", agentReq)
	}
	run := waitForAnalysisRun(t, server, "chat")
	if run.Status != "complete" || !strings.Contains(run.AnalysisSummary, "Chat-requested") {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestChatAnalysisRequestWithoutTargetUsesLatestAlert(t *testing.T) {
	server := NewServer()
	agentReqCh := make(chan AgentAnalysisRequest, 1)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AgentAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode agent analysis request: %v", err)
		}
		agentReqCh <- req
		_ = json.NewEncoder(w).Encode(AgentAnalysisResponse{
			Status:          "ok",
			AnalysisSummary: "Latest alert RCA completed.",
			AnalysisDetail:  "## Root Cause\n\nChat selected the latest alert.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	_, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat-latest"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"queue":     "gpu-a",
		},
		Annotations: map[string]string{"summary": "Workload pending"},
		Fingerprint: "fp-chat-latest",
	})
	payload, _ := json.Marshal(ChatRequest{Message: "지금 알람 분석해줘"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected chat 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode chat response: %v", err)
	}
	if response.AnalysisRun == nil || response.AnalysisRun.TargetType != "alert" || response.AnalysisRun.TargetID != record.AlertID {
		t.Fatalf("expected latest alert analysis run, got %+v", response)
	}
	agentReq := <-agentReqCh
	if agentReq.IncidentID != record.IncidentID || agentReq.Alert.Fingerprint != "fp-chat-latest" {
		t.Fatalf("expected latest alert sent to agent, got %+v", agentReq)
	}
	run := waitForAnalysisRun(t, server, "chat")
	if run.Status != "complete" || !strings.Contains(run.AnalysisSummary, "Latest alert") {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestFeedbackAndSimilarIncidentMemory(t *testing.T) {
	store := NewStore()
	priorAlert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer",
		},
		Annotations: map[string]string{"summary": "Workload pending because GPU quota is exhausted"},
		Fingerprint: "fp-prior",
	}
	priorIncident, priorRecord := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "prior"}, priorAlert)
	store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:ai queue gpu-a was saturated and quota blocked scheduling.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota was exhausted in queue gpu-a.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	summary, ok, err := store.AddFeedback("incident", priorIncident.IncidentID, FeedbackRequest{
		Vote:    "up",
		Comment: "Matched the quota saturation incident we saw last week.",
		Author:  "operator",
	})
	if err != nil || !ok {
		t.Fatalf("feedback failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || len(summary.Comments) != 1 {
		t.Fatalf("unexpected feedback summary: %+v", summary)
	}

	currentAlert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer-v2",
		},
		Annotations: map[string]string{"summary": "Workload pending while waiting for GPU quota"},
		Fingerprint: "fp-current",
	}
	currentIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "current"}, currentAlert)
	similar := store.SimilarIncidentsForAlert(currentAlert, currentIncident.IncidentID, 5)
	if len(similar) == 0 {
		t.Fatalf("expected similar incident")
	}
	if similar[0].IncidentID != priorIncident.IncidentID {
		t.Fatalf("expected prior incident first, got %+v", similar[0])
	}
	if similar[0].PositiveFeedback != 1 || similar[0].CommentCount != 1 {
		t.Fatalf("expected feedback metadata on similar result, got %+v", similar[0])
	}
	hints := store.FeedbackHintsForAlert(currentAlert, currentIncident.IncidentID, 5)
	if len(hints) == 0 {
		t.Fatalf("expected feedback hints")
	}
	foundComment := false
	for _, hint := range hints {
		if strings.Contains(hint.Text, "quota saturation") {
			foundComment = true
			break
		}
	}
	if !foundComment {
		t.Fatalf("expected operator comment in feedback hints, got %+v", hints)
	}
	search := store.SearchIncidentMemory("gpu quota saturated scheduling", 5)
	if len(search) == 0 || search[0].IncidentID != priorIncident.IncidentID {
		t.Fatalf("expected embedding search to return prior incident, got %+v", search)
	}
}

func TestSimilarIncidentsLimitAndLatestTieBreak(t *testing.T) {
	store := NewStore()
	alert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"namespace": "runai",
			"pod":       "trainer-0",
		},
		Annotations: map[string]string{"summary": "GPU quota exhausted for trainer"},
		Fingerprint: "fp-current-similar-limit",
	}
	queryVector := textVector(alertSearchText(alert))
	base := time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		id := "INC-similar-000" + string(rune('1'+i))
		store.memories[id] = &IncidentMemory{
			IncidentID:      id,
			AlertID:         "ALR-similar-000" + string(rune('1'+i)),
			Title:           "RunAI workload pending",
			Severity:        "warning",
			Status:          "resolved",
			AnalysisSummary: "GPU quota exhausted for trainer",
			AnalysisDetail:  "Quota was expanded and the pod recovered.",
			Labels:          cloneMap(alert.Labels),
			CreatedAt:       base.Add(time.Duration(i) * time.Minute),
			Vector:          queryVector,
		}
	}

	similar := store.SimilarIncidentsForAlert(alert, "INC-current", 5)
	if len(similar) != similarIncidentLimit {
		t.Fatalf("expected %d similar incidents, got %d: %+v", similarIncidentLimit, len(similar), similar)
	}
	for i, want := range []string{"INC-similar-0004", "INC-similar-0003", "INC-similar-0002"} {
		if similar[i].IncidentID != want {
			t.Fatalf("expected latest tie-break result %s at %d, got %+v", want, i, similar)
		}
	}
}

func TestFeedbackHintsCapsInvalidLimit(t *testing.T) {
	store := NewStore()
	alert := Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"namespace": "runai",
			"pod":       "trainer-0",
		},
		Annotations: map[string]string{"summary": "GPU quota exhausted for trainer"},
	}
	store.memories["INC-prior-hint"] = &IncidentMemory{
		IncidentID:      "INC-prior-hint",
		AlertID:         "ALR-prior-hint",
		Title:           "RunAI workload pending",
		Severity:        "warning",
		Status:          "resolved",
		AnalysisSummary: "GPU quota exhausted for trainer",
		AnalysisDetail:  "Quota was expanded.",
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
		Vector:          textVector(alertSearchText(alert)),
	}
	store.comments["CMT-prior-hint"] = &CommentRecord{
		CommentID:  "CMT-prior-hint",
		TargetType: "incident",
		TargetID:   "INC-prior-hint",
		IncidentID: "INC-prior-hint",
		Body:       "operator note",
		CreatedAt:  time.Now().UTC(),
	}

	hints := store.FeedbackHintsForAlert(alert, "INC-current", -1)
	if len(hints) == 0 || hints[0].Text != "operator note" {
		t.Fatalf("expected invalid limit to fall back to default hint cap, got %+v", hints)
	}
}

func TestFlappingAlertGroupingUsesNamespaceWorkloadAndWindow(t *testing.T) {
	store := NewStore()
	base := time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC)
	makeAlert := func(namespace, pod, fingerprint string, at time.Time) Alert {
		return Alert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "PodCrashLooping",
				"severity":  "warning",
				"cluster":   "lab",
				"namespace": namespace,
				"pod":       pod,
			},
			Annotations: map[string]string{"summary": "Pod is repeatedly failing"},
			Fingerprint: fingerprint,
			StartsAt:    at.Format(time.RFC3339),
		}
	}

	firstIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "same-am-group"}, makeAlert("runai-a", "trainer-7d9f8c6b5-aaaa1", "fp-flap-1", base))
	// Same workload, fresh controller-generated pod name inside the window: this is
	// the Loki/CrashLoop flapping shape, and it must collapse onto one incident.
	rotatedPodIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "same-am-group"}, makeAlert("runai-a", "trainer-7d9f8c6b5-bbbb2", "fp-flap-2", base.Add(10*time.Minute)))
	if rotatedPodIncident.IncidentID != firstIncident.IncidentID {
		t.Fatalf("same-workload alert with a rotated pod suffix inside window should group: %s != %s", rotatedPodIncident.IncidentID, firstIncident.IncidentID)
	}

	differentNamespaceIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "same-am-group"}, makeAlert("runai-b", "trainer-7d9f8c6b5-cccc3", "fp-flap-3", base.Add(11*time.Minute)))
	if differentNamespaceIncident.IncidentID == firstIncident.IncidentID {
		t.Fatalf("alerts from different namespaces must not group")
	}
	differentWorkloadIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "same-am-group"}, makeAlert("runai-a", "inference-5c8f9d7a4-dddd4", "fp-flap-4", base.Add(12*time.Minute)))
	if differentWorkloadIncident.IncidentID == firstIncident.IncidentID {
		t.Fatalf("alerts from different workloads must not group")
	}
	outsideWindowIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "same-am-group"}, makeAlert("runai-a", "trainer-7d9f8c6b5-eeee5", "fp-flap-5", base.Add(45*time.Minute)))
	if outsideWindowIncident.IncidentID == firstIncident.IncidentID {
		t.Fatalf("same-workload alert outside flapping window should start a new incident")
	}
}

func TestResolveEndpointTogglesResolvedStatus(t *testing.T) {
	server := NewServer()
	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "resolve-toggle"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"namespace": "runai",
			"pod":       "trainer-0",
		},
		Annotations: map[string]string{"summary": "Workload pending"},
		Fingerprint: "fp-resolve-toggle",
	})
	path := "/api/v1/incidents/" + incident.IncidentID + "/resolve"

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first resolve 200, got %d: %s", rec.Code, rec.Body.String())
	}
	detail, ok := server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.Status != "resolved" || detail.ResolvedAt == nil {
		t.Fatalf("expected incident to be resolved, got ok=%t detail=%+v", ok, detail)
	}

	rec = httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected second resolve 200, got %d: %s", rec.Code, rec.Body.String())
	}
	detail, ok = server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.Status != "firing" || detail.ResolvedAt != nil {
		t.Fatalf("expected second resolve click to reopen incident, got ok=%t detail=%+v", ok, detail)
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "firing" {
		t.Fatalf("expected response status firing, got %+v", response)
	}
}

func TestDenseEmbeddingIsDeterministicAndNormalized(t *testing.T) {
	text := "Run:AI GPU quota saturated scheduling blocked"
	a := denseEmbedding(text)
	b := denseEmbedding(text)
	if len(a) != embeddingDim {
		t.Fatalf("expected embedding dimension %d, got %d", embeddingDim, len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("embedding is not deterministic at index %d: %v vs %v", i, a[i], b[i])
		}
	}
	var norm float64
	for _, v := range a {
		norm += float64(v) * float64(v)
	}
	if math.Abs(norm-1) > 1e-5 {
		t.Fatalf("embedding should be L2-normalized, got norm^2=%v", norm)
	}
	if literal := embeddingLiteral(a); literal[0] != '[' || literal[len(literal)-1] != ']' {
		t.Fatalf("embedding literal must be bracketed for pgvector, got %q", literal)
	}
	if empty := denseEmbedding(""); len(empty) != embeddingDim {
		t.Fatalf("empty text should still yield a zero vector of the right dim, got %d", len(empty))
	}
}

func TestReapStaleAnalyzingRunsMarksFailed(t *testing.T) {
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "reap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-reap",
	})
	// Simulate a run left "analyzing" by a previous process (no goroutine ran).
	stale := store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	done := store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	store.CompleteAnalysisRun(done.RunID, AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})

	reaped := store.ReapStaleAnalyzingRuns()
	if reaped != 1 {
		t.Fatalf("expected exactly 1 stale run reaped, got %d", reaped)
	}

	var staleAfter, doneAfter AnalysisRun
	for _, run := range store.ListAnalysisRuns() {
		switch run.RunID {
		case stale.RunID:
			staleAfter = run
		case done.RunID:
			doneAfter = run
		}
	}
	if staleAfter.Status != "failed" {
		t.Fatalf("stale run should be failed, got %q", staleAfter.Status)
	}
	if len(staleAfter.Warnings) == 0 || staleAfter.Capabilities["agent"] != "interrupted" {
		t.Fatalf("stale run missing interruption warning/capability: %+v", staleAfter)
	}
	if doneAfter.Status != "complete" {
		t.Fatalf("completed run must be untouched, got %q", doneAfter.Status)
	}

	alert, _ := store.AlertDetail(record.AlertID)
	if alert.IsAnalyzing {
		t.Fatalf("alert is_analyzing flag should be cleared after reap")
	}
	if detail, ok := store.IncidentDetail(incident.IncidentID); !ok || detail.IsAnalyzing {
		t.Fatalf("incident is_analyzing flag should be cleared after reap")
	}
}

func waitForAnalysisRun(t *testing.T, server *Server, source string) AnalysisRun {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, run := range server.store.ListAnalysisRuns() {
			if run.Source == source && run.Status != "analyzing" {
				return run
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("analysis run with source %q did not complete: %+v", source, server.store.ListAnalysisRuns())
	return AnalysisRun{}
}

func TestAlertListIncludesSimilarIncidentMemory(t *testing.T) {
	server := NewServer()
	priorIncident, priorRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "list-prior"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer",
		},
		Annotations: map[string]string{"summary": "Workload pending because GPU quota is exhausted"},
		Fingerprint: "fp-list-prior",
	})
	server.store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Run:AI queue gpu-a was saturated and quota blocked scheduling.",
		AnalysisDetail:  "## Root Cause\n\nGPU quota was exhausted in queue gpu-a.",
		AnalysisQuality: "high",
		Capabilities:    map[string]string{"runai": "ok"},
	})
	_, currentRecord := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "list-current"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIWorkloadPending",
			"severity":  "warning",
			"cluster":   "lab",
			"project":   "vision",
			"queue":     "gpu-a",
			"namespace": "runai-vision",
			"workload":  "trainer-v2",
		},
		Annotations: map[string]string{"summary": "Workload pending while waiting for GPU quota"},
		Fingerprint: "fp-list-current",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data []AlertRecord `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode alert list response: %v", err)
	}
	foundCurrent := false
	for _, alert := range response.Data {
		if alert.AlertID != currentRecord.AlertID {
			continue
		}
		foundCurrent = true
		if len(alert.SimilarIncidents) == 0 {
			t.Fatalf("expected similar incidents in alert list response")
		}
		if alert.SimilarIncidents[0].IncidentID != priorIncident.IncidentID {
			t.Fatalf("expected prior incident first, got %+v", alert.SimilarIncidents[0])
		}
	}
	if !foundCurrent {
		t.Fatalf("current alert missing from list response")
	}
}

func TestFeedbackVoteToggleCancelsSameActorVote(t *testing.T) {
	store := NewStore()
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "toggle"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-toggle",
	})

	summary, ok, err := store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "up",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("upvote failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || summary.Negative != 0 || summary.MyVote != "up" {
		t.Fatalf("unexpected upvote summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "none",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("cancel failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 0 || summary.Negative != 0 || summary.MyVote != "" {
		t.Fatalf("unexpected cancel summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "down",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("downvote failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 0 || summary.Negative != 1 || summary.MyVote != "down" {
		t.Fatalf("unexpected downvote summary: %+v", summary)
	}

	summary, ok, err = store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		VoteType: "up",
		Author:   "browser-test",
	})
	if err != nil || !ok {
		t.Fatalf("switch failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || summary.Negative != 0 || summary.MyVote != "up" {
		t.Fatalf("unexpected switched summary: %+v", summary)
	}
}

func TestFeedbackRejectsOversizedCommentFields(t *testing.T) {
	store := NewStore()
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "feedback-bounds"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-feedback-bounds",
	})

	tooLongComment := strings.Repeat("x", maxStoredCommentBodyBytes+1)
	tooLongAuthor := strings.Repeat("a", maxFeedbackAuthorBytes+1)

	if _, _, err := store.AddComment("incident", incident.IncidentID, CommentRequest{Body: tooLongComment}); err == nil {
		t.Fatalf("expected oversized comment body to be rejected")
	}
	if _, _, err := store.AddComment("incident", incident.IncidentID, CommentRequest{Body: "Check scheduler logs.", Author: tooLongAuthor}); err == nil {
		t.Fatalf("expected oversized comment author to be rejected")
	}
	if _, _, err := store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{Vote: "up", Comment: tooLongComment}); err == nil {
		t.Fatalf("expected oversized feedback comment to be rejected")
	}
	if _, _, err := store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{Vote: "up", Author: tooLongAuthor}); err == nil {
		t.Fatalf("expected oversized feedback author to be rejected")
	}
}

func TestFeedbackRoutesReturnSummary(t *testing.T) {
	server := NewServer()
	incident, _ := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "route"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "critical",
			"namespace": "runai",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-route",
	})
	payload, _ := json.Marshal(FeedbackRequest{
		Vote:    "down",
		Comment: "Need scheduler logs before trusting this RCA.",
	})
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/incidents/"+incident.IncidentID+"/feedback",
		bytes.NewReader(payload),
	)
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode feedback response: %v", err)
	}
	if response.Data.Negative != 1 || len(response.Data.Comments) != 1 {
		t.Fatalf("unexpected feedback response: %+v", response.Data)
	}
	commentID := response.Data.Comments[0].CommentID

	updatePayload, _ := json.Marshal(CommentRequest{Body: "Scheduler logs showed a different queue path."})
	updateReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/incidents/"+incident.IncidentID+"/comments/"+commentID,
		bytes.NewReader(updatePayload),
	)
	updateRec := httptest.NewRecorder()

	server.routes().ServeHTTP(updateRec, updateReq)

	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected comment update 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	var updateResponse struct {
		Data FeedbackSummary `json:"data"`
	}
	if err := json.Unmarshal(updateRec.Body.Bytes(), &updateResponse); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updateResponse.Data.Comments[0].Body != "Scheduler logs showed a different queue path." {
		t.Fatalf("comment was not updated: %+v", updateResponse.Data.Comments[0])
	}

	deleteReq := httptest.NewRequest(
		http.MethodDelete,
		"/api/v1/incidents/"+incident.IncidentID+"/comments/"+commentID,
		nil,
	)
	deleteRec := httptest.NewRecorder()

	server.routes().ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected comment delete 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	searchBody, _ := json.Marshal(EmbeddingSearchRequest{Query: "queue blocked scheduler", Limit: 3})
	searchReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/embeddings/search",
		bytes.NewReader(searchBody),
	)
	searchRec := httptest.NewRecorder()

	server.routes().ServeHTTP(searchRec, searchReq)

	if searchRec.Code != http.StatusOK {
		t.Fatalf("expected embedding search 200, got %d: %s", searchRec.Code, searchRec.Body.String())
	}
}

func TestEmbeddingSearchRejectsOversizedQuery(t *testing.T) {
	server := NewServer()
	body, _ := json.Marshal(EmbeddingSearchRequest{Query: strings.Repeat("q", maxEmbeddingQueryBytes+1)})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(
		rec,
		httptest.NewRequest(http.MethodPost, "/api/v1/embeddings/search", bytes.NewReader(body)),
	)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized query 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
