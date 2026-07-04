package server

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
	"unicode/utf8"
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
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 || runs[0].TargetType != "alert" || runs[0].AlertID != groupedAlerts[0].AlertID {
		t.Fatalf("expected one grouped-alert analysis run, got %+v", runs)
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

func TestIncidentAnalysisTargetPrefersFiringAlert(t *testing.T) {
	store := NewStore()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	incident, firing := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "analysis-target-firing"}, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-analysis-target-firing",
		StartsAt:    base.Format(time.RFC3339),
	})
	resolvedAt := base.Add(time.Hour)
	store.mu.Lock()
	store.alerts["ALR-analysis-target-resolved"] = &AlertRecord{
		AlertID:     "ALR-analysis-target-resolved",
		IncidentID:  incident.IncidentID,
		AlarmTitle:  "Recovered alert",
		Severity:    "warning",
		Status:      "resolved",
		FiredAt:     resolvedAt,
		ResolvedAt:  &resolvedAt,
		Fingerprint: "fp-analysis-target-resolved",
		ThreadTS:    "thread-resolved",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue recovered"},
	}
	store.mu.Unlock()

	alert, _, alertID, _, _, ok := store.AnalysisTarget("incident", incident.IncidentID)
	if !ok || alertID != firing.AlertID || status(alert.Status) != "firing" {
		t.Fatalf("expected firing alert target, got ok=%t alertID=%s alert=%+v", ok, alertID, alert)
	}
}

func TestIncidentSeverityNormalizesCaseBeforeRanking(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "severity-case"}
	incident, _ := store.UpsertAlert(webhook, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "Critical",
		},
		Annotations: map[string]string{"summary": "Queue blocked"},
	})
	if incident.Severity != "critical" {
		t.Fatalf("expected severity to be canonicalized, got %q", incident.Severity)
	}

	incident, _ = store.UpsertAlert(webhook, Alert{
		Status: "firing",
		Labels: map[string]string{
			"alertname": "RunAIQueueBlocked",
			"severity":  "warning",
		},
		Annotations: map[string]string{"summary": "Queue still blocked"},
	})
	if incident.Severity != "critical" {
		t.Fatalf("warning alert should not downgrade critical incident, got %q", incident.Severity)
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

func TestAlertmanagerWebhookSkipsAutoAnalysisForResolvedOnlyIncident(t *testing.T) {
	server := NewServer()
	payload, _ := json.Marshal(AlertmanagerWebhook{
		GroupKey: "resolved-only",
		Alerts: []Alert{{
			Status:      "Resolved",
			Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
			Annotations: map[string]string{"summary": "Workload recovered"},
			Fingerprint: "fp-resolved-only",
		}},
	})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 0 {
		t.Fatalf("resolved-only webhook should not start auto analysis, got %+v", runs)
	}
	alerts := server.store.ListAlerts()
	if len(alerts) != 1 || alerts[0].Status != "resolved" {
		t.Fatalf("resolved status should be canonicalized, got %+v", alerts)
	}
}

func TestAlertmanagerWebhookSkipsAutoAnalysisWhenAlertResolvesInSamePayload(t *testing.T) {
	server := NewServer()
	payload, _ := json.Marshal(AlertmanagerWebhook{
		GroupKey: "firing-then-resolved",
		Alerts: []Alert{
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
				Annotations: map[string]string{"summary": "Workload pending"},
				Fingerprint: "fp-firing-then-resolved",
			},
			{
				Status:      "resolved",
				Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
				Annotations: map[string]string{"summary": "Workload recovered"},
				Fingerprint: "fp-firing-then-resolved",
			},
		},
	})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["auto_analyses"].(float64) != 0 {
		t.Fatalf("resolved final state should not start auto analysis, got %+v", response)
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 0 {
		t.Fatalf("resolved final state should not create analysis runs, got %+v", runs)
	}
	alerts := server.store.ListAlerts()
	if len(alerts) != 1 || alerts[0].Status != "resolved" {
		t.Fatalf("expected final alert status resolved, got %+v", alerts)
	}
}

func TestAlertmanagerWebhookAnalyzesNewIncidentWhenFiringFollowsResolved(t *testing.T) {
	server := NewServer()
	payload, _ := json.Marshal(AlertmanagerWebhook{
		GroupKey: "resolved-then-firing",
		Alerts: []Alert{
			{
				Status:      "resolved",
				Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
				Annotations: map[string]string{"summary": "Workload recovered"},
			},
			{
				Status:      "firing",
				Labels:      map[string]string{"alertname": "RunAIWorkloadPending", "severity": "warning"},
				Annotations: map[string]string{"summary": "Workload pending again"},
			},
		},
	})
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", bytes.NewReader(payload)))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if runs := server.store.ListAnalysisRuns(); len(runs) != 1 {
		t.Fatalf("firing alert on new incident should start one auto analysis, got %+v", runs)
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

func TestChatRejectsOversizedMessage(t *testing.T) {
	server := NewServer()
	payload, _ := json.Marshal(ChatRequest{Message: strings.Repeat("x", maxChatMessageBytes+1)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestExcerptDoesNotSplitUTF8(t *testing.T) {
	got := excerpt("한글 alert", 4)
	if !utf8.ValidString(got) {
		t.Fatalf("excerpt returned invalid UTF-8: %q", got)
	}
	if got != "한..." {
		t.Fatalf("excerpt should stop at rune boundary, got %q", got)
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

func TestIncidentChatContextSummarizesAlerts(t *testing.T) {
	alerts := []AlertRecord{{
		AlertID:         "ALR-chat-context",
		AlarmTitle:      "RunAIQueueBlocked",
		Severity:        "warning",
		Status:          "firing",
		AnalysisSummary: "large RCA summary",
		AnalysisDetail:  strings.Repeat("detail ", 100),
		Labels:          map[string]string{"queue": "gpu-a"},
	}}
	for i := 0; i < dashboardChatRecentLimit+2; i++ {
		alerts = append(alerts, AlertRecord{
			AlertID:    "ALR-chat-extra-" + strconv.Itoa(i),
			AlarmTitle: strings.Repeat("extra-title-", 20),
			Severity:   "warning",
			Status:     "firing",
		})
	}
	context := incidentChatContext(&IncidentDetail{
		Incident: Incident{
			IncidentID: "INC-chat-context",
			Title:      "Queue blocked",
			Severity:   "warning",
			Status:     "firing",
		},
		Feedback: FeedbackSummary{
			Positive: 1,
			Comments: []CommentRecord{{
				Body: strings.Repeat("operator comment ", 100),
			}},
		},
		SimilarIncidents: []SimilarIncident{{
			IncidentID:      "INC-prior-chat",
			AlertID:         "ALR-prior-chat",
			Title:           strings.Repeat("prior-title-", 20),
			Similarity:      0.91,
			AnalysisSummary: strings.Repeat("summary ", 200),
			AnalysisDetail:  strings.Repeat("detail ", 500),
		}},
		Alerts: alerts,
	})

	contextAlerts, ok := context["alerts"].([]map[string]any)
	if !ok || len(contextAlerts) != dashboardChatRecentLimit {
		t.Fatalf("expected summarized alert context, got %+v", context["alerts"])
	}
	if contextAlerts[0]["alert_id"] != "ALR-chat-context" || contextAlerts[0]["title"] != "RunAIQueueBlocked" {
		t.Fatalf("alert summary lost identity fields: %+v", contextAlerts[0])
	}
	if _, ok := contextAlerts[0]["analysis_detail"]; ok {
		t.Fatalf("chat context should not include full alert RCA detail: %+v", contextAlerts[0])
	}
	if _, ok := contextAlerts[0]["labels"]; ok {
		t.Fatalf("chat context should not include full alert labels: %+v", contextAlerts[0])
	}
	if context["omitted_alerts"] != 3 {
		t.Fatalf("expected omitted alert count, got %+v", context["omitted_alerts"])
	}
	if title, _ := contextAlerts[1]["title"].(string); len(title) > 123 || !strings.HasSuffix(title, "...") {
		t.Fatalf("alert titles should be capped, got %q", title)
	}
	feedback, ok := context["feedback"].(map[string]any)
	if !ok || feedback["comment_count"] != 1 {
		t.Fatalf("expected summarized feedback context, got %+v", context["feedback"])
	}
	if _, ok := feedback["comments"]; ok {
		t.Fatalf("chat context should not include full feedback comments: %+v", feedback)
	}
	similar, ok := context["similar_incidents"].([]map[string]any)
	if !ok || len(similar) != 1 {
		t.Fatalf("expected compact similar incident context, got %+v", context["similar_incidents"])
	}
	if _, ok := similar[0]["analysis_detail"]; ok {
		t.Fatalf("chat context should not include similar incident detail: %+v", similar[0])
	}
	if title, _ := similar[0]["title"].(string); len(title) > 123 || !strings.HasSuffix(title, "...") {
		t.Fatalf("similar incident title should be capped, got %q", title)
	}
	if summary, _ := similar[0]["analysis_summary"].(string); len(summary) > 803 || !strings.HasSuffix(summary, "...") {
		t.Fatalf("similar incident summary should be capped, got len=%d", len(summary))
	}
}

func TestChatContextDropsClientSuppliedPayload(t *testing.T) {
	server := NewServer()
	incident, alert := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "chat-context-trim"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-chat-context-trim",
	})

	req := server.enrichChatRequest(ChatRequest{
		Message:         "compare RCA",
		ConversationID:  strings.Repeat("conversation-", 40),
		Language:        strings.Repeat("language-", 40),
		Page:            strings.Repeat("page-", 80),
		IncidentContent: strings.Repeat("client supplied RCA ", 400),
		Context: map[string]any{
			"incident_id":      incident.IncidentID,
			"dashboard_state":  map[string]any{"fake": true},
			"untrusted_blob":   strings.Repeat("x", 4096),
			"similar_incident": strings.Repeat("y", 4096),
		},
	})

	if req.IncidentID != incident.IncidentID {
		t.Fatalf("incident id from context should still be honored, got %q", req.IncidentID)
	}
	if strings.Contains(req.IncidentContent, "client supplied RCA") {
		t.Fatalf("client-supplied incident content should be replaced with server context")
	}
	if len(req.ConversationID) > maxChatMetadataBytes+len("...") ||
		len(req.Language) > maxChatMetadataBytes+len("...") ||
		len(req.Page) > maxChatMetadataBytes+len("...") {
		t.Fatalf("chat metadata should be capped, got conversation=%d language=%d page=%d", len(req.ConversationID), len(req.Language), len(req.Page))
	}
	if req.Context["page"] != req.Page {
		t.Fatalf("context page should use capped page metadata")
	}
	missing := server.enrichChatRequest(ChatRequest{
		Message:         "compare RCA",
		IncidentID:      "INC-missing",
		IncidentTitle:   "client title",
		IncidentContent: strings.Repeat("client supplied RCA ", 400),
		AlertTitle:      "client alert",
		AlertContent:    strings.Repeat("client alert RCA ", 400),
	})
	if missing.IncidentTitle != "" || missing.IncidentContent != "" || missing.AlertTitle != "" || missing.AlertContent != "" {
		t.Fatalf("client-supplied content should be dropped for missing targets: %+v", missing)
	}
	mismatched := server.enrichChatRequest(ChatRequest{
		Message:    "compare RCA",
		IncidentID: "INC-wrong",
		AlertID:    alert.AlertID,
	})
	if mismatched.IncidentID != incident.IncidentID {
		t.Fatalf("alert context should correct mismatched incident id, got %q", mismatched.IncidentID)
	}
	alertContext, ok := mismatched.Context["alert"].(map[string]any)
	if !ok {
		t.Fatalf("expected sanitized alert context, got %+v", mismatched.Context["alert"])
	}
	if _, ok := alertContext["labels"]; ok {
		t.Fatalf("alert context should not include full labels: %+v", alertContext)
	}
	if _, ok := alertContext["annotations"]; ok {
		t.Fatalf("alert context should not include full annotations: %+v", alertContext)
	}
	if _, ok := alertContext["artifacts"]; ok {
		t.Fatalf("alert context should not include full artifacts: %+v", alertContext)
	}
	if _, ok := req.Context["untrusted_blob"]; ok {
		t.Fatalf("client-supplied context leaked to agent payload: %+v", req.Context)
	}
	if _, ok := req.Context["similar_incident"]; ok {
		t.Fatalf("client-supplied similar context leaked to agent payload: %+v", req.Context)
	}
	targetType, targetID, inferred := server.chatAnalysisTarget(req)
	if targetType != "incident" || targetID != incident.IncidentID || inferred {
		t.Fatalf("chat target should use sanitized incident id, got type=%q id=%q inferred=%t", targetType, targetID, inferred)
	}
	invalidAlert := server.enrichChatRequest(ChatRequest{
		Message:    "compare RCA",
		IncidentID: incident.IncidentID,
		AlertID:    "ALR-missing",
	})
	if invalidAlert.AlertID != "" || invalidAlert.IncidentID != incident.IncidentID {
		t.Fatalf("invalid alert id should fall back to incident target, got alert=%q incident=%q", invalidAlert.AlertID, invalidAlert.IncidentID)
	}
	targetType, targetID, inferred = server.chatAnalysisTarget(invalidAlert)
	if targetType != "incident" || targetID != incident.IncidentID || inferred {
		t.Fatalf("invalid alert should not block valid incident target, got type=%q id=%q inferred=%t", targetType, targetID, inferred)
	}
	state, ok := req.Context["dashboard_state"].(map[string]any)
	if !ok || state["fake"] != nil {
		t.Fatalf("dashboard_state should be server-generated, got %+v", req.Context["dashboard_state"])
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
	waitForAnalysisRun(t, server, "comment")

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

func TestWantsAnalysisRunDoesNotTreatReplayAsReanalysis(t *testing.T) {
	if wantsAnalysisRun("분석 결과 다시 보여줘") {
		t.Fatalf("replaying an analysis result should not start a new agent run")
	}
	for _, message := range []string{
		"이 RCA 분석 다시 돌려줘",
		"지금 알람 분석해줘",
		"분석 새로 시작해줘",
	} {
		if !wantsAnalysisRun(message) {
			t.Fatalf("expected analysis request for %q", message)
		}
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

func TestIncidentMemoryKeepsMultipleAlertAnalyses(t *testing.T) {
	store := NewStore()
	incident, first := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "multi-memory"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-memory-first",
	})
	secondID := "ALR-memory-second"
	store.mu.Lock()
	store.alerts[secondID] = &AlertRecord{
		AlertID:     secondID,
		IncidentID:  incident.IncidentID,
		AlarmTitle:  "Quota alert",
		Severity:    "critical",
		Status:      "firing",
		FiredAt:     first.FiredAt.Add(time.Minute),
		Fingerprint: "fp-memory-second",
		ThreadTS:    "thread-" + secondID,
		Labels:      map[string]string{"alertname": "RunAIQuotaBlocked", "severity": "critical", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Quota blocked"},
	}
	store.mu.Unlock()

	store.ApplyAnalysis(first.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Queue saturation RCA.",
		AnalysisDetail:  "Queue workers are waiting.",
	})
	store.ApplyAnalysis(secondID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Quota exhaustion RCA.",
		AnalysisDetail:  "GPU quota is exhausted.",
	})

	if len(store.memories) != 2 {
		t.Fatalf("expected two alert memories, got %+v", store.memories)
	}
	firstMemory := store.memories[first.AlertID]
	if firstMemory == nil || firstMemory.AnalysisSummary != "Queue saturation RCA." {
		t.Fatalf("first alert memory was overwritten: %+v", firstMemory)
	}
	secondMemory := store.memories[secondID]
	if secondMemory == nil || secondMemory.AnalysisSummary != "Quota exhaustion RCA." {
		t.Fatalf("second alert memory missing: %+v", secondMemory)
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

func TestSimilarIncidentsDedupesAlertMemoriesByIncident(t *testing.T) {
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
	}
	base := time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		alertID string
		at      time.Time
	}{
		{"ALR-prior-old", base},
		{"ALR-prior-new", base.Add(time.Minute)},
	} {
		store.memories[item.alertID] = &IncidentMemory{
			IncidentID:      "INC-prior-shared",
			AlertID:         item.alertID,
			Title:           "RunAI workload pending",
			Severity:        "warning",
			Status:          "resolved",
			AnalysisSummary: "GPU quota exhausted for trainer",
			AnalysisDetail:  "Quota was expanded.",
			Labels:          cloneMap(alert.Labels),
			CreatedAt:       item.at,
			Vector:          textVector(alertSearchText(alert)),
		}
	}

	similar := store.SimilarIncidentsForAlert(alert, "INC-current", 5)
	if len(similar) != 1 {
		t.Fatalf("expected one similar incident per prior incident, got %+v", similar)
	}
	if similar[0].AlertID != "ALR-prior-new" {
		t.Fatalf("expected latest tied alert memory to represent incident, got %+v", similar[0])
	}
	search := store.SearchIncidentMemory("GPU quota exhausted for trainer", 5)
	if len(search) != 1 || search[0].IncidentID != "INC-prior-shared" {
		t.Fatalf("expected search memory to dedupe by incident, got %+v", search)
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

func TestFeedbackHintsHonorsLimitAcrossVoteHints(t *testing.T) {
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
	store.memories["ALR-prior-limit"] = &IncidentMemory{
		IncidentID:      "INC-prior-limit",
		AlertID:         "ALR-prior-limit",
		Title:           "RunAI workload pending",
		Severity:        "warning",
		Status:          "resolved",
		AnalysisSummary: "GPU quota exhausted for trainer",
		AnalysisDetail:  "Quota was expanded.",
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
		Vector:          textVector(alertSearchText(alert)),
	}
	store.feedback["FDB-prior-up"] = &FeedbackRecord{
		FeedbackID: "FDB-prior-up",
		TargetType: "incident",
		TargetID:   "INC-prior-limit",
		Vote:       "up",
		Author:     "operator-a",
		CreatedAt:  time.Now().UTC(),
	}
	store.feedback["FDB-prior-down"] = &FeedbackRecord{
		FeedbackID: "FDB-prior-down",
		TargetType: "incident",
		TargetID:   "INC-prior-limit",
		Vote:       "down",
		Author:     "operator-b",
		CreatedAt:  time.Now().UTC(),
	}

	hints := store.FeedbackHintsForAlert(alert, "INC-current", 1)
	if len(hints) != 1 {
		t.Fatalf("expected feedback hints to honor limit, got %+v", hints)
	}
}

func TestFeedbackHintsCapHintText(t *testing.T) {
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
	store.memories["ALR-prior-long-hint"] = &IncidentMemory{
		IncidentID:      "INC-prior-long-hint",
		AlertID:         "ALR-prior-long-hint",
		Title:           "RunAI workload pending",
		Severity:        "warning",
		Status:          "resolved",
		AnalysisSummary: strings.Repeat("quota summary ", 200),
		AnalysisDetail:  "Quota was expanded.",
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
		Vector:          textVector(alertSearchText(alert)),
	}
	store.feedback["FDB-prior-long-hint"] = &FeedbackRecord{
		FeedbackID: "FDB-prior-long-hint",
		TargetType: "incident",
		TargetID:   "INC-prior-long-hint",
		Vote:       "up",
		Author:     "operator-a",
		CreatedAt:  time.Now().UTC(),
	}
	store.comments["CMT-prior-long-hint"] = &CommentRecord{
		CommentID:  "CMT-prior-long-hint",
		TargetType: "incident",
		TargetID:   "INC-prior-long-hint",
		IncidentID: "INC-prior-long-hint",
		Body:       strings.Repeat("operator comment ", 200),
		CreatedAt:  time.Now().UTC(),
	}

	hints := store.FeedbackHintsForAlert(alert, "INC-current", 5)
	if len(hints) < 2 {
		t.Fatalf("expected vote and comment hints, got %+v", hints)
	}
	for _, hint := range hints {
		if len(hint.Text) > maxFeedbackHintTextBytes+len("...") || !strings.HasSuffix(hint.Text, "...") {
			t.Fatalf("feedback hint text should be capped, got len=%d text=%q", len(hint.Text), hint.Text)
		}
	}
}

func TestFeedbackHintsDedupesIncidentCommentsAcrossAlertMemories(t *testing.T) {
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
	for _, alertID := range []string{"ALR-prior-a", "ALR-prior-b"} {
		store.memories[alertID] = &IncidentMemory{
			IncidentID:      "INC-prior-duplicate-comments",
			AlertID:         alertID,
			Title:           "RunAI workload pending",
			Severity:        "warning",
			Status:          "resolved",
			AnalysisSummary: "GPU quota exhausted for trainer",
			AnalysisDetail:  "Quota was expanded.",
			Labels:          cloneMap(alert.Labels),
			CreatedAt:       time.Now().UTC(),
			Vector:          textVector(alertSearchText(alert)),
		}
	}
	store.comments["CMT-duplicate-hint"] = &CommentRecord{
		CommentID:  "CMT-duplicate-hint",
		TargetType: "incident",
		TargetID:   "INC-prior-duplicate-comments",
		IncidentID: "INC-prior-duplicate-comments",
		Body:       "same incident note",
		CreatedAt:  time.Now().UTC(),
	}

	hints := store.FeedbackHintsForAlert(alert, "INC-current", 5)
	commentHints := 0
	for _, hint := range hints {
		if hint.Sentiment == "comment" && hint.Text == "same incident note" {
			commentHints++
		}
	}
	if commentHints != 1 {
		t.Fatalf("expected one deduped comment hint, got %d in %+v", commentHints, hints)
	}
}

func TestFlappingAlertGroupingUsesNamespaceWorkloadAndWindow(t *testing.T) {
	t.Setenv("FLAPPING_GROUP_WINDOW_MINUTES", "30") // pin the window this test asserts against
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
	incident, record := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "resolve-toggle"}, Alert{
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
	server.store.ApplyAnalysis(record.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Pending workload RCA.",
		AnalysisDetail:  "Quota blocked scheduling.",
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
	if memory := server.store.memories[record.AlertID]; memory == nil || memory.Status != "resolved" {
		t.Fatalf("expected alert memory to resolve with incident, got %+v", memory)
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
	if memory := server.store.memories[record.AlertID]; memory == nil || memory.Status != "firing" {
		t.Fatalf("expected alert memory to reopen with incident, got %+v", memory)
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "firing" {
		t.Fatalf("expected response status firing, got %+v", response)
	}
}

func TestIncidentDetailAggregatesAlertAnalyses(t *testing.T) {
	store := NewStore()
	incident, first := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "aggregate-rca"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-aggregate-first",
	})
	secondID := "ALR-aggregate-second"
	store.mu.Lock()
	store.alerts[secondID] = &AlertRecord{
		AlertID:     secondID,
		IncidentID:  incident.IncidentID,
		AlarmTitle:  "Quota alert",
		Severity:    "critical",
		Status:      "firing",
		FiredAt:     first.FiredAt.Add(time.Minute),
		Fingerprint: "fp-aggregate-second",
		ThreadTS:    "thread-" + secondID,
		Labels:      map[string]string{"alertname": "RunAIQuotaBlocked", "severity": "critical"},
		Annotations: map[string]string{"summary": "Quota blocked"},
	}
	store.mu.Unlock()
	store.ApplyAnalysis(first.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Queue saturation RCA.",
		AnalysisDetail:  "Queue workers are waiting.",
		AnalysisQuality: "medium",
		MissingData:     []string{"loki.logs"},
		Warnings:        []string{"partial logs"},
		Artifacts:       []Artifact{{Agent: "runai", Source: "workloads", Type: "api", Status: "ok", Confidence: "high"}},
	})
	store.ApplyAnalysis(secondID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Quota exhaustion RCA.",
		AnalysisDetail:  "GPU quota is exhausted.",
		AnalysisQuality: "high",
		MissingData:     []string{"loki.logs"},
		Warnings:        []string{"partial logs"},
		Artifacts:       []Artifact{{Agent: "runai", Source: "workloads", Type: "api", Status: "ok", Confidence: "high"}},
	})

	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok {
		t.Fatalf("incident detail missing")
	}
	if !strings.Contains(detail.AnalysisSummary, "Queue saturation RCA.") ||
		!strings.Contains(detail.AnalysisSummary, "Quota exhaustion RCA.") {
		t.Fatalf("incident summary should aggregate alert RCA summaries, got %q", detail.AnalysisSummary)
	}
	if !strings.Contains(detail.AnalysisDetail, "Queue workers are waiting.") ||
		!strings.Contains(detail.AnalysisDetail, "GPU quota is exhausted.") {
		t.Fatalf("incident detail should aggregate alert RCA details, got %q", detail.AnalysisDetail)
	}
	if len(detail.MissingData) != 1 || len(detail.Warnings) != 1 || len(detail.Artifacts) != 1 {
		t.Fatalf("incident RCA metadata should be deduplicated, got missing=%v warnings=%v artifacts=%v", detail.MissingData, detail.Warnings, detail.Artifacts)
	}
}

func TestIncidentDetailCapsAggregateAnalysisTextOnly(t *testing.T) {
	store := NewStore()
	incident, alert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "aggregate-cap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-aggregate-cap",
	})
	longSummary := strings.Repeat("s", maxIncidentAggregateSummaryBytes+100)
	longDetail := strings.Repeat("d", maxIncidentAggregateDetailBytes+100)
	store.ApplyAnalysis(alert.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: longSummary,
		AnalysisDetail:  longDetail,
	})

	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok {
		t.Fatalf("incident detail missing")
	}
	if len(detail.AnalysisSummary) > maxIncidentAggregateSummaryBytes+len("...") ||
		!strings.HasSuffix(detail.AnalysisSummary, "...") {
		t.Fatalf("incident summary aggregate was not capped, len=%d", len(detail.AnalysisSummary))
	}
	if len(detail.AnalysisDetail) > maxIncidentAggregateDetailBytes+len("...") ||
		!strings.HasSuffix(detail.AnalysisDetail, "...") {
		t.Fatalf("incident detail aggregate was not capped, len=%d", len(detail.AnalysisDetail))
	}
	if len(detail.Alerts) != 1 || detail.Alerts[0].AnalysisSummary != longSummary || detail.Alerts[0].AnalysisDetail != longDetail {
		t.Fatalf("alert-level RCA should remain complete in incident detail")
	}
}

func TestDenseEmbeddingIsDeterministicAndNormalized(t *testing.T) {
	text := "Run:AI GPU quota saturated scheduling blocked"
	a := denseEmbedding(text, embeddingDim)
	b := denseEmbedding(text, embeddingDim)
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
	if empty := denseEmbedding("", embeddingDim); len(empty) != embeddingDim {
		t.Fatalf("empty text should still yield a zero vector of the right dim, got %d", len(empty))
	}
}

func TestEmbedderRemotePath(t *testing.T) {
	const dim = 4
	var gotModel, gotInput string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/embeddings" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		var req struct {
			Model string `json:"model"`
			Input string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotModel, gotInput = req.Model, req.Input
		writeJSON(w, http.StatusOK, map[string]any{
			"data": []map[string]any{{"embedding": []float32{3, 0, 4, 0}}},
		})
	}))
	defer srv.Close()

	e := &embedder{endpoint: srv.URL, model: "test-model", dim: dim, client: srv.Client()}
	vec := e.embed("장애 원인 분석")
	if len(vec) != dim {
		t.Fatalf("expected dim %d, got %d", dim, len(vec))
	}
	if gotModel != "test-model" || gotInput != "장애 원인 분석" {
		t.Fatalf("endpoint got model=%q input=%q", gotModel, gotInput)
	}
	// {3,0,4,0} normalized -> {0.6,0,0.8,0}.
	if math.Abs(float64(vec[0])-0.6) > 1e-5 || math.Abs(float64(vec[2])-0.8) > 1e-5 {
		t.Fatalf("remote vector not L2-normalized: %v", vec)
	}
}

func TestEmbedderFallsBackToHash(t *testing.T) {
	// No endpoint -> deterministic hash embedding, matching denseEmbedding.
	offline := &embedder{dim: embeddingDim}
	got := offline.embed("hello world")
	want := denseEmbedding("hello world", embeddingDim)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("offline embedder should equal hash embedding")
	}

	// Endpoint configured but failing (server returns 500) -> still falls back,
	// so an incident write/search is never blocked by embedding unavailability.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	failing := &embedder{endpoint: srv.URL, model: "m", dim: embeddingDim, client: srv.Client()}
	if fb := failing.embed("hello world"); !reflect.DeepEqual(fb, want) {
		t.Fatalf("failed endpoint should fall back to hash embedding of the stored dim")
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
	done := store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	store.CompleteAnalysisRun(done.RunID, AgentAnalysisResponse{Status: "ok", AnalysisSummary: "done"})
	stale := store.CreateAnalysisRun("auto", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")

	reaped := store.ReapStaleAnalyzingRuns(0, 0)
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

func TestReapStaleAnalyzingRunsKeepsFreshRun(t *testing.T) {
	store := NewStore()
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "fresh-reap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-fresh-reap",
	})
	run := store.CreateAnalysisRun("manual", "alert", record.AlertID, incident.IncidentID, record.AlertID, "t", "")
	store.BeginAnalyzing(incident.IncidentID, record.AlertID)

	reaped := store.ReapStaleAnalyzingRuns(time.Hour, time.Hour)
	if reaped != 0 {
		t.Fatalf("fresh run should not be reaped, got %d", reaped)
	}
	found := false
	for _, current := range store.ListAnalysisRuns() {
		if current.RunID == run.RunID && current.Status != "analyzing" {
			t.Fatalf("fresh run should stay analyzing, got %q", current.Status)
		}
		found = found || current.RunID == run.RunID
	}
	if !found {
		t.Fatalf("fresh run disappeared")
	}
	if alert, _ := store.AlertDetail(record.AlertID); !alert.IsAnalyzing {
		t.Fatalf("fresh alert should stay analyzing")
	}
	if detail, ok := store.IncidentDetail(incident.IncidentID); !ok || !detail.IsAnalyzing {
		t.Fatalf("fresh incident should stay analyzing")
	}
}

func TestReapStaleAnalyzingRunsUsesManualTimeoutOnlyForManualRuns(t *testing.T) {
	store := NewStore()
	incident, autoAlert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "auto-reap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIAutoBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Auto queue blocked"},
		Fingerprint: "fp-auto-reap",
	})
	manualIncident, manualAlert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "manual-reap"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIManualBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Manual queue blocked"},
		Fingerprint: "fp-manual-reap",
	})
	autoRun := store.CreateAnalysisRun("auto", "alert", autoAlert.AlertID, incident.IncidentID, autoAlert.AlertID, "auto", "")
	manualRun := store.CreateAnalysisRun("manual", "alert", manualAlert.AlertID, manualIncident.IncidentID, manualAlert.AlertID, "manual", "")

	store.mu.Lock()
	store.analysisRuns[autoRun.RunID].UpdatedAt = time.Now().UTC().Add(-5 * time.Minute)
	store.analysisRuns[manualRun.RunID].UpdatedAt = time.Now().UTC().Add(-5 * time.Minute)
	store.mu.Unlock()

	reaped := store.ReapStaleAnalyzingRuns(3*time.Minute, 15*time.Minute)
	if reaped != 1 {
		t.Fatalf("expected only stale auto run to be reaped, got %d", reaped)
	}
	for _, run := range store.ListAnalysisRuns() {
		switch run.RunID {
		case autoRun.RunID:
			if run.Status != "failed" {
				t.Fatalf("auto run should be reaped with default timeout, got %q", run.Status)
			}
		case manualRun.RunID:
			if run.Status != "analyzing" {
				t.Fatalf("manual run should use manual timeout, got %q", run.Status)
			}
		}
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

func TestChatAnalysisRequestWithoutAnyAlertCreatesAdHocIncident(t *testing.T) {
	// The operator asks about something Alertmanager never caught: no explicit
	// target, no reference to existing alerts. The chat must create an ad-hoc
	// incident (visible in the incident list) and analyze IT — not silently
	// hijack an unrelated latest alert, and not dead-end.
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
			AnalysisSummary: "Ad-hoc RCA completed.",
			AnalysisDetail:  "## Root Cause\n\nAd-hoc analysis.",
			AnalysisQuality: "medium",
			Capabilities:    map[string]string{"analysis": "ok"},
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	// An unrelated alert exists — it must NOT be hijacked.
	_, unrelated := server.store.UpsertAlert(AlertmanagerWebhook{GroupKey: "unrelated"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "SomethingElse", "severity": "warning"},
		Fingerprint: "fp-unrelated",
	})

	message := "dgx02 노드 GPU가 이상한 것 같아. 분석해줘"
	payload, _ := json.Marshal(ChatRequest{Message: message})
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
	if response.AnalysisRun == nil || response.AnalysisRun.TargetType != "alert" {
		t.Fatalf("expected an analysis run on an alert target, got %+v", response)
	}
	if response.AnalysisRun.TargetID == unrelated.AlertID {
		t.Fatalf("ad-hoc request must not hijack the unrelated latest alert")
	}
	agentReq := <-agentReqCh
	if agentReq.Alert.Labels["alertname"] != "OperatorRequestedAnalysis" {
		t.Fatalf("expected the ad-hoc alert sent to the agent, got %+v", agentReq.Alert.Labels)
	}
	// The chat message must steer the analysis as operator guidance.
	if agentReq.Alert.Annotations["operator_prompt"] != message {
		t.Fatalf("expected the chat message as operator_prompt, got %q",
			agentReq.Alert.Annotations["operator_prompt"])
	}
	run := waitForAnalysisRun(t, server, "chat")
	if run.Status != "complete" {
		t.Fatalf("unexpected analysis run: %+v", run)
	}
}

func TestFlappingWindowGroupsRecurrenceWithinConfiguredWindow(t *testing.T) {
	t.Setenv("FLAPPING_GROUP_WINDOW_MINUTES", "180") // 3h
	store := NewStore()
	if store.flappingWindow != 180*time.Minute {
		t.Fatalf("flappingWindow = %v, want 180m", store.flappingWindow)
	}
	mk := func(ts time.Time) (AlertmanagerWebhook, Alert) {
		a := Alert{
			Status:      "firing",
			Labels:      map[string]string{"alertname": "MemPageFaults", "namespace": "monitoring", "pod": "prometheus-prometheus-node-exporter-qxhvl"},
			Annotations: map[string]string{},
			Fingerprint: "fp-mempagefaults",
			StartsAt:    ts.Format(time.RFC3339),
		}
		return AlertmanagerWebhook{}, a
	}
	base := time.Now().UTC().Add(-10 * time.Hour)
	wh, a := mk(base)
	r1 := store.UpsertAlertResult(wh, a)
	// recurrence 2h later → within 3h window → SAME incident, occurrence grows
	wh, a = mk(base.Add(2 * time.Hour))
	r2 := store.UpsertAlertResult(wh, a)
	if r2.Incident.IncidentID != r1.Incident.IncidentID {
		t.Fatalf("2h recurrence should reuse incident: got %s vs %s", r2.Incident.IncidentID, r1.Incident.IncidentID)
	}
	if r2.NewAlert {
		t.Fatalf("2h recurrence should not create a new alert row")
	}
	// recurrence 5h after the last → beyond 3h window → NEW incident
	wh, a = mk(base.Add(7 * time.Hour))
	r3 := store.UpsertAlertResult(wh, a)
	if r3.Incident.IncidentID == r1.Incident.IncidentID {
		t.Fatalf("recurrence beyond window should start a new incident")
	}
}
