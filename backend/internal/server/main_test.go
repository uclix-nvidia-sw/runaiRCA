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

func TestListIncidentsPageFiltered(t *testing.T) {
	store := NewStore()
	mkAlert := func(name, status, severity string) Alert {
		return Alert{
			Status: status,
			Labels: map[string]string{
				"alertname": name,
				"severity":  severity,
				"cluster":   "lab",
				"namespace": "runai-vision",
				"workload":  name,
			},
			Annotations: map[string]string{"summary": name},
			Fingerprint: "fp-" + name,
		}
	}
	approvedAt := time.Date(2026, 7, 6, 10, 0, 0, 0, time.UTC)
	approved, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "filter-approved"}, mkAlert("approved", "resolved", "critical"))
	pending, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "filter-pending"}, mkAlert("pending", "firing", "warning"))
	analyzing, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "filter-analyzing"}, mkAlert("analyzing", "firing", "critical"))
	store.mu.Lock()
	store.incidents[approved.IncidentID].UserApprovedAt = &approvedAt
	store.incidents[analyzing.IncidentID].IsAnalyzing = true
	store.mu.Unlock()

	items, total := store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{
		Status:        "resolved",
		Severity:      "critical",
		FinalDecision: "approved",
	})
	if total != 1 || len(items) != 1 || items[0].IncidentID != approved.IncidentID {
		t.Fatalf("expected only approved resolved critical incident, total=%d items=%+v", total, items)
	}

	items, total = store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{Status: "analyzing"})
	if total != 1 || len(items) != 1 || items[0].IncidentID != analyzing.IncidentID {
		t.Fatalf("expected only analyzing incident, total=%d items=%+v", total, items)
	}

	items, total = store.ListIncidentsPageFiltered(0, 0, incidentViewActive, IncidentListFilter{FinalDecision: "pending"})
	if total != 2 || len(items) != 2 || items[0].IncidentID == approved.IncidentID || items[1].IncidentID == approved.IncidentID {
		t.Fatalf("expected pending final decision incidents (%s, %s), total=%d items=%+v", pending.IncidentID, analyzing.IncidentID, total, items)
	}
}

func TestListAlertsPageFiltered(t *testing.T) {
	store := NewStore()
	mkAlert := func(name, status, severity string) Alert {
		return Alert{
			Status: status,
			Labels: map[string]string{
				"alertname": name,
				"severity":  severity,
				"cluster":   "lab",
				"namespace": "runai-vision",
				"workload":  name,
			},
			Annotations: map[string]string{"summary": name},
			Fingerprint: "fp-alert-" + name,
		}
	}
	_, critical := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "alert-filter-critical"}, mkAlert("critical", "firing", "critical"))
	_, resolved := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "alert-filter-resolved"}, mkAlert("resolved", "resolved", "warning"))
	_, analyzing := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "alert-filter-analyzing"}, mkAlert("analyzing", "firing", "warning"))
	store.mu.Lock()
	store.alerts[analyzing.AlertID].IsAnalyzing = true
	store.mu.Unlock()

	items, total := store.ListAlertsPageFiltered(0, 0, AlertListFilter{Severity: "critical"})
	if total != 1 || len(items) != 1 || items[0].AlertID != critical.AlertID {
		t.Fatalf("expected only critical alert, total=%d items=%+v", total, items)
	}

	items, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Status: "resolved"})
	if total != 1 || len(items) != 1 || items[0].AlertID != resolved.AlertID {
		t.Fatalf("expected only resolved alert, total=%d items=%+v", total, items)
	}

	items, total = store.ListAlertsPageFiltered(0, 0, AlertListFilter{Status: "analyzing"})
	if total != 1 || len(items) != 1 || items[0].AlertID != analyzing.AlertID {
		t.Fatalf("expected only analyzing alert, total=%d items=%+v", total, items)
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

func TestResolvedIncidentAnalysisTargetIgnoresStaleFiringAlert(t *testing.T) {
	store := NewStore()
	base := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "resolved-target-stale-firing"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Stale firing row"},
		Fingerprint: "fp-stale-firing",
		StartsAt:    base.Add(time.Hour).Format(time.RFC3339),
	})
	resolvedAt := base.Add(30 * time.Minute)
	store.mu.Lock()
	store.alerts["ALR-resolved-target"] = &AlertRecord{
		AlertID:     "ALR-resolved-target",
		IncidentID:  incident.IncidentID,
		AlarmTitle:  "Resolved historical alert",
		Severity:    "warning",
		Status:      "resolved",
		FiredAt:     base,
		ResolvedAt:  &resolvedAt,
		Fingerprint: "fp-resolved-target",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "pod": "trainer-dead"},
		Annotations: map[string]string{"summary": "Queue recovered"},
	}
	store.incidents[incident.IncidentID].Status = "resolved"
	store.incidents[incident.IncidentID].ResolvedAt = &resolvedAt
	store.mu.Unlock()

	alert, _, alertID, _, _, ok := store.AnalysisTarget("incident", incident.IncidentID)
	if !ok || alertID != "ALR-resolved-target" || status(alert.Status) != "resolved" {
		t.Fatalf("expected resolved historical target, got ok=%t alertID=%s alert=%+v", ok, alertID, alert)
	}
	if alert.EndsAt != resolvedAt.Format(time.RFC3339Nano) {
		t.Fatalf("expected resolved target window, got endsAt=%q", alert.EndsAt)
	}
}

func TestAnalysisTargetRestoresStoredHistoricalWindow(t *testing.T) {
	store := NewStore()
	firedAt := time.Date(2026, 6, 30, 10, 0, 0, 123456789, time.FixedZone("KST", 9*60*60))
	resolvedAt := firedAt.Add(37 * time.Minute)
	incident, record := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "analysis-target-window"}, Alert{
		Status:      "resolved",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue recovered"},
		Fingerprint: "fp-analysis-target-window",
		StartsAt:    firedAt.Format(time.RFC3339Nano),
		EndsAt:      resolvedAt.Format(time.RFC3339Nano),
	})

	for targetType, targetID := range map[string]string{
		"alert":    record.AlertID,
		"incident": incident.IncidentID,
	} {
		alert, _, _, _, _, ok := store.AnalysisTarget(targetType, targetID)
		if !ok {
			t.Fatalf("expected %s analysis target", targetType)
		}
		if alert.StartsAt != firedAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("expected stored fired_at for %s target, got %q", targetType, alert.StartsAt)
		}
		if alert.EndsAt != resolvedAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("expected stored resolved_at for %s target, got %q", targetType, alert.EndsAt)
		}
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

func TestAgentResponseBodyLimitConfig(t *testing.T) {
	t.Setenv("AGENT_MAX_RESPONSE_BODY_BYTES", "3145728")
	server := NewServer()

	if server.agentResponseBodyLimit() != 3145728 {
		t.Fatalf("expected configured agent response limit, got %d", server.agentResponseBodyLimit())
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

func TestChatHistoryPersistsListsAndDeletes(t *testing.T) {
	server := NewServer()
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ChatResponse{
			Status:         "ok",
			Answer:         "The scheduler is blocked by GPU quota.",
			ConversationID: "chat-history",
		})
	}))
	defer agent.Close()
	server.agentURL = agent.URL

	body, _ := json.Marshal(ChatRequest{
		Message:        "Why is the workload pending?",
		ConversationID: "chat-history",
		Page:           "chat_dashboard",
	})
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/chat", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected chat 200, got %d: %s", rec.Code, rec.Body.String())
	}

	listRec := httptest.NewRecorder()
	server.routes().ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/api/v1/chat/conversations", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected history 200, got %d: %s", listRec.Code, listRec.Body.String())
	}
	var list struct {
		Data []ChatConversation `json:"data"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "chat-history" || len(list.Data[0].Messages) != 2 {
		t.Fatalf("unexpected history: %+v", list.Data)
	}
	if list.Data[0].Messages[0].Role != "user" || list.Data[0].Messages[1].Role != "assistant" {
		t.Fatalf("unexpected message roles: %+v", list.Data[0].Messages)
	}

	deleteRec := httptest.NewRecorder()
	server.routes().ServeHTTP(deleteRec, httptest.NewRequest(http.MethodDelete, "/api/v1/chat/conversations/chat-history", nil))
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected delete 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
	if _, total := server.store.ListChatConversationsPage(0, 0); total != 0 {
		t.Fatalf("expected chat history to be deleted, total=%d", total)
	}
}

func TestIncidentChatContextSummarizesAlerts(t *testing.T) {
	alerts := []AlertRecord{{
		AlertID:    "ALR-chat-context",
		AlarmTitle: "RunAIQueueBlocked",
		Severity:   "warning",
		Status:     "firing",
		Labels:     map[string]string{"queue": "gpu-a"},
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
		"재분석 부탁해",
		"이 인시던트 재분석",
		"analyze this again please",
		"start a new analysis for the runai namespace",
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
	if len(store.SearchIncidentMemory("gpu quota saturated scheduling", 5)) != 0 {
		t.Fatalf("unresolved incident RCA must not be loaded into memory")
	}
	approveIncidentForTest(t, store, priorIncident.IncidentID)
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

func TestIncidentMemoryIsOnePerIncidentFromLatestRun(t *testing.T) {
	// Memory is one embedding per incident now (not one per alert), sourced from the
	// incident's latest analysis run.
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

	// Seed two completed runs with distinct timestamps so "latest" is deterministic.
	base := first.FiredAt
	store.mu.Lock()
	store.analysisRuns["RUN-first"] = &AnalysisRun{
		RunID: "RUN-first", Status: "complete", IncidentID: incident.IncidentID, AlertID: first.AlertID,
		AnalysisSummary: "Queue saturation RCA.", AnalysisDetail: "Queue workers are waiting.", UpdatedAt: base,
	}
	store.analysisRuns["RUN-second"] = &AnalysisRun{
		RunID: "RUN-second", Status: "complete", IncidentID: incident.IncidentID, AlertID: secondID,
		AnalysisSummary: "Quota exhaustion RCA.", AnalysisDetail: "GPU quota is exhausted.",
		UpdatedAt: base.Add(time.Minute),
	}
	store.mu.Unlock()

	if len(store.memories) != 0 {
		t.Fatalf("unresolved analysis should not create memory, got %+v", store.memories)
	}
	approveIncidentForTest(t, store, incident.IncidentID)
	if len(store.memories) != 1 {
		t.Fatalf("expected exactly one incident memory, got %+v", store.memories)
	}
	for _, memory := range store.memories {
		if memory.IncidentID != incident.IncidentID {
			t.Fatalf("memory not keyed to the incident: %+v", memory)
		}
		if memory.AnalysisSummary != "Quota exhaustion RCA." {
			t.Fatalf("incident memory should carry the latest run's RCA, got %q", memory.AnalysisSummary)
		}
	}
}

func TestSimilarIncidentsUseDisplayedApprovedRCAFamily(t *testing.T) {
	store := NewStore()
	priorAlert := Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-similar-provenance-prior",
	}
	priorIncident, priorRecord := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "similar-provenance-prior"}, priorAlert)
	store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Initial AI RCA.",
		AnalysisDetail:  "Initial AI detail.",
		RootCauseFamily: "runai_scheduling_quota",
	})
	correction, ok := store.CreateOperatorRun(priorIncident.IncidentID, priorRecord.AlertID, "RUN-"+priorRecord.AlertID, "gpu_hardware_error", "Operator RCA.", "Operator detail.")
	if !ok {
		t.Fatal("expected pinned operator correction")
	}
	later, created := store.CreateAnalysisRunIfAllowed("auto", "incident", priorIncident.IncidentID, priorIncident.IncidentID, priorRecord.AlertID, "Later AI RCA", "")
	if !created {
		t.Fatal("expected later AI run")
	}
	if _, ok := store.CompleteAnalysisRun(later.RunID, AgentAnalysisResponse{
		AnalysisSummary: "Later AI RCA.",
		AnalysisDetail:  "Later AI detail.",
		RootCauseFamily: "runai_scheduling_quota",
	}); !ok {
		t.Fatal("expected later AI run to complete")
	}
	approveIncidentForTest(t, store, priorIncident.IncidentID)

	currentAlert := priorAlert
	currentAlert.Fingerprint = "fp-similar-provenance-current"
	currentIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "similar-provenance-current"}, currentAlert)
	similar := store.SimilarIncidentsForAlert(currentAlert, currentIncident.IncidentID, 5)
	if len(similar) != 1 {
		t.Fatalf("expected one approved similar incident, got %+v", similar)
	}
	if similar[0].IncidentID != priorIncident.IncidentID || !similar[0].Approved || similar[0].RootCauseFamily != correction.RootCauseFamily {
		t.Fatalf("similar incident should use the displayed pinned RCA family and approval: %+v", similar[0])
	}
}

func TestSimilarIncidentsExcludeUnapprovedPrior(t *testing.T) {
	store := NewStore()
	alert := Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-similar-unapproved-prior",
	}
	priorIncident, priorRecord := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "similar-unapproved-prior"}, alert)
	store.ApplyAnalysis(priorRecord.AlertID, AgentAnalysisResponse{
		Status:          "ok",
		AnalysisSummary: "Unapproved AI RCA.",
		AnalysisDetail:  "Unapproved AI detail.",
		RootCauseFamily: "runai_scheduling_quota",
	})
	store.memories[priorIncident.IncidentID] = &IncidentMemory{
		IncidentID:      priorIncident.IncidentID,
		Title:           priorIncident.Title,
		Severity:        priorIncident.Severity,
		Status:          priorIncident.Status,
		AnalysisSummary: "Unapproved AI RCA.",
		Labels:          cloneMap(alert.Labels),
		CreatedAt:       time.Now().UTC(),
		Vector:          textVector(alertSearchText(alert)),
	}

	currentAlert := alert
	currentAlert.Fingerprint = "fp-similar-unapproved-current"
	currentIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "similar-unapproved-current"}, currentAlert)
	if similar := store.SimilarIncidentsForAlert(currentAlert, currentIncident.IncidentID, 5); len(similar) != 0 {
		t.Fatalf("unapproved prior must remain excluded by the approval gate, got %+v", similar)
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
		seedApprovedMemoryIncidentForTest(store, id, base.Add(time.Duration(i)*time.Minute))
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
		seedApprovedMemoryIncidentForTest(store, "INC-prior-shared", item.at)
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
	seedApprovedMemoryIncidentForTest(store, "INC-prior-hint", time.Now().UTC())
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
	seedApprovedMemoryIncidentForTest(store, "INC-prior-limit", time.Now().UTC())
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
	seedApprovedMemoryIncidentForTest(store, "INC-prior-long-hint", time.Now().UTC())
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
		seedApprovedMemoryIncidentForTest(store, "INC-prior-duplicate-comments", time.Now().UTC())
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

func TestResolveEndpointTogglesUserApproval(t *testing.T) {
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
	if len(server.store.memories) != 0 {
		t.Fatalf("analysis should not load memory before manual resolve, got %+v", server.store.memories)
	}
	path := "/api/v1/incidents/" + incident.IncidentID + "/resolve"

	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first resolve 200, got %d: %s", rec.Code, rec.Body.String())
	}
	detail, ok := server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.Status != "firing" || detail.ResolvedAt != nil || detail.UserApprovedAt == nil {
		t.Fatalf("expected incident status to stay firing and user approval to be set, got ok=%t detail=%+v", ok, detail)
	}
	if memory := server.store.memories[incident.IncidentID]; memory == nil || memory.Status != "firing" {
		t.Fatalf("expected incident memory to load after user approval, got %+v", memory)
	}

	rec = httptest.NewRecorder()
	server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected second resolve 200, got %d: %s", rec.Code, rec.Body.String())
	}
	detail, ok = server.store.IncidentDetail(incident.IncidentID)
	if !ok || detail.Status != "firing" || detail.ResolvedAt != nil || detail.UserApprovedAt != nil {
		t.Fatalf("expected second resolve click to clear user approval only, got ok=%t detail=%+v", ok, detail)
	}
	if memory := server.store.memories[incident.IncidentID]; memory == nil {
		t.Fatalf("expected memory row to remain for future reapproval, got %+v", memory)
	}
	if search := server.store.SearchIncidentMemory("quota blocked scheduling", 5); len(search) != 0 {
		t.Fatalf("reopened incident memory should not be searchable, got %+v", search)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "firing" || response["user_approved_at"] != nil {
		t.Fatalf("expected response status firing, got %+v", response)
	}
}

func TestIncidentDetailUsesLatestAnalysisRun(t *testing.T) {
	// Incident RCA now comes from the incident's latest completed analysis run
	// (the durable store), not from concatenating the per-alert analysis columns.
	store := NewStore()
	incident, first := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "latest-run-rca"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-latest-run",
	})
	base := first.FiredAt
	store.mu.Lock()
	store.analysisRuns["RUN-old"] = &AnalysisRun{
		RunID: "RUN-old", Status: "complete", IncidentID: incident.IncidentID, AlertID: first.AlertID,
		AnalysisSummary: "Old superseded RCA.", AnalysisDetail: "Old detail.", UpdatedAt: base,
	}
	store.analysisRuns["RUN-new"] = &AnalysisRun{
		RunID: "RUN-new", Status: "complete", IncidentID: incident.IncidentID, AlertID: first.AlertID,
		AnalysisSummary: "Latest RCA.", AnalysisDetail: "GPU quota is exhausted.",
		AnalysisQuality: "high", RootCauseFamily: "runai_scheduling_quota",
		MissingData: []string{"loki.logs"}, Warnings: []string{"partial logs"},
		Artifacts: []Artifact{{Agent: "runai", Source: "workloads", Type: "api", Status: "ok", Confidence: "high"}},
		UpdatedAt: base.Add(time.Minute),
	}
	store.mu.Unlock()

	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok {
		t.Fatalf("incident detail missing")
	}
	if !strings.Contains(detail.AnalysisSummary, "Latest RCA.") || strings.Contains(detail.AnalysisSummary, "Old superseded RCA.") {
		t.Fatalf("incident summary should be the latest run only, got %q", detail.AnalysisSummary)
	}
	if !strings.Contains(detail.AnalysisDetail, "GPU quota is exhausted.") {
		t.Fatalf("incident detail should come from the latest run, got %q", detail.AnalysisDetail)
	}
	if detail.AnalysisQuality != "high" || detail.RootCauseFamily != "runai_scheduling_quota" {
		t.Fatalf("incident should take quality/family from the latest run, got %q/%q", detail.AnalysisQuality, detail.RootCauseFamily)
	}
	if len(detail.MissingData) != 1 || len(detail.Warnings) != 1 || len(detail.Artifacts) != 1 {
		t.Fatalf("incident RCA metadata should come from the run, got missing=%v warnings=%v artifacts=%v", detail.MissingData, detail.Warnings, detail.Artifacts)
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
	store.mu.Lock()
	store.analysisRuns["RUN-cap"] = &AnalysisRun{
		RunID: "RUN-cap", Status: "complete", IncidentID: incident.IncidentID, AlertID: alert.AlertID,
		AnalysisSummary: longSummary, AnalysisDetail: longDetail, UpdatedAt: alert.FiredAt,
	}
	store.mu.Unlock()

	detail, ok := store.IncidentDetail(incident.IncidentID)
	if !ok {
		t.Fatalf("incident detail missing")
	}
	if len(detail.AnalysisSummary) > maxIncidentAggregateSummaryBytes+len("...") ||
		!strings.HasSuffix(detail.AnalysisSummary, "...") {
		t.Fatalf("incident summary was not capped, len=%d", len(detail.AnalysisSummary))
	}
	if len(detail.AnalysisDetail) > maxIncidentAggregateDetailBytes+len("...") ||
		!strings.HasSuffix(detail.AnalysisDetail, "...") {
		t.Fatalf("incident detail was not capped, len=%d", len(detail.AnalysisDetail))
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

func approveIncidentForTest(t *testing.T, store *Store, incidentID string) {
	t.Helper()
	now := time.Now().UTC()
	store.mu.Lock()
	incident := store.incidents[incidentID]
	if incident == nil {
		store.mu.Unlock()
		t.Fatalf("incident %s missing", incidentID)
	}
	incident.UserApprovedAt = &now
	store.upsertApprovedIncidentMemoriesLocked(incident)
	store.mu.Unlock()
}

func seedApprovedMemoryIncidentForTest(store *Store, incidentID string, at time.Time) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	store.incidents[incidentID] = &Incident{
		IncidentID:     incidentID,
		CorrelationKey: incidentID,
		Title:          incidentID,
		Severity:       "warning",
		Status:         "resolved",
		FiredAt:        at,
		UserApprovedAt: &at,
	}
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
	approveIncidentForTest(t, server.store, priorIncident.IncidentID)
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

func TestFeedbackInlineCommentStoredOnce(t *testing.T) {
	store := NewStore()
	incident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "feedback-inline-comment"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-feedback-inline-comment",
	})

	summary, ok, err := store.AddFeedback("incident", incident.IncidentID, FeedbackRequest{
		Vote:    "up",
		Comment: "useful RCA",
		Author:  "operator",
	})
	if err != nil || !ok {
		t.Fatalf("feedback failed: ok=%t err=%v", ok, err)
	}
	if summary.Positive != 1 || len(summary.Comments) != 1 || summary.Comments[0].Body != "useful RCA" {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	for _, record := range store.feedback {
		if record.Comment != "" {
			t.Fatalf("vote row should not duplicate inline comment text: %+v", record)
		}
	}
	if prompt := store.OperatorPromptForTarget("incident", incident.IncidentID); !strings.Contains(prompt, "useful RCA") {
		t.Fatalf("operator prompt should include inline comment, got %q", prompt)
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
	if r2.Alert.OccurrenceCount != 2 {
		t.Fatalf("2h recurrence should grow occurrence to 2, got %d", r2.Alert.OccurrenceCount)
	}
	if r2.Incident.AlertCount != 2 {
		t.Fatalf("2h recurrence should grow incident AlertCount to 2, got %d", r2.Incident.AlertCount)
	}
	// recurrence 5h after the last → beyond 3h window → NEW incident
	wh, a = mk(base.Add(7 * time.Hour))
	r3 := store.UpsertAlertResult(wh, a)
	if r3.Incident.IncidentID == r1.Incident.IncidentID {
		t.Fatalf("recurrence beyond window should start a new incident")
	}
}

func TestResolvedThenRefiringGrowsOccurrence(t *testing.T) {
	// The user's real cadence: an alert fires, resolves, then fires again ~2h later
	// with the SAME Alertmanager fingerprint. Each fresh firing episode must grow the
	// occurrence count — not merely toggle status firing↔resolved with the count
	// stuck at 1. The resolve itself must NOT grow the count.
	t.Setenv("FLAPPING_GROUP_WINDOW_MINUTES", "180") // 3h, so the 2h re-fire reuses the incident
	store := NewStore()
	mk := func(alertStatus string, ts time.Time) (AlertmanagerWebhook, Alert) {
		a := Alert{
			Status:      alertStatus,
			Labels:      map[string]string{"alertname": "RunaiReconcile", "namespace": "runai", "pod": "runai-project-controller-5d696ddbf9-hct89"},
			Annotations: map[string]string{},
			Fingerprint: "fp-reconcile",
			StartsAt:    ts.Format(time.RFC3339),
		}
		if alertStatus == "resolved" {
			a.EndsAt = ts.Format(time.RFC3339)
		}
		return AlertmanagerWebhook{}, a
	}
	base := time.Now().UTC().Add(-4 * time.Hour)
	wh, a := mk("firing", base)
	r1 := store.UpsertAlertResult(wh, a)
	if r1.Alert.OccurrenceCount != 1 {
		t.Fatalf("first firing occurrence = %d, want 1", r1.Alert.OccurrenceCount)
	}
	// resolve — must NOT grow the count
	wh, a = mk("resolved", base.Add(30*time.Minute))
	rResolved := store.UpsertAlertResult(wh, a)
	if rResolved.Alert.OccurrenceCount != 1 {
		t.Fatalf("resolve must not grow occurrence, got %d", rResolved.Alert.OccurrenceCount)
	}
	// re-fire 2h later, same fingerprint — a genuine new episode → occurrence grows
	wh, a = mk("firing", base.Add(2*time.Hour))
	r2 := store.UpsertAlertResult(wh, a)
	if r2.Incident.IncidentID != r1.Incident.IncidentID {
		t.Fatalf("re-fire should reuse incident: %s vs %s", r2.Incident.IncidentID, r1.Incident.IncidentID)
	}
	if r2.Alert.Status != "firing" {
		t.Fatalf("re-fire status = %s, want firing", r2.Alert.Status)
	}
	if r2.Alert.OccurrenceCount != 2 {
		t.Fatalf("resolved→re-fire must grow occurrence to 2, got %d", r2.Alert.OccurrenceCount)
	}
	if r2.Incident.AlertCount != 2 {
		t.Fatalf("resolved→re-fire must grow incident AlertCount to 2, got %d", r2.Incident.AlertCount)
	}
}

func TestAutoAnalyzeSeverityGate(t *testing.T) {
	if parseAutoAnalyzeSeverities("") != nil || parseAutoAnalyzeSeverities("all") != nil || parseAutoAnalyzeSeverities("*") != nil {
		t.Fatalf("empty/all/* should mean no severity gating")
	}
	set := parseAutoAnalyzeSeverities("warning, Critical")
	if !set["warning"] || !set["critical"] || set["none"] {
		t.Fatalf("expected {warning,critical}, got %+v", set)
	}
	gated := &Server{autoAnalyzeSeverities: set}
	if !gated.severityAutoAnalyzable("warning") || !gated.severityAutoAnalyzable("CRITICAL") {
		t.Fatalf("warning/critical must be auto-analyzable")
	}
	if gated.severityAutoAnalyzable("none") || gated.severityAutoAnalyzable("info") {
		t.Fatalf("none/info must be gated out of auto-analysis")
	}
	if !(&Server{}).severityAutoAnalyzable("none") {
		t.Fatalf("a nil allowlist must auto-analyze every severity")
	}
}

func TestApprovalSurvivesResolvedRefire(t *testing.T) {
	// Regression: an approved incident was silently un-approved overnight when the
	// same alert re-fired (resolved→firing cleared UserApprovedAt). Approval of the
	// RCA must survive a recurrence of the same incident.
	store := NewStore()
	mk := func(status string, ts time.Time) (AlertmanagerWebhook, Alert) {
		a := Alert{
			Status:      status,
			Labels:      map[string]string{"alertname": "RunaiReconcile", "namespace": "runai", "pod": "p-0"},
			Annotations: map[string]string{},
			Fingerprint: "fp-approve-refire",
			StartsAt:    ts.Format(time.RFC3339),
		}
		if status == "resolved" {
			a.EndsAt = ts.Format(time.RFC3339)
		}
		return AlertmanagerWebhook{}, a
	}
	base := time.Now().UTC().Add(-4 * time.Hour)
	wh, a := mk("firing", base)
	r1 := store.UpsertAlertResult(wh, a)
	// Operator approves the incident's RCA.
	now := time.Now().UTC()
	store.incidents[r1.Incident.IncidentID].UserApprovedAt = &now
	// Resolve, then the SAME alert re-fires within the reuse window (reuses the incident).
	wh, a = mk("resolved", base.Add(30*time.Minute))
	store.UpsertAlertResult(wh, a)
	wh, a = mk("firing", base.Add(2*time.Hour))
	r2 := store.UpsertAlertResult(wh, a)
	if r2.Incident.IncidentID != r1.Incident.IncidentID {
		t.Fatalf("re-fire should reuse incident: %s vs %s", r2.Incident.IncidentID, r1.Incident.IncidentID)
	}
	if r2.Incident.Status != "firing" {
		t.Fatalf("re-fire status = %s, want firing", r2.Incident.Status)
	}
	if store.incidents[r1.Incident.IncidentID].UserApprovedAt == nil {
		t.Fatalf("approval must survive a resolved→firing re-fire, got nil")
	}
}

func TestTokenizeKeepsKoreanAndSimilarityIsHighForNearDuplicates(t *testing.T) {
	// The old tokenizer dropped all Hangul, so near-identical Korean reports scored
	// ~50%. Korean eojeols must now survive and drive a high similarity.
	toks := tokenize("노드 192.168.20.172에서 메이저 페이지 폴트 지속 발생 메모리 압박")
	has := func(w string) bool {
		for _, tk := range toks {
			if tk == w {
				return true
			}
		}
		return false
	}
	if !has("노드") || !has("메모리") || !has("페이지") {
		t.Fatalf("Korean tokens dropped: %v", toks)
	}

	a := textVector("노드 192.168.20.172에서 초당 500회 이상 메이저 페이지 폴트 지속 발생 — 노드 메모리 압박(스왑/디스크 I/O 증가)이 주원인으로 판단됩니다")
	b := textVector("노드 192.168.20.172에서 초당 520회 메이저 페이지 폴트 지속 발생 — 노드 메모리/디스크 압박이 주원인으로 판단됩니다")
	sim := cosineSimilarity(a, b)
	if sim < 0.8 {
		t.Fatalf("near-identical Korean reports should score high, got %.2f", sim)
	}

	// A clearly different incident must NOT score high (no false grouping).
	c := textVector("GPU XID 79 발생 — GPU가 PCIe 버스에서 떨어져 하드웨어 결함으로 판단됩니다")
	if s := cosineSimilarity(a, c); s > 0.5 {
		t.Fatalf("unrelated incident scored too high: %.2f", s)
	}
}

func TestIncidentLifecycleViewsAndDeletedGuards(t *testing.T) {
	store := NewStore()
	webhook := AlertmanagerWebhook{GroupKey: "lifecycle"}
	alert := Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "namespace": "runai", "workload": "trainer"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-lifecycle",
		StartsAt:    "2026-07-01T10:00:00Z",
	}
	incident, record := store.UpsertAlert(webhook, alert)
	store.ApplyAnalysis(record.AlertID, AgentAnalysisResponse{AnalysisSummary: "Queue blocked by quota."})

	if _, ok := store.ArchiveIncident(incident.IncidentID, true); !ok {
		t.Fatalf("archive failed")
	}
	if active, total := store.ListIncidentsPage(0, 0); total != 0 || len(active) != 0 {
		t.Fatalf("archived incident should leave active view, got total=%d items=%+v", total, active)
	}
	if archived, total := store.ListIncidentsPage(0, 0, incidentViewArchived); total != 1 || archived[0].ArchivedAt == nil {
		t.Fatalf("archived view missing incident, total=%d items=%+v", total, archived)
	}

	next := alert
	next.Fingerprint = "fp-lifecycle-new"
	result := store.UpsertAlertResult(webhook, next)
	if result.Incident.ArchivedAt != nil {
		t.Fatalf("new alert should unarchive incident: %+v", result.Incident)
	}

	if _, ok := store.SoftDeleteIncident(incident.IncidentID); !ok {
		t.Fatalf("soft delete failed")
	}
	if active, total := store.ListIncidentsPage(0, 0); total != 0 || len(active) != 0 {
		t.Fatalf("deleted incident should leave active view, got total=%d items=%+v", total, active)
	}
	if trash, total := store.ListIncidentsPage(0, 0, incidentViewTrash); total != 1 || trash[0].DeletedAt == nil {
		t.Fatalf("trash view missing incident, total=%d items=%+v", total, trash)
	}
	if alerts, total := store.ListAlertsPage(0, 0); total != 0 || len(alerts) != 0 {
		t.Fatalf("deleted incident alerts should be hidden, total=%d items=%+v", total, alerts)
	}
	if got := store.DashboardSnapshot(5); got.IncidentCount != 0 || got.AlertCount != 0 {
		t.Fatalf("dashboard should exclude deleted incidents: %+v", got)
	}
	if got := store.LatestAlertID(); got != "" {
		t.Fatalf("latest alert should exclude deleted incident alert, got %s", got)
	}
	if ids := store.AlertIDsNeedingAnalysis(10, 0, time.Now().UTC(), nil); len(ids) != 0 {
		t.Fatalf("backfill should exclude deleted incident alerts: %+v", ids)
	}
	if _, _, _, _, _, ok := store.AnalysisTarget("incident", incident.IncidentID); ok {
		t.Fatalf("deleted incident should not be analyzable")
	}
	if results := store.SearchIncidentMemory("quota blocked", 5); len(results) != 0 {
		t.Fatalf("memory search should exclude deleted incidents: %+v", results)
	}

	recreated := store.UpsertAlertResult(webhook, alert)
	if !recreated.NewIncident || recreated.Incident.IncidentID == incident.IncidentID {
		t.Fatalf("same fingerprint after soft delete should create a new incident: %+v", recreated)
	}
	if _, ok := store.RestoreIncident(incident.IncidentID); !ok {
		t.Fatalf("restore failed")
	}
	reused := store.UpsertAlertResult(webhook, alert)
	if reused.Incident.IncidentID != recreated.Incident.IncidentID {
		t.Fatalf("restore should not steal occupied indexes, got %+v want %s", reused.Incident, recreated.Incident.IncidentID)
	}
}

func TestIncidentHardDeleteAndTrashPurge(t *testing.T) {
	store := NewStore()
	oldIncident, oldAlert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "purge-old"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-purge-old",
	})
	store.ApplyAnalysis(oldAlert.AlertID, AgentAnalysisResponse{AnalysisSummary: "Old queue block."})
	if _, _, err := store.AddFeedback("incident", oldIncident.IncidentID, FeedbackRequest{Vote: "up", Comment: "useful"}); err != nil {
		t.Fatalf("feedback seed failed: %v", err)
	}
	if _, _, err := store.AddComment("incident", oldIncident.IncidentID, CommentRequest{Body: "operator note"}); err != nil {
		t.Fatalf("comment seed failed: %v", err)
	}
	store.CreateAnalysisRun("manual", "incident", oldIncident.IncidentID, oldIncident.IncidentID, oldAlert.AlertID, "Manual", "")

	keepIncident, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "purge-keep"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-b"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-purge-keep",
	})
	store.SoftDeleteIncident(oldIncident.IncidentID)
	store.SoftDeleteIncident(keepIncident.IncidentID)
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	store.mu.Lock()
	oldDeleted := now.AddDate(0, 0, -31)
	keepDeleted := now.AddDate(0, 0, -1)
	store.incidents[oldIncident.IncidentID].DeletedAt = &oldDeleted
	store.incidents[keepIncident.IncidentID].DeletedAt = &keepDeleted
	store.mu.Unlock()

	if purged := store.PurgeExpiredTrash(30*24*time.Hour, now); purged != 1 {
		t.Fatalf("expected one expired trash purge, got %d", purged)
	}
	if _, ok := store.incidents[oldIncident.IncidentID]; ok {
		t.Fatalf("expired incident was not hard deleted")
	}
	if _, ok := store.alerts[oldAlert.AlertID]; ok {
		t.Fatalf("hard delete should remove alerts")
	}
	if len(store.memories) != 0 || len(store.feedback) != 0 || len(store.comments) != 0 || len(store.analysisRuns) != 0 {
		t.Fatalf("hard delete should cascade, memories=%d feedback=%d comments=%d runs=%d", len(store.memories), len(store.feedback), len(store.comments), len(store.analysisRuns))
	}
	if _, ok := store.incidents[keepIncident.IncidentID]; !ok {
		t.Fatalf("recent trash should be retained")
	}
}

func TestRecurrenceStatsAndIncidentSimilarRecentCount(t *testing.T) {
	store := NewStore()
	// IncidentDetail calculates its rolling seven-day window from the real
	// service clock. Keep the fixture in that same window; a fixed calendar
	// date makes this test start failing after one week.
	now := time.Now().UTC()
	prior, priorAlert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "recurrence-prior"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a", "namespace": "runai"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-recur-prior",
		StartsAt:    now.AddDate(0, 0, -2).Format(time.RFC3339),
	})
	store.ApplyAnalysis(priorAlert.AlertID, AgentAnalysisResponse{AnalysisSummary: "Queue gpu-a quota saturated."})
	approveIncidentForTest(t, store, prior.IncidentID)
	current, _ := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "recurrence-current"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a", "namespace": "runai"},
		Annotations: map[string]string{"summary": "Queue blocked again"},
		Fingerprint: "fp-recur-current",
		StartsAt:    now.AddDate(0, 0, -1).Format(time.RFC3339),
	})
	deleted, deletedAlert := store.UpsertAlert(AlertmanagerWebhook{GroupKey: "recurrence-deleted"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a", "namespace": "runai"},
		Annotations: map[string]string{"summary": "Deleted recurrence"},
		Fingerprint: "fp-recur-deleted",
		StartsAt:    now.Format(time.RFC3339),
	})
	store.ApplyAnalysis(deletedAlert.AlertID, AgentAnalysisResponse{AnalysisSummary: "Deleted queue block."})
	approveIncidentForTest(t, store, deleted.IncidentID)
	store.SoftDeleteIncident(deleted.IncidentID)

	stats := store.RecurrenceStats(7, now)
	if stats.Total != 2 || stats.Recurred != 1 || stats.Rate != 0.5 {
		t.Fatalf("unexpected recurrence stats: %+v prior=%s", stats, prior.IncidentID)
	}
	detail, ok := store.IncidentDetail(current.IncidentID)
	if !ok || detail.SimilarRecentCount != 1 {
		t.Fatalf("expected one recent similar incident, got ok=%t detail=%+v", ok, detail)
	}
}

func TestRecurrenceStatsCacheExpiresAndInvalidates(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	if stats := store.RecurrenceStats(7, now); stats.Total != 0 {
		t.Fatalf("expected empty baseline stats, got %+v", stats)
	}
	store.UpsertAlert(AlertmanagerWebhook{GroupKey: "cache-first"}, Alert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-a"},
		Annotations: map[string]string{"summary": "Queue blocked"},
		Fingerprint: "fp-cache-first",
		StartsAt:    now.Format(time.RFC3339),
	})
	if stats := store.RecurrenceStats(7, now); stats.Total != 1 {
		t.Fatalf("expected normal write to invalidate recurrence cache, got %+v", stats)
	}

	store.mu.Lock()
	store.incidents["INC-cache-direct"] = &Incident{
		IncidentID:       "INC-cache-direct",
		CorrelationKey:   "cache-direct",
		Title:            "Directly inserted cache probe",
		Severity:         "warning",
		Status:           "firing",
		FiredAt:          now.Add(30 * time.Second),
		LatestActivityAt: now.Add(30 * time.Second),
	}
	store.alerts["ALR-cache-direct"] = &AlertRecord{
		AlertID:     "ALR-cache-direct",
		IncidentID:  "INC-cache-direct",
		AlarmTitle:  "Directly inserted cache probe",
		Severity:    "warning",
		Status:      "firing",
		FiredAt:     now.Add(30 * time.Second),
		Fingerprint: "fp-cache-direct",
		Labels:      map[string]string{"alertname": "RunAIQueueBlocked", "severity": "warning", "queue": "gpu-b"},
		Annotations: map[string]string{"summary": "Queue blocked"},
	}
	store.mu.Unlock()

	if stats := store.RecurrenceStats(7, now.Add(30*time.Second)); stats.Total != 1 {
		t.Fatalf("expected cached stats inside TTL, got %+v", stats)
	}
	if stats := store.RecurrenceStats(7, now.Add(61*time.Second)); stats.Total != 2 {
		t.Fatalf("expected recurrence cache to expire, got %+v", stats)
	}
}
