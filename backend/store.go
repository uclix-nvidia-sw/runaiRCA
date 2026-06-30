package main

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pgvectorStatusDisabled    = "disabled"
	pgvectorStatusEnabled     = "enabled"
	pgvectorStatusUnavailable = "unavailable"
	vectorFallbackJSONB       = "jsonb"
	similaritySearchPGVector  = "pgvector_cosine"
	similaritySearchJSONB     = "jsonb_sparse_vectors"
	similaritySearchMemory    = "in_memory_sparse_vectors"

	maxOperatorPromptBytes             = 8000
	maxOperatorPromptCommentsPerTarget = 10
	maxOperatorPromptCommentBodyBytes  = 200
	maxOperatorPromptAuthorBytes       = 80

	maxIncidentAggregateSummaryBytes = 8000
	maxIncidentAggregateDetailBytes  = 32000

	maxStoredCommentBodyBytes = 8000
	maxFeedbackAuthorBytes    = 120
)

type Store struct {
	mu             sync.RWMutex
	incidentSeq    atomic.Int64
	alertSeq       atomic.Int64
	feedbackSeq    atomic.Int64
	commentSeq     atomic.Int64
	analysisRunSeq atomic.Int64
	incidents      map[string]*Incident
	incidentByKey  map[string]string
	alerts         map[string]*AlertRecord
	alertByFinger  map[string]string
	alertByGroup   map[string]string
	memories       map[string]*IncidentMemory
	feedback       map[string]*FeedbackRecord
	comments       map[string]*CommentRecord
	analysisRuns   map[string]*AnalysisRun
	db             *sql.DB
	dbReady        bool
	pgvectorReady  bool
	pgvectorDetail string
}

type AlertUpsertResult struct {
	Incident       *Incident
	Alert          *AlertRecord
	CorrelationKey string
	NewIncident    bool
	NewAlert       bool
	Changed        bool
}

type DashboardSnapshot struct {
	IncidentCount     int
	OpenIncidentCount int
	AlertCount        int
	FiringAlertCount  int
	AnalysisRunCount  int
	AnalysisStatuses  map[string]int
	RecentAlerts      []AlertRecord
	RecentRuns        []AnalysisRun
}

func NewStore() *Store {
	return &Store{
		incidents:     make(map[string]*Incident),
		incidentByKey: make(map[string]string),
		alerts:        make(map[string]*AlertRecord),
		alertByFinger: make(map[string]string),
		alertByGroup:  make(map[string]string),
		memories:      make(map[string]*IncidentMemory),
		feedback:      make(map[string]*FeedbackRecord),
		comments:      make(map[string]*CommentRecord),
		analysisRuns:  make(map[string]*AnalysisRun),
	}
}

func (s *Store) pgvectorStatus() string {
	if s.pgvectorReady {
		return pgvectorStatusEnabled
	}
	if s.dbReady {
		return pgvectorStatusUnavailable
	}
	return pgvectorStatusDisabled
}

func (s *Store) pgvectorLogState() string {
	if s.pgvectorReady {
		return "pgvector=enabled"
	}
	if s.dbReady {
		return "pgvector=unavailable, fallback=jsonb"
	}
	return "pgvector=disabled"
}

func pageRange(total, limit, offset int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		return offset, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}

func sameTimePtr(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func (s *Store) databaseHealth() map[string]any {
	health := map[string]any{
		"postgres":          s.dbReady,
		"pgvector":          s.pgvectorReady,
		"pgvector_status":   s.pgvectorStatus(),
		"similarity_search": similaritySearchMemory,
	}
	if s.dbReady {
		health["similarity_search"] = similaritySearchJSONB
	}
	if s.pgvectorReady {
		health["similarity_search"] = similaritySearchPGVector
	}
	if s.dbReady && !s.pgvectorReady {
		health["fallback"] = vectorFallbackJSONB
		if s.pgvectorDetail != "" {
			health["pgvector_detail"] = s.pgvectorDetail
		}
	}
	return health
}

func (s *Store) UpsertAlert(webhook AlertmanagerWebhook, alert Alert) (*Incident, *AlertRecord) {
	result := s.UpsertAlertResult(webhook, alert)
	return result.Incident, result.Alert
}

func (s *Store) UpsertAlertResult(webhook AlertmanagerWebhook, alert Alert) AlertUpsertResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.Labels == nil {
		alert.Labels = map[string]string{}
	}
	if alert.Annotations == nil {
		alert.Annotations = map[string]string{}
	}
	key := correlationKey(webhook, alert)
	fingerprint := alertIdentity(alert)
	storageKey := alertStorageKey(webhook, alert, key)
	alertStatus := status(alert.Status)
	now := time.Now().UTC()
	alertFiredAt := firstTime(alert.StartsAt, now)
	alertID := ""
	if storageKey != "" {
		alertID = s.alertByGroup[storageKey]
	}
	existingIDForFingerprint := ""
	if fingerprint != "" {
		existingIDForFingerprint = s.alertByFinger[fingerprint]
	}
	if alertID == "" && existingIDForFingerprint != "" {
		alertID = existingIDForFingerprint
	}
	incidentID := ""
	if alertID != "" {
		if existing := s.alerts[alertID]; existing != nil {
			if s.shouldReuseIncidentForAlertLocked(key, s.incidents[existing.IncidentID], alertFiredAt) {
				incidentID = existing.IncidentID
			} else {
				alertID = ""
			}
		}
	}
	if incidentID == "" {
		incidentID = s.incidentByKey[key]
		if incidentID != "" && !s.shouldReuseIncidentForAlertLocked(key, s.incidents[incidentID], alertFiredAt) {
			incidentID = ""
		}
	}
	newIncident := false
	if incidentID == "" {
		incidentID = nextID("INC", s.incidentSeq.Add(1))
		s.incidentByKey[key] = incidentID
		newIncident = true
		s.incidents[incidentID] = &Incident{
			IncidentID:     incidentID,
			CorrelationKey: key,
			Title:          groupedIncidentTitle(alert, 1),
			Severity:       severity(alert),
			Status:         "firing",
			FiredAt:        alertFiredAt,
		}
	}
	incident := s.incidents[incidentID]
	incident.Severity = maxSeverity(incident.Severity, severity(alert))
	if alertStatus == "resolved" && incident.ResolvedAt == nil {
		t := firstTime(alert.EndsAt, now)
		incident.ResolvedAt = &t
		incident.Status = "resolved"
	} else if alertStatus != "resolved" && incident.Status == "resolved" {
		incident.Status = "firing"
		incident.ResolvedAt = nil
	}

	if alertID == "" {
		alertID = nextID("ALR", s.alertSeq.Add(1))
	}
	if storageKey != "" {
		s.alertByGroup[storageKey] = alertID
	}
	if fingerprint != "" {
		s.alertByFinger[fingerprint] = alertID
	}
	record := s.alerts[alertID]
	newAlert := record == nil
	previousStatus := ""
	var previousResolvedAt *time.Time
	previousOccurrenceCount := 0
	if record == nil {
		record = &AlertRecord{AlertID: alertID}
		s.alerts[alertID] = record
	} else {
		previousStatus = record.Status
		previousResolvedAt = record.ResolvedAt
		previousOccurrenceCount = record.OccurrenceCount
	}
	newOccurrence := newAlert || existingIDForFingerprint == "" || existingIDForFingerprint != alertID
	if newOccurrence {
		incident.AlertCount++
	}
	incident.Title = groupedIncidentTitle(alert, incident.AlertCount)
	record.IncidentID = incidentID
	if record.OccurrenceCount <= 0 {
		record.OccurrenceCount = 0
	}
	if newOccurrence {
		record.OccurrenceCount++
	}
	if record.OccurrenceCount <= 0 {
		record.OccurrenceCount = 1
	}
	record.OccurrencePods = appendOccurrencePod(record.OccurrencePods, podName(alert))
	record.AlarmTitle = groupedIncidentTitle(alert, record.OccurrenceCount)
	record.Severity = severity(alert)
	record.Status = alertStatus
	record.FiredAt = alertFiredAt
	record.Fingerprint = fingerprint
	record.ThreadTS = "thread-" + alertID
	record.Labels = cloneMap(alert.Labels)
	record.Annotations = cloneMap(alert.Annotations)
	if alertStatus == "resolved" {
		t := firstTime(alert.EndsAt, now)
		record.ResolvedAt = &t
	} else {
		record.ResolvedAt = nil
	}
	activityAt := record.FiredAt
	if record.ResolvedAt != nil && record.ResolvedAt.After(activityAt) {
		activityAt = *record.ResolvedAt
	}
	if activityAt.After(incident.LatestActivityAt) {
		incident.LatestActivityAt = activityAt
	}
	changed := newAlert || previousStatus != record.Status || previousOccurrenceCount != record.OccurrenceCount || !sameTimePtr(previousResolvedAt, record.ResolvedAt)
	s.persistIncidentLocked(incident)
	s.persistAlertLocked(record)
	return AlertUpsertResult{
		Incident:       cloneIncident(incident),
		Alert:          cloneAlert(record),
		CorrelationKey: key,
		NewIncident:    newIncident,
		NewAlert:       newAlert,
		Changed:        changed,
	}
}

func (s *Store) shouldReuseIncidentForAlertLocked(key string, incident *Incident, firedAt time.Time) bool {
	if incident == nil {
		return false
	}
	if !strings.HasPrefix(key, "flap:") {
		return true
	}
	latest := incident.LatestActivityAt
	delta := firedAt.Sub(latest)
	if delta < 0 {
		delta = -delta
	}
	return delta <= flappingGroupWindow
}

func (s *Store) ListIncidents() []Incident {
	items, _ := s.ListIncidentsPage(0, 0)
	return items
}

func (s *Store) ListIncidentsPage(limit, offset int) ([]Incident, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ordered := make([]*Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		ordered = append(ordered, incident)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].FiredAt.After(ordered[j].FiredAt) })
	start, end := pageRange(len(ordered), limit, offset)
	items := make([]Incident, 0, end-start)
	for _, incident := range ordered[start:end] {
		items = append(items, *cloneIncident(incident))
	}
	return items, len(ordered)
}

func (s *Store) ListAlerts() []AlertRecord {
	items, _ := s.ListAlertsPage(0, 0)
	return items
}

func (s *Store) ListAlertsPage(limit, offset int) ([]AlertRecord, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ordered := make([]*AlertRecord, 0, len(s.alerts))
	for _, alert := range s.alerts {
		ordered = append(ordered, alert)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].FiredAt.After(ordered[j].FiredAt) })
	start, end := pageRange(len(ordered), limit, offset)
	items := make([]AlertRecord, 0, end-start)
	for _, alert := range ordered[start:end] {
		copied := cloneAlert(alert)
		copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, similarIncidentLimit)
		copied.Feedback = s.feedbackSummaryLocked("alert", alert.AlertID)
		items = append(items, *copied)
	}
	return items, len(ordered)
}

func (s *Store) ListAnalysisRuns() []AnalysisRun {
	items, _ := s.ListAnalysisRunsPage(0, 0)
	return items
}

func (s *Store) ListAnalysisRunsPage(limit, offset int) ([]AnalysisRun, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ordered := make([]*AnalysisRun, 0, len(s.analysisRuns))
	for _, run := range s.analysisRuns {
		ordered = append(ordered, run)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].CreatedAt.After(ordered[j].CreatedAt) })
	start, end := pageRange(len(ordered), limit, offset)
	items := make([]AnalysisRun, 0, end-start)
	for _, run := range ordered[start:end] {
		items = append(items, cloneAnalysisRun(run))
	}
	return items, len(ordered)
}

func (s *Store) DashboardSnapshot(recentLimit int) DashboardSnapshot {
	if recentLimit < 0 {
		recentLimit = 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := DashboardSnapshot{
		AnalysisStatuses: map[string]int{},
		RecentAlerts:     []AlertRecord{},
		RecentRuns:       []AnalysisRun{},
	}
	alerts := make([]*AlertRecord, 0, len(s.alerts))
	runs := make([]*AnalysisRun, 0, len(s.analysisRuns))
	for _, incident := range s.incidents {
		if incident == nil {
			continue
		}
		snapshot.IncidentCount++
		if incident.Status != "resolved" {
			snapshot.OpenIncidentCount++
		}
	}
	for _, alert := range s.alerts {
		if alert == nil {
			continue
		}
		snapshot.AlertCount++
		if alert.Status != "resolved" {
			snapshot.FiringAlertCount++
		}
		if recentLimit > 0 {
			alerts = append(alerts, alert)
		}
	}
	for _, run := range s.analysisRuns {
		if run == nil {
			continue
		}
		snapshot.AnalysisRunCount++
		snapshot.AnalysisStatuses[first(run.Status, "unknown")]++
		if recentLimit > 0 {
			runs = append(runs, run)
		}
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].FiredAt.After(alerts[j].FiredAt) })
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	if len(alerts) > recentLimit {
		alerts = alerts[:recentLimit]
	}
	if len(runs) > recentLimit {
		runs = runs[:recentLimit]
	}
	for _, alert := range alerts {
		snapshot.RecentAlerts = append(snapshot.RecentAlerts, *cloneAlert(alert))
	}
	for _, run := range runs {
		snapshot.RecentRuns = append(snapshot.RecentRuns, cloneAnalysisRun(run))
	}
	return snapshot
}

func (s *Store) LatestAlertID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *AlertRecord
	var latestFiring *AlertRecord
	for _, alert := range s.alerts {
		if alert == nil {
			continue
		}
		if latest == nil || alert.FiredAt.After(latest.FiredAt) {
			latest = alert
		}
		if alert.Status != "resolved" && (latestFiring == nil || alert.FiredAt.After(latestFiring.FiredAt)) {
			latestFiring = alert
		}
	}
	if latestFiring != nil {
		return latestFiring.AlertID
	}
	if latest != nil {
		return latest.AlertID
	}
	return ""
}

func (s *Store) CreateAnalysisRun(
	source string,
	targetType string,
	targetID string,
	incidentID string,
	alertID string,
	title string,
	prompt string,
) AnalysisRun {
	run, _ := s.CreateAnalysisRunIfAllowed(source, targetType, targetID, incidentID, alertID, title, prompt)
	return run
}

func (s *Store) CreateAnalysisRunIfAllowed(
	source string,
	targetType string,
	targetID string,
	incidentID string,
	alertID string,
	title string,
	prompt string,
) (AnalysisRun, bool) {
	source = first(source, "manual")
	now := time.Now().UTC()
	run := &AnalysisRun{
		RunID:        nextID("ANL", s.analysisRunSeq.Add(1)),
		Source:       source,
		Status:       "analyzing",
		TargetType:   targetType,
		TargetID:     targetID,
		IncidentID:   incidentID,
		AlertID:      alertID,
		Title:        first(title, "RCA analysis request"),
		Prompt:       strings.TrimSpace(prompt),
		Capabilities: map[string]string{},
		MissingData:  []string{},
		Warnings:     []string{},
		Artifacts:    []Artifact{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.analyzingAnalysisRunLocked(targetType, targetID, alertID); existing != nil {
		return cloneAnalysisRun(existing), false
	}
	if source == "auto" {
		if existing := s.latestAutoAnalysisRunLocked(alertID); existing != nil {
			return cloneAnalysisRun(existing), false
		}
	}
	s.analysisRuns[run.RunID] = run
	if !s.persistAnalysisRunLocked(run) {
		delete(s.analysisRuns, run.RunID)
		return AnalysisRun{}, false
	}
	return cloneAnalysisRun(run), true
}

func (s *Store) analyzingAnalysisRunLocked(targetType string, targetID string, alertID string) *AnalysisRun {
	var selected *AnalysisRun
	for _, run := range s.analysisRuns {
		if run == nil || run.Status != "analyzing" {
			continue
		}
		sameTarget := run.TargetType == targetType && run.TargetID == targetID
		sameAlert := alertID != "" && run.AlertID == alertID
		if !sameTarget && !sameAlert {
			continue
		}
		if selected == nil || run.CreatedAt.After(selected.CreatedAt) {
			selected = run
		}
	}
	return selected
}

func (s *Store) ExistingAutoAnalysisRun(alertID string) (AnalysisRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	selected := s.latestAutoAnalysisRunLocked(alertID)
	if selected == nil {
		return AnalysisRun{}, false
	}
	return cloneAnalysisRun(selected), true
}

func (s *Store) latestAutoAnalysisRunLocked(alertID string) *AnalysisRun {
	var selected *AnalysisRun
	for _, run := range s.analysisRuns {
		if run == nil || run.Source != "auto" || run.AlertID != alertID {
			continue
		}
		if selected == nil || run.CreatedAt.After(selected.CreatedAt) {
			selected = run
		}
	}
	return selected
}

func (s *Store) CompleteAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
	before := cloneAnalysisRun(run)
	run.Status = "complete"
	run.AnalysisSummary = response.AnalysisSummary
	run.AnalysisDetail = response.AnalysisDetail
	if run.AnalysisDetail == "" {
		run.AnalysisDetail = response.Analysis
	}
	run.AnalysisQuality = response.AnalysisQuality
	run.Capabilities = response.Capabilities
	run.MissingData = response.MissingData
	run.Warnings = response.Warnings
	run.Artifacts = response.Artifacts
	run.UpdatedAt = time.Now().UTC()
	if !s.persistAnalysisRunLocked(run) {
		*run = before
		return cloneAnalysisRun(run), false
	}
	return cloneAnalysisRun(run), true
}

func (s *Store) FailAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
	before := cloneAnalysisRun(run)
	run.Status = "failed"
	run.AnalysisSummary = response.AnalysisSummary
	run.AnalysisDetail = response.AnalysisDetail
	if run.AnalysisDetail == "" {
		run.AnalysisDetail = response.Analysis
	}
	run.AnalysisQuality = first(response.AnalysisQuality, "low")
	run.Capabilities = response.Capabilities
	run.MissingData = response.MissingData
	run.Warnings = response.Warnings
	run.Artifacts = response.Artifacts
	run.UpdatedAt = time.Now().UTC()
	if !s.persistAnalysisRunLocked(run) {
		*run = before
		return cloneAnalysisRun(run), false
	}
	return cloneAnalysisRun(run), true
}

// ReapStaleAnalyzingRuns enforces the lifecycle invariant across process
// restarts. A run persisted as "analyzing" past its source timeout has no
// goroutine to finish it, so on startup it is marked failed with a warning. Any
// stale is_analyzing flags on alerts/incidents are also cleared when no
// analyzing run remains for them. It returns the number of runs reaped.
func (s *Store) ReapStaleAnalyzingRuns(staleAfter time.Duration, manualStaleAfter time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	reaped := 0
	for _, run := range s.analysisRuns {
		if run == nil || run.Status != "analyzing" {
			continue
		}
		runStaleAfter := staleAfter
		if run.Source == "manual" {
			runStaleAfter = manualStaleAfter
		}
		if runStaleAfter > 0 && run.UpdatedAt.After(now.Add(-runStaleAfter)) {
			continue
		}
		before := cloneAnalysisRun(run)
		run.Status = "failed"
		run.AnalysisQuality = first(run.AnalysisQuality, "low")
		if run.Capabilities == nil {
			run.Capabilities = map[string]string{}
		}
		run.Capabilities["agent"] = "interrupted"
		run.Warnings = append(run.Warnings, "analysis was interrupted by a backend restart and marked failed")
		run.UpdatedAt = now
		if !s.persistAnalysisRunLocked(run) {
			*run = before
			continue
		}
		reaped++
	}
	activeAlerts := map[string]bool{}
	activeIncidents := map[string]bool{}
	for _, run := range s.analysisRuns {
		if run == nil || run.Status != "analyzing" {
			continue
		}
		if run.AlertID != "" {
			activeAlerts[run.AlertID] = true
		}
		if run.IncidentID != "" {
			activeIncidents[run.IncidentID] = true
		}
	}
	for _, alert := range s.alerts {
		if alert != nil && alert.IsAnalyzing && !activeAlerts[alert.AlertID] {
			alert.IsAnalyzing = false
			s.persistAlertLocked(alert)
		}
	}
	for _, incident := range s.incidents {
		if incident != nil && incident.IsAnalyzing && !activeIncidents[incident.IncidentID] {
			incident.IsAnalyzing = false
			s.persistIncidentLocked(incident)
		}
	}
	return reaped
}

func (s *Store) AnalysisTarget(targetType string, targetID string) (Alert, string, string, string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch targetType {
	case "alert":
		alert := s.alerts[targetID]
		if alert == nil {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*alert), alert.IncidentID, alert.AlertID, alert.ThreadTS, alert.AlarmTitle, true
	case "incident":
		incident := s.incidents[targetID]
		if incident == nil {
			return Alert{}, "", "", "", "", false
		}
		var selected *AlertRecord
		var selectedFiring *AlertRecord
		for _, alert := range s.alerts {
			if alert.IncidentID != targetID {
				continue
			}
			if selected == nil || alert.FiredAt.After(selected.FiredAt) {
				selected = alert
			}
			if alert.Status != "resolved" && (selectedFiring == nil || alert.FiredAt.After(selectedFiring.FiredAt)) {
				selectedFiring = alert
			}
		}
		if selectedFiring != nil {
			selected = selectedFiring
		}
		if selected == nil {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*selected), incident.IncidentID, selected.AlertID, selected.ThreadTS, incident.Title, true
	default:
		return Alert{}, "", "", "", "", false
	}
}

// OccurrenceSummaryForTarget returns the distinct concrete pod names and the
// total occurrence count behind an analysis target, aggregated across the grouped
// alert rows. It lets the agent reason about which pods cycled even though the
// flapping was collapsed into one row to protect the store.
func (s *Store) OccurrenceSummaryForTarget(incidentID string, alertID string) ([]string, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pods := []string{}
	seen := map[string]struct{}{}
	count := 0
	add := func(record *AlertRecord) {
		if record == nil {
			return
		}
		count += record.OccurrenceCount
		for _, pod := range record.OccurrencePods {
			if pod == "" {
				continue
			}
			if _, ok := seen[pod]; ok {
				continue
			}
			seen[pod] = struct{}{}
			pods = append(pods, pod)
		}
	}
	if incidentID != "" {
		records := make([]*AlertRecord, 0)
		for _, record := range s.alerts {
			if record != nil && record.IncidentID == incidentID {
				records = append(records, record)
			}
		}
		sort.Slice(records, func(i, j int) bool { return records[i].FiredAt.After(records[j].FiredAt) })
		for _, record := range records {
			add(record)
		}
	} else if alertID != "" {
		add(s.alerts[alertID])
	}
	if len(pods) > maxOccurrencePods {
		pods = pods[:maxOccurrencePods]
	}
	return pods, count
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
	detail.MissingData = []string{}
	detail.Warnings = []string{}
	detail.Artifacts = []Artifact{}
	detail.SimilarIncidents = []SimilarIncident{}
	detail.Alerts = []AlertRecord{}
	for _, alert := range s.alerts {
		if alert.IncidentID != id {
			continue
		}
		copied := cloneAlert(alert)
		copied.Feedback = s.feedbackSummaryLocked("alert", alert.AlertID)
		copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, similarIncidentLimit)
		detail.Alerts = append(detail.Alerts, *copied)
	}
	sort.Slice(detail.Alerts, func(i, j int) bool {
		return detail.Alerts[i].FiredAt.After(detail.Alerts[j].FiredAt)
	})
	summaryLines := []string{}
	detailSections := []string{}
	seenMissingData := map[string]struct{}{}
	seenWarnings := map[string]struct{}{}
	seenArtifacts := map[string]struct{}{}
	for _, alert := range detail.Alerts {
		if strings.TrimSpace(alert.AnalysisSummary) == "" && strings.TrimSpace(alert.AnalysisDetail) == "" {
			continue
		}
		title := first(alert.AlarmTitle, alert.AlertID)
		if strings.TrimSpace(alert.AnalysisSummary) != "" {
			summaryLines = append(summaryLines, fmt.Sprintf("- %s: %s", title, alert.AnalysisSummary))
		}
		if strings.TrimSpace(alert.AnalysisDetail) != "" {
			detailSections = append(detailSections, fmt.Sprintf("## %s\n\n%s", title, alert.AnalysisDetail))
		}
		if detail.AnalysisQuality == "" {
			detail.AnalysisQuality = alert.AnalysisQuality
		}
		for key, value := range alert.Capabilities {
			detail.Capabilities[key] = value
		}
		for _, item := range alert.MissingData {
			if _, ok := seenMissingData[item]; ok {
				continue
			}
			seenMissingData[item] = struct{}{}
			detail.MissingData = append(detail.MissingData, item)
		}
		for _, item := range alert.Warnings {
			if _, ok := seenWarnings[item]; ok {
				continue
			}
			seenWarnings[item] = struct{}{}
			detail.Warnings = append(detail.Warnings, item)
		}
		for _, artifact := range alert.Artifacts {
			key := string(mustJSON(artifact))
			if _, ok := seenArtifacts[key]; ok {
				continue
			}
			seenArtifacts[key] = struct{}{}
			detail.Artifacts = append(detail.Artifacts, artifact)
		}
	}
	if len(summaryLines) > 0 {
		detail.AnalysisSummary = excerpt(strings.Join(summaryLines, "\n"), maxIncidentAggregateSummaryBytes)
	}
	if len(detailSections) > 0 {
		detail.AnalysisDetail = excerpt(strings.Join(detailSections, "\n\n"), maxIncidentAggregateDetailBytes)
	}
	detail.Feedback = s.feedbackSummaryLocked("incident", id)
	if len(detail.Alerts) > 0 {
		detail.SimilarIncidents = s.similarIncidentsLocked(
			alertFromRecord(detail.Alerts[0]),
			id,
			similarIncidentLimit,
		)
	}
	return detail, true
}

func (s *Store) AlertDetail(id string) (*AlertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert := s.alerts[id]
	if alert == nil {
		return nil, false
	}
	copied := cloneAlert(alert)
	copied.Feedback = s.feedbackSummaryLocked("alert", id)
	copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, similarIncidentLimit)
	return copied, true
}

func (s *Store) AddFeedback(
	targetType string,
	targetID string,
	req FeedbackRequest,
) (FeedbackSummary, bool, error) {
	rawVote := strings.TrimSpace(first(req.Vote, req.VoteType))
	vote := normalizeVote(rawVote)
	actor := feedbackActor(req.Author)
	comment := strings.TrimSpace(req.Comment)
	if err := validateStoredText("author", actor, maxFeedbackAuthorBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	if err := validateStoredText("comment", comment, maxStoredCommentBodyBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	if strings.EqualFold(rawVote, "none") {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
			return FeedbackSummary{}, false, nil
		}
		s.deleteFeedbackForActorLocked(targetType, targetID, actor)
		return s.feedbackSummaryForActorLocked(targetType, targetID, actor), true, nil
	}
	if vote == "" {
		return FeedbackSummary{}, false, errors.New("vote must be up or down")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incidentID, alertID, ok := s.targetIDsLocked(targetType, targetID)
	if !ok {
		return FeedbackSummary{}, false, nil
	}
	s.deleteFeedbackForActorLocked(targetType, targetID, actor)
	record := &FeedbackRecord{
		FeedbackID: nextID("FDB", s.feedbackSeq.Add(1)),
		TargetType: targetType,
		TargetID:   targetID,
		IncidentID: incidentID,
		AlertID:    alertID,
		Vote:       vote,
		Comment:    comment,
		Author:     actor,
		CreatedAt:  time.Now().UTC(),
	}
	s.feedback[record.FeedbackID] = record
	s.persistFeedbackLocked(record)
	if record.Comment != "" {
		comment := &CommentRecord{
			CommentID:  nextID("CMT", s.commentSeq.Add(1)),
			TargetType: targetType,
			TargetID:   targetID,
			IncidentID: incidentID,
			AlertID:    alertID,
			Body:       record.Comment,
			Author:     record.Author,
			CreatedAt:  record.CreatedAt,
		}
		s.comments[comment.CommentID] = comment
		s.persistCommentLocked(comment)
	}
	return s.feedbackSummaryForActorLocked(targetType, targetID, actor), true, nil
}

func (s *Store) AddComment(
	targetType string,
	targetID string,
	req CommentRequest,
) (FeedbackSummary, bool, error) {
	body := strings.TrimSpace(req.Body)
	if body == "" {
		return FeedbackSummary{}, false, errors.New("comment body is required")
	}
	author := strings.TrimSpace(req.Author)
	if err := validateStoredText("comment body", req.Body, maxStoredCommentBodyBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	if err := validateStoredText("author", author, maxFeedbackAuthorBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incidentID, alertID, ok := s.targetIDsLocked(targetType, targetID)
	if !ok {
		return FeedbackSummary{}, false, nil
	}
	comment := &CommentRecord{
		CommentID:  nextID("CMT", s.commentSeq.Add(1)),
		TargetType: targetType,
		TargetID:   targetID,
		IncidentID: incidentID,
		AlertID:    alertID,
		Body:       body,
		Author:     author,
		CreatedAt:  time.Now().UTC(),
	}
	s.comments[comment.CommentID] = comment
	s.persistCommentLocked(comment)
	return s.feedbackSummaryLocked(targetType, targetID), true, nil
}

func (s *Store) UpdateComment(
	targetType string,
	targetID string,
	commentID string,
	req CommentRequest,
) (FeedbackSummary, bool, error) {
	body := strings.TrimSpace(req.Body)
	if body == "" {
		return FeedbackSummary{}, false, errors.New("comment body is required")
	}
	author := strings.TrimSpace(req.Author)
	if err := validateStoredText("comment body", req.Body, maxStoredCommentBodyBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	if err := validateStoredText("author", author, maxFeedbackAuthorBytes); err != nil {
		return FeedbackSummary{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
		return FeedbackSummary{}, false, nil
	}
	comment := s.comments[commentID]
	if comment == nil || comment.TargetType != targetType || comment.TargetID != targetID {
		return FeedbackSummary{}, false, nil
	}
	comment.Body = body
	if author != "" {
		comment.Author = author
	}
	s.persistCommentUpdateLocked(comment)
	return s.feedbackSummaryLocked(targetType, targetID), true, nil
}

func validateStoredText(field string, value string, maxBytes int) error {
	if len(value) > maxBytes {
		return fmt.Errorf("%s must be %d bytes or less", field, maxBytes)
	}
	return nil
}

func (s *Store) OperatorPromptForTarget(targetType string, targetID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	incidentID, alertID, ok := s.targetIDsLocked(targetType, targetID)
	if !ok {
		return ""
	}
	lines := []string{"Operator feedback comments to consider during this reanalysis:"}
	lines = appendCommentPromptLines(lines, "incident", incidentID, s.commentsForTargetLocked("incident", incidentID))
	if alertID != "" {
		lines = appendCommentPromptLines(lines, "alert", alertID, s.commentsForTargetLocked("alert", alertID))
	}
	if len(lines) == 1 {
		return ""
	}
	return excerpt(strings.Join(lines, "\n"), maxOperatorPromptBytes)
}

func appendCommentPromptLines(lines []string, targetType string, targetID string, comments []CommentRecord) []string {
	if targetID == "" || len(comments) == 0 {
		return lines
	}
	if len(comments) > maxOperatorPromptCommentsPerTarget {
		omitted := len(comments) - maxOperatorPromptCommentsPerTarget
		lines = append(lines, fmt.Sprintf("- %d older %s comment(s) omitted from this analysis prompt.", omitted, targetType))
		comments = comments[omitted:]
	}
	for _, comment := range comments {
		body := strings.TrimSpace(comment.Body)
		if body == "" {
			continue
		}
		author := excerpt(first(strings.TrimSpace(comment.Author), "operator"), maxOperatorPromptAuthorBytes)
		lines = append(lines, fmt.Sprintf("- %s %s by %s: %s", targetType, targetID, author, excerpt(body, maxOperatorPromptCommentBodyBytes)))
	}
	return lines
}

func (s *Store) DeleteComment(
	targetType string,
	targetID string,
	commentID string,
) (FeedbackSummary, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.targetIDsLocked(targetType, targetID); !ok {
		return FeedbackSummary{}, false
	}
	comment := s.comments[commentID]
	if comment == nil || comment.TargetType != targetType || comment.TargetID != targetID {
		return FeedbackSummary{}, false
	}
	delete(s.comments, commentID)
	s.persistCommentDeleteLocked(commentID)
	return s.feedbackSummaryLocked(targetType, targetID), true
}

func (s *Store) feedbackSummaryLocked(targetType string, targetID string) FeedbackSummary {
	summary := FeedbackSummary{
		TargetType: targetType,
		TargetID:   targetID,
		Comments:   s.commentsForTargetLocked(targetType, targetID),
	}
	for _, record := range s.feedback {
		if record.TargetType != targetType || record.TargetID != targetID {
			continue
		}
		switch record.Vote {
		case "up":
			summary.Positive++
		case "down":
			summary.Negative++
		}
	}
	if summary.Positive > 0 {
		summary.LearningHints = append(summary.LearningHints, FeedbackHint{
			SourceID:  targetID,
			Sentiment: "positive",
			Weight:    float64(summary.Positive),
			Text:      "Operators marked this RCA as useful.",
		})
	}
	if summary.Negative > 0 {
		summary.LearningHints = append(summary.LearningHints, FeedbackHint{
			SourceID:  targetID,
			Sentiment: "negative",
			Weight:    float64(summary.Negative),
			Text:      "Operators marked this RCA as needing correction.",
		})
	}
	return summary
}

func (s *Store) feedbackSummaryForActorLocked(targetType string, targetID string, author string) FeedbackSummary {
	summary := s.feedbackSummaryLocked(targetType, targetID)
	if record := s.feedbackForActorLocked(targetType, targetID, author); record != nil {
		summary.MyVote = record.Vote
	}
	return summary
}

func (s *Store) feedbackForActorLocked(targetType string, targetID string, author string) *FeedbackRecord {
	actor := feedbackActor(author)
	for _, record := range s.feedback {
		if record.TargetType == targetType && record.TargetID == targetID && feedbackActor(record.Author) == actor {
			return record
		}
	}
	return nil
}

func (s *Store) deleteFeedbackForActorLocked(targetType string, targetID string, author string) {
	actor := feedbackActor(author)
	for feedbackID, record := range s.feedback {
		if record.TargetType == targetType && record.TargetID == targetID && feedbackActor(record.Author) == actor {
			delete(s.feedback, feedbackID)
		}
	}
	s.persistFeedbackDeleteForActorLocked(targetType, targetID, actor)
}

func (s *Store) commentsForTargetLocked(targetType string, targetID string) []CommentRecord {
	items := []CommentRecord{}
	for _, comment := range s.comments {
		if comment.TargetType == targetType && comment.TargetID == targetID {
			items = append(items, *cloneComment(comment))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items
}

func (s *Store) targetIDsLocked(targetType string, targetID string) (string, string, bool) {
	switch targetType {
	case "incident":
		if s.incidents[targetID] == nil {
			return "", "", false
		}
		return targetID, "", true
	case "alert":
		alert := s.alerts[targetID]
		if alert == nil {
			return "", "", false
		}
		return alert.IncidentID, alert.AlertID, true
	default:
		return "", "", false
	}
}

func (s *Store) TargetIDs(targetType string, targetID string) (string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.targetIDsLocked(targetType, targetID)
}
