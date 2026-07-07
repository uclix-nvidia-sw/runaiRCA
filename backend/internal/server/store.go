package server

import (
	"database/sql"
	"encoding/json"
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

	maxProgressLogEntries = 200

	incidentViewActive   = "active"
	incidentViewArchived = "archived"
	incidentViewTrash    = "trash"

	recurrenceStatsCacheTTL = time.Minute
)

type recurrenceStatsCacheKey struct {
	days int
	asOf time.Time
}

type recurrenceStatsCacheEntry struct {
	expiresAt time.Time
	stats     RecurrenceStats
}

type Store struct {
	mu                   sync.RWMutex
	incidentSeq          atomic.Int64
	alertSeq             atomic.Int64
	feedbackSeq          atomic.Int64
	commentSeq           atomic.Int64
	analysisRunSeq       atomic.Int64
	incidents            map[string]*Incident
	incidentByKey        map[string]string
	alerts               map[string]*AlertRecord
	alertByFinger        map[string]string
	alertByGroup         map[string]string
	memories             map[string]*IncidentMemory
	feedback             map[string]*FeedbackRecord
	comments             map[string]*CommentRecord
	analysisRuns         map[string]*AnalysisRun
	recurrenceStatsCache map[recurrenceStatsCacheKey]recurrenceStatsCacheEntry
	db                   *sql.DB
	dbReady              bool
	pgvectorReady        bool
	pgvectorDetail       string
	embedder             *embedder
	flappingWindow       time.Duration
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
		recurrenceStatsCache: make(
			map[recurrenceStatsCacheKey]recurrenceStatsCacheEntry,
		),
		embedder: newEmbedder(),
		// How long an alert signature can be quiet before a recurrence is treated as
		// a NEW incident rather than another occurrence of the flapping one. 30 min
		// was too tight — real alerts recur over hours, so each firing spawned its
		// own row. Default 2h; tune per environment.
		flappingWindow: time.Duration(getenvInt("FLAPPING_GROUP_WINDOW_MINUTES", 120)) * time.Minute,
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

func validIncidentView(view string) bool {
	return view == incidentViewActive || view == incidentViewArchived || view == incidentViewTrash
}

type IncidentListFilter struct {
	Status        string
	Severity      string
	FinalDecision string
}

type AlertListFilter struct {
	Status   string
	Severity string
}

func validIncidentStatusFilter(status string) bool {
	return status == "" || status == "firing" || status == "resolved" || status == "analyzing"
}

func validIncidentSeverityFilter(severity string) bool {
	return severity == "" || severity == "critical" || severity == "warning" || severity == "info"
}

func validIncidentFinalDecisionFilter(decision string) bool {
	return decision == "" || decision == "approved" || decision == "pending"
}

func incidentInView(incident *Incident, view string) bool {
	if incident == nil {
		return false
	}
	switch view {
	case incidentViewArchived:
		return incident.DeletedAt == nil && incident.ArchivedAt != nil
	case incidentViewTrash:
		return incident.DeletedAt != nil
	default:
		return incident.DeletedAt == nil && incident.ArchivedAt == nil
	}
}

func incidentMatchesListFilter(incident *Incident, filter IncidentListFilter) bool {
	if incident == nil {
		return false
	}
	if filter.Status != "" {
		if filter.Status == "analyzing" {
			if !incident.IsAnalyzing {
				return false
			}
		} else if incident.Status != filter.Status {
			return false
		}
	}
	if filter.Severity != "" && incident.Severity != filter.Severity {
		return false
	}
	if filter.FinalDecision == "approved" && incident.UserApprovedAt == nil {
		return false
	}
	if filter.FinalDecision == "pending" && incident.UserApprovedAt != nil {
		return false
	}
	return true
}

func alertMatchesListFilter(alert *AlertRecord, filter AlertListFilter) bool {
	if alert == nil {
		return false
	}
	if filter.Status != "" {
		if filter.Status == "analyzing" {
			if !alert.IsAnalyzing {
				return false
			}
		} else if alert.Status != filter.Status {
			return false
		}
	}
	if filter.Severity != "" && alert.Severity != filter.Severity {
		return false
	}
	return true
}

func incidentDeleted(incident *Incident) bool {
	return incident != nil && incident.DeletedAt != nil
}

func incidentUserApproved(incident *Incident) bool {
	return incident != nil && incident.UserApprovedAt != nil
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
	if incident.ArchivedAt != nil {
		incident.ArchivedAt = nil
	}
	incident.Severity = maxSeverity(incident.Severity, severity(alert))
	if alertStatus == "resolved" && incident.ResolvedAt == nil {
		t := firstTime(alert.EndsAt, now)
		incident.ResolvedAt = &t
		incident.Status = "resolved"
	} else if alertStatus != "resolved" && incident.Status == "resolved" {
		incident.Status = "firing"
		incident.ResolvedAt = nil
		incident.UserApprovedAt = nil
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
	previousSeverity := ""
	previousFiredAt := time.Time{}
	var previousResolvedAt *time.Time
	previousOccurrenceCount := 0
	if record == nil {
		record = &AlertRecord{AlertID: alertID}
		s.alerts[alertID] = record
	} else {
		previousStatus = record.Status
		previousSeverity = record.Severity
		previousFiredAt = record.FiredAt
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
	changed := newAlert ||
		previousStatus != record.Status ||
		previousSeverity != record.Severity ||
		!previousFiredAt.Equal(record.FiredAt) ||
		previousOccurrenceCount != record.OccurrenceCount ||
		!sameTimePtr(previousResolvedAt, record.ResolvedAt)
	s.persistIncidentLocked(incident)
	s.persistAlertLocked(record)
	s.invalidateRecurrenceStatsLocked()
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
	if incident == nil || incidentDeleted(incident) {
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
	window := s.flappingWindow
	if window <= 0 {
		window = flappingGroupWindow
	}
	return delta <= window
}

func (s *Store) ListIncidents() []Incident {
	items, _ := s.ListIncidentsPage(0, 0, incidentViewActive)
	return items
}

func (s *Store) ListIncidentsPage(limit, offset int, views ...string) ([]Incident, int) {
	view := incidentViewActive
	if len(views) > 0 && views[0] != "" {
		view = views[0]
	}
	return s.ListIncidentsPageFiltered(limit, offset, view, IncidentListFilter{})
}

func (s *Store) ListIncidentsPageFiltered(limit, offset int, view string, filter IncidentListFilter) ([]Incident, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ordered := make([]*Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		if !incidentInView(incident, view) || !incidentMatchesListFilter(incident, filter) {
			continue
		}
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
	return s.ListAlertsPageFiltered(limit, offset, AlertListFilter{})
}

func (s *Store) ListAlertsPageFiltered(limit, offset int, filter AlertListFilter) ([]AlertRecord, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ordered := make([]*AlertRecord, 0, len(s.alerts))
	for _, alert := range s.alerts {
		if alert == nil || incidentDeleted(s.incidents[alert.IncidentID]) || !alertMatchesListFilter(alert, filter) {
			continue
		}
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

func (s *Store) ArchiveIncident(id string, archived bool) (*Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incidentDeleted(incident) {
		return nil, false
	}
	if archived {
		now := time.Now().UTC()
		incident.ArchivedAt = &now
	} else {
		incident.ArchivedAt = nil
	}
	if !s.persistIncidentLocked(incident) {
		return nil, false
	}
	s.invalidateRecurrenceStatsLocked()
	return cloneIncident(incident), true
}

func (s *Store) SoftDeleteIncident(id string) (*Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incident == nil {
		return nil, false
	}
	if incident.DeletedAt == nil {
		now := time.Now().UTC()
		incident.DeletedAt = &now
	}
	s.removeIncidentIndexesLocked(id)
	if !s.persistIncidentLocked(incident) {
		return nil, false
	}
	s.invalidateRecurrenceStatsLocked()
	return cloneIncident(incident), true
}

func (s *Store) RestoreIncident(id string) (*Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incident == nil {
		return nil, false
	}
	incident.DeletedAt = nil
	incident.ArchivedAt = nil
	s.registerIncidentIndexesLocked(incident)
	if !s.persistIncidentLocked(incident) {
		return nil, false
	}
	s.invalidateRecurrenceStatsLocked()
	return cloneIncident(incident), true
}

func (s *Store) HardDeleteIncident(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incident == nil {
		return false
	}
	alertIDs := map[string]struct{}{}
	for alertID, alert := range s.alerts {
		if alert != nil && alert.IncidentID == id {
			alertIDs[alertID] = struct{}{}
		}
	}
	alertList := make([]string, 0, len(alertIDs))
	for alertID := range alertIDs {
		alertList = append(alertList, alertID)
	}
	if !s.persistHardDeleteIncidentLocked(id, alertList) {
		return false
	}
	s.removeIncidentIndexesLocked(id)
	delete(s.incidents, id)
	for alertID := range alertIDs {
		delete(s.alerts, alertID)
	}
	for key, memory := range s.memories {
		if memory == nil {
			continue
		}
		if memory.IncidentID == id {
			delete(s.memories, key)
			continue
		}
		if _, ok := alertIDs[memory.AlertID]; ok {
			delete(s.memories, key)
		}
	}
	for key, record := range s.feedback {
		if record == nil {
			continue
		}
		if record.IncidentID == id || (record.TargetType == "incident" && record.TargetID == id) {
			delete(s.feedback, key)
			continue
		}
		if _, ok := alertIDs[record.AlertID]; ok {
			delete(s.feedback, key)
			continue
		}
		if record.TargetType == "alert" {
			if _, ok := alertIDs[record.TargetID]; ok {
				delete(s.feedback, key)
			}
		}
	}
	for key, record := range s.comments {
		if record == nil {
			continue
		}
		if record.IncidentID == id || (record.TargetType == "incident" && record.TargetID == id) {
			delete(s.comments, key)
			continue
		}
		if _, ok := alertIDs[record.AlertID]; ok {
			delete(s.comments, key)
			continue
		}
		if record.TargetType == "alert" {
			if _, ok := alertIDs[record.TargetID]; ok {
				delete(s.comments, key)
			}
		}
	}
	for key, run := range s.analysisRuns {
		if run == nil {
			continue
		}
		if run.IncidentID == id {
			delete(s.analysisRuns, key)
			continue
		}
		if _, ok := alertIDs[run.AlertID]; ok {
			delete(s.analysisRuns, key)
		}
	}
	s.invalidateRecurrenceStatsLocked()
	return true
}

func (s *Store) PurgeExpiredTrash(retention time.Duration, now time.Time) int {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-retention)
	ids := []string{}
	s.mu.RLock()
	for id, incident := range s.incidents {
		if incident == nil || incident.DeletedAt == nil {
			continue
		}
		if !incident.DeletedAt.After(cutoff) {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()
	purged := 0
	for _, id := range ids {
		if s.HardDeleteIncident(id) {
			purged++
		}
	}
	return purged
}

func (s *Store) removeIncidentIndexesLocked(incidentID string) {
	incident := s.incidents[incidentID]
	if incident != nil && s.incidentByKey[incident.CorrelationKey] == incidentID {
		delete(s.incidentByKey, incident.CorrelationKey)
	}
	for _, alert := range s.alerts {
		if alert == nil || alert.IncidentID != incidentID {
			continue
		}
		if s.alertByFinger[alert.Fingerprint] == alert.AlertID {
			delete(s.alertByFinger, alert.Fingerprint)
		}
		if incident != nil {
			key := "correlation:" + incident.CorrelationKey
			if s.alertByGroup[key] == alert.AlertID {
				delete(s.alertByGroup, key)
			}
		}
	}
}

func (s *Store) registerIncidentIndexesLocked(incident *Incident) {
	if incident == nil || incident.DeletedAt != nil {
		return
	}
	if incident.CorrelationKey != "" && s.incidentByKey[incident.CorrelationKey] == "" {
		s.incidentByKey[incident.CorrelationKey] = incident.IncidentID
	}
	for _, alert := range s.alerts {
		if alert == nil || alert.IncidentID != incident.IncidentID {
			continue
		}
		if alert.Fingerprint != "" && s.alertByFinger[alert.Fingerprint] == "" {
			s.alertByFinger[alert.Fingerprint] = alert.AlertID
		}
		key := "correlation:" + incident.CorrelationKey
		if incident.CorrelationKey != "" && s.alertByGroup[key] == "" {
			s.alertByGroup[key] = alert.AlertID
		}
	}
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
		if incidentDeleted(incident) {
			continue
		}
		snapshot.IncidentCount++
		if incident.Status != "resolved" {
			snapshot.OpenIncidentCount++
		}
	}
	for _, alert := range s.alerts {
		if alert == nil || incidentDeleted(s.incidents[alert.IncidentID]) {
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

func (s *Store) RecurrenceStats(days int, now time.Time) RecurrenceStats {
	if days <= 0 {
		days = 7
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.AddDate(0, 0, -days)
	stats := RecurrenceStats{Days: days, Daily: make([]RecurrenceDay, 0, days)}
	byDate := map[string]int{}
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		stats.Daily = append(stats.Daily, RecurrenceDay{Date: date})
		byDate[date] = len(stats.Daily) - 1
	}

	cacheKey := recurrenceStatsCacheKey{days: days, asOf: now.Truncate(time.Minute)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.recurrenceStatsCache[cacheKey]; ok && now.Before(entry.expiresAt) {
		return cloneRecurrenceStats(entry.stats)
	}
	// ponytail: O(recent incidents * memories), cached for the dashboard's polling cadence.
	for _, incident := range s.incidents {
		if incident == nil || incidentDeleted(incident) || incident.FiredAt.Before(since) || incident.FiredAt.After(now) {
			continue
		}
		alert := s.latestAlertForIncidentLocked(incident.IncidentID)
		if alert == nil {
			continue
		}
		stats.Total++
		day, ok := byDate[incident.FiredAt.Format("2006-01-02")]
		if ok {
			stats.Daily[day].Total++
		}
		before := incident.FiredAt
		if s.similarRecentCountLocked(alertFromRecord(*alert), incident.IncidentID, incident.FiredAt.AddDate(0, 0, -days), &before) == 0 {
			continue
		}
		stats.Recurred++
		if ok {
			stats.Daily[day].Recurred++
		}
	}
	stats.Rate = recurrenceRate(stats.Recurred, stats.Total)
	for i := range stats.Daily {
		stats.Daily[i].Rate = recurrenceRate(stats.Daily[i].Recurred, stats.Daily[i].Total)
	}
	s.recurrenceStatsCache[cacheKey] = recurrenceStatsCacheEntry{
		expiresAt: now.Add(recurrenceStatsCacheTTL),
		stats:     cloneRecurrenceStats(stats),
	}
	return cloneRecurrenceStats(stats)
}

func (s *Store) invalidateRecurrenceStatsLocked() {
	if len(s.recurrenceStatsCache) > 0 {
		s.recurrenceStatsCache = make(map[recurrenceStatsCacheKey]recurrenceStatsCacheEntry)
	}
}

func cloneRecurrenceStats(stats RecurrenceStats) RecurrenceStats {
	stats.Daily = append([]RecurrenceDay(nil), stats.Daily...)
	return stats
}

func (s *Store) LLMSpendStats(days int, now time.Time) LLMSpendStats {
	if days <= 0 {
		days = 7
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.AddDate(0, 0, -days)
	stats := LLMSpendStats{
		Days:    days,
		ByModel: map[string]LLMSpendBucket{},
		Daily:   make([]LLMSpendDay, 0, days),
	}
	byDate := map[string]int{}
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		stats.Daily = append(stats.Daily, LLMSpendDay{Date: date})
		byDate[date] = len(stats.Daily) - 1
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, run := range s.analysisRuns {
		if run == nil || run.UpdatedAt.Before(since) || run.UpdatedAt.After(now) {
			continue
		}
		usage, ok := run.Metadata["llm_usage"].(map[string]any)
		if !ok {
			continue
		}
		addUsageBucket(&stats.LLMSpendBucket, usage)
		if day, ok := byDate[run.UpdatedAt.Format("2006-01-02")]; ok {
			addUsageBucket(&stats.Daily[day].LLMSpendBucket, usage)
		}
		if rawByModel, ok := usage["by_model"].(map[string]any); ok {
			for model, rawBucket := range rawByModel {
				bucketMap, ok := rawBucket.(map[string]any)
				if !ok {
					continue
				}
				bucket := stats.ByModel[model]
				addUsageBucket(&bucket, bucketMap)
				stats.ByModel[model] = bucket
			}
		}
	}
	return stats
}

// llm_usage may carry a nested "nat" per-stage breakdown of these same totals; it is deliberately not aggregated here (it would double count).
func addUsageBucket(bucket *LLMSpendBucket, usage map[string]any) {
	bucket.Calls += usageInt(usage["calls"])
	bucket.CallsWithoutUsage += usageInt(usage["calls_without_usage"])
	bucket.FailedCalls += usageInt(usage["failed_calls"])
	bucket.PromptTokens += usageInt(usage["prompt_tokens"])
	bucket.CompletionTokens += usageInt(usage["completion_tokens"])
	bucket.TotalTokens += usageInt(usage["total_tokens"])
	bucket.CostUSD += usageFloat(usage["cost_usd"])
}

func usageInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case json.Number:
		out, _ := v.Int64()
		return int(out)
	default:
		return 0
	}
}

func usageFloat(value any) float64 {
	switch v := value.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case float32:
		return float64(v)
	case json.Number:
		out, _ := v.Float64()
		return out
	default:
		return 0
	}
}

func (s *Store) KPIStats(days int, now time.Time) KPIStats {
	if days <= 0 {
		days = 7
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	since := now.AddDate(0, 0, -days)
	stats := KPIStats{Days: days, Daily: make([]KPIDay, 0, days)}
	byDate := map[string]int{}
	rcaByDay := make([][]float64, days)
	resolveByDay := make([][]float64, days)
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		stats.Daily = append(stats.Daily, KPIDay{Date: date})
		byDate[date] = len(stats.Daily) - 1
	}

	rcaMinutes := []float64{}
	resolveMinutes := []float64{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, incident := range s.incidents {
		if incident == nil || incidentDeleted(incident) || incident.FiredAt.Before(since) || incident.FiredAt.After(now) {
			continue
		}
		day, hasDay := byDate[incident.FiredAt.Format("2006-01-02")]
		if firstCompleted := s.firstCompletedAtForIncidentLocked(incident.IncidentID); firstCompleted != nil && !firstCompleted.Before(incident.FiredAt) {
			minutes := firstCompleted.Sub(incident.FiredAt).Minutes()
			rcaMinutes = append(rcaMinutes, minutes)
			if hasDay {
				rcaByDay[day] = append(rcaByDay[day], minutes)
			}
		}
		if incident.ResolvedAt != nil && !incident.ResolvedAt.Before(incident.FiredAt) {
			minutes := incident.ResolvedAt.Sub(incident.FiredAt).Minutes()
			resolveMinutes = append(resolveMinutes, minutes)
			if hasDay {
				resolveByDay[day] = append(resolveByDay[day], minutes)
			}
		}
	}
	stats.TimeToRCA = kpiBucket(rcaMinutes)
	stats.TimeToResolve = kpiBucket(resolveMinutes)
	for i := range stats.Daily {
		stats.Daily[i].TimeToRCA = kpiBucket(rcaByDay[i])
		stats.Daily[i].TimeToResolve = kpiBucket(resolveByDay[i])
	}
	return stats
}

func (s *Store) firstCompletedAtForIncidentLocked(incidentID string) *time.Time {
	var selected *time.Time
	for _, run := range s.analysisRuns {
		if run == nil || run.Status != "complete" || run.IncidentID != incidentID {
			continue
		}
		completedAt := run.FirstCompletedAt
		if completedAt == nil {
			completedAt = &run.UpdatedAt
		}
		if selected == nil || completedAt.Before(*selected) {
			value := *completedAt
			selected = &value
		}
	}
	return selected
}

func kpiBucket(values []float64) KPIBucket {
	if len(values) == 0 {
		return KPIBucket{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, value := range sorted {
		sum += value
	}
	return KPIBucket{
		Count:      len(sorted),
		AvgMinutes: roundMinutes(sum / float64(len(sorted))),
		P50Minutes: roundMinutes(percentile(sorted, 0.50)),
		P90Minutes: roundMinutes(percentile(sorted, 0.90)),
	}
}

func percentile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1)*q + 0.5)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func roundMinutes(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

func recurrenceRate(recurred int, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(recurred) / float64(total)
}

func metadataFromAgentContext(context map[string]any) map[string]any {
	if context == nil {
		return nil
	}
	usage, ok := context["llm_usage"]
	if !ok {
		return nil
	}
	if usageMap, ok := usage.(map[string]any); ok {
		return map[string]any{"llm_usage": cloneAnyMap(usageMap)}
	}
	return map[string]any{"llm_usage": usage}
}

func mergeAnalysisMetadata(existing map[string]any, incoming map[string]any) map[string]any {
	if len(existing) == 0 {
		return cloneAnyMap(incoming)
	}
	out := cloneAnyMap(existing)
	for key, value := range incoming {
		if child, ok := value.(map[string]any); ok {
			out[key] = cloneAnyMap(child)
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func progressLogFromMetadata(metadata map[string]any) []any {
	raw, ok := metadata["progress_log"].([]any)
	if !ok {
		return []any{}
	}
	return append([]any{}, raw...)
}

func nextProgressSeq(log []any) int {
	if len(log) == 0 {
		return 1
	}
	if item, ok := log[len(log)-1].(map[string]any); ok {
		return usageInt(item["seq"]) + 1
	}
	return len(log) + 1
}

func normalizeProgressEntry(entry map[string]any, seq int, now time.Time) map[string]any {
	out := cloneAnyMap(entry)
	out["seq"] = seq
	if _, ok := out["timestamp"]; !ok {
		out["timestamp"] = now
	}
	return out
}

func (s *Store) latestTokenUsageLocked(incidentID string) map[string]any {
	alertIDs := map[string]struct{}{}
	for _, alert := range s.alerts {
		if alert != nil && alert.IncidentID == incidentID {
			alertIDs[alert.AlertID] = struct{}{}
		}
	}
	var selected *AnalysisRun
	for _, run := range s.analysisRuns {
		if run == nil || len(run.Metadata) == 0 {
			continue
		}
		matches := run.IncidentID == incidentID
		if !matches {
			_, matches = alertIDs[run.AlertID]
		}
		if !matches {
			continue
		}
		if _, ok := run.Metadata["llm_usage"]; !ok {
			continue
		}
		if selected == nil || run.UpdatedAt.After(selected.UpdatedAt) {
			selected = run
		}
	}
	if selected == nil {
		return nil
	}
	if usage, ok := selected.Metadata["llm_usage"].(map[string]any); ok {
		return cloneAnyMap(usage)
	}
	return map[string]any{"value": selected.Metadata["llm_usage"]}
}

func (s *Store) latestAlertForIncidentLocked(incidentID string) *AlertRecord {
	var selected *AlertRecord
	var selectedFiring *AlertRecord
	for _, alert := range s.alerts {
		if alert == nil || alert.IncidentID != incidentID {
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
		return selectedFiring
	}
	return selected
}

func (s *Store) LatestAlertID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *AlertRecord
	var latestFiring *AlertRecord
	for _, alert := range s.alerts {
		if alert == nil || incidentDeleted(s.incidents[alert.IncidentID]) {
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
	} else if existing := s.latestReusableAnalysisRunLocked(targetType, targetID); existing != nil {
		// Re-analysis updates the existing run in place instead of appending a
		// new row, so an incident keeps a single evolving RCA run.
		// Clear previous result fields so stale content is not surfaced while
		// the new analysis is in progress.
		existing.Status = "analyzing"
		existing.Source = source
		existing.Title = run.Title
		existing.Prompt = run.Prompt
		existing.AnalysisSummary = ""
		existing.AnalysisDetail = ""
		existing.AnalysisQuality = ""
		existing.Capabilities = map[string]string{}
		existing.MissingData = []string{}
		existing.Warnings = []string{}
		existing.Artifacts = []Artifact{}
		existing.Metadata = nil
		// This IS a new analysis occupying the old row, so it must also become the
		// NEWEST run: isLatestAnalysisRunForAlert compares CreatedAt, and with the
		// old timestamp any run created later (e.g. a comment reanalysis) stayed
		// permanently newer — every re-analysis of this alert then completed only
		// to be rejected as stale ("alert RCA persistence failed"), forever.
		existing.CreatedAt = now
		existing.UpdatedAt = now
		if !s.persistAnalysisRunLocked(existing) {
			return AnalysisRun{}, false
		}
		return cloneAnalysisRun(existing), true
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

// latestReusableAnalysisRunLocked returns the most recent non-analyzing run for
// the exact target so a re-analysis updates it in place instead of creating a
// new row. Matched by target_type+target_id only: an alert-scoped run and an
// incident-scoped run for the same alert are distinct and must stay separate.
func (s *Store) latestReusableAnalysisRunLocked(targetType string, targetID string) *AnalysisRun {
	var selected *AnalysisRun
	for _, run := range s.analysisRuns {
		if run == nil || run.Status == "analyzing" {
			continue
		}
		if run.TargetType != targetType || run.TargetID != targetID {
			continue
		}
		if selected == nil || run.UpdatedAt.After(selected.UpdatedAt) {
			selected = run
		}
	}
	return selected
}

func (s *Store) AppendAnalysisProgress(runID string, entry map[string]any) (AnalysisRun, map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil || run.Status != "analyzing" {
		return AnalysisRun{}, nil, false
	}
	if run.Metadata == nil {
		run.Metadata = map[string]any{}
	}
	log := progressLogFromMetadata(run.Metadata)
	progress := normalizeProgressEntry(entry, nextProgressSeq(log), time.Now().UTC())
	log = append(log, progress)
	if len(log) > maxProgressLogEntries {
		log = log[len(log)-maxProgressLogEntries:]
	}
	run.Metadata["progress_log"] = log
	return cloneAnalysisRun(run), cloneAnyMap(progress), true
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
	run.Metadata = mergeAnalysisMetadata(run.Metadata, metadataFromAgentContext(response.Context))
	run.UpdatedAt = time.Now().UTC()
	if run.FirstCompletedAt == nil {
		run.FirstCompletedAt = &run.UpdatedAt
	}
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
	run.Metadata = mergeAnalysisMetadata(run.Metadata, metadataFromAgentContext(response.Context))
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

// AlertIDsNeedingAnalysis returns up to `limit` non-resolved, non-analyzing alerts
// that have no completed analysis run: alerts that never got a run (dropped by the
// fan-out / rate caps) and alerts whose latest run failed longer ago than
// retryCooldown. Completed and in-flight alerts are skipped, so backfill never
// re-runs a good RCA and does not hammer a just-failed one.
func (s *Store) AlertIDsNeedingAnalysis(limit int, retryCooldown time.Duration, now time.Time) []string {
	if limit <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	type runInfo struct {
		status  string
		updated time.Time
	}
	latest := map[string]runInfo{}
	for _, run := range s.analysisRuns {
		if run == nil || run.AlertID == "" {
			continue
		}
		if cur, ok := latest[run.AlertID]; !ok || run.UpdatedAt.After(cur.updated) {
			latest[run.AlertID] = runInfo{status: run.Status, updated: run.UpdatedAt}
		}
	}
	out := make([]string, 0, limit)
	for _, alert := range s.alerts {
		if alert == nil || alert.IsAnalyzing {
			continue
		}
		if incidentDeleted(s.incidents[alert.IncidentID]) {
			continue
		}
		if status(alert.Status) == "resolved" {
			continue
		}
		if info, ok := latest[alert.AlertID]; ok {
			if info.status == "complete" || info.status == "analyzing" {
				continue
			}
			// A recently failed run is left to cool down before we retry it.
			if retryCooldown > 0 && info.updated.After(now.Add(-retryCooldown)) {
				continue
			}
		}
		out = append(out, alert.AlertID)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *Store) AnalysisTarget(targetType string, targetID string) (Alert, string, string, string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch targetType {
	case "alert":
		alert := s.alerts[targetID]
		if alert == nil || incidentDeleted(s.incidents[alert.IncidentID]) {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*alert), alert.IncidentID, alert.AlertID, alert.ThreadTS, alert.AlarmTitle, true
	case "incident":
		incident := s.incidents[targetID]
		if incident == nil || incidentDeleted(incident) {
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

// BumpIncidentAnalysisSeq increments the incident's Slack analysis counter and
// returns the new value (1 = Initial Analysis, 2 = 2nd Analysis, ...).
func (s *Store) BumpIncidentAnalysisSeq(id string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incident == nil || incidentDeleted(incident) {
		return 0, false
	}
	incident.AnalysisSeq++
	s.persistIncidentLocked(incident)
	return incident.AnalysisSeq, true
}

// SetIncidentSlackThread stores the Slack root-message timestamp so later
// re-analyses reply into the same thread (survives restarts, unlike an
// in-memory map).
func (s *Store) SetIncidentSlackThread(id string, ts string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident := s.incidents[id]
	if incident == nil || incidentDeleted(incident) {
		return
	}
	incident.SlackThreadTS = ts
	s.persistIncidentLocked(incident)
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
		detail.SimilarRecentCount = s.similarRecentCountLocked(alertFromRecord(detail.Alerts[0]), id, time.Now().UTC().AddDate(0, 0, -7), nil)
	}
	detail.TokenUsage = s.latestTokenUsageLocked(id)
	return detail, true
}

func (s *Store) AlertDetail(id string) (*AlertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert := s.alerts[id]
	if alert == nil || incidentDeleted(s.incidents[alert.IncidentID]) {
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
	if err := validateStoredText("comment body", body, maxStoredCommentBodyBytes); err != nil {
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
	if err := validateStoredText("comment body", body, maxStoredCommentBodyBytes); err != nil {
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
