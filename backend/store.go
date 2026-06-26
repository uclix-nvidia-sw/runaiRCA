package main

import (
	"database/sql"
	"errors"
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
	similaritySearchJSONB     = "jsonb_sparse_vectors"
	similaritySearchMemory    = "in_memory_sparse_vectors"
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
	memories       map[string]*IncidentMemory
	feedback       map[string]*FeedbackRecord
	comments       map[string]*CommentRecord
	analysisRuns   map[string]*AnalysisRun
	db             *sql.DB
	dbReady        bool
	pgvectorReady  bool
}

func NewStore() *Store {
	return &Store{
		incidents:     make(map[string]*Incident),
		incidentByKey: make(map[string]string),
		alerts:        make(map[string]*AlertRecord),
		alertByFinger: make(map[string]string),
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
	if s.dbReady && !s.pgvectorReady {
		health["fallback"] = vectorFallbackJSONB
	}
	return health
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
		incidentID = nextID("INC", s.incidentSeq.Add(1))
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
		alertID = nextID("ALR", s.alertSeq.Add(1))
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
	s.persistIncidentLocked(incident)
	s.persistAlertLocked(record)
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
		copied := cloneAlert(alert)
		copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, 5)
		copied.Feedback = s.feedbackSummaryLocked("alert", alert.AlertID)
		items = append(items, *copied)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FiredAt.After(items[j].FiredAt) })
	return items
}

func (s *Store) ListAnalysisRuns() []AnalysisRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AnalysisRun, 0, len(s.analysisRuns))
	for _, run := range s.analysisRuns {
		items = append(items, cloneAnalysisRun(run))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items
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
	now := time.Now().UTC()
	run := &AnalysisRun{
		RunID:        nextID("ANL", s.analysisRunSeq.Add(1)),
		Source:       first(source, "manual"),
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
	s.analysisRuns[run.RunID] = run
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run)
}

func (s *Store) CompleteAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
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
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run), true
}

func (s *Store) FailAnalysisRun(runID string, response AgentAnalysisResponse) (AnalysisRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.analysisRuns[runID]
	if run == nil {
		return AnalysisRun{}, false
	}
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
	s.persistAnalysisRunLocked(run)
	return cloneAnalysisRun(run), true
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
		for _, alert := range s.alerts {
			if alert.IncidentID != targetID {
				continue
			}
			if selected == nil || alert.FiredAt.After(selected.FiredAt) {
				selected = alert
			}
		}
		if selected == nil {
			return Alert{}, "", "", "", "", false
		}
		return alertFromRecord(*selected), incident.IncidentID, selected.AlertID, selected.ThreadTS, incident.Title, true
	default:
		return Alert{}, "", "", "", "", false
	}
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
		copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, 5)
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
	detail.Feedback = s.feedbackSummaryLocked("incident", id)
	if len(detail.Alerts) > 0 {
		detail.SimilarIncidents = s.similarIncidentsLocked(
			alertFromRecord(detail.Alerts[0]),
			id,
			5,
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
	copied.SimilarIncidents = s.similarIncidentsLocked(alertFromRecord(*copied), alert.IncidentID, 5)
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
		Comment:    strings.TrimSpace(req.Comment),
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
		Author:     strings.TrimSpace(req.Author),
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
	if author := strings.TrimSpace(req.Author); author != "" {
		comment.Author = author
	}
	s.persistCommentUpdateLocked(comment)
	return s.feedbackSummaryLocked(targetType, targetID), true, nil
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
