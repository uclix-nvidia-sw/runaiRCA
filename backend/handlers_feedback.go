package main

import (
	"net/http"
	"strings"
)

func (s *Server) handleFeedback(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
) {
	var req FeedbackRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	if strings.TrimSpace(req.Author) == "" {
		req.Author = r.URL.Query().Get("feedback_author")
	}
	summary, ok, err := s.store.AddFeedback(targetType, targetID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	incidentID, alertID, _ := s.store.TargetIDs(targetType, targetID)
	s.hub.Broadcast(feedbackUpdatedEvent(summary, incidentID, alertID))
	if strings.TrimSpace(req.Comment) != "" {
		s.startAnalysisRun(targetType, targetID, "feedback", req.Comment)
	}
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleComment(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
) {
	var req CommentRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	summary, ok, err := s.store.AddComment(targetType, targetID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "target not found")
		return
	}
	incidentID, alertID, _ := s.store.TargetIDs(targetType, targetID)
	s.hub.Broadcast(feedbackUpdatedEvent(summary, incidentID, alertID))
	s.startAnalysisRun(targetType, targetID, "comment", req.Body)
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleCommentAction(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	parts []string,
) {
	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		s.handleComment(w, r, targetType, targetID)
	case len(parts) == 3 && r.Method == http.MethodPut:
		s.handleCommentUpdate(w, r, targetType, targetID, parts[2])
	case len(parts) == 3 && r.Method == http.MethodDelete:
		s.handleCommentDelete(w, r, targetType, targetID, parts[2])
	default:
		writeError(w, http.StatusNotFound, "unknown comment action")
	}
}

func (s *Server) handleCommentUpdate(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	commentID string,
) {
	var req CommentRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	summary, ok, err := s.store.UpdateComment(targetType, targetID, commentID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "comment not found")
		return
	}
	incidentID, alertID, _ := s.store.TargetIDs(targetType, targetID)
	s.hub.Broadcast(feedbackUpdatedEvent(summary, incidentID, alertID))
	s.startAnalysisRun(targetType, targetID, "comment", req.Body)
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleCommentDelete(
	w http.ResponseWriter,
	r *http.Request,
	targetType string,
	targetID string,
	commentID string,
) {
	summary, ok := s.store.DeleteComment(targetType, targetID, commentID)
	if !ok {
		writeError(w, http.StatusNotFound, "comment not found")
		return
	}
	incidentID, alertID, _ := s.store.TargetIDs(targetType, targetID)
	s.hub.Broadcast(feedbackUpdatedEvent(summary, incidentID, alertID))
	writeJSON(w, http.StatusOK, envelope(summary))
}

func (s *Server) handleEmbeddingSearch(w http.ResponseWriter, r *http.Request) {
	var req EmbeddingSearchRequest
	if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeError(w, http.StatusBadRequest, "query is required")
		return
	}
	if len(query) > maxEmbeddingQueryBytes {
		writeError(w, http.StatusBadRequest, "query is too long")
		return
	}
	results := s.store.SearchIncidentMemory(query, req.Limit)
	writeJSON(w, http.StatusOK, envelope(EmbeddingSearchResponse{
		Model:   "local-term-frequency",
		Results: results,
	}))
}
