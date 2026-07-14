package server

import (
	"net/http"
	"strings"
)

func (s *Server) handleAnalysisRunEvaluation(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/analysis-runs/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "evaluation" {
		writeError(w, http.StatusNotFound, "unknown analysis run evaluation")
		return
	}
	runID := parts[0]
	switch r.Method {
	case http.MethodGet:
		view, ok := s.store.EvaluationForRun(runID, r.URL.Query().Get("author"))
		if !ok {
			writeError(w, http.StatusNotFound, "analysis run not found")
			return
		}
		writeJSON(w, http.StatusOK, envelope(view))
	case http.MethodPut:
		var req EvaluationReviewRequest
		if status, err := decodeJSONBody(w, r, &req, maxJSONBodyBytes); err != nil {
			writeError(w, status, err.Error())
			return
		}
		if req.Author == "" {
			req.Author = r.URL.Query().Get("author")
		}
		var allowedFamilies []string
		if strings.TrimSpace(req.ExpectedFamily) != "" && strings.TrimSpace(req.CaseType) != "novel" {
			catalog, err := s.fetchRootCauseFamilyCatalog(r.Context())
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "root-cause family catalog unavailable")
				return
			}
			allowedFamilies = catalog.Families
		}
		review, ok, err := s.store.UpsertEvaluationReview(runID, req, allowedFamilies)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "analysis run not found")
			return
		}
		writeJSON(w, http.StatusOK, envelope(review))
	default:
		writeError(w, http.StatusNotFound, "unknown analysis run evaluation")
	}
}

func (s *Server) handleAnalysisRunAction(w http.ResponseWriter, r *http.Request) {
	rest := pathPart(r.URL.Path, "/api/v1/analysis-runs/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "progress" {
		writeError(w, http.StatusNotFound, "unknown analysis run action")
		return
	}

	var req map[string]any
	if status, err := decodeJSONBody(w, r, &req, maxProgressBodyBytes); err != nil {
		writeError(w, status, err.Error())
		return
	}
	if len(req) == 0 {
		writeError(w, http.StatusBadRequest, "progress payload is required")
		return
	}

	run, progress, ok := s.store.AppendAnalysisProgress(parts[0], req)
	if !ok {
		writeError(w, http.StatusConflict, "analysis run is not accepting progress")
		return
	}
	s.hub.Broadcast(analysisProgressEvent(run, progress))
	writeJSON(w, http.StatusOK, envelope(progress))
}
