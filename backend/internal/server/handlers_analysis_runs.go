package server

import (
	"net/http"
	"strings"
)

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
