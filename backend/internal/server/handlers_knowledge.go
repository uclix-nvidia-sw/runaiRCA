package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var errKnowledgeValidatorRejected = errors.New("knowledge validator rejected candidate")

const maxRootCauseFamilyCatalogBytes = 64 << 10

type RootCauseFamilyCatalog struct {
	Families []string `json:"families"`
}

func (s *Server) handleKnowledge(w http.ResponseWriter, r *http.Request) {
	prefix := ""
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/knowledge-candidates"):
		prefix = "/api/v1/knowledge-candidates"
	case strings.HasPrefix(r.URL.Path, "/api/v1/knowledge-packages"):
		prefix = "/api/v1/knowledge-packages"
	default:
		writeError(w, http.StatusNotFound, "unknown knowledge endpoint")
		return
	}
	rest := strings.Trim(pathPart(r.URL.Path, prefix), "/")
	parts := strings.Split(rest, "/")
	if prefix == "/api/v1/knowledge-candidates" {
		if rest == "" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, envelope(s.store.ListKnowledgeCandidates(strings.TrimSpace(r.URL.Query().Get("status")))))
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			if c, ok := s.store.KnowledgeCandidate(parts[0]); ok {
				writeJSON(w, http.StatusOK, envelope(c))
			} else {
				writeError(w, http.StatusNotFound, "knowledge candidate not found")
			}
			return
		}
		if len(parts) == 2 && parts[1] == "decision" && r.Method == http.MethodPost {
			s.handleKnowledgeCandidateDecision(w, r, parts[0])
			return
		}
	}
	if prefix == "/api/v1/knowledge-packages" {
		if rest == "" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, envelope(s.store.ListKnowledgePackages(strings.EqualFold(r.URL.Query().Get("include_retired"), "true"))))
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			if p, ok := s.store.KnowledgePackage(parts[0]); ok {
				writeJSON(w, http.StatusOK, envelope(p))
			} else {
				writeError(w, http.StatusNotFound, "knowledge package not found")
			}
			return
		}
		if len(parts) == 2 && parts[1] == "retire" && r.Method == http.MethodPost {
			s.handleKnowledgePackageRetirement(w, r, parts[0])
			return
		}
	}
	writeError(w, http.StatusNotFound, "unknown knowledge endpoint")
}

func (s *Server) handleKnowledgeRuntimeSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot := s.store.KnowledgeRuntimeSnapshot()
	etag := `"` + snapshot.Revision + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleProbeMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope(s.store.ProbeMetrics()))
}

func (s *Server) handleRootCauseFamilies(w http.ResponseWriter, r *http.Request) {
	catalog, err := s.fetchRootCauseFamilyCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "root-cause family catalog unavailable")
		return
	}
	writeJSON(w, http.StatusOK, envelope(catalog))
}

func (s *Server) fetchRootCauseFamilyCatalog(parent context.Context) (RootCauseFamilyCatalog, error) {
	if strings.TrimSpace(s.agentURL) == "" || s.client == nil {
		return RootCauseFamilyCatalog{}, errors.New("agent is not configured")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.agentURL, "/")+"/knowledge/families", nil)
	if err != nil {
		return RootCauseFamilyCatalog{}, err
	}
	response, err := s.client.Do(req)
	if err != nil {
		return RootCauseFamilyCatalog{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return RootCauseFamilyCatalog{}, errors.New("agent rejected family catalog request")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRootCauseFamilyCatalogBytes+1))
	if err != nil {
		return RootCauseFamilyCatalog{}, err
	}
	if len(body) > maxRootCauseFamilyCatalogBytes {
		return RootCauseFamilyCatalog{}, errors.New("family catalog response is too large")
	}
	var catalog RootCauseFamilyCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return RootCauseFamilyCatalog{}, err
	}
	seen := make(map[string]struct{}, len(catalog.Families))
	for index, family := range catalog.Families {
		family = strings.TrimSpace(family)
		if family == "" {
			return RootCauseFamilyCatalog{}, errors.New("family catalog contains an empty family")
		}
		if _, duplicate := seen[family]; duplicate {
			return RootCauseFamilyCatalog{}, errors.New("family catalog contains duplicate families")
		}
		seen[family] = struct{}{}
		catalog.Families[index] = family
	}
	if len(catalog.Families) == 0 {
		return RootCauseFamilyCatalog{}, errors.New("family catalog is empty")
	}
	return catalog, nil
}

type knowledgeDecisionPayload struct {
	KnowledgeDecisionRequest
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

func decodeKnowledgeDecision(w http.ResponseWriter, r *http.Request) (knowledgeDecisionPayload, bool) {
	var request knowledgeDecisionPayload
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid knowledge decision payload")
		return knowledgeDecisionPayload{}, false
	}
	if request.Note == "" {
		request.Note = request.Reason
	}
	return request, true
}

func (s *Server) handleKnowledgeCandidateDecision(w http.ResponseWriter, r *http.Request, id string) {
	request, ok := decodeKnowledgeDecision(w, r)
	if !ok {
		return
	}
	switch request.Action {
	case "approve", "shadow":
		if err := s.validateKnowledgeCandidate(id); err != nil {
			if errors.Is(err, errKnowledgeValidatorRejected) {
				if _, transitionErr := s.store.FailKnowledgeCandidateValidation(id); transitionErr != nil {
					writeError(w, http.StatusServiceUnavailable, "could not persist knowledge validation failure")
					return
				}
				writeError(w, http.StatusUnprocessableEntity, "knowledge validator rejected candidate")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "knowledge validator unavailable or rejected candidate")
			return
		}
		var candidate KnowledgeCandidate
		var pkg KnowledgePackage
		var err error
		if request.Action == "shadow" {
			candidate, pkg, err = s.store.ShadowKnowledgeCandidate(id, request.KnowledgeDecisionRequest)
		} else {
			candidate, pkg, err = s.store.ApproveKnowledgeCandidate(id, request.KnowledgeDecisionRequest)
		}
		if err != nil {
			knowledgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope(map[string]any{"candidate": candidate, "package": pkg}))
	case "activate":
		candidate, pkg, err := s.store.ActivateShadowKnowledgeCandidate(id, request.KnowledgeDecisionRequest)
		if err != nil {
			knowledgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope(map[string]any{"candidate": candidate, "package": pkg}))
	case "reject":
		if candidate, ok := s.store.KnowledgeCandidate(id); ok && candidate.Status == knowledgeCandidateShadow {
			candidate, pkg, err := s.store.RejectShadowKnowledgeCandidate(id, request.KnowledgeDecisionRequest)
			if err != nil {
				knowledgeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, envelope(map[string]any{"candidate": candidate, "package": pkg}))
			return
		}
		candidate, err := s.store.RejectKnowledgeCandidate(id, request.KnowledgeDecisionRequest)
		if err != nil {
			knowledgeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, envelope(candidate))
	default:
		writeError(w, http.StatusBadRequest, "decision action must be approve, shadow, activate, or reject")
	}
}

// validateKnowledgeCandidate asks the Agent to validate the exact compiled
// runtime shape before publishing it. It never sends case snapshots, raw
// artifacts, evidence excerpts, queries, or logs. Candidate generation remains
// local and does not depend on this service; only promotion is gated.
func (s *Server) validateKnowledgeCandidate(id string) error {
	candidate, ok := s.store.KnowledgeCandidate(id)
	if !ok {
		return errors.New("candidate not found")
	}
	compiled, _ := candidate.Payload["compiled"].(map[string]any)
	if len(compiled) == 0 {
		return errors.New("candidate has no compiled payload")
	}
	base := strings.TrimRight(s.knowledgeValidatorURL, "/")
	if base == "" || s.client == nil {
		return errors.New("validator is not configured")
	}
	// Match the Agent's runtime registry contract exactly. This is deliberately
	// a one-package snapshot containing only compiled knowledge, never a Case
	// snapshot, candidate payload, trace, query, or artifact.
	body := mustJSON(map[string]any{
		"revision": "validation:" + candidate.ContentHash,
		"packages": []any{map[string]any{
			"package_id": candidate.CandidateID,
			"status":     "active",
			"compiled":   compiled,
		}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/knowledge/validate", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return errors.New("validator unavailable")
	}
	var result struct {
		Valid *bool `json:"valid"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if result.Valid == nil {
		return errors.New("validator returned invalid response")
	}
	if !*result.Valid {
		return errKnowledgeValidatorRejected
	}
	return nil
}

func (s *Server) handleKnowledgePackageRetirement(w http.ResponseWriter, r *http.Request, id string) {
	request, ok := decodeKnowledgeDecision(w, r)
	if !ok {
		return
	}
	pkg, err := s.store.RetireKnowledgePackage(id, request.KnowledgeDecisionRequest)
	if err != nil {
		knowledgeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope(pkg))
}

func knowledgeError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "not found") {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if strings.Contains(err.Error(), "persist") {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeError(w, http.StatusConflict, err.Error())
}
