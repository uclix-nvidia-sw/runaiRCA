package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPIContractIsServedAndContainsKnowledgeLifecycle(t *testing.T) {
	server := NewServer()
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected OpenAPI endpoint to return 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("unexpected content type %q", got)
	}
	var spec struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &spec); err != nil {
		t.Fatalf("OpenAPI document is not valid JSON: %v", err)
	}
	if spec.OpenAPI != "3.0.3" {
		t.Fatalf("unexpected OpenAPI version %q", spec.OpenAPI)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("OpenAPI endpoint must remain readable by a GitBook origin, got CORS %q", got)
	}
	for _, path := range []string{
		"/api/v1/knowledge-candidates/{id}/decision",
		"/api/v1/knowledge-packages/{id}/retire",
		"/api/v1/knowledge/runtime-snapshot",
		"/api/v1/knowledge/probe-metrics",
	} {
		if _, ok := spec.Paths[path]; !ok {
			t.Fatalf("OpenAPI contract missing %s", path)
		}
	}
}

func TestScalarAPIDocsUsesSameOriginOpenAPIContract(t *testing.T) {
	server := NewServer()
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api-docs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected API docs to return 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("unexpected content type %q", got)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"@scalar/api-reference",
		"url: '/api/v1/openapi.json'",
		"hideClientButton: false",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Scalar API docs missing %q", want)
		}
	}
}
