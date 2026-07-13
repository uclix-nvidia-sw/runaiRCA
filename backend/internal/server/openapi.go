package server

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the versioned HTTP contract served by every Backend instance.
// Keeping it beside the router lets CI assert the public paths before a release.
//
//go:embed openapi.json
var openAPISpec []byte

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(openAPISpec)
}
