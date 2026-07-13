package server

import "net/http"

const scalarReferenceHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Run:ai RCA API Reference</title>
    <style>html,body,#app{height:100%;margin:0}</style>
  </head>
  <body>
    <div id="app"></div>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
    <script>
      Scalar.createApiReference('#app', {
        url: '/api/v1/openapi.json',
        pageTitle: 'Run:ai RCA API Reference',
        theme: 'purple',
        layout: 'modern',
        hideClientButton: false,
        hideDownloadButton: false
      })
    </script>
  </body>
</html>`

func (s *Server) handleAPIDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(scalarReferenceHTML))
}
