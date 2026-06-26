# Run:AI RCA Frontend

React dashboard for Run:AI RCA.

The UI is white-first with NVIDIA green accents. The Analysis Dashboard shows
incident/alert trends, MTTR, severity and quality distribution, top Run:AI
targets, missing evidence, feedback, similar incidents, and per-agent coverage.

Agent evidence is also shown inside the Incident or Alert detail page.

The detail workspace also shows similar incidents, feedback votes, and markdown
comments with write/preview, edit, and delete controls.

RCA chat is available as a floating or docked context-aware assistant across
dashboards and detail workspaces.

## Run

```bash
npm install
npm run dev
```

Set `VITE_API_BASE_URL=http://localhost:8080` when the backend is on a different
origin.

Mock dashboard samples are enabled by default only in Vite development mode.
Override with `VITE_ENABLE_MOCK_DATA=false` or the runtime
`window.__RUNAI_RCA_CONFIG__.enableMockData` value. In Helm/static deployments,
mock samples default to disabled. When enabled, mock samples are shown only when
live incident and alert lists are empty, or when the local dev backend is
unavailable. Optional analysis-run API failures never hide live incident or
alert data.
