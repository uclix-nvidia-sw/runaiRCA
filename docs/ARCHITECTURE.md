# Architecture

Run:AI RCA is organized around three runtime services: Backend, Agent, and
Frontend. The MVP keeps state in the Backend memory store so the project can be
run quickly; the API and data shapes are designed to move to PostgreSQL and
pgvector without changing the UI contract.

## Runtime Flow

1. Alertmanager sends `POST /webhook/alertmanager` to the Backend.
2. Backend normalizes each alert and derives Run:ai context from labels and
   annotations.
3. Backend correlates alerts into incidents using:
   `cluster + project + queue + namespace + workload`, then `cluster + node`,
   then Alertmanager `groupKey`.
4. Backend creates or updates the incident and alert records.
5. Backend asynchronously calls Agent `POST /analyze`.
6. Agent runs component evidence collectors in parallel:
   Run:ai, Kubernetes, Postgres, Prometheus, Loki.
7. Agent synthesizes a single RCA plus an `artifacts` list that preserves each
   agent's query, summary, confidence, and status.
8. Backend stores the analysis response and broadcasts SSE updates.
9. Frontend renders the final RCA and the agent evidence trail on the same
   Incident or Alert detail page.

## Services

### Agent

The Agent is a FastAPI service with a NeMo Agent Toolkit workflow configuration
under `agent/configs/runai_rca_workflow.yml`.

The Python service includes a deterministic fallback orchestrator so local
development and tests can run before external Run:ai, Kubernetes, Postgres,
Prometheus, Loki, or NIM credentials exist. When `ENABLE_NAT_RUNTIME=true`, the
`NemoWorkflowRunner` can delegate to the `nat` CLI with the configured workflow.

### Backend

The Backend is a Go HTTP API. The MVP uses the Go standard library to avoid
external dependency bootstrapping while the product shape stabilizes.

It owns:

- Alertmanager webhook intake
- Incident and alert correlation
- Agent request lifecycle
- SSE event fanout
- Chat proxy
- Unified API response shape for the frontend

### Frontend

The Frontend is a React app that starts on the operational dashboard. It does
not include a marketing-style landing page.

The key interaction is the Unified RCA Workspace:

- Summary and recommended action at the top
- Impact, evidence, missing data, and prevention in the middle
- Agent Evidence Trail at the bottom of the same page

## Evidence Contract

Agent responses contain both the synthesized RCA and source-level artifacts.

```json
{
  "analysis_summary": "GPU allocation delayed by queue saturation",
  "analysis_detail": "## Root Cause ...",
  "capabilities": {
    "runai": "ok",
    "kubernetes": "partial",
    "postgres": "ok",
    "prometheus": "unavailable",
    "loki": "ok"
  },
  "artifacts": [
    {
      "agent": "runai",
      "source": "runai",
      "type": "workload_context",
      "status": "ok",
      "confidence": "medium",
      "query": "workload lookup",
      "summary": "Workload is pending in project vision queue gpu-a."
    }
  ]
}
```

The UI must not route operators to separate agent pages. It may use accordions
or tabs inside the detail page, but all evidence stays in context.
