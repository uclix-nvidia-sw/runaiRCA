# Architecture

Run:AI RCA is organized around three runtime services: Backend, Agent, and
Frontend. The Backend can run with an in-memory fallback for local development,
but production-style deployments should provide Postgres through
`DATABASE_URL`. The API stores incidents, alerts, operator feedback, comments,
and similar-incident vectors without changing the UI contract.

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
7. The analysis/synthesis step consults the optional TypeDB ontology knowledge
   base once (node blast radius and prior same-alert incidents), and a
   deterministic root-cause ranking scores the five failure families
   (node/kubelet pressure, scheduling/quota exhaustion, control-plane error,
   workload/image startup failure, insufficient evidence) using rules R1-R6,
   never naming a cause without a corroborating source.
8. Agent synthesizes a single RCA — grounded in the collected evidence, the
   ranked candidates, and the knowledge-base facts — plus an `artifacts` list
   that preserves each agent's query, summary, confidence, and status.
9. Backend stores the analysis response and broadcasts SSE updates.
10. Backend writes analyzed incidents into `incident_embeddings` and includes
   similar prior incidents plus feedback hints in future Agent requests.
11. Frontend renders the final RCA and the agent evidence trail on the same
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

The Backend is a Go HTTP API. It uses Postgres when `DATABASE_URL` or
`POSTGRES_DSN` is configured, and keeps the in-memory fallback for local smoke
tests where no database is available.

It owns:

- Alertmanager webhook intake
- Incident and alert correlation
- Agent request lifecycle
- Postgres persistence for incidents, alerts, embeddings, feedback, comments, and analysis runs
- KubeRCA-style `/api/v1/embeddings/search` similar-incident API
- SSE event fanout
- Chat proxy
- Unified API response shape for the frontend

### Frontend

The Frontend is a React app that starts on the operational dashboard. It does
not include a marketing-style landing page.

The key interaction is the Unified RCA Workspace:

- Summary and recommended action at the top
- Similar incidents, operator votes/comments, impact, missing data, and prevention in the middle
- Agent Evidence Trail at the bottom of the same page

## Feedback And Memory Loop

1. When an analysis completes, the Backend creates or updates an
   `incident_embeddings` row with the incident text, labels, and sparse text
   vector.
2. Operators can vote up/down and leave markdown comments on either an incident
   or alert. These are stored in `rca_feedback` and `rca_comments`.
3. New alerts are compared against prior incident vectors. The top matches are
   attached to the detail response and sent to the Agent as
   `similar_incidents`.
4. Feedback counts and comments from similar incidents are converted into
   `feedback_hints`, so the Agent can reuse accepted RCA patterns and avoid
   repeating rejected ones.
5. New operator comments and chat messages that explicitly ask for analysis
   create `analysis_runs`. Each run is processed by the Agent independently and
   appears as its own item in the Analysis Dashboard.

## Ontology Knowledge Graph

An optional TypeDB knowledge graph (`typedb.enabled`, default off) gives the
final analysis/synthesis step relational reasoning that pgvector similarity and
label overlap cannot express. It is a knowledge resource consulted once at
synthesis time — not a parallel evidence collector.

- **Schema** (`agent/ontology/schema.tql`): typed entities (cluster, node, GPU,
  pod, workload, project, queue, namespace, alert, incident, symptom, root
  cause, ...) and relations (`pod runsOn node`,
  `workload submittedToQueue queue`, `incident hasSymptom symptom`, ...), with
  the five root-cause families modeled as `sub` types.
- **Ingestion** (`agent/ontology/ingest.py`): a deterministic, review-gated
  projection of the existing `incidents`/`alerts` Postgres rows into the graph.
  Only incidents an operator has reviewed (an up-vote or a comment) are
  committed, so the graph is not poisoned by unverified auto-analysis.
- **Enrichment** (`agent/app/services/kg_enrichment.py`): the analysis/synthesis
  step queries the graph once for facts the flat collectors miss — node blast
  radius (how many workloads share the alerting node) and prior incidents that
  fired the same alert, with their stored RCA. Degrades to an empty context when
  TypeDB is disabled or unreachable; never raises into the analysis path.
- **Ranking** (`agent/app/services/root_cause_ranking.py`): scores the five
  failure families for the current incident (rules R1-R6). This ranks *causes*,
  not similarity — pgvector still owns "which past incidents are similar".

TypeDB runs as a single-node StatefulSet
(`charts/runai-rca/templates/typedb.yaml`); Community Edition is single-node, so
HA/clustering would require the paid Enterprise tier.

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
