# Architecture

> **Lens:** How it's built — the contract from Alertmanager webhook to a stored RCA.
> **In this doc:** runtime flow · the three services · feedback/memory loop · ontology knowledge graph · Slack notifications · evidence contract.

Run:AI RCA is organized around three runtime services: Backend, Agent, and
Frontend. The Backend can run with an in-memory fallback for local development,
but production-style deployments should provide Postgres through
`DATABASE_URL`. The API stores incidents, alerts, operator feedback, comments,
and similar-incident vectors without changing the UI contract.

The Agent's analysis is a multi-stage pipeline, not a single prompt — this doc
gives the service-level contract; the [RCA Pipeline](RCA-PIPELINE.md) doc walks
every stage, and the [Knowledge Base](KNOWLEDGE-BASE.md) doc covers the catalogs
and ontology it consults.

## Runtime Flow

1. Alertmanager sends `POST /webhook/alertmanager` to the Backend.
2. Backend normalizes each alert and derives Run:ai context from labels and
   annotations.
3. Backend correlates alerts into incidents using:
   `cluster + project + queue + namespace + workload`, then `cluster + node`,
   then Alertmanager `groupKey`.
4. Backend creates or updates the incident and alert records, and attaches
   pgvector-similar prior incidents + feedback hints.
5. Backend asynchronously calls Agent `POST /analyze` under an overall deadline.
6. The Agent **orchestrator** plans the investigation, then runs seven evidence
   collectors in parallel — Run:ai, Kubernetes, Prometheus, Loki, Postgres,
   System, Change — deepened by a central investigation loop and per-collector
   autonomous drill-down (each agent, read-only, own-domain tools only).
7. Signature matching (built-in alert / known issue / failure-mode symptom /
   NVIDIA XID, with a BM25 recall fallback) plus deterministic ranking (rules
   R1–R6) name the cause; a skeptical self-check may trigger one bounded
   re-analysis. The orchestrator consults the optional TypeDB ontology for node
   blast radius, prior same-alert incidents, and graph-derived remediation.
8. The Agent synthesizes a single RCA — Problem → Root Cause → Recommended
   Actions → Appendix — plus an `artifacts` list preserving each agent's real
   query, summary, highlighted findings, confidence, and status.
9. Backend stores the analysis response, broadcasts SSE updates, and posts an
   incident summary to Slack on completion (first analysis opens a thread;
   operator re-analyses reply into it).
10. Backend writes analyzed incidents into `incident_embeddings` and includes
   similar prior incidents plus feedback hints in future Agent requests.
11. Frontend renders the final RCA and the agent evidence trail on the same
   Incident or Alert detail page.

## Services

### Agent

The Agent is a FastAPI service backed by one in-process NeMo Agent Toolkit
workflow, `agent/configs/runai_rca_engine.yml`. The RCA pipeline stages are NAT
functions, and the `runai_rca_pipeline` controller workflow owns the sequence.

The Python service builds the NAT workflow once at startup. If the engine cannot
start or a per-request engine run fails, the same pipeline stages run directly in
process so local development and tests still work before external Run:ai,
Kubernetes, Postgres, Prometheus, Loki, or LLM credentials exist.

Every LLM stage (planner refine, investigation loop, per-collector drill-down,
self-check, Korean synthesis) is optional and best-effort: with no LLM, or on any
failure, the orchestrator degrades to its deterministic path and still returns a
report. The whole run is bounded by `ANALYSIS_DEADLINE_SECONDS` (default 1500s);
the backend's `AGENT_REQUEST_TIMEOUT_SECONDS` (1560s) stays above it so a
graceful degraded report is never lost. See [RCA Pipeline](RCA-PIPELINE.md).

### Backend

The Backend is a Go HTTP API. It uses Postgres when `DATABASE_URL` or
`POSTGRES_DSN` is configured, and keeps the in-memory fallback for local smoke
tests where no database is available.

It owns:

- Alertmanager webhook intake
- Incident and alert correlation
- Agent request lifecycle (async run, deadline, stale-run reaping)
- Postgres persistence for incidents, alerts, embeddings, feedback, comments, and analysis runs
- **pgvector similarity** — the `incident_embeddings` cosine search (HNSW, JSONB fallback) that finds prior incidents; results are passed into each Agent request as `similar_incidents` + `feedback_hints`
- KubeRCA-style `/api/v1/embeddings/search` similar-incident API
- SSE event fanout
- Slack notification on analysis completion — incident summary + Recommended Action + Open-Incident link, threaded per incident (see [Slack Notifications](#slack-notifications))
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

An optional TypeDB knowledge graph (`typedb.enabled`, default **on** in Helm)
gives the **orchestrator** relational reasoning that pgvector similarity and
label overlap cannot express. It is a knowledge resource the orchestrator
consults around synthesis time — not a parallel evidence collector, and not a
separate agent. Full detail: [Knowledge Base](KNOWLEDGE-BASE.md).

- **Schema** (`agent/ontology/schema.tql`): typed entities (cluster, node, pod,
  workload, project, queue, namespace, alert, incident, symptom, root cause,
  `control_plane_component`, `xid_error`, ...) and relations (`runs_on`,
  `submitted_to`, `grouped_into`, `indicates`, `depends_on`, `leads_to`, ...),
  with 15 root-cause families modeled as `sub` types.
- **Ingestion** (`agent/ontology/ingest.py`, CronJob): a deterministic projection
  of resolved `incidents`/`alerts` into the graph after a grace window. Optionally
  review-gated (`requireReview`) and can promote operator-confirmed RCAs into
  reusable knowledge (`--promote-knowledge`).
- **Enrichment** (`agent/app/services/kg_enrichment.py`): the orchestrator queries
  the graph for facts the flat collectors miss — node blast radius, prior
  same-alert incidents with their stored RCA (`enrich`), and graph-derived
  family/XID remediation with root-cause chains (`graph_remediation`). Degrades to
  an empty context when TypeDB is disabled/unreachable; never raises.
- **Ranking** (`agent/app/services/root_cause_ranking.py`) scores failure families
  (rules R1-R6) and **signature promotion** headlines the most specific match.
  This ranks *causes*, not similarity — pgvector (owned by the backend) still owns
  "which past incidents are similar".

Verify what the graph holds with `python -m ontology.query` or TypeDB Studio —
see [Knowledge Base → Querying the graph](KNOWLEDGE-BASE.md#querying-the-graph).
TypeDB runs as a single-node StatefulSet
(`charts/runai-rca/templates/typedb.yaml`); Community Edition is single-node, so
HA/clustering would require the paid Enterprise tier.

## Slack Notifications

On analysis-run completion the Backend posts a concise incident summary to one
Slack channel (`backend/internal/server/slack.go`). It is the natural owner: it
holds the run lifecycle, the SSE broadcast, and the incident's Slack thread.

**Delivery rules** (incident-level, not per-alert):

- The **first** completed analysis of an incident posts a root channel message
  (*"Initial Analysis"*) and stores its `thread_ts` on the incident row so
  threading survives restarts.
- Later **operator-driven** re-analyses (`manual`/`comment`/`feedback`/`chat`)
  reply into that thread (*"2nd Analysis"*, *"3rd Analysis"*, …), tracked by the
  incident's `analysis_seq`.
- Follow-up **auto/backfill** completions and **failed** runs never reach Slack —
  raw alerts already arrive via other channels and the dashboard keeps the full
  per-alert history.

Each message carries a severity color bar, the **Root Cause** summary, the first
**Recommended Action** lines, key fields (namespace/node/severity/alert count),
and — when `DASHBOARD_URL` is set — an **Open Incident** deep-link button. The
long-form report stays in the UI; Slack is the notification, not the report.

A **bot token** (`SLACK_BOT_TOKEN` + `SLACK_CHANNEL_ID`), not an incoming webhook,
is required: `chat.postMessage` returns the message `ts` needed to thread
replies. Delivery is fire-and-forget — errors are logged and never affect run
persistence.

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
      "agent": "kubernetes",
      "source": "kubernetes",
      "type": "adhoc_query",
      "status": "ok",
      "confidence": "medium",
      "title": "파드 조회",
      "query": "kubectl get pods train-0 -n runai",
      "summary": "signals: CrashLoopBackOff, OOMKilled",
      "highlights": ["CrashLoopBackOff", "OOMKilled"]
    }
  ]
}
```

`title` is the human card name, `query` is the *real* command an operator can
replay, and `highlights` are problem signals the UI marks in red so the finding
reads before the boilerplate — see
[RCA Pipeline → Evidence presentation](RCA-PIPELINE.md#evidence-presentation).

The UI must not route operators to separate agent pages. It may use accordions
or tabs inside the detail page, but all evidence stays in context.
