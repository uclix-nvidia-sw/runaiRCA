# Operating Model

> **Lens:** How it behaves — what the system does, and the lines it won't cross.
> **In this doc:** supported signals · intake/analysis triggers · runtime status semantics · agent role contracts · RCA boundaries · degraded mode.

Run:AI RCA is read-only by default.

## Supported Signals

- Alertmanager webhooks
- Run:ai control plane metadata
- Kubernetes pod, workload, event, node, and manifest state
- Postgres RCA store, pgvector, connection, and write-path health
- Prometheus metrics
- Loki logs

## Intake And Analysis Triggers

Automatic RCA is webhook-driven. Alertmanager must route matching alerts to
Backend `POST /webhook/alertmanager`; receiving the same alert in Slack only
proves that the Slack receiver matched. It does not prove that the RCA webhook
receiver matched or that Alertmanager could reach the Backend service.

Every accepted webhook alert is stored, correlated into an incident, and then
starts an asynchronous Agent `/analyze` call. Operators can also create analysis
runs manually from incident analysis, comment/feedback reanalysis, or chat
requests that explicitly ask for a new analysis. When chat does not specify a
target incident or alert, Backend selects the latest non-resolved alert if one
exists. The Analysis Dashboard is backed by `/api/v1/analysis-runs`; if that
list is empty, no analysis trigger has reached the Backend yet.

## Runtime Status Semantics

Kubernetes `Running` and Agent `/healthz` confirm that processes are alive, but
they do not mean collector evidence has been produced. The Agents view marks a
collector `ok` only after recent RCA data contains at least one artifact from
that collector. If no artifact is attached yet, the UI shows `pending` even when
all pods are healthy.

Agent `/healthz` reports `nemo_runtime` as `enabled` or `fallback`.
`fallback` means the service will use deterministic in-process RCA synthesis.
`enabled` means `/analyze` will attempt the configured NeMo Agent Toolkit
workflow before falling back. It is not a chat-specific LLM readiness signal.

## Agent Role Contracts

- RunAI Agent uses the Run:ai API for workload, project, queue, quota, priority,
  and scheduling context. It does not run the `runai` CLI by default.
- Kubernetes Agent inspects workload pods/events, Run:ai control-plane pod
  health, namespace scans, node conditions, and Kubernetes scheduling blockers.
- Prometheus Agent inspects queue/project GPU metrics and pod or namespace
  resource signals.
- Loki Agent inspects workload logs plus Run:ai control-plane/backend logs from
  `runai` and `runai-backend` by default.
- Postgres Agent inspects RCA store connectivity, pgvector, embeddings,
  feedback, comments, and memory health.
- Store/Postgres ownership includes verifying the target database exists, the
  backend user can create/update RCA tables, and pgvector is installed plus
  enabled with `CREATE EXTENSION vector;` when true pgvector readiness is
  required. Without pgvector, the backend should remain healthy with JSONB
  sparse-vector memory fallback.
- Analysis Agent produces the KubeRCA-style dashboard RCA: root cause,
  confidence, impact, missing data, recommended manual actions, prevention, and
  evidence coverage.
- Chat Agent answers operator follow-up questions from the active RCA, alert
  analysis, evidence trail, feedback, and similar incident memory. In the
  current implementation, `/chat` is deterministic and context-grounded; it does
  not directly call the NeMo/LLM runtime. `ENABLE_NAT_RUNTIME=true` affects
  `/analyze` synthesis. If chat is opened from a dashboard page without attached
  incident or alert RCA content, Backend attaches dashboard and analysis-run
  state so Chat can report current alert counts, latest run state, agent
  timeout/failure warnings, database state, and runtime mode.

## RCA Boundaries

The system can:

- explain likely root cause
- list supporting evidence
- identify missing evidence
- recommend manual next steps
- compare to previous incidents

The system must not:

- delete workloads
- change queues or quotas
- restart pods
- mutate Kubernetes resources
- perform autonomous remediation

## Degraded Mode

Each collector reports `ok`, `partial`, or `unavailable`. The final RCA should
prefer transparent partial answers over pretending all integrations worked.
