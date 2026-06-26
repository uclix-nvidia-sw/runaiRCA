# Operating Model

Run:AI RCA is read-only by default.

## Supported Signals

- Alertmanager webhooks
- Run:ai control plane metadata
- Kubernetes pod, workload, event, node, and manifest state
- Postgres RCA store, pgvector, connection, and write-path health
- Prometheus metrics
- Loki logs

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
- Analysis Agent produces the KubeRCA-style dashboard RCA: root cause,
  confidence, impact, missing data, recommended manual actions, prevention, and
  evidence coverage.
- Chat Agent answers operator follow-up questions from the active RCA, alert
  analysis, evidence trail, feedback, and similar incident memory.

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
