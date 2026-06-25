# Operating Model

Run:AI RCA is read-only by default.

## Supported Signals

- Alertmanager webhooks
- Run:ai control plane metadata
- Kubernetes pod, workload, event, node, and manifest state
- Postgres RCA store, pgvector, connection, and write-path health
- Prometheus metrics
- Loki logs

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
