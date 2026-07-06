# Improvement Plan

> **Lens:** Review follow-up - what changed now, what remains.
> **In this doc:** review score · shipped quick wins and features · measured eval results · remaining roadmap.

The mock review scored Run:AI RCA at **66.7/100**. The main gaps were not one
large missing system; they were the small pieces that make a tool trustworthy in
daily operations: CI coverage, license clarity, eval taxonomy drift, transient
LLM failure handling, unpinned external source, token cost visibility, and
incident lifecycle controls.

The review criteria were treated as:

- **Correctness and eval quality:** fixture labels must match the taxonomy, and
  changes must keep the RCA classifier measurable.
- **Reliability and operability:** transient LLM errors need bounded retry,
  backfill must not revive deleted incidents, and trash purge must be testable.
- **Observability and cost control:** LLM token usage should be visible from the
  agent through the backend and frontend.
- **Product workflow completeness:** operators need archive, delete, restore,
  recurrence, export, and a clear dashboard path.

## Implemented In This Pass

- Added GitHub Actions test coverage for backend, agent, and frontend.
- Added the Apache-2.0 root `LICENSE`.
- Updated eval fixtures to the current RCA taxonomy and removed the misleading
  `OOMKilled` token from the image-pull case.
- Added bounded LLM retry for 429, 5xx, and network-status failures.
- Pinned `runai-mcp` to commit `527b14087c35edf3467f5028fcc3793475976855`.
- Added LLM usage tracking from agent calls into backend analysis-run metadata
  and the incident diagnostics panel.
- Added incident archive, unarchive, soft delete, restore, permanent delete, and
  30-day trash retention with purge.
- Added active, archived, and trash views with row actions and SSE refreshes.
- Added recurrence stats for the dashboard and per-incident recent similar
  counts.
- Added Word export for incident RCA details, evidence, alerts, and similar
  incidents.
- Moved pagination controls to the center so the chat launcher no longer blocks
  them.

## Eval Results

After the fixture taxonomy update:

| Run | Result |
| --- | --- |
| `python -m eval.run_eval` | KG on, n=8, Top-1 8/8 (100%), Top-3 8/8 (100%), false assertions 0 |
| `python -m eval.run_eval --kg-off` | KG off, n=8, Top-1 8/8 (100%), Top-3 8/8 (100%), false assertions 0 |

The A/B currently shows parity on the small fixture set. Keep TypeDB enabled as
an optional path until a larger A3-style measurement shows a clear benefit.

## Remaining Roadmap

- Model differentiation by task type and confidence, rather than one model path
  for every step.
- KPI dashboard for mean time to RCA, recurrence trend, automation coverage, and
  operator feedback quality.
- Collector pluginization so Kubernetes, Prometheus, Loki, Run:ai, Postgres, and
  system evidence can be extended independently.
- Multitenancy boundaries for data access, incident views, and credentials.
- TypeDB default decision after a larger A3 remeasurement and KG-on/KG-off A/B.
- Split `App.tsx` into smaller feature modules once the dashboard surface
  stabilizes.
- Revisit whether `systemAgent` should be privileged by default.
- Slack thread cleanup on incident deletion or permanent purge.
