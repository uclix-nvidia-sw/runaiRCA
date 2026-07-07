# Improvement Plan

> **Lens:** Review follow-up - what changed now, what remains.
> **In this doc:** review score · shipped quick wins and features · measured eval results · remaining roadmap.

The first mock review scored Run:AI RCA at **66.7/100**; the follow-up review
after the first fix pass scored **72.6/100**. The remaining gaps were not one
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
- Added stage-specific LLM model routing, missing-usage accounting, estimated
  LLM spend, token budgets, and `/api/v1/stats/llm-spend`.
- Added MTTR/time-to-RCA KPI stats with first-completion baselines and frontend
  widgets.
- Expanded eval fixtures to 23 gated cases plus a holdout set, added real-data
  fixture export tooling, and kept KG on/off A/B visible.
- Externalized collector registration and root-cause family catalogs while
  keeping security-sensitive tool boundaries in code.
- Added backend/agent/frontend live analysis progress: `analysis.progress` SSE,
  agent hypothesis ledger updates, and a workspace thought-process timeline.
- Split the frontend app root into hooks, dashboard components, workspace
  components, common controls, and shared utilities.
- Kept multitenancy out of the current roadmap because this product is deployed
  per cluster; cross-tenant data boundaries would add complexity without a clear
  operating benefit.
- Kept the privileged system agent and TypeDB defaults documented as
  security-sensitive choices: acceptable for the current PoC/default chart, but
  production installs should review RBAC, credentials, and network exposure.

## Eval Results

After the expanded fixture gate:

| Run | Result |
| --- | --- |
| `python -m eval.run_eval --min-top1 0.8` | KG on, n=23, Top-1 23/23 (100%), Top-3 23/23 (100%), false assertions 0 |
| `python -m eval.run_eval --kg-off --min-top1 0.8` | KG off A/B gate; record alongside KG-on results when changing family rules or TypeDB weighting |

The gated set now blocks regressions. The holdout set is intentionally
report-only so it can expose weak spots without making every exploratory case a
release blocker.

## Remaining Roadmap

- Larger real-cluster A3 measurement and KG-on/KG-off comparison before making
  TypeDB weighting a stronger default dependency.
- Harder holdout coverage for noisy multi-signal incidents, especially mixed
  Kubernetes scheduling plus GPU/runtime failures.
- Production hardening guidance for privileged `systemAgent`, TypeDB
  credentials, and network policy.
- Slack thread cleanup on incident deletion or permanent purge.
