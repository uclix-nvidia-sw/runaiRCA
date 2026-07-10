# RCA evaluation and runtime harness

This project evaluates RCA in two places:

- **Runtime harness**: protects every RCA before it reaches an operator.
- **Offline evaluation**: measures regressions, novelty handling, and tool
  degradation with fixtures and operator reviews.

## Runtime harness

The pipeline runs `harness` after synthesis. It assigns `E01`, `E02`, … IDs to
artifacts, creates a claim ledger, and checks the final report.

| Dimension | Weight |
| --- | ---: |
| Evidence grounding | 25 |
| Diagnostic reasoning | 20 |
| Investigation plan | 20 |
| Uncertainty calibration | 15 |
| Operational usefulness | 10 |
| Tool efficiency | 5 |
| Safety | 5 |

The initial pass score is 70/100. The three non-negotiable gates are:

1. a high-confidence cause needs two independent live evidence sources or a
   dispositive signature;
2. a material cause claim must trace to usable current-run evidence;
3. disruptive actions need read-only verification, impact/rollback guidance,
   and operator approval before they are suggested.

The harness applies deterministic repairs for missing evidence trace, missing
safety guardrails, and overconfident labels, up to
`MAX_RCA_REPAIR_ATTEMPTS=3`. A remaining hard-gate failure becomes an honest
`insufficient_evidence` response instead of a guessed family. A score-only
failure remains visible as `degraded`.

Historical TypeDB evidence is context, never a substitute for current evidence.

## Operator review

Incident detail exposes the latest run's harness result and an RCA Evaluation
form. Reviews are tied to `analysis_hash`; a re-analysis creates a new review
surface, while prior reviews remain historical.

The form records:

- case type: `known`, `compositional`, `novel`, or `tool_degraded`;
- optional expected family;
- the seven 0–5 rubric scores;
- hard-gate assessment;
- resolution outcome and an action that actually worked;
- notes.

Only `resolved` or `mitigated` actions become TypeDB verified actions. A report
recommendation by itself is not proof that the action fixed an incident.

## Offline cases

| Case type | What is evaluated |
| --- | --- |
| Known regression | Top-1/Top-3 root-cause family |
| Compositional | Causal ordering, competing hypotheses, discriminating checks |
| Open-world / novel | Grounding, calibrated uncertainty, and investigation plan; no forced family |
| Tool degraded | Honest missing-data reporting and safe fallback |

Novelty mutations remove a signature, omit one symptom, add contradictory
evidence, remove a data source, or shift the incident window. A good answer may
be provisional or unresolved; forcing a familiar family is a failure.

## Commands

```bash
cd agent
.venv/bin/python -m pytest -vv tests/test_harness.py tests/test_nat_engine.py
.venv/bin/python -m eval.run_eval --fixtures eval/fixtures.jsonl --min-top1 0.8
```

The baseline known-family fixture score must not regress from 22/23 Top-1.
Open-world cases must produce zero unsupported high-confidence conclusions.

## Configuration

| Variable | Default | Meaning |
| --- | ---: | --- |
| `ENABLE_RCA_OUTPUT_HARNESS` | `true` | Enable final response validation |
| `MAX_RCA_REPAIR_ATTEMPTS` | `3` | Maximum deterministic repair passes |
| `RCA_HARNESS_PASS_SCORE` | `70` | Score below which a non-fatal response is degraded |

See [RCA Pipeline](RCA-PIPELINE.md) and [Ontology Guide](ONTOLOGY-GUIDE.md).
