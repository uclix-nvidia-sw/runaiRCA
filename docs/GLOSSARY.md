# RCA Output Terminology Glossary

> **Lens:** How to read the operator-facing RCA output.
> **In this doc:** family labels · support states · evaluation · output validation · report generation.

This is a concise reference for terms that have more than one implementation-specific meaning in Run:AI RCA.

## Terms

### `family`

**Definition.** A `family` is one of the 16 fault categories in `agent/knowledge/families.yaml`, mirrored in code as `DEFAULT_FAMILY_RULES` in `agent/app/knowledge.py`. The deterministic ranker scores families using their `keywords`; `planner_keywords` help the investigation planner recall hypotheses, but never contribute to the family score. When no family reaches the ranking evidence floor, the pipeline injects the synthetic `insufficient_evidence` family.

**Where you see it.** As the root-cause family label in ranked candidates, the RCA headline, harness claims, and related evidence or knowledge records.

### `supported` / `supporting`

**Definition.** This word has four distinct technical meanings. They are related, but are computed at different stages and attached to different objects:

1. **Investigator hypothesis-ledger status:** `supported` is one of `_LEDGER_STATUSES = {open, testing, supported, refuted, uncertain}` in `agent/app/services/investigator.py:49`. It means the investigation loop considers that hypothesis backed enough to stop probing it.
2. **Evidence-blackboard fact status:** `supported` is one value of `HypothesisStatus = Literal["untested", "testing", "supported", "refuted", "provisional"]` in `agent/app/services/evidence_blackboard.py:27`. It is the status recorded for a blackboard hypothesis/fact.
3. **Harness `diagnosis_state`:** `supported` is the operator-visible verdict state in `agent/app/services/harness.py:343-344`. The harness sets it when a family is present and confidence is not low; otherwise the state is `provisional` for low confidence or `unresolved` when the family is absent/`insufficient_evidence`.
4. **Direct evidence:** `supporting_source_groups` in reasoning trace v3 and `supporting_artifacts` in the report identify the specific evidence artifacts that directly back the root cause, as distinct from contradicting or context artifacts (`agent/app/services/pipeline.py:1297, 3267`).

The four meanings must not be conflated: a hypothesis being `supported` in the investigator ledger does not mean the harness marked the diagnosis `supported`.

**Where you see it.** In investigation traces and hypothesis ledgers, blackboard facts, the harness `diagnosis_state`, reasoning traces, and report evidence sections; the surrounding object and field name tells you which meaning applies.

### `evaluation`

**Definition.** `evaluation` has two meanings. First, probe evaluation is the deterministic verdict `supports`, `refutes`, `inconclusive`, or `unavailable` computed by `agent/app/services/probe_evaluation.py` from explicitly authored probe signals. Second, evaluation is the human operator review of a completed run exposed through the backend/frontend `EvaluationView`; that review and its knowledge-promotion checks can gate whether knowledge is promoted.

**Where you see it.** Probe assessments and investigation records for the first meaning; the completed-run Evaluation view, review score, and knowledge-promotion preview for the second.

### `harness`

**Definition.** The `harness` is the post-synthesis output validator in `agent/app/services/harness.py`. It checks hard gates for unsupported high confidence, missing evidence trace, invalid evidence links, unresolved contradiction, and unsafe action without a guardrail, and also computes a rubric score. It can repair the report, downgrade its verdict, or abstain by replacing the top cause with `insufficient_evidence`. It is controlled by `ENABLE_RCA_OUTPUT_HARNESS`, which defaults to on.

**Where you see it.** In the final response context, harness status/score, `diagnosis_state`, hard-gate results, and any repaired or abstained RCA output.

### `synthesis`

**Definition.** `synthesis` is the stage that generates the final operator-facing report: `synthesize_stage` in `agent/app/services/pipeline.py` builds the deterministic English report, and when configured for Korean it may be overwritten by a Korean LLM report grounded strictly in eligible evidence.

**Where you see it.** As the `synthesize` pipeline stage and in the final report summary, detail, actions, caveats, and evidence presentation.
