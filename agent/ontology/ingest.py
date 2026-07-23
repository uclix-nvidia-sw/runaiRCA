"""Project the backend's existing incidents/alerts into the TypeDB knowledge graph.

Deterministic, no LLM: each incident's entities come from the alert labels via the
same `resolve_target()` the collectors use. Writes topology (cluster/node/namespace/
project/queue/workload/pod) + incident/alert + relations — exactly what the
TypeDBCollector queries (node blast radius, incident history).

KB-poisoning guard (critique #1): by default only incidents an operator has
reviewed (an `up` vote or a comment) are committed. Use --all to bulk-load a
sample set for the initial PoC.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 POSTGRES_DSN=... \
        ./.venv/bin/python -m ontology.ingest --all --limit 50

ponytail: match-or-insert per keyed entity inside one WRITE txn per incident
(uncommitted inserts are visible within the txn). Re-runnable; commits per
incident so one bad row can't drop the batch. First run must be validated
against a live TypeDB — TypeQL 3.x syntax is not exercised by the unit tests.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime
from typing import Any

from app.collectors.base import resolve_target
from app.config import load_settings
from app.knowledge import load_family_catalog
from app.ontology.typedb_client import escape_typeql as esc
from ontology.incident import OntologyIncident
from ontology.load_knowledge import (
    _ensure_action,
    _ensure_cause,
    _ensure_symptom,
    _relate_indicates,
    _relate_resolved_by,
)

_SELECT_INCIDENTS = """
SELECT i.incident_id, i.correlation_key, i.title, i.severity, i.status,
       i.fired_at::text AS fired_at,
       i.user_approved_at::text AS user_approved_at,
       a.alert_id, a.fingerprint, a.occurrence_count, a.occurrence_pods,
       a.labels, a.annotations,
       COALESCE(r.run_id, '') AS run_id,
       COALESCE(r.case_id, '') AS case_id,
       COALESCE(r.approval_state, '') AS approval_state,
       COALESCE(r.mechanism, '') AS mechanism,
       COALESCE(r.mechanism_fingerprint, '') AS mechanism_fingerprint,
       COALESCE(r.case_analysis_hash, '') AS case_analysis_hash,
       COALESCE(r.analysis_summary, '') AS analysis_summary,
       COALESCE(r.analysis_detail, '')  AS analysis_detail,
       COALESCE(r.root_cause_family, '') AS root_cause_family,
       COALESCE(r.artifacts, '[]'::jsonb) AS artifacts,
       COALESCE(r.metadata, '{}'::jsonb) AS analysis_metadata,
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object(
           'statement', er.effective_action,
           'outcome', er.resolution_outcome
         ))
           FROM rca_eval_reviews er
          WHERE er.run_id = r.run_id
            AND er.analysis_hash = r.case_analysis_hash
            AND er.resolution_outcome IN ('resolved', 'mitigated')
            AND er.effective_action <> ''
       ), '[]'::jsonb) AS verified_actions,
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object(
           'statement', er.effective_action,
           'outcome', er.resolution_outcome
         ))
           FROM rca_eval_reviews er
          WHERE er.run_id = r.run_id
            AND er.analysis_hash = r.case_analysis_hash
            AND er.resolution_outcome = 'ineffective'
            AND er.effective_action <> ''
       ), '[]'::jsonb) AS ineffective_actions,
       COALESCE((
         SELECT jsonb_agg(er.scores)
           FROM rca_eval_reviews er
          WHERE er.run_id = r.run_id
            AND er.analysis_hash = r.case_analysis_hash
       ), '[]'::jsonb) AS evaluation_scores,
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object(
           'case_type', er.case_type,
           'expected_family', er.expected_family,
           'resolution_outcome', er.resolution_outcome
         ) ORDER BY er.updated_at, er.review_id)
           FROM rca_eval_reviews er
          WHERE er.run_id = r.run_id
            AND er.analysis_hash = r.case_analysis_hash
       ), '[]'::jsonb) AS evaluation_reviews,
       (SELECT count(*) FROM rca_feedback f
         WHERE f.target_id IN (i.incident_id, a.alert_id)
           AND f.kind = 'vote'
           AND f.vote = 'up') AS positive_feedback,
       (SELECT count(*) FROM rca_feedback f
         WHERE f.target_id IN (i.incident_id, a.alert_id)
           AND f.kind = 'vote'
           AND f.vote = 'down') AS negative_feedback,
       (EXISTS (SELECT 1 FROM rca_feedback f
                 WHERE f.target_id IN (i.incident_id, a.alert_id)
                   AND f.kind = 'vote' AND f.vote = 'up')
        OR EXISTS (SELECT 1 FROM rca_feedback c
                    WHERE c.target_id IN (i.incident_id, a.alert_id)
                      AND c.kind = 'comment')) AS reviewed
FROM incidents i
JOIN alerts a ON a.incident_id = i.incident_id
-- Approved historical knowledge must bind to the exact immutable snapshot, not
-- to whichever analysis_run happened to become latest after approval.
LEFT JOIN LATERAL (
    SELECT cs.case_id, cs.approval_state, cs.mechanism, cs.mechanism_fingerprint,
           cs.analysis_hash AS case_analysis_hash,
           cs.run_id,
           COALESCE(cs.snapshot->>'analysis_summary', '') AS analysis_summary,
           COALESCE(cs.snapshot->>'analysis_detail', '') AS analysis_detail,
           cs.root_cause_family,
           COALESCE(cs.snapshot->'artifacts', '[]'::jsonb) AS artifacts,
           COALESCE(cs.snapshot->'metadata', '{}'::jsonb) AS metadata,
           COALESCE(cs.snapshot->'case_card', '{}'::jsonb) AS case_card
      FROM rca_case_snapshots cs
     WHERE cs.incident_id = i.incident_id
       AND cs.approval_state = 'active'
     ORDER BY cs.approved_at DESC
     LIMIT 1
) r ON TRUE
{where}
ORDER BY i.fired_at DESC
LIMIT $1
"""

# Only incidents resolved at least N hours ago (grace window lets late feedback /
# re-analysis settle before the KG learns). Re-fired incidents have status back to
# 'firing', so they are excluded automatically.
_RESOLVED_GRACE_WHERE = (
    "WHERE i.status = 'resolved' AND i.resolved_at IS NOT NULL "
    "AND i.resolved_at < now() - make_interval(hours => $2::int)"
)


def _json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return [str(v) for v in parsed] if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _json_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
    return []


def _action_list(value: Any) -> list[dict[str, str]]:
    """Normalize review actions without treating arbitrary text as verified."""
    actions: list[dict[str, str]] = []
    for item in _json_list(value):
        statement = " ".join(str(item.get("statement") or "").split())[:_ACTION_MAXLEN]
        outcome = str(item.get("outcome") or "").strip()
        if statement and outcome in {"resolved", "mitigated", "ineffective"}:
            actions.append({"statement": statement, "outcome": outcome})
    return actions


_REVIEW_DIMENSIONS = (
    "evidence_grounding",
    "diagnostic_reasoning",
    "investigation_plan",
    "uncertainty_calibration",
    "operational_usefulness",
    "tool_efficiency",
    "safety",
)


def _quality_score(metadata: dict[str, Any], review_scores: Any) -> tuple[int | None, str]:
    """Prefer operator review score; harness is an explicitly labelled fallback."""
    complete: list[float] = []
    for scores in _json_list(review_scores):
        try:
            values = [int(scores[dimension]) for dimension in _REVIEW_DIMENSIONS]
        except (KeyError, TypeError, ValueError):
            continue
        if all(0 <= value <= 5 for value in values):
            complete.append(sum(values) / len(values) * 20)
    if complete:
        return round(sum(complete) / len(complete)), "operator_review"
    harness = metadata.get("harness")
    if isinstance(harness, dict):
        try:
            score = int(harness.get("overall_score"))
            if 0 <= score <= 100:
                return score, "harness"
        except (TypeError, ValueError):
            pass
    return None, ""


def _to_incident(row: dict[str, Any]) -> OntologyIncident:
    labels = _json(row.get("labels"))
    annotations = _json(row.get("annotations"))
    target = resolve_target(labels, annotations)
    metadata = _json(row.get("analysis_metadata"))
    harness = metadata.get("harness")
    case_card = _json(row.get("case_card"))
    quality_score, quality_source = _quality_score(metadata, row.get("evaluation_scores"))
    return OntologyIncident(
        incident_id=str(row["incident_id"]),
        alert_id=str(row.get("alert_id") or ""),
        correlation_key=str(row.get("correlation_key") or ""),
        analysis_summary=str(row.get("analysis_summary") or ""),
        analysis_detail=str(row.get("analysis_detail") or ""),
        run_id=str(row.get("run_id") or ""),
        analysis_hash=str(row.get("case_analysis_hash") or metadata.get("analysis_hash") or ""),
        case_id=str(row.get("case_id") or ""),
        approval_state=str(row.get("approval_state") or ""),
        mechanism=str(row.get("mechanism") or ""),
        mechanism_fingerprint=str(row.get("mechanism_fingerprint") or ""),
        case_card=case_card,
        successful_actions=_action_list(row.get("verified_actions")),
        failed_actions=_action_list(row.get("ineffective_actions")),
        quality_score=quality_score,
        quality_source=quality_source,
        artifacts=_json_list(row.get("artifacts")),
        harness=harness if isinstance(harness, dict) else {},
        reasoning_trace_v3=_trace_v3(metadata),
        title=str(row.get("title") or ""),
        severity=str(row.get("severity") or "warning"),
        status=str(row.get("status") or "firing"),
        fired_at=str(row.get("fired_at") or ""),
        cluster=target.cluster,
        node=target.node,
        namespace=target.namespace,
        project=target.project,
        queue=target.queue,
        workload_name=target.workload_name,
        workload_type=target.workload_type,
        alert_name=target.alert_name,
        fingerprint=str(row.get("fingerprint") or ""),
        occurrence_count=int(row.get("occurrence_count") or 0),
        occurrence_pods=_list(row.get("occurrence_pods")),
        root_cause_family=str(row.get("root_cause_family") or ""),
        user_approved_at=str(row.get("user_approved_at") or ""),
        reviewed=bool(row.get("reviewed")),
    )


def _trace_v3(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return only an explicitly versioned trace-v3 payload.

    Version 1/2 records have different semantics and must never be promoted by
    guesswork into hypothesis or probe-execution graph edges.
    """
    trace = metadata.get("reasoning_trace_v3") or metadata.get("trace_v3")
    if not isinstance(trace, dict):
        return {}
    try:
        version = int(trace.get("schema_version") or 0)
    except (TypeError, ValueError):
        return {}
    return trace if version == 3 else {}


async def _fetch(limit: int, resolved_grace_hours: int = 0) -> list[dict[str, Any]]:
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping ingest.")
        return []
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        if resolved_grace_hours > 0:
            # Replace only our named sentinel. PostgreSQL JSON literals such as
            # '{}' are data, not Python format fields.
            sql = _SELECT_INCIDENTS.replace("{where}", _RESOLVED_GRACE_WHERE)
            rows = await conn.fetch(sql, limit, resolved_grace_hours)
        else:
            rows = await conn.fetch(_SELECT_INCIDENTS.replace("{where}", ""), limit)
    finally:
        await conn.close()
    return [dict(r) for r in rows]


# The trace-v3 backfill has a deliberately separate keyset query. It traverses
# active approved snapshots (not latest incidents), so a large history can be
# resumed exactly at `(approved_at, case_id)` without relying on OFFSET.
_SELECT_TRACE_V3_PAGE = """
SELECT i.incident_id, i.correlation_key, i.title, i.severity, i.status,
       i.fired_at::text AS fired_at,
       i.user_approved_at::text AS user_approved_at,
       a.alert_id, a.fingerprint, a.occurrence_count, a.occurrence_pods,
       a.labels, a.annotations,
       cs.case_id, cs.approval_state, cs.mechanism, cs.mechanism_fingerprint,
       cs.analysis_hash AS case_analysis_hash, cs.run_id,
       cs.approved_at::text AS snapshot_approved_at,
       COALESCE(cs.snapshot->>'analysis_summary', '') AS analysis_summary,
       COALESCE(cs.snapshot->>'analysis_detail', '') AS analysis_detail,
       cs.root_cause_family,
       COALESCE(cs.snapshot->'artifacts', '[]'::jsonb) AS artifacts,
       COALESCE(cs.snapshot->'metadata', '{}'::jsonb) AS analysis_metadata,
       COALESCE(cs.snapshot->'case_card', '{}'::jsonb) AS case_card,
       '[]'::jsonb AS verified_actions,
       '[]'::jsonb AS ineffective_actions,
       '[]'::jsonb AS evaluation_scores,
       false AS reviewed
FROM rca_case_snapshots cs
JOIN incidents i ON i.incident_id = cs.incident_id
JOIN LATERAL (
    SELECT alert_id, fingerprint, occurrence_count, occurrence_pods, labels, annotations
      FROM alerts
     WHERE incident_id = i.incident_id
     ORDER BY fired_at DESC
     LIMIT 1
) a ON TRUE
WHERE cs.approval_state = 'active'
  AND cs.approved_at IS NOT NULL
  AND i.user_approved_at IS NOT NULL
  AND ($1::timestamptz IS NULL OR (cs.approved_at, cs.case_id) > ($1::timestamptz, $2::text))
ORDER BY cs.approved_at ASC, cs.case_id ASC
LIMIT $3
"""


def _trace_v3_cursor_datetime(value: str) -> datetime | None:
    """Parse a durable keyset cursor into the type asyncpg expects.

    The cursor table intentionally stores the value as text so operators can
    inspect and resume it.  asyncpg does not coerce that text for a
    ``timestamptz`` bind parameter, however, so preserve its offset while
    converting it back to an aware ``datetime`` before querying.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid trace-v3 cursor timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("trace-v3 cursor timestamp must include a timezone offset")
    return parsed


async def _fetch_trace_v3_page(
    after_approved_at: str = "", after_case_id: str = "", limit: int = 200
) -> list[dict[str, Any]]:
    """Fetch one approval-keyset page for the resumable trace-v3 backfill."""
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping trace-v3 backfill.")
        return []
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        rows = await conn.fetch(
            _SELECT_TRACE_V3_PAGE,
            _trace_v3_cursor_datetime(after_approved_at),
            after_case_id,
            max(1, limit),
        )
    finally:
        await conn.close()
    return [dict(row) for row in rows]


def _ensure(tx: Any, etype: str, key_attr: str, value: str) -> None:
    if not value:
        return
    q = f'match $x isa {etype}, has {key_attr} "{esc(value)}"; select $x;'
    if not list(tx.query(q).resolve().as_concept_rows()):
        tx.query(f'insert $x isa {etype}, has {key_attr} "{esc(value)}";').resolve()


def _replace_attr(
    tx: Any,
    etype: str,
    key_attr: str,
    key_value: str,
    attr: str,
    new_value: Any,
    quoted: bool = True,
) -> None:
    # Remove any existing value of `attr`, then set the new one. Replace (not
    # add-if-missing) so a re-projected incident whose RCA/status changed after a
    # re-open+re-analysis updates in place instead of accumulating stale values —
    # required, since owns defaults to @card(0..1) so a second value fails commit.
    # quoted=False for non-string attributes (e.g. integer occurrence_count).
    # TypeDB 3.x delete syntax: `delete has <attr> of <owner>` (2.x was `delete $x has $old`).
    tx.query(
        f'match $x isa {etype}, has {key_attr} "{esc(key_value)}", has {attr} $old; '
        f"delete has $old of $x;"
    ).resolve()
    value = f'"{esc(str(new_value))}"' if quoted else str(new_value)
    tx.query(
        f'match $x isa {etype}, has {key_attr} "{esc(key_value)}"; '
        f"insert $x has {attr} {value};"
    ).resolve()


def _relate(
    tx: Any,
    a: tuple[str, str, str],
    b: tuple[str, str, str],
    rel: str,
    role_a: str,
    role_b: str,
) -> None:
    """match-and-insert a binary relation; skips when either end is missing.

    Existence-check then insert (like _ensure) rather than inline `not { ... }`
    negation: TypeDB 3.11 rejects that negation form ([TQL03] "expected pattern").
    """
    (ta, ka, va), (tb, kb, vb) = a, b
    if not va or not vb:
        return
    match = f'$a isa {ta}, has {ka} "{esc(va)}"; $b isa {tb}, has {kb} "{esc(vb)}";'
    relation = f"({role_a}: $a, {role_b}: $b) isa {rel}"
    if list(tx.query(f"match {match} {relation}; select $a;").resolve().as_concept_rows()):
        return
    tx.query(f"match {match} insert {relation};").resolve()


def _clear_run_projection(tx: Any, run_id: str) -> None:
    """Remove only run-local diagnosis edges before a re-analysis projection."""
    if not run_id:
        return
    match = f'$r isa analysis_run, has run_id "{esc(run_id)}"; '
    tx.query(
        f"match {match} $d isa diagnosis, links (run: $r); "
        f"$s isa supported_by, links (claim: $d, proof: $e); delete $s;"
    ).resolve()
    tx.query(
        f"match {match} $d isa diagnosis, links (run: $r); "
        f"$c isa contradicted_by, links (claim: $d, proof: $e); delete $c;"
    ).resolve()
    tx.query(
        f"match {match} $d isa diagnosis, links (run: $r); "
        f"$p isa case_projection, links (finding: $d, case: $case); delete $p;"
    ).resolve()
    tx.query(f"match {match} $d isa diagnosis, links (run: $r); delete $d;").resolve()


def _is_novel_family(family: str) -> bool:
    return family.startswith("novel_")


def _cause_instance_id(inc: OntologyIncident) -> str:
    return inc.case_id or f"{inc.run_id}:{inc.analysis_hash or 'unhashed'}"


def _ensure_cause_instance(tx: Any, inc: OntologyIncident, family: str) -> None:
    cause_id = _cause_instance_id(inc)
    _ensure(tx, "cause_instance", "cause_id", cause_id)
    _replace_attr(tx, "cause_instance", "cause_id", cause_id, "subtype", family)
    if inc.mechanism:
        _replace_attr(tx, "cause_instance", "cause_id", cause_id, "mechanism", inc.mechanism)
    if inc.mechanism_fingerprint:
        _replace_attr(
            tx,
            "cause_instance",
            "cause_id",
            cause_id,
            "mechanism_fingerprint",
            inc.mechanism_fingerprint,
        )


def _cause_match(inc: OntologyIncident, family: str) -> str:
    if _is_novel_family(family):
        return f'$c isa cause_instance, has cause_id "{esc(_cause_instance_id(inc))}"; '
    return f'$c isa {family}, has subtype "{esc(family)}"; '


def _ensure_diagnosis(
    tx: Any,
    inc: OntologyIncident,
    family: str,
    *,
    confidence: str,
    diagnosis_state: str,
    harness_status: str,
    harness_score: int,
) -> None:
    if not inc.run_id or not family:
        return
    match = (
        f'$r isa analysis_run, has run_id "{esc(inc.run_id)}"; '
        f'$i isa incident, has incident_id "{esc(inc.incident_id)}"; '
        + _cause_match(inc, family)
    )
    tx.query(
        f"match {match} insert $d isa diagnosis, links (run: $r, incident: $i, cause: $c);"
    ).resolve()
    attrs = {
        "confidence": confidence or "low",
        "diagnosis_state": diagnosis_state or "unresolved",
        "analysis_hash": inc.analysis_hash,
        "harness_status": harness_status or "degraded",
        "harness_score": str(max(0, min(100, harness_score))),
    }
    for attr, value in attrs.items():
        if not value and attr == "analysis_hash":
            continue
        tx.query(
            f"match {match} $d isa diagnosis, links (run: $r, incident: $i, cause: $c), has {attr} $old; "
            f"delete has $old of $d;"
        ).resolve()
        literal = value if attr == "harness_score" else f'"{esc(value)}"'
        tx.query(
            f"match {match} $d isa diagnosis, links (run: $r, incident: $i, cause: $c); "
            f"insert $d has {attr} {literal};"
        ).resolve()


def _ensure_evidence(tx: Any, inc: OntologyIncident, item: dict[str, Any]) -> str:
    evidence_id = str(item.get("evidence_id") or "").strip()
    if not inc.run_id or not evidence_id:
        return ""
    key = f"{inc.run_id}:{evidence_id}"
    _ensure(tx, "evidence", "evidence_id", key)
    values = {
        "artifact_ref": key,
        "source": str(item.get("source") or item.get("agent") or ""),
        "evidence_type": str(item.get("type") or ""),
        "summary": " ".join(str(item.get("summary") or "").split())[:1200],
        "confidence": str(item.get("confidence") or "low"),
    }
    for attr, value in values.items():
        if value:
            _replace_attr(tx, "evidence", "evidence_id", key, attr, value)
    return key


_TRACE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


def _trace_id(value: object) -> str:
    """Accept an explicit trace ID verbatim, or reject it without fallback."""
    candidate = str(value or "").strip()
    return candidate if _TRACE_ID.fullmatch(candidate) else ""


def _trace_key(inc: OntologyIncident, local_id: str) -> str:
    """Namespace response-local trace IDs without changing their local value."""
    prefix = f"{inc.run_id}:"
    return local_id if local_id.startswith(prefix) else f"{prefix}{local_id}"


def _trace_text(value: object, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _ensure_trace_evidence(tx: Any, inc: OntologyIncident, item: dict[str, Any]) -> str:
    """Project trace-v3 evidence without merging it with legacy artifact rows."""
    local_id = _trace_id(item.get("evidence_id"))
    if not local_id:
        return ""
    evidence_id = _trace_key(inc, local_id)
    _ensure(tx, "evidence", "evidence_id", evidence_id)
    # Every field below is supplied by the trace-v3 evidence object itself.
    # In particular, do not copy these values from an artifact or a v1/v2 trace.
    window = item.get("observation_window")
    window = window if isinstance(window, dict) else {}
    values = {
        "artifact_ref": local_id,
        "trace_local_id": local_id,
        "source": _trace_text(item.get("source"), 120),
        "observed_entity": _trace_text(item.get("entity"), 300),
        "source_group": _trace_text(item.get("source_group"), 120),
        "predicate": _trace_text(item.get("predicate"), 300),
        "observed_value": _trace_text(item.get("value"), 500),
        "polarity": _trace_text(item.get("polarity"), 80),
        "coverage": _trace_text(item.get("coverage"), 120),
        "quality": _trace_text(item.get("quality"), 120),
        "observed_window_start": _trace_text(window.get("start"), 80),
        "observed_window_end": _trace_text(window.get("end"), 80),
    }
    for attr, value in values.items():
        if value:
            _replace_attr(tx, "evidence", "evidence_id", evidence_id, attr, value)
    return evidence_id


def _trace_relation(
    tx: Any,
    match: str,
    relation: str,
    insert: str,
) -> None:
    if not list(tx.query(f"match {match} {relation}; select $x;").resolve().as_concept_rows()):
        tx.query(f"match {match} insert {insert};").resolve()


def _clear_trace_v3_projection(tx: Any, run_id: str) -> None:
    """Detach a run's previous v3 links, retaining legacy evidence untouched."""
    run = f'$r isa analysis_run, has run_id "{esc(run_id)}"; '
    hypothesis = '$h isa hypothesis_for, links (run: $r, hypothesis: $hyp); '
    # Delete dependent trace links before the run-to-hypothesis membership.
    for _relation, extra in (
        ("supported_by", '$x isa supported_by, links (claim: $hyp, proof: $e); '),
        ("contradicted_by", '$x isa contradicted_by, links (claim: $hyp, proof: $e); '),
        ("rejected_evidence_link", '$x isa rejected_evidence_link, links (hypothesis: $hyp, proof: $e); '),
        (
            "probe_execution_evidence",
            '$t isa probe_execution_tests, links (execution: $execution, hypothesis: $hyp); '
            '$x isa probe_execution_evidence, links (execution: $execution, proof: $e); ',
        ),
        (
            "probe_execution_for",
            '$t isa probe_execution_tests, links (execution: $execution, hypothesis: $hyp); '
            '$x isa probe_execution_for, links (execution: $execution, template: $template); ',
        ),
        ("probe_execution_tests", '$x isa probe_execution_tests, links (execution: $execution, hypothesis: $hyp); '),
        ("hypothesis_for", '$x isa hypothesis_for, links (run: $r, hypothesis: $hyp); '),
    ):
        tx.query(f"match {run}{hypothesis}{extra} delete $x;").resolve()


def _relate_trace_evidence(
    tx: Any, hypothesis_id: str, evidence_id: str, relation: str
) -> None:
    match = (
        f'$h isa hypothesis, has hypothesis_id "{esc(hypothesis_id)}"; '
        f'$e isa evidence, has evidence_id "{esc(evidence_id)}"; '
    )
    edge = f"$x isa {relation}, links (claim: $h, proof: $e)"
    _trace_relation(tx, match, edge, f"$x isa {relation}, links (claim: $h, proof: $e)")


def _write_trace_v3_projection(tx: Any, inc: OntologyIncident) -> None:
    """Write only the explicit, versioned hypothesis/probe trace contract."""
    trace = inc.reasoning_trace_v3
    if not inc.run_id or not isinstance(trace, dict):
        return
    try:
        version = int(trace.get("schema_version") or 0)
    except (TypeError, ValueError):
        return
    if version != 3:
        return

    raw_hypotheses = trace.get("hypotheses")
    raw_evidence = trace.get("evidence")
    raw_executions = trace.get("probe_executions")
    if not isinstance(raw_hypotheses, list):
        raw_hypotheses = []
    if not isinstance(raw_evidence, list):
        raw_evidence = []
    if not isinstance(raw_executions, list):
        raw_executions = []
    _clear_trace_v3_projection(tx, inc.run_id)

    evidence = {
        evidence_id: evidence_id
        for item in raw_evidence
        if isinstance(item, dict)
        if (evidence_id := _ensure_trace_evidence(tx, inc, item))
    }
    hypothesis_ids: dict[str, str] = {}
    for item in raw_hypotheses:
        if not isinstance(item, dict):
            continue
        local_hypothesis_id = _trace_id(item.get("hypothesis_id"))
        if not local_hypothesis_id:
            continue
        hypothesis_id = _trace_key(inc, local_hypothesis_id)
        hypothesis_ids[local_hypothesis_id] = hypothesis_id
        _ensure(tx, "hypothesis", "hypothesis_id", hypothesis_id)
        for attr, value in {
            "trace_local_id": local_hypothesis_id,
            "hypothesis_family": _trace_text(item.get("family"), 160),
            "mechanism": _trace_text(item.get("mechanism"), 1200),
            "mechanism_fingerprint": _trace_text(
                item.get("mechanism_fingerprint"), 160
            ),
            "hypothesis_status": _trace_text(item.get("status"), 80),
            "confidence": _trace_text(item.get("confidence"), 80),
        }.items():
            if value:
                _replace_attr(tx, "hypothesis", "hypothesis_id", hypothesis_id, attr, value)
        _replace_attr(tx, "hypothesis", "hypothesis_id", hypothesis_id, "trace_version", version, quoted=False)
        match = (
            f'$r isa analysis_run, has run_id "{esc(inc.run_id)}"; '
            f'$i isa incident, has incident_id "{esc(inc.incident_id)}"; '
            f'$h isa hypothesis, has hypothesis_id "{esc(hypothesis_id)}"; '
        )
        edge = "$x isa hypothesis_for, links (run: $r, incident: $i, hypothesis: $h)"
        _trace_relation(tx, match, edge, " $x isa hypothesis_for, links (run: $r, incident: $i, hypothesis: $h)")
        for evidence_id in item.get("evidence_for") or []:
            if _trace_id(evidence_id) in evidence:
                _relate_trace_evidence(tx, hypothesis_id, evidence[_trace_id(evidence_id)], "supported_by")
        for evidence_id in item.get("evidence_against") or []:
            if _trace_id(evidence_id) in evidence:
                _relate_trace_evidence(tx, hypothesis_id, evidence[_trace_id(evidence_id)], "contradicted_by")

    for item in raw_executions:
        if not isinstance(item, dict):
            continue
        local_execution_id = _trace_id(item.get("execution_id"))
        template_id = _trace_id(item.get("template_id"))
        if not local_execution_id or not template_id:
            continue
        execution_id = _trace_key(inc, local_execution_id)
        # The template must be authored/loaded first. Never create a template
        # from a trace payload, because that could smuggle query arguments.
        template_match = f'$p isa diagnostic_probe_template, has probe_id "{esc(template_id)}"; '
        if not list(tx.query(f"match {template_match} select $p;").resolve().as_concept_rows()):
            continue
        _ensure(tx, "probe_execution", "probe_execution_id", execution_id)
        for attr, value in {
            "trace_local_id": local_execution_id,
            "probe_verdict": _trace_text(item.get("verdict"), 80),
            "executed_at": _trace_text(item.get("executed_at"), 80),
        }.items():
            if value:
                _replace_attr(tx, "probe_execution", "probe_execution_id", execution_id, attr, value)
        _replace_attr(tx, "probe_execution", "probe_execution_id", execution_id, "trace_version", version, quoted=False)
        match = (
            f'$x isa probe_execution, has probe_execution_id "{esc(execution_id)}"; '
            f'$p isa diagnostic_probe_template, has probe_id "{esc(template_id)}"; '
        )
        edge = "$link isa probe_execution_for, links (execution: $x, template: $p)"
        _trace_relation(tx, match, edge, "$link isa probe_execution_for, links (execution: $x, template: $p)")
        for hypothesis_id in item.get("hypothesis_ids") or []:
            hypothesis_id = _trace_id(hypothesis_id)
            if hypothesis_id not in hypothesis_ids:
                continue
            hmatch = match + (
                f'$h isa hypothesis, has hypothesis_id "{esc(hypothesis_ids[hypothesis_id])}"; '
            )
            hedge = "$link isa probe_execution_tests, links (execution: $x, hypothesis: $h)"
            _trace_relation(tx, hmatch, hedge, "$link isa probe_execution_tests, links (execution: $x, hypothesis: $h)")
        for evidence_id in item.get("evidence_ids") or []:
            evidence_id = _trace_id(evidence_id)
            if evidence_id not in evidence:
                continue
            ematch = match + f'$e isa evidence, has evidence_id "{esc(evidence[evidence_id])}"; '
            eedge = "$link isa probe_execution_evidence, links (execution: $x, proof: $e)"
            _trace_relation(tx, ematch, eedge, "$link isa probe_execution_evidence, links (execution: $x, proof: $e)")

    for item in trace.get("rejected_evidence_links") or []:
        if not isinstance(item, dict):
            continue
        hypothesis_id = _trace_id(item.get("hypothesis_id"))
        evidence_id = _trace_id(item.get("evidence_id"))
        if hypothesis_id not in hypothesis_ids or evidence_id not in evidence:
            continue
        match = (
            f'$h isa hypothesis, has hypothesis_id "{esc(hypothesis_ids[hypothesis_id])}"; '
            f'$e isa evidence, has evidence_id "{esc(evidence[evidence_id])}"; '
        )
        reason = _trace_text(item.get("reason"), 500)
        edge = "$x isa rejected_evidence_link, links (hypothesis: $h, proof: $e)"
        if not list(tx.query(f"match {match} {edge}; select $x;").resolve().as_concept_rows()):
            suffix = f', has rejection_reason "{esc(reason)}"' if reason else ""
            tx.query(f"match {match} insert $x isa rejected_evidence_link, links (hypothesis: $h, proof: $e){suffix};").resolve()


def _relate_diagnosis_evidence(
    tx: Any,
    inc: OntologyIncident,
    family: str,
    evidence_key: str,
    relation: str = "supported_by",
) -> None:
    if not inc.run_id or not family or not evidence_key:
        return
    match = (
        f'$r isa analysis_run, has run_id "{esc(inc.run_id)}"; '
        f'$i isa incident, has incident_id "{esc(inc.incident_id)}"; '
        + _cause_match(inc, family)
        + '$d isa diagnosis, links (run: $r, incident: $i, cause: $c); '
        + f'$e isa evidence, has evidence_id "{esc(evidence_key)}"; '
    )
    exists = list(
        tx.query(f"match {match} $s isa {relation}, links (claim: $d, proof: $e); select $d;")
        .resolve()
        .as_concept_rows()
    )
    if not exists:
        tx.query(f"match {match} insert $s isa {relation}, links (claim: $d, proof: $e);").resolve()


def _ensure_case_projection(tx: Any, inc: OntologyIncident, family: str) -> None:
    if not inc.case_id or not inc.run_id:
        return
    _ensure(tx, "case_snapshot", "case_id", inc.case_id)
    _replace_attr(tx, "case_snapshot", "case_id", inc.case_id, "approval_state", inc.approval_state or "active")
    if inc.analysis_hash:
        _replace_attr(tx, "case_snapshot", "case_id", inc.case_id, "analysis_hash", inc.analysis_hash)
    if inc.user_approved_at:
        _replace_attr(tx, "case_snapshot", "case_id", inc.case_id, "approved_at", inc.user_approved_at)
    # Keep the immutable approval record self-describing for the retrieval
    # projection. Empty mechanism values are represented inside case_card rather
    # than forced as TypeDB attributes, so legacy snapshots remain queryable.
    if inc.mechanism:
        _replace_attr(tx, "case_snapshot", "case_id", inc.case_id, "mechanism", inc.mechanism)
    if inc.mechanism_fingerprint:
        _replace_attr(
            tx,
            "case_snapshot",
            "case_id",
            inc.case_id,
            "mechanism_fingerprint",
            inc.mechanism_fingerprint,
        )
    card = _case_card_for_graph(inc, family)
    _replace_attr(
        tx,
        "case_snapshot",
        "case_id",
        inc.case_id,
        "case_card",
        json.dumps(card, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )
    if inc.quality_score is not None:
        _replace_attr(
            tx,
            "case_snapshot",
            "case_id",
            inc.case_id,
            "quality_score",
            max(0, min(100, inc.quality_score)),
            quoted=False,
        )
    match = (
        f'$case isa case_snapshot, has case_id "{esc(inc.case_id)}"; '
        f'$r isa analysis_run, has run_id "{esc(inc.run_id)}"; '
        f'$i isa incident, has incident_id "{esc(inc.incident_id)}"; '
        + _cause_match(inc, family)
        + '$d isa diagnosis, links (run: $r, incident: $i, cause: $c); '
    )
    exists = list(
        tx.query(f"match {match} $p isa case_projection, links (case: $case, finding: $d); select $p;")
        .resolve()
        .as_concept_rows()
    )
    if not exists:
        tx.query(f"match {match} insert $p isa case_projection, links (case: $case, finding: $d);").resolve()


def _case_card_for_graph(inc: OntologyIncident, family: str) -> dict[str, Any]:
    """Merge immutable snapshot facts and hash-bound review outcomes.

    This is a stored *projection*, not a generated RCA: values originate from
    CaseSnapshot payload, harness links, or evaluation rows selected by the
    same `(run_id, analysis_hash)` as the approved case.
    """
    raw = inc.case_card if isinstance(inc.case_card, dict) else {}
    card = json.loads(json.dumps(raw, ensure_ascii=False)) if raw else {}
    try:
        card["schema_version"] = max(1, int(card.get("schema_version") or 1))
    except (TypeError, ValueError):
        card["schema_version"] = 1
    card["historical_prior"] = True
    card["case_id"] = inc.case_id
    card["incident_id"] = inc.incident_id
    card["family"] = family
    card["approval_analysis_hash"] = inc.analysis_hash
    if inc.mechanism and not card.get("mechanism"):
        card["mechanism"] = inc.mechanism
    if inc.mechanism_fingerprint and not card.get("mechanism_fingerprint"):
        card["mechanism_fingerprint"] = inc.mechanism_fingerprint
    if inc.quality_score is not None:
        card["quality_score"] = max(0, min(100, inc.quality_score))
        card["quality_source"] = inc.quality_source or "harness"
    if inc.successful_actions:
        card["successful_actions"] = inc.successful_actions
    if inc.failed_actions:
        card["failed_actions"] = inc.failed_actions
    return card


def _ensure_resolution(
    tx: Any,
    inc: OntologyIncident,
    family: str,
    action: dict[str, str],
) -> None:
    statement = " ".join(str(action.get("statement") or "").split())[:_ACTION_MAXLEN]
    outcome = str(action.get("outcome") or "").strip()
    if not statement or outcome not in {"resolved", "mitigated", "ineffective"}:
        return
    _ensure_action(tx, statement)
    match = (
        f'$r isa analysis_run, has run_id "{esc(inc.run_id)}"; '
        f'$i isa incident, has incident_id "{esc(inc.incident_id)}"; '
        + _cause_match(inc, family)
        + '$d isa diagnosis, links (run: $r, incident: $i, cause: $c); '
        + f'$a isa action, has statement "{esc(statement)}"; '
    )
    exists = list(
        tx.query(
            f'match {match} $resolution isa resolution, '
            f'links (finding: $d, remedy: $a), has outcome "{esc(outcome)}"; select $resolution;'
        )
        .resolve()
        .as_concept_rows()
    )
    if not exists:
        tx.query(
            f'match {match} insert $resolution isa resolution, '
            f'links (finding: $d, remedy: $a), has outcome "{esc(outcome)}";'
        ).resolve()


def _write_run_projection(tx: Any, inc: OntologyIncident) -> None:
    if not inc.run_id:
        return
    _ensure(tx, "analysis_run", "run_id", inc.run_id)
    _replace_attr(tx, "analysis_run", "run_id", inc.run_id, "status", "complete")
    _relate(
        tx,
        ("incident", "incident_id", inc.incident_id),
        ("analysis_run", "run_id", inc.run_id),
        "analyzed_by",
        "incident",
        "run",
    )
    _clear_run_projection(tx, inc.run_id)

    catalog = load_family_catalog("knowledge/families.yaml")
    # Preserve an evidence-backed open-world family as a run-local
    # cause_instance. Only malformed/empty non-catalog values abstain into the
    # legacy insufficient_evidence bucket.
    if inc.root_cause_family in catalog.families:
        family = inc.root_cause_family
        _ensure_cause(tx, family)
    elif _is_novel_family(inc.root_cause_family):
        family = inc.root_cause_family
        _ensure_cause_instance(tx, inc, family)
    else:
        family = "insufficient_evidence"
        _ensure_cause(tx, family)
    harness = inc.harness
    claims = harness.get("claims") if isinstance(harness.get("claims"), list) else []
    root_claim = next(
        (claim for claim in claims if isinstance(claim, dict) and claim.get("kind") == "root_cause"),
        {},
    )
    confidence = str(root_claim.get("confidence") or "low") if isinstance(root_claim, dict) else "low"
    state = str(harness.get("diagnosis_state") or "unresolved")
    status = str(harness.get("status") or "degraded")
    try:
        score = int(harness.get("overall_score") or 0)
    except (TypeError, ValueError):
        score = 0
    _ensure_diagnosis(
        tx,
        inc,
        family,
        confidence=confidence,
        diagnosis_state=state,
        harness_status=status,
        harness_score=score,
    )
    _ensure_case_projection(tx, inc, family)
    evidence_by_id = {
        str(item.get("evidence_id") or ""): item
        for item in inc.artifacts
        if isinstance(item, dict) and item.get("evidence_id")
    }
    for item in evidence_by_id.values():
        _ensure_evidence(tx, inc, item)
    support = root_claim.get("supporting_evidence") if isinstance(root_claim, dict) else []
    for evidence_id in support if isinstance(support, list) else []:
        item = evidence_by_id.get(str(evidence_id))
        if item:
            _relate_diagnosis_evidence(tx, inc, family, _ensure_evidence(tx, inc, item))
    contradictions = []
    if isinstance(root_claim, dict):
        raw = root_claim.get("contradicting_evidence") or root_claim.get("contradiction_evidence_ids")
        if isinstance(raw, list):
            contradictions = raw
    for evidence_id in contradictions:
        item = evidence_by_id.get(str(evidence_id))
        if item:
            _relate_diagnosis_evidence(
                tx,
                inc,
                family,
                _ensure_evidence(tx, inc, item),
                relation="contradicted_by",
            )
    # Resolution outcomes are allowed into the graph only from hash-bound
    # evaluation reviews.  This keeps recommended actions separate from actions
    # that an operator actually reported as effective or ineffective.
    for action in [*inc.successful_actions, *inc.failed_actions]:
        _ensure_resolution(tx, inc, family, action)
    # Keep the versioned trace separate from the legacy diagnosis projection:
    # it is populated solely from explicit reasoning_trace_v3 fields.
    _write_trace_v3_projection(tx, inc)


def _write_incident(tx: Any, inc: OntologyIncident) -> None:
    # keyed singletons (match-or-insert)
    _ensure(tx, "cluster", "name", inc.cluster)
    _ensure(tx, "node", "name", inc.node)
    _ensure(tx, "namespace", "name", inc.namespace)
    _ensure(tx, "project", "name", inc.project)
    _ensure(tx, "queue", "name", inc.queue)
    _ensure(tx, "workload", "name", inc.workload_name)
    _ensure(tx, "incident", "incident_id", inc.incident_id)
    _ensure(tx, "alert", "alert_id", inc.alert_id)

    # incident attributes (replace-in-place so re-projection updates, not duplicates)
    for attr, value in (
        ("title", inc.title),
        ("severity", inc.severity),
        ("status", inc.status),
        ("correlation_key", inc.correlation_key),
        ("analysis_summary", inc.analysis_summary),
    ):
        _replace_attr(tx, "incident", "incident_id", inc.incident_id, attr, value)
    if inc.user_approved_at:
        _replace_attr(
            tx, "incident", "incident_id", inc.incident_id, "approved_at", inc.user_approved_at
        )

    # alert attributes + grouped_into(incident, alert). Replace-in-place (like the
    # incident attrs above) so re-projecting the same alert with a changed value
    # updates instead of adding a 2nd value that fails commit (@card(0..1)).
    if inc.alert_id:
        for attr, value in (
            ("alert_name", inc.alert_name),
            ("severity", inc.severity),
            ("status", inc.status),
            ("fingerprint", inc.fingerprint),
        ):
            _replace_attr(tx, "alert", "alert_id", inc.alert_id, attr, value)
        _replace_attr(
            tx, "alert", "alert_id", inc.alert_id,
            "occurrence_count", max(inc.occurrence_count, 0), quoted=False,
        )
        _relate(
            tx,
            ("incident", "incident_id", inc.incident_id),
            ("alert", "alert_id", inc.alert_id),
            "grouped_into", "incident", "member",
        )

    # topology relations (each skipped when either end is missing)
    _relate(tx, ("cluster", "name", inc.cluster), ("node", "name", inc.node),
            "scopes", "scope", "member")
    _relate(tx, ("cluster", "name", inc.cluster), ("project", "name", inc.project),
            "scopes", "scope", "member")
    _relate(tx, ("project", "name", inc.project), ("workload", "name", inc.workload_name),
            "in_project", "project", "member")
    _relate(tx, ("queue", "name", inc.queue), ("workload", "name", inc.workload_name),
            "submitted_to", "queue", "job")

    # pods (occurrence) -> runs_on node + belongs_to workload + contains namespace
    for pod in inc.occurrence_pods[:25]:
        _ensure(tx, "pod", "name", pod)
        _relate(tx, ("node", "name", inc.node), ("pod", "name", pod),
                "runs_on", "host", "guest")
        _relate(tx, ("workload", "name", inc.workload_name), ("pod", "name", pod),
                "belongs_to", "owner", "member")
        _relate(tx, ("namespace", "name", inc.namespace), ("pod", "name", pod),
                "contains", "space", "occupant")

    _write_run_projection(tx, inc)


# --- knowledge promotion (--promote-knowledge) --------------------------------
# Promote approved RCAs into the knowledge layer the synthesis step consults:
# symptom "confirmed:{alert_name}" -indicates-> family root_cause, with only
# actions an operator marked resolved/mitigated. The hash-bound evaluation must
# explicitly confirm the persisted family; analysis prose is never a label.

_ACTION_CAP = 3
_ACTION_MAXLEN = 200


def _extract_actions(detail: str) -> list[str]:
    """Bullet lines from the Recommended-Actions section only.

    The heading appears as '## Recommended Actions', numbered
    '## 3. Recommended Actions', or Korean '## 3. 권장 조치 (Recommended Actions)'
    depending on language/report shape — match the phrase, not an exact prefix."""
    actions: list[str] = []
    in_section = False
    for line in (detail or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            in_section = "recommended actions" in stripped.lower() or "권장 조치" in stripped
            continue
        if in_section and stripped.startswith("- "):
            text = stripped[2:].strip().strip("*").strip()
            if text:
                actions.append(text[:_ACTION_MAXLEN])
        if len(actions) >= _ACTION_CAP:
            break
    return actions


def _action_statements(value: Any) -> list[str]:
    """Return only outcome-qualified action text from the CaseCard SQL shape."""
    structured = [
        action["statement"]
        for action in _action_list(value)
        if action.get("outcome") in {"resolved", "mitigated"}
    ]
    if structured:
        return structured
    # Compatibility with rows fetched before verified_actions became structured:
    # that legacy SQL column was already filtered to resolved/mitigated reviews.
    return [" ".join(item.split())[:_ACTION_MAXLEN] for item in _list(value) if item.strip()]


def _evaluation_review_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _operator_confirms_promoted_family(row: dict[str, Any], family: str) -> bool:
    """Require an exact, successful review for the hash-scoped model family."""
    reviews = _evaluation_review_rows(row.get("evaluation_reviews"))
    if not reviews:
        return False
    successful = False
    for review in reviews:
        case_type = str(review.get("case_type") or "").strip()
        expected = str(review.get("expected_family") or "").strip()
        if case_type in {"known", "compositional"}:
            if not expected:
                if family.startswith("novel_"):
                    return False
                continue
            if expected != family:
                return False
            if str(review.get("resolution_outcome") or "") in {"resolved", "mitigated"}:
                successful = True
        elif case_type == "novel":
            if expected or not family.startswith("novel_"):
                return False
            if str(review.get("resolution_outcome") or "") in {"resolved", "mitigated"}:
                successful = True
        else:
            # tool_degraded (including an optional label) and malformed legacy
            # reviews are useful evaluation data, not promotable knowledge.
            return False
    return successful


def _promotion_from_row(row: dict[str, Any]) -> tuple[str, str, list[str]] | None:
    """(alert_name, family, actions) when the row is promotable, else None.

    Promotable = resolved + Dashboard approval + exact successful operator-family
    confirmation + a non-abstained, evidence-gated analysis + a real alertname.
    Only evaluation-confirmed actions are promoted as remedies.
    """
    if str(row.get("status") or "") != "resolved":
        return None
    if not str(row.get("user_approved_at") or "").strip():
        return None
    harness = _json(row.get("analysis_metadata"))
    if str((harness.get("harness") or {}).get("status") or "") == "abstained":
        return None
    target = resolve_target(_json(row.get("labels")), _json(row.get("annotations")))
    alert_name = (target.alert_name or "").strip()
    if not alert_name or alert_name == "RunAIAlert":  # resolve_target's fallback, not a real name
        return None
    family = str(row.get("root_cause_family") or "").strip()
    if not family or not _operator_confirms_promoted_family(row, family):
        return None
    return alert_name, family, _action_statements(row.get("verified_actions"))[:_ACTION_CAP]


def _promote_one(tx: Any, alert_name: str, family: str, actions: list[str]) -> None:
    """Idempotent knowledge insert (reuses load_knowledge's _exists helpers)."""
    name = f"confirmed:{alert_name}"
    _ensure_cause(tx, family)
    _ensure_symptom(tx, name, [alert_name.strip().lower()])
    _relate_indicates(tx, name, family)
    for statement in actions[:_ACTION_CAP]:
        _ensure_action(tx, statement)
        _relate_resolved_by(tx, name, statement)


def _promote(rows: list[dict[str, Any]]) -> tuple[int, int]:
    from typedb.driver import TransactionType

    from app.ontology.typedb_client import open_driver

    records = [rec for rec in (_promotion_from_row(row) for row in rows) if rec]
    if not records:
        print("promotion: no eligible incidents")
        return 0, 0
    settings = load_settings()
    promoted = failed = 0
    with open_driver(settings) as driver:
        for alert_name, family, actions in records:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    _promote_one(tx, alert_name, family, actions)
                    tx.commit()
                promoted += 1
            except Exception as exc:  # noqa: BLE001 - report and continue the batch
                failed += 1
                print(f"  ! promote {alert_name}: {type(exc).__name__}: {exc}", file=sys.stderr)
    print(f"promotion: {promoted} promoted, {failed} failed")
    return promoted, failed


def _write(incidents: list[OntologyIncident]) -> tuple[int, int]:
    from typedb.driver import TransactionType

    from app.ontology.typedb_client import open_driver

    settings = load_settings()
    written = 0
    failed = 0
    with open_driver(settings) as driver:
        for inc in incidents:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    _write_incident(tx, inc)
                    tx.commit()
                written += 1
            except Exception as exc:  # noqa: BLE001 - report and continue the batch
                failed += 1
                print(f"  ! {inc.incident_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return written, failed


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest backend incidents into TypeDB.")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument(
        "--approved-only",
        action="store_true",
        help="ingest only incidents approved in the dashboard (default behavior)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="override the approval gate for one-off sample/backfill use",
    )
    parser.add_argument(
        "--resolved-grace-hours",
        type=int,
        default=0,
        help="only ingest incidents resolved at least N hours ago (0 = no gate)",
    )
    parser.add_argument(
        "--promote-knowledge",
        action="store_true",
        help="also promote resolved, operator-family-confirmed RCAs "
        "into the knowledge layer (symptom -> root_cause -> action); default off",
    )
    args = parser.parse_args()

    rows = asyncio.run(_fetch(args.limit, args.resolved_grace_hours))
    incidents = [_to_incident(r) for r in rows]
    selected = [i for i in incidents if args.all or bool(i.user_approved_at)]
    skipped = len(incidents) - len(selected)
    print(
        f"fetched {len(incidents)} incident(s); "
        f"ingesting {len(selected)}, skipping {skipped} unapproved"
    )
    written = failed = 0
    if selected:
        written, failed = _write(selected)
        print(f"done: {written} written, {failed} failed")
    if args.promote_knowledge and rows:
        _promote(rows)
    return 1 if failed and not written else 0


if __name__ == "__main__":
    raise SystemExit(main())
