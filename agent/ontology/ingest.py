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
import sys
from typing import Any

from app.collectors.base import resolve_target
from app.config import load_settings
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
       a.alert_id, a.fingerprint, a.occurrence_count, a.occurrence_pods,
       a.labels, a.annotations, a.analysis_summary, a.analysis_detail,
       (SELECT count(*) FROM rca_feedback f
         WHERE f.target_id IN (i.incident_id, a.alert_id)
           AND f.vote = 'up') AS positive_feedback,
       (SELECT count(*) FROM rca_feedback f
         WHERE f.target_id IN (i.incident_id, a.alert_id)
           AND f.vote = 'down') AS negative_feedback,
       (EXISTS (SELECT 1 FROM rca_feedback f
                 WHERE f.target_id IN (i.incident_id, a.alert_id) AND f.vote = 'up')
        OR EXISTS (SELECT 1 FROM rca_comments c
                    WHERE c.target_id IN (i.incident_id, a.alert_id))) AS reviewed
FROM incidents i
JOIN alerts a ON a.incident_id = i.incident_id
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


def _to_incident(row: dict[str, Any]) -> OntologyIncident:
    labels = _json(row.get("labels"))
    annotations = _json(row.get("annotations"))
    target = resolve_target(labels, annotations)
    return OntologyIncident(
        incident_id=str(row["incident_id"]),
        alert_id=str(row.get("alert_id") or ""),
        correlation_key=str(row.get("correlation_key") or ""),
        analysis_summary=str(row.get("analysis_summary") or ""),
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
        reviewed=bool(row.get("reviewed")),
    )


async def _fetch(limit: int, resolved_grace_hours: int = 0) -> list[dict[str, Any]]:
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        print("POSTGRES_DSN not set; skipping ingest.")
        return []
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        if resolved_grace_hours > 0:
            sql = _SELECT_INCIDENTS.format(where=_RESOLVED_GRACE_WHERE)
            rows = await conn.fetch(sql, limit, resolved_grace_hours)
        else:
            rows = await conn.fetch(_SELECT_INCIDENTS.format(where=""), limit)
    finally:
        await conn.close()
    return [dict(r) for r in rows]


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


# --- knowledge promotion (--promote-knowledge) --------------------------------
# Promote operator-CONFIRMED RCAs into the knowledge layer the synthesis step
# consults: symptom "confirmed:{alert_name}" -indicates-> family root_cause,
# -resolved_by-> action(s) from the stored report. The backend does NOT persist
# the agent's ranked_root_cause_candidates (the response `context` dict is
# dropped by the Go store), so the top family is recovered from the stored
# analysis text instead — a printed family label is decisive, otherwise >= 2
# distinct keyword hits with a unique best family. Ambiguity -> skip.

# family -> (decisive label markers, weak keywords). Labels mirror
# orchestrator._family_label / _FAMILY_EXPLANATION output; keywords mirror
# root_cause_ranking._FAMILY_RULES. insufficient_evidence is never promoted.
_FAMILY_MARKERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "node_kubelet_pressure": (
        ("node_kubelet_pressure", "node kubelet pressure", "node hosting this workload is under"),
        ("diskpressure", "memorypressure", "pidpressure", "kubelet", "evict"),
    ),
    "scheduling_quota_exhaustion": (
        ("scheduling_quota_exhaustion", "scheduling quota exhaustion", "queue capacity looks"),
        ("failedscheduling", "unschedulable", "quota", "preempt", "insufficient gpu"),
    ),
    "runai_control_plane_error": (
        ("runai_control_plane_error", "run:ai control-plane error"),
        ("control plane", "control-plane", "admission", "reconcile", "runai-backend"),
    ),
    "workload_startup_image_failure": (
        ("workload_startup_image_failure", "workload startup/image failure"),
        ("imagepullbackoff", "errimagepull", "crashloopbackoff", "oomkilled", "back-off"),
    ),
}

_ACTION_CAP = 3
_ACTION_MAXLEN = 200


def _derive_family(text: str) -> str:
    """Best-effort family from stored analysis text; "" when ambiguous."""
    t = (text or "").lower()
    if not t:
        return ""
    for family, (labels, _) in _FAMILY_MARKERS.items():
        if any(label in t for label in labels):
            return family
    scores = {fam: sum(1 for kw in kws if kw in t) for fam, (_, kws) in _FAMILY_MARKERS.items()}
    top = max(scores.values())
    if top < 2 or sum(1 for s in scores.values() if s == top) > 1:
        return ""
    return max(scores, key=lambda fam: scores[fam])


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


def _promotion_from_row(row: dict[str, Any]) -> tuple[str, str, list[str]] | None:
    """(alert_name, family, actions) when the row is promotable, else None.

    Promotable = resolved + net-positive operator feedback (rca_feedback votes)
    + a recoverable root-cause family + a real alertname label.
    """
    if str(row.get("status") or "") != "resolved":
        return None
    if int(row.get("positive_feedback") or 0) <= int(row.get("negative_feedback") or 0):
        return None
    target = resolve_target(_json(row.get("labels")), _json(row.get("annotations")))
    alert_name = (target.alert_name or "").strip()
    if not alert_name or alert_name == "RunAIAlert":  # resolve_target's fallback, not a real name
        return None
    summary = str(row.get("analysis_summary") or "")
    detail = str(row.get("analysis_detail") or "")
    family = _derive_family(f"{summary}\n{detail}")
    if not family:
        return None
    return alert_name, family, _extract_actions(detail)


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
    parser.add_argument("--all", action="store_true", help="ingest unreviewed incidents too")
    parser.add_argument(
        "--resolved-grace-hours",
        type=int,
        default=0,
        help="only ingest incidents resolved at least N hours ago (0 = no gate)",
    )
    parser.add_argument(
        "--promote-knowledge",
        action="store_true",
        help="also promote operator-confirmed RCAs (resolved + net-positive feedback) "
        "into the knowledge layer (symptom -> root_cause -> action); default off",
    )
    args = parser.parse_args()

    rows = asyncio.run(_fetch(args.limit, args.resolved_grace_hours))
    incidents = [_to_incident(r) for r in rows]
    selected = [i for i in incidents if args.all or i.reviewed]
    skipped = len(incidents) - len(selected)
    print(
        f"fetched {len(incidents)} incident(s); "
        f"ingesting {len(selected)}, skipping {skipped} unreviewed"
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
