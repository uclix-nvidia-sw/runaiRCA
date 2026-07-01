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

_SELECT_INCIDENTS = """
SELECT i.incident_id, i.correlation_key, i.title, i.severity, i.status,
       i.fired_at::text AS fired_at,
       a.alert_id, a.fingerprint, a.occurrence_count, a.occurrence_pods,
       a.labels, a.annotations, a.analysis_summary,
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
    tx: Any, etype: str, key_attr: str, key_value: str, attr: str, new_value: Any, quoted: bool = True
) -> None:
    # Remove any existing value of `attr`, then set the new one. Replace (not
    # add-if-missing) so a re-projected incident whose RCA/status changed after a
    # re-open+re-analysis updates in place instead of accumulating stale values —
    # required, since owns defaults to @card(0..1) so a second value fails commit.
    # quoted=False for non-string attributes (e.g. integer occurrence_count).
    tx.query(
        f'match $x isa {etype}, has {key_attr} "{esc(key_value)}", has {attr} $old; '
        f"delete has $old of $x;"  # TypeDB 3.x: `delete has <attr> of <owner>` (2.x was `delete $x has $old`)
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
    args = parser.parse_args()

    rows = asyncio.run(_fetch(args.limit, args.resolved_grace_hours))
    incidents = [_to_incident(r) for r in rows]
    selected = [i for i in incidents if args.all or i.reviewed]
    skipped = len(incidents) - len(selected)
    print(
        f"fetched {len(incidents)} incident(s); "
        f"ingesting {len(selected)}, skipping {skipped} unreviewed"
    )
    if not selected:
        return 0
    written, failed = _write(selected)
    print(f"done: {written} written, {failed} failed")
    return 1 if failed and not written else 0


if __name__ == "__main__":
    raise SystemExit(main())
