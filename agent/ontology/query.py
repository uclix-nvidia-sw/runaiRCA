"""Read-only introspection of the TypeDB knowledge graph.

For verifying what the ingest cronjob actually projected — "is this incident in
the graph yet?" — without hand-writing TypeQL. Reuses the same client the
synthesis path uses, so it sees exactly what enrich() would.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=<host>:1729 \
        python -m ontology.query --incident INC-...-000023
    python -m ontology.query --recent 20
    python -m ontology.query --count
    python -m ontology.query --alert "Memory major page faults are occurring at very high rate."
    python -m ontology.query --raw 'match $i isa incident, has title $t; select $t;'

In-cluster (agent pod already has the driver + TYPEDB_* env):
    kubectl exec -n <ns> deploy/<release>-agent -- python -m ontology.query --incident INC-...
"""

from __future__ import annotations

import argparse
import sys

from app.config import load_settings
from app.ontology.typedb_client import TypeDBClient
from app.ontology.typedb_client import escape_typeql as esc


def _rows(client: TypeDBClient, typeql: str) -> list[dict]:
    try:
        return client.fetch_rows(typeql)
    except Exception as exc:  # noqa: BLE001 - a CLI: report, don't traceback-spam
        print(f"query failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return []


def _incident(client: TypeDBClient, incident_id: str) -> int:
    rows = _rows(
        client,
        f'match $i isa incident, has incident_id "{esc(incident_id)}", '
        f"has title $t, has status $st, has severity $sv, has analysis_summary $s; "
        f"select $t, $st, $sv, $s;",
    )
    if not rows:
        print(f"NOT in the graph: {incident_id}")
        print("(not ingested yet, or the id is wrong — try --recent to see what IS there)")
        return 1
    r = rows[0]
    print(f"incident_id      {incident_id}")
    print(f"title            {r.get('t')}")
    print(f"status/severity  {r.get('st')} / {r.get('sv')}")
    print(f"analysis_summary {r.get('s') or '(empty)'}")
    # Linked alert(s) via grouped_into.
    alerts = _rows(
        client,
        f'match $i isa incident, has incident_id "{esc(incident_id)}"; '
        f"(incident: $i, member: $a) isa grouped_into; "
        f"$a isa alert, has alert_name $an, has occurrence_count $oc; select $an, $oc;",
    )
    for a in alerts:
        print(f"alert            {a.get('an')} (occurrences: {a.get('oc')})")
    return 0


def _recent(client: TypeDBClient, limit: int) -> int:
    rows = _rows(
        client,
        "match $i isa incident, has incident_id $id, has title $t, has status $st; "
        f"select $id, $t, $st; limit {max(1, limit)};",
    )
    if not rows:
        print("no incidents in the graph yet.")
        return 1
    for r in rows:
        print(f"{r.get('id')}  [{r.get('st')}]  {r.get('t')}")
    print(f"\n{len(rows)} incident(s) shown.")
    return 0


def _by_alert(client: TypeDBClient, alert_name: str) -> int:
    rows = _rows(
        client,
        f'match $a isa alert, has alert_name "{esc(alert_name)}"; '
        f"(incident: $i, member: $a) isa grouped_into; "
        f"$i isa incident, has incident_id $id, has status $st, has analysis_summary $s; "
        f"select $id, $st, $s;",
    )
    if not rows:
        print(f"no incident in the graph for alert: {alert_name!r}")
        return 1
    for r in rows:
        print(f"{r.get('id')}  [{r.get('st')}]  {r.get('s') or '(no summary)'}")
    return 0


def _count(client: TypeDBClient) -> int:
    for etype, key in (("incident", "incident_id"), ("alert", "alert_id"), ("node", "name")):
        rows = _rows(client, f"match $x isa {etype}, has {key} $k; select $k;")
        print(f"{etype:10} {len(rows)}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only TypeDB knowledge-graph introspection.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--incident", metavar="ID", help="look up one incident by incident_id")
    g.add_argument("--alert", metavar="NAME", help="incidents linked to an alert name")
    g.add_argument("--recent", nargs="?", type=int, const=20, metavar="N", help="list N incidents")
    g.add_argument("--count", action="store_true", help="count incidents / alerts / nodes")
    g.add_argument("--raw", metavar="TYPEQL", help="run a raw read query (must `select`)")
    args = p.parse_args()

    settings = load_settings()
    if not settings.typedb_address:
        print("TYPEDB_ADDRESS is not set (and ENABLE_TYPEDB). Nothing to query.", file=sys.stderr)
        return 2
    client = TypeDBClient(settings)

    if args.incident:
        return _incident(client, args.incident)
    if args.alert:
        return _by_alert(client, args.alert)
    if args.recent is not None:
        return _recent(client, args.recent)
    if args.count:
        return _count(client)
    for row in _rows(client, args.raw):
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
