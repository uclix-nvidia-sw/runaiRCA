"""TypeDB knowledge-graph collector.

The genuine value the KG adds over pgvector/label-overlap: multi-hop relational
facts. For the PoC it answers two questions the flat collectors can't:
  - blast radius: how many distinct workloads share the alerting node
    (feeds rule R1 in app/services/root_cause_ranking.py), and
  - history: how many past incidents carried this alert.

Degrades gracefully (like the Postgres collector): disabled flag, missing driver,
or any query error -> `unavailable`/`partial`, never an exception that breaks
the analyze fan-out.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings
from app.ontology.typedb_client import TypeDBClient, escape_typeql

_BLAST_QUERY = """
match
  $n isa node, has name "{node}";
  (host: $n, guest: $p) isa runs_on;
  (owner: $w, member: $p) isa belongs_to;
  $w isa workload, has name $wn;
select $wn;
"""

_HISTORY_QUERY = """
match
  $a isa alert, has alert_name "{alert}";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid;
select $iid;
"""


class TypeDBCollector:
    name = "typedb"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        if not self._settings.enable_typedb or not self._settings.typedb_address:
            return self._unavailable(
                "TypeDB knowledge graph is disabled or its address is not configured.",
                ["typedb.address"],
            )

        try:
            import typedb.driver  # noqa: F401 - presence check only
        except ImportError:
            return self._unavailable(
                "typedb-driver is not installed, so knowledge-graph evidence was skipped.",
                ["python.typedb-driver"],
            )

        client = TypeDBClient(self._settings)
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_query_kg, client, target),
                timeout=self._settings.typedb_timeout_seconds + 1,
            )
        except Exception as exc:  # noqa: BLE001 - collector reports diagnostics, not failures
            summary = f"TypeDB query failed: {exc.__class__.__name__}."
            return CollectorResult(
                agent=self.name,
                status="partial",
                summary=summary,
                confidence="low",
                warnings=[summary],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="typedb",
                        type="kg_query",
                        status="partial",
                        confidence="low",
                        summary=summary,
                        result={"error_type": exc.__class__.__name__},
                    )
                ],
            )

        blast = data["blast_radius_workloads"]
        history = data["historical_incident_count"]
        summary = (
            f"Knowledge graph: {blast} workload(s) share node "
            f"{target.node or 'unknown'}; this alert appears in {history} past incident(s)."
        )
        return CollectorResult(
            agent=self.name,
            status="ok",
            summary=summary,
            confidence="medium",
            details=data,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="typedb",
                    type="kg_query",
                    status="ok",
                    confidence="medium",
                    query=f"blast_radius(node={target.node}); history(alert={target.alert_name})",
                    summary=summary,
                    result=data,
                )
            ],
        )

    def _unavailable(self, summary: str, missing: list[str]) -> CollectorResult:
        return CollectorResult(
            agent=self.name,
            status="unavailable",
            summary=summary,
            confidence="low",
            missing_data=missing,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="typedb",
                    type="kg_query",
                    status="unavailable",
                    confidence="low",
                    summary=summary,
                    result={"enabled": self._settings.enable_typedb},
                )
            ],
        )


def _query_kg(client: TypeDBClient, target: AnalysisTarget) -> dict[str, Any]:
    workloads: list[str] = []
    if target.node:
        rows = client.fetch_rows(_BLAST_QUERY.format(node=escape_typeql(target.node)))
        workloads = sorted({str(r.get("wn")) for r in rows if r.get("wn")})

    incidents: set[str] = set()
    if target.alert_name:
        rows = client.fetch_rows(_HISTORY_QUERY.format(alert=escape_typeql(target.alert_name)))
        incidents = {str(r.get("iid")) for r in rows if r.get("iid")}

    return {
        "blast_radius_workloads": len(workloads),
        "blast_radius_workload_names": workloads[:20],
        "historical_incident_count": len(incidents),
        "node": target.node,
        "alert_name": target.alert_name,
    }
