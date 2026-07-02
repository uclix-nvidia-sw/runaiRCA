"""Synthesis-time knowledge-graph enrichment.

The ontology knowledge graph is NOT a parallel evidence collector. It is a
knowledge resource the final synthesis/analysis step consults once to make a
better, grounded RCA: node blast radius (relational impact pgvector can't see)
and prior incidents that fired the same alert, with their past RCA.

Queried a single time per analysis (centralized at synthesis) to keep load low.
Degrades to an empty, "available: false" context when TypeDB is disabled,
the driver is missing, or the server is unreachable — never raises into analyze.

ponytail: same-alert recurrence + node blast radius are the cheap, high-value
signals available from the topology already ingested. Same-node neighbours and
confirmed cause->action edges are a later enrichment (needs richer ingestion).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from app.collectors.base import AnalysisTarget
from app.config import Settings
from app.ontology.typedb_client import TypeDBClient, escape_typeql

_log = logging.getLogger(__name__)

_BLAST_QUERY = """
match
  $n isa node, has name "{node}";
  (host: $n, guest: $p) isa runs_on;
  (owner: $w, member: $p) isa belongs_to;
  $w isa workload, has name $wn;
select $wn;
"""

_PRIOR_QUERY = """
match
  $a isa alert, has alert_name "{alert}";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid, has analysis_summary $sum;
select $iid, $sum;
"""

# Validated TypeDB 3.x reasoning functions (ontology/functions.tql). Called after
# ranking to pull graph-derived remediation. The `match let $x in <fn>(<arg>);
# select $x;` call form is the validated 3.11.x syntax — do not "simplify" it.
_FN_FIXES_FOR_FAMILY = 'match let $x in fixes_for_family("{family}"); select $x;'
_FN_FIXES_FOR_XID = "match let $x in fixes_for_xid({code}); select $x;"
_FN_XIDS_FOR_GPU_MODEL = 'match let $x in xids_for_gpu_model("{model}"); select $x;'

# Curated failure-mode knowledge (knowledge layer), loaded by
# ontology/load_knowledge.py: family -> symptom(keywords) -> action. The synthesis
# matches the incident's evidence against the keywords to pick precise actions.
_KNOWLEDGE_QUERY = """
match
  $rc isa root_cause, has subtype $fam;
  (symptom: $sy, cause: $rc) isa indicates;
  $sy isa symptom, has name $sn, has keyword $kw;
  (symptom: $sy, remedy: $ac) isa resolved_by;
  $ac isa action, has statement $st;
select $fam, $sn, $kw, $st;
"""


@dataclass
class KGContext:
    enabled: bool = False
    available: bool = False
    blast_radius_workloads: int = 0
    blast_radius_workload_names: list[str] = field(default_factory=list)
    prior_incidents: list[dict[str, str]] = field(default_factory=list)
    # family -> [{symptom, keywords[], actions[]}]  (curated knowledge layer)
    knowledge: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "available": self.available,
            "blast_radius_workloads": self.blast_radius_workloads,
            "blast_radius_workload_names": self.blast_radius_workload_names,
            "prior_incidents": self.prior_incidents,
            "knowledge": self.knowledge,
            "warnings": self.warnings,
        }


async def enrich(settings: Settings, target: AnalysisTarget) -> KGContext:
    if not settings.enable_typedb or not settings.typedb_address:
        return KGContext(enabled=False, available=False)

    try:
        import typedb.driver  # noqa: F401 - presence check only
    except ImportError:
        return KGContext(
            enabled=True,
            available=False,
            warnings=["typedb-driver is not installed; knowledge-graph context skipped."],
        )

    client = TypeDBClient(settings)
    try:
        data = await asyncio.wait_for(
            asyncio.to_thread(_query_kg, client, target),
            timeout=settings.typedb_timeout_seconds + 1,
        )
    except Exception as exc:  # noqa: BLE001 - enrichment is best-effort, never fatal
        # Full traceback to pod logs, and the actual message (not just the class
        # name) into warnings, so "unreachable" can be diagnosed: connection
        # refused vs auth vs a [TQLxx] query-syntax error look identical otherwise.
        _log.warning("TypeDB knowledge-graph enrichment failed", exc_info=True)
        detail = " ".join(str(exc).split())[:200] or exc.__class__.__name__
        return KGContext(
            enabled=True,
            available=False,
            warnings=[
                f"TypeDB knowledge-graph query failed ({exc.__class__.__name__}): {detail}"
            ],
        )

    return KGContext(
        enabled=True,
        available=True,
        blast_radius_workloads=data["blast_radius_workloads"],
        blast_radius_workload_names=data["blast_radius_workload_names"],
        prior_incidents=data["prior_incidents"],
        knowledge=data["knowledge"],
    )


@dataclass
class GraphRemediation:
    """Graph-derived remediation from the validated TypeDB reasoning functions."""

    family_fixes: list[str] = field(default_factory=list)
    xid_fixes: dict[int, list[str]] = field(default_factory=dict)
    model_xids: dict[str, list[int]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.family_fixes or self.xid_fixes or self.model_xids)

    def as_dict(self) -> dict[str, Any]:
        return {
            "family_fixes": self.family_fixes,
            "xid_fixes": {str(k): v for k, v in self.xid_fixes.items()},
            "model_xids": {k: v for k, v in self.model_xids.items()},
            "warnings": self.warnings,
        }


async def graph_remediation(
    settings: Settings,
    *,
    family: str = "",
    xid_codes: list[int] | None = None,
    gpu_model: str = "",
) -> GraphRemediation:
    """Best-effort graph-derived remediation via the validated reasoning functions.

    Runs AFTER ranking: fixes_for_family(top_family), fixes_for_xid(N) for any Xid
    codes found in evidence, xids_for_gpu_model(M) when a model is derivable.
    Degrades to an empty result (never raises) when TypeDB is disabled/unreachable,
    the driver is missing, or the functions are not defined in the schema.
    """
    xid_codes = xid_codes or []
    if not settings.enable_typedb or not settings.typedb_address:
        return GraphRemediation()
    if not (family or xid_codes or gpu_model):
        return GraphRemediation()
    try:
        import typedb.driver  # noqa: F401 - presence check only
    except ImportError:
        return GraphRemediation(
            warnings=["typedb-driver is not installed; graph remediation skipped."]
        )

    client = TypeDBClient(settings)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_query_remediation, client, family, xid_codes, gpu_model),
            timeout=settings.typedb_timeout_seconds + 1,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort; never fatal to analyze
        _log.warning("TypeDB graph-remediation query failed", exc_info=True)
        detail = " ".join(str(exc).split())[:200] or exc.__class__.__name__
        return GraphRemediation(
            warnings=[f"Graph remediation lookup failed ({exc.__class__.__name__}): {detail}"]
        )


def _query_remediation(
    client: TypeDBClient,
    family: str,
    xid_codes: list[int],
    gpu_model: str,
) -> GraphRemediation:
    out = GraphRemediation()
    with client.open_reader() as run:
        if family:
            rows = run(_FN_FIXES_FOR_FAMILY.format(family=escape_typeql(family)))
            out.family_fixes = _statements(rows)
        for code in dict.fromkeys(xid_codes):  # de-dupe, preserve order
            rows = run(_FN_FIXES_FOR_XID.format(code=int(code)))
            fixes = _statements(rows)
            if fixes:
                out.xid_fixes[int(code)] = fixes
        if gpu_model:
            rows = run(_FN_XIDS_FOR_GPU_MODEL.format(model=escape_typeql(gpu_model)))
            xids = sorted({int(v) for v in _values(rows) if _is_int(v)})
            if xids:
                out.model_xids[gpu_model] = xids
    return out


def _statements(rows: list[dict[str, Any]]) -> list[str]:
    """Distinct non-empty string values from a single-column function result row set."""
    seen: list[str] = []
    for value in _values(rows):
        text = str(value).strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def _values(rows: list[dict[str, Any]]) -> list[Any]:
    # Function results bind to `$x` (select $x), but tolerate any single column.
    out: list[Any] = []
    for row in rows:
        if "x" in row:
            out.append(row["x"])
        else:
            out.extend(v for v in row.values() if v is not None)
    return out


def _is_int(value: Any) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


def _query_kg(client: TypeDBClient, target: AnalysisTarget) -> dict[str, Any]:
    # One connection for all three synthesis queries: a transient connect blip on
    # any single fresh connection would fail the whole enrichment, so opening once
    # (instead of per query) shrinks that failure surface ~3x.
    with client.open_reader() as run:
        workloads: list[str] = []
        if target.node:
            rows = run(_BLAST_QUERY.format(node=escape_typeql(target.node)))
            workloads = sorted({str(r.get("wn")) for r in rows if r.get("wn")})

        prior: list[dict[str, str]] = []
        if target.alert_name:
            rows = run(_PRIOR_QUERY.format(alert=escape_typeql(target.alert_name)))
            seen: set[str] = set()
            for r in rows:
                iid = str(r.get("iid") or "")
                if iid and iid not in seen:
                    seen.add(iid)
                    prior.append(
                        {"incident_id": iid, "analysis_summary": str(r.get("sum") or "")}
                    )

        knowledge_rows = run(_KNOWLEDGE_QUERY)

    grouped: dict[tuple[str, str], dict[str, set[str]]] = {}
    for r in knowledge_rows:
        fam = str(r.get("fam") or "")
        sname = str(r.get("sn") or "")
        if not fam or not sname:
            continue
        entry = grouped.setdefault((fam, sname), {"keywords": set(), "actions": set()})
        if r.get("kw"):
            entry["keywords"].add(str(r["kw"]))
        if r.get("st"):
            entry["actions"].add(str(r["st"]))
    knowledge: dict[str, list[dict[str, Any]]] = {}
    for (fam, sname), entry in grouped.items():
        knowledge.setdefault(fam, []).append(
            {
                "symptom": sname,
                "keywords": sorted(entry["keywords"]),
                "actions": sorted(entry["actions"]),
            }
        )

    return {
        "blast_radius_workloads": len(workloads),
        "blast_radius_workload_names": workloads[:20],
        "prior_incidents": prior[:5],
        "knowledge": knowledge,
    }
