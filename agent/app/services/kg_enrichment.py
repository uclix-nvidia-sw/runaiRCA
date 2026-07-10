"""Planning and synthesis knowledge-graph enrichment.

The ontology knowledge graph is NOT a parallel evidence collector. It is a
knowledge resource the pipeline consults once before planning, then reuses for
collector guidance and final synthesis: executable diagnostics, node blast
radius, and prior incidents that fired the same alert with their past RCA.

Queried a single time per analysis (centralized in enrich_stage) to keep load low.
Degrades to an empty, "available: false" context when TypeDB is disabled,
the driver is missing, or the server is unreachable — never raises into analyze.

ponytail: same-alert recurrence + node blast radius are the cheap, high-value
signals available from the topology already ingested. Same-node neighbours and
confirmed cause->action edges are a later enrichment (needs richer ingestion).
"""

from __future__ import annotations

import asyncio
import json
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
# Reverse leads_to: the root fault(s) that escalate INTO an observed XID.
_FN_ROOT_XIDS_FOR = "match let $x in root_xids_for({code}); select $x;"
_FN_ANCESTOR_XIDS_FOR = "match let $x in ancestor_xids_for({code}); select $x;"
_FN_CAUSES_FOR_SYMPTOM = 'match let $x in causes_for_symptom("{symptom}"); select $x;'
_FN_DEPENDENCIES_FOR_COMPONENT = 'match let $x in dependencies_for_component("{component}"); select $x;'
_FN_CHECKS_FOR_COMPONENT_PATH = 'match let $x, $y in checks_for_component_path("{component}"); select $x, $y;'
_FN_VERIFIED_ACTIONS_FOR_FAMILY = 'match let $x in verified_actions_for_family("{family}"); select $x;'

_DIAGNOSTIC_RUNBOOK = "k8s-senior-troubleshooting"
_FN_DIAGNOSTIC_STEPS = (
    'match let $id, $q, $v, $i, $a, $m in diagnostic_steps_for_runbook("{runbook}"); '
    "select $id, $q, $v, $i, $a, $m;"
)
_FN_DIAGNOSTIC_ENTRY = (
    'match let $id in entry_steps_for_runbook("{runbook}"); select $id;'
)
_FN_DIAGNOSTIC_TRANSITIONS = (
    'match let $pid, $nid, $m, $priority in diagnostic_transitions_for_runbook("{runbook}"); '
    "select $pid, $nid, $m, $priority;"
)
_FN_DIAGNOSTIC_OUTCOMES = (
    'match let $id, $family, $sum, $conf in diagnostic_outcomes_for_runbook("{runbook}"); '
    "select $id, $family, $sum, $conf;"
)
_FN_DIAGNOSTIC_ACTIONS = (
    'match let $id, $st, $seq in diagnostic_actions_for_runbook("{runbook}"); '
    "select $id, $st, $seq;"
)
_FN_DIAGNOSTIC_DISCONFIRM = (
    'match let $id, $d in diagnostic_disconfirmations_for_runbook("{runbook}"); '
    "select $id, $d;"
)

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
    reasoning: dict[str, Any] = field(default_factory=dict)
    # Executable diagnostic graph projected from TypeDB. Empty means the caller
    # should use the version-controlled YAML fallback.
    diagnostic_tree: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "available": self.available,
            "blast_radius_workloads": self.blast_radius_workloads,
            "blast_radius_workload_names": self.blast_radius_workload_names,
            "prior_incidents": self.prior_incidents,
            "knowledge": self.knowledge,
            "reasoning": self.reasoning,
            "diagnostic_tree": self.diagnostic_tree,
            "warnings": self.warnings,
        }

    def public_dict(self) -> dict[str, Any]:
        """Operator context without duplicating the full 64-node graph payload."""
        payload = self.as_dict()
        tree = payload.pop("diagnostic_tree", {})
        payload["diagnostic_runbook"] = {
            "available": bool(tree),
            "steps": len(tree.get("nodes") or {}) if isinstance(tree, dict) else 0,
        }
        return payload


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
        reasoning=data["reasoning"],
        diagnostic_tree=data["diagnostic_tree"],
    )


@dataclass
class GraphRemediation:
    """Graph-derived remediation from the validated TypeDB reasoning functions."""

    family_fixes: list[str] = field(default_factory=list)
    xid_fixes: dict[int, list[str]] = field(default_factory=dict)
    model_xids: dict[str, list[int]] = field(default_factory=dict)
    # observed XID -> root XID(s) that escalate into it, walked TRANSITIVELY back
    # along the leads_to chain (nearest hop first). E.g. observing 154 with chain
    # 144 -> 48 -> 154 yields [48, 144]: both the near cause and the true origin.
    root_xids: dict[int, list[int]] = field(default_factory=dict)
    verified_actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.family_fixes
            or self.xid_fixes
            or self.model_xids
            or self.root_xids
            or self.verified_actions
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "family_fixes": self.family_fixes,
            "xid_fixes": {str(k): v for k, v in self.xid_fixes.items()},
            "model_xids": {k: v for k, v in self.model_xids.items()},
            "root_xids": {str(k): v for k, v in self.root_xids.items()},
            "verified_actions": self.verified_actions,
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
            try:
                out.verified_actions = _statements(
                    run(_FN_VERIFIED_ACTIONS_FOR_FAMILY.format(family=escape_typeql(family)))
                )
            except Exception:  # noqa: BLE001 - older graph function set remains usable
                pass
        for raw_code in dict.fromkeys(xid_codes):  # de-dupe, preserve order
            code = int(raw_code)
            fixes = _statements(run(_FN_FIXES_FOR_XID.format(code=code)))
            if fixes:
                out.xid_fixes[code] = fixes
            # Drill to the ROOT of the leads_to causal chain: which fault(s)
            # escalate INTO this observed XID. root_xids_for is one hop back, so
            # we walk it TRANSITIVELY (bounded BFS) — a chain 144 → 48 → 154 must
            # surface 144 as the origin of 154, not just the intermediate 48.
            # Surfacing the true root (and its fix) is the ontology's precision
            # win: fix the origin, not the downstream symptom. root_xids_for is
            # newer than the validated functions, so a query error must NOT wipe
            # the fixes above: _root_chain_for isolates per-hop failures.
            try:
                roots = [int(v) for v in _values(run(_FN_ANCESTOR_XIDS_FOR.format(code=code))) if _is_int(v)]
            except Exception:  # noqa: BLE001 - retain the validated one-hop fallback
                roots = _root_chain_for(run, code)
            if not roots:
                # Older deployments may accept the function call but not have
                # the new definition yet; keep the established one-hop walk.
                roots = _root_chain_for(run, code)
            if roots:
                out.root_xids[code] = roots
                for root in roots:
                    if root not in out.xid_fixes:
                        rfixes = _statements(run(_FN_FIXES_FOR_XID.format(code=root)))
                        if rfixes:
                            out.xid_fixes[root] = rfixes
        if gpu_model:
            rows = run(_FN_XIDS_FOR_GPU_MODEL.format(model=escape_typeql(gpu_model)))
            xids = sorted({int(v) for v in _values(rows) if _is_int(v)})
            if xids:
                out.model_xids[gpu_model] = xids
    return out


# Cap the causal walk so a mis-loaded cyclic edge can never spin forever and the
# root list stays operator-legible. Real XID chains are short (<= a few hops).
_MAX_CHAIN_NODES = 16
_MAX_CHAIN_DEPTH = 6


def _root_chain_for(run: Any, code: int) -> list[int]:
    """Transitive ancestors of `code` along leads_to, nearest hop first.

    Repeatedly applies the validated one-hop `root_xids_for` backward from the
    observed code, accumulating every fault that (directly or indirectly)
    escalates into it. Cycle-safe (visited set) and bounded (`_MAX_CHAIN_*`).
    Best-effort: a failed hop is skipped, never fatal.
    """
    ordered: list[int] = []
    seen: set[int] = {code}
    frontier: list[int] = [code]
    depth = 0
    while frontier and depth < _MAX_CHAIN_DEPTH and len(ordered) < _MAX_CHAIN_NODES:
        depth += 1
        nxt: list[int] = []
        for cur in frontier:
            try:
                rows = run(_FN_ROOT_XIDS_FOR.format(code=cur))
            except Exception:  # noqa: BLE001 - best-effort drill-down, never fatal
                continue
            for value in _values(rows):
                if not _is_int(value):
                    continue
                root = int(value)
                if root in seen:
                    continue
                seen.add(root)
                ordered.append(root)
                nxt.append(root)
                if len(ordered) >= _MAX_CHAIN_NODES:
                    break
            if len(ordered) >= _MAX_CHAIN_NODES:
                break
        frontier = nxt
    return ordered


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
        reasoning: dict[str, Any] = {}
        component = target.workload_name
        if component:
            try:
                dependencies = _values(
                    run(_FN_DEPENDENCIES_FOR_COMPONENT.format(component=escape_typeql(component)))
                )
                reasoning["dependencies"] = sorted({str(item) for item in dependencies if item})[:30]
                checks = run(_FN_CHECKS_FOR_COMPONENT_PATH.format(component=escape_typeql(component)))
                reasoning["component_checks"] = [
                    {"component": str(row.get("x") or ""), "check": str(row.get("y") or "")}
                    for row in checks
                    if row.get("x") and row.get("y")
                ][:30]
            except Exception as exc:  # noqa: BLE001 - YAML topology remains the fallback
                reasoning["warning"] = f"ontology component reasoning unavailable: {type(exc).__name__}"
        try:
            diagnostic_tree = _query_diagnostic_tree(run)
        except Exception:  # noqa: BLE001 - old schema during rolling upgrades
            _log.warning("TypeDB diagnostic runbook query failed; YAML fallback will be used")
            diagnostic_tree = {}

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
        "reasoning": reasoning,
        "diagnostic_tree": diagnostic_tree,
    }


async def candidate_families_for_symptoms(
    settings: Settings, symptom_names: list[str]
) -> tuple[dict[str, int], list[str]]:
    """Return small graph priors for symptoms already observed live in this run."""
    names = list(dict.fromkeys(name.strip() for name in symptom_names if name.strip()))[:12]
    if not names or not settings.enable_typedb or not settings.typedb_address:
        return {}, []
    try:
        import typedb.driver  # noqa: F401
    except ImportError:
        return {}, ["typedb-driver is not installed; candidate reasoning skipped."]
    client = TypeDBClient(settings)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_query_candidate_families, client, names),
            timeout=settings.typedb_timeout_seconds + 1,
        )
    except Exception as exc:  # noqa: BLE001 - no graph prior is safer than a failed RCA
        return {}, [f"ontology candidate reasoning unavailable: {type(exc).__name__}"]


def _query_candidate_families(client: TypeDBClient, names: list[str]) -> tuple[dict[str, int], list[str]]:
    counts: dict[str, int] = {}
    with client.open_reader() as run:
        for name in names:
            rows = run(_FN_CAUSES_FOR_SYMPTOM.format(symptom=escape_typeql(name)))
            for family in _values(rows):
                value = str(family).strip()
                if value:
                    counts[value] = counts.get(value, 0) + 1
    return counts, []


def _query_diagnostic_tree(run: Any) -> dict[str, Any]:
    runbook = escape_typeql(_DIAGNOSTIC_RUNBOOK)
    step_rows = run(_FN_DIAGNOSTIC_STEPS.format(runbook=runbook))
    entry_rows = run(_FN_DIAGNOSTIC_ENTRY.format(runbook=runbook))
    if not step_rows or not entry_rows:
        return {}

    nodes: dict[str, dict[str, Any]] = {}
    for row in step_rows:
        step_id = str(row.get("id") or "")
        if not step_id:
            continue
        nodes[step_id] = {
            "id": step_id,
            "question": str(row.get("q") or ""),
            "verify": str(row.get("v") or ""),
            "interpretation": str(row.get("i") or ""),
            "avoid": str(row.get("a") or ""),
            "match": _json_object(row.get("m")),
        }

    transitions = run(_FN_DIAGNOSTIC_TRANSITIONS.format(runbook=runbook))
    for row in sorted(transitions, key=lambda item: int(item.get("priority") or 0)):
        prior = nodes.get(str(row.get("pid") or ""))
        next_id = str(row.get("nid") or "")
        if prior is None or next_id not in nodes:
            continue
        prior.setdefault("branches", []).append(
            {"match": _json_object(row.get("m")), "next": next_id}
        )

    for row in run(_FN_DIAGNOSTIC_OUTCOMES.format(runbook=runbook)):
        node = nodes.get(str(row.get("id") or ""))
        if node is None:
            continue
        node["conclusion"] = {
            "family": str(row.get("family") or ""),
            "summary": str(row.get("sum") or ""),
            "confidence": str(row.get("conf") or ""),
            "next_steps": [],
        }

    action_rows = run(_FN_DIAGNOSTIC_ACTIONS.format(runbook=runbook))
    for row in sorted(action_rows, key=lambda item: int(item.get("seq") or 0)):
        conclusion = (nodes.get(str(row.get("id") or "")) or {}).get("conclusion")
        if isinstance(conclusion, dict) and row.get("st"):
            conclusion["next_steps"].append(str(row["st"]))

    for row in run(_FN_DIAGNOSTIC_DISCONFIRM.format(runbook=runbook)):
        conclusion = (nodes.get(str(row.get("id") or "")) or {}).get("conclusion")
        if isinstance(conclusion, dict) and row.get("d"):
            conclusion.setdefault("disconfirm", []).append(str(row["d"]))

    principle_rows = run(
        f'match $r isa runbook, has name "{runbook}", has principle $p; select $p;'
    )
    source_rows = run(
        f'match $r isa runbook, has name "{runbook}", has source_url $s; select $s;'
    )
    root = str(entry_rows[0].get("id") or "")
    if root not in nodes:
        return {}
    return {
        "root": root,
        "nodes": nodes,
        "principles": sorted({str(row["p"]) for row in principle_rows if row.get("p")}),
        "sources": sorted({str(row["s"]) for row in source_rows if row.get("s")}),
    }


def _json_object(value: object) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}
