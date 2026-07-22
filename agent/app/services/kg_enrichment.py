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
from app.knowledge import _keyword_hits
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
  $i isa incident, has incident_id $iid, has analysis_summary $sum, has status "resolved";
  $case isa case_snapshot, has approval_state "active", has case_id $case_id;
  $diagnosis isa diagnosis, links (incident: $i, cause: $cause);
  (case: $case, finding: $diagnosis) isa case_projection;
  $cause has subtype $family;
select $iid, $sum, $case_id, $family;
"""

_CASE_BY_INCIDENT_QUERY = """
match
  $i isa incident, has incident_id "{incident_id}", has analysis_summary $sum, has status "resolved";
  $case isa case_snapshot, has approval_state "active", has case_id $case_id;
  $diagnosis isa diagnosis, links (incident: $i, cause: $cause);
  (case: $case, finding: $diagnosis) isa case_projection;
  $cause has subtype $family;
select $sum, $case_id, $family;
"""

# CaseCards deliberately retrieve graph links separately from the immutable
# JSON projection. That keeps operator review outcomes/evidence relations
# queryable without requiring optional TypeQL attributes on legacy snapshots.
_CASE_CARD_QUERY = """
match
  $case isa case_snapshot, has case_id "{case_id}", has case_card $card;
select $card;
"""
_CASE_CARD_EVIDENCE_QUERY = """
match
  $case isa case_snapshot, has case_id "{case_id}";
  (case: $case, finding: $diagnosis) isa case_projection;
  $link isa {relation}, links (claim: $diagnosis, proof: $evidence);
  $evidence isa evidence, has evidence_id $evidence_id, has source $source;
select $evidence_id, $source;
"""
_CASE_CARD_ACTIONS_QUERY = """
match
  $case isa case_snapshot, has case_id "{case_id}";
  (case: $case, finding: $diagnosis) isa case_projection;
  $resolution isa resolution, links (finding: $diagnosis, remedy: $action), has outcome $outcome;
  $action isa action, has statement $statement;
select $statement, $outcome;
"""

# Validated TypeDB 3.x reasoning functions (ontology/functions.tql). Called after
# ranking to pull signature-specific graph remediation. The `match let $x in <fn>(<arg>);
# select $x;` call form is the validated 3.11.x syntax — do not "simplify" it.
_FN_FIXES_FOR_XID = "match let $x in fixes_for_xid({code}); select $x;"
_FN_TRIGGER_FOR_XID = "match let $x in trigger_for_xid({code}); select $x;"
_FN_XIDS_FOR_GPU_MODEL = 'match let $x in xids_for_gpu_model("{model}"); select $x;'
# Reverse leads_to: the root fault(s) that escalate INTO an observed XID.
_FN_ROOT_XIDS_FOR = "match let $x in root_xids_for({code}); select $x;"
_FN_CAUSES_FOR_SYMPTOM = 'match let $x in causes_for_symptom("{symptom}"); select $x;'
_FN_DEPENDENCIES_FOR_COMPONENT = 'match let $x in dependencies_for_component("{component}"); select $x;'
_FN_CHECKS_FOR_COMPONENT_PATH = 'match let $x, $y in checks_for_component_path("{component}"); select $x, $y;'

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
_FN_DIAGNOSTIC_PROBES = (
    'match let $id, $probe in diagnostic_probes_for_runbook("{runbook}"); select $id, $probe;'
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

_KNOWLEDGE_REASON_QUERY = """
match
  $sy isa symptom, has name $sn, has reason $reason;
select $sn, $reason;
"""

_KNOWLEDGE_EXCLUSIVE_ACTIONS_QUERY = """
match
  $sy isa symptom, has name $sn, has exclusive_actions $exclusive_actions;
select $sn, $exclusive_actions;
"""

_KNOWLEDGE_REASON_KO_QUERY = """
match
  $sy isa symptom, has name $sn, has reason_ko $reason_ko;
select $sn, $reason_ko;
"""

_KNOWLEDGE_COMPONENT_QUERY = """
match
  $sy isa symptom, has name $sn, has component $component;
select $sn, $component;
"""

_KNOWLEDGE_NAME_KO_QUERY = """
match
  $sy isa symptom, has name $sn, has name_ko $name_ko;
select $sn, $name_ko;
"""

_KNOWLEDGE_ACTIONS_KO_QUERY = """
match
  $sy isa symptom, has name $sn, has statement_ko $statement_ko;
select $sn, $statement_ko;
"""


@dataclass
class KGContext:
    enabled: bool = False
    available: bool = False
    blast_radius_workloads: int = 0
    blast_radius_workload_names: list[str] = field(default_factory=list)
    prior_incidents: list[dict[str, str]] = field(default_factory=list)
    case_cards: list[dict[str, Any]] = field(default_factory=list)
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
            "case_cards": self.case_cards,
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


async def enrich(
    settings: Settings,
    target: AnalysisTarget,
    similar_incidents: list[Any] | None = None,
) -> KGContext:
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
            asyncio.to_thread(_query_kg, client, target, similar_incidents or []),
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
        case_cards=data["case_cards"],
        knowledge=data["knowledge"],
        reasoning=data["reasoning"],
        diagnostic_tree=data["diagnostic_tree"],
    )


@dataclass
class GraphRemediation:
    """Graph-derived remediation from the validated TypeDB reasoning functions."""

    # Legacy response fields retained for compatibility. Production lookup no
    # longer populates them: flattening symptom actions or historical outcomes
    # by family destroys symptom->action provenance.
    family_fixes: list[str] = field(default_factory=list)
    xid_fixes: dict[int, list[str]] = field(default_factory=dict)
    xid_triggers: dict[int, str] = field(default_factory=dict)
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
            or self.xid_triggers
            or self.model_xids
            or self.root_xids
            or self.verified_actions
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "family_fixes": self.family_fixes,
            "xid_fixes": {str(k): v for k, v in self.xid_fixes.items()},
            "xid_triggers": {str(k): v for k, v in self.xid_triggers.items()},
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

    Runs AFTER ranking for fixes_for_xid(N) and xids_for_gpu_model(M). ``family``
    remains API-compatible, but family-wide action queries are intentionally not
    executed; callers use symptom-linked ``KGContext.knowledge`` instead.
    Degrades to an empty result (never raises) when TypeDB is disabled/unreachable,
    the driver is missing, or the functions are not defined in the schema.
    """
    xid_codes = xid_codes or []
    if not settings.enable_typedb or not settings.typedb_address:
        return GraphRemediation()
    if not (xid_codes or gpu_model):
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
        for raw_code in dict.fromkeys(xid_codes):  # de-dupe, preserve order
            code = int(raw_code)
            fixes = _statements(run(_FN_FIXES_FOR_XID.format(code=code)))
            if fixes:
                out.xid_fixes[code] = fixes
            triggers = _statements(run(_FN_TRIGGER_FOR_XID.format(code=code)))
            if triggers:
                out.xid_triggers[code] = triggers[0]
            # Drill to the ROOT of the leads_to causal chain: which fault(s)
            # escalate INTO this observed XID. root_xids_for is one hop back, so
            # we walk it TRANSITIVELY (bounded BFS) — a chain 144 → 48 → 154 must
            # surface 144 as the origin of 154, not just the intermediate 48.
            # Surfacing the true root (and its fix) is the ontology's precision
            # win: fix the origin, not the downstream symptom. root_xids_for is
            # newer than the validated functions, so a query error must NOT wipe
            # the fixes above: _root_chain_for isolates per-hop failures.
            # TypeDB 3.11 rejects a recursive function whose input is also
            # read from an attribute. Keep the traversal in Python instead:
            # it is bounded, cycle-safe, and composes the validated one-hop
            # root_xids_for function without a failed query per XID.
            roots = _root_chain_for(run, code)
            if roots:
                out.root_xids[code] = roots
                for root in roots:
                    if root not in out.xid_fixes:
                        rfixes = _statements(run(_FN_FIXES_FOR_XID.format(code=root)))
                        if rfixes:
                            out.xid_fixes[root] = rfixes
                    if root not in out.xid_triggers:
                        triggers = _statements(run(_FN_TRIGGER_FOR_XID.format(code=root)))
                        if triggers:
                            out.xid_triggers[root] = triggers[0]
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


def _select_case_cards(
    prior: list[dict[str, Any]], target: AnalysisTarget | None = None
) -> list[dict[str, Any]]:
    """Return diverse historical priors without letting them become evidence.

    The alert-family query naturally produces close analogs.  A different
    approved family for the same alert is useful as a counterexample; bridge
    cards require topology/entity retrieval and are deliberately omitted until
    that relation exists rather than fabricating a misleading role.
    """
    if not prior:
        return []
    cards: list[dict[str, Any]] = []
    analog = prior[0]
    cards.append(_case_card(analog, "analog"))
    analog_family = analog.get("family") or ""
    counterexample = next(
        (item for item in prior[1:] if item.get("family") and item.get("family") != analog_family),
        None,
    )
    if counterexample is not None:
        cards.append(_case_card(counterexample, "counterexample"))
    component = str(getattr(target, "component", "") or "").strip()
    bridge = next(
        (
            item
            for item in prior
            if item is not analog
            and item is not counterexample
            and component
            and isinstance(item.get("case_card"), dict)
            and str((item["case_card"].get("context") or {}).get("component") or "")
            == component
        ),
        None,
    )
    if bridge is not None:
        cards.append(_case_card(bridge, "bridge"))
    return cards


def _case_card(item: dict[str, Any], kind: str) -> dict[str, Any]:
    raw = item.get("case_card")
    card = _safe_case_card(raw)
    # The role and identifiers are set by the retrieval path, never taken from
    # stored free text. Historical priors must not be mistaken for live proof.
    card.update({
        "kind": kind,
        "historical_prior": True,
        "case_id": _card_text(item.get("case_id"), 180),
        "incident_id": _card_text(item.get("incident_id"), 180),
        "family": _card_text(item.get("family"), 160),
        "analysis_summary": _card_text(item.get("analysis_summary"), 500),
    })
    retrieval = item.get("retrieval")
    if isinstance(retrieval, dict):
        card["retrieval"] = {
            key: retrieval[key]
            for key in ("sources", "rrf_score", "vector_similarity")
            if key in retrieval
        }
    return card


_CASE_CONTEXT_FIELDS = frozenset(
    {
        "alert_name",
        "cluster",
        "node",
        "namespace",
        "pod",
        "project",
        "queue",
        "workload",
        "workload_type",
        "component",
        "version",
        "gpu_model",
        "incident_phase",
        "incident_status_at_approval",
    }
)


def _card_text(value: Any, limit: int = 300) -> str:
    return " ".join(str(value or "").split())[:limit]


def _safe_case_card(raw: Any) -> dict[str, Any]:
    """Allowlist the historical prior payload before it reaches an LLM prompt."""
    if not isinstance(raw, dict):
        return {}
    card: dict[str, Any] = {}
    for key, limit in (
        ("mechanism", 500),
        ("mechanism_fingerprint", 160),
        ("approval_analysis_hash", 160),
        ("quality_source", 64),
        # External support-case priors carry an origin + a use-class label so the
        # synthesis prompt can present them as external reference cases, not proof.
        ("context_class", 40),
        ("case_origin", 64),
    ):
        if value := _card_text(raw.get(key), limit):
            card[key] = value
    try:
        quality = int(raw.get("quality_score"))
        if 0 <= quality <= 100:
            card["quality_score"] = quality
    except (TypeError, ValueError):
        pass
    context = raw.get("context")
    if isinstance(context, dict):
        safe_context = {
            key: value
            for key, value in (
                (key, _card_text(context.get(key), 160)) for key in _CASE_CONTEXT_FIELDS
            )
            if value
        }
        if safe_context:
            card["context"] = safe_context
    return card


def _case_card_projection(run: Any, case_id: str) -> dict[str, Any]:
    """Read a CaseCard's immutable payload plus actual TypeDB link facts."""
    if not case_id:
        return {}
    encoded_id = escape_typeql(case_id)
    card: dict[str, Any] = {}
    try:
        rows = run(_CASE_CARD_QUERY.format(case_id=encoded_id))
        if rows:
            raw = next((row.get("card") for row in rows if row.get("card")), "")
            if isinstance(raw, str):
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    card = _safe_case_card(parsed)
    except Exception:  # noqa: BLE001 - schema rollout must retain legacy priors
        # A rolling schema upgrade may not yet expose case_card; legacy priors
        # still retain their graph-linked evidence/action fields below.
        card = {}

    for relation, key in (
        ("supported_by", "supporting_evidence_by_source"),
        ("contradicted_by", "contradicting_evidence_by_source"),
    ):
        try:
            rows = run(
                _CASE_CARD_EVIDENCE_QUERY.format(case_id=encoded_id, relation=relation)
            )
        except Exception:  # noqa: BLE001 - a partial graph must not discard the card
            continue
        grouped: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            evidence_id = str(row.get("evidence_id") or "").strip()
            source = str(row.get("source") or "unknown").strip() or "unknown"
            if evidence_id:
                grouped.setdefault(source, []).append({"evidence_id": evidence_id})
        if grouped:
            card[key] = grouped

    try:
        rows = run(_CASE_CARD_ACTIONS_QUERY.format(case_id=encoded_id))
    except Exception:  # noqa: BLE001 - pre-resolution schema is an allowed fallback
        rows = []
    successful: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    for row in rows:
        statement = " ".join(str(row.get("statement") or "").split())[:200]
        outcome = str(row.get("outcome") or "").strip()
        if not statement:
            continue
        item = {"statement": statement, "outcome": outcome}
        if outcome in {"resolved", "mitigated"}:
            successful.append(item)
        elif outcome == "ineffective":
            failed.append(item)
    if successful:
        card["successful_actions"] = successful
    if failed:
        card["failed_actions"] = failed
    return card


_PRIOR_CONTEXT_TARGET_FIELDS = {
    "cluster": "cluster",
    "namespace": "namespace",
    "project": "project",
    "queue": "queue",
    "workload": "workload_name",
    "workload_type": "workload_type",
    "pod": "pod",
    "component": "component",
}


def _prior_is_context_compatible(item: dict[str, Any], target: AnalysisTarget) -> bool:
    """Reject a historical CaseCard that explicitly names another entity.

    The same Alertmanager rule can fire in many clusters, namespaces and
    workloads.  TypeDB's same-alert lookup is intentionally broad for recall,
    but an approved card's explicit context is a stronger identity claim than
    the alert name.  Such a mismatch is historical *context*, not a prior for
    this target, and must not steer the planner or enter few-shot summaries.

    Sparse legacy cards remain usable: absence is unknown, not a mismatch.
    """
    card = item.get("case_card")
    context = card.get("context") if isinstance(card, dict) else None
    if not isinstance(context, dict):
        return True
    for context_key, target_key in _PRIOR_CONTEXT_TARGET_FIELDS.items():
        historical = _card_text(context.get(context_key), 160)
        current = _card_text(getattr(target, target_key, ""), 160)
        if historical and current and historical.casefold() != current.casefold():
            return False
    # A planned/live-inferred node is not alert provenance.  Only an alert
    # declared node may disqualify a historical card by node identity.
    historical_node = _card_text(context.get("node"), 160)
    current_node = _card_text(getattr(target, "node", ""), 160)
    if (
        historical_node
        and current_node
        and str(getattr(target, "node_source", "") or "") in {"", "alert"}
        and historical_node.casefold() != current_node.casefold()
    ):
        return False
    return True


def _query_kg(
    client: TypeDBClient,
    target: AnalysisTarget,
    similar_incidents: list[Any] | None = None,
) -> dict[str, Any]:
    # One connection for all three synthesis queries: a transient connect blip on
    # any single fresh connection would fail the whole enrichment, so opening once
    # (instead of per query) shrinks that failure surface ~3x.
    with client.open_reader() as run:
        workloads: list[str] = []
        if target.node:
            rows = run(_BLAST_QUERY.format(node=escape_typeql(target.node)))
            workloads = sorted({str(r.get("wn")) for r in rows if r.get("wn")})

        prior: list[dict[str, Any]] = []
        if target.alert_name:
            rows = run(_PRIOR_QUERY.format(alert=escape_typeql(target.alert_name)))
            seen: set[str] = set()
            for r in rows:
                iid = str(r.get("iid") or "")
                if iid and iid not in seen:
                    seen.add(iid)
                    case_id = str(r.get("case_id") or "")
                    prior.append(
                        {
                            "incident_id": iid,
                            "case_id": case_id,
                            "family": str(r.get("family") or ""),
                            "analysis_summary": str(r.get("sum") or ""),
                            "case_card": _case_card_projection(run, case_id),
                        }
                    )

        # A vector memory becomes a CaseCard only when TypeDB independently
        # verifies that this exact incident has an active approved snapshot.
        # This prevents unreviewed memory text from entering few-shot context.
        for vector_rank, similar in enumerate((similar_incidents or [])[:5], start=1):
            incident_id = _similar_incident_id(similar)
            if not incident_id or any(item.get("incident_id") == incident_id for item in prior):
                continue
            try:
                rows = run(
                    _CASE_BY_INCIDENT_QUERY.format(incident_id=escape_typeql(incident_id))
                )
            except Exception:  # noqa: BLE001 - stale vector result is non-fatal
                continue
            row = next((candidate for candidate in rows if candidate.get("case_id")), None)
            if not isinstance(row, dict):
                continue
            case_id = str(row.get("case_id") or "")
            prior.append(
                {
                    "incident_id": incident_id,
                    "case_id": case_id,
                    "family": str(row.get("family") or ""),
                    "analysis_summary": str(row.get("sum") or _similar_summary(similar)),
                    "case_card": _case_card_projection(run, case_id),
                    "vector_rank": vector_rank,
                    "vector_similarity": _similarity(similar),
                }
            )

        knowledge_rows = run(_KNOWLEDGE_QUERY)
        knowledge_reason_rows = run(_KNOWLEDGE_REASON_QUERY)
        knowledge_exclusive_action_rows = run(_KNOWLEDGE_EXCLUSIVE_ACTIONS_QUERY)
        knowledge_reason_ko_rows = run(_KNOWLEDGE_REASON_KO_QUERY)
        knowledge_component_rows = run(_KNOWLEDGE_COMPONENT_QUERY)
        knowledge_name_ko_rows = run(_KNOWLEDGE_NAME_KO_QUERY)
        knowledge_actions_ko_rows = run(_KNOWLEDGE_ACTIONS_KO_QUERY)
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

    reasons = {
        str(row.get("sn") or ""): str(row.get("reason") or "")
        for row in knowledge_reason_rows
        if row.get("sn") and row.get("reason")
    }
    exclusive_actions = {
        str(row.get("sn") or "")
        for row in knowledge_exclusive_action_rows
        if row.get("sn") and str(row.get("exclusive_actions")).casefold() == "true"
    }
    reasons_ko = {
        str(row.get("sn") or ""): str(row.get("reason_ko") or "")
        for row in knowledge_reason_ko_rows
        if row.get("sn") and row.get("reason_ko")
    }
    components = {
        str(row.get("sn") or ""): str(row.get("component") or "")
        for row in knowledge_component_rows
        if row.get("sn") and row.get("component")
    }
    names_ko = {
        str(row.get("sn") or ""): str(row.get("name_ko") or "")
        for row in knowledge_name_ko_rows
        if row.get("sn") and row.get("name_ko")
    }
    actions_ko: dict[str, set[str]] = {}
    for row in knowledge_actions_ko_rows:
        sname = str(row.get("sn") or "")
        statement_ko = str(row.get("statement_ko") or "")
        if sname and statement_ko:
            actions_ko.setdefault(sname, set()).add(statement_ko)
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
                "reason": reasons.get(sname, ""),
                "exclusive_actions": sname in exclusive_actions,
                "component": components.get(sname, ""),
                "symptom_ko": names_ko.get(sname, ""),
                "reason_ko": reasons_ko.get(sname, ""),
                "actions_ko": sorted(actions_ko.get(sname, set())),
            }
        )

    # A same-alert match is only a retrieval candidate.  Do not admit an
    # approved historical card that explicitly belongs to another entity:
    # otherwise an alert rule shared across tenants can silently make a
    # cross-namespace prior look like evidence for this incident.
    prior = [
        item for item in prior if _prior_is_context_compatible(item, target)
    ]
    prior = _rrf_case_priors(prior, similar_incidents or [])
    case_cards = _select_case_cards(prior, target)
    return {
        "blast_radius_workloads": len(workloads),
        "blast_radius_workload_names": workloads[:20],
        "prior_incidents": prior[:5],
        "case_cards": case_cards,
        "knowledge": knowledge,
        "reasoning": reasoning,
        "diagnostic_tree": diagnostic_tree,
    }


def _similar_incident_id(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("incident_id") or "").strip()
    return str(getattr(item, "incident_id", "") or "").strip()


def _similarity(item: Any) -> float:
    value = item.get("similarity") if isinstance(item, dict) else getattr(item, "similarity", 0)
    try:
        return max(0.0, min(1.0, float(value or 0)))
    except (TypeError, ValueError):
        return 0.0


def _similar_summary(item: Any) -> str:
    value = item.get("analysis_summary") if isinstance(item, dict) else getattr(item, "analysis_summary", "")
    return str(value or "")


def _rrf_case_priors(prior: list[dict[str, Any]], similar_incidents: list[Any]) -> list[dict[str, Any]]:
    """Fuse same-alert graph and vector-retrieved approved cases with RRF."""
    vector_by_id = {
        incident_id: (rank, item)
        for rank, item in enumerate(similar_incidents, start=1)
        if (incident_id := _similar_incident_id(item))
    }
    fused: list[dict[str, Any]] = []
    for graph_rank, item in enumerate(prior, start=1):
        incident_id = str(item.get("incident_id") or "")
        ranks = [graph_rank]
        vector = vector_by_id.get(incident_id)
        if vector is not None:
            ranks.append(vector[0])
        copy = dict(item)
        copy["retrieval"] = {
            "sources": ["typedb", *( ["vector"] if vector is not None else [])],
            "rrf_score": round(sum(1.0 / (60 + rank) for rank in ranks), 6),
            "vector_similarity": _similarity(vector[1]) if vector is not None else 0.0,
        }
        fused.append(copy)
    return sorted(
        fused,
        key=lambda item: (
            -float((item.get("retrieval") or {}).get("rrf_score") or 0),
            str(item.get("incident_id") or ""),
        ),
    )


# External support-case priors. Unlike _PRIOR_QUERY (same-alert, resolved-only),
# these are retrieved by ERROR-SIGNATURE match on a case-local symptom's keywords
# and are deliberately NOT status-gated: mitigated/unresolved external cases are
# still useful labelled context. The approval gate is `approval_state "active"`,
# which only --approved-by ingestion sets. Only proven TypeQL constructs are used.
_EXTERNAL_CASE_QUERY = """
match
  $i isa incident, has incident_id $iid, has analysis_summary $sum;
  (incident: $i, symptom: $sy) isa has_symptom;
  $sy isa symptom, has name $sn, has keyword $kw;
  $case isa case_snapshot, has approval_state "active", has case_id $case_id;
  $diagnosis isa diagnosis, links (incident: $i, cause: $cause);
  (case: $case, finding: $diagnosis) isa case_projection;
  $cause has subtype $family;
select $iid, $sum, $sn, $kw, $case_id, $family;
"""


async def external_case_cards(
    settings: Settings, observed_text: str, *, limit: int = 2
) -> tuple[list[dict[str, Any]], list[str]]:
    """Labelled external support-case priors whose error signature hits the run's
    observed evidence. Empty (never an exception) when the graph ships no external
    cases or nothing matches — a missing prior is safer than a failed RCA."""
    if not observed_text or not settings.enable_typedb or not settings.typedb_address:
        return [], []
    try:
        import typedb.driver  # noqa: F401
    except ImportError:
        return [], ["typedb-driver is not installed; external-case retrieval skipped."]
    client = TypeDBClient(settings)
    try:
        cards = await asyncio.wait_for(
            asyncio.to_thread(_query_external_cases, client, observed_text, limit),
            timeout=settings.typedb_timeout_seconds + 1,
        )
        return cards, []
    except Exception as exc:  # noqa: BLE001 - no external prior is safer than a failed RCA
        _log.warning("external-case retrieval failed: %s", exc, exc_info=True)
        return [], [f"external-case retrieval unavailable: {type(exc).__name__}"]


async def external_case_hints(
    settings: Settings, observed_text: str, *, limit: int = 2
) -> list[dict[str, Any]]:
    """Return bounded, unverified diagnostic leads from matching external cases.

    This deliberately reads the immutable CaseCard JSON rather than resolution
    relations: diagnostic/preventive historical actions are investigation leads,
    not known causes or fixes. A missing lead must never fail an RCA.
    """
    if not observed_text or not settings.enable_typedb or not settings.typedb_address:
        return []
    try:
        import typedb.driver  # noqa: F401
    except ImportError:
        _log.warning("external-case hints skipped: typedb-driver is not installed")
        return []
    try:
        client = TypeDBClient(settings)
        return await asyncio.wait_for(
            asyncio.to_thread(
                _query_external_case_hints, client, observed_text, min(max(limit, 1), 2)
            ),
            timeout=settings.typedb_timeout_seconds + 1,
        )
    except Exception as exc:  # noqa: BLE001 - a missing hint is safer than a failed RCA
        _log.warning("external-case hint retrieval failed: %s", exc, exc_info=True)
        return []


def _matched_external_cases(
    run: Any, observed_text: str
) -> list[tuple[str, dict[str, Any], list[str]]]:
    """Use the shared external error-signature matcher before card projection."""
    text = (observed_text or "").lower()
    if not text:
        return []
    cases: dict[str, dict[str, Any]] = {}
    for row in run(_EXTERNAL_CASE_QUERY):
        case_id = str(row.get("case_id") or "")
        name = str(row.get("sn") or "")
        if not case_id or not name.startswith("ext:"):  # only case-local symptoms
            continue
        info = cases.setdefault(
            case_id,
            {
                "incident_id": str(row.get("iid") or ""),
                "family": str(row.get("family") or ""),
                "analysis_summary": str(row.get("sum") or ""),
                "keywords": set(),
            },
        )
        kw = str(row.get("kw") or "").strip().lower()
        if kw:
            info["keywords"].add(kw)
    matched: list[tuple[str, dict[str, Any], list[str]]] = []
    for case_id, info in cases.items():
        hits, _negated = _keyword_hits(text, sorted(info["keywords"]))
        if hits:
            matched.append((case_id, info, hits))
    return sorted(matched, key=lambda match: (-len(match[2]), match[0]))


def _external_case_hint_projection(run: Any, case_id: str) -> list[dict[str, Any]]:
    """Extract only diagnostic/preventive CaseCard actions for drill-down."""
    if not case_id:
        return []
    try:
        rows = run(_CASE_CARD_QUERY.format(case_id=escape_typeql(case_id)))
        raw = next((row.get("card") for row in rows if row.get("card")), "")
        card = json.loads(raw) if isinstance(raw, str) else {}
    except Exception:  # noqa: BLE001 - external hints are strictly best-effort
        return []
    if not isinstance(card, dict):
        return []
    searchable_context = card.get("searchable_context")
    raw_tokens = (
        searchable_context.get("canonical_component_tokens")
        if isinstance(searchable_context, dict)
        else []
    )
    tokens = [
        " ".join(str(token).split()).lower()[:80]
        for token in raw_tokens
        if str(token).strip()
    ][:12] if isinstance(raw_tokens, list) else []
    hints: list[dict[str, Any]] = []
    for action in card.get("historical_actions") or []:
        if not isinstance(action, dict):
            continue
        if str(action.get("outcome") or "").strip().lower() not in {
            "diagnostic",
            "preventive",
        }:
            continue
        normalized_action = " ".join(str(action.get("normalized_action") or "").split())[:500]
        if normalized_action:
            hints.append(
                {
                    "case_id": case_id,
                    "normalized_action": normalized_action,
                    "canonical_component_tokens": tokens,
                }
            )
    return hints[:4]


def _query_external_case_hints(
    client: TypeDBClient, observed_text: str, limit: int
) -> list[dict[str, Any]]:
    with client.open_reader() as run:
        hints: list[dict[str, Any]] = []
        case_limit = min(max(limit, 1), 2)
        for case_id, _info, _hits in _matched_external_cases(run, observed_text)[:case_limit]:
            hints.extend(_external_case_hint_projection(run, case_id))
        return hints


def _query_external_cases(
    client: TypeDBClient, observed_text: str, limit: int
) -> list[dict[str, Any]]:
    with client.open_reader() as run:
        matched = _matched_external_cases(run, observed_text)
        # Most signature hits first, then case_id — deterministic, no run() calls
        # for non-matching cases (early return before per-case projection).
        cards: list[dict[str, Any]] = []
        for case_id, info, hits in matched[:limit]:
            projection = _case_card_projection(run, case_id)
            built = _case_card(
                {
                    "case_id": case_id,
                    "incident_id": info["incident_id"],
                    "family": info["family"],
                    "analysis_summary": info["analysis_summary"],
                    "case_card": projection,
                },
                "external",
            )
            built["matched_error_signatures"] = hits[:3]
            # The shared allowlist (_safe_case_card) strips actions; re-attach them
            # for external cards only — "what was tried, incl. what did NOT work" is
            # the whole value of an external prior. Labelled kind=external, so the
            # synthesis prompt rule forbids presenting them as verified resolutions.
            for key in ("successful_actions", "failed_actions"):
                if projection.get(key):
                    built[key] = projection[key]
            cards.append(built)
        return cards


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

    try:
        probe_rows = run(_FN_DIAGNOSTIC_PROBES.format(runbook=runbook))
    except Exception:  # noqa: BLE001 - schema v1 remains a rolling-upgrade fallback
        probe_rows = []
    for row in probe_rows:
        node = nodes.get(str(row.get("id") or ""))
        probe = _json_object(row.get("probe"))
        if node is not None and probe:
            node.setdefault("probes", []).append(probe)

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
