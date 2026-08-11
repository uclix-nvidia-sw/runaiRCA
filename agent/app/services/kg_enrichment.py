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
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.collectors.base import AnalysisTarget
from app.config import Settings
from app.knowledge import _keyword_hits, gpu_model_tokens
from app.ontology.typedb_client import TypeDBClient, escape_typeql
from ontology.normalization import workload_uid

_log = logging.getLogger(__name__)

_BLAST_QUERY = """
match
  $n isa node, has name "{node}";
  (host: $n, guest: $w) isa runs_on;
  $w isa workload, has name $wn;
select $wn;
"""

# Location history: past RESOLVED incidents whose alerts fired at the same
# place, regardless of alert name. Alerts carry node_name/namespace_name as
# plain attributes (2026-07-27 infra simplification), so this is a one-hop
# filter; the resolved-only gate keeps the live incident itself out.
_NODE_HISTORY_QUERY = """
match
  $a isa alert, has node_name "{node}";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid, has analysis_summary $sum, has status "resolved";
select $iid, $sum;
"""

_NAMESPACE_HISTORY_QUERY = """
match
  $a isa alert, has namespace_name "{namespace}";
  (incident: $i, member: $a) isa grouped_into;
  $i isa incident, has incident_id $iid, has analysis_summary $sum, has status "resolved";
select $iid, $sum;
"""

# Stable-identity topology around the target workload (stem identity):
# Services exposing it, PVCs it uses, and the other workloads sharing a PVC —
# the storage blast radius.
_WORKLOAD_SERVICES_QUERY = """
match
  $w isa workload, has workload_uid "{workload_uid}";
  (endpoint: $s, backend: $w) isa exposes;
  $s isa service, has name $sn;
select $sn;
"""

_WORKLOAD_PVCS_QUERY = """
match
  $w isa workload, has workload_uid "{workload_uid}";
  (consumer: $w, storage: $p) isa uses_storage;
  $p isa pvc, has name $pn;
select $pn;
"""

_SHARED_PVC_QUERY = """
match
  $p isa pvc, has name "{pvc}";
  (consumer: $o, storage: $p) isa uses_storage;
  $o isa workload, has name $on, has workload_uid $ou;
select $on, $ou;
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
_FN_XID_DETAIL = "match let $m, $d, $s in detail_for_xid({code}); select $m, $d, $s;"
_FN_XIDS_FOR_GPU_MODEL = 'match let $x in xids_for_gpu_model("{model}"); select $x;'
# Validated one-hop reverse leads_to, used only to order a complete recursive result.
_FN_ROOT_XIDS_FOR = "match let $x in root_xids_for({code}); select $x;"
# Transitive reverse leads_to: every fault that escalates INTO an observed XID.
_FN_ROOT_XID_CHAIN_FOR = "match let $x in root_xid_chain_for({code}); select $x;"
_FN_LINKAGE_NOTE_FOR_XID = "match let $x in linkage_note_for_xid({code}); select $x;"
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
_FN_DIAGNOSTIC_ALTERNATIVES = (
    'match let $id, $family, $reason, $disc, $seq in '
    'diagnostic_alternatives_for_runbook("{runbook}"); '
    "select $id, $family, $reason, $disc, $seq;"
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

# Operator-confirmed promotions may establish a family before an action has
# been verified.  They are still keyword-matchable family priors, just with no
# remediation to render.
_KNOWLEDGE_ACTIONLESS_QUERY = """
match
  $rc isa root_cause, has subtype $fam;
  (symptom: $sy, cause: $rc) isa indicates;
  $sy isa symptom, has name $sn, has keyword $kw;
  not { (symptom: $sy, remedy: $ac) isa resolved_by; };
select $fam, $sn, $kw;
"""

# Trace-v3 probe-execution verdict history (ontology/ingest.py's
# _write_trace_v3_projection), grouped by the hypothesis family each execution
# tested and the probe template it ran. A template that has repeatedly come
# back "inconclusive" for a family is worth knowing BEFORE spending another
# round on it; a template that reliably "supports"/"refutes" is worth running
# again. Read by planner._diagnostic_directive (see KGContext.probe_history).
_PROBE_HISTORY_QUERY = """
match
  $t isa diagnostic_probe_template, has probe_id $tid;
  $x isa probe_execution, has probe_verdict $verdict;
  (execution: $x, template: $t) isa probe_execution_for;
  (execution: $x, hypothesis: $h) isa probe_execution_tests;
  $h isa hypothesis, has hypothesis_family $family;
select $tid, $family, $verdict;
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

# Rollout-flavored lifecycle symptoms (knowledge/failure_modes.yaml
# `requires_lifecycle_signal: true`). pipeline._gate_lifecycle_symptoms drops a
# platform_lifecycle_change match carrying this flag unless an active rollout
# signal corroborates it — without this field surviving the graph round-trip,
# that gate is a permanent no-op on the TypeDB path.
_KNOWLEDGE_LIFECYCLE_SIGNAL_QUERY = """
match
  $sy isa symptom, has name $sn, has requires_lifecycle_signal $requires_lifecycle_signal;
select $sn, $requires_lifecycle_signal;
"""

# Version-linked known issues (ontology/load_known_issues.py mirrors each entry
# of knowledge/runai_known_issues.yaml as a name-keyed symptom carrying these
# two optional attributes) so a known issue surfaced through the graph's
# generic symptom match carries the same "affected vX, fixed in vY" context the
# YAML-only known-issues path already attaches.
_KNOWLEDGE_AFFECTED_VERSION_QUERY = """
match
  $sy isa symptom, has name $sn, has affected_version $affected_version;
select $sn, $affected_version;
"""
_KNOWLEDGE_FIXED_VERSION_QUERY = """
match
  $sy isa symptom, has name $sn, has fixed_version $fixed_version;
select $sn, $fixed_version;
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
    # Resolved incidents that fired at the same node/namespace, any alert name.
    location_history: list[dict[str, str]] = field(default_factory=list)
    location_history_truncated: bool = False
    # Stable-identity Service/PVC attachments of the target workload.
    workload_topology: dict[str, Any] = field(default_factory=dict)
    # Complete lookup, or why the topology lookup was skipped.
    workload_topology_status: str = ""
    case_cards: list[dict[str, Any]] = field(default_factory=list)
    # family -> [{symptom, keywords[], actions[]}]  (curated knowledge layer)
    knowledge: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # family -> probe template_id -> {verdict: count, ..., "total": N}. Prior
    # trace-v3 probe-execution outcomes across every ingested run, so a planner
    # can see a template is repeatedly "inconclusive" for this family before
    # spending another round on it. See _PROBE_HISTORY_QUERY.
    probe_history: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
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
            "location_history": self.location_history,
            "location_history_truncated": self.location_history_truncated,
            "workload_topology": self.workload_topology,
            "workload_topology_status": self.workload_topology_status,
            "case_cards": self.case_cards,
            "knowledge": self.knowledge,
            "probe_history": self.probe_history,
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
        location_history=data.get("location_history") or [],
        location_history_truncated=bool(data.get("location_history_truncated")),
        workload_topology=data.get("workload_topology") or {},
        workload_topology_status=str(data.get("workload_topology_status") or ""),
        case_cards=data["case_cards"],
        knowledge=data["knowledge"],
        probe_history=data["probe_history"],
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
    # The XID's own catalog identity (knowledge/xid_catalog.yaml mnemonic /
    # description / severity) — "GPU has fallen off the bus", not just its fix.
    xid_mnemonics: dict[int, str] = field(default_factory=dict)
    xid_descriptions: dict[int, str] = field(default_factory=dict)
    xid_severities: dict[int, str] = field(default_factory=dict)
    # Driver/CUDA version an XID's leads_to escalation was confirmed under
    # (xid_catalog.yaml `linkage_note`); sparse — only XIDs that escalate.
    xid_linkage_notes: dict[int, str] = field(default_factory=dict)
    model_xids: dict[str, list[int]] = field(default_factory=dict)
    # observed XID -> complete transitive ancestors, in causal order when known.
    root_xids: dict[int, list[int]] = field(default_factory=dict)
    # observed XID -> ordered, complete-but-unordered, or degraded.
    root_xid_status: dict[int, str] = field(default_factory=dict)
    verified_actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.family_fixes
            or self.xid_fixes
            or self.xid_triggers
            or self.xid_mnemonics
            or self.model_xids
            or self.root_xids
            or self.verified_actions
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "family_fixes": self.family_fixes,
            "xid_fixes": {str(k): v for k, v in self.xid_fixes.items()},
            "xid_triggers": {str(k): v for k, v in self.xid_triggers.items()},
            "xid_mnemonics": {str(k): v for k, v in self.xid_mnemonics.items()},
            "xid_descriptions": {str(k): v for k, v in self.xid_descriptions.items()},
            "xid_severities": {str(k): v for k, v in self.xid_severities.items()},
            "xid_linkage_notes": {str(k): v for k, v in self.xid_linkage_notes.items()},
            "model_xids": {k: v for k, v in self.model_xids.items()},
            "root_xids": {str(k): v for k, v in self.root_xids.items()},
            "root_xid_status": {str(k): v for k, v in self.root_xid_status.items()},
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
    observed_codes = {int(c) for c in xid_codes}
    with client.open_reader() as run:
        for raw_code in dict.fromkeys(xid_codes):  # de-dupe, preserve order
            code = int(raw_code)
            fixes = _statements(run(_FN_FIXES_FOR_XID.format(code=code)))
            if fixes:
                out.xid_fixes[code] = fixes
            triggers = _statements(run(_FN_TRIGGER_FOR_XID.format(code=code)))
            if triggers:
                out.xid_triggers[code] = triggers[0]
            _fill_xid_detail(run, out, code)
            # Drill to the ROOT of the leads_to causal chain: which fault(s)
            # escalate INTO this observed XID. TypeDB's recursive function returns
            # the full chain in one query, so a chain 144 → 48 → 154 surfaces both
            # the intermediate 48 and true origin 144.
            # Surfacing the true root (and its fix) is the ontology's precision
            # win: fix the origin, not the downstream symptom. A query error must
            # NOT wipe the fixes above: _root_chain_for isolates that failure.
            roots, root_status = _root_chain_for(run, code)
            out.root_xid_status[code] = root_status
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
                    _fill_xid_detail(run, out, root)
        for candidate in _gpu_model_candidates(gpu_model):
            rows = run(_FN_XIDS_FOR_GPU_MODEL.format(model=escape_typeql(candidate)))
            xids = sorted({int(v) for v in _values(rows) if _is_int(v)})
            if xids:
                out.model_xids[candidate] = xids
                # Only gate when the model is known AND its catalog is non-empty.
                # An unrecognised model or a failed/empty lookup must leave every
                # XID in place rather than silently dropping knowledge.
                _gate_root_xids_to_model(out, candidate, set(xids), observed_codes)
                break
    return out


def _gpu_model_candidates(gpu_model: str) -> list[str]:
    """The reported GPU string, then the catalog-shaped model tokens inside it.

    ``xids_for_gpu_model`` matches the catalog name exactly (A100, H100, GB200),
    but a node reports the GPU Feature Discovery product label -- for example
    ``NVIDIA-H100-80GB-HBM3``. Trying the raw value first keeps an
    already-canonical name working; the tokens are what make the per-model gate
    reachable from a real cluster at all, instead of a guard that never fires.
    """
    value = str(gpu_model or "").strip()
    if not value:
        return []
    candidates = [value]
    for token in gpu_model_tokens(value):
        if token not in candidates:
            candidates.append(token)
    return candidates


def _gate_root_xids_to_model(
    out: GraphRemediation, gpu_model: str, valid: set[int], observed: set[int]
) -> None:
    """Drop upstream/ancestor XIDs the detected GPU model cannot raise.

    Only ``root_xids`` VALUES (ancestor codes) are gated. An observed XID —
    a ``root_xids`` dict key, or any code the incident itself reported — is
    never dropped, even if it is absent from the model's catalog: that is a
    data/detection mismatch, not a reason to delete the operator's own
    finding, so it is left in place and flagged in ``out.warnings`` instead.
    """
    mismatched = sorted(code for code in observed if code not in valid)
    if mismatched:
        out.warnings.append(
            f"Observed XID(s) not listed for detected GPU model {gpu_model}: "
            f"{', '.join(str(c) for c in mismatched)}. Kept as reported."
        )

    ancestors = {root for roots in out.root_xids.values() for root in roots}
    invalid = {code for code in ancestors if code not in valid and code not in observed}
    if not invalid:
        return
    for code in list(out.root_xids):
        kept = [root for root in out.root_xids[code] if root not in invalid]
        if kept:
            out.root_xids[code] = kept
        else:
            del out.root_xids[code]
            out.root_xid_status.pop(code, None)
    for code in invalid:
        out.xid_fixes.pop(code, None)
        out.xid_triggers.pop(code, None)
    out.warnings.append(
        f"Dropped upstream XID(s) not valid for detected GPU model {gpu_model}: "
        f"{', '.join(str(c) for c in sorted(invalid))}."
    )


def _fill_xid_detail(run: Any, out: GraphRemediation, code: int) -> None:
    """The XID's own catalog identity: mnemonic/description/severity, plus the
    driver/CUDA linkage_note when its leads_to escalation carries one. Isolated
    like the fixes/triggers lookups above — a query error here must not lose
    those. Best-effort: an XID with no catalog row silently contributes nothing."""
    if code in out.xid_mnemonics:
        return
    row = next(iter(run(_FN_XID_DETAIL.format(code=code))), None)
    if isinstance(row, dict):
        mnemonic = str(row.get("m") or "").strip()
        description = str(row.get("d") or "").strip()
        severity = str(row.get("s") or "").strip()
        if mnemonic:
            out.xid_mnemonics[code] = mnemonic
        if description:
            out.xid_descriptions[code] = description
        if severity:
            out.xid_severities[code] = severity
    # A separate function/query (like trigger_for_xid): linkage_note is sparse,
    # so folding it into detail_for_xid's single `has` conjunction would drop
    # mnemonic/description/severity for every XID that never escalates.
    note = _statements(run(_FN_LINKAGE_NOTE_FOR_XID.format(code=code)))
    if note:
        out.xid_linkage_notes[code] = note[0]


def _root_chain_for(run: Any, code: int) -> tuple[list[int], str]:
    """Complete ancestors, causally ordered only when every hop is available."""
    try:
        roots = {
            int(value)
            for value in _values(run(_FN_ROOT_XID_CHAIN_FOR.format(code=code)))
            if _is_int(value)
        }
    except Exception:  # noqa: BLE001 - best-effort drill-down, never fatal
        return [], "degraded"
    roots.discard(code)
    nodes = roots | {code}
    try:
        parents = {
            node: {
                int(value)
                for value in _values(run(_FN_ROOT_XIDS_FOR.format(code=node)))
                if _is_int(value)
            }
            & nodes
            for node in sorted(nodes)
        }
    except Exception:  # noqa: BLE001 - completeness came from recursion
        return sorted(roots), "complete-but-unordered"

    children = {node: [] for node in nodes}
    for child, direct_parents in parents.items():
        for parent in direct_parents:
            children[parent].append(child)
    for direct_children in children.values():
        direct_children.sort()

    ordered: list[int] = []
    ready = sorted(node for node, direct_parents in parents.items() if not direct_parents)
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for child in children[node]:
            parents[child].remove(node)
            if not parents[child]:
                ready.append(child)
        ready.sort()
    if len(ordered) != len(nodes):
        return sorted(roots), "complete-but-unordered"
    return [node for node in ordered if node != code], "ordered"


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
    # Curated differential diagnosis (external cases only): other plausible
    # families the curator weighed, each with a confidence bucket. Bounded and
    # re-typed field-by-field — never passed through wholesale — like every
    # other entry in this allowlist.
    candidates = raw.get("family_candidates")
    if isinstance(candidates, list):
        safe_candidates = [
            {"family": family, "confidence": _card_text(item.get("confidence"), 20)}
            for item in candidates
            if isinstance(item, dict) and (family := _card_text(item.get("family"), 80))
        ][:5]
        if safe_candidates:
            card["family_candidates"] = safe_candidates
    # Curator cross-references to an EXISTING curated symptom / known issue
    # (external cases only; ontology/load_external_cases.py already bounded
    # these to the closed catalogs before they reached this card). Lets the
    # report cite the more precise curated entry instead of only the raw case.
    for key in ("failure_mode_matches", "known_issue_matches"):
        if safe_matches := _safe_knowledge_link_matches(raw.get(key)):
            card[key] = safe_matches
    return card


def _safe_knowledge_link_matches(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or not (name := _card_text(item.get("name"), 160)):
            continue
        entry = {"name": name, "confidence": _card_text(item.get("confidence"), 20)}
        if match_type := _card_text(item.get("match_type"), 40):
            entry["match_type"] = match_type
        out.append(entry)
    return out[:5]


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


def _read_location_history(run: Callable, target: AnalysisTarget) -> tuple[list[dict[str, str]], bool]:
    """Past resolved incidents at the same location (any alert name) — the
    infra layer's "have we seen trouble HERE before" signal."""
    location_history: list[dict[str, str]] = []
    location_history_truncated = False
    seen_locations: set[str] = set()
    for where, query in (
        ("node " + target.node, _NODE_HISTORY_QUERY.format(node=escape_typeql(target.node)))
        if target.node
        else (None, None),
        (
            "namespace " + target.namespace,
            _NAMESPACE_HISTORY_QUERY.format(namespace=escape_typeql(target.namespace)),
        )
        if target.namespace
        else (None, None),
    ):
        if not query:
            continue
        for r in run(query):
            iid = str(r.get("iid") or "")
            if not iid or iid in seen_locations:
                continue
            seen_locations.add(iid)
            location_history.append(
                {
                    "incident_id": iid,
                    "where": where,
                    "analysis_summary": str(r.get("sum") or ""),
                }
            )
            if len(location_history) >= 6:
                location_history_truncated = True
                break
        if len(location_history) >= 6:
            break
    return location_history, location_history_truncated


def _read_workload_topology(run: Callable, target: AnalysisTarget) -> tuple[dict[str, Any], str]:
    """Topology around the stem workload identity: exposing Services, used
    PVCs, and the storage blast radius (other workloads on the same PVC)."""
    workload_topology: dict[str, Any] = {}
    workload_topology_status = ""
    # Namespace-less alerts cannot name one graph workload safely: do not
    # fall back to the ambiguous display name.
    if target.workload_name and target.namespace:
        workload_topology_status = "complete"
        workload = workload_uid(target.namespace, target.workload_name)
        services = sorted(
            {
                str(r.get("sn"))
                for r in run(
                    _WORKLOAD_SERVICES_QUERY.format(workload_uid=escape_typeql(workload))
                )
                if r.get("sn")
            }
        )
        pvcs = sorted(
            {
                str(r.get("pn"))
                for r in run(
                    _WORKLOAD_PVCS_QUERY.format(workload_uid=escape_typeql(workload))
                )
                if r.get("pn")
            }
        )
        shared: list[str] = []
        shared_storage_pvcs = pvcs[:3]
        for pvc in shared_storage_pvcs:
            for r in run(_SHARED_PVC_QUERY.format(pvc=escape_typeql(pvc))):
                other = str(r.get("on") or "")
                other_uid = str(r.get("ou") or "")
                if other and other_uid != workload and other not in shared:
                    shared.append(other)
        if services or pvcs:
            workload_topology = {
                "services": services[:10],
                "pvcs": pvcs[:10],
                "shared_storage_workloads": shared[:10],
                "shared_storage_pvcs": shared_storage_pvcs,
                "shared_storage_truncated": len(pvcs) > len(shared_storage_pvcs),
            }
    elif target.workload_name:
        workload_topology_status = "skipped_missing_namespace"
    return workload_topology, workload_topology_status


def _read_prior_cases(
    run: Callable, target: AnalysisTarget, similar_incidents: list[Any] | None
) -> list[dict[str, Any]]:
    """Approved prior CaseCards: same-alert matches first, then vector hits."""
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
                        "matched_by": "same_alert",
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
                "matched_by": "similarity",
            }
        )
    return prior


def _read_component_reasoning(run: Callable, component: str) -> dict[str, Any]:
    """Ontology dependency/check paths for the alert's component, if any."""
    reasoning: dict[str, Any] = {}
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
    return reasoning


def _read_knowledge_rows(run: Callable) -> dict[str, list]:
    """Every curated-knowledge projection, read on the one open transaction."""
    return {
        "symptoms": [*run(_KNOWLEDGE_QUERY), *run(_KNOWLEDGE_ACTIONLESS_QUERY)],
        "reason": run(_KNOWLEDGE_REASON_QUERY),
        "exclusive_actions": run(_KNOWLEDGE_EXCLUSIVE_ACTIONS_QUERY),
        "lifecycle": run(_KNOWLEDGE_LIFECYCLE_SIGNAL_QUERY),
        "reason_ko": run(_KNOWLEDGE_REASON_KO_QUERY),
        "component": run(_KNOWLEDGE_COMPONENT_QUERY),
        "name_ko": run(_KNOWLEDGE_NAME_KO_QUERY),
        "actions_ko": run(_KNOWLEDGE_ACTIONS_KO_QUERY),
        "affected_version": run(_KNOWLEDGE_AFFECTED_VERSION_QUERY),
        "fixed_version": run(_KNOWLEDGE_FIXED_VERSION_QUERY),
    }


def _project_knowledge(rows: dict[str, list]) -> dict[str, list[dict[str, Any]]]:
    """Group the per-attribute knowledge rows into one entry per symptom."""
    reasons = {
        str(row.get("sn") or ""): str(row.get("reason") or "")
        for row in rows["reason"]
        if row.get("sn") and row.get("reason")
    }
    exclusive_actions = {
        str(row.get("sn") or "")
        for row in rows["exclusive_actions"]
        if row.get("sn") and str(row.get("exclusive_actions")).casefold() == "true"
    }
    lifecycle_required = {
        str(row.get("sn") or "")
        for row in rows["lifecycle"]
        if row.get("sn") and str(row.get("requires_lifecycle_signal")).casefold() == "true"
    }
    affected_versions = {
        str(row.get("sn") or ""): str(row.get("affected_version") or "")
        for row in rows["affected_version"]
        if row.get("sn") and row.get("affected_version")
    }
    fixed_versions = {
        str(row.get("sn") or ""): str(row.get("fixed_version") or "")
        for row in rows["fixed_version"]
        if row.get("sn") and row.get("fixed_version")
    }
    reasons_ko = {
        str(row.get("sn") or ""): str(row.get("reason_ko") or "")
        for row in rows["reason_ko"]
        if row.get("sn") and row.get("reason_ko")
    }
    components = {
        str(row.get("sn") or ""): str(row.get("component") or "")
        for row in rows["component"]
        if row.get("sn") and row.get("component")
    }
    names_ko = {
        str(row.get("sn") or ""): str(row.get("name_ko") or "")
        for row in rows["name_ko"]
        if row.get("sn") and row.get("name_ko")
    }
    actions_ko: dict[str, set[str]] = {}
    for row in rows["actions_ko"]:
        sname = str(row.get("sn") or "")
        statement_ko = str(row.get("statement_ko") or "")
        if sname and statement_ko:
            actions_ko.setdefault(sname, set()).add(statement_ko)
    grouped: dict[tuple[str, str], dict[str, set[str]]] = {}
    for r in rows["symptoms"]:
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
                "requires_lifecycle_signal": sname in lifecycle_required,
                "component": components.get(sname, ""),
                "symptom_ko": names_ko.get(sname, ""),
                "reason_ko": reasons_ko.get(sname, ""),
                "actions_ko": sorted(actions_ko.get(sname, set())),
                "affected_version": affected_versions.get(sname, ""),
                "fixed_version": fixed_versions.get(sname, ""),
            }
        )
    return knowledge


def _query_kg(
    client: TypeDBClient,
    target: AnalysisTarget,
    similar_incidents: list[Any] | None = None,
) -> dict[str, Any]:
    # One connection for all the synthesis queries: a transient connect blip on
    # any single fresh connection would fail the whole enrichment, so opening
    # once (instead of per query) shrinks that failure surface.
    with client.open_reader() as run:
        workloads: list[str] = []
        if target.node:
            rows = run(_BLAST_QUERY.format(node=escape_typeql(target.node)))
            workloads = sorted({str(r.get("wn")) for r in rows if r.get("wn")})
        location_history, location_history_truncated = _read_location_history(run, target)
        workload_topology, workload_topology_status = _read_workload_topology(run, target)
        prior = _read_prior_cases(run, target, similar_incidents)
        knowledge_rows = _read_knowledge_rows(run)
        probe_history_rows = run(_PROBE_HISTORY_QUERY)
        reasoning = _read_component_reasoning(run, target.workload_name)
        try:
            diagnostic_tree = _query_diagnostic_tree(run)
        except Exception:  # noqa: BLE001 - old schema during rolling upgrades
            _log.warning("TypeDB diagnostic runbook query failed; YAML fallback will be used")
            diagnostic_tree = {}

    knowledge = _project_knowledge(knowledge_rows)
    # A same-alert match is only a retrieval candidate.  Do not admit an
    # approved historical card that explicitly belongs to another entity:
    # otherwise an alert rule shared across tenants can silently make a
    # cross-namespace prior look like evidence for this incident.
    prior = [item for item in prior if _prior_is_context_compatible(item, target)]
    prior = _rrf_case_priors(prior, similar_incidents or [])
    case_cards = _select_case_cards(prior, target)
    return {
        "blast_radius_workloads": len(workloads),
        "blast_radius_workload_names": workloads[:20],
        "prior_incidents": prior[:5],
        "location_history": location_history,
        "location_history_truncated": location_history_truncated,
        "workload_topology": workload_topology,
        "workload_topology_status": workload_topology_status,
        "case_cards": case_cards,
        "knowledge": knowledge,
        "probe_history": _aggregate_probe_history(probe_history_rows),
        "reasoning": reasoning,
        "diagnostic_tree": diagnostic_tree,
    }


def _aggregate_probe_history(rows: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    """family -> template_id -> {verdict: count, ..., "total": N}, from every
    ingested run's trace-v3 probe executions (see _PROBE_HISTORY_QUERY)."""
    out: dict[str, dict[str, dict[str, int]]] = {}
    for row in rows:
        family = str(row.get("family") or "").strip()
        template_id = str(row.get("tid") or "").strip()
        verdict = str(row.get("verdict") or "").strip()
        if not (family and template_id and verdict):
            continue
        bucket = out.setdefault(family, {}).setdefault(template_id, {"total": 0})
        bucket[verdict] = bucket.get(verdict, 0) + 1
        bucket["total"] += 1
    return out


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
    by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(prior):
        key = str(item.get("incident_id") or f"__missing_{index}")
        existing = by_id.get(key)
        if existing is None or (
            item.get("matched_by") == "same_alert"
            and existing.get("matched_by") != "same_alert"
        ):
            by_id[key] = item

    fused: list[dict[str, Any]] = []
    for graph_rank, item in enumerate(by_id.values(), start=1):
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


def _evidence_summaries_by_id(card: dict[str, Any]) -> dict[str, str]:
    """evidence_id -> masked summary, from the loader's bounded evidence_refs
    projection (ontology/load_external_cases.py). Cards written before that
    field existed carry no `evidence_refs` key -- must degrade to {}, never
    KeyError, so a stale graph load still yields plain (unobserved) hints."""
    refs = card.get("evidence_refs")
    if not isinstance(refs, list):
        return {}
    out: dict[str, str] = {}
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        evidence_id = str(ref.get("evidence_id") or "").strip()
        summary = str(ref.get("summary") or "").strip()
        if evidence_id and summary:
            out[evidence_id] = summary
    return out


def _external_case_hint_projection(run: Any, case_id: str) -> list[dict[str, Any]]:
    """Extract only diagnostic/preventive CaseCard actions for drill-down.

    Each hint carries the support thread's own narrative: `order` (its 1-based
    position among this case's diagnostic/preventive steps), `outcome`, and up
    to 2 `observed` evidence summaries -- so a lead reads as "step 2, a
    preventive check, which found X" instead of a bare imperative.
    """
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
    evidence_summaries = _evidence_summaries_by_id(card)
    hints: list[dict[str, Any]] = []
    order = 0
    for action in card.get("historical_actions") or []:
        if not isinstance(action, dict):
            continue
        outcome = str(action.get("outcome") or "").strip().lower()
        if outcome not in {"diagnostic", "preventive"}:
            continue
        order += 1
        normalized_action = " ".join(str(action.get("normalized_action") or "").split())[:500]
        if not normalized_action:
            continue
        hint: dict[str, Any] = {
            "case_id": case_id,
            "normalized_action": normalized_action,
            "canonical_component_tokens": tokens,
            "order": order,
            "outcome": outcome,
        }
        evidence_ids = action.get("evidence_ids")
        if isinstance(evidence_ids, list):
            observed = [
                evidence_summaries[key]
                for eid in evidence_ids
                if (key := str(eid)) in evidence_summaries
            ]
            if observed:
                hint["observed"] = [summary[:200] for summary in observed[:2]]
        hints.append(hint)
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

    try:
        alternative_rows = run(_FN_DIAGNOSTIC_ALTERNATIVES.format(runbook=runbook))
    except Exception:  # noqa: BLE001 - schema v1 remains a rolling-upgrade fallback
        alternative_rows = []
    for row in sorted(alternative_rows, key=lambda item: int(item.get("seq") or 0)):
        node = nodes.get(str(row.get("id") or ""))
        family = str(row.get("family") or "")
        if node is None or not family:
            continue
        node.setdefault("alternatives", []).append(
            {
                "family": family,
                "reason": str(row.get("reason") or ""),
                "discriminator": str(row.get("disc") or ""),
            }
        )

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
