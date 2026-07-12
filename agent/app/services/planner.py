"""Investigation planner — the orchestrator's "think first" step.

Builds an InvestigationPlan from the alert (labels/target), the knowledge-graph
context, and any vector-similar incidents BEFORE any collector runs. The plan
scopes each collector to what this specific alert needs, so agents stop always
scraping the Run:ai control plane (the #1 accuracy complaint).

Deterministic core (always runs); an optional LLM pass refines focus/hypotheses/
strategy/narrative when configured. On ANY LLM failure the deterministic plan
stands — this module never raises into analyze.

ponytail: keyword/label heuristics over the target, not a model, for the core.
The LLM only refines what the deterministic pass already produced.
"""

from __future__ import annotations

import logging
import re

from app.collectors.base import AnalysisTarget
from app.config import Settings
from app.knowledge import (
    FamilyCatalog,
    _keyword_negated,
    component_for_target,
    load_architecture,
    load_family_catalog,
    load_runai_alerts,
    match_failure_mode_symptoms,
    match_runai_alert,
)
from app.llm import complete_json, llm_configured
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.services.decision_tree import resolve_tree, walk_tree

_log = logging.getLogger(__name__)

# A similar incident is only trustworthy above this cosine similarity.
_SIMILARITY_FLOOR = 0.80

# Keywords in the alert name / labels that genuinely implicate the Run:ai
# control plane (scheduler/quota/admission/reconcile), independent of namespace.
_CONTROL_PLANE_KEYWORDS = (
    "scheduler",
    "quota",
    "admission",
    "reconcile",
    "queue",
    "runai-backend",
)
_SIMILAR_STOPWORDS = {
    "alert",
    "and",
    "error",
    "failure",
    "firing",
    "gpu",
    "namespace",
    "old",
    "pod",
    "pods",
    "run",
    "runai",
    "status",
    "the",
}
_XID_PATTERN = re.compile(r"\bxid\s*(?:\([^)]*\))?\s*[:=]?\s*(\d{1,4})", re.IGNORECASE)
_ROLLOUT_CHANGE_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}


def _is_runai_namespace(namespace: str) -> bool:
    # A Run:ai platform/project namespace. Excludes runai-rca — the RCA tool's OWN
    # namespace, which is a plain Kubernetes problem, not a Run:ai workload/control
    # plane. (runai and runai-backend stay in — they ARE the Run:ai platform.)
    ns = (namespace or "").lower()
    return ns.startswith("runai") and ns != "runai-rca"


# Generic cluster/monitoring components that are NOT a Run:ai workload. A failing
# kube-state-metrics / node-exporter / prometheus pod that happens to live in a
# runai-* namespace is a plain Kubernetes problem — routing it to the Run:ai
# scheduler is the misclassification we're guarding against. Matched on the pod
# name (token boundary), so component identity beats the namespace prefix.
_GENERIC_INFRA_STEMS: tuple[str, ...] = (
    "kube-state-metrics", "node-exporter", "prometheus", "alertmanager", "grafana",
    "loki", "promtail", "thanos", "kube-proxy", "coredns", "kube-dns", "metrics-server",
    "cadvisor", "fluent-bit", "fluentd", "otel-collector", "opentelemetry",
)


def _is_generic_infra(target: AnalysisTarget) -> bool:
    """True when the alert target is a generic k8s/monitoring component, not a
    Run:ai workload — so it must follow general Kubernetes troubleshooting."""
    name = (target.pod or target.workload_name or "").lower()
    return any(stem in name for stem in _GENERIC_INFRA_STEMS)


def _implicates_control_plane(target: AnalysisTarget) -> bool:
    if _is_generic_infra(target):
        return False
    if _is_runai_namespace(target.namespace):
        return True
    if target.project or target.queue:
        return True
    haystack = " ".join(
        [target.alert_name or "", target.workload_type or ""]
    ).lower()
    return any(kw in haystack for kw in _CONTROL_PLANE_KEYWORDS)


def _is_platform_namespace(namespace: str, settings: Settings) -> bool:
    """A Run:ai *platform* namespace — the control plane itself (runai / runai-backend).

    These are the configured log namespaces; a problem here is a problem operating the
    Run:ai platform, distinct from a user workload that merely runs inside it."""
    ns = (namespace or "").strip().lower()
    return bool(ns) and ns in {n.strip().lower() for n in settings.runai_log_namespaces}


def _namespace_scope(target: AnalysisTarget, settings: Settings) -> str:
    """Where the alert lives — decides the investigation emphasis:

    - "platform": a Run:ai platform namespace (runai/runai-backend). The platform
      itself is unhealthy, so investigate Kubernetes AND node/system evidence broadly.
    - "workload": a user workload running inside Run:ai (a runai-* project namespace,
      or any namespace carrying a Run:ai project/queue). Focus on the Run:ai scheduler
      and the workload's scheduling/quota/startup.
    - "infra": node-level / namespace-less / non-Run:ai — node & system first.
      Also generic k8s/monitoring components (kube-state-metrics, prometheus, …)
      wherever they run: they are a Kubernetes problem, not a Run:ai workload.
    """
    if _is_generic_infra(target):
        return "infra"
    if _is_platform_namespace(target.namespace, settings):
        return "platform"
    if _is_runai_namespace(target.namespace) or target.project or target.queue:
        return "workload"
    return "infra"


# scope -> (families to lead the hypotheses with, the reason tag)
_SCOPE_LEAD: dict[str, tuple[tuple[str, ...], str]] = {
    "platform": (
        ("runai_control_plane_error", "node_kubelet_pressure"),
        "Run:ai platform namespace — the control plane itself; investigate Kubernetes "
        "and node/system evidence broadly, not just the workload",
    ),
    "workload": (
        ("runai_scheduling_quota", "workload_startup_error"),
        "user workload inside the Run:ai platform — focus on the Run:ai scheduler and "
        "the workload's scheduling/quota/startup",
    ),
}


def _promote_families(
    hypotheses: list[dict[str, str]], lead_families: tuple[str, ...], reason: str
) -> list[dict[str, str]]:
    """Move lead_families to the front (in order), tagging their reason."""
    lead_set = set(lead_families)
    lead = [
        {"family": fam, "reason": reason}
        for fam in lead_families
        if any(h["family"] == fam for h in hypotheses)
    ]
    rest = [h for h in hypotheses if h["family"] not in lead_set]
    return lead + rest


def _ordered_hypotheses(
    target: AnalysisTarget, family_catalog: FamilyCatalog
) -> tuple[list[dict[str, str]], bool]:
    """Ranked families + whether ANY family actually matched a keyword.

    The bool matters: on a 0-0-0-0 tie the declaration-order tiebreak would make
    node_kubelet_pressure the "top" hypothesis for an alert that gave no signal at
    all (e.g. PrometheusMissingRuleEvaluations). The caller uses the flag to avoid
    fabricating a confident "most likely X" out of the tiebreak."""
    haystack = " ".join(
        [target.alert_name or "", target.workload_name or "", target.workload_type or ""]
    ).lower()
    scored: list[tuple[int, str]] = []
    for family, keywords in family_catalog.hints:
        hits = sum(1 for kw in keywords if kw in haystack)
        scored.append((hits, family))
    # Highest keyword-hit families first; keep declaration order as the tiebreak
    # (enumerate index) so a 0-0 tie stays deterministic.
    scored_indexed = [(hits, -i, fam) for i, (hits, fam) in enumerate(scored)]
    scored_indexed.sort(reverse=True)
    hypotheses = [
        {"family": fam, "reason": family_catalog.reasons.get(fam, fam)}
        for _, _, fam in scored_indexed
    ]
    return hypotheses, any(hits for hits, _ in scored)


def _node_first_hypotheses(
    hypotheses: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Promote node/system-level families for a namespace-less (node) alert.

    node_kubelet_pressure is the node-level failure family in the ranked set
    (GPU/hardware faults surface here via the system agent's kernel/XID lines).
    """
    node_family = "node_kubelet_pressure"
    reason = "namespace-less alert — investigate node/system level first"
    promoted = [{"family": node_family, "reason": reason}]
    return promoted + [h for h in hypotheses if h["family"] != node_family]


def _best_similar(similar_incidents: list, alert_text: str = "") -> object | None:
    best = None
    best_sim = _SIMILARITY_FLOOR
    for item in similar_incidents or []:
        sim = getattr(item, "similarity", 0) or 0
        if sim >= best_sim and _similar_relevant(item, alert_text):
            best_sim = sim
            best = item
    return best


def _similar_relevant(item: object, alert_text: str) -> bool:
    prior_text = " ".join(
        str(getattr(item, field, "") or "")
        for field in ("title", "analysis_summary", "analysis_detail")
    )
    if not prior_text.strip() or not alert_text.strip():
        return True
    return bool(_similar_tokens(alert_text) & _similar_tokens(prior_text))


def _similar_tokens(text: str) -> set[str]:
    lowered = (text or "").lower()
    return {
        match.group(0)
        for match in re.finditer(r"[a-z0-9]+", lowered)
        if len(match.group(0)) > 2
        and match.group(0) not in _SIMILAR_STOPWORDS
        and not _keyword_negated(lowered, match.start(), match.end())
    }


def _ontology_match(kg_context, alert_text: str) -> bool:
    """True only when the ontology has facts about THIS alert.

    That means a prior incident for the same alert, or a knowledge symptom whose
    keyword actually appears in the alert's own text. Mere EXISTENCE of static
    curated knowledge for the top family made every plan claim
    "targeted (matched knowledge-graph facts)" — a hollow claim that had nothing
    to do with the alert being investigated."""
    if not kg_context or not kg_context.get("available"):
        return False
    if kg_context.get("prior_incidents"):
        return True
    diagnostic = walk_tree(kg_context.get("diagnostic_tree"), alert_text)
    conclusion = diagnostic.get("conclusion") if isinstance(diagnostic, dict) else None
    if isinstance(conclusion, dict) and conclusion.get("family") not in (
        "",
        "insufficient_evidence",
    ):
        return True
    text = (alert_text or "").lower()
    if not text:
        return False
    return bool(match_failure_mode_symptoms(kg_context.get("knowledge") or {}, text))


def _diagnostic_directive(
    settings: Settings,
    kg_context: dict,
    alert_text: str,
    family_catalog: FamilyCatalog,
) -> dict:
    tree, source = resolve_tree(
        kg_context.get("diagnostic_tree"), settings.failure_modes_file
    )
    walked = walk_tree(tree, alert_text)
    if not walked.get("path"):
        return {}
    steps = walked.get("steps") or []
    conclusion = walked.get("conclusion") or {}
    family = str(conclusion.get("family") or "")
    rule = family_catalog.rules.get(family)
    collectors = list(rule[1]) if rule else []
    alternatives = [
        alternative
        for step in steps
        for alternative in step.get("alternatives") or []
        if isinstance(alternative, dict)
    ]
    return {
        "source": source,
        "path": list(walked.get("path") or []),
        "questions": [str(step["question"])[:400] for step in steps if step.get("question")][
            :6
        ],
        "checks": [str(step["verify"])[:500] for step in steps if step.get("verify")][:6],
        "interpretation": [
            str(step["interpretation"])[:400]
            for step in steps
            if step.get("interpretation")
        ][:4],
        "probes": [
            {**probe, "hypothesis_family": family}
            for step in steps
            for probe in (step.get("probes") or [])
            if isinstance(probe, dict)
        ][:8],
        "avoid": [str(step["avoid"])[:400] for step in steps if step.get("avoid")][:4],
        "disconfirm": [str(item)[:500] for item in conclusion.get("disconfirm") or []][:6],
        "provisional_family": family,
        "competing_hypotheses": alternatives[:6],
        "recommended_collectors": collectors,
        "instruction": (
            "Collect evidence that can confirm or refute every live hypothesis; "
            "do not search only for the provisional family."
        ),
    }


def _alert_haystack(target: AnalysisTarget, alert) -> str:
    parts = [target.alert_name or "", target.workload_name or ""]
    labels = getattr(alert, "labels", None) or {}
    annotations = getattr(alert, "annotations", None) or {}
    parts.extend(str(v) for v in labels.values())
    parts.extend(str(v) for v in annotations.values())
    return " ".join(parts)


def _recent_change_lead(
    settings: Settings,
    target: AnalysisTarget,
    recent_changes: list[dict],
) -> dict[str, str] | None:
    changes = [c for c in recent_changes or [] if isinstance(c, dict)]
    if not changes:
        return None
    for change in changes:
        kind = str(change.get("kind") or "")
        if kind == "NodeCondition":
            return _change_hypothesis(settings, "node_kubelet_pressure", change)
        if kind == "PodDeleted" or kind in _ROLLOUT_CHANGE_KINDS:
            return _change_hypothesis(settings, "workload_startup_error", change)
    family = (
        "node_kubelet_pressure"
        if _ambiguous_change_is_node(target, changes)
        else "workload_startup_error"
    )
    return _change_hypothesis(settings, family, changes[0])


def _ambiguous_change_is_node(target: AnalysisTarget, changes: list[dict]) -> bool:
    if target.node and not target.namespace:
        return True
    node = (target.node or "").lower()
    if not node:
        return False
    return any(
        node in " ".join(str(c.get(k) or "") for k in ("kind", "name", "summary")).lower()
        for c in changes
    )


def _change_hypothesis(settings: Settings, family: str, change: dict) -> dict[str, str]:
    kind = str(change.get("kind") or "change")
    summary = str(change.get("summary") or change.get("name") or "recent Kubernetes change")
    if getattr(settings, "language", "en") == "ko":
        reason = f"계획 전 확인된 최근 Kubernetes 변경({kind}: {summary})"
    else:
        reason = f"recent Kubernetes change before planning ({kind}: {summary})"
    return {"family": family, "reason": reason}


def _recent_change_narrative(settings: Settings, change_lead: dict[str, str]) -> str:
    if getattr(settings, "language", "en") == "ko":
        return (
            "계획 단계에서 최근 Kubernetes 변경이 먼저 확인되었습니다. "
            "스케줄러/쿼터 가정보다 해당 변경이 알림을 유발했는지 먼저 확인하세요. "
        )
    return (
        "A recent Kubernetes change was found before planning. Verify whether that "
        "change triggered the alert before treating scheduler/quota as the lead. "
    )


def _has_precise_xid(alert_text: str) -> bool:
    return bool(_XID_PATTERN.search(alert_text or ""))


async def plan_investigation(
    settings: Settings,
    target: AnalysisTarget,
    alert,
    kg_context: dict | None,
    similar_incidents: list | None,
    recent_changes: list[dict] | None = None,
) -> InvestigationPlan:
    kg_context = kg_context or {}
    similar_incidents = similar_incidents or []
    recent_changes = recent_changes or []
    alert_text = _alert_haystack(target, alert)

    namespaces = [target.namespace] if target.namespace else []
    check_control_plane = _implicates_control_plane(target)
    if check_control_plane:
        for ns in settings.runai_log_namespaces:
            if ns and ns not in namespaces:
                namespaces.append(ns)

    family_catalog = load_family_catalog(settings.families_file)
    diagnostic_directive = _diagnostic_directive(
        settings, kg_context, alert_text, family_catalog
    )
    hypotheses, keyword_signal = _ordered_hypotheses(target, family_catalog)
    # Namespace decides the emphasis: a Run:ai platform namespace (runai/runai-backend)
    # means the control plane itself is unhealthy -> lead control-plane + node/system
    # broadly; a user workload namespace inside Run:ai -> lead the scheduler/scheduling.
    scope = _namespace_scope(target, settings)
    if scope in _SCOPE_LEAD:
        lead_families, scope_reason = _SCOPE_LEAD[scope]
        hypotheses = _promote_families(hypotheses, lead_families, scope_reason)
    # Namespace-less alert (no namespace, project, or queue): there is no workload
    # scope to dig into, so lead with node/system-level causes. The workload/loki/
    # runai agents will have nothing to match; the system agent (node syslog/
    # journalctl/dmesg) + kubernetes node conditions carry the investigation.
    node_focused = not target.namespace and not target.project and not target.queue
    if node_focused:
        hypotheses = _node_first_hypotheses(hypotheses)
    # family, and fix — lead with that family and carry the definition on the plan.
    matched_alert = match_runai_alert(
        load_runai_alerts(settings.runai_alerts_file), target.alert_name
    )
    if matched_alert and matched_alert.get("family"):
        fam = matched_alert["family"]
        reason = f"documented Run:ai built-in alert: {matched_alert.get('trigger', '')}".strip()
        hypotheses = [{"family": fam, "reason": reason}] + [
            h for h in hypotheses if h["family"] != fam
        ]
    change_lead = _recent_change_lead(settings, target, recent_changes)
    if change_lead:
        hypotheses = [change_lead] + [
            h for h in hypotheses if h["family"] != change_lead["family"]
        ]
    if _has_precise_xid(alert_text):
        hypotheses = [
            {
                "family": "gpu_hardware_error",
                "reason": "alert contains a precise NVIDIA XID code",
            }
        ] + [h for h in hypotheses if h["family"] != "gpu_hardware_error"]
    # Component identity: when the alert TARGET itself is a known platform
    # component (pod/workload name), that names the entry point directly — e.g.
    # runai-container-toolkit-* implicates the NVIDIA GPU Operator stack via its
    # depends_on chain, with or without any error string in the evidence. WHO the
    # alert is about is more specific than both the namespace scope and the alert
    # catalog's coarse family (a "DaemonSet Rollout Stuck" catalog entry says
    # runai_control_plane_error even when the stuck daemonset is the container
    # toolkit), so this promotion runs LAST and wins the lead; the catalog
    # definition stays on the plan for its actions/narrative.
    component_entry = component_for_target(
        load_architecture(settings.architecture_file), target.pod, target.workload_name
    )
    component = str(component_entry.get("component") or "") if component_entry else ""
    if component_entry and component_entry.get("family"):
        effect = str(
            component_entry.get("failure_effect") or component_entry.get("purpose") or ""
        )
        reason = f"alert targets platform component '{component}' — {effect}".strip(" —")
        hypotheses = [{"family": str(component_entry["family"]), "reason": reason}] + [
            h for h in hypotheses if h["family"] != component_entry["family"]
        ]
    best_similar = _best_similar(similar_incidents, alert_text)
    used_similarity = best_similar is not None
    used_ontology = _ontology_match(kg_context, alert_text)

    if used_similarity or used_ontology:
        strategy = "targeted"
    else:
        strategy = "breadth_first"

    # Did anything actually EARN the leading hypothesis, or is it just the
    # declaration-order tiebreak? A namespace scope, a documented alert, a
    # node-level alert, or a keyword hit all count as real signal.
    leader_earned = (
        keyword_signal
        or bool(matched_alert)
        or bool(component)
        or bool(change_lead)
        or scope in _SCOPE_LEAD
        or node_focused
    )
    where = target.workload_name or target.pod or target.namespace or "the cluster"
    if not leader_earned:
        # No signal at all: don't let node_kubelet_pressure masquerade as the
        # top cause. Rank from live collector evidence instead of the tiebreak.
        hypotheses = [
            {
                "family": "insufficient_evidence",
                "reason": "no alert/namespace/keyword signal — rank from collector evidence",
            }
        ] + hypotheses
        focus = (
            f"{target.alert_name or 'alert'} on {where} "
            "— no strong family signal; breadth-first"
        )
    else:
        focus = (
            f"{target.alert_name or 'alert'} on {where} "
            f"— most likely {hypotheses[0]['family'].replace('_', ' ')}"
        )

    if strategy == "targeted":
        matched: list[str] = []
        if used_similarity:
            matched.append(
                f"vector match {getattr(best_similar, 'incident_id', '?')} "
                f"(similarity {getattr(best_similar, 'similarity', 0):.2f})"
            )
        if used_ontology:
            matched.append("ontology facts for this alert")
        narrative = (
            "Targeted investigation: " + " and ".join(matched) + ". "
            "Confirm the prior cause against live evidence before acting."
        )
    else:
        sweep = "Kubernetes events/pods and Prometheus metrics for the target"
        if check_control_plane:
            sweep += ", plus Run:ai control-plane logs"
        narrative = (
            "No prior incident or ontology fact cleared the confidence bar, so sweep "
            f"breadth-first: {sweep}. Rank the failure family from what the collectors "
            "actually find rather than assuming a cause."
        )

    if scope == "platform":
        narrative = (
            "This alert is in a Run:ai platform namespace (the control plane itself). "
            "Investigate broadly — Kubernetes events/pods AND node/system evidence, not "
            "just the workload. " + narrative
        )
    elif scope == "workload":
        narrative = (
            "This alert is a user workload inside the Run:ai platform. Focus on the "
            "Run:ai scheduler and the workload's scheduling/quota/startup, and read the "
            "scheduler/control-plane logs. " + narrative
        )
    elif scope == "infra" and _is_generic_infra(target):
        narrative = (
            "This alert targets a generic Kubernetes/monitoring component, NOT a Run:ai "
            "workload — treat it as ordinary Kubernetes troubleshooting: read the pod's "
            "logs, describe its state/events (waiting/terminated reason, restarts, "
            "last-state exit code), and check node/system health. Do not assume the "
            "Run:ai scheduler or control plane. " + narrative
        )
    if node_focused:
        node_note = (
            "No namespace/project/queue on this alert, so the workload, Loki, and Run:ai "
            "agents will likely report '증거를 찾기 어렵습니다.'. Focus the investigation on "
            "node/system level: the system agent (node syslog/journalctl/dmesg) and "
            "Kubernetes node conditions are the primary evidence sources. "
        )
        narrative = node_note + narrative
    if change_lead:
        narrative = _recent_change_narrative(settings, change_lead) + narrative

    if matched_alert:
        narrative = (
            f"Documented Run:ai alert '{matched_alert.get('alert')}' "
            f"({matched_alert.get('severity', 'n/a')}): {matched_alert.get('trigger', '')} "
            + narrative
        )
    if component_entry:
        narrative = (
            f"The alert target IS the platform component '{component}' "
            f"({component_entry.get('failure_effect') or component_entry.get('purpose')}). "
            "Check that component and its depends_on chain first. " + narrative
        )

    plan = InvestigationPlan(
        focus=focus,
        namespaces=namespaces,
        node=target.node or "",
        workload=target.workload_name or "",
        pod=target.pod or "",
        check_control_plane=check_control_plane,
        hypotheses=hypotheses,
        strategy=strategy,
        used_similarity=used_similarity,
        used_ontology=used_ontology,
        narrative=narrative,
        matched_alert=matched_alert,
        component=component,
        diagnostic_directive=diagnostic_directive,
        case_cards=list(kg_context.get("case_cards") or [])[:3],
    )

    # Operator guidance (the prompt an operator attached to this Analyze request /
    # their feedback) is a human directive — the LLM refine must honor it.
    guidance = str((getattr(alert, "annotations", None) or {}).get("operator_prompt") or "")

    if llm_configured(settings, settings.llm_model_planner):
        try:
            refined = await _llm_refine(
                settings, target, plan, kg_context, similar_incidents, guidance
            )
            if refined:
                plan = refined
        except Exception:  # noqa: BLE001 - planning is best-effort; keep deterministic plan
            _log.warning("LLM plan refinement failed; using deterministic plan", exc_info=True)

    return plan


async def _llm_refine(
    settings: Settings,
    target: AnalysisTarget,
    plan: InvestigationPlan,
    kg_context: dict,
    similar_incidents: list,
    guidance: str = "",
) -> InvestigationPlan | None:
    kg_summary = "none"
    if kg_context.get("available"):
        prior = kg_context.get("prior_incidents") or []
        kg_summary = (
            f"blast_radius={kg_context.get('blast_radius_workloads', 0)} workloads; "
            f"{len(prior)} prior incident(s) for this alert; "
            f"knowledge families={sorted((kg_context.get('knowledge') or {}).keys())}"
        )
    sim_lines = [
        f"- {getattr(i, 'incident_id', '?')} sim={getattr(i, 'similarity', 0):.2f}: "
        f"{getattr(i, 'analysis_summary', '') or getattr(i, 'title', '')}"
        for i in similar_incidents[:5]
    ] or ["- none"]

    system = (
        "You are a senior SRE planning a root-cause investigation for an NVIDIA Run:ai "
        "GPU platform. Given the alert, knowledge-graph summary, and similar past "
        "incidents, refine the investigation plan. Be honest: if nothing matches, keep "
        "strategy breadth_first and describe HOW to approach. Do not force-fit a prior "
        "incident. Keys: focus (str), hypotheses (list of {family, reason}), strategy "
        "('targeted' or 'breadth_first'), narrative (str). "
        "You may WIDEN the search when your re-reasoning calls for it — you can never "
        "narrow it below what the deterministic router already chose. Optional key "
        "check_control_plane (bool): set true to ALSO read Run:ai control-plane "
        "logs/pods (runai, runai-backend) when your leading hypothesis points at the "
        "platform / scheduler / backend. "
        "Respect the investigation scope: 'platform' = a Run:ai platform namespace (the "
        "control plane itself) — investigate Kubernetes and node/system evidence "
        "broadly; 'workload' = a user workload running inside Run:ai — focus on the "
        "Run:ai scheduler and the workload's scheduling/quota/startup; 'infra' = "
        "node/system level first. "
        "If operator guidance is present it is a direct instruction from the human "
        "operator — honor it when ordering hypotheses and writing the narrative "
        "(e.g. if it says this is a GPU problem, lead with the GPU/hardware path)."
    )
    if getattr(settings, "language", "en") == "ko":
        system += " Write the focus, reason, and narrative values in Korean."
    user = _planner_masker(settings).mask_text(
        f"Alert: {target.alert_name}\n"
        f"Operator guidance: {guidance or '(none)'}\n"
        f"Namespace: {target.namespace} (scope: {_namespace_scope(target, settings)})  "
        f"Node: {target.node}  "
        f"Workload: {target.workload_name}  Pod: {target.pod}  "
        f"Project: {target.project}  Queue: {target.queue}\n"
        f"Knowledge graph: {kg_summary}\n"
        f"Similar incidents (only >=0.80 are trustworthy):\n" + "\n".join(sim_lines) + "\n\n"
        f"Current deterministic plan:\n"
        f"focus={plan.focus}\nstrategy={plan.strategy}\n"
        f"hypotheses={plan.hypotheses}\nnarrative={plan.narrative}\n"
    )
    data = await complete_json(settings, system=system, user=user, model=settings.llm_model_planner)
    if not data:
        return None

    masker = _planner_masker(settings)
    focus = data.get("focus")
    strategy = data.get("strategy")
    narrative = data.get("narrative")
    hypotheses = _coerce_hypotheses(data.get("hypotheses"), masker)

    # Scope may only WIDEN, never narrow: when the LLM re-reasons the cause toward the
    # platform, it can turn control-plane reading ON, but it cannot switch off evidence
    # the deterministic router already required. This keeps "what's the cause" and
    # "where to look" moving together while the deterministic floor stays intact.
    check_control_plane = plan.check_control_plane or data.get("check_control_plane") is True
    namespaces = list(plan.namespaces)
    if check_control_plane and not plan.check_control_plane:
        # Newly widened by the LLM — mirror the deterministic control-plane sweep so the
        # control-plane namespaces are actually read (collectors also gate on the flag).
        for ns in settings.runai_log_namespaces:
            if ns and ns not in namespaces:
                namespaces.append(ns)

    return InvestigationPlan(
        focus=_plan_text(masker, focus, limit=240)
        if isinstance(focus, str) and focus.strip()
        else plan.focus,
        namespaces=namespaces,
        node=plan.node,
        workload=plan.workload,
        pod=plan.pod,
        check_control_plane=check_control_plane,
        hypotheses=hypotheses or plan.hypotheses,
        strategy=strategy if strategy in ("targeted", "breadth_first") else plan.strategy,
        used_similarity=plan.used_similarity,
        used_ontology=plan.used_ontology,
        narrative=_plan_text(masker, narrative, limit=800)
        if isinstance(narrative, str) and narrative.strip()
        else plan.narrative,
        matched_alert=plan.matched_alert,
        component=plan.component,
        diagnostic_directive=plan.diagnostic_directive,
        case_cards=plan.case_cards,
    )


def _planner_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _plan_text(masker, value: object, *, limit: int) -> str:
    text = " ".join(masker.mask_text(str(value or "")).split())
    return text[:limit]


def _coerce_hypotheses(value: object, masker=None) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, dict) and item.get("family"):
            family = str(item["family"])
            reason = str(item.get("reason", ""))
            if masker is not None:
                family = _plan_text(masker, family, limit=120)
                reason = _plan_text(masker, reason, limit=360)
            out.append(
                {"family": family, "reason": reason}
            )
    return out
