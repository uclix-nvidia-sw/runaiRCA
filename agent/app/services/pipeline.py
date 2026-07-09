from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, resolve_target
from app.collectors.registry import build_collectors
from app.config import Settings
from app.knowledge import (
    _keyword_negated,
    component_action_lines,
    component_check_lines,
    dependency_path,
    load_architecture,
    load_failure_modes,
    load_runai_known_issues,
    load_troubleshooting_cases,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)
from app.llm import (
    complete,
    complete_json,
    llm_configured,
    parse_json_object,
    token_budget_exceeded,
    token_budget_warning,
)
from app.masking import Masker, build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.prompts import load_agent_souls
from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse
from app.services.decision_tree import load_tree, walk_tree
from app.services.kg_enrichment import GraphRemediation, enrich, graph_remediation
from app.services.planner import plan_investigation
from app.services.root_cause_ranking import RankedCause, rank_root_cause_candidates

_log = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)
Stage = Callable[["PipelineState"], Awaitable["PipelineState"]]
_SYNTHESIS_ARTIFACT_RESULT_CHARS = 1200
_SYNTHESIS_USER_CHARS = 12000


@dataclass
class PipelineState:
    settings: Settings
    request: AlertAnalysisRequest
    target: AnalysisTarget
    progress: ProgressReporter
    masker: Masker
    collectors: list[object]
    runtime_label: str = "fallback"
    agent_souls: str = ""
    kg_context: Any = None
    plan: InvestigationPlan | None = None
    results: list[CollectorResult] = field(default_factory=list)
    investigation_context: dict[str, object] = field(default_factory=dict)
    priors: dict[str, float] | None = None
    observed: str = ""
    alert_fuzzy: str = ""
    xid_codes: list[int] = field(default_factory=list)
    failure_modes: dict[str, list[dict]] = field(default_factory=dict)
    known_issues: list[dict] = field(default_factory=list)
    root_cause_candidates: list[RankedCause] = field(default_factory=list)
    self_check_caveat: str = ""
    self_check_refuted: bool = False
    self_check_next: str = ""
    reanalysis_note: str = ""
    graph_fixes: GraphRemediation | None = None
    timeline: object | None = None
    troubleshooting_path: dict[str, Any] | None = None
    quality: str = ""
    summary: str = ""
    detail: str = ""
    extra_warnings: list[str] = field(default_factory=list)
    capabilities: dict[str, str] = field(default_factory=dict)
    artifacts: list[object] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    response: AlertAnalysisResponse | None = None
    analysis_started_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class _ReanalysisTarget:
    family: str
    reason: str
    refuted_family: str = ""
    initial_refutation: bool = False


@dataclass(frozen=True)
class _ReanalysisOutcome:
    results: list[CollectorResult]
    candidates: list[RankedCause]
    caveat: str
    note: str
    refuted: bool
    next_check: str


def new_state(
    settings: Settings,
    request: AlertAnalysisRequest,
    *,
    collectors: list[object] | None = None,
    runtime_label: str = "fallback",
) -> PipelineState:
    target = resolve_target(request.alert.labels, request.alert.annotations)
    masker = _build_settings_masker(settings)
    return PipelineState(
        settings=settings,
        request=request,
        target=target,
        progress=ProgressReporter.from_alert(settings, request.alert, masker),
        masker=masker,
        collectors=collectors if collectors is not None else build_collectors(settings),
        runtime_label=runtime_label,
    )


def _aggregate_evidence(state: PipelineState) -> None:
    kg_warnings = getattr(state.kg_context, "warnings", []) if state.kg_context is not None else []
    state.capabilities = {result.agent: result.status for result in state.results}
    state.artifacts = [artifact for result in state.results for artifact in result.artifacts]
    state.missing = sorted({item for result in state.results for item in result.missing_data})
    state.warnings = sorted(
        {item for result in state.results for item in result.warnings}
        | set(state.extra_warnings)
        | set(kg_warnings)
    )


async def enrich_stage(state: PipelineState) -> PipelineState:
    target = state.target
    state.progress.emit(
        "planning",
        "Analysis started",
        target=target.__dict__,
    )
    _log.info(
        "analyze start: alert=%s ns=%s node=%s workload=%s",
        target.alert_name,
        target.namespace,
        target.node,
        target.workload_name,
    )
    # Knowledge graph is consulted once here, at synthesis time, as a
    # knowledge resource for the final RCA — not as a parallel collector.
    state.kg_context = await enrich(state.settings, target)
    return state


async def plan_stage(state: PipelineState) -> PipelineState:
    recent_changes = await _preplan_recent_changes(state)
    # Plan first (senior-SRE "think before you dig"): scope every collector to
    # what THIS alert needs instead of always scraping the control plane.
    state.plan = await plan_investigation(
        state.settings,
        state.target,
        state.request.alert,
        state.kg_context.as_dict(),
        list(state.request.similar_incidents),
        recent_changes,
    )
    # Alert labels frequently name a pod the controller already replaced (grouped
    # CrashLoop occurrences) and carry no node label — so kubernetes GETs 404 and
    # the system agent skips node/kernel evidence entirely. Re-resolve a LIVE pod
    # and its node ONCE here; every collector then scopes off the plan.
    seed_pod = state.plan.pod or state.target.pod
    if state.target.namespace and seed_pod:
        from app.collectors.kubernetes import resolve_live_pod_node

        live_pod, live_node = await resolve_live_pod_node(
            state.settings,
            state.target.namespace,
            seed_pod,
            list(state.request.occurrence_pods),
        )
        if live_pod and live_pod != seed_pod:
            _log.info("plan: stale pod %s re-resolved to live pod %s", seed_pod, live_pod)
        if live_pod:
            state.plan.pod = live_pod
        # Never override an explicit node label from the alert itself.
        state.plan.node = state.plan.node or live_node
    state.progress.emit(
        "planning",
        "Investigation plan built",
        plan=state.plan.as_dict(),
        hypotheses=state.plan.hypotheses,
    )
    _log.info(
        "plan: strategy=%s focus=%s hypotheses=%s",
        state.plan.strategy,
        state.plan.focus,
        [h.get("family") for h in (state.plan.hypotheses or [])[:3]],
    )
    state.agent_souls = load_agent_souls(state.settings.agent_souls_file)
    return state


async def _preplan_recent_changes(state: PipelineState) -> list[dict]:
    collector = next((c for c in state.collectors if getattr(c, "name", "") == "change"), None)
    if collector is None:
        return []
    result = await _collect_safely(collector, state.target, None, state.masker)
    changes = result.details.get("changes") if isinstance(result.details, dict) else None
    return [c for c in changes if isinstance(c, dict)] if isinstance(changes, list) else []


async def evidence_stage(state: PipelineState) -> PipelineState:
    settings = state.settings
    plan = state.plan
    assert plan is not None
    # The plan is authoritative after plan_stage — it may carry a re-resolved
    # LIVE pod/node for a stale alert pod. Scope the stage's working target ONCE
    # so the flowchart follow-ups, drill-down, and investigation loop query the
    # live pod too, not just the base collectors (which scope internally).
    from app.collectors.kubernetes import _scope_target

    target = _scope_target(state.target, plan)
    state.investigation_context = {}

    # Synthesis MUST see EVERY collector's result. Await the full gather over ALL
    # collectors here, before any ranking/synthesis, and never synthesize from a
    # subset — an early/partial synthesis would produce a confident-but-wrong RCA.
    # LLM-gated senior-SRE loop when enabled; otherwise the one-shot gather. Both
    # return one CollectorResult per collector (investigate runs any it skipped).
    if (
        llm_configured(settings, settings.llm_model_investigation)
        and settings.enable_investigation_loop
    ):
        from app.services.investigator import investigate

        state.results, state.investigation_context = await investigate(
            settings,
            target,
            state.collectors,
            plan,
            state.kg_context.as_dict(),
            settings.max_investigation_steps,
            reporter=state.progress,
        )
    else:
        state.progress.emit("collection", "Gathering collector evidence")
        state.results = list(
            await asyncio.gather(
                *(
                    _collect_safely(collector, target, plan, state.masker)
                    for collector in state.collectors
                )
            )
        )
        state.progress.emit(
            "collection",
            "Collector evidence gathered",
            collectors=[result.agent for result in state.results],
        )
    assert len(state.results) == len(state.collectors), (
        "synthesis must wait for all collectors: "
        f"{len(state.results)} results for {len(state.collectors)} collectors"
    )
    # Deterministic flowchart-driven follow-up: keep pulling k8s evidence based on
    # what was found (Pending -> events/quota/pvc -> storageclass; CrashLoop/
    # ImagePull -> events). Runs with OR without the LLM loop, so collection stays
    # iterative even when litellm is down (the ReAct loop is skipped then).
    try:
        from app.collectors.kubernetes import k8s_followup
        from app.collectors.prometheus import prometheus_followup

        k8s_result = next((r for r in state.results if r.agent == "kubernetes"), None)
        prom_result = next((r for r in state.results if r.agent == "prometheus"), None)
        await k8s_followup(settings, k8s_result, target)
        # Cross-collector: k8s findings (OOM/restart/Pending) -> derived PromQL.
        await prometheus_followup(settings, prom_result, k8s_result, target)
    except Exception:  # noqa: BLE001 - follow-up is best-effort, never fail analysis
        pass
    # Per-collector autonomous drill-down (LLM-gated): each domain agent runs a
    # bounded LLM loop with ONLY its domain's read-only tools to deepen its own
    # evidence (services/drilldown.py). Best-effort, never fails analysis.
    try:
        from app.services.drilldown import run_drilldowns

        await run_drilldowns(settings, state.results, target, plan)
    except Exception:  # noqa: BLE001 - drill-down is best-effort
        pass
    for r in state.results:
        _log.info(
            "evidence: agent=%s status=%s confidence=%s — %s",
            r.agent,
            r.status,
            r.confidence,
            " ".join((r.summary or "").split())[:160],
        )

    _aggregate_evidence(state)
    return state


def _component_identity(
    settings: Settings, plan: InvestigationPlan | None
) -> tuple[str, str, list[str]]:
    """Topology signal for the ranker: (component_family, component, depends_on chain).

    The planner already resolved which platform component the alert target IS
    (``plan.component``). Look up its curated family and dependency check order
    from runai_architecture.yaml so the ranker can lead with the right subsystem
    (e.g. runai-container-toolkit → gpu_hardware_error, check the GPU Operator
    stack) instead of a keyword-only node/workload guess. Empty when the target
    is not a known component or the map is unavailable.
    """
    component = str(getattr(plan, "component", "") or "")
    if not component:
        return "", "", []
    components = load_architecture(settings.architecture_file)
    entry = components.get(component)
    if not entry:
        return "", component, []
    family = str(entry.get("family") or "")
    chain = dependency_path(components, component)
    return family, component, chain


def _affected_pods_from_results(results: list[CollectorResult]) -> list[str]:
    """Concrete pod names the kubernetes collector discovered for the alert subject.

    Alerts routed through kube-state-metrics name the KSM EXPORTER pod, not the
    workload that actually broke. When the investigation was scoped to a concrete
    subject (a named pod, or a workload whose pods we listed), the kubernetes
    collector already fetched the real pods into ``details["pod_statuses"]`` — each
    entry carries a top-level ``name``. Surface those so the dashboard can show the
    impacted pods. Returns ``[]`` for unscoped (namespace/node-only) investigations,
    where a pod listing would not represent "affected" pods.
    """
    for result in results:
        if getattr(result, "agent", "") != "kubernetes":
            continue
        details = result.details if isinstance(result.details, dict) else None
        if not details:
            return []
        scoped = bool(
            str(details.get("workload_name") or "").strip()
            or str(details.get("pod") or "").strip()
        )
        if not scoped:
            return []
        statuses = details.get("pod_statuses")
        if not isinstance(statuses, list):
            return []
        names: list[str] = []
        seen: set[str] = set()
        for entry in statuses:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not isinstance(name, str):
                meta = entry.get("metadata")
                name = meta.get("name") if isinstance(meta, dict) else None
            if isinstance(name, str):
                cleaned = name.strip()
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    names.append(cleaned)
        return names[:25]
    return []


def _lifecycle_signal(
    results: list[CollectorResult], component: str, chain: list[str]
) -> dict[str, object]:
    """Nature signal for the ranker: is the implicated component mid-rollout?

    Reads the change collector's structured rollout flags. A lifecycle event is
    "active" only when a controller that IS the alert's component (or sits in its
    depends_on chain) is mid-rollout — so unrelated namespace churn never trips
    it. ``target_rollout`` means the alert's OWN component is the one rolling,
    which is dispositive. Empty dict = no lifecycle signal (ranking stays legacy).
    """
    change = next((r for r in results if getattr(r, "agent", "") == "change"), None)
    if change is None or getattr(change, "status", "") not in ("ok", "partial"):
        return {}
    details = change.details if isinstance(change.details, dict) else {}
    changes = details.get("changes") if isinstance(details.get("changes"), list) else []
    rolling = {
        str(c.get("name"))
        for c in changes
        if isinstance(c, dict) and c.get("rollout") and c.get("name")
    }
    if not rolling:
        return {}
    implicated = set(chain or ([component] if component else []))
    hit = sorted(rolling & implicated)
    if not hit:
        return {}
    # Name the upstream Helm trigger (if any) among the matched components so the
    # ranker rationale can point at the real change instead of a downstream symptom.
    helm = [
        f"{c.get('name')} rev {c.get('revision')} ({c.get('helm_status') or 'changed'})"
        for c in changes
        if isinstance(c, dict)
        and c.get("kind") == "HelmRelease"
        and str(c.get("name")) in set(hit)
    ]
    signal: dict[str, object] = {
        "active": True,
        "components": hit,
        "target_rollout": bool(component and component in rolling),
    }
    if helm:
        signal["helm"] = helm
    return signal


_LIFECYCLE_FAMILY = "platform_lifecycle_change"


def _gate_lifecycle_symptoms(
    matches: list[tuple[str, dict]], lifecycle: dict[str, object] | None
) -> list[tuple[str, dict]]:
    """Drop lifecycle symptom matches unless the lifecycle signal is active.

    ``_promote_signature_cause`` runs after the ranker and can override its top
    family from a curated symptom keyword. The lifecycle symptoms match the
    change collector's generic ``mid-rollout`` text, so WITHOUT this gate a
    coincidental unrelated rollout in the alert namespace could promote
    ``platform_lifecycle_change`` over a genuine fault — the exact ungated
    over-attribution the ranker's component-chain gate was built to prevent.
    """
    if lifecycle and lifecycle.get("active"):
        return matches
    return [(fam, sym) for fam, sym in matches if fam != _LIFECYCLE_FAMILY]


async def rank_stage(state: PipelineState) -> PipelineState:
    settings = state.settings
    request = state.request
    # Topology identity resolved by the planner (which component the alert IS).
    comp_family, comp_name, comp_chain = _component_identity(settings, state.plan)
    lifecycle = _lifecycle_signal(state.results, comp_name, comp_chain)
    try:
        from app.services.feedback_priors import derive_priors
    except ImportError:
        pass
    else:
        state.priors = derive_priors(request.feedback_hints)
    state.progress.emit(
        "ranking",
        "Ranking root-cause candidates",
        hypothesis_ledger=state.investigation_context.get("hypothesis_ledger"),
    )
    state.root_cause_candidates = rank_root_cause_candidates(
        state.target,
        state.results,
        occurrence_count=request.occurrence_count,
        kg_blast_radius=state.kg_context.blast_radius_workloads,
        priors=state.priors,
        component_family=comp_family,
        component=comp_name,
        depends_on_chain=comp_chain,
        lifecycle=lifecycle,
    )
    # Signature-first headline: the keyword ranker only decides when NOTHING
    # specific matched. A specific signature — an NVIDIA XID (dispositive), a
    # known-issue signature, or a curated symptom keyword — names the cause
    # family directly; the ranker chronically mis-headlined these (e.g.
    # node_kubelet_pressure winning on "DiskPressure"/"kubelet" words present in
    # the k8s node-conditions text even when every condition is False).
    state.observed = _observed_text(state.results, request)
    state.xid_codes = _xid_codes_from_results(state.results, _alert_text(request))
    state.failure_modes = load_failure_modes(settings.failure_modes_file)
    state.known_issues = load_runai_known_issues(settings.runai_known_issues_file)
    # Version-aware precision: drop known issues already fixed in the cluster's
    # running Run:ai version so we don't attribute a symptom to a patched bug.
    state.known_issues = _suppress_fixed_known_issues(
        state.known_issues, _runai_version_from(state.results)
    )
    # Fuzzy recall (BM25+synonyms, app.bm25) queries the alert's OWN text only:
    # collector summaries would feed pipeline boilerplate to the matcher. And it
    # informs, never headlines: promotion below stays exact-signature-only (a
    # statistical hit is not "a specific signature that names the cause family"
    # — e.g. NodeDiskPressure's disk+pressure tokens must not promote a
    # database-disk known issue), while the playbook/actions/verify surfaces
    # use fuzzy matches as candidates the LLM verify pass can still refute.
    state.alert_fuzzy = _alert_text(request)
    state.root_cause_candidates = _promote_signature_cause(
        state.root_cause_candidates,
        state.xid_codes,
        match_runai_known_issues(state.known_issues, state.observed),
        _gate_lifecycle_symptoms(
            match_failure_mode_symptoms(state.failure_modes, state.observed), lifecycle
        ),
    )
    if state.root_cause_candidates:
        top = state.root_cause_candidates[0]
        state.progress.emit(
            "ranking",
            f"Top candidate: {top.family}",
            top_root_cause=top.as_dict(),
            root_cause_candidates=[
                candidate.as_dict() for candidate in state.root_cause_candidates
            ],
        )
        _log.info(
            "ranked cause: %s (confidence=%s score=%.1f agents=%s)",
            top.family,
            top.confidence,
            top.score,
            top.evidence_agents,
        )
    return state


async def self_check_stage(state: PipelineState) -> PipelineState:
    # Optional self-check: refute the top cause, apply its calibrated confidence
    # to the top candidate, and keep the caveat text for the report.
    try:
        from app.services.self_check import refute_top_cause
    except ImportError:
        pass
    else:
        if state.root_cause_candidates:
            state.progress.emit("self_check", "Checking whether the top cause can be refuted")
            check = await refute_top_cause(
                state.settings,
                state.root_cause_candidates[0],
                state.results,
                plan=state.investigation_context,
            )
            if isinstance(check, dict):
                calibrated = check.get("confidence")
                if calibrated in ("low", "medium", "high"):
                    state.root_cause_candidates[0].confidence = calibrated
                state.self_check_caveat = str(check.get("caveat") or "").strip()
                state.self_check_refuted = bool(check.get("refuted"))
                state.self_check_next = str(check.get("next_check") or "").strip()
            state.progress.emit(
                "self_check",
                "Self-check complete",
                refuted=state.self_check_refuted,
                caveat=state.self_check_caveat,
                next_check=state.self_check_next,
            )
    return state


async def synthesize_stage(state: PipelineState) -> PipelineState:
    settings = state.settings
    request = state.request
    plan = state.plan
    assert plan is not None

    # Graph-derived remediation from the validated TypeDB reasoning functions,
    # keyed to the ranked top family + any Xid codes / GPU model in the evidence.
    # Best-effort: an empty result when TypeDB is off/unreachable.
    top_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
    state.graph_fixes = await graph_remediation(
        settings,
        family=top_family if top_family != "insufficient_evidence" else "",
        # xid_codes already includes the alert's own text (NVRM Xid alerts name
        # their code even when every collector comes back empty).
        xid_codes=state.xid_codes,
        gpu_model=_gpu_model_from(state.target, state.results),
    )
    _aggregate_evidence(state)
    state.warnings = sorted(set(state.warnings) | set(state.graph_fixes.warnings))
    # Optional change/timeline capability — added to the synthesis context.
    try:
        from app.services.timeline import build_timeline
    except ImportError:
        pass
    else:
        state.timeline = build_timeline(state.results)
    state.troubleshooting_path = walk_tree(
        load_tree(_k8s_troubleshooting_tree_path(settings)),
        _observed_text(state.results, request),
    )
    state.quality = _quality_from(state.results)
    # Adversarial precision: LLM-verify signature/keyword matches (known issues,
    # failure-mode symptoms, GPU XIDs) and drop ones the evidence doesn't support.
    # Best-effort + LLM-gated: with no LLM nothing is suppressed. (failure_modes /
    # known_issues / observed were computed before ranking promotion above.)
    try:
        from app.services.self_check import verify_known_issues, verify_matches
    except ImportError:
        pass
    else:
        ki_matches = match_runai_known_issues(
            state.known_issues, state.observed, fuzzy_query=state.alert_fuzzy
        )
        if ki_matches:
            refuted = await verify_known_issues(settings, ki_matches, state.results)
            if refuted:
                state.root_cause_candidates = _drop_refuted_signature_candidates(
                    state.root_cause_candidates, refuted
                )
                state.known_issues = [
                    k for k in state.known_issues if k.get("issue") not in refuted
                ]

        ev_candidates = [
            {
                "name": sym.get("symptom", ""),
                "detail": f"{fam} — {'; '.join(sym.get('actions', [])[:1])}",
            }
            for fam, sym in match_failure_mode_symptoms(
                state.failure_modes, state.observed, fuzzy_query=state.alert_fuzzy
            )
        ]
        ev_candidates += [
            {"name": f"XID {code}", "detail": "; ".join(state.graph_fixes.xid_fixes[code][:1])}
            for code in state.graph_fixes.xid_fixes
        ]
        if ev_candidates:
            refuted = await verify_matches(
                settings, ev_candidates, state.results, subject="matched symptom or GPU XID"
            )
            if refuted:
                state.root_cause_candidates = _drop_refuted_signature_candidates(
                    state.root_cause_candidates, refuted
                )
                state.failure_modes = {
                    fam: [s for s in syms if s.get("symptom") not in refuted]
                    for fam, syms in state.failure_modes.items()
                }
                for label in refuted:
                    if label.startswith("XID "):
                        try:
                            code = int(label[4:])
                        except ValueError:
                            continue
                        state.graph_fixes.xid_fixes.pop(code, None)
                        state.graph_fixes.root_xids.pop(code, None)
    state.summary = _summary_from(request, state.results, state.root_cause_candidates)
    playbook_fallback = load_troubleshooting_cases(settings.troubleshooting_cases_file)
    state.detail = _detail_from(
        request,
        state.results,
        state.missing,
        state.failure_modes,
        playbook_fallback,
        state.agent_souls,
        state.root_cause_candidates,
        state.kg_context.as_dict(),
        plan,
        state.graph_fixes,
        language=getattr(settings, "language", "en"),
        known_issues=state.known_issues,
        components=load_architecture(settings.architecture_file),
        masker=state.masker,
    )
    # Korean LLM synthesis (preferred when language == "ko" and LLM configured):
    # rewrite summary + detail grounded STRICTLY in the evidence just gathered.
    # Falls back to the deterministic English report on any failure.
    if getattr(settings, "language", "en") == "ko":
        synth = None
        if llm_configured(settings, settings.llm_model_synthesis):
            synth = await _synthesize_korean(
                settings,
                request=request,
                results=state.results,
                plan=plan,
                root_cause_candidates=state.root_cause_candidates,
                kg_context=state.kg_context.as_dict(),
                graph_fixes=state.graph_fixes,
                fallback_detail=state.detail,
                timeline=state.timeline,
                troubleshooting_path=state.troubleshooting_path,
            )
        if synth:
            state.summary, state.detail = synth
        elif llm_configured(settings, getattr(settings, "llm_model_insight", "")):
            # Synthesis fell back to the deterministic report, which splices the
            # curated KB playbook in verbatim ENGLISH — translate that one
            # section so the operator guidance still reads in their language.
            state.detail = await _translate_playbook_ko(settings, state.detail)

    # Self-check caveat (optional hook) + re-analysis note — inserted BEFORE the
    # appendix so the document reads problem -> cause -> actions -> checks -> appendix.
    self_check_lines = [text for text in (state.self_check_caveat, state.reanalysis_note) if text]
    if self_check_lines:
        state.detail = _insert_before_appendix(
            state.detail, "## Self-Check\n\n" + "\n\n".join(self_check_lines)
        )

    # Operator questions: when the RCA could not settle (insufficient evidence,
    # or still refuted after re-analysis), honestly ask for the missing inputs.
    top_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
    if top_family in ("", "insufficient_evidence") or state.self_check_refuted:
        try:
            questions = await _operator_questions(
                settings, state.missing, plan, state.target, state.self_check_next
            )
        except Exception:  # noqa: BLE001 - questions are best-effort
            questions = []
        if questions:
            header = (
                "## 추가 확인 요청"
                if getattr(settings, "language", "en") == "ko"
                else "## Questions for the Operator"
            )
            body = "\n".join(f"- {question}" for question in questions)
            state.detail = _insert_before_appendix(state.detail, f"{header}\n\n{body}")

    affected_pods = _affected_pods_from_results(state.results)

    state.response = AlertAnalysisResponse(
        status="ok",
        thread_ts=request.thread_ts,
        analysis=state.detail,
        analysis_summary=state.summary,
        analysis_detail=state.detail,
        analysis_type=request.analysis_type or request.alert.status or "firing",
        analysis_quality=state.quality,
        root_cause_family=(
            state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        ),
        missing_data=state.missing,
        warnings=state.warnings,
        capabilities=state.capabilities,
        affected_pods=affected_pods,
        context={
            "target": state.target.__dict__,
            "nemo_runtime": "enabled" if state.runtime_label == "enabled" else "fallback",
            "occurrence_count": request.occurrence_count,
            "occurrence_pods": request.occurrence_pods,
            "affected_pods": affected_pods,
            "similar_incidents": [
                item.model_dump(mode="json") for item in request.similar_incidents
            ],
            "feedback_hints": [item.model_dump(mode="json") for item in request.feedback_hints],
            "agent_souls_file": settings.agent_souls_file,
            "agent_souls_applied": bool(state.agent_souls),
            "root_cause_candidates": [
                candidate.as_dict() for candidate in state.root_cause_candidates
            ],
            "top_root_cause": (
                state.root_cause_candidates[0].as_dict() if state.root_cause_candidates else None
            ),
            "knowledge_base": state.kg_context.as_dict(),
            "plan": plan.as_dict(),
            "hypothesis_ledger": state.investigation_context.get("hypothesis_ledger"),
            "investigation": state.investigation_context,
            **({"timeline": state.timeline} if state.timeline else {}),
            **(
                {"troubleshooting_path": state.troubleshooting_path}
                if state.troubleshooting_path and state.troubleshooting_path.get("path")
                else {}
            ),
        },
        artifacts=state.artifacts,
    )
    state.response = _mask_model(state.response, AlertAnalysisResponse, state.masker)
    return state


async def run_pipeline(
    state: PipelineState,
    stages: dict[str, Stage] | None = None,
) -> AlertAnalysisResponse:
    stages = stages or {}
    for name, stage in (
        ("enrich", enrich_stage),
        ("plan", plan_stage),
        ("evidence", evidence_stage),
        ("rank", rank_stage),
        ("self_check", self_check_stage),
    ):
        state = await stages.get(name, stage)(state)

    await _investigate_until_settled(state)

    state = await stages.get("synthesize", synthesize_stage)(state)
    assert state.response is not None
    return state.response


async def _investigate_until_settled(state: PipelineState) -> None:
    if not (
        state.root_cause_candidates
        and llm_configured(state.settings, state.settings.llm_model_investigation)
        and state.settings.enable_investigation_loop
    ):
        return
    cap = max(0, int(getattr(state.settings, "max_investigation_iterations", 0) or 0))
    if cap <= 0:
        return

    attempted: set[str] = set()
    # ponytail: cap 0 disables this control-flow expansion; the loop never recurses.
    for _ in range(cap):
        if not _needs_more_investigation(state):
            break
        if token_budget_exceeded(state.settings):
            state.extra_warnings.append(token_budget_warning(state.settings))
            _aggregate_evidence(state)
            break
        if _deadline_exceeded(state):
            state.extra_warnings.append(
                "analysis deadline reached; skipped additional investigation iterations"
            )
            _aggregate_evidence(state)
            break

        target = _next_reanalysis_target(state, attempted)
        if target is None:
            break
        before_evidence = _evidence_signature(state.results)
        before_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        attempted.add(target.family)
        outcome = await _reanalyze_once(state, target=target)
        if outcome is None:
            break

        state.results = outcome.results
        state.root_cause_candidates = outcome.candidates
        state.self_check_caveat = outcome.caveat
        state.reanalysis_note = "\n\n".join(
            note for note in (state.reanalysis_note, outcome.note) if note
        )
        state.self_check_refuted = outcome.refuted
        state.self_check_next = outcome.next_check
        _aggregate_evidence(state)

        after_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        if after_family == before_family and _evidence_signature(state.results) == before_evidence:
            break


def _needs_more_investigation(state: PipelineState) -> bool:
    if not state.root_cause_candidates:
        return False
    top = state.root_cause_candidates[0]
    return (
        state.self_check_refuted
        or top.confidence not in {"medium", "high"}
        or bool(state.missing)
    )


def _next_reanalysis_target(
    state: PipelineState, attempted: set[str]
) -> _ReanalysisTarget | None:
    top = state.root_cause_candidates[0] if state.root_cause_candidates else None
    refuted_family = top.family if top and state.self_check_refuted else ""
    excluded = {
        family
        for family in (*attempted, refuted_family, "insufficient_evidence")
        if family
    }

    if state.self_check_refuted:
        for candidate in state.root_cause_candidates[1:]:
            if candidate.family not in excluded:
                return _ReanalysisTarget(
                    candidate.family,
                    "re-analysis after the previous conclusion was refuted",
                    refuted_family,
                    not state.reanalysis_note,
                )
        kg_blast = getattr(state.kg_context, "blast_radius_workloads", 0)
        comp_family, comp_name, comp_chain = _component_identity(state.settings, state.plan)
        lifecycle = _lifecycle_signal(state.results, comp_name, comp_chain)
        for candidate in rank_root_cause_candidates(
            state.target,
            state.results,
            occurrence_count=state.request.occurrence_count,
            top_n=5,
            kg_blast_radius=kg_blast,
            priors=state.priors,
            component_family=comp_family,
            component=comp_name,
            depends_on_chain=comp_chain,
            lifecycle=lifecycle,
        ):
            if candidate.family not in excluded:
                return _ReanalysisTarget(
                    candidate.family,
                    "re-analysis after the previous conclusion was refuted",
                    refuted_family,
                    not state.reanalysis_note,
                )

    if top and top.family not in excluded:
        return _ReanalysisTarget(
            top.family,
            "targeted follow-up for low-confidence or missing evidence",
            refuted_family,
        )

    plan = state.plan
    for hypothesis in (plan.hypotheses if plan else []) or []:
        family = str(hypothesis.get("family") or "").strip()
        if family and family not in excluded:
            return _ReanalysisTarget(
                family,
                str(hypothesis.get("reason") or "targeted follow-up for missing evidence"),
                refuted_family,
            )

    if state.missing and "evidence_gap" not in excluded:
        return _ReanalysisTarget(
            "evidence_gap",
            "targeted follow-up for missing evidence: " + ", ".join(state.missing[:5]),
            refuted_family,
        )
    return None


def _deadline_exceeded(state: PipelineState) -> bool:
    deadline = int(getattr(state.settings, "analysis_deadline_seconds", 0) or 0)
    return deadline > 0 and time.monotonic() - state.analysis_started_at >= deadline


def _evidence_signature(results: list[CollectorResult]) -> tuple[tuple[object, ...], ...]:
    return tuple(
        sorted(
            (
                result.agent,
                result.status,
                result.confidence,
                result.summary,
                tuple(result.missing_data),
                tuple(result.warnings),
                _json_fingerprint(result.details),
                tuple(_artifact_signature(artifact) for artifact in result.artifacts),
            )
            for result in results
        )
    )


def _artifact_signature(artifact: object) -> tuple[object, ...]:
    return (
        getattr(artifact, "title", ""),
        getattr(artifact, "status", ""),
        getattr(artifact, "summary", ""),
        _json_fingerprint(getattr(artifact, "result", None)),
    )


def _json_fingerprint(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return repr(value)


async def _reanalyze_once(
    state: PipelineState,
    *,
    target: _ReanalysisTarget,
) -> _ReanalysisOutcome | None:
    """One bounded targeted investigation pass. Never re-enters analyze()."""
    try:
        from app.services.investigator import investigate
        from app.services.self_check import refute_top_cause

        plan = state.plan
        assert plan is not None
        kg_dict = state.kg_context.as_dict()
        kg_blast = getattr(state.kg_context, "blast_radius_workloads", 0)
        comp_family, comp_name, comp_chain = _component_identity(state.settings, plan)

        lead = {
            "family": target.family,
            "reason": target.reason,
        }
        rest = [
            h
            for h in (plan.hypotheses or [])
            if isinstance(h, dict) and h.get("family") != target.family
        ]
        replan = replace(plan, hypotheses=[lead, *rest])
        fresh, re_context = await investigate(
            state.settings,
            state.target,
            state.collectors,
            replan,
            kg_dict,
            min(state.settings.max_reanalysis_steps, state.settings.max_investigation_steps),
        )
        merged = {result.agent: result for result in state.results}
        for result in fresh:
            merged[result.agent] = result
        merged_results = list(merged.values())

        lifecycle = _lifecycle_signal(merged_results, comp_name, comp_chain)
        candidates = rank_root_cause_candidates(
            state.target,
            merged_results,
            occurrence_count=state.request.occurrence_count,
            kg_blast_radius=kg_blast,
            priors=state.priors,
            component_family=comp_family,
            component=comp_name,
            depends_on_chain=comp_chain,
            lifecycle=lifecycle,
        )
        # The signature-first rule applies to the RE-rank too. Without it the
        # raw keyword ranker decided alone here — the 2026-07-08 re-analysis
        # "concluded" node_kubelet_pressure on a healthy node while the loki
        # reconcile errors still carried the real (signature-backed) cause.
        observed = _observed_text(merged_results, state.request)
        candidates = _promote_signature_cause(
            candidates,
            _xid_codes_from_results(merged_results, _alert_text(state.request)),
            match_runai_known_issues(state.known_issues, observed),
            _gate_lifecycle_symptoms(
                match_failure_mode_symptoms(state.failure_modes, observed), lifecycle
            ),
        )
        if token_budget_exceeded(state.settings) or _deadline_exceeded(state):
            if token_budget_exceeded(state.settings):
                state.extra_warnings.append(token_budget_warning(state.settings))
            else:
                state.extra_warnings.append(
                    "analysis deadline reached; skipped additional investigation iterations"
                )
            return None
        caveat = ""
        refuted = False
        next_check = ""
        if candidates:
            check = await refute_top_cause(
                state.settings,
                candidates[0],
                merged_results,
                plan=re_context,
            )
            if isinstance(check, dict):
                calibrated = check.get("confidence")
                if calibrated in ("low", "medium", "high"):
                    candidates[0].confidence = calibrated
                caveat = str(check.get("caveat") or "").strip()
                refuted = bool(check.get("refuted"))
                next_check = str(check.get("next_check") or "").strip()
        new_family = candidates[0].family if candidates else "insufficient_evidence"
        if target.refuted_family and getattr(state.settings, "language", "en") == "ko":
            label = "1차 결론" if target.initial_refutation else "이전 결론"
            note = (
                f"{label}({target.refuted_family})이 반증되어 "
                "재분석을 수행했습니다 → "
                f"재분석 결론: {new_family}"
            )
        elif target.refuted_family:
            label = "initial" if target.initial_refutation else "previous"
            note = (
                f"The {label} conclusion ({target.refuted_family}) was refuted, so a "
                f"targeted re-analysis pass was performed → revised conclusion: {new_family}."
            )
        elif getattr(state.settings, "language", "en") == "ko":
            note = (
                "낮은 확신/증거 공백 때문에 추가 조사를 수행했습니다 → "
                f"결론: {new_family}"
            )
        else:
            note = (
                "A targeted investigation pass was performed for low confidence "
                f"or evidence gaps → revised conclusion: {new_family}."
            )
        return _ReanalysisOutcome(
            merged_results, candidates, caveat, note, refuted, next_check
        )
    except Exception:  # noqa: BLE001 - re-analysis is best-effort; keep 1st result
        return None


async def _synthesize_korean(
    settings: Settings,
    *,
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    plan: InvestigationPlan,
    root_cause_candidates: list[RankedCause],
    kg_context: dict,
    graph_fixes: GraphRemediation,
    fallback_detail: str,
    timeline: list[dict] | None = None,
    troubleshooting_path: dict[str, Any] | None = None,
) -> tuple[str, str] | None:
    """LLM synthesis of the RCA report in Korean, grounded STRICTLY in the evidence.

    Returns (analysis_summary, analysis_detail) in Korean, or None on any failure so
    the caller keeps the deterministic English report. Never raises into analyze().
    """
    from app.collectors.http_json import compact

    observed_text = _observed_text(results, request)
    similar_incidents = (
        [
            {
                "incident_id": i.incident_id,
                "similarity": i.similarity,
                "analysis_summary": i.analysis_summary or i.title,
            }
            for i in request.similar_incidents
            if (i.similarity or 0) >= _SIMILARITY_FLOOR
        ]
        if _similar_incident_relevant(request, observed_text)
        else []
    )
    # Key ORDER matters: the final JSON is hard-capped at _SYNTHESIS_USER_CHARS,
    # which tail-truncates. Put the SMALL high-value inputs FIRST so a heavy
    # collector_findings block (many artifacts with trimmed-but-still-bulky raw
    # results) can only cost its OWN tail. operator_guidance leads: it is the
    # human operator's direct instruction (highest priority per the system
    # prompt) and must NEVER be truncated away.
    guidance_raw = (request.alert.annotations or {}).get("operator_prompt", "")
    operator_guidance = _short_sentence(str(guidance_raw), limit=500) if guidance_raw else ""
    evidence = {
        **({"operator_guidance": operator_guidance} if operator_guidance else {}),
        "alert": {
            "name": request.alert.labels.get("alertname"),
            "labels": request.alert.labels,
            "annotations": request.alert.annotations,
        },
        # Past-incident re-analysis signal: a resolved alert means the live state is
        # likely healthy again, so live collectors can legitimately be thin.
        **(
            {"incident_state": "resolved — alert no longer firing; live state likely normal, so live evidence may be limited (past-incident re-analysis)"}
            if str(getattr(request.alert, "status", "")).lower() == "resolved"
            else {}
        ),
        # Chronological event chain (oldest first): recent deploy/rollout, node
        # reboot/condition, pod delete/create, warning events → the alert. Small +
        # high-value, so it leads the reasoning inputs and the char cap won't trim it.
        **({"timeline": (timeline or [])[-40:]} if timeline else {}),
        **(
            {"troubleshooting_path": troubleshooting_path}
            if troubleshooting_path and troubleshooting_path.get("path")
            else {}
        ),
        "plan": plan.as_dict(),
        "ranked_root_cause_candidates": [c.as_dict() for c in root_cause_candidates],
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
            "knowledge": kg_context.get("knowledge"),
        },
        "graph_remediation": graph_fixes.as_dict(),
        "matched_alert": plan.matched_alert,
        "similar_incidents": similar_incidents,
        # Bulky — kept LAST so the char cap trims raw collector result tails
        # rather than the reasoning inputs above.
        "collector_findings": [
            {
                "agent": r.agent,
                "status": r.status,
                "confidence": r.confidence,
                "summary": r.summary if _collector_is_evidence(r) else NO_EVIDENCE,
                "artifacts": [
                    {
                        "type": art.type,
                        "title": art.title,
                        "status": art.status,
                        "query": art.query,
                        "summary": art.summary,
                        "highlights": art.highlights,
                        "result": _compact_synthesis_value(
                            art.result, limit=_SYNTHESIS_ARTIFACT_RESULT_CHARS
                        ),
                    }
                    for art in [a for a in r.artifacts if _artifact_is_evidence(a)][-3:]
                ],
            }
            for r in results
        ],
    }
    system = (
        "당신은 NVIDIA Run:ai GPU 플랫폼을 담당하는 시니어 SRE입니다. 제공된 증거(수집기별 "
        "발견 사항, 조사 계획, 순위가 매겨진 원인 후보, 지식 그래프/함수 기반 조치, 매칭된 "
        "내장 알림, 유사 인시던트)에만 근거하여 한국어로 장애 분석 보고서를 작성하세요.\n"
        "규칙:\n"
        "- 증거에 operator_guidance(운영자 지침)가 있으면 사람 운영자의 직접 지시입니다. "
        "원인 판단과 조치 순서에 최우선으로 반영하고, 보고서가 그 지침을 어떻게 따랐는지 "
        "드러나게 쓰세요 (단, 증거에 없는 사실을 지어내면서까지 따르지는 마세요).\n"
        "- 반드시 한국어로, 비전문가도 이해할 수 있게 작성합니다 (전문용어는 풀어서).\n"
        "- 길게 쓰지 마세요. 아래 1~3 섹션 합쳐서 A4 한 페이지 이내가 목표입니다.\n"
        "- 증거에 없는 사실을 절대 만들어내지 마세요.\n"
        "- 특정 수집기가 아무것도 찾지 못했으면 '증거를 찾기 어렵습니다.'라고 명시하세요.\n"
        "- 증거에 incident_state가 resolved(과거 인시던트 재분석)면, 현재 상태가 정상이라 "
        "라이브 증거가 제한적일 수 있습니다. 증거가 얇으면 억지로 원인을 단정하지 말고 '현재는 "
        "정상 상태로 회복되어 라이브 수집·분석이 제한적입니다'를 명시한 뒤, 남은 흔적·과거 기록·"
        "타임라인 기반으로 신중히 설명하세요.\n"
        "- 증거에 timeline(시간순 이벤트)이 있으면, 알림 직전의 '최근 변경'을 근본 원인으로 "
        "최우선 검토하세요: 배포/rollout(generation 변경), 노드 리부트·컨디션 변화, 파드 삭제/"
        "드레인, MIG/설정 변경 등. 스케줄러·증상성 경고(예: PodGroup Warning)보다 '무엇이 바뀌어 "
        "이 알림이 촉발됐는가'를 먼저 의심하고, 시간 순서(변경 → 결과 → 알림)로 인과를 설명하세요.\n"
        "- 증거에 troubleshooting_path가 있으면 그 steps를 사용해 진단 흐름을 단계별로 설명하세요. "
        "단, troubleshooting_path의 conclusion은 보강 근거일 뿐이며 XID/known-issue 같은 정밀 "
        "signature 또는 ranked_root_cause_candidates의 1순위 원인을 절대 덮어쓰지 마세요.\n"
        "- 반드시 이 문서 구조를 따르세요 (Word 제출용이므로 헤딩/번호목록만 사용, 표·HTML 금지):\n"
        "  # 장애 분석 보고서 — {알림명}\n"
        "  발생/심각도/대상 메타 한 줄\n"
        "  ## 1. 문제 (Problem) — 무엇이/어디서/언제부터/어떤 영향, 3~4문장.\n"
        "  ## 2. 원인 (Root Cause) — 운영자가 AI 판단을 검증할 수 있게 다음 항목을 "
        "굵은 라벨로 명확히 구분해 쓰세요:\n"
        "    - **결론**: 한 문장 (근본 원인).\n"
        "    - **확신도**: 높음/중간/낮음 (analysis_quality와 근거의 양·일관성 기준) + 한 줄 이유.\n"
        "    - **근거(Evidence)**: 직접 '관찰된 사실'만 2~4개 (수집기별: 무엇을 관찰, 언제부터). "
        "추론이 아니라 사실만.\n"
        "    - **추론(Inference)**: 위 근거가 왜 그 결론으로 이어지는지 논리 (시간 순서 인과 포함). "
        "XID 인과 사슬이 있으면 명시 (예: 'XID 74(NVLink) → XID 45 앱 크래시 — 뿌리는 NVLink').\n"
        "    - **반대 증거·한계(Contradicting evidence)**: 결론과 상충하거나 확인하지 못한 것, "
        "self-check가 반박한 내용 (없으면 '특이사항 없음').\n"
        "  ## 3. 권장 조치 (Recommended Actions) — 번호 목록, 즉시/후속/예방 순서, "
        "구체적 명령·확인 포함, 중복 금지.\n"
        "  ## 4. 부록 (Appendix) — 수집기별 증거 한 줄씩, 조사 계획 요약.\n"
        '- 반드시 JSON 객체 하나로만 응답하세요: {"summary": <한국어 한 문장: 문제+원인 요약>, '
        '"detail": <위 구조의 한국어 마크다운 본문>}'
    )
    safe_evidence = _build_settings_masker(settings).mask_object(compact(evidence, limit=8))
    user = "증거(JSON):\n" + _synthesis_evidence_json(safe_evidence, _SYNTHESIS_USER_CHARS)
    try:
        data = await _complete_synthesis_json(settings, system=system, user=user)
    except Exception:  # noqa: BLE001 - synthesis is best-effort; keep deterministic report
        return None
    if not data:
        return None
    summary = data.get("summary")
    detail = data.get("detail")
    if not isinstance(summary, str) or not summary.strip():
        return None
    if not isinstance(detail, str) or not detail.strip():
        detail = fallback_detail
    return _short_sentence(summary, limit=280), detail.strip()


async def _complete_synthesis_json(settings: Settings, *, system: str, user: str) -> dict | None:
    """Synthesis JSON with ONE retry: a single malformed reply must not silently
    downgrade the whole report to the deterministic English fallback.

    max_tokens is EXPLICIT: without it the gateway's own completion cap applies,
    and a full Korean report JSON that gets cut mid-string parses as nothing —
    the LLM "worked" (call succeeded, tokens billed) while the report silently
    fell back to English. The log names which way it failed."""
    instruction = "\n\nJSON 객체 하나로만, 프롬프트나 코드펜스 없이 응답하세요."
    for attempt in range(2):
        text = await complete(
            settings,
            system=system
            + instruction
            + (
                "\n(직전 응답이 유효한 JSON 객체가 아니었습니다 — 이번에는 반드시 "
                "JSON 객체 하나만 출력하세요.)"
                if attempt
                else ""
            ),
            user=user,
            temperature=0.2,
            max_tokens=settings.llm_synthesis_max_tokens,
            model=settings.llm_model_synthesis,
        )
        parsed = parse_json_object(text or "")
        if parsed is not None:
            return parsed
        if text is None:
            _log.warning("korean synthesis call failed (attempt %d): no reply", attempt + 1)
        else:
            truncated = not text.rstrip().endswith("}")
            _log.warning(
                "korean synthesis reply was not valid JSON (attempt %d)%s: %r",
                attempt + 1,
                " — looks TRUNCATED (completion cap?)" if truncated else "",
                text[:160],
            )
    return None


def _synthesis_evidence_json(evidence: dict, max_chars: int) -> str:
    """Serialize the synthesis evidence to VALID JSON within max_chars.

    A blunt string slice would cut the JSON mid-structure and hand the model
    malformed evidence (unterminated string / unbalanced braces). Instead drop
    whole collector_findings entries from the END — the lowest-priority,
    most-likely-NO_EVIDENCE collectors, whose summaries still live in the
    deterministic detail — and re-serialize, so the JSON stays well-formed and
    the leading reasoning inputs (operator_guidance, ranked cause, graph/KG
    remediation) are always intact. The non-collector part is bounded by
    construction (short_sentence caps, compact), so it fits well under the cap."""
    findings = evidence.get("collector_findings")
    text = json.dumps(evidence, ensure_ascii=False, default=str)
    while len(text) > max_chars and isinstance(findings, list) and findings:
        findings = findings[:-1]
        evidence = {**evidence, "collector_findings": findings}
        text = json.dumps(evidence, ensure_ascii=False, default=str)
    return text


def _compact_synthesis_value(value: object, *, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(value)
    return " ".join(text.split())[:limit]


def _quality_from(results: list[CollectorResult]) -> str:
    counts = Counter(result.status for result in results)
    if counts["ok"] >= 3:
        return "high"
    if counts["ok"] >= 1 or counts["partial"] >= 2:
        return "medium"
    return "low"


async def _collect_safely(
    collector: object, target: object, plan: object = None, masker: Masker | None = None
) -> CollectorResult:
    try:
        return await collector.collect(target, plan)  # type: ignore[attr-defined]
    except Exception as exc:
        agent = _collector_name(collector)
        error = _masked_exception_text(exc, masker)
        return CollectorResult(
            agent=agent,
            status="unavailable",
            summary=f"{agent} collector failed unexpectedly before returning evidence.",
            confidence="low",
            details={"error": error},
            missing_data=[f"{agent}.collector_exception"],
            warnings=[_unexpected_runtime_warning(agent, exc, masker)],
        )


def _collector_name(collector: object) -> str:
    name = collector.__class__.__name__
    if name.endswith("Collector"):
        name = name[: -len("Collector")]
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return normalized.replace("_a_i", "ai") or "collector"


def _unexpected_runtime_warning(
    component: str, exc: Exception, masker: Masker | None = None
) -> str:
    return f"{component} failed unexpectedly: {_masked_exception_text(exc, masker)}"


def _masked_exception_text(exc: Exception, masker: Masker | None = None) -> str:
    active_masker = masker or build_masker(())
    return active_masker.mask_text(f"{type(exc).__name__}: {exc}")



def _build_settings_masker(settings: Settings) -> Masker:
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _k8s_troubleshooting_tree_path(settings: Settings) -> str:
    base = Path(settings.failure_modes_file or "knowledge/failure_modes.yaml")
    try:
        return str(base.with_name("k8s_troubleshooting_tree.yaml"))
    except ValueError:
        return "knowledge/k8s_troubleshooting_tree.yaml"


def _mask_model(model: TModel, model_type: type[TModel], masker: Masker) -> TModel:
    payload = model.model_dump(mode="json")
    return model_type.model_validate(masker.mask_object(payload))



def _summary_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    root_cause_candidates: list[RankedCause],
) -> str:
    return _short_sentence(_ranked_root_cause_statement(root_cause_candidates, request), limit=280)


# Section headings for the report document (Word-export-clean markdown).
_HEADINGS = {
    "en": {
        "title": "# Incident Analysis Report",
        "problem": "## 1. Problem",
        "cause": "## 2. Root Cause",
        "actions": "## 3. Recommended Actions",
        "appendix": "## 4. Appendix",
        "fired": "Fired",
        "severity": "Severity",
        "target": "Target",
        "what": "What",
        "where": "Where",
        "impact": "Impact",
    },
    "ko": {
        "title": "# 장애 분석 보고서",
        "problem": "## 1. 문제 (Problem)",
        "cause": "## 2. 원인 (Root Cause)",
        "actions": "## 3. 권장 조치 (Recommended Actions)",
        "appendix": "## 4. 부록 (Appendix)",
        "fired": "발생",
        "severity": "심각도",
        "target": "대상",
        "what": "증상",
        "where": "위치",
        "impact": "영향",
    },
}


def _detail_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    missing: list[str],
    failure_modes: dict[str, list[dict]] | None = None,
    troubleshooting_cases: str = "",
    agent_souls: str = "",
    root_cause_candidates: list[RankedCause] | None = None,
    kg_context: dict | None = None,
    plan: InvestigationPlan | None = None,
    graph_fixes: GraphRemediation | None = None,
    language: str = "en",
    known_issues: list[dict] | None = None,
    components: dict[str, dict] | None = None,
    masker: Masker | None = None,
) -> str:
    """Problem -> Root Cause -> Recommended Actions, then everything else in an
    appendix. Sections 1-3 are the ~1-page report an operator (or a Word export)
    actually reads; the appendix keeps the full evidence trail."""
    h = _HEADINGS.get(language, _HEADINGS["en"])
    labels = request.alert.labels
    annotations = request.alert.annotations
    alert_name = labels.get("alertname") or request.alert.labels.get("alert_name") or "alert"
    target = resolve_target(labels, annotations)

    # --- header -------------------------------------------------------------
    meta = [f"{h['severity']}: {target.severity}"]
    if request.alert.startsAt:
        meta.insert(0, f"{h['fired']}: {request.alert.startsAt}")
    where = " / ".join(
        part for part in (target.namespace, target.workload_name or target.pod, target.node) if part
    )
    if where:
        meta.append(f"{h['target']}: {where}")
    lines = [f"{h['title']} — {alert_name}", "", " · ".join(meta), ""]

    # --- 1. Problem -----------------------------------------------------------
    lines.extend([h["problem"], ""])
    lines.append(f"- {h['what']}: {_root_cause_statement(request)}")
    if where:
        lines.append(f"- {h['where']}: {where}")
    if request.occurrence_count > 1:
        impact = (
            f"같은 워크로드에서 {request.occurrence_count}회 반복 발생"
            if language == "ko"
            else f"recurred {request.occurrence_count} times on the same workload"
        )
        lines.append(f"- {h['impact']}: {impact}")

    # --- 2. Root Cause --------------------------------------------------------
    lines.extend(["", h["cause"], ""])
    lines.append(_ranked_root_cause_statement(root_cause_candidates or [], request))
    # Multi-axis facets (Locus / Nature / Trigger) for the top cause — names the
    # subsystem, the KIND of cause, and (when known) what set it off.
    if root_cause_candidates:
        facets = _facets_line(root_cause_candidates[0], language)
        if facets:
            lines.append(facets)
    # Ground the coarse family in the most specific signature match when one exists:
    # a recognised known issue (with its affected/fixed version) is far more precise.
    lines.extend(
        _known_issue_cause_lines(
            known_issues, _observed_text(results, request), language, _alert_text(request)
        )
    )
    supporting = _supporting_evidence(results)
    if supporting:
        lines.append("")
        lines.extend(f"- **{agent}**: {finding}" for agent, finding in supporting)
    causal = _causal_chain_line(graph_fixes, language)
    if causal:
        lines.extend(["", causal])

    # --- 3. Recommended Actions ------------------------------------------------
    lines.extend(["", h["actions"], ""])
    numbered = _numbered_actions(
        plan,
        graph_fixes,
        root_cause_candidates,
        _observed_text(results, request),
        failure_modes or {},
        missing,
        request,
        known_issues or [],
        components=components,
    )
    if numbered:
        lines.extend(numbered)
    else:
        # Never a dangling empty section — say honestly why there are no actions.
        lines.append(
            "증거가 부족하여 구체적인 조치를 제시하기 어렵습니다. "
            "아래 확인 요청을 먼저 진행해 주세요."
            if language == "ko"
            else "Not enough evidence for concrete actions yet — please address the "
            "questions below first."
        )

    # --- 4. Appendix (full evidence trail; children demoted to ###) -----------
    lines.extend(["", h["appendix"], "", "### Evidence", ""])
    for result in results:
        lines.append(f"- **{result.agent}**: {_appendix_evidence_line(result)}")
    lines.extend(_investigation_plan_lines(plan))
    lines.extend(
        _knowledge_base_lines(
            kg_context,
            root_cause_candidates,
            _observed_text(results, request),
            _alert_text(request),
            masker,
        )
    )
    operator_prompt = annotations.get("operator_prompt")
    if operator_prompt:
        active_masker = masker or build_masker(())
        lines.extend(
            [
                "",
                "### Operator Guidance",
                "",
                _short_sentence(active_masker.mask_text(str(operator_prompt)), limit=500),
            ]
        )
    # ponytail: no "Agent Role Coverage" section — it was the same static
    # collector-catalog text in every report, telling the operator nothing about
    # THIS incident. (Kept in prompts.py for the NAT workflow's system prompt.)
    if not agent_souls:
        lines.append("- Agent role contract file was not loaded; fallback guidance was used.")
    lines.extend(_affected_pods_lines(request, language))
    lines.extend(["", "### Troubleshooting Playbook", ""])
    lines.extend(
        _playbook_lines(
            root_cause_candidates,
            _observed_text(results, request),
            failure_modes or {},
            troubleshooting_cases,
            known_issues or [],
            _alert_text(request),
            components,
            masker,
            component=getattr(plan, "component", "") if plan is not None else "",
        )
    )
    lines.extend(_similar_incident_lines(request))
    lines.extend(_feedback_hint_lines(request))
    lines.extend(
        [
            "",
            "### Alert Labels",
            "",
            "```json",
            json.dumps(labels, indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines)


async def _translate_playbook_ko(settings: Settings, detail: str) -> str:
    """Translate ONLY the Troubleshooting Playbook section to Korean.

    The deterministic fallback report splices curated KB text (known issues /
    failure-mode actions) in verbatim English. One bounded LLM call fixes the
    operator-facing section; on any failure the English original stays (honest
    degradation, same as synthesis itself)."""
    marker = "\n### Troubleshooting Playbook\n"
    start = detail.find(marker)
    if start < 0:
        return detail
    body_start = start + len(marker)
    end = detail.find("\n### ", body_start)
    if end < 0:
        end = len(detail)
    block = detail[body_start:end].strip()
    if not block:
        return detail
    system = (
        "다음 마크다운 트러블슈팅 지침을 자연스러운 한국어로 번역하세요. "
        "목록 구조·볼드·들여쓰기를 그대로 유지하고, 백틱 안의 명령어, 리소스/메트릭 "
        "이름, 제품명(Run:ai, Prometheus, Thanos 등), 버전 표기는 원문 그대로 두세요. "
        "설명을 추가하지 말고 번역문만 출력하세요."
    )
    try:
        translated = await complete(
            settings,
            system=system,
            user=block,
            max_tokens=1600,
            model=getattr(settings, "llm_model_insight", "") or None,
        )
    except Exception:  # noqa: BLE001 - translation is best-effort polish
        return detail
    if not translated or not translated.strip():
        return detail
    translated = _build_settings_masker(settings).mask_text(translated.strip())
    return f"{detail[:body_start]}\n{translated}\n{detail[end:]}"


def _insert_before_appendix(detail: str, block: str) -> str:
    """Insert a section before the appendix so it reads as part of the report body.

    Falls back to appending at the end when no appendix heading exists (e.g. an
    LLM-synthesized or NAT-produced detail with a different shape).
    """
    for heading in ("\n## 4. 부록", "\n## 4. Appendix"):
        idx = detail.find(heading)
        if idx >= 0:
            return f"{detail[:idx]}\n{block}\n{detail[idx:]}"
    return f"{detail}\n\n{block}"


def _supporting_evidence(results: list[CollectorResult]) -> list[tuple[str, str]]:
    """Up to 4 (agent, finding) pairs with a REAL finding — no no-evidence lines."""
    picked: list[tuple[str, str]] = []
    for result in results:
        if result.status not in ("ok", "partial"):
            continue
        line = _best_evidence_line(result)
        if line.startswith(NO_EVIDENCE):
            continue
        picked.append((result.agent, line))
        if len(picked) >= 4:
            break
    return picked


def _causal_chain_line(graph_fixes: GraphRemediation | None, language: str) -> str:
    """One line naming the XID causal picture when the graph produced one.

    When the ontology's leads_to chain resolves a ROOT fault for an observed XID
    (e.g. NVLink Xid 74 -> app-crash Xid 45), name the chain so the operator fixes
    the origin, not the downstream symptom — the drill-down precision win."""
    if graph_fixes is None or not graph_fixes.xid_fixes:
        return ""
    codes = ", ".join(str(code) for code in sorted(graph_fixes.xid_fixes))
    roots = getattr(graph_fixes, "root_xids", None) or {}
    chain = "; ".join(
        dict.fromkeys(
            f"XID {root} → XID {observed}"
            for observed, root_list in sorted(roots.items())
            for root in root_list
        )
    )
    if language == "ko":
        if chain:
            return (
                f"- 관련 GPU 오류(XID): {codes} — 인과 사슬(뿌리→관측): {chain}. "
                "뿌리 XID를 먼저 조치하세요."
            )
        return f"- 관련 GPU 오류(XID): {codes} — 세부 조치는 아래 권장 조치를 참고."
    if chain:
        return (
            f"- Related GPU errors (XID): {codes} — causal chain (root → observed): "
            f"{chain}. Fix the root XID first."
        )
    return f"- Related GPU errors (XID): {codes} — see the recommended actions below."


def _promote_signature_cause(
    candidates: list[RankedCause],
    xid_codes: list[int],
    known_issue_matches: list[dict],
    symptom_matches: list[tuple[str, dict]],
) -> list[RankedCause]:
    """A specific signature names the headline family; the keyword ranker is only
    the no-signal fallback. Precedence: NVIDIA XID (dispositive) > known-issue
    signature > curated symptom keyword > ranker. When the signature agrees with
    the ranker's top family the richer ranked entry is kept as-is."""
    if xid_codes:
        return _promote_xid_cause(candidates, xid_codes)
    top_family = candidates[0].family if candidates else ""
    for entry in known_issue_matches:
        family = str(entry.get("family") or "")
        if not family:
            continue
        if family == top_family:
            return [
                _with_signature_support(
                    candidates[0], f"matched known-issue signature: {entry.get('issue')}", 8.0
                ),
                *candidates[1:],
            ]
        lead = RankedCause(
            family=family,
            confidence="medium",
            score=8.0,
            rationale=[f"matched known-issue signature: {entry.get('issue')}"],
            evidence_agents=["signature"],
            trigger=_trigger_for_family(candidates, family),
        )
        return [lead] + [c for c in candidates if c.family != family]
    for family, symptom in symptom_matches:
        if not family:
            continue
        if family == top_family:
            return [
                _with_signature_support(
                    candidates[0], f"matched curated symptom: {symptom.get('symptom')}", 7.0
                ),
                *candidates[1:],
            ]
        lead = RankedCause(
            family=family,
            confidence="medium",
            score=7.0,
            rationale=[f"matched curated symptom: {symptom.get('symptom')}"],
            evidence_agents=["signature"],
            trigger=_trigger_for_family(candidates, family),
        )
        return [lead] + [c for c in candidates if c.family != family]
    return candidates


def _trigger_for_family(candidates: list[RankedCause], family: str) -> str:
    """Carry the ranker-computed Trigger facet across signature promotion.

    Trigger is the one facet that is not intrinsic to the family (subsystem and
    nature auto-derive in ``RankedCause.__post_init__``); it is set dynamically on
    the lifecycle candidate by the ranker. When a promoted family displaces the
    ranker's top, copy the trigger from that family's pre-promotion candidate so
    it is not silently lost from the report and ``as_dict()`` output."""
    for candidate in candidates:
        if candidate.family == family and candidate.trigger:
            return candidate.trigger
    return ""


def _with_signature_support(
    candidate: RankedCause, rationale: str, score_floor: float
) -> RankedCause:
    rationale_items = [*candidate.rationale]
    if rationale not in rationale_items:
        rationale_items.append(rationale)
    return RankedCause(
        family=candidate.family,
        confidence="medium" if candidate.confidence == "low" else candidate.confidence,
        score=max(candidate.score, score_floor),
        rationale=rationale_items,
        evidence_agents=sorted({*candidate.evidence_agents, "signature"}),
        trigger=candidate.trigger,
    )


def _promote_xid_cause(candidates: list[RankedCause], xid_codes: list[int]) -> list[RankedCause]:
    """Lead with gpu_hardware_error when an NVIDIA XID is present.

    An XID in the alert/evidence is dispositive for the cause CATEGORY (the GPU
    driver itself reported the fault); the generic keyword families then describe
    downstream effects at best. Deterministic — no LLM, no score fight."""
    if not xid_codes:
        return candidates
    codes = ", ".join(str(code) for code in xid_codes)
    gpu = RankedCause(
        family="gpu_hardware_error",
        confidence="high",
        score=10.0,
        rationale=[f"NVIDIA XID {codes} present in the alert/evidence"],
        evidence_agents=["alert"],
    )
    return [gpu] + [c for c in candidates if c.family != "gpu_hardware_error"]


def _drop_refuted_signature_candidates(
    candidates: list[RankedCause], refuted: set[str]
) -> list[RankedCause]:
    if not refuted:
        return candidates
    labels = {item.lower() for item in refuted if item}
    kept: list[RankedCause] = []
    for candidate in candidates:
        rationale = " ".join(candidate.rationale).lower()
        if "nvidia xid" in rationale and _xid_candidate_still_supported(rationale, labels):
            kept.append(candidate)
            continue
        signature_claim = (
            "matched known-issue signature" in rationale
            or "matched curated symptom" in rationale
            or "nvidia xid" in rationale
        )
        if signature_claim and any(label in rationale for label in labels):
            continue
        kept.append(candidate)
    if kept:
        return kept
    return [
        RankedCause(
            family="insufficient_evidence",
            confidence="low",
            score=0.0,
            rationale=[
                "The signature match was refuted; no other family cleared the evidence gate."
            ],
            evidence_agents=[],
        )
    ]


def _xid_candidate_still_supported(rationale: str, refuted_labels: set[str]) -> bool:
    codes = set(re.findall(r"\b\d{1,4}\b", rationale))
    if not codes:
        return False
    refuted_codes = {
        code
        for label in refuted_labels
        for code in re.findall(r"\b\d{1,4}\b", label)
    }
    return bool(codes - refuted_codes)


def _runai_version_from(results: list[CollectorResult]) -> str:
    """The running Run:ai control-plane version, if the runai collector resolved one."""
    for result in results:
        if result.agent == "runai":
            value = result.details.get("runai_version")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text or "")[:4])


def _known_issue_fixed_in_running(issue: dict, running_version: str) -> bool:
    """True when the cluster's Run:ai version is at/after the issue's fixed version:
    the bug is already patched here, so surfacing it would be a false positive."""
    fixed = _version_tuple(str(issue.get("fixed_version") or ""))
    running = _version_tuple(running_version)
    return bool(fixed and running and running >= fixed)


def _suppress_fixed_known_issues(known_issues: list[dict], running_version: str) -> list[dict]:
    """Drop known issues already fixed in the running Run:ai version (precision:
    don't attribute a symptom to a bug the cluster is already patched against)."""
    if not running_version:
        return known_issues
    return [k for k in known_issues if not _known_issue_fixed_in_running(k, running_version)]


def _known_issue_cause_lines(
    known_issues: list[dict] | None,
    observed_text: str,
    language: str,
    fuzzy_query: str = "",
) -> list[str]:
    """Ground the root cause in a recognised known issue — more precise than the
    coarse family. Names the issue and its affected/fixed Run:ai version. Returns
    the grounded line(s), or [] when no known-issue signature matches the evidence."""
    matches = match_runai_known_issues(known_issues or [], observed_text, fuzzy_query=fuzzy_query)
    out: list[str] = []
    for issue in matches[:2]:  # the strongest signature hits only
        name = str(issue.get("issue") or "").strip()
        reason = " ".join(str(issue.get("reason") or "").split())
        affected = str(issue.get("affected_version") or "").strip()
        fixed = str(issue.get("fixed_version") or "").strip()
        ver = ""
        if affected or fixed:
            head = affected or "?"
            if language == "ko":
                ver = f" (영향 버전: {head}" + (f", 수정: {fixed}" if fixed else "") + ")"
            else:
                ver = f" (affected {head}" + (f", fixed in {fixed}" if fixed else "") + ")"
        label = "알려진 이슈로 인식" if language == "ko" else "Recognised known issue"
        line = f"- {label}: **{name}**{ver}"
        if reason:
            line += f" — {reason}"
        out.append(line)
    return out


def _numbered_actions(
    plan: InvestigationPlan | None,
    graph_fixes: GraphRemediation | None,
    candidates: list[RankedCause] | None,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    missing: list[str],
    request: AlertAnalysisRequest,
    known_issues: list[dict] | None = None,
    components: dict[str, dict] | None = None,
) -> list[str]:
    """One deduped, numbered priority list — documented-alert fixes first, then
    the alert target's own component checks, then recognised known-issue fixes,
    graph-derived and curated family fixes, then infra-restore steps."""
    ordered: list[str] = []
    specific_actions = 0
    fuzzy = _alert_text(request)
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    if plan is not None and plan.matched_alert:
        alert_family = str(plan.matched_alert.get("family") or "")
        if (not top_family or alert_family == top_family) and top_family != "insufficient_evidence":
            ordered.extend(str(a) for a in plan.matched_alert.get("actions", []))
    # Component identity: the alert target IS this platform component, so its
    # own checks + dependency chain (e.g. runai-container-toolkit → the NVIDIA
    # GPU Operator stack) come before any keyword-matched guidance.
    if plan is not None and getattr(plan, "component", ""):
        component_actions = component_action_lines(components or {}, plan.component)
        specific_actions += len(component_actions)
        ordered.extend(component_actions)
    # Known operator cases recognised by their signature keywords in the evidence
    # (ranking-independent): version-regression / observability / expected-behavior
    # fixes surface even when the coarse family ranking points elsewhere.
    if top_family != "insufficient_evidence":
        for issue in match_runai_known_issues(known_issues or [], observed_text, fuzzy_query=fuzzy):
            if filter_to_top and str(issue.get("family") or "") != top_family:
                continue
            actions = [str(a) for a in issue.get("actions", [])]
            specific_actions += len(actions)
            ordered.extend(actions)
    if graph_fixes is not None:
        specific_actions += len(graph_fixes.family_fixes)
        ordered.extend(graph_fixes.family_fixes)
        root_codes = {r for roots in graph_fixes.root_xids.values() for r in roots}
        # Fix the ROOT of the causal chain before its downstream symptoms.
        for code in sorted(graph_fixes.xid_fixes, key=lambda c: (c not in root_codes, c)):
            label = "root XID" if code in root_codes else "XID"
            fixes = [f"({label} {code}) {fix}" for fix in graph_fixes.xid_fixes[code]]
            specific_actions += len(fixes)
            ordered.extend(fixes)
    # Curated failure-mode fixes for the settled top family only. The promotion
    # step already used cross-family signatures to choose that family; repeating
    # every side-match here pollutes actions with stale/context text.
    if top_family != "insufficient_evidence":
        for family, symptom in match_failure_mode_symptoms(
            failure_modes, observed_text, top_family, fuzzy_query=fuzzy
        ):
            if filter_to_top and family != top_family:
                continue
            actions = [str(a) for a in symptom.get("actions", [])]
            specific_actions += len(actions)
            ordered.extend(actions)
    ordered.extend(
        line.removeprefix("- ")
        for line in _recommended_action_lines(
            missing,
            request,
            include_similar=(
                specific_actions == 0 or _similar_incident_relevant(request, fuzzy)
            ),
        )
    )
    seen: set[str] = set()
    numbered: list[str] = []
    action_masker = build_masker(())
    for action in ordered:
        action = _safe_line(action, limit=420, masker=action_masker)
        if not action or action in seen:
            continue
        seen.add(action)
        numbered.append(f"{len(numbered) + 1}. {action}")
        if len(numbered) >= 8:
            break
    return numbered


def _root_cause_statement(request: AlertAnalysisRequest) -> str:
    annotations = request.alert.annotations
    labels = request.alert.labels
    text = (
        annotations.get("description")
        or annotations.get("summary")
        or labels.get("alertname")
        or "The alert fired before the agent could identify a precise root cause."
    )
    return _short_sentence(text, limit=320)


def _top_family_settled(candidates: list[RankedCause] | None) -> bool:
    if not candidates:
        return False
    top = candidates[0]
    return top.family != "insufficient_evidence" and (
        top.confidence != "low" or top.score >= 2.0
    )


def _ranked_root_cause_statement(
    candidates: list[RankedCause], request: AlertAnalysisRequest
) -> str:
    subject = _as_sentence(_root_cause_statement(request))
    if not candidates:
        return subject
    top = candidates[0]
    if top.family == "insufficient_evidence":
        return _short_sentence(
            f"{subject} Insufficient evidence: there is not yet enough evidence to point "
            "at a specific cause; the collected signals are inconclusive.",
            limit=320,
        )
    explanation = _FAMILY_EXPLANATION.get(top.family) or _family_label(top.family)
    return _short_sentence(f"{subject} Likely cause: {explanation}.", limit=320)


# Nature axis labels for the operator-facing facets line.
_NATURE_LABELS = {
    "en": {
        "fault": "fault (a defect)",
        "saturation": "saturation (resource exhaustion)",
        "lifecycle_change": "lifecycle change (expected rollout/upgrade disruption)",
        "observability": "observability (monitoring accuracy, not the workload)",
    },
    "ko": {
        "fault": "결함(fault)",
        "saturation": "리소스 포화(saturation)",
        "lifecycle_change": "라이프사이클 변경(rollout/upgrade — 정상 교체 중단)",
        "observability": "관측성(모니터링 정확도 — 워크로드 아님)",
    },
}


def _facets_line(top: RankedCause, language: str) -> str:
    """One compact line annotating the top cause on the (Locus, Nature, Trigger)
    axes — WHERE the cause sits, WHAT KIND it is, and WHAT SET IT OFF. Skips
    empty axes (e.g. no trigger known) and returns '' for non-causes."""
    if not top or top.family == "insufficient_evidence":
        return ""
    ko = language == "ko"
    parts: list[str] = []
    if top.subsystem:
        parts.append(("서브시스템" if ko else "Subsystem") + f": {top.subsystem}")
    if top.nature:
        nature = _NATURE_LABELS.get(language, _NATURE_LABELS["en"]).get(top.nature, top.nature)
        parts.append(("성격" if ko else "Nature") + f": {nature}")
    if top.trigger:
        parts.append(("트리거" if ko else "Trigger") + f": {top.trigger}")
    if not parts:
        return ""
    label = "분류(Facets)" if ko else "Facets"
    return f"- {label}: " + " · ".join(parts)


def _as_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    if text and text[-1] not in ".!?":
        text += "."
    return text


# Plain-language cause per family for operator-facing summaries — no scores,
# confidence words, or keyword-match jargon.
_FAMILY_EXPLANATION = {
    "node_kubelet_pressure": (
        "the node hosting this workload is under resource pressure (disk, memory, or "
        "PID), which can evict or restart its pods"
    ),
    "runai_scheduling_quota": (
        "the Run:ai SCHEDULER held/evicted this workload — GPU quota, fairshare "
        "reclaim, preemption, gang/pod-group, or queue capacity (its own decision, "
        "not the Kubernetes scheduler)"
    ),
    "k8s_scheduling_error": (
        "the KUBERNETES scheduler could not place the pod — a predicate failed "
        "(taint/toleration, node affinity/selector, topology spread, or a namespace "
        "ResourceQuota), independent of Run:ai quota"
    ),
    "runai_control_plane_error": (
        "the Run:ai PLATFORM control plane (runai-scheduler, runai-backend, "
        "cluster-sync) is reporting errors that affect this workload — not the "
        "Kubernetes control plane"
    ),
    "k8s_control_plane_error": (
        "the KUBERNETES cluster's own control plane is unhealthy (kube-apiserver, "
        "etcd, kube-scheduler/controller-manager, kubelet certs, admission webhooks) "
        "— a cluster-level fault beneath Run:ai"
    ),
    "workload_startup_error": (
        "the container itself fails to start once the image is present — a crash "
        "loop, OOM at start, bad entrypoint, missing config/secret, or a failing "
        "startup probe (the workload's own fault, not the image pull)"
    ),
    "image_pull_error": (
        "the node cannot PULL the container image — image-pull backoff, a bad tag/"
        "manifest, private-registry auth, a registry TLS/rate-limit/5xx problem "
        "(a registry/image issue, not the workload's code)"
    ),
    "gpu_hardware_error": (
        "the GPU itself reported a fault (NVIDIA XID) — a hardware/driver/fabric "
        "problem on the node, not a scheduling or workload issue"
    ),
    "network_fabric_error": (
        "the GPU interconnect / multi-node communication layer is failing "
        "(NCCL, NVLink/NVSwitch, InfiniBand/RDMA) — distributed training breaks "
        "even though each GPU looks healthy"
    ),
    "cluster_network_error": (
        "cluster networking is failing (CNI, CoreDNS, pod networking) — pods can't "
        "resolve names or get network connectivity"
    ),
    "k8s_storage_error": (
        "the Kubernetes storage layer is failing (CSI driver, PVC binding, "
        "StorageClass, volume attach/mount, node-affinity) — the volume can't be "
        "provisioned or mounted"
    ),
    "storage_backend_error": (
        "the backing storage system is degraded (NFS server unresponsive, Ceph "
        "cluster unhealthy, node filesystem read-only) — IO hangs or fails beneath "
        "the CSI layer"
    ),
    "workload_runtime_error": (
        "the workload's own code failed while running (application crash, CUDA "
        "out-of-memory) — an application-level fault, not a platform problem"
    ),
    "observability_accuracy": (
        "the metrics/observability pipeline is degraded (Prometheus, Thanos, DCGM, "
        "metrics-exporter) — dashboards are wrong or empty, not the workload itself"
    ),
    "platform_auth_error": (
        "login/permissions/SSO is failing (JWT attributes, SAML/OIDC config, "
        "Access Rules) or a UI/API call returned 401/403/503/500 — an auth or "
        "control-plane service issue, not a workload fault"
    ),
    "platform_lifecycle_change": (
        "a platform rollout/upgrade is in progress (GPU Operator, a controller, or "
        "a Helm release) — the disruption is EXPECTED churn from that change, not a "
        "fault; verify the rollout/Helm release finished before digging elsewhere"
    ),
}


def _alert_text(request: AlertAnalysisRequest) -> str:
    """The alert's own labels+annotations text — it often carries the signature
    (e.g. 'XID 79 ... GPU has fallen off the bus') even when every collector
    comes back empty."""
    alert = request.alert
    parts = [str(v) for v in (alert.labels or {}).values()]
    parts.extend(str(v) for v in (alert.annotations or {}).values())
    return " ".join(parts)


def _observed_text(
    results: list[CollectorResult], request: AlertAnalysisRequest | None = None
) -> str:
    from app.services.root_cause_ranking import COLLECTOR_TEXT_DROP_KEYS

    parts: list[str] = []
    if request is not None:
        # The alert message itself is evidence: signature matching (symptoms, known
        # issues, XIDs) must see it, or an alert whose collectors all came back
        # empty matches NOTHING even though its own text names the fault.
        parts.append(_alert_text(request))
    for result in results:
        if not _collector_is_evidence(result):
            continue
        drop_keys = COLLECTOR_TEXT_DROP_KEYS.get(getattr(result, "agent", ""))
        if result.summary:
            parts.append(result.summary)
        for art in result.artifacts:
            if not _artifact_is_evidence(art):
                continue
            if art.summary:
                parts.append(art.summary)
            if art.result is not None:
                parts.append(_evidence_leaf_text(art.result, limit=2000, drop_keys=drop_keys))
    return " ".join(parts).lower()


def _evidence_leaf_text(
    value: Any, *, limit: int = 2000, drop_keys: "frozenset[str] | set[str] | None" = None
) -> str:
    """Evidence matching should see RETURNED values — not JSON key names, and not
    the probe text we sent (queries/paths/urls/name listings; see
    root_cause_ranking.METADATA_VALUE_KEYS). A LogQL probe carrying
    "cluster-sync" must not signature-match a cluster-sync symptom.

    ``drop_keys`` prunes whole subtrees whose dict key matches (case-insensitive) —
    the kubernetes ``queries`` firehose embeds the RAW node/pod objects, and a
    healthy node literally contains "DiskPressure"/"MemoryPressure" type names, so
    it must be dropped here exactly as it is for the family ranker
    (COLLECTOR_TEXT_DROP_KEYS) or a healthy node signature-matches node-pressure."""
    from app.services.root_cause_ranking import METADATA_VALUE_KEYS

    parts: list[str] = []
    drop = {k.lower() for k in drop_keys} if drop_keys else None

    def add(text: object) -> None:
        if len(" ".join(parts)) < limit:
            parts.append(str(text))

    def walk(node: Any, key: str = "") -> None:
        if node is None:
            return
        key_l = key.lower()
        # Prune metadata-key subtrees BEFORE recursing (mirrors _leaf_text): a
        # metadata key can hold a dict/list (e.g. a prometheus ``metric`` label
        # set), and checking only at the scalar leaf let those identity literals
        # ("DiskPressure", status "true") leak and signature-match a healthy node.
        if key_l in METADATA_VALUE_KEYS:
            return
        if isinstance(node, dict):
            for child_key, child in node.items():
                if drop and str(child_key).lower() in drop:
                    continue
                walk(child, str(child_key))
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child, key)
        elif key_l in {"xid", "xid_code", "nvidia_xid"}:
            add(f"xid {node}")
        elif isinstance(node, (str, int, float, bool)):
            add(node)
        else:
            add(node)

    walk(value)
    return " ".join(" ".join(parts).split())[:limit]


def _knowledge_base_lines(
    kg_context: dict | None,
    candidates: list[RankedCause] | None = None,
    observed_text: str = "",
    fuzzy_query: str = "",
    masker: Masker | None = None,
) -> list[str]:
    if not kg_context or not kg_context.get("enabled"):
        return []
    if not kg_context.get("available"):
        # Optional enrichment; when it is not available we simply omit the section
        # rather than surfacing infra jargon. The reason is carried in `warnings`.
        return []
    active_masker = masker or build_masker(())
    body: list[str] = []
    blast = kg_context.get("blast_radius_workloads") or 0
    if blast:
        body.append(
            f"- Blast radius: {blast} workload(s) share the alerting node, so the impact "
            "is node-wide rather than a single workload."
        )
    prior = kg_context.get("prior_incidents") or []
    if prior:
        body.append(f"- This alert recurred in {len(prior)} prior incident(s):")
        for item in prior[:5]:
            incident_id = _short_sentence(
                active_masker.mask_text(str(item.get("incident_id") or "(unknown)")),
                limit=80,
            )
            summary = _short_sentence(
                active_masker.mask_text(
                    str(item.get("analysis_summary") or "(no stored RCA summary)")
                ),
                limit=320,
            )
            body.append(f"  - {incident_id}: {summary}")
    body.extend(
        _kb_remediation_lines(
            kg_context, candidates, observed_text, fuzzy_query, active_masker
        )
    )
    if not body:
        body.append("- No related knowledge-graph facts were found for this entity yet.")
    return ["", "### Knowledge Base (Ontology)", "", *body]


def _kb_remediation_lines(
    kg_context: dict,
    candidates: list[RankedCause] | None,
    observed_text: str,
    fuzzy_query: str = "",
    masker: Masker | None = None,
) -> list[str]:
    knowledge = kg_context.get("knowledge") or {}
    if not knowledge:
        return []
    # Entry point = the fine-grained signature match across ALL families, not the
    # coarse ranked family (which can be wrong, or can't even nominate the right one
    # such as gpu_hardware_error). The ranker only orders the matches.
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    active_masker = masker or build_masker(())
    for family, symptom in match_failure_mode_symptoms(
        knowledge, observed_text, top_family, fuzzy_query=fuzzy_query
    ):
        if filter_to_top and family != top_family:
            continue
        actions = symptom.get("actions", [])
        if actions:
            symptom_name = _safe_line(symptom.get("symptom"), limit=160, masker=active_masker)
            header = (
                f"- Matched symptom **{symptom_name}** "
                f"({_family_label(family)}); known fixes from the knowledge base:"
            )
            return [
                header,
                *[f"  - {_safe_line(a, limit=360, masker=active_masker)}" for a in actions[:5]],
            ]
    # No symptom keyword matched the observed evidence: don't dump a generic family
    # checklist as if it were a match — say so plainly.
    return ["- No closely-matching prior knowledge for this evidence yet."]


def _playbook_lines(
    candidates: list[RankedCause] | None,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    fallback_cases: str,
    known_issues: list[dict] | None = None,
    fuzzy_query: str = "",
    components: dict[str, dict] | None = None,
    masker: Masker | None = None,
    component: str = "",
) -> list[str]:
    """Root-cause-relevant remediation, most specific first.

    Precision order: the alert target's OWN component (identity beats any
    keyword), then matched known issues (real operator cases), then matched
    curated symptoms for the settled top family. Cross-family signatures have
    already been used to pick that top family; unrelated side text should not
    become playbook guidance.
    """
    lines: list[str] = []
    active_masker = masker or build_masker(())
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    if component:
        comp_lines = component_check_lines(components or {}, component)
        if comp_lines:
            lines.append(f"- **{component}** (the alert target itself)")
            lines.extend(comp_lines)
    for issue in match_runai_known_issues(
        known_issues or [], observed_text, fuzzy_query=fuzzy_query
    )[:2]:
        if filter_to_top and str(issue.get("family") or "") != top_family:
            continue
        issue_name = _safe_line(issue.get("issue"), limit=180, masker=active_masker)
        lines.append(f"- **{issue_name}** (known issue)")
        reason = _safe_line(issue.get("reason"), limit=360, masker=active_masker)
        if reason:
            lines.append(f"  - {reason}")
        lines.extend(
            f"  - {_safe_line(action, limit=360, masker=active_masker)}"
            for action in issue.get("actions", [])[:4]
        )
    for family, symptom in match_failure_mode_symptoms(
        failure_modes, observed_text, top_family, fuzzy_query=fuzzy_query
    ):
        if filter_to_top and family != top_family:
            continue
        symptom_name = _safe_line(symptom.get("symptom"), limit=180, masker=active_masker)
        lines.append(f"- **{symptom_name}** ({_family_label(family)})")
        lines.extend(
            f"  - {_safe_line(action, limit=360, masker=active_masker)}"
            for action in symptom.get("actions", [])[:5]
        )
        # Architecture layer: the implicated platform component's failure effect,
        # dependency check order, and ready-to-run checks (runai_architecture.yaml).
        if symptom.get("component"):
            lines.extend(component_check_lines(components or {}, str(symptom["component"])))
    if lines:
        return lines
    # No precise signature matched: fall back to the ranked family's general
    # checklist (the coarse ranking's legitimate role), else the full case library.
    symptoms = failure_modes.get(top_family) if top_family else None
    if top_family == "insufficient_evidence":
        return ["- No troubleshooting playbook matched the available evidence yet."]
    if symptoms:
        actions = sorted(
            {
                _safe_line(a, limit=360, masker=active_masker)
                for s in symptoms
                for a in s.get("actions", [])
            }
        )
        header = f"Guidance for the most likely cause: **{_family_label(top_family)}**."
        return [header, "", *[f"- {action}" for action in actions[:6]]]
    if fallback_cases:
        return [fallback_cases]
    return ["- No troubleshooting guidance is available for this cause yet."]


def _family_label(family: str) -> str:
    labels = {
        "node_kubelet_pressure": "node kubelet pressure",
        "runai_scheduling_quota": "Run:ai scheduling / GPU quota (preempt/reclaim/gang)",
        "k8s_scheduling_error": "Kubernetes scheduling error (taint/affinity/topology/quota)",
        "runai_control_plane_error": "Run:ai control-plane error (scheduler/backend/cluster-sync)",
        "k8s_control_plane_error": "Kubernetes control-plane error (apiserver/etcd/scheduler)",
        "workload_startup_error": "workload startup/config/crash",
        "image_pull_error": "image pull / registry failure",
        "gpu_hardware_error": "GPU hardware error",
        "platform_version_bug": "Run:ai version bug",
        "observability_accuracy": "metrics/observability accuracy",
        "expected_known_behavior": "expected/known behavior",
        "network_fabric_error": "GPU interconnect/fabric error (NCCL/IB/NVLink)",
        "cluster_network_error": "cluster networking error (CNI/DNS)",
        "k8s_storage_error": "Kubernetes storage error (CSI/PVC/StorageClass)",
        "storage_backend_error": "backend storage error (NFS/Ceph/read-only fs)",
        "workload_runtime_error": "workload runtime error (application fault)",
        "platform_auth_error": "authentication/SSO error (login/permissions/SAML/OIDC)",
        "insufficient_evidence": "insufficient evidence",
    }
    return labels.get(family, family.replace("_", " "))


def _short_sentence(value: str, *, limit: int) -> str:
    text = " ".join(value.split())
    if not text:
        return "The agent has not received enough alert context to name a root cause."
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _safe_line(value: object, *, limit: int, masker: Masker | None = None) -> str:
    active_masker = masker or build_masker(())
    text = " ".join(active_masker.mask_text(str(value or "")).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _investigation_plan_lines(plan: InvestigationPlan | None) -> list[str]:
    if plan is None:
        return []
    matched = []
    if plan.used_similarity:
        matched.append("a similar past incident")
    if plan.used_ontology:
        matched.append("knowledge-graph facts")
    matched_text = (
        "matched " + " and ".join(matched)
        if matched
        else "nothing prior matched — reasoning from live evidence"
    )
    lines = [
        "",
        "### Investigation Plan",
        "",
        f"- Focus: {plan.focus}",
        f"- Strategy: {plan.strategy} ({matched_text}).",
    ]
    if plan.check_control_plane:
        lines.append("- Run:ai control plane is in scope for this alert.")
    else:
        lines.append("- Run:ai control plane was ruled out of scope for this alert.")
    if plan.narrative:
        lines.append(f"- Approach: {plan.narrative}")
    alert = plan.matched_alert
    if alert:
        lines.append(
            f"- Documented Run:ai alert **{alert.get('alert')}** "
            f"({alert.get('severity', 'n/a')}) — {alert.get('trigger', '')}"
        )
        for step in alert.get("actions", [])[:5]:
            lines.append(f"  - {step}")
    return lines


def _best_evidence_line(result: CollectorResult) -> str:
    """The single most useful finding for this agent, not a status blurb."""
    artifact_line = _artifact_evidence_line(result)
    if artifact_line:
        return artifact_line
    if result.agent == "kubernetes":
        picked = _kubernetes_highlights(result.details)
    elif result.agent == "loki":
        picked = _loki_highlights(result.details)
    elif result.agent == "runai":
        picked = _runai_highlights(result.details)
    else:
        picked = []
    if picked:
        # highlight lines start with "- "; strip the marker for inline use.
        return picked[0].lstrip("- ").strip()
    return result.summary


def _appendix_evidence_line(result: CollectorResult) -> str:
    artifact_line = _artifact_evidence_line(result)
    if artifact_line:
        return artifact_line
    unavailable_line = _artifact_evidence_line(result, include_unavailable=True)
    return unavailable_line or _best_evidence_line(result)


_GENERIC_ARTIFACT_SUMMARY_RE = re.compile(
    r"^(?:\d+\s+row\(s\)|metadata rows?|schema rows?|ok|success|drilldown ok)$",
    re.IGNORECASE,
)


def _artifact_evidence_line(
    result: CollectorResult, *, include_unavailable: bool = False
) -> str:
    for art in reversed(getattr(result, "artifacts", []) or []):
        if not _artifact_is_evidence(art) and not include_unavailable:
            continue
        summary = " ".join(str(art.summary or "").split())
        result_text = _evidence_leaf_text(art.result, limit=500) if art.result is not None else ""
        if summary and not _GENERIC_ARTIFACT_SUMMARY_RE.match(summary):
            finding = summary
        elif result_text and result_text.lower() not in {"true", "false", "none", "null"}:
            finding = result_text
        else:
            finding = ""
        if not finding and art.highlights:
            finding = "signals: " + ", ".join(f"**{marker}**" for marker in art.highlights[:6])
        if not finding:
            continue
        title = str(art.title or art.type or "artifact").strip()
        query = f" via {_short_sentence(str(art.query), limit=120)}" if art.query else ""
        return f"{title}: {_short_sentence(finding, limit=260)}{query}"
    return ""


def _artifact_is_evidence(art: object) -> bool:
    return getattr(art, "status", "") in ("ok", "partial")


def _collector_is_evidence(result: object) -> bool:
    return getattr(result, "status", "ok") in ("ok", "partial")


def _kubernetes_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    # Run:ai CRD findings first — a not-Ready project/workload is the most direct
    # answer for a control-plane alert that carried no workload label.
    crd_findings = details.get("runai_crd_findings")
    if isinstance(crd_findings, list):
        for finding in crd_findings[:3]:
            if not isinstance(finding, dict) or not finding.get("name"):
                continue
            kind = finding.get("kind") or "resource"
            reason = finding.get("reason") or "NotReady"
            message = str(finding.get("message") or "")
            line = f"- Run:ai {kind} {finding.get('name')} is not Ready ({reason})"
            if message:
                line += f": {_short_sentence(message, limit=200)}"
            lines.append(line)
    warning_events = details.get("warning_events")
    if isinstance(warning_events, list):
        for event in warning_events[:3]:
            if not isinstance(event, dict):
                continue
            reason = event.get("reason") or "Warning"
            message = event.get("message") or ""
            if message:
                lines.append(
                    f"- Kubernetes event {reason}: {_short_sentence(str(message), limit=220)}"
                )
    pod_statuses = details.get("pod_statuses")
    if isinstance(pod_statuses, list):
        for pod in pod_statuses[:2]:
            if not isinstance(pod, dict):
                continue
            if pod.get("phase") and pod.get("name"):
                lines.append(_pod_describe_line(pod))
    return lines


def _pod_describe_line(pod: dict[str, object]) -> str:
    """`kubectl describe`-grade one-liner: phase + per-container limits, restarts,
    and last termination. "phase Running" alone told the operator nothing on a
    memory-limit alert — the limit and any OOMKilled restarts are the evidence."""
    base = f"- Kubernetes pod {pod.get('name')} is in phase {pod.get('phase')}"
    resources = pod.get("resources") if isinstance(pod.get("resources"), dict) else {}
    statuses = pod.get("containerStatuses")
    parts: list[str] = []
    for st in (statuses if isinstance(statuses, list) else [])[:2]:
        if not isinstance(st, dict) or not st.get("name"):
            continue
        cname = str(st["name"])
        facts: list[str] = []
        res = resources.get(cname) if isinstance(resources.get(cname), dict) else {}
        limits = res.get("limits") if isinstance(res.get("limits"), dict) else {}
        requests = res.get("requests") if isinstance(res.get("requests"), dict) else {}
        if limits.get("memory"):
            mem = f"mem limit {limits['memory']}"
            if requests.get("memory"):
                mem += f" (request {requests['memory']})"
            facts.append(mem)
        if limits.get("cpu"):
            facts.append(f"cpu limit {limits['cpu']}")
        restarts = st.get("restartCount")
        if isinstance(restarts, int) and restarts > 0:
            facts.append(f"{restarts} restart(s)")
        state = st.get("state") if isinstance(st.get("state"), dict) else {}
        waiting = state.get("waiting") if isinstance(state.get("waiting"), dict) else {}
        if waiting.get("reason"):
            facts.append(f"waiting: {waiting['reason']}")
        last_state = st.get("lastState") if isinstance(st.get("lastState"), dict) else {}
        term = last_state.get("terminated")
        term = term if isinstance(term, dict) else {}
        if term.get("reason") or term.get("exitCode") is not None:
            last = f"last {term.get('reason') or 'terminated'}"
            if term.get("exitCode") is not None:
                last += f" (exit {term['exitCode']})"
            if term.get("finishedAt"):
                last += f" at {term['finishedAt']}"
            facts.append(last)
        if facts:
            parts.append(f"{cname}: " + ", ".join(facts))
    if parts:
        base += " — " + "; ".join(parts)
    return base + "."


def _loki_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    queries = details.get("queries")
    if not isinstance(queries, list):
        return lines
    for query in queries:
        if not isinstance(query, dict):
            continue
        line_count = query.get("line_count")
        name = query.get("name") or "query"
        if isinstance(line_count, int) and line_count > 0:
            lines.append(f"- Loki {name} returned {line_count} matching log line(s).")
    return lines


def _runai_highlights(details: dict[str, object]) -> list[str]:
    lines: list[str] = []
    project = details.get("project")
    workload = details.get("workload_name") or details.get("runai_workload_id")
    if project or workload:
        lines.append(
            "- Run:ai target context: "
            f"project={project or 'unknown'}, workload={workload or 'unknown'}."
        )
    queries = details.get("queries")
    if isinstance(queries, list):
        for query in queries[:3]:
            if not isinstance(query, dict):
                continue
            if query.get("error"):
                lines.append(
                    f"- Run:ai {query.get('name', 'query')} failed with {query.get('error')}."
                )
    return lines


_SIMILARITY_FLOOR = 0.80


def _recommended_action_lines(
    missing: list[str],
    request: AlertAnalysisRequest | None = None,
    *,
    include_similar: bool = True,
) -> list[str]:
    # Concrete actions only — no generic "trust the evidence" filler.
    lines: list[str] = []
    # Weave the proven RCA/fix from a high-similarity past incident into the actions.
    top = _top_similar_incident(request) if request and include_similar else None
    if top is not None:
        proven = _short_sentence(top.analysis_summary or top.title or "", limit=320)
        if proven:
            lines.append(
                f"- Similar past incident {top.incident_id} (similarity "
                f"{top.similarity:.2f}) was resolved by: {proven} — verify this fix "
                "applies here before repeating it."
            )
    if "runai.auth" in missing or "runai.query" in missing:
        lines.append(
            "- Restore Run:ai API authentication so the agent can attach "
            "workload/project context on the next analysis run."
        )
    if "loki.auth" in missing or "loki.query" in missing:
        lines.append(
            "- Fix Loki reachability for the next analysis run: prefer the direct "
            "loki-read service, and only add tenant/auth settings when the endpoint "
            "explicitly requires them."
        )
    if "postgres.query" in missing or "postgres.connection" in missing:
        lines.append(
            "- Restore Postgres connectivity so RCA memory and similar-incident "
            "evidence stay current."
        )
    return lines


async def _operator_questions(
    settings: Settings,
    missing: list[str],
    plan: InvestigationPlan | None,
    target: AnalysisTarget,
    next_check: str,
) -> list[str]:
    """2-4 concrete follow-up questions when the RCA could not settle.

    Derived deterministically from missing_data + the plan; the LLM only sharpens
    the wording when configured (deterministic list is the fallback).
    """
    ko = getattr(settings, "language", "en") == "ko"

    def has(prefix: str) -> bool:
        return any(item.startswith(prefix) for item in missing)

    questions: list[str] = []
    if next_check:
        questions.append(next_check)
    if has("loki."):
        questions.append(
            "Loki 주소(LOKI_URL)가 설정되어 있고 에이전트에서 접근 가능한지 확인해 주세요."
            if ko
            else "Is the Loki URL configured and reachable from the agent?"
        )
    if has("runai."):
        questions.append(
            "Run:ai API 인증 정보(토큰 또는 클라이언트 ID/시크릿)가 유효한지 확인해 주세요."
            if ko
            else "Are the Run:ai API credentials (token or client id/secret) still valid?"
        )
    if has("prometheus."):
        questions.append(
            "Prometheus 주소(PROMETHEUS_URL)가 설정되어 있는지 확인해 주세요."
            if ko
            else "Is the Prometheus URL configured for the agent?"
        )
    if has("postgres."):
        questions.append(
            "Postgres 연결 정보(DSN)가 설정되어 있는지 확인해 주세요."
            if ko
            else "Is the Postgres DSN configured so RCA memory can be consulted?"
        )
    if has("kubernetes."):
        questions.append(
            "에이전트의 Kubernetes 서비스 계정 토큰이 유효한지 확인해 주세요."
            if ko
            else "Is the agent's Kubernetes service-account token valid?"
        )
    namespaces = list(plan.namespaces) if plan else []
    if has("system_agent.") or not (target.namespace or namespaces):
        questions.append(
            "이 알림이 발생한 노드에 접근(시스템 에이전트 등)이 가능한지 확인해 주세요."
            if ko
            else "Is the node this alert fired on accessible (system agent or SSH)?"
        )
    if len(questions) < 2:
        questions.append(
            "알림 발생 시각 전후에 배포나 설정 변경이 있었는지 확인해 주세요."
            if ko
            else "Were there any deployments or config changes around the alert time?"
        )
    questions = questions[:4]

    if llm_configured(settings, getattr(settings, "llm_model_insight", "")):
        try:
            sharpened = await _sharpen_operator_questions(settings, questions, missing, plan)
        except Exception:  # noqa: BLE001 - sharpening is best-effort
            sharpened = None
        if sharpened:
            return sharpened
    return [_short_sentence(question, limit=240) for question in questions]


async def _sharpen_operator_questions(
    settings: Settings,
    questions: list[str],
    missing: list[str],
    plan: InvestigationPlan | None,
) -> list[str] | None:
    """LLM-sharpened operator questions; None keeps the deterministic list."""
    ko = getattr(settings, "language", "en") == "ko"
    system = (
        "You review operator-facing follow-up questions for an RCA that could not "
        "settle on a root cause. Rewrite the draft questions to be sharper and more "
        "specific to the missing data and investigation plan. Do not invent facts, "
        "do not add generic filler. "
        + ("반드시 한국어로 작성하세요. " if ko else "Write in English. ")
        + 'Respond with ONLY JSON: {"questions": [str, ...]} containing 2 to 4 questions.'
    )
    user = _build_settings_masker(settings).mask_text(json.dumps(
        {
            "draft_questions": questions,
            "missing_data": missing,
            "plan": plan.as_dict() if plan else {},
        },
        ensure_ascii=False,
        default=str,
    ))
    data = await complete_json(
        settings,
        system=system,
        user=user,
        temperature=0.2,
        model=getattr(settings, "llm_model_insight", "") or None,
    )
    if not isinstance(data, dict):
        return None
    raw = data.get("questions")
    if not isinstance(raw, list):
        return None
    masker = _build_settings_masker(settings)
    cleaned = [
        _short_sentence(masker.mask_text(str(item)), limit=240)
        for item in raw
        if str(item).strip()
    ]
    if 2 <= len(cleaned) <= 4:
        return cleaned
    return None


# Xid codes appear as "Xid 79", "Xid: 79", or "NVRM: Xid (PCI:0000:3b:00): 79" —
# skip the optional parenthesized PCI address before the code so we don't capture it.
_XID_PATTERN = re.compile(r"\bxid\s*(?:\([^)]*\))?\s*[:=]?\s*(\d{1,4})", re.IGNORECASE)


def _xid_codes_from_results(results: list[CollectorResult], alert_text: str = "") -> list[int]:
    """Distinct NVIDIA Xid codes in the alert's own text + loki/system/kubernetes
    evidence. The alert text matters: an NVRM Xid alert names its code even when
    every collector comes back empty."""
    texts = [alert_text] if alert_text else []
    texts.extend(
        _stringify_result(result)
        for result in results
        if result.agent in ("loki", "system", "kubernetes") and _collector_is_evidence(result)
    )
    codes: list[int] = []
    for text in texts:
        for match in _XID_PATTERN.finditer(text):
            if _keyword_negated(text.lower(), match.start(), match.end()):
                continue
            code = int(match.group(1))
            if code not in codes:
                codes.append(code)
    return codes


def _gpu_model_from(target: AnalysisTarget, results: list[CollectorResult]) -> str:
    """GPU model, when a collector resolved one into its details (e.g. gpu_model)."""
    for result in results:
        for key in ("gpu_model", "gpu_type", "gpu_product"):
            value = result.details.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _stringify_result(result: CollectorResult) -> str:
    parts = [result.summary or ""]
    artifacts = getattr(result, "artifacts", []) or []
    parts.extend(art.summary or "" for art in artifacts if _artifact_is_evidence(art))
    parts.extend(
        _evidence_leaf_text(art.result)
        for art in artifacts
        if _artifact_is_evidence(art) and art.result
    )
    details = getattr(result, "details", {})
    if details:
        parts.append(_evidence_leaf_text(details))
    return " ".join(parts)


def _graph_remediation_lines(graph_fixes: GraphRemediation | None) -> list[str]:
    if graph_fixes is None or graph_fixes.is_empty():
        return []
    masker = build_masker(())
    lines = ["- Knowledge-graph derived remediation:"]
    for statement in graph_fixes.family_fixes[:5]:
        lines.append(f"  - {_safe_line(statement, limit=360, masker=masker)}")
    for code, fixes in graph_fixes.xid_fixes.items():
        lines.append(f"  - NVIDIA Xid {code}:")
        lines.extend(
            f"    - {_safe_line(statement, limit=360, masker=masker)}"
            for statement in fixes[:5]
        )
    for model, xids in graph_fixes.model_xids.items():
        rendered = ", ".join(str(x) for x in xids)
        safe_model = _safe_line(model, limit=120, masker=masker)
        lines.append(f"  - Known Xid codes for {safe_model}: {rendered}.")
    return lines


def _affected_pods_lines(request: AlertAnalysisRequest, language: str = "en") -> list[str]:
    pods = [pod.strip() for pod in request.occurrence_pods if pod and pod.strip()]
    count = request.occurrence_count
    if not pods and count <= 1:
        return []
    ko = language == "ko"
    lines = ["", "### Affected Pods", ""]
    if count > 1:
        lines.append(
            f"- 같은 워크로드에서 {count}회 발생한 알림을 묶었습니다. 컨트롤러가 파드를 "
            "새 이름으로 계속 재생성하므로, 아래 이름들은 개별 장애가 아니라 하나의 "
            "순환(재시작) 워크로드로 보세요."
            if ko
            else f"- This alert was grouped from {count} occurrence(s) of the same workload; "
            "the controller keeps recreating pods under new names, so treat the names "
            "below as one cycling workload rather than separate failures."
        )
    if pods:
        shown = pods[:20]
        lines.extend(f"- `{pod}`" for pod in shown)
        if len(pods) > len(shown):
            more = len(pods) - len(shown)
            lines.append(f"- … 외 {more}개 파드" if ko else f"- … and {more} more pod(s)")
    else:
        lines.append(
            "- 알림 라벨에 개별 파드 이름이 없었습니다."
            if ko
            else "- Individual pod names were not present on the alert labels."
        )
    return lines


def _top_similar_incident(request: AlertAnalysisRequest):
    """Highest-similarity incident at/above the 0.80 trust floor, else None."""
    qualified = [
        item for item in request.similar_incidents if (item.similarity or 0) >= _SIMILARITY_FLOOR
    ]
    if not qualified:
        return None
    return max(qualified, key=lambda item: item.similarity or 0)


_SIMILAR_STOPWORDS = {
    "alert",
    "and",
    "ai",
    "because",
    "check",
    "critical",
    "during",
    "error",
    "errors",
    "failed",
    "failure",
    "firing",
    "gpu",
    "incident",
    "namespace",
    "nvidia",
    "old",
    "out",
    "over",
    "pod",
    "pods",
    "run",
    "runai",
    "status",
    "the",
    "training",
    "warning",
}


def _similar_incident_relevant(request: AlertAnalysisRequest, observed_text: str) -> bool:
    top = _top_similar_incident(request)
    if top is None:
        return False
    current = _similar_tokens(observed_text)
    prior = _similar_tokens(
        " ".join([top.title or "", top.analysis_summary or "", top.analysis_detail or ""])
    )
    return bool(current & prior)


def _similar_tokens(text: str) -> set[str]:
    lowered = (text or "").lower()
    return {
        match.group(0)
        for match in re.finditer(r"[a-z0-9]+", lowered)
        if len(match.group(0)) > 2
        and match.group(0) not in _SIMILAR_STOPWORDS
        and not _keyword_negated(lowered, match.start(), match.end())
    }


def _similar_incident_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "### Similar Incidents", ""]
    # Only surface vector hits we actually trust; a 0.70 "match" is noise.
    qualified = sorted(
        (i for i in request.similar_incidents if (i.similarity or 0) >= _SIMILARITY_FLOOR),
        key=lambda i: i.similarity or 0,
        reverse=True,
    )
    if not qualified:
        return [*lines, "- No similar past incident found."]
    for item in qualified[:3]:
        feedback = (
            f"{item.positive_feedback} up / {item.negative_feedback} down / "
            f"{item.comment_count} comments"
        )
        lines.append(
            f"- {item.incident_id} ({item.similarity:.3f}, {feedback}): "
            f"{_short_sentence(item.analysis_summary or item.title or '', limit=320)}"
        )
    return lines


def _feedback_hint_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "### Feedback Learning Hints", ""]
    if not request.feedback_hints:
        return [*lines, "- No operator feedback hints were provided."]
    for hint in request.feedback_hints[:5]:
        lines.append(
            f"- {hint.sentiment} from {hint.source_id}: "
            f"{_short_sentence(hint.text, limit=320)}"
        )
    return lines
