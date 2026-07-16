from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, TypeVar

from pydantic import BaseModel

from app.collectors.base import (
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    causal_evidence_time_range,
    condition_observations,
    kubernetes_salient_markers,
    parse_incident_time,
    resolve_target,
    salient_markers,
)
from app.collectors.base import artifact as make_artifact
from app.collectors.registry import build_collectors, unknown_collector_names
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
)
from app.masking import Masker, build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.prompts import load_agent_souls
from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse
from app.services.decision_tree import resolve_tree, walk_tree
from app.services.general_guidance import general_guidance_lines
from app.services.kg_enrichment import GraphRemediation, enrich, graph_remediation
from app.services.planner import plan_investigation
from app.services.root_cause_ranking import (
    RankedCause,
    artifact_supports_family,
    merge_open_world_candidates,
    rank_root_cause_candidates,
)

_log = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)
Stage = Callable[["PipelineState"], Awaitable["PipelineState"]]
_SYNTHESIS_ARTIFACT_RESULT_CHARS = 1200
_SYNTHESIS_USER_CHARS = 24000

# Raw Kubernetes objects contain failure vocabulary even when the observed
# value is healthy or merely declarative configuration.  Those fields remain
# available in the response artifact for operators, but the free-form
# synthesizer receives a status-aware projection instead.
_K8S_SYNTHESIS_CONTEXT_DROP_KEYS = frozenset(
    {
        "args",
        "arguments",
        "command",
        "managedfields",
        "metadata",
        "path",
        "preemptionpolicy",
        "priorityclassname",
        "queries",
        "query",
        "request",
        "request_body",
        "spec",
        "url",
    }
)
_K8S_CONDITION_TYPES = frozenset(
    {
        "containersready",
        "diskpressure",
        "disruptiontarget",
        "memorypressure",
        "networkunavailable",
        "pidpressure",
        "podscheduled",
        "ready",
    }
)
_SYNTHESIS_ASSERTION_CONDITIONAL = re.compile(
    r"\b(?:check|verify|whether|hypothesis|possible|possibly|could|may|might|candidate)\b|"
    r"(?:확인\s*(?:필요|대상|예정)|확인(?:하|해|해야)|점검|검증|여부|가설|가능성|의심|후보)",
    re.IGNORECASE,
)
_SYNTHESIS_PRIVATE_FACT_CITATION = re.compile(
    r"(?<![A-Za-z0-9_-])F-[0-9a-f]{8,64}(?![A-Za-z0-9_-])", re.IGNORECASE
)
_SYNTHESIS_PUBLIC_EVIDENCE_CITATION = re.compile(r"\[(E\d+)\]")


@dataclass
class PipelineState:
    settings: Settings
    request: AlertAnalysisRequest
    target: AnalysisTarget
    progress: ProgressReporter
    masker: Masker
    collectors: list[object]
    # Immutable identity resolved from the alert payload. ``target`` becomes
    # the effective post-plan scope for live analysis; keeping this baseline is
    # what lets historical pinning remain stable across repeated evidence runs.
    declared_target: AnalysisTarget | None = None
    runtime_label: str = "fallback"
    agent_souls: str = ""
    kg_context: Any = None
    plan: InvestigationPlan | None = None
    results: list[CollectorResult] = field(default_factory=list)
    investigation_context: dict[str, object] = field(default_factory=dict)
    # Per-analysis shared, query-safe facts.  This is intentionally runtime
    # state; the selected trace is persisted only after the response passes the
    # approval path.
    blackboard: Any = None
    priors: dict[str, float] | None = None
    observed: str = ""
    alert_fuzzy: str = ""
    xid_codes: list[int] = field(default_factory=list)
    failure_modes: dict[str, list[dict]] = field(default_factory=dict)
    known_issues: list[dict] = field(default_factory=list)
    root_cause_candidates: list[RankedCause] = field(default_factory=list)
    open_world_candidates: list[RankedCause] = field(default_factory=list)
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
    investigation_context: dict[str, Any]
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
    analysis_started_at: float | None = None,
) -> PipelineState:
    target = resolve_target(
        request.alert.labels,
        request.alert.annotations,
        fired_at=request.alert.startsAt or "",
        resolved_at=request.alert.endsAt or "",
    )
    masker = _build_settings_masker(settings)
    active_collectors = collectors if collectors is not None else build_collectors(settings)
    for collector in active_collectors:
        clear_cache = getattr(collector, "clear_cache", None)
        if callable(clear_cache):
            clear_cache()
    state = PipelineState(
        settings=settings,
        request=request,
        target=target,
        progress=ProgressReporter.from_alert(settings, request.alert, masker),
        masker=masker,
        collectors=active_collectors,
        declared_target=target,
        runtime_label=runtime_label,
        analysis_started_at=(
            analysis_started_at if analysis_started_at is not None else time.monotonic()
        ),
    )
    state.extra_warnings.extend(
        f"configured collector '{name}' is unknown; its evidence plane is missing"
        for name in unknown_collector_names(settings)
    )
    return state


def _finalization_reserve_seconds(total_seconds: int) -> float:
    """Automatically reserve time for rank/self-check/synthesis/harness.

    At the default 1500s deadline, evidence gathering (investigation plus every
    drill-down) shares 1200s and finalization keeps 300s. Short test/operator
    deadlines reserve at most half so evidence still gets a useful window.
    """
    if total_seconds <= 0:
        return 0.0
    return min(300.0, max(30.0, total_seconds * 0.20), total_seconds * 0.50)


def _evidence_deadline_monotonic(state: PipelineState) -> float | None:
    total = int(getattr(state.settings, "analysis_deadline_seconds", 0) or 0)
    if total <= 0:
        return None
    return state.analysis_started_at + total - _finalization_reserve_seconds(total)


def _evidence_budget_exceeded(state: PipelineState) -> bool:
    deadline = _evidence_deadline_monotonic(state)
    return deadline is not None and time.monotonic() >= deadline


def _record_evidence_budget_stop(state: PipelineState, phase: str) -> None:
    """Record the expected safety stop in trace/logs, not operator warnings.

    The evidence deadline intentionally reserves time for synthesis and the
    output harness. Reaching it after base evidence is complete is normal and
    should not look like a telemetry failure in the final report.
    """
    _log.info("evidence budget reached; skipped optional %s", phase)
    trace = state.investigation_context.get("reasoning_trace_v2")
    if isinstance(trace, dict):
        trace["stop_reason"] = "analysis_budget_exhausted"
    reporter = getattr(state, "progress", None)
    if reporter is not None:
        reporter.emit(
            "investigation",
            "Evidence budget reached; moving to synthesis",
            stopped_phase=phase,
        )


def _is_resolved_reanalysis(request: AlertAnalysisRequest) -> bool:
    """Whether this run must preserve the alert's historical resource identity.

    A replacement Pod discovered *now* is useful for a firing alert, but it is
    not the Pod that a resolved alert fired on.  Retargeting Event reads to it
    can turn the old Pod's warning events into a false historical absence.
    """
    if str(getattr(request.alert, "status", "") or "").strip().casefold() == "resolved":
        return True
    # Stored/manual re-analysis can carry the authoritative historical end while
    # an older alert row still says firing. Treat only a valid end at/after the
    # start as resolved; Alertmanager's zero/placeholder endsAt must not freeze a
    # genuinely firing alert onto stale Pod identities.
    ends_at = parse_incident_time(getattr(request.alert, "endsAt", None))
    starts_at = parse_incident_time(getattr(request.alert, "startsAt", None))
    return ends_at is not None and (starts_at is None or ends_at >= starts_at)


def _pin_resolved_target_identity(state: PipelineState) -> None:
    """Keep resolved RCA reads on identities that existed during the alert.

    The planner may suggest a currently visible replacement Pod, node, workload,
    or even put another namespace first. Those are useful for a firing alert but
    cannot replace immutable historical identities. A single grouped occurrence
    Pod is also a concrete historical identity when the selected alert row did
    not retain a Pod label; multiple occurrence Pods remain a set and are not
    collapsed to an arbitrary member.
    """
    if not _is_resolved_reanalysis(state.request) or state.plan is None:
        return

    if state.declared_target is None:
        state.declared_target = state.target
    target = state.declared_target
    plan = state.plan
    if target.namespace:
        plan.namespaces = [
            target.namespace,
            *(namespace for namespace in plan.namespaces if namespace != target.namespace),
        ]

    occurrence_pods = list(
        dict.fromkeys(
            pod.strip()
            for pod in state.request.occurrence_pods
            if isinstance(pod, str) and pod.strip()
        )
    )
    historical_pod = target.pod or (
        occurrence_pods[0] if len(occurrence_pods) == 1 else ""
    )
    if plan.pod and plan.pod != historical_pod:
        _log.info(
            "plan: dropping live/guessed pod %s for resolved target %s",
            plan.pod,
            historical_pod or "<no-single-pod>",
        )
    plan.pod = historical_pod

    # An absent historical node/workload is an evidence gap, not permission to
    # substitute a planner guess derived from today's cluster state.
    plan.node = target.node
    plan.workload = target.workload_name


def _apply_effective_target(state: PipelineState) -> AnalysisTarget:
    """Persist the one target identity used after planning.

    Collectors already narrow live alerts through the plan.  Persisting that
    narrowed identity on ``state.target`` keeps blackboard aliases, eligibility,
    ranking, self-check, and the harness from validating the returned evidence
    against the stale alert Pod.  Resolved incidents remain pinned to their
    historical identity and never adopt a live replacement.
    """
    if state.plan is None:
        return state.target
    from app.collectors.kubernetes import _scope_target

    if state.declared_target is None:
        state.declared_target = state.target
    state.target = _scope_target(state.declared_target, state.plan)
    return state.target


_ALERT_DISPOSITIVE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "image_pull_error": (
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
    ),
    "workload_startup_error": (
        "CrashLoopBackOff",
        "OOMKilled",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
    ),
    "k8s_scheduling_error": ("FailedScheduling", "Unschedulable"),
    "k8s_storage_error": (
        "FailedMount",
        "FailedAttachVolume",
        "ProvisioningFailed",
        "VolumeBinding",
    ),
}

_ALERT_STATE_FIELDS = ("status", "value", "active", "state")
_ALERT_TRUE_VALUES = frozenset({"true", "1", "yes", "active", "firing", "present"})
_ALERT_FALSE_VALUES = frozenset(
    {"false", "0", "no", "inactive", "absent", "cleared", "resolved"}
)
_ALERT_NON_EVIDENCE_FIELD_RE = re.compile(
    r"(?:runbook|operator_prompt|analysis_run_id|dashboard|documentation|docs?|"
    r"query|expression|command|template|example|sample)",
    re.IGNORECASE,
)
_ALERT_NON_ASSERTIVE_PREFIX_RE = re.compile(
    r"(?:\b(?:check|verify|inspect|grep|search|test|rule\s+out|look\s+for)\b[^.!?\n]{0,96}"
    r"|\b(?:possible|possibly|potential|maybe|hypothesis|candidate|runbook|"
    r"example|sample|template|expected\s+observation)\b[^.!?\n]{0,96})$",
    re.IGNORECASE,
)
_ALERT_NON_ASSERTIVE_SUFFIX_RE = re.compile(
    r"^\s*(?:[=:,-]\s*)?(?:"
    r"(?:is\s+|was\s+)?(?:false|inactive|absent|possible|potential|hypothetical)\b"
    r"|(?:as\s+)?(?:a\s+)?possibility\b|if\b|whether\b|=\s*0\b)",
    re.IGNORECASE,
)


def _alert_boolean_state(value: object) -> bool | None:
    normalized = str(value or "").strip().casefold()
    if normalized in _ALERT_TRUE_VALUES:
        return True
    if normalized in _ALERT_FALSE_VALUES:
        return False
    return None


def _alert_signal_field(key: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key or "").casefold()).strip("_")
    return (
        "condition" in normalized
        or normalized == "reason"
        or normalized.endswith("_reason")
        or normalized.endswith("_phase")
    )


def _asserted_alert_texts(request: AlertAnalysisRequest) -> list[str]:
    """Return alert values that can make an auditable positive assertion.

    Condition/status pairs are evaluated structurally in both labels and
    annotations, so sender insertion order cannot turn ``False OOMKilled`` into
    a positive fact.  Runbook/operator/query fields remain hypothesis guidance,
    never incident evidence.
    """
    texts: list[str] = []
    for metadata in (request.alert.labels or {}, request.alert.annotations or {}):
        entries = [
            (str(key), str(value).strip())
            for key, value in metadata.items()
            if str(value).strip()
        ]
        normalized = {key.casefold(): value for key, value in entries}
        state = next(
            (
                parsed
                for field in _ALERT_STATE_FIELDS
                if field in normalized
                and (parsed := _alert_boolean_state(normalized[field])) is not None
            ),
            None,
        )
        has_structured_signal = any(_alert_signal_field(key) for key, _value in entries)
        if state is False and has_structured_signal:
            continue
        for key, value in entries:
            if key.casefold() in _ALERT_STATE_FIELDS:
                continue
            if _ALERT_NON_EVIDENCE_FIELD_RE.search(key):
                continue
            if value not in texts:
                texts.append(value)
    return texts


def _alert_signature_is_asserted(text: str, start: int, end: int) -> bool:
    lowered = text.casefold()
    if _keyword_negated(lowered, start, end):
        return False
    prefix = text[max(0, start - 128) : start]
    # Restrict the extra False/order and instruction checks to the local clause;
    # an earlier healthy condition followed by "but OOMKilled" is not negation.
    local_prefix = re.split(
        r"(?:[.;!?\n]|\bbut\b|\bhowever\b|하지만)", prefix, flags=re.IGNORECASE
    )[-1]
    if re.search(r"\b(?:false|inactive|absent|zero|0)\b", local_prefix, re.IGNORECASE):
        return False
    if _ALERT_NON_ASSERTIVE_PREFIX_RE.search(local_prefix):
        return False
    suffix = text[end : end + 80]
    return _ALERT_NON_ASSERTIVE_SUFFIX_RE.match(suffix) is None


def _asserted_alert_signatures(
    request: AlertAnalysisRequest,
) -> tuple[list[int], dict[str, list[str]]]:
    codes: list[int] = []
    matched_by_family: dict[str, list[str]] = {}
    for text in _asserted_alert_texts(request):
        for match in _XID_PATTERN.finditer(text):
            if not _alert_signature_is_asserted(text, match.start(), match.end()):
                continue
            code = int(match.group(1))
            if code not in codes:
                codes.append(code)
        for family, markers in _ALERT_DISPOSITIVE_SIGNATURES.items():
            for marker in markers:
                for match in re.finditer(re.escape(marker), text, re.IGNORECASE):
                    if not _alert_signature_is_asserted(text, match.start(), match.end()):
                        continue
                    matched = matched_by_family.setdefault(family, [])
                    if marker not in matched:
                        matched.append(marker)
                    break
    return codes, matched_by_family


def _alert_evidence_identity(
    request: AlertAnalysisRequest, target: AnalysisTarget
) -> str:
    return str(request.alert.fingerprint or target.alert_name or "alert").strip() or "alert"


def _alert_signature_evidence_result(
    request: AlertAnalysisRequest, target: AnalysisTarget
) -> CollectorResult | None:
    """Materialize explicit alert failure signatures as typed, citable evidence."""
    codes, matched_by_family = _asserted_alert_signatures(request)
    if not codes and not matched_by_family:
        return None

    # The alert payload is an observation by Alertmanager.  Never attach it to
    # a live replacement Pod/node discovered later by planning; run identity +
    # alert fingerprint keep it auditable without broadening collector scope.
    observed_entity = {
        "kind": "alert",
        "name": _alert_evidence_identity(request, target),
    }

    cards = []
    if codes:
        signals = [f"NVIDIA XID {code}" for code in codes]
        summary = "Alert payload explicitly reported " + ", ".join(signals) + "."
        cards.append(
            make_artifact(
                agent="alert",
                source="alertmanager",
                type="alert_signature",
                status="ok",
                confidence="high",
                summary=summary,
                result={
                    "matched_signals": signals,
                    "xid_codes": codes,
                    "observation": {
                        "predicate": "alert_signature:nvidia_xid",
                        "polarity": "present",
                        "coverage": "scoped",
                        "observed_entity": observed_entity,
                    },
                },
                highlights=signals,
            )
        )
    for family, matched in matched_by_family.items():
        signals = list(dict.fromkeys(matched))
        summary = "Alert payload explicitly reported " + ", ".join(signals) + "."
        cards.append(
            make_artifact(
                agent="alert",
                source="alertmanager",
                type="alert_signature",
                status="ok",
                confidence="high",
                summary=summary,
                result={
                    "matched_signals": signals,
                    "observation": {
                        "predicate": f"alert_signature:{family}",
                        "polarity": "present",
                        "coverage": "scoped",
                        "observed_entity": observed_entity,
                    },
                },
                highlights=signals,
            )
        )
    combined = " ".join(str(card.summary or "") for card in cards)
    return CollectorResult(
        agent="alert",
        status="ok",
        summary=combined,
        confidence="high",
        details={"source_group": "alertmanager"},
        artifacts=cards,
    )


def _aggregate_evidence(state: PipelineState) -> None:
    kg_warnings = getattr(state.kg_context, "warnings", []) if state.kg_context is not None else []
    state.capabilities = {result.agent: result.status for result in state.results}
    # Evidence IDs are assigned after every collector has completed. They are
    # response-local, deterministic, and become run-qualified during TypeDB ingest.
    from app.services.harness import assign_evidence_ids

    state.artifacts = assign_evidence_ids(state.results)
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
    # Knowledge graph is consulted once here before planning, then the same
    # snapshot guides collectors and final synthesis — not a parallel collector.
    state.kg_context = await enrich(
        state.settings, target, list(state.request.similar_incidents)
    )
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
    # A planner/live lookup may identify resources that exist today. Pin every
    # concrete identity carried by a resolved alert before any collector uses it.
    _pin_resolved_target_identity(state)
    # Alert labels frequently name a pod the controller already replaced (grouped
    # CrashLoop occurrences) and carry no node label — so kubernetes GETs 404 and
    # the system agent skips node/kernel evidence entirely. Re-resolve a LIVE pod
    # and its node ONCE here; every collector then scopes off the plan.
    seed_pod = state.plan.pod or state.target.pod
    if state.target.namespace and seed_pod and not _is_resolved_reanalysis(state.request):
        from app.collectors.kubernetes import resolve_live_pod_node

        live_pod, live_node = await resolve_live_pod_node(
            state.settings,
            state.target.namespace,
            seed_pod,
            list(state.request.occurrence_pods),
            state.target.workload_name or state.plan.workload,
        )
        if live_pod and live_pod != seed_pod:
            _log.info("plan: stale pod %s re-resolved to live pod %s", seed_pod, live_pod)
        if live_pod:
            state.plan.pod = live_pod
        # Resource identity beats planner prose: retain an explicit alert node,
        # otherwise the live Pod's spec.nodeName overrides a guessed plan node.
        if state.target.node:
            state.plan.node = state.target.node
        elif live_node:
            state.plan.node = live_node
    _apply_effective_target(state)
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
    # Keep this guard at the execution boundary too: callers/tests may provide
    # a prebuilt plan without going through plan_stage.
    _pin_resolved_target_identity(state)
    # The plan is authoritative after plan_stage — it may carry a re-resolved
    # LIVE pod/node for a stale alert pod. Scope the stage's working target ONCE
    # so the flowchart follow-ups, drill-down, and investigation loop query the
    # live pod too, not just the base collectors (which scope internally).
    target = _apply_effective_target(state)
    causal_window = causal_evidence_time_range(target) or {}
    state.investigation_context = {}
    from app.services.evidence_blackboard import Blackboard

    state.blackboard = Blackboard(run_id=str(state.request.incident_id or ""))

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

        investigation_kwargs: dict[str, Any] = {"reporter": state.progress}
        if (
            getattr(settings, "open_world_rca_mode", "off") != "off"
            and _accepts_keyword(investigate, "blackboard")
        ):
            investigation_kwargs["blackboard"] = state.blackboard
        if _accepts_keyword(investigate, "deadline_monotonic"):
            investigation_kwargs["deadline_monotonic"] = _evidence_deadline_monotonic(state)
        state.results, state.investigation_context = await investigate(
            settings,
            target,
            state.collectors,
            plan,
            state.kg_context.as_dict(),
            settings.max_investigation_steps,
            **investigation_kwargs,
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
    alert_evidence = _alert_signature_evidence_result(state.request, target)
    if alert_evidence is not None and not any(r.agent == "alert" for r in state.results):
        state.results.append(alert_evidence)
    # The investigator receives the board only in open-world mode for backward
    # compatibility with legacy integrations, but every evidence agent must
    # still receive the same shared observations during drill-down. Seeding is
    # idempotent, so this also covers results already recorded by investigate.
    state.blackboard.seed_results(
        state.results,
        entity=_blackboard_target_entity(target),
        timestamp=getattr(target, "fired_at", ""),
        observed_window_start=str(causal_window.get("start") or ""),
        observed_window_end=str(causal_window.get("end") or ""),
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
        state.blackboard.seed_results(
            state.results,
            entity=_blackboard_target_entity(target),
            timestamp=getattr(target, "fired_at", ""),
            observed_window_start=str(causal_window.get("start") or ""),
            observed_window_end=str(causal_window.get("end") or ""),
        )
    except Exception:  # noqa: BLE001 - follow-up is best-effort, never fail analysis
        pass
    # Per-collector autonomous drill-down (LLM-gated): each domain agent runs a
    # bounded LLM loop with ONLY its domain's read-only tools to deepen its own
    # evidence (services/drilldown.py). Best-effort, never fails analysis.
    try:
        from app.services.drilldown import run_drilldowns

        drilldown_kwargs: dict[str, Any] = {"blackboard": state.blackboard}
        if _accepts_keyword(run_drilldowns, "deadline_monotonic"):
            drilldown_kwargs["deadline_monotonic"] = _evidence_deadline_monotonic(state)
        await run_drilldowns(settings, state.results, target, plan, **drilldown_kwargs)
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
    _link_probe_assessments_to_ledger(state)
    # The blackboard facts are an additive, compact trace for ranking/synthesis;
    # raw artifacts remain the source for the existing response contract.
    state.investigation_context.setdefault(
        "reasoning_trace_v2",
        {
            "schema_version": 2,
            "hypotheses": state.investigation_context.get("hypothesis_ledger", []),
            "referenced_facts": state.blackboard.prompt_view(limit=30),
            "stop_reason": "base_evidence_complete",
        },
    )
    state.investigation_context["reasoning_trace_v2"] = _public_reasoning_trace(
        state.investigation_context.get("reasoning_trace_v2"), state
    )
    assessments = _probe_assessments(state.results)
    if assessments:
        trace = state.investigation_context.get("reasoning_trace_v2")
        if isinstance(trace, dict):
            trace["probe_assessments"] = assessments
    state.investigation_context["reasoning_trace_v3"] = _public_reasoning_trace_v3(state)
    return state


def _blackboard_target_entity(target: AnalysisTarget) -> str:
    for field_name in ("pod", "node", "workload_name", "namespace", "alert_name"):
        value = str(getattr(target, field_name, "") or "").strip()
        if value:
            return f"{field_name}:{value}"
    return ""


def _accepts_keyword(callable_obj: Any, name: str) -> bool:
    """Keep the optional blackboard additive for legacy integrations/tests."""
    try:
        parameters = inspect.signature(callable_obj).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _probe_assessments(results: list[CollectorResult]) -> list[dict[str, Any]]:
    """Expose only structured, query-free probe verdicts to subsequent reasoning."""
    assessments: list[dict[str, Any]] = []
    for result in results:
        raw = result.details.get("ontology_probe_assessments")
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, dict):
                continue
            verdict = str(item.get("verdict") or "")
            if verdict not in {"supports", "refutes", "inconclusive", "unavailable"}:
                continue
            assessments.append(
                {
                    "agent": result.agent,
                    "probe_id": str(item.get("probe_id") or "")[:120],
                    # IDs are opaque contract values: never truncate or infer them.
                    "template_id": str(item.get("template_id") or ""),
                    "execution_id": str(item.get("execution_id") or ""),
                    "executed_at": str(item.get("executed_at") or "")[:80],
                    "hypothesis_ids": [
                        str(value)
                        for value in item.get("hypothesis_ids") or []
                        if str(value).strip()
                    ],
                    "tool": str(item.get("tool") or "")[:80],
                    "verdict": verdict,
                    "support_signals": [
                        str(value)[:160] for value in item.get("support_signals") or []
                    ],
                    "refute_signals": [
                        str(value)[:160] for value in item.get("refute_signals") or []
                    ],
                    "hypothesis_family": str(item.get("hypothesis_family") or "")[:120],
                    "evidence_id": _assessment_evidence_id(result, item),
                }
            )
            assessments[-1]["evidence_ids"] = [
                str(value)
                for value in item.get("evidence_ids") or []
                if str(value).strip()
            ] or ([assessments[-1]["evidence_id"]] if assessments[-1]["evidence_id"] else [])
    return assessments[:30]


def _assessment_evidence_id(result: CollectorResult, assessment: dict[str, Any]) -> str:
    try:
        index = int(assessment.get("artifact_index"))
    except (TypeError, ValueError):
        return ""
    if 0 <= index < len(result.artifacts):
        return str(getattr(result.artifacts[index], "evidence_id", "") or "")
    return ""


def _link_probe_assessments_to_ledger(state: PipelineState) -> None:
    """Attach deterministic probe verdicts to matching hypotheses, never promote them.

    Links require exact, execution-time hypothesis IDs. A family name is useful
    planning context but is never a safe identity: multiple hypotheses may
    share one family. Status/confidence still require the investigator/ranker
    to weigh all corroborating and contradicting observations.
    """
    ledger = state.investigation_context.get("hypothesis_ledger")
    if not isinstance(ledger, list):
        return
    by_id = {
        str(item.get("id") or ""): item
        for item in ledger
        if isinstance(item, dict) and str(item.get("id") or "")
    }
    available_evidence = {
        str(getattr(artifact, "evidence_id", "") or "")
        for artifact in state.artifacts
        if getattr(artifact, "evidence_id", "")
    }
    eligibility_by_id = _public_evidence_eligibility(state)
    for assessment in _probe_assessments(state.results):
        verdict = assessment.get("verdict")
        if verdict not in {"supports", "refutes"}:
            continue
        hypothesis_ids = [
            str(value) for value in assessment.get("hypothesis_ids") or []
            if str(value) in by_id
        ]
        if not hypothesis_ids:
            continue
        evidence_ids = [
            str(value) for value in assessment.get("evidence_ids") or []
            if str(value) in available_evidence
        ]
        if not evidence_ids:
            continue
        key = "evidence_for" if verdict == "supports" else "evidence_against"
        role = "support" if verdict == "supports" else "contradict"
        for evidence_id in evidence_ids:
            eligibility = eligibility_by_id.get(evidence_id)
            if eligibility is None or not eligibility.permits(role):
                continue
            for hypothesis_id in hypothesis_ids:
                hypothesis = by_id[hypothesis_id]
                current = hypothesis.setdefault(key, [])
                if isinstance(current, list) and evidence_id not in current:
                    current.append(evidence_id)


def _blackboard_artifact_evidence_ids(state: PipelineState) -> dict[str, str]:
    board = state.blackboard
    identify = getattr(board, "evidence_id_for", None)
    if not callable(identify):
        return {}
    aliases: dict[str, str] = {}
    facts_method = getattr(board, "facts", None)
    try:
        facts = tuple(facts_method()) if callable(facts_method) else ()
    except Exception:  # noqa: BLE001 - blackboard remains optional
        facts = ()
    from app.services.evidence_blackboard import normalize_artifact

    target = state.target
    target_entity = next(
        (
            f"{field}:{value}"
            for field in ("pod", "node", "workload_name", "namespace")
            if (value := str(getattr(target, field, "") or "").strip())
        ),
        "",
    )
    target_timestamp = str(getattr(target, "fired_at", "") or "")
    causal_window = causal_evidence_time_range(target) or {}
    target_window_start = str(causal_window.get("start") or "")
    target_window_end = str(causal_window.get("end") or "")
    facts_by_id = {str(getattr(fact, "fact_id", "")): fact for fact in facts}
    board_run_id = str(getattr(board, "_run_id", "") or "")

    for result in state.results:
        details = result.details if isinstance(result.details, dict) else {}
        source_group = str(details.get("source_group") or "")
        run_id = str(details.get("run_id") or details.get("incident_run_id") or "")
        topology = details.get("topology") or details.get("target_topology") or ()
        for artifact in result.artifacts:
            evidence_id = str(getattr(artifact, "evidence_id", "") or "")
            if not evidence_id:
                continue
            try:
                aliases[str(identify(artifact))] = evidence_id
                # Reproduce the investigator's target/window normalization to
                # link the public artifact to its exact blackboard fact.  Do
                # not alias every fact with the same summary/type: a collector
                # can observe identically worded conditions for two Pods or
                # incident windows, and letting the last E-id win would cite
                # one target's artifact as evidence for another.
                # Blackboard gives an artifact-declared run ID precedence over
                # result- and board-level defaults. Mirror that precedence so
                # a stale declared ID cannot be silently relabelled as this
                # incident while resolving the public alias.
                artifact_run_id = str(normalize_artifact(artifact).run_id or "")
                contextual_fact_id = str(
                    normalize_artifact(
                        artifact,
                        entity=target_entity,
                        timestamp=target_timestamp,
                        observed_window_start=target_window_start,
                        observed_window_end=target_window_end,
                        source_group=source_group,
                        run_id=artifact_run_id or run_id or board_run_id,
                        topology=topology,
                        require_typed_observation=True,
                    ).fact_id
                )
                if contextual_fact_id in facts_by_id:
                    aliases[contextual_fact_id] = evidence_id
                    continue

                # Older blackboard integrations may not have received the
                # resolved incident context.  Retain that compatibility path
                # only when the artifact identity resolves to exactly one fact;
                # ambiguity is unsafe and must remain uncitable.
                artifact_identity = normalize_artifact(artifact).artifact_id
                matches = [
                    fact
                    for fact in facts
                    if str(getattr(fact, "artifact_id", "")) == artifact_identity
                ]
                if len(matches) == 1:
                    aliases[str(getattr(matches[0], "fact_id", ""))] = evidence_id
            except Exception:  # noqa: BLE001 - a missing alias is harmless
                continue
    return aliases


def _public_reasoning_trace(trace: object, state: PipelineState) -> dict[str, Any]:
    if not isinstance(trace, dict):
        return {}
    aliases = _blackboard_artifact_evidence_ids(state)
    output = dict(trace)
    facts = output.get("referenced_facts")
    if isinstance(facts, list):
        output["referenced_facts"] = [
            {
                **fact,
                "evidence_id": aliases.get(
                    str(fact.get("evidence_id") or ""), fact.get("evidence_id")
                ),
            }
            for fact in facts
            if isinstance(fact, dict)
        ]
    return output


def _public_reasoning_trace_v3(state: PipelineState) -> dict[str, Any]:
    """Serialize a strict, public, fact-level reasoning graph.

    v2 carries the legacy free-form ledger. v3 is deliberately narrower: every
    evidence reference is a response-local E-id, and a link exists only when
    the normalized observation is eligible for its reasoning role.
    """
    aliases = _blackboard_artifact_evidence_ids(state)
    board = state.blackboard
    facts_method = getattr(board, "facts", None)
    try:
        facts = tuple(facts_method()) if callable(facts_method) else ()
    except Exception:  # noqa: BLE001 - v3 is additive, never fatal
        facts = ()

    facts_by_evidence: dict[str, object] = {}
    for fact in facts:
        evidence_id = aliases.get(str(getattr(fact, "fact_id", "")), "")
        if evidence_id and evidence_id not in facts_by_evidence:
            facts_by_evidence[evidence_id] = fact

    evidence_context = _evidence_context(state)
    evidence = [
        _public_v3_fact(evidence_id, fact, evidence_context)
        for evidence_id, fact in sorted(facts_by_evidence.items())
    ]
    ledger = state.investigation_context.get("hypothesis_ledger")
    ledger_items = (
        [item for item in ledger if isinstance(item, dict)] if isinstance(ledger, list) else []
    )
    eligibility_by_fact = _blackboard_eligibility(state)
    hypotheses: list[dict[str, Any]] = []
    rejected_links: list[dict[str, str]] = []
    known_ids = set(facts_by_evidence)
    for item in ledger_items:
        hypothesis_id = str(item.get("id") or "").strip()
        if not hypothesis_id:
            continue
        eligible_ids = {"support": [], "contradict": []}
        for evidence_field, role in (
            ("evidence_for", "support"),
            ("evidence_against", "contradict"),
        ):
            for evidence_id in _public_evidence_ids(item, evidence_field, aliases, known_ids):
                fact = facts_by_evidence.get(evidence_id)
                eligibility = eligibility_by_fact.get(str(getattr(fact, "fact_id", "")))
                if eligibility is not None and eligibility.permits(role):
                    eligible_ids[role].append(evidence_id)
                else:
                    rejected_links.append(
                        {
                            "hypothesis_id": hypothesis_id,
                            "evidence_id": evidence_id,
                            "role": role,
                            "reason": str(getattr(eligibility, "reason", "ineligible observation")),
                        }
                    )
        hypotheses.append(
            _public_v3_hypothesis(
                item,
                evidence_for=eligible_ids["support"],
                evidence_against=eligible_ids["contradict"],
                facts_by_evidence=facts_by_evidence,
            )
        )

    assessments = _probe_assessments(state.results)
    executions: list[dict[str, Any]] = []
    for assessment in assessments:
        execution_id = str(assessment.get("execution_id") or "").strip()
        template_id = str(assessment.get("template_id") or "").strip()
        verdict = str(assessment.get("verdict") or "").strip()
        role = "support" if verdict == "supports" else "contradict" if verdict == "refutes" else ""
        hypothesis_ids = [
            str(value) for value in assessment.get("hypothesis_ids") or []
            if str(value).strip() in {item["hypothesis_id"] for item in hypotheses}
        ]
        evidence_ids = [
            str(value) for value in assessment.get("evidence_ids") or []
            if str(value).strip() in known_ids
        ]
        if not (execution_id and template_id):
            continue
        eligible_evidence: list[str] = []
        for evidence_id in evidence_ids:
            fact = facts_by_evidence.get(evidence_id)
            eligibility = eligibility_by_fact.get(str(getattr(fact, "fact_id", "")))
            if not role or (eligibility is not None and eligibility.permits(role)):
                eligible_evidence.append(evidence_id)
                continue
            for hypothesis_id in hypothesis_ids:
                rejected_links.append(
                    {
                        "hypothesis_id": hypothesis_id,
                        "execution_id": execution_id,
                        "evidence_id": evidence_id,
                        "role": role,
                        "reason": str(getattr(eligibility, "reason", "ineligible observation")),
                    }
                )
        executions.append(
            {
                "execution_id": execution_id,
                "template_id": template_id,
                "tool": str(assessment.get("tool") or ""),
                "verdict": verdict,
                "executed_at": str(assessment.get("executed_at") or ""),
                "hypothesis_ids": list(dict.fromkeys(hypothesis_ids)),
                "evidence_ids": list(dict.fromkeys(eligible_evidence)),
            }
        )

    return {
        "schema_version": 3,
        "hypotheses": hypotheses,
        "evidence": evidence,
        "probe_executions": _dedupe_v3_records(executions),
        "rejected_evidence_links": _dedupe_v3_records(rejected_links),
        "stop_reason": _v3_stop_reason(state),
    }


def _public_v3_fact(
    evidence_id: str, fact: object, evidence_context: dict[str, object]
) -> dict[str, Any]:
    from app.services.evidence_blackboard import temporal_relation_to_incident

    observed_start = str(getattr(fact, "observed_window_start", "") or "")
    observed_end = str(getattr(fact, "observed_window_end", "") or "")
    return {
        "evidence_id": evidence_id,
        "observation_window": {
            "start": observed_start,
            "end": observed_end,
        },
        # Evidence observed after an alert can corroborate a condition, but is
        # not silently presented as temporally preceding its symptom.
        "temporal_relation": temporal_relation_to_incident(
            observed_start,
            observed_end,
            str(evidence_context.get("window_start") or ""),
            str(evidence_context.get("window_end") or ""),
        ),
        "entity": str(getattr(fact, "entity", "") or ""),
        "source": str(getattr(fact, "source", "") or ""),
        "source_group": str(
            getattr(fact, "source_group", "") or getattr(fact, "independence_group", "") or ""
        ),
        "predicate": str(getattr(fact, "predicate", "") or ""),
        "polarity": str(getattr(fact, "polarity", "unknown") or "unknown"),
        "coverage": str(getattr(fact, "coverage", "unknown") or "unknown"),
        "quality": str(getattr(fact, "quality", "") or ""),
    }


def _public_v3_hypothesis(
    item: dict[str, Any],
    *,
    evidence_for: list[str],
    evidence_against: list[str],
    facts_by_evidence: dict[str, object],
) -> dict[str, Any]:
    def groups(evidence_ids: list[str]) -> list[str]:
        return sorted(
            {
                str(
                    getattr(facts_by_evidence.get(evidence_id), "source_group", "")
                    or getattr(facts_by_evidence.get(evidence_id), "independence_group", "")
                    or "unknown"
                )
                for evidence_id in evidence_ids
            }
        )

    return {
        "hypothesis_id": str(item.get("id") or ""),
        "family": str(item.get("family") or ""),
        "mechanism": str(item.get("mechanism") or item.get("statement") or ""),
        "status": str(item.get("status") or "uncertain"),
        "confidence": item.get("confidence"),
        "evidence_for": list(dict.fromkeys(evidence_for)),
        "evidence_against": list(dict.fromkeys(evidence_against)),
        "supporting_source_groups": groups(evidence_for),
        "contradicting_source_groups": groups(evidence_against),
    }


def _public_evidence_ids(
    item: dict[str, Any], field: str, aliases: dict[str, str], known_ids: set[str]
) -> list[str]:
    values = list(item.get(field) or [])
    derived_key = (
        "support_evidence_ids" if field == "evidence_for" else "contradiction_evidence_ids"
    )
    values.extend(item.get(derived_key) or [])
    ids: list[str] = []
    for value in values:
        text = str(value)
        ids.extend(
            aliases[match.group(0)]
            for match in re.finditer(r"(?<![A-Za-z0-9_-])F-[0-9a-f]{12,64}(?![A-Za-z0-9_-])", text)
            if match.group(0) in aliases
        )
        ids.extend(
            match.group(0)
            for match in re.finditer(r"(?<![A-Za-z0-9_-])E\d+(?![A-Za-z0-9_-])", text)
            if match.group(0) in known_ids
        )
    return list(dict.fromkeys(ids))


def _dedupe_v3_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for item in records:
        unique[json.dumps(item, sort_keys=True, separators=(",", ":"))] = item
    return list(unique.values())


def _v3_stop_reason(state: PipelineState) -> str:
    v2 = state.investigation_context.get("reasoning_trace_v2")
    if not isinstance(v2, dict):
        return "base_evidence_complete"
    return str(v2.get("stop_reason") or "base_evidence_complete")


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
    if not _has_scoped_change_observation(change):
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


def _has_scoped_change_observation(change: CollectorResult) -> bool:
    """Require a bounded change artifact before using rollout as an RCA trigger."""
    for artifact in change.artifacts:
        if getattr(artifact, "type", "") != "change_detection":
            continue
        result = getattr(artifact, "result", None)
        observation = result.get("observation") if isinstance(result, dict) else None
        if not isinstance(observation, dict):
            continue
        if (
            str(observation.get("polarity") or "").lower() == "present"
            and str(observation.get("coverage") or "").lower() == "scoped"
        ):
            return True
    return False


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
    eligible_support_ids = _eligible_support_ids_for_output(state)
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
        eligible_evidence_ids=eligible_support_ids,
    )
    # Signature-first headline: the keyword ranker only decides when NOTHING
    # specific matched. A specific signature — an NVIDIA XID (dispositive), a
    # known-issue signature, or a curated symptom keyword — names the cause
    # family directly; the ranker chronically mis-headlined these (e.g.
    # node_kubelet_pressure winning on "DiskPressure"/"kubelet" words present in
    # the k8s node-conditions text even when every condition is False).
    state.observed = _observed_text(
        state.results, request, eligible_support_ids=eligible_support_ids
    )
    state.xid_codes = _xid_codes_from_results(
        state.results,
        _alert_text(request),
        eligible_support_ids=eligible_support_ids,
    )
    # TypeDB is the runtime source of truth. The version-controlled YAML matcher
    # remains only for deployments where the graph is disabled/unavailable.
    state.failure_modes = (
        state.kg_context.knowledge
        or load_failure_modes(settings.failure_modes_file)
    )
    state.known_issues = load_runai_known_issues(settings.runai_known_issues_file)
    # Version-aware precision: drop known issues already fixed in the cluster's
    # running Run:ai version so we don't attribute a symptom to a patched bug.
    state.known_issues = _suppress_fixed_known_issues(
        state.known_issues, _runai_version_from(state.results)
    )
    # TypeDB only sees approved historical incidents. It can corroborate a
    # symptom already observed live, but never supplies evidence by itself.
    symptom_names = [
        str(symptom.get("symptom") or "")
        for _family, symptom in match_failure_mode_symptoms(state.failure_modes, state.observed)
        if isinstance(symptom, dict)
    ]
    if state.target.alert_name:
        symptom_names.append(state.target.alert_name)
    try:
        from app.services.kg_enrichment import candidate_families_for_symptoms

        graph_counts, graph_warnings = await candidate_families_for_symptoms(
            settings, symptom_names
        )
    except Exception:  # noqa: BLE001 - graph prior is optional
        graph_counts, graph_warnings = {}, []
    if graph_warnings:
        state.extra_warnings.extend(graph_warnings)
    if graph_counts:
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
            graph_candidate_counts=graph_counts,
            eligible_evidence_ids=eligible_support_ids,
        )
        if isinstance(getattr(state.kg_context, "reasoning", None), dict):
            state.kg_context.reasoning["candidate_families"] = graph_counts
    # External support-case priors: exact error-signature match against the run's
    # observed evidence (available only post-collection, so this cannot run at plan
    # time). Labelled historical context for synthesis only — never a ranking input
    # and never presented as a verified resolution (see synthesis prompt rule).
    try:
        from app.services.kg_enrichment import external_case_cards

        ext_cards, ext_warnings = await external_case_cards(settings, state.observed)
    except Exception:  # noqa: BLE001 - external prior is optional
        ext_cards, ext_warnings = [], []
    state.extra_warnings.extend(ext_warnings)
    if ext_cards and state.kg_context is not None:
        seen = {str(c.get("case_id") or "") for c in state.kg_context.case_cards}
        state.kg_context.case_cards.extend(
            c for c in ext_cards if str(c.get("case_id") or "") not in seen
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
    open_world = _merge_open_world_candidates(state, state.root_cause_candidates)
    # Shadow and assist expose evidence-gated novel reasoning in context without
    # changing the headline.  Only authoritative mode may replace the final RCA.
    if getattr(settings, "open_world_rca_mode", "off") == "authoritative":
        state.root_cause_candidates = open_world
    if state.root_cause_candidates:
        top = state.root_cause_candidates[0]
        # A shadow/assist candidate is explicitly not the approved diagnosis.
        # Persist a mechanism only when the final headline is itself the
        # evidence-gated open-world candidate.
        _record_selected_open_world_hypothesis(state)
        _record_selected_hypothesis_id(state)
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


def _merge_open_world_candidates(
    state: PipelineState, known_candidates: list[RankedCause]
) -> list[RankedCause]:
    """Merge evidence-gated novel candidates for both initial and follow-up ranks."""
    _prepare_open_world_ledger(state)
    merged = merge_open_world_candidates(
        known_candidates,
        state.investigation_context.get("hypothesis_ledger"),
        fact_groups=_blackboard_fact_groups(
            state.blackboard,
            _blackboard_artifact_evidence_ids(state),
            eligibility_by_fact=_blackboard_eligibility(state),
        ),
        enabled=getattr(state.settings, "open_world_rca_mode", "off") != "off",
    )
    state.open_world_candidates = [
        candidate for candidate in merged if candidate.novelty == "open_world"
    ]
    return merged


def _refresh_public_reasoning_trace(state: PipelineState) -> None:
    """Refresh v2 and v3 public traces after response-local IDs are assigned."""
    trace = state.investigation_context.get("reasoning_trace_v2")
    if isinstance(trace, dict):
        state.investigation_context["reasoning_trace_v2"] = _public_reasoning_trace(
            trace, state
        )
    state.investigation_context["reasoning_trace_v3"] = _public_reasoning_trace_v3(state)


def _record_selected_open_world_hypothesis(state: PipelineState) -> None:
    """Persist a mechanism only if the open-world candidate is the headline."""
    trace = state.investigation_context.get("reasoning_trace_v2")
    if not state.root_cause_candidates or not isinstance(trace, dict):
        return
    top = state.root_cause_candidates[0]
    if top.novelty != "open_world" or not top.mechanism:
        return
    trace["selected_hypothesis"] = {
        "hypothesis_id": top.hypothesis_id,
        "mechanism": top.mechanism,
        "mechanism_fingerprint": top.mechanism_fingerprint,
        "family": top.family,
        "supporting_evidence_ids": top.support_evidence_ids,
        "contradicting_evidence_ids": top.contradiction_evidence_ids,
    }


def _record_selected_hypothesis_id(state: PipelineState) -> None:
    """Publish a final selection only from a candidate's exact hypothesis ID.

    Catalog candidates normally have no hypothesis ID.  In that case—and when
    a stale candidate ID is not present in the public trace—we deliberately
    omit the field rather than guessing from the family name.
    """
    trace = state.investigation_context.get("reasoning_trace_v3")
    if not isinstance(trace, dict):
        return
    trace.pop("selected_hypothesis_id", None)
    if not state.root_cause_candidates:
        return
    hypothesis_id = str(getattr(state.root_cause_candidates[0], "hypothesis_id", "") or "").strip()
    hypotheses = trace.get("hypotheses")
    known = {
        str(item.get("hypothesis_id") or "")
        for item in hypotheses
        if isinstance(item, dict)
    } if isinstance(hypotheses, list) else set()
    if hypothesis_id and hypothesis_id in known:
        trace["selected_hypothesis_id"] = hypothesis_id


def _prepare_open_world_ledger(state: PipelineState) -> None:
    ledger = state.investigation_context.get("hypothesis_ledger")
    if not isinstance(ledger, list):
        return
    aliases = _blackboard_artifact_evidence_ids(state)
    known = set(aliases.values())
    for item in ledger:
        if not isinstance(item, dict):
            continue
        for source_key, target_key in (
            ("evidence_for", "support_evidence_ids"),
            ("evidence_against", "contradiction_evidence_ids"),
        ):
            references = item.get(source_key)
            if not isinstance(references, list):
                continue
            ids = [
                match.group(0)
                for value in references
                for match in re.finditer(r"F-[0-9a-f]{12,64}", str(value))
                if aliases.get(match.group(0)) in known
            ]
            if ids:
                item[target_key] = list(dict.fromkeys(aliases[fact_id] for fact_id in ids))


def _evidence_context(state: PipelineState) -> dict[str, object]:
    target = state.target
    alert_entities = (
        [f"alert:{_alert_evidence_identity(state.request, target)}"]
        if any(result.agent == "alert" for result in state.results)
        else []
    )
    entities = tuple(
        dict.fromkeys(
            [
                f"{field}:{value}"
                for field in (
                    "pod",
                    "node",
                    "workload_name",
                    "runai_workload_id",
                    "project",
                    "queue",
                    "namespace",
                    "storage_claim",
                    "service",
                )
                if (value := str(getattr(target, field, "") or "").strip())
            ]
            + alert_entities
        )
    )
    topology = tuple(
        f"{field}:{value}"
        for field in ("cluster", "project", "queue", "namespace", "node", "component")
        if (value := str(getattr(target, field, "") or "").strip())
    )
    # Collection deliberately includes a five-minute prelude (to catch the
    # trigger that led to the alert) and, for firing alerts, a bounded 15-minute
    # forward interval.  The post-resolution collection epilogue is useful for
    # confirming recovery, but it must not establish the cause of an incident
    # that has already ended.  Keep the causal eligibility window aligned with
    # that policy instead of collapsing every firing alert to its exact fired
    # instant, which discarded all bounded post-fire observations.
    causal_window = causal_evidence_time_range(target) or {}
    return {
        "run_id": str(state.request.incident_id or ""),
        "window_start": str(causal_window.get("start") or ""),
        "window_end": str(causal_window.get("end") or ""),
        "entities": entities,
        "topology": topology,
    }


def _blackboard_eligibility(state: PipelineState) -> dict[str, object]:
    """One central context-aware eligibility verdict for all consumers."""
    from app.services.evidence_blackboard import EvidenceEligibility

    facts = getattr(state.blackboard, "facts", None)
    if not callable(facts):
        return {}
    try:
        context = _evidence_context(state)
        return {
            str(fact.fact_id): EvidenceEligibility.from_fact(fact, context=context)
            for fact in facts()
            if getattr(fact, "fact_id", "")
        }
    except Exception:  # noqa: BLE001 - malformed facts are never eligible
        return {}


def _public_evidence_eligibility(state: PipelineState) -> dict[str, object]:
    aliases = _blackboard_artifact_evidence_ids(state)
    return {
        evidence_id: eligibility
        for fact_id, eligibility in _blackboard_eligibility(state).items()
        if (evidence_id := aliases.get(fact_id))
    }


def _eligible_support_ids_for_output(state: PipelineState) -> set[str]:
    """Return only response artifacts that may substantiate the final report.

    The deterministic report and the Korean synthesis must share the exact
    target/window gate used by the harness.  Otherwise a typed but unrelated
    artifact can appear under the report's root-cause evidence even though it
    cannot be cited by the approved RCA claim.
    """
    return {
        evidence_id
        for evidence_id, eligibility in _public_evidence_eligibility(state).items()
        if callable(getattr(eligibility, "permits", None)) and eligibility.permits("support")
    }


def _blackboard_fact_groups(
    blackboard: Any,
    aliases: dict[str, str] | None = None,
    *,
    eligibility_by_fact: dict[str, object] | None = None,
) -> dict[str, str]:
    facts = getattr(blackboard, "facts", None)
    if not callable(facts):
        return {}
    try:
        aliases = aliases or {}
        return {
            aliases.get(str(fact.fact_id), str(fact.fact_id)): str(fact.independence_group)
            for fact in facts()
            if getattr(fact, "fact_id", "")
            # Open-world promotion is fail-closed: no eligibility verdict (for
            # example because a malformed fact could not be normalized) is not
            # evidence provenance.  Only an explicit scoped-positive verdict
            # may contribute an independent source group.
            and bool(getattr((eligibility_by_fact or {}).get(str(fact.fact_id)), "support", False))
        }
    except Exception:  # noqa: BLE001 - blackboard remains an optional enhancement
        return {}


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
            self_check_kwargs: dict[str, object] = {"plan": state.investigation_context}
            # Keep optional integrations/test doubles that predate the
            # blackboard contract working while the production implementation
            # receives the strict target/window verdicts.
            if _accepts_keyword(refute_top_cause, "evidence_eligibility"):
                self_check_kwargs["evidence_eligibility"] = _public_evidence_eligibility(state)
            check = await refute_top_cause(
                state.settings,
                state.root_cause_candidates[0],
                state.results,
                **self_check_kwargs,
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
    eligible_support_ids = _eligible_support_ids_for_output(state)
    state.warnings = sorted(set(state.warnings) | set(state.graph_fixes.warnings))
    # Optional change/timeline capability — added to the synthesis context.
    try:
        from app.services.timeline import build_timeline
    except ImportError:
        pass
    else:
        state.timeline = build_timeline(state.results)
    diagnostic_tree, diagnostic_source = resolve_tree(
        getattr(state.kg_context, "diagnostic_tree", {}), settings.failure_modes_file
    )
    state.troubleshooting_path = walk_tree(
        diagnostic_tree,
        _observed_text(
            state.results, request, eligible_support_ids=eligible_support_ids
        ),
    )
    if state.troubleshooting_path.get("path"):
        state.troubleshooting_path["source"] = diagnostic_source
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
            verify_known_kwargs: dict[str, object] = {}
            if _accepts_keyword(verify_known_issues, "declared_alert"):
                verify_known_kwargs["declared_alert"] = _alert_text(request)
            refuted = await verify_known_issues(
                settings,
                ki_matches,
                state.results,
                **verify_known_kwargs,
            )
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
            verify_match_kwargs: dict[str, object] = {
                "subject": "matched symptom or GPU XID"
            }
            if _accepts_keyword(verify_matches, "declared_alert"):
                verify_match_kwargs["declared_alert"] = _alert_text(request)
            refuted = await verify_matches(
                settings,
                ev_candidates,
                state.results,
                **verify_match_kwargs,
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
                        state.graph_fixes.xid_triggers.pop(code, None)
                        state.graph_fixes.root_xids.pop(code, None)
    state.summary = _summary_from(
        request,
        state.results,
        state.root_cause_candidates,
        state.failure_modes,
        language=getattr(settings, "language", "en"),
    )
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
        eligible_support_ids=eligible_support_ids,
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
                self_check_caveat=state.self_check_caveat,
                self_check_refuted=state.self_check_refuted,
                self_check_next=state.self_check_next,
                reanalysis_note=state.reanalysis_note,
                # v2 retains the investigator's free-form F-* ledger for
                # compatibility.  Synthesis must use the eligibility-filtered,
                # response-local E-id graph only.
                reasoning_trace=state.investigation_context.get("reasoning_trace_v3"),
                evidence_eligibility=_public_evidence_eligibility(state),
            )
        if synth:
            state.summary, state.detail = synth
        elif llm_configured(settings, getattr(settings, "llm_model_insight", "")):
            state.warnings.append(
                "한국어 LLM 종합이 유효한 보고서를 반환하지 않아 "
                "결정론적 fallback 보고서를 사용했습니다."
            )
            # Synthesis fell back to the deterministic report, which splices the
            # curated KB playbook in verbatim ENGLISH — translate that one
            # section so the operator guidance still reads in their language.
            state.detail = await _translate_playbook_ko(settings, state.detail)

    # A Korean synthesis can replace the deterministic detail wholesale. Restore
    # the explicitly non-diagnostic guide when the RCA had no supported action.
    if _needs_general_guidance(state.root_cause_candidates, eligible_support_ids):
        heading = _general_guidance_heading(getattr(settings, "language", "en"))
        if heading not in state.detail:
            block = "\n".join(
                [
                    heading,
                    "",
                    *general_guidance_lines(
                        _alert_text(request),
                        state.failure_modes,
                        state.known_issues,
                        language=getattr(settings, "language", "en"),
                        masker=state.masker,
                    ),
                ]
            )
            state.detail = _append_general_guidance(state.detail, block)

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
            "knowledge_base": state.kg_context.public_dict(),
            "ontology_reasoning": state.kg_context.as_dict().get("reasoning", {}),
            "plan": plan.as_dict(),
            "hypothesis_ledger": state.investigation_context.get("hypothesis_ledger"),
            "investigation": state.investigation_context,
            "reasoning_trace_v2": state.investigation_context.get("reasoning_trace_v2", {}),
            "reasoning_trace_v3": state.investigation_context.get("reasoning_trace_v3", {}),
            "open_world_candidates": [
                candidate.as_dict() for candidate in state.open_world_candidates
            ],
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


async def harness_stage(state: PipelineState) -> PipelineState:
    """Validate the already-synthesized RCA and make bounded safe repairs."""
    from app.services.critic import (
        CriticResult,
        apply_safe_patches,
        critique_claims,
    )
    from app.services.harness import (
        abstain,
        analysis_hash,
        apply_confidence_downgrade,
        apply_safety_guardrail,
        apply_trace,
        evaluate,
        payload,
    )

    response = state.response
    assert response is not None
    if not state.settings.enable_rca_output_harness:
        response.context["harness"] = {
            "rubric_version": "1",
            "status": "disabled",
            "repair_attempts": 0,
        }
        response.context["analysis_hash"] = analysis_hash(response)
        return state

    repairs = 0
    verdict = evaluate(
        response,
        state.results,
        state.root_cause_candidates,
        next_check=state.self_check_next,
        evidence_eligibility=_public_evidence_eligibility(state),
    )
    evidence_ids = [
        str(getattr(artifact, "evidence_id", ""))
        for artifact in state.artifacts
        if getattr(artifact, "evidence_id", "")
    ]
    critic = critique_claims(verdict.claims, available_evidence_ids=evidence_ids)
    llm_critic = await _semantic_critic(
        state.settings,
        verdict.claims,
        available_evidence_ids=evidence_ids,
    )
    if not llm_critic.is_noop:
        critic = CriticResult(
            issues=(*critic.issues, *llm_critic.issues),
            patches=(*critic.patches, *llm_critic.patches),
            status="issues",
        )
    patched_claims = apply_safe_patches(verdict.claims, critic)
    for claim in patched_claims:
        if claim.get("claim_id") == "C01" and claim.get("confidence") == "medium":
            apply_confidence_downgrade(state.root_cause_candidates)
    for _ in range(state.settings.max_rca_repair_attempts):
        if not verdict.failed_gates and verdict.score >= state.settings.rca_harness_pass_score:
            break
        changed = False
        if verdict.gates["missing_evidence_trace"]:
            changed = apply_trace(response, verdict) or changed
        if verdict.gates["unsafe_action_without_guardrail"]:
            changed = apply_safety_guardrail(response) or changed
        if verdict.gates["unsupported_high_confidence"]:
            changed = apply_confidence_downgrade(state.root_cause_candidates) or changed
        if not changed:
            break
        repairs += 1
        verdict = evaluate(
            response,
            state.results,
            state.root_cause_candidates,
            next_check=state.self_check_next,
            evidence_eligibility=_public_evidence_eligibility(state),
        )

    status = "pass"
    if verdict.failed_gates:
        abstain(
            response,
            state.root_cause_candidates,
            verdict,
            historical_reanalysis=_is_resolved_reanalysis(state.request),
        )
        verdict = evaluate(
            response,
            state.results,
            state.root_cause_candidates,
            next_check=state.self_check_next,
            evidence_eligibility=_public_evidence_eligibility(state),
        )
        status = "abstained"
    elif verdict.score < state.settings.rca_harness_pass_score:
        response.analysis_quality = "degraded"
        response.warnings = sorted(
            set(response.warnings) | {"RCA harness quality score below threshold"}
        )
        status = "degraded"

    top = state.root_cause_candidates[0] if state.root_cause_candidates else None
    response.root_cause_family = top.family if top else ""
    response.context["root_cause_candidates"] = [
        candidate.as_dict() for candidate in state.root_cause_candidates
    ]
    response.context["top_root_cause"] = top.as_dict() if top else None
    response.context["harness"] = payload(verdict, status=status, repairs=repairs)
    response.context["harness"]["critic"] = critic.as_dict()
    response.context["analysis_hash"] = analysis_hash(response)
    response.analysis = response.analysis_detail
    state.response = response
    return state


async def _semantic_critic(
    settings: Settings,
    claims: list[dict[str, Any]],
    *,
    available_evidence_ids: list[str],
):
    """Ask an optional critic for whitelist-only claim patches.

    The critic never sees raw credentials or tool output and its response is
    parsed by ``parse_critic_result``; it can only downgrade confidence or mark
    a claim inferred, never manufacture an RCA or remediation.
    """
    from app.services.critic import CriticResult, parse_critic_result

    # Stage-model overrides conventionally fall back to LLM_MODEL. Leaving
    # LLM_MODEL_CRITIC empty must not silently disable the semantic critic.
    model = str(getattr(settings, "llm_model_critic", "") or "").strip() or settings.llm_model
    if not llm_configured(settings, model):
        return CriticResult()
    try:
        raw = await complete_json(
            settings,
            system=(
                "You are a skeptical RCA claim critic. Inspect only evidence IDs and claim links. "
                "Return JSON with optional issues and patches. Allowed patches are exclusively "
                "downgrade_confidence to low/medium or mark_inferred to inferred. Never add "
                "evidence, actions, mechanisms, or prose."
            ),
            user=json.dumps(
                {"claims": claims, "available_evidence_ids": available_evidence_ids},
                ensure_ascii=False,
            ),
            model=model,
        )
    except Exception:  # noqa: BLE001 - critic is advisory, hard gates remain local
        return CriticResult()
    return parse_critic_result(
        raw,
        claim_ids=[str(claim.get("claim_id") or "") for claim in claims],
        available_evidence_ids=available_evidence_ids,
    )


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

    state.progress.emit("synthesize", "Synthesizing final RCA")
    state = await stages.get("synthesize", synthesize_stage)(state)
    state.progress.emit("synthesize", "Synthesis complete")
    state.progress.emit("harness", "Validating synthesized RCA")
    state = await stages.get("harness", harness_stage)(state)
    assert state.response is not None
    harness = state.response.context.get("harness")
    harness_status = (
        str(harness.get("status") or "complete")
        if isinstance(harness, dict)
        else "complete"
    )
    state.progress.emit(
        "harness",
        "Validation complete",
        status=harness_status,
    )
    flush = getattr(state.progress, "flush", None)
    if callable(flush):
        await flush()
    return state.response


async def _investigate_until_settled(state: PipelineState) -> None:
    if not (
        state.root_cause_candidates
        and llm_configured(state.settings, state.settings.llm_model_investigation)
        and state.settings.enable_investigation_loop
    ):
        return
    attempted: set[str] = set()
    # Re-analysis gets at most three reasoning passes by default. Each pass can
    # batch many read-only queries, so this bounds repeated candidate churn
    # without narrowing evidence collection.
    reanalysis_round_limit = state.settings.max_reanalysis_steps or 3
    for _round in range(reanalysis_round_limit):
        if not _needs_more_investigation(state):
            break
        if _evidence_budget_exceeded(state):
            _record_evidence_budget_stop(state, "additional investigation iterations")
            _aggregate_evidence(state)
            break

        target = _next_reanalysis_target(state, attempted)
        if target is None:
            break
        state.progress.emit(
            "investigation",
            "Running targeted follow-up before synthesis",
            step=_round + 1,
            selected_hypothesis=target.family,
            reason=target.reason,
        )
        before_evidence = _evidence_signature(state.results)
        before_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        attempted.add(target.family)
        outcome = await _reanalyze_once(state, target=target)
        if outcome is None:
            break

        state.results = outcome.results
        # Keep the latest hypothesis/evidence ledger.  Previously re-analysis
        # ranked its fresh evidence but discarded the ledger that explained it,
        # so a valid open-world hypothesis could neither cite evidence nor
        # participate in the final headline.
        state.investigation_context = outcome.investigation_context
        state.root_cause_candidates = outcome.candidates
        state.self_check_caveat = outcome.caveat
        state.reanalysis_note = "\n\n".join(
            note for note in (state.reanalysis_note, outcome.note) if note
        )
        state.self_check_refuted = outcome.refuted
        state.self_check_next = outcome.next_check
        _aggregate_evidence(state)
        _refresh_public_reasoning_trace(state)
        open_world = _merge_open_world_candidates(state, state.root_cause_candidates)
        if getattr(state.settings, "open_world_rca_mode", "off") == "authoritative":
            state.root_cause_candidates = open_world
        _record_selected_open_world_hypothesis(state)
        _record_selected_hypothesis_id(state)

        after_family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        if after_family == before_family and _evidence_signature(state.results) == before_evidence:
            break
    else:
        if _needs_more_investigation(state):
            state.extra_warnings.append(
                f"re-analysis stopped after {reanalysis_round_limit} reasoning rounds"
            )


def _needs_more_investigation(state: PipelineState) -> bool:
    if not state.root_cause_candidates:
        return False
    top = state.root_cause_candidates[0]
    return (
        state.self_check_refuted
        or top.family == "insufficient_evidence"
        or top.confidence not in {"medium", "high"}
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
        eligible_support_ids = _eligible_support_ids_for_output(state)
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
            eligible_evidence_ids=eligible_support_ids,
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
                _json_fingerprint(
                    {
                        key: value
                        for key, value in result.details.items()
                        if key != "probe_results"
                    }
                    if isinstance(result.details, dict)
                    else result.details
                ),
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


def _fresh_results_support_family(
    family: str,
    fresh_results: list[CollectorResult],
    evidence_eligibility: Mapping[str, object],
) -> bool:
    """Whether this pass added eligible semantic support for a refuted family.

    A prior self-check is a reason to seek an alternative, not a permanent ban.
    Direct, target/window-scoped evidence found by the follow-up pass may
    rehabilitate the family; compatibility summaries and ineligible cards may
    not.
    """
    for result in fresh_results:
        for artifact in result.artifacts:
            evidence_id = str(getattr(artifact, "evidence_id", "") or "")
            eligibility = evidence_eligibility.get(evidence_id)
            permits = getattr(eligibility, "permits", None)
            if not callable(permits) or not permits("support"):
                continue
            if artifact_supports_family(family, artifact):
                return True
    return False


async def _reanalyze_once(
    state: PipelineState,
    *,
    target: _ReanalysisTarget,
) -> _ReanalysisOutcome | None:
    """One bounded targeted investigation pass. Never re-enters analyze()."""
    try:
        from app.services.investigator import _merge_collector_results, investigate
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
        investigation_kwargs: dict[str, Any] = {"reporter": state.progress}
        if (
            getattr(state.settings, "open_world_rca_mode", "off") != "off"
            and _accepts_keyword(investigate, "blackboard")
        ):
            investigation_kwargs["blackboard"] = state.blackboard
        if _accepts_keyword(investigate, "deadline_monotonic"):
            investigation_kwargs["deadline_monotonic"] = _evidence_deadline_monotonic(state)
        fresh, re_context = await investigate(
            state.settings,
            state.target,
            state.collectors,
            replan,
            kg_dict,
            min(state.settings.max_reanalysis_steps, state.settings.max_investigation_steps),
            **investigation_kwargs,
        )
        merged = {result.agent: result for result in state.results}
        for result in fresh:
            merged[result.agent] = _merge_collector_results(
                merged.get(result.agent), result
            )
        merged_results = list(merged.values())

        # Re-analysis returns fresh artifacts after the initial evidence-stage
        # aggregation.  Give them response-local IDs and normalize them onto
        # the same board before re-ranking; otherwise an out-of-window fresh
        # card could influence this one path only because its eligibility map
        # did not exist yet.
        from app.services.harness import assign_evidence_ids

        assign_evidence_ids(merged_results)
        seed = getattr(state.blackboard, "seed_results", None)
        if callable(seed):
            causal_window = causal_evidence_time_range(state.target) or {}
            seed(
                merged_results,
                entity=_blackboard_target_entity(state.target),
                timestamp=str(getattr(state.target, "fired_at", "") or ""),
                observed_window_start=str(causal_window.get("start") or ""),
                observed_window_end=str(causal_window.get("end") or ""),
            )
        previous_results = state.results
        state.results = merged_results
        try:
            eligible_support_ids = _eligible_support_ids_for_output(state)
            evidence_eligibility = _public_evidence_eligibility(state)
        finally:
            state.results = previous_results

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
            eligible_evidence_ids=eligible_support_ids,
        )
        # The signature-first rule applies to the RE-rank too. Without it the
        # raw keyword ranker decided alone here — the 2026-07-08 re-analysis
        # "concluded" node_kubelet_pressure on a healthy node while the loki
        # reconcile errors still carried the real (signature-backed) cause.
        observed = _observed_text(
            merged_results,
            state.request,
            eligible_support_ids=eligible_support_ids,
        )
        candidates = _promote_signature_cause(
            candidates,
            _xid_codes_from_results(
                merged_results,
                _alert_text(state.request),
                eligible_support_ids=eligible_support_ids,
            ),
            match_runai_known_issues(state.known_issues, observed),
            _gate_lifecycle_symptoms(
                match_failure_mode_symptoms(state.failure_modes, observed), lifecycle
            ),
        )
        if target.refuted_family and not _fresh_results_support_family(
            target.refuted_family,
            fresh,
            evidence_eligibility,
        ):
            alternatives = [
                candidate
                for candidate in candidates
                if candidate.family != target.refuted_family
            ]
            if alternatives:
                candidates = alternatives
        skip_self_check = _evidence_budget_exceeded(state)
        if skip_self_check:
            # The targeted probes already completed and were normalized/ranked.
            # Preserve that fresh evidence; only the optional LLM self-check is
            # skipped so final synthesis can use the last bounded observation.
            _record_evidence_budget_stop(state, "post-reanalysis self-check")
        caveat = ""
        refuted = False
        next_check = ""
        if candidates and not skip_self_check:
            self_check_kwargs: dict[str, object] = {"plan": re_context}
            if _accepts_keyword(refute_top_cause, "evidence_eligibility"):
                self_check_kwargs["evidence_eligibility"] = evidence_eligibility
            check = await refute_top_cause(
                state.settings,
                candidates[0],
                merged_results,
                **self_check_kwargs,
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
            merged_results,
            candidates,
            re_context if isinstance(re_context, dict) else {},
            caveat,
            note,
            refuted,
            next_check,
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
    reasoning_trace: object | None = None,
    evidence_eligibility: Mapping[str, object] | None = None,
    self_check_caveat: str = "",
    self_check_refuted: bool = False,
    self_check_next: str = "",
    reanalysis_note: str = "",
) -> tuple[str, str] | None:
    """LLM synthesis of the RCA report in Korean, grounded STRICTLY in the evidence.

    Returns (analysis_summary, analysis_detail) in Korean, or None on any failure so
    the caller keeps the deterministic English report. Never raises into analyze().
    """
    from app.collectors.http_json import compact

    eligible_support_ids = (
        {
            evidence_id
            for evidence_id, eligibility in (evidence_eligibility or {}).items()
            if callable(getattr(eligibility, "permits", None))
            and eligibility.permits("support")
        }
        if evidence_eligibility is not None
        else None
    )
    observed_text = _observed_text(
        results, request, eligible_support_ids=eligible_support_ids
    )
    has_scoped_support = _synthesis_has_scoped_support(evidence_eligibility)
    # The deterministic report receives the response-local eligibility set.  Do
    # the equivalent check before exposing graph fixes to the free-form Korean
    # synthesizer: graph edges and approved historical resolutions are useful
    # guidance, but cannot substantiate a remediation for this incident when
    # all current observations are context-only, unavailable, or out of scope.
    graph_remediation_context = (
        graph_fixes.as_dict()
        if has_scoped_support
        else {
            "family_fixes": [],
            "xid_fixes": {},
            "xid_triggers": {},
            "model_xids": {},
            "root_xids": {},
            "verified_actions": [],
            "warnings": [
                "Current incident has no target/window-scoped supporting observation; "
                "graph remediation is withheld until it is verified."
            ],
        }
    )
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
        if has_scoped_support and _similar_incident_relevant(request, observed_text)
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
            {
                "incident_state": (
                    "resolved — alert no longer firing; live state likely normal, so live "
                    "evidence may be limited (past-incident re-analysis)"
                )
            }
            if str(getattr(request.alert, "status", "")).lower() == "resolved"
            else {}
        ),
        # Chronological event chain (oldest first): recent deploy/rollout, node
        # reboot/condition, pod delete/create, warning events → the alert. Small +
        # high-value, so it leads the reasoning inputs and the char cap won't trim it.
        **({"timeline": (timeline or [])[-40:]} if timeline else {}),
        **(
            {"troubleshooting_path": troubleshooting_path}
            if has_scoped_support and troubleshooting_path and troubleshooting_path.get("path")
            else {}
        ),
        "plan": _synthesis_plan_context(plan, allow_remediation=has_scoped_support),
        "ranked_root_cause_candidates": [c.as_dict() for c in root_cause_candidates],
        **(
            {
                "self_check": {
                    "refuted": self_check_refuted,
                    "caveat": self_check_caveat,
                    "next_check": self_check_next,
                    "reanalysis_note": reanalysis_note,
                }
            }
            if any((self_check_caveat, self_check_next, reanalysis_note))
            else {}
        ),
        **(
            {"reasoning_trace_v3": reasoning_trace}
            if isinstance(reasoning_trace, dict)
            and reasoning_trace.get("schema_version") == 3
            else {}
        ),
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents") if has_scoped_support else [],
            "historical_case_cards": (kg_context.get("case_cards") or [])
            if has_scoped_support
            else [],
            "knowledge": kg_context.get("knowledge") if has_scoped_support else {},
        },
        "graph_remediation": graph_remediation_context,
        "matched_alert": plan.matched_alert if has_scoped_support else None,
        "similar_incidents": similar_incidents,
        "remediation_evidence": {
            "scoped_support": has_scoped_support,
            "rule": (
                "Cause-specific remediation is allowed only with a current "
                "target/window-scoped supporting observation."
            ),
        },
        # Bulky — kept LAST so the char cap trims raw collector result tails
        # rather than the reasoning inputs above.
        "collector_findings": _synthesis_collector_findings(
            results, evidence_eligibility=evidence_eligibility
        ),
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
        "- collector_findings의 supporting_artifacts만 원인을 지지하는 직접 근거입니다. "
        "contradicting_artifacts는 결론을 반박하는 직접 근거이고, context_artifacts 및 "
        "collection_summary는 운영 맥락일 뿐 원인·반증 근거가 아닙니다.\n"
        "- collector_findings에 status=ok인 read-only 진단 결과가 이미 있으면 권장 조치에서 "
        "그 조회나 같은 명령을 다시 실행하라고 하지 마세요. 이미 확인된 결과를 요약하고, "
        "그 결과가 요구할 때에만 조건부 후속 조치를 제시하세요. context_artifact라는 이유만으로 "
        "완료된 조회를 미수행 점검으로 되돌리지 마세요.\n"
        "- self_check에 구체적인 로그 기반 오류가 있으면, 그 오류를 원인과 권장 조치의 첫 항목에 "
        "반영하세요. 이미 반증된 넓은 분류의 범용 플레이북(OOM, entrypoint, secret, probe)을 "
        "그 구체 오류보다 앞세우거나 나열하지 마세요.\n"
        "- MemoryPressure/DiskPressure/PIDPressure/NetworkUnavailable 같은 condition 이름은 "
        "존재 자체가 장애 증거가 아닙니다. artifact의 evidence_role=support 안의 "
        "condition_checks.active=true만 지지 증거이며, evidence_role=contradict 안의 "
        "active=false만 명시적 반대 증거입니다. 원문 result의 키워드만 보고 상태를 "
        "추정하지 마세요.\n"
        "- reasoning_trace_v3의 evidence는 상태·범위 검증을 통과한 공개 관측입니다. 원인·반증 "
        "주장을 쓸 때 해당 E-ID만 [E01] 형식으로 인용하세요. F-* 내부 ID를 출력하거나 "
        "rejected_evidence_links의 항목을 근거로 사용하지 마세요. historical prior는 현재 "
        "증거로 쓰지 마세요.\n"
        "- historical_case_cards는 승인된 과거 사례의 prior이며 현재 evidence가 아닙니다. "
        "유사 사례가 있어도 현재 관측으로 별도 확인될 때만 원인으로 사용하세요.\n"
        "- kind=external 또는 context_class(evaluation_only/mitigated_context/"
        "unresolved_context)가 붙은 카드는 외부 지원 사례입니다. 그 successful/failed_actions를 "
        "현재 사건의 검증된 해결책으로 제시하지 말고 '과거 외부 사례에서 시도된 조치'로만 "
        "인용하세요.\n"
        "- graph_remediation은 현재 support observation이 있을 때에만 조치 후보입니다. "
        "warnings에 현재 범위의 support가 없다고 표시되면 graph/과거 사례의 조치를 실행하라고 "
        "권고하지 말고, 먼저 대상·시간 범위에서 확인할 진단 단계만 제시하세요.\n"
        "- remediation_evidence.scoped_support=false이면 내장 alert, component, knowledge base, "
        "과거 사례, troubleshooting_path의 원인별 조치를 권고하지 마세요. 현재 범위에서 확인할 "
        "진단 단계와 누락된 증거만 제시하세요.\n"
        "- 특정 수집기가 아무것도 찾지 못했으면 '증거를 찾기 어렵습니다.'라고 명시하세요.\n"
        "- 증거에 incident_state가 resolved(과거 인시던트 재분석)면, 현재 상태가 정상이라 "
        "라이브 증거가 제한적일 수 있습니다. 증거가 얇으면 억지로 원인을 단정하지 말고 '현재는 "
        "정상 상태로 회복되어 라이브 수집·분석이 제한적입니다'를 명시한 뒤, 남은 흔적·과거 기록·"
        "타임라인 기반으로 신중히 설명하세요. ranked 후보가 있으면 관찰 사실과 분리하여 낮은 "
        "확신도의 잠정 가설로 제시할 수 있지만, 확정 원인이나 원인별 조치 근거로 승격하지 마세요.\n"
        "- timeline(시간순 이벤트)은 evidence_role을 반드시 지키세요. support인 항목만 원인·조치의 "
        "직접 근거가 될 수 있습니다. context 항목은 시간 순서 설명과 다음 점검 후보일 뿐이며, "
        "그 자체로 최근 변경·오류를 근본 원인이나 관찰 사실로 쓰면 안 됩니다. support timeline에 "
        "배포/rollout(generation 변경), 노드 리부트·컨디션 변화, 파드 삭제/드레인, MIG/설정 변경이 "
        "있을 때만 변경 → 결과 → 알림의 인과를 우선 검토하세요.\n"
        "- 증거에 troubleshooting_path가 있으면 그 steps를 사용해 진단 흐름을 단계별로 설명하세요. "
        "steps 안의 alternatives는 동시에 성립한 경쟁 가설이므로, 선택한 경로와 함께 무엇을 추가로 "
        "확인하면 반증되는지 설명하세요. principles와 conclusion.disconfirm이 있으면 성급한 확정을 "
        "막는 검증 규칙으로 적용하세요. "
        "단, troubleshooting_path의 conclusion은 보강 근거일 뿐이며 XID/known-issue 같은 정밀 "
        "signature 또는 ranked_root_cause_candidates의 1순위 원인을 절대 덮어쓰지 마세요.\n"
        "- 반드시 이 문서 구조를 따르세요 (Word 제출용이므로 헤딩/번호목록만 사용, 표·HTML 금지):\n"
        "  # 장애 분석 보고서 — {알림명}\n"
        "  발생/심각도/대상 메타 한 줄\n"
        "  ## 1. 문제 (Problem) — 무엇이/어디서/언제부터/어떤 영향, 3~4문장.\n"
        "  ## 2. 원인 (Root Cause) — 운영자가 AI 판단을 검증할 수 있게 다음 항목을 "
        "굵은 라벨로 명확히 구분해 쓰세요:\n"
        "    - **결론**: 한 문장 (근본 원인).\n"
        "    - **확신도**: 높음/중간/낮음 (analysis_quality와 근거의 양·일관성 기준) "
        "+ 한 줄 이유.\n"
        "    - **근거(Evidence)**: 직접 '관찰된 사실'만 2~4개 (수집기별: 무엇을 관찰, 언제부터). "
        "추론이 아니라 사실만.\n"
        "    - **추론(Inference)**: 위 근거가 왜 그 결론으로 이어지는지 논리 "
        "(시간 순서 인과 포함). "
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
    except Exception as exc:  # noqa: BLE001 - synthesis is best-effort
        _log.warning("korean synthesis call failed: %s", _masked_exception_text(exc))
        return None
    if not data:
        _log.warning("korean synthesis returned no valid JSON report; using deterministic fallback")
        return None
    summary = data.get("summary")
    detail = data.get("detail")
    if not isinstance(summary, str) or not summary.strip():
        _log.warning("korean synthesis JSON omitted summary; using deterministic fallback")
        return None
    if not isinstance(detail, str) or not detail.strip():
        _log.warning("korean synthesis JSON omitted detail; using deterministic fallback")
        return None
    conflict = _synthesis_semantic_conflict(
        summary,
        detail,
        request=request,
        results=results,
        evidence_eligibility=evidence_eligibility,
    )
    if conflict:
        _log.warning("korean synthesis rejected by semantic evidence guard: %s", conflict)
        return None
    return _short_sentence(summary, limit=280), detail.strip()


def _synthesis_has_scoped_support(evidence_eligibility: Mapping[str, object] | None) -> bool:
    """Whether the Korean synthesizer may receive graph remediation actions.

    ``None`` preserves direct/unit callers that do not have a blackboard.  In a
    pipeline run an empty/non-permitting map is an explicit safety verdict, not
    a reason to fall back to broad collector text or historical knowledge.
    """
    if evidence_eligibility is None:
        return True
    return any(
        callable(getattr(eligibility, "permits", None)) and eligibility.permits("support")
        for eligibility in evidence_eligibility.values()
    )


def _synthesis_plan_context(
    plan: InvestigationPlan, *, allow_remediation: bool
) -> dict[str, object]:
    """Project the plan for free-form synthesis without leaking dormant fixes.

    A plan can carry catalog actions and historical case cards so collectors know
    what to verify.  When every current artifact is context-only or out of
    scope, those fields must not become an indirect recommendation channel for
    the synthesis model.
    """
    context = plan.as_dict()
    if allow_remediation:
        return context
    matched = context.get("matched_alert")
    if isinstance(matched, dict):
        context["matched_alert"] = {
            key: value for key, value in matched.items() if key != "actions"
        }
    context["case_cards"] = []
    return context


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
            missing = [
                field
                for field in ("summary", "detail")
                if not isinstance(parsed.get(field), str) or not parsed[field].strip()
            ]
            if not missing:
                return parsed
            _log.warning(
                "korean synthesis JSON omitted required field(s) %s (attempt %d); retrying",
                ", ".join(missing),
                attempt + 1,
            )
            continue
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


def _synthesis_collector_findings(
    results: list[CollectorResult],
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Project artifacts into evidence roles before giving them to synthesis.

    This is intentionally stricter than a transport-success check. The LLM may
    see useful context, but it receives a machine-readable boundary that only
    a scoped observation can support or contradict the RCA.
    """
    findings: list[dict[str, object]] = []
    for result in results:
        grouped: dict[str, list[dict[str, object]]] = {
            "supporting_artifacts": [],
            "contradicting_artifacts": [],
            "context_artifacts": [],
        }
        for artifact in result.artifacts:
            if not _artifact_is_evidence(artifact):
                continue
            payload = _synthesis_artifact_payload(
                artifact, evidence_eligibility=evidence_eligibility
            )
            role = str(payload["evidence_role"])
            key = {
                "support": "supporting_artifacts",
                "contradict": "contradicting_artifacts",
            }.get(role, "context_artifacts")
            grouped[key].append(payload)
        findings.append(
            {
                "agent": result.agent,
                "status": result.status,
                "confidence": result.confidence,
                # A collector headline is operational context, never a direct
                # observation. Retain it without inviting the model to cite it.
                "collection_summary": (
                    result.summary if _collector_is_evidence(result) else NO_EVIDENCE
                ),
                **{
                    key: [
                        artifact for _index, artifact in sorted(
                            ([(len(artifacts) - 1, artifacts[-1])] if artifacts else []) + sorted(
                                enumerate(artifacts[:-1]),
                                key=lambda item: (
                                    bool(item[1].get("highlights")),
                                    item[1].get("status") == "ok",
                                    item[0],
                                ),
                                reverse=True,
                            )[:5]
                        )
                    ]
                    for key, artifacts in grouped.items()
                },
            }
        )
    return findings


def _synthesis_artifact_payload(
    artifact: object, *, evidence_eligibility: Mapping[str, object] | None = None
) -> dict[str, object]:
    result = getattr(artifact, "result", None)
    observation = result.get("observation") if isinstance(result, dict) else None
    polarity = "unknown"
    coverage = "partial"
    if isinstance(observation, dict):
        candidate_polarity = str(observation.get("polarity") or "").strip().lower()
        candidate_coverage = str(observation.get("coverage") or "").strip().lower()
        if candidate_polarity in {"present", "absent", "unknown", "unavailable"}:
            polarity = candidate_polarity
        if candidate_coverage in {"scoped", "partial", "unknown"}:
            coverage = candidate_coverage
    if evidence_eligibility is not None:
        # The blackboard has already checked run, target entity, topology and
        # incident-window compatibility.  A raw artifact can claim to be a
        # scoped observation while still belonging to another workload or a
        # different time window, so never let the synthesis model re-promote
        # it from its local polarity alone.
        evidence_id = str(getattr(artifact, "evidence_id", "") or "")
        eligibility = evidence_eligibility.get(evidence_id)
        permits = getattr(eligibility, "permits", None)
        if callable(permits) and permits("support"):
            role = "support"
        elif callable(permits) and permits("contradict"):
            role = "contradict"
        else:
            role = "context"
    elif polarity == "present" and coverage == "scoped":
        role = "support"
    elif polarity == "absent" and coverage == "scoped":
        role = "contradict"
    else:
        role = "context"
    agent = str(getattr(artifact, "agent", "") or "")
    prompt_result = (
        _sanitize_kubernetes_context_result(result)
        if agent == "kubernetes" and role == "context"
        else result
    )
    return {
        "type": str(getattr(artifact, "type", "")),
        "title": str(getattr(artifact, "title", "")),
        "status": str(getattr(artifact, "status", "")),
        "query": str(getattr(artifact, "query", "")),
        "summary": str(getattr(artifact, "summary", "")),
        "highlights": list(getattr(artifact, "highlights", []) or []),
        "evidence_role": role,
        "observation": {"polarity": polarity, "coverage": coverage},
        "condition_checks": condition_observations(result),
        "result": _compact_synthesis_value(
            prompt_result, limit=_SYNTHESIS_ARTIFACT_RESULT_CHARS
        ),
    }


_SYNTHESIS_OMIT = object()


def _sanitize_kubernetes_context_result(value: object) -> object:
    """Project live Kubernetes context without failure-looking configuration.

    The response artifact still retains the full YAML/JSON for the operator.
    This copy is only for the synthesis prompt, where raw ``spec`` fields such
    as ``preemptionPolicy=PreemptLowerPriority`` and healthy condition reason
    strings repeatedly became fabricated observations.
    """

    def walk(node: object, key: str = "") -> object:
        if key.casefold() in _K8S_SYNTHESIS_CONTEXT_DROP_KEYS:
            return _SYNTHESIS_OMIT
        if isinstance(node, dict):
            condition_type = str(node.get("type") or "").strip()
            if (
                condition_type.casefold() in _K8S_CONDITION_TYPES
                and "status" in node
            ):
                checks = condition_observations(
                    {"type": condition_type, "status": node.get("status")}, limit=1
                )
                if not checks:
                    return {"active": "unknown", "status": str(node.get("status") or "")}
                check = checks[0]
                # Inactive conditions are already represented, with their
                # exact names, in the sibling condition_checks projection. Do
                # not repeat failure vocabulary inside raw result text.
                if not check.get("active"):
                    return {"active": False, "status": str(node.get("status") or "")}
                projected: dict[str, object] = {
                    "condition": condition_type,
                    "active": True,
                    "status": str(node.get("status") or ""),
                }
                for field in ("reason", "message", "lastTransitionTime"):
                    if node.get(field) not in (None, ""):
                        projected[field] = node[field]
                return projected
            projected_dict: dict[str, object] = {}
            for child_key, child in node.items():
                projected = walk(child, str(child_key))
                if projected is not _SYNTHESIS_OMIT:
                    projected_dict[str(child_key)] = projected
            return projected_dict
        if isinstance(node, (list, tuple)):
            projected_list = []
            for child in node:
                projected = walk(child, key)
                if projected is not _SYNTHESIS_OMIT:
                    projected_list.append(projected)
            return projected_list
        return node

    projected = walk(value)
    return {} if projected is _SYNTHESIS_OMIT else projected


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


_SYNTHESIS_SIGNAL_TERMS: dict[str, tuple[str, ...]] = {
    "networkunavailable": ("networkunavailable",),
    "memorypressure": ("memorypressure",),
    "diskpressure": ("diskpressure",),
    "pidpressure": ("pidpressure",),
    "preemption": ("preempt", "preemption", "선점", "프리엠션"),
    "oomkilled": ("oomkill", "out of memory"),
    "restart_loop": (
        "crashloopbackoff",
        "restart loop",
        "restarting loop",
        "재시작 루프",
    ),
    "unschedulable": ("unschedulable", "failedscheduling", "스케줄링 불가"),
}


def _synthesis_supported_signal_groups(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    evidence_eligibility: Mapping[str, object] | None,
) -> set[str]:
    """Return problem-signal groups backed by alert/support observations."""
    markers = list(salient_markers(_alert_text(request), limit=20))
    for result in results:
        for artifact in result.artifacts:
            payload = _synthesis_artifact_payload(
                artifact, evidence_eligibility=evidence_eligibility
            )
            if payload.get("evidence_role") != "support":
                continue
            for check in payload.get("condition_checks") or []:
                if isinstance(check, dict) and check.get("active") is True:
                    markers.append(str(check.get("condition") or ""))
            raw_result = getattr(artifact, "result", None)
            extractor = (
                kubernetes_salient_markers
                if str(getattr(artifact, "agent", "") or "") == "kubernetes"
                else salient_markers
            )
            markers.extend(extractor(raw_result, limit=20))

    normalized = " ".join(markers).casefold()
    supported: set[str] = set()
    for group, terms in _SYNTHESIS_SIGNAL_TERMS.items():
        if any(term.casefold() in normalized for term in terms):
            supported.add(group)
    return supported


def _synthesis_claim_fragments(text: str) -> list[str]:
    return [
        fragment.strip()
        for fragment in re.split(r"(?<=[.!?。！？])|[\r\n]+", text or "")
        if fragment.strip()
    ]


_SYNTHESIS_CLAUSE_BREAK = re.compile(
    r"[.;!?。！？\r\n]+|\b(?:but|however|though|yet)\b|(?:하지만|반면|지만)",
    re.IGNORECASE,
)


def _synthesis_signal_mentions(
    fragment: str, terms: tuple[str, ...]
) -> list[tuple[int, int]]:
    """Return every case-insensitive signal span in a report fragment."""
    lowered = fragment.casefold()
    spans: list[tuple[int, int]] = []
    for term in terms:
        needle = term.casefold()
        start = 0
        while needle:
            index = lowered.find(needle, start)
            if index < 0:
                break
            end = index + len(needle)
            spans.append((index, end))
            start = end
    return spans


def _synthesis_fragment_asserts_signal(fragment: str, start: int, end: int) -> bool:
    """Whether one signal mention is asserted rather than negated or conditional.

    Polarity must be evaluated around the specific signal. A whole-fragment
    check reverses Korean statements such as ``MemoryPressure가 아닌 ...`` and
    can also let a different positive signal hide behind an unrelated negation.
    """
    lowered = fragment.casefold()
    if _keyword_negated(lowered, start, end):
        return False

    prefix = fragment[:start]
    suffix = fragment[end:]
    local_prefix = _SYNTHESIS_CLAUSE_BREAK.split(prefix)[-1]
    local_suffix = _SYNTHESIS_CLAUSE_BREAK.split(suffix, maxsplit=1)[0]
    local_clause = f"{local_prefix}{fragment[start:end]}{local_suffix}"
    if _SYNTHESIS_ASSERTION_CONDITIONAL.search(local_clause):
        return False
    return True


def _synthesis_semantic_conflict(
    summary: str,
    detail: str,
    *,
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    evidence_eligibility: Mapping[str, object] | None,
) -> str:
    """Reject free-form prose that reverses typed evidence truth.

    This is deliberately a rejection guard, not a prose rewriter.  On conflict
    the pipeline keeps its deterministic report rather than trying to repair a
    causal statement with another unconstrained model call.
    """
    text = f"{summary}\n{detail}"
    if _SYNTHESIS_PRIVATE_FACT_CITATION.search(text):
        return "private F-* evidence citation escaped into the report"

    known_evidence_ids = {
        str(getattr(artifact, "evidence_id", "") or "")
        for result in results
        for artifact in result.artifacts
        if str(getattr(artifact, "evidence_id", "") or "")
    }
    unknown_citations = sorted(
        {
            match.group(1)
            for match in _SYNTHESIS_PUBLIC_EVIDENCE_CITATION.finditer(text)
            if match.group(1) not in known_evidence_ids
        }
    )
    if unknown_citations:
        return f"unknown evidence citation(s): {', '.join(unknown_citations)}"

    supported = _synthesis_supported_signal_groups(
        request, results, evidence_eligibility
    )
    for fragment in _synthesis_claim_fragments(text):
        for group, terms in _SYNTHESIS_SIGNAL_TERMS.items():
            if group in supported:
                continue
            for start, end in _synthesis_signal_mentions(fragment, terms):
                if _synthesis_fragment_asserts_signal(fragment, start, end):
                    return f"unsupported positive {group} claim: {fragment[:180]}"
    return ""


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
        agent = _collector_name(collector)
        scoped_plan = plan.for_collector(agent) if isinstance(plan, InvestigationPlan) else plan
        return await collector.collect(target, scoped_plan)  # type: ignore[attr-defined]
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


def _mask_model(model: TModel, model_type: type[TModel], masker: Masker) -> TModel:
    payload = model.model_dump(mode="json")
    return model_type.model_validate(masker.mask_object(payload))



def _summary_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    root_cause_candidates: list[RankedCause],
    failure_modes: dict[str, list[dict]] | None = None,
    *,
    language: str = "en",
) -> str:
    observed = _observed_text(results, request)
    return _short_sentence(
        _failure_mode_root_cause_statement(
            root_cause_candidates,
            request,
            observed,
            failure_modes or {},
            language,
        ),
        limit=280,
    )


def _failure_mode_root_cause_statement(
    candidates: list[RankedCause],
    request: AlertAnalysisRequest,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    language: str,
) -> str:
    """Prefer an exact, curated mechanism over a coarse ranked-family sentence."""
    for _family, symptom in _actionable_failure_mode_matches(
        failure_modes, observed_text, candidates
    ):
        reason = str(
            symptom.get("reason_ko" if language == "ko" else "reason") or ""
        ).strip()
        if reason:
            return reason
    return _ranked_root_cause_statement(candidates, request)


def _localized_failure_mode_name(symptom: dict, language: str) -> str:
    if language == "ko" and symptom.get("symptom_ko"):
        return str(symptom["symptom_ko"])
    return str(symptom.get("symptom") or "")


def _localized_failure_mode_actions(symptom: dict, language: str) -> list[str]:
    localized = symptom.get("actions_ko") if language == "ko" else None
    actions = localized or symptom.get("actions") or []
    return [str(action) for action in actions if str(action).strip()]


def _actionable_failure_mode_matches(
    failure_modes: dict[str, list[dict]],
    observed_text: str,
    candidates: list[RankedCause] | None,
    *,
    fuzzy_query: str = "",
) -> list[tuple[str, dict]]:
    """Apply common knowledge metadata after signature matching.

    An ``exclusive_actions`` entry is a curated assertion that its precise
    remediation supersedes broad same-incident checklists such as the generic
    CrashLoopBackOff runbook.
    """
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    matches = [
        (family, symptom)
        for family, symptom in match_failure_mode_symptoms(
            failure_modes, observed_text, top_family, fuzzy_query=fuzzy_query
        )
        if not filter_to_top or family == top_family
    ]
    exclusive = next(
        ((family, symptom) for family, symptom in matches if symptom.get("exclusive_actions")),
        None,
    )
    return [exclusive] if exclusive else matches


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
    eligible_support_ids: set[str] | None = None,
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
    observed_text = _observed_text(
        results, request, eligible_support_ids=eligible_support_ids
    )
    lines.extend(["", h["cause"], ""])
    lines.append(
        _failure_mode_root_cause_statement(
            root_cause_candidates or [],
            request,
            observed_text,
            failure_modes or {},
            language,
        )
    )
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
            known_issues, observed_text, language, _alert_text(request)
        )
    )
    supporting = _supporting_evidence(results, eligible_support_ids=eligible_support_ids)
    if supporting:
        lines.append("")
        lines.extend(f"- **{agent}**: {finding}" for agent, finding in supporting)
    # A graph/XID chain is useful remediation knowledge, but it is not a
    # current incident observation by itself.  Keep it out of the headline
    # causal narrative when every collected artifact was demoted to context or
    # rejected for a different target/window.  Otherwise "fix root XID first"
    # can look like a current, grounded instruction despite having no eligible
    # observation in this run.
    # Curated alert/component/playbook/graph actions are *guidance*, not a
    # current-incident observation.  They all need the same target/window gate:
    # otherwise an all-context run could withhold graph fixes yet still tell an
    # operator to execute a documented-alert fix or repeat a historical remedy.
    allow_cause_specific_actions = eligible_support_ids is None or bool(eligible_support_ids)
    causal = _causal_chain_line(graph_fixes, language) if allow_cause_specific_actions else ""
    if causal:
        lines.extend(["", causal])
    if allow_cause_specific_actions:
        lines.extend(_xid_diagnostic_guidance_lines(graph_fixes, language))

    # --- 3. Recommended Actions ------------------------------------------------
    lines.extend(["", h["actions"], ""])
    numbered = _numbered_actions(
        plan,
        graph_fixes,
        root_cause_candidates,
        observed_text,
        failure_modes or {},
        missing,
        request,
        known_issues or [],
        components=components,
        allow_cause_specific_actions=allow_cause_specific_actions,
        language=language,
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
            observed_text,
            _alert_text(request),
            masker,
            allow_remediation=allow_cause_specific_actions,
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
            observed_text,
            failure_modes or {},
            troubleshooting_cases,
            known_issues or [],
            _alert_text(request),
            components,
            masker,
            component=getattr(plan, "component", "") if plan is not None else "",
            allow_remediation=allow_cause_specific_actions,
            language=language,
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
    if _needs_general_guidance(root_cause_candidates, eligible_support_ids):
        lines.extend(
            [
                "",
                _general_guidance_heading(language),
                "",
                *general_guidance_lines(
                    _alert_text(request),
                    failure_modes or {},
                    known_issues or [],
                    language=language,
                    masker=masker,
                ),
            ]
        )
    return "\n".join(lines)


def _needs_general_guidance(
    candidates: list[RankedCause] | None, eligible_support_ids: set[str] | None
) -> bool:
    """Show non-diagnostic help only when the RCA cannot support an action."""
    top_family = candidates[0].family if candidates else ""
    return top_family in ("", "insufficient_evidence") or eligible_support_ids == set()


def _general_guidance_heading(language: str) -> str:
    return (
        "## 일반 점검 가이드 (현재 RCA 결론 아님)"
        if language == "ko"
        else "## General Troubleshooting Guidance (Not a Current RCA Conclusion)"
    )


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


def _append_general_guidance(detail: str, block: str) -> str:
    """Keep non-diagnostic guidance outside the RCA conclusion and action sections."""
    return f"{detail.rstrip()}\n\n{block}"


def _supporting_evidence(
    results: list[CollectorResult], *, eligible_support_ids: set[str] | None = None
) -> list[tuple[str, str]]:
    """Up to four scoped positive findings for the Root Cause section.

    The Appendix can retain partial/current context for an operator, but this
    headline section must agree with the ranker and self-check: a successful
    query alone is not proof that its signal was present during the incident.
    """
    picked: list[tuple[str, str]] = []
    for result in results:
        if result.status not in ("ok", "partial"):
            continue
        line = _artifact_evidence_line(result, eligible_support_ids=eligible_support_ids)
        if not line:
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
    if graph_fixes is None:
        return ""
    codes = sorted(set(graph_fixes.xid_fixes) | set(graph_fixes.xid_triggers))
    if not codes:
        return ""
    rendered_codes = ", ".join(str(code) for code in codes)
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
                f"- 관련 GPU 오류(XID): {rendered_codes} — 인과 사슬(뿌리→관측): {chain}. "
                "뿌리 XID를 먼저 조치하세요."
            )
        return f"- 관련 GPU 오류(XID): {rendered_codes} — 세부 조치는 아래 권장 조치를 참고."
    if chain:
        return (
            f"- Related GPU errors (XID): {rendered_codes} — causal chain (root → observed): "
            f"{chain}. Fix the root XID first."
        )
    return f"- Related GPU errors (XID): {rendered_codes} — see the recommended actions below."


def _xid_diagnostic_guidance_lines(
    graph_fixes: GraphRemediation | None, language: str
) -> list[str]:
    if graph_fixes is None or not graph_fixes.xid_triggers:
        return []
    masker = build_masker(())
    label = "진단 안내" if language == "ko" else "Diagnostic guidance"
    return [
        f"- {label} (XID {code}): {_safe_line(trigger, limit=360, masker=masker)}"
        for code, trigger in sorted(graph_fixes.xid_triggers.items())
    ]


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
    *,
    allow_graph_remediation: bool = True,
    allow_cause_specific_actions: bool | None = None,
    language: str = "en",
) -> list[str]:
    """One deduped, numbered priority list — documented-alert fixes first, then
    the alert target's own component checks, then recognised known-issue fixes,
    graph-derived and curated family fixes, then infra-restore steps."""
    # ``allow_graph_remediation`` predates the broader action gate and remains
    # for callers outside the pipeline. In a real report, every remedy that
    # depends on a candidate (catalog, component, prior, graph, playbook) must
    # obey the same evidence boundary as graph remediation.
    if allow_cause_specific_actions is None:
        allow_cause_specific_actions = allow_graph_remediation
    ordered: list[str] = []
    specific_actions = 0
    fuzzy = _alert_text(request)
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    symptom_matches = _actionable_failure_mode_matches(
        failure_modes, observed_text, candidates, fuzzy_query=fuzzy
    )
    if allow_cause_specific_actions and symptom_matches[0:1] and symptom_matches[0][1].get(
        "exclusive_actions"
    ):
        actions = _localized_failure_mode_actions(symptom_matches[0][1], language)
        return [f"{index}. {action}" for index, action in enumerate(actions, start=1)]
    if allow_cause_specific_actions and plan is not None and plan.matched_alert:
        alert_family = str(plan.matched_alert.get("family") or "")
        if (not top_family or alert_family == top_family) and top_family != "insufficient_evidence":
            ordered.extend(str(a) for a in plan.matched_alert.get("actions", []))
    # Component identity: the alert target IS this platform component, so its
    # own checks + dependency chain (e.g. runai-container-toolkit → the NVIDIA
    # GPU Operator stack) come before any keyword-matched guidance.
    if allow_cause_specific_actions and plan is not None and getattr(plan, "component", ""):
        component_actions = component_action_lines(components or {}, plan.component)
        specific_actions += len(component_actions)
        ordered.extend(component_actions)
    # Known operator cases recognised by their signature keywords in the evidence
    # (ranking-independent): version-regression / observability / expected-behavior
    # fixes surface even when the coarse family ranking points elsewhere.
    if allow_cause_specific_actions and top_family != "insufficient_evidence":
        for issue in match_runai_known_issues(known_issues or [], observed_text, fuzzy_query=fuzzy):
            if filter_to_top and str(issue.get("family") or "") != top_family:
                continue
            actions = [str(a) for a in issue.get("actions", [])]
            specific_actions += len(actions)
            ordered.extend(actions)
    # Knowledge-graph/XID fixes are recommendations, not evidence.  The
    # production report passes False when its artifact eligibility gate found
    # no target/window-scoped support, preventing an unavailable or unrelated
    # observation from turning a historical graph edge into an instruction.
    if graph_fixes is not None and allow_cause_specific_actions:
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
    if allow_cause_specific_actions and top_family != "insufficient_evidence":
        for _family, symptom in symptom_matches:
            actions = _localized_failure_mode_actions(symptom, language)
            specific_actions += len(actions)
            ordered.extend(actions)
    ordered.extend(
        line.removeprefix("- ")
        for line in _recommended_action_lines(
            missing,
            request,
            include_similar=(
                allow_cause_specific_actions
                and (specific_actions == 0 or _similar_incident_relevant(request, fuzzy))
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
    labels = alert.labels or {}
    # Prometheus/Kubernetes alerts commonly encode a Boolean condition across
    # two independent labels (for example condition=DiskPressure,status=false).
    # Flattening mapping values preserves sender insertion order, so a false
    # value before its condition could evade the keyword negation logic and turn
    # a healthy condition into RCA support. Recompose that structured pair
    # before adding ordinary label values.
    normalized = {str(key).casefold(): str(value) for key, value in labels.items()}
    condition_keys = [key for key in normalized if "condition" in key and normalized[key].strip()]
    state_key = next(
        (
            key
            for key in ("status", "value", "active", "state")
            if normalized.get(key, "").strip()
        ),
        "",
    )
    paired = set(condition_keys)
    if state_key and condition_keys:
        paired.add(state_key)
    parts = [
        (
            f"{normalized[key]} is {normalized[state_key]}"
            if state_key
            else normalized[key]
        )
        for key in condition_keys
    ]
    parts.extend(
        str(value)
        for key, value in labels.items()
        if str(key).casefold() not in paired
    )
    parts.extend(str(v) for v in (alert.annotations or {}).values())
    return " ".join(parts)


def _observed_text(
    results: list[CollectorResult],
    request: AlertAnalysisRequest | None = None,
    *,
    eligible_support_ids: set[str] | None = None,
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
        artifacts = list(result.artifacts)
        # Once a collector publishes typed observations, do not let its broad
        # summary/current snapshot re-enter signature promotion by keyword. The
        # alert's own text above remains a separate direct observation, while
        # legacy collectors retain their compatibility path until upgraded.
        if any(_artifact_observation(art) is not None for art in artifacts):
            artifacts = [
                art
                for art in artifacts
                if _artifact_is_scoped_support(art, eligible_support_ids=eligible_support_ids)
            ]
        elif result.summary:
            parts.append(result.summary)
        for art in artifacts:
            if not _artifact_is_evidence(art):
                continue
            if art.summary:
                parts.append(art.summary)
            if art.result is not None:
                parts.append(_evidence_leaf_text(art.result, limit=2000, drop_keys=drop_keys))
    return " ".join(parts).lower()


def _evidence_leaf_text(
    value: Any, *, limit: int = 2000, drop_keys: frozenset[str] | set[str] | None = None
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
    *,
    allow_remediation: bool = True,
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
    if allow_remediation:
        body.extend(
            _kb_remediation_lines(
                kg_context, candidates, observed_text, fuzzy_query, active_masker
            )
        )
    elif kg_context.get("knowledge"):
        body.append(
            "- Knowledge-base remediation is withheld until a current "
            "target/window-scoped observation is available."
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
    *,
    allow_remediation: bool = True,
    language: str = "en",
) -> list[str]:
    """Root-cause-relevant remediation, most specific first.

    Precision order: the alert target's OWN component (identity beats any
    keyword), then matched known issues (real operator cases), then matched
    curated symptoms for the settled top family. Cross-family signatures have
    already been used to pick that top family; unrelated side text should not
    become playbook guidance.
    """
    if not allow_remediation:
        return [
            "- Specific playbook remediation is withheld until a current "
            "target/window-scoped observation is available."
        ]
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
    symptom_matches = _actionable_failure_mode_matches(
        failure_modes, observed_text, candidates, fuzzy_query=fuzzy_query
    )
    if symptom_matches[0:1] and symptom_matches[0][1].get("exclusive_actions"):
        lines = []
    for family, symptom in symptom_matches:
        symptom_name = _safe_line(
            _localized_failure_mode_name(symptom, language),
            limit=180,
            masker=active_masker,
        )
        lines.append(f"- **{symptom_name}** ({_family_label(family)})")
        lines.extend(
            f"  - {_safe_line(action, limit=360, masker=active_masker)}"
            for action in _localized_failure_mode_actions(symptom, language)[:5]
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
    context_line = _artifact_evidence_line(result, include_context=True)
    if context_line:
        return context_line
    unavailable_line = _artifact_evidence_line(result, include_unavailable=True)
    return unavailable_line or _best_evidence_line(result)


_GENERIC_ARTIFACT_SUMMARY_RE = re.compile(
    r"^(?:\d+\s+row\(s\)|metadata rows?|schema rows?|ok|success|drilldown ok)$",
    re.IGNORECASE,
)


def _artifact_evidence_line(
    result: CollectorResult,
    *,
    include_unavailable: bool = False,
    include_context: bool = False,
    eligible_support_ids: set[str] | None = None,
) -> str:
    for art in reversed(getattr(result, "artifacts", []) or []):
        is_context = getattr(art, "status", "") in ("ok", "partial")
        if (
            not _artifact_is_scoped_support(art, eligible_support_ids=eligible_support_ids)
            and not (include_context and is_context)
            and not include_unavailable
        ):
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
    """Whether an artifact is usable investigation input in any capacity."""
    return getattr(art, "status", "") in ("ok", "partial")


def _artifact_is_scoped_support(
    art: object, *, eligible_support_ids: set[str] | None = None
) -> bool:
    """Whether an artifact may be printed as Root Cause supporting evidence."""
    observation = _artifact_observation(art)
    if observation is None:
        return False
    raw_support = (
        str(observation.get("polarity") or "").strip().lower() == "present"
        and str(observation.get("coverage") or "").strip().lower() == "scoped"
    )
    if not raw_support:
        return False
    if eligible_support_ids is None:
        return True
    # Once the pipeline has a contextual eligibility map, an E-id missing from
    # it is not merely "legacy" evidence: it is not approved for this report.
    return str(getattr(art, "evidence_id", "") or "") in eligible_support_ids


def _artifact_observation(art: object) -> dict[str, object] | None:
    result = getattr(art, "result", None)
    if not isinstance(result, dict):
        return None
    observation = result.get("observation")
    return observation if isinstance(observation, dict) else None


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


def _xid_codes_from_results(
    results: list[CollectorResult],
    alert_text: str = "",
    *,
    eligible_support_ids: set[str] | None = None,
) -> list[int]:
    """Distinct NVIDIA Xid codes in the alert's own text + loki/system/kubernetes
    evidence. The alert text matters: an NVRM Xid alert names its code even when
    every collector comes back empty."""
    texts = [alert_text] if alert_text else []
    texts.extend(
        _stringify_result(result, eligible_support_ids=eligible_support_ids)
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


def _stringify_result(
    result: CollectorResult, *, eligible_support_ids: set[str] | None = None
) -> str:
    """Render only causally usable text for signature-specific extractors.

    Structured collectors distinguish an observation's polarity and temporal
    coverage.  Their broad summaries/details are often live topology or query
    metadata, so letting those strings back into an extractor (such as Xid)
    would bypass the scoped-evidence rule used by ``_observed_text``.  Legacy
    collectors retain their existing text path until they publish observations.
    """
    artifacts = getattr(result, "artifacts", []) or []
    structured = any(_artifact_observation(art) is not None for art in artifacts)
    if structured:
        artifacts = [
            art
            for art in artifacts
            if _artifact_is_scoped_support(
                art, eligible_support_ids=eligible_support_ids
            )
        ]

    parts = [] if structured else [result.summary or ""]
    parts.extend(art.summary or "" for art in artifacts if _artifact_is_evidence(art))
    parts.extend(
        _evidence_leaf_text(art.result)
        for art in artifacts
        if _artifact_is_evidence(art) and art.result
    )
    details = getattr(result, "details", {})
    if details and not structured:
        parts.append(_evidence_leaf_text(details))
    return " ".join(parts)


def _graph_remediation_lines(graph_fixes: GraphRemediation | None) -> list[str]:
    if graph_fixes is None or graph_fixes.is_empty():
        return []
    masker = build_masker(())
    lines = ["- Knowledge-graph derived remediation:"]
    for statement in graph_fixes.family_fixes[:5]:
        lines.append(f"  - {_safe_line(statement, limit=360, masker=masker)}")
    for statement in graph_fixes.verified_actions[:5]:
        lines.append(
            f"  - Verified in an approved historical resolution: "
            f"{_safe_line(statement, limit=360, masker=masker)}"
        )
    for code, fixes in graph_fixes.xid_fixes.items():
        lines.append(f"  - NVIDIA Xid {code}:")
        lines.extend(
            f"    - {_safe_line(statement, limit=360, masker=masker)}"
            for statement in fixes[:5]
        )
    for code, trigger in graph_fixes.xid_triggers.items():
        lines.append(
            f"  - Diagnostic guidance (XID {code}): "
            f"{_safe_line(trigger, limit=360, masker=masker)}"
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
