from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import textwrap
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app.collectors.base import (
    AnalysisTarget,
    CollectorResult,
    causal_evidence_time_range,
    parse_incident_time,
    resolve_target,
)
from app.collectors.base import artifact as make_artifact
from app.collectors.http_json import post_json
from app.collectors.registry import build_collectors, unknown_collector_names
from app.config import Settings
from app.knowledge import (
    _keyword_hits,
    _keyword_negated,
    component_action_lines,
    component_check_lines,
    component_for_text,
    dependency_path,
    family_label,
    is_matcher_only_family,
    load_architecture,
    load_failure_modes,
    load_family_catalog,
    load_runai_known_issues,
    load_troubleshooting_cases,
    load_xid_catalog,
    localized_failure_mode_actions,
    localized_failure_mode_name,
    match_failure_mode_symptoms,
    match_runai_known_issues,
    merge_runtime_failure_modes,
    runtime_shadow_hints,
)
from app.llm import (
    _analysis_time_remaining,
    complete_json,
    complete_with_error,
    llm_configured,
    parse_json_object,
)
from app.masking import Masker, build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.prompts import load_agent_souls
from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse, SimilarIncidentContext
from app.services.decision_tree import resolve_tree, walk_tree
from app.services.evidence_projection import EXECUTION_METADATA_KEYS
from app.services.general_guidance import general_guidance_lines
from app.services.kg_enrichment import GraphRemediation, enrich, graph_remediation
from app.services.planner import plan_investigation
from app.services.query_memory import QueryMemory
from app.services.remediation import (
    fill_placeholders,
    format_memory,
    image_repository,
    image_typo_hint,
    memory_sizing_action,
    parse_memory,
)
from app.services.root_cause_ranking import (
    FAMILIES,
    RankedCause,
    artifact_supports_family,
    merge_open_world_candidates,
    rank_root_cause_candidates,
    scheduling_reason_family,
)

_log = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)
Stage = Callable[["PipelineState"], Awaitable["PipelineState"]]
_SYNTHESIS_ARTIFACT_RESULT_CHARS = 1200

# Raw Kubernetes objects contain failure vocabulary even when the observed
# value is healthy or merely declarative configuration.  Those fields remain
# available in the response artifact for operators, but the free-form
# synthesizer receives a status-aware projection instead.
_K8S_SYNTHESIS_CONTEXT_DROP_KEYS = EXECUTION_METADATA_KEYS | frozenset(
    {
        "managedfields",
        "metadata",
        "preemptionpolicy",
        "priorityclassname",
        "spec",
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
_DISPOSITIVE_TYPED_REASONS: dict[str, frozenset[str]] = {
    "image_pull_error": frozenset(
        {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull"}
    ),
    "workload_startup_error": frozenset(
        {
            "CrashLoopBackOff",
            "CreateContainerConfigError",
            "CreateContainerError",
            "RunContainerError",
            "StartError",
        }
    ),
    "workload_runtime_error": frozenset({"OOMKilled"}),
    # Set only by the typed PodScheduled=False condition artifact
    # (kubernetes_pod_scheduling); container states and Warning events never
    # carry these reason strings, so lifecycle/event promotion is unaffected.
    "k8s_scheduling_error": frozenset({"Unschedulable", "SchedulingGated"}),
}


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
    query_memory: QueryMemory = field(default_factory=QueryMemory)
    priors: dict[str, float] | None = None
    effective_seed_family: str = ""
    effective_seed_provenance: str = ""
    observed: str = ""
    alert_fuzzy: str = ""
    xid_codes: list[int] = field(default_factory=list)
    failure_modes: dict[str, list[dict]] = field(default_factory=dict)
    runtime_knowledge_hints: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    known_issues: list[dict] = field(default_factory=list)
    root_cause_candidates: list[RankedCause] = field(default_factory=list)
    # Immutable-at-stage-boundary snapshot used to explain ranking separately
    # from later self-check/signature verification/harness calibration.
    ranking_candidate_before_self_check: RankedCause | None = None
    open_world_candidates: list[RankedCause] = field(default_factory=list)
    self_check_caveat: str = ""
    self_check_refuted: bool = False
    self_check_next: str = ""
    self_check_confidence_before: str = ""
    self_check_confidence_after: str = ""
    reanalysis_note: str = ""
    # The family the LAST reanalysis-round note asserted as its conclusion
    # (R1) -- captured so harness_stage can tell, once it knows the FINAL
    # published family, whether the Self-Check text it already wrote into
    # state.detail is now stale (a later harness repair/abstain, or the
    # refuted-top fallback, can change the headline after this note was
    # written).
    reanalysis_note_family: str = ""
    synthesis_status: str = "not_requested"
    synthesis_error: str = ""
    synthesis_duration: float | None = None
    # Eligible semantic matches returned by the most recent re-analysis pass.
    # This is intentionally transient: it only changes the next probe order.
    reanalysis_fresh_support_families: tuple[str, ...] = ()
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
    refuted_mechanism: str = ""
    initial_refutation: bool = False


@dataclass(frozen=True)
class _ReanalysisOutcome:
    results: list[CollectorResult]
    candidates: list[RankedCause]
    ranking_candidate: RankedCause | None
    investigation_context: dict[str, Any]
    caveat: str
    note: str
    refuted: bool
    next_check: str
    fresh_support_families: tuple[str, ...]


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

    At the default 900s deadline, evidence gathering (investigation plus every
    drill-down) now shares 750s and finalization keeps a 150s floor. Deadlines
    under ~375s are unaffected -- 40% of them was already below this floor, so
    short test/operator deadlines still reserve at most half, same as before.

    The floor used to be a flat 360s (40% of 900s) grounded in the
    ``llm_synthesis_max_tokens`` comment in config.py: one call legally
    spending 300-450s on a 16384-token completion. That call no longer
    exists. Since 2026-07-22 Korean "synthesis" only translates the
    already-decided deterministic report (owner directive: never re-analyze),
    in concurrency-4 batches of ~2000 source chars each
    (``_TRANSLATION_BATCH_CHARS`` / ``_TRANSLATION_BATCH_CONCURRENCY``), so one
    batch's own cap is ~3072 tokens (``_translate_line_batch``), not 16384. A
    real run measured the whole finalization phase (rank + self-check +
    synthesis + harness) at 67.5s against the old 360s floor -- 292.5s
    reserved but never spent, while evidence gathering was cut off early with
    real drill-downs still queued (stop_reason ``analysis_budget_exhausted``
    at 605s of a 900s deadline). 150s is a bit over 2x that measurement: room
    for a genuinely slow batch/self-check round plus a retry, without pinning
    the 16k-token budget the translate-only path no longer spends.
    """
    if total_seconds <= 0:
        return 0.0
    return min(150.0, max(30.0, total_seconds * 0.40), total_seconds * 0.50)


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


async def _resolve_free_text_target(state: PipelineState) -> None:
    """Adopt a live workload named in the operator's request, when unambiguous.

    Only for a request that carries no target at all: an alert with labels is
    already scoped, and prose must never override structured identity. Silent
    when nothing resolves — a wrong target is worse than none, since every
    collector would then investigate the wrong service with full confidence.
    """
    target = state.target
    if target.namespace or target.pod or target.workload_name or state.plan is None:
        return
    text = " ".join(
        part
        for part in (
            state.request.alert.annotations.get("operator_prompt"),
            state.request.alert.annotations.get("summary"),
            state.request.alert.annotations.get("description"),
        )
        if part
    ).strip()
    if not text:
        return
    from app.collectors.kubernetes import resolve_target_from_text

    try:
        namespace, workload = await resolve_target_from_text(state.settings, text)
    except Exception:  # noqa: BLE001 - an unscoped run is the status quo, not a failure
        _log.warning("free-text target resolution failed", exc_info=True)
        return
    if not namespace or not workload:
        return
    _log.info("plan: operator request resolved to workload %s/%s", namespace, workload)
    state.plan.workload = workload
    state.plan.namespaces = [namespace, *[ns for ns in state.plan.namespaces if ns != namespace]]
    state.extra_warnings.append(
        f"target read from the operator's request and confirmed live: {namespace}/{workload}"
    )


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
    scoped = _scope_target(state.declared_target, state.plan)
    # ``plan.namespaces`` is an investigation SCOPE and may lead with a platform
    # component's home namespace (the planner puts it first so the component is
    # read). An alert that declares its own namespace has already stated the
    # target's identity, and evidence eligibility compares every observation
    # against it — so the plan may ADD namespaces to read, never move the target
    # out of the namespace the alert named. Per-probe scoping keeps using
    # ``_scope_target`` directly and is unaffected.
    if state.declared_target.namespace:
        scoped = replace(scoped, namespace=state.declared_target.namespace)
    state.target = scoped
    return state.target


_ALERT_DISPOSITIVE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "image_pull_error": (
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
    ),
    "workload_startup_error": (
        "CrashLoopBackOff",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
    ),
    # OOMKilled is a RUNTIME termination everywhere else (typed container
    # reason, failure_modes, families keywords). Filing it under startup here
    # minted an alert_signature card no family could support — startup's
    # keyword rule has no "oomkilled" — while seeding the wrong candidate.
    "workload_runtime_error": ("OOMKilled",),
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
    request: AlertAnalysisRequest,
    target: AnalysisTarget,
    known_issues: list[dict[str, Any]] | None = None,
) -> CollectorResult | None:
    """Materialize explicit alert failure signatures as typed, citable evidence."""
    codes, matched_by_family = _asserted_alert_signatures(request)
    # "Unschedulable" in a NODE alert's prose describes the node's own
    # administrative state (cordon), not a pod-scheduling failure — a
    # node-target alert cannot mint pod-scheduling evidence
    # (INC-1785215448065944607: a manual cordon scored k8s_scheduling_error
    # from its alert title alone).
    if not (target.pod or target.workload_name):
        matched_by_family.pop("k8s_scheduling_error", None)
    asserted_texts = _asserted_alert_texts(request)
    asserted_known_issues: list[dict[str, Any]] = []
    for entry in match_runai_known_issues(
        known_issues or [], " ".join(asserted_texts)
    ):
        asserted_keywords = []
        for keyword in entry.get("matched_keywords") or []:
            for text in asserted_texts:
                if any(
                    _alert_signature_is_asserted(text, match.start(), match.end())
                    for match in re.finditer(re.escape(str(keyword)), text, re.IGNORECASE)
                ):
                    asserted_keywords.append(str(keyword))
                    break
        family = str(entry.get("family") or "")
        if family and _promotable(asserted_keywords, family):
            asserted_known_issues.append(
                {**entry, "matched_keywords": list(dict.fromkeys(asserted_keywords))}
            )
    if not codes and not matched_by_family and not asserted_known_issues:
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
    for entry in asserted_known_issues:
        family = str(entry.get("family") or "")
        issue = str(entry.get("issue") or "")
        signals = list(dict.fromkeys(entry.get("matched_keywords") or []))
        summary = (
            f"Alert payload explicitly reported known-issue signature {issue}: "
            + ", ".join(signals)
            + "."
        )
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
                    "matched_known_issue": issue,
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
    # A semantic observation gets one evidence card. Repeated collector passes
    # used to survive when only collection timestamps/counters changed because
    # the full result JSON was part of the key. Keep the latest observation for
    # the same agent/type/query/title while preserving distinct Node conditions
    # that intentionally share one `kubectl get node` command.
    artifact_positions: dict[
        tuple[str, str, str, str, str, str], tuple[list[Any], int]
    ] = {}
    for result in state.results:
        retained = []
        for item in result.artifacts:
            query = str(getattr(item, "query", "") or "")
            title = str(getattr(item, "title", "") or "")
            key = (
                str(getattr(item, "agent", "")),
                str(getattr(item, "type", "")),
                query,
                title,
                _artifact_observation_scope(item),
                # Cards without an executable query/title can represent two
                # different observed entities with identical display text.
                # Preserve their typed payload identity instead of merging
                # unrelated Pods/facts.
                "" if query or title else _json_fingerprint(getattr(item, "result", None)),
            )
            previous = artifact_positions.get(key)
            if previous is not None:
                previous_artifacts, position = previous
                previous_artifacts[position] = item
                continue
            artifact_positions[key] = (retained, len(retained))
            retained.append(item)
        result.artifacts = retained
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


def _artifact_observation_scope(item: object) -> str:
    """Keep equal display queries distinct when entity/window semantics differ."""
    payload = getattr(item, "result", None)
    if not isinstance(payload, Mapping):
        return ""
    observation = payload.get("observation")
    observation = observation if isinstance(observation, Mapping) else {}
    window = observation.get("observation_window")
    if not isinstance(window, Mapping):
        window = payload.get("observation_window") or payload.get("time_range")
    semantic_scope = {
        "predicate": observation.get("predicate") or observation.get("kind") or "",
        "observed_entity": observation.get("observed_entity") or payload.get("observed_entity"),
        "observation_window": window if isinstance(window, Mapping) else {},
    }
    return (
        _json_fingerprint(semantic_scope)
        if any(value not in (None, "", {}) for value in semantic_scope.values())
        else ""
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
    explicit_seed = str(state.request.seed_family or "").strip()
    approved_seed = approved_similar_seed(
        state.request.similar_incidents,
        load_family_catalog(state.settings.families_file),
    )
    state.effective_seed_family = explicit_seed or approved_seed
    state.effective_seed_provenance = (
        "operator_reverify"
        if explicit_seed
        else "approved_prior_match"
        if approved_seed
        else ""
    )
    # Plan first (senior-SRE "think before you dig"): scope every collector to
    # what THIS alert needs instead of always scraping the control plane.
    state.plan = await plan_investigation(
        state.settings,
        state.target,
        state.request.alert,
        state.kg_context.as_dict(),
        list(state.request.similar_incidents),
        recent_changes,
        state.effective_seed_family,
    )
    state.extra_warnings.extend(state.plan.warnings)
    # A planner/live lookup may identify resources that exist today. Pin every
    # concrete identity carried by a resolved alert before any collector uses it.
    _pin_resolved_target_identity(state)
    # Alert labels frequently name a pod the controller already replaced (grouped
    # CrashLoop occurrences) and carry no node label — so kubernetes GETs 404 and
    # the system agent skips node/kernel evidence entirely. Re-resolve a LIVE pod
    # and its node ONCE here; every collector then scopes off the plan.
    # A chat-initiated request names its subject in prose, not in labels, so it
    # arrives with no namespace/pod/workload and every scoped collector skips
    # itself. Read the subject out of the operator's own sentence and verify it
    # against the live cluster before adopting it.
    await _resolve_free_text_target(state)
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

    # The adaptive investigator may stop with a collector subset only after a
    # supported hypothesis cites a scoped positive fact. Without that proof the
    # investigator (and the no-LLM compatibility path) still gathers every
    # configured collector, so transport/model failure cannot masquerade as a
    # confident early conclusion.
    if (
        llm_configured(settings, settings.llm_model_investigation)
        and settings.enable_investigation_loop
    ):
        from app.services.investigator import investigate

        investigation_kwargs: dict[str, Any] = {"reporter": state.progress}
        if _accepts_keyword(investigate, "blackboard"):
            investigation_kwargs["blackboard"] = state.blackboard
        if _accepts_keyword(investigate, "query_memory"):
            investigation_kwargs["query_memory"] = state.query_memory
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
    # A generic alert title cannot choose the exact tree branch until base
    # evidence arrives (for example KubePodNotReady -> FailedScheduling).
    # Rebind ontology probes before optional follow-ups and domain drill-down.
    if state.plan is not None:
        from app.services.planner import refresh_diagnostic_directive_from_evidence

        refresh_diagnostic_directive_from_evidence(
            settings,
            state.plan,
            state.kg_context.as_dict() if state.kg_context is not None else {},
            _observed_text(state.results, state.request),
            seed_family=state.effective_seed_family,
            run_id=str(state.request.alert.annotations.get("analysis_run_id") or ""),
        )
    evidence_sufficient = _investigation_evidence_sufficient(state)
    alert_evidence = _alert_signature_evidence_result(
        state.request,
        target,
        load_runai_known_issues(state.settings.runai_known_issues_file),
    )
    if alert_evidence is not None and not any(r.agent == "alert" for r in state.results):
        state.results.append(alert_evidence)
    # Facts and hashed query receipts are run-scoped memory for every evidence
    # path. Seeding is idempotent, so this also covers results already recorded
    # by investigate.
    state.blackboard.seed_results(
        state.results,
        entity=_blackboard_target_entity(target),
        timestamp=getattr(target, "fired_at", ""),
        observed_window_start=str(causal_window.get("start") or ""),
        observed_window_end=str(causal_window.get("end") or ""),
    )
    state.query_memory.seed_results(state.results, target)
    # Deterministic flowchart-driven follow-up: keep pulling k8s evidence based on
    # what was found (Pending -> events/quota/pvc -> storageclass; CrashLoop/
    # ImagePull -> events). Runs with OR without the LLM loop, so collection stays
    # iterative even when litellm is down (the ReAct loop is skipped then).
    try:
        from app.collectors.kubernetes import k8s_followup
        from app.collectors.prometheus import prometheus_followup

        k8s_result = next((r for r in state.results if r.agent == "kubernetes"), None)
        prom_result = next((r for r in state.results if r.agent == "prometheus"), None)
        k8s_followup_kwargs: dict[str, Any] = {}
        if _accepts_keyword(k8s_followup, "query_memory"):
            k8s_followup_kwargs["query_memory"] = state.query_memory
        if not evidence_sufficient:
            await k8s_followup(settings, k8s_result, target, **k8s_followup_kwargs)
            # Cross-collector: k8s findings (OOM/restart/Pending) -> derived PromQL.
            prom_followup_kwargs: dict[str, Any] = {}
            if _accepts_keyword(prometheus_followup, "query_memory"):
                prom_followup_kwargs["query_memory"] = state.query_memory
            await prometheus_followup(
                settings, prom_result, k8s_result, target, **prom_followup_kwargs
            )
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
        from app.services.kg_enrichment import external_case_hints

        drilldown_kwargs: dict[str, Any] = {"blackboard": state.blackboard}
        if _accepts_keyword(run_drilldowns, "query_memory"):
            drilldown_kwargs["query_memory"] = state.query_memory
        if _accepts_keyword(run_drilldowns, "evidence_sufficient"):
            drilldown_kwargs["evidence_sufficient"] = evidence_sufficient
        evidence_deadline = _evidence_deadline_monotonic(state)
        if _accepts_keyword(run_drilldowns, "deadline_monotonic"):
            drilldown_kwargs["deadline_monotonic"] = evidence_deadline
        if not evidence_sufficient and _accepts_keyword(
            run_drilldowns, "external_case_hints"
        ):
            observed_text = _observed_text(state.results, state.request)
            try:
                if evidence_deadline is not None:
                    remaining = max(0.0, evidence_deadline - time.monotonic())
                    hints = await asyncio.wait_for(
                        external_case_hints(settings, observed_text), timeout=remaining
                    )
                else:
                    hints = await external_case_hints(settings, observed_text)
            except Exception:  # noqa: BLE001 - optional hints must not skip drill-down
                hints = []
            drilldown_kwargs["external_case_hints"] = hints
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
    if evidence_sufficient:
        for name in state.investigation_context.get("skipped_collectors", []):
            if isinstance(name, str) and name:
                state.capabilities[name] = "skipped_sufficient_evidence"
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


def _investigation_evidence_sufficient(state: PipelineState) -> bool:
    """Recompute the deterministic terminal condition from typed evidence."""
    context = state.investigation_context
    if not isinstance(context, dict) or state.blackboard is None:
        return False
    ledger = context.get("hypothesis_ledger")
    if not isinstance(ledger, list):
        return False
    from app.services.investigator import _evidence_sufficiency

    decision = _evidence_sufficiency(
        ledger, state.results, state.blackboard, state.target
    )
    return bool(decision.get("sufficient"))


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
    # Resolve by execution identity, never by position: _aggregate_evidence
    # compacts result.artifacts after drill-down, so a recorded index dangles
    # or mislinks. The drill-down stamps probe_execution_ids on the artifact
    # whose observation the assessment judged.
    execution_id = str(assessment.get("execution_id") or "")
    if not execution_id:
        return ""
    for item in result.artifacts:
        if execution_id in (getattr(item, "probe_execution_ids", None) or []):
            return str(getattr(item, "evidence_id", "") or "")
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
        # The OBSERVED failure tokens (salient markers / matched alert signals).
        # `predicate` is a machine category name ("kubernetes_target_container_
        # lifecycle"); learned-knowledge keyword compilation needs what was
        # actually seen ("CreateContainerConfigError"), or a promoted symptom
        # ends up matching on fragments like "container" and "error".
        "observed_terms": [
            str(term)[:80] for term in tuple(getattr(fact, "highlights", ()) or ())[:6]
        ],
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
        # The ledger's own status is not eligibility-aware: a hypothesis can be
        # marked ``supported`` from citations this serializer then drops. Publish
        # the reconciled state so a reader never sees "supported" with nothing
        # supporting it.
        "status": (
            "testing"
            if str(item.get("status") or "") == "supported" and not evidence_for
            else str(item.get("status") or "uncertain")
        ),
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
    helm_changed = {
        str(c.get("name"))
        for c in changes
        if isinstance(c, dict)
        and (c.get("kind") or c.get("type")) == "HelmRelease"
        and c.get("name")
    }
    if not rolling:
        return {}
    implicated = set(chain or ([component] if component else []))
    hit = sorted(rolling & implicated)
    if not hit:
        return {}
    target_rollout = bool(
        component
        and component in rolling
        and (
            any(
                str(c.get("name")) == component
                and c.get("rollout")
                and c.get("corroborated", True)
                for c in changes
                if isinstance(c, dict)
            )
            or component in helm_changed
        )
    )
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
        "target_rollout": target_rollout,
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
    """Drop rollout-flavored lifecycle symptoms unless the signal is active.

    ``_promote_signature_cause`` runs after the ranker and can override its top
    family from a curated symptom keyword. Rollout symptoms match the change
    collector's generic ``mid-rollout`` text, so WITHOUT this gate a
    coincidental unrelated rollout in the alert namespace could promote
    ``platform_lifecycle_change`` over a genuine fault. Those symptoms carry
    ``requires_lifecycle_signal: true`` in failure_modes.yaml; lifecycle
    symptoms grounded in their own specific evidence (a node cordon) pass
    ungated — the family-wide drop silently unplugged the cordon playbook.
    """
    if lifecycle and lifecycle.get("active"):
        return matches
    return [
        (fam, sym)
        for fam, sym in matches
        if fam != _LIFECYCLE_FAMILY or not sym.get("requires_lifecycle_signal")
    ]


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
    seed_family = state.effective_seed_family
    if seed_family in load_family_catalog(settings.families_file).families:
        state.priors = dict(state.priors or {})
        # A correction changes investigation order, not the evidence gate: the
        # ranker applies this only to a family with typed current evidence.
        state.priors[seed_family] = max(state.priors.get(seed_family, 1.0), 1.75)
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
        evidence_eligibility=_public_evidence_eligibility(state),
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
    evidence_observed = _observed_text(
        state.results, None, eligible_support_ids=eligible_support_ids
    )
    state.xid_codes = _xid_codes_from_results(
        state.results,
        # An XID code found here is dispositive (_promote_xid_cause forces the
        # score to 10.0 with no further gate), so this must be the narrow text
        # — an operator musing "xid 79?" must not mint a hardware-fault cause.
        _alert_signature_text(request),
        eligible_support_ids=eligible_support_ids,
    )
    # TypeDB is the runtime source of truth. The version-controlled YAML matcher
    # remains only for deployments where the graph is disabled/unavailable.
    # The family universe is CLOSED (families.yaml == failure_modes == ranker
    # vocabulary). An old approved-incident ingest wrote an LLM-authored family
    # into the graph; consuming it as a curated symptom made an ungroundable
    # name ('workload_startup_image_failure') the headline over the
    # signature-clean catalog family image_pull_error and forced a harness
    # abstain (2026-07-22 ImagePullBackOff incident). Names outside the catalog
    # never reach the symptom matcher.
    graph_knowledge = _catalog_only_knowledge(state.kg_context.knowledge)
    state.failure_modes = (
        merge_runtime_failure_modes(graph_knowledge)
        if graph_knowledge
        else load_failure_modes(settings.failure_modes_file)
    )
    state.runtime_knowledge_hints = runtime_shadow_hints(state.observed)
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
    graph_counts = _catalog_only_candidate_counts(
        graph_counts, getattr(state.kg_context, "reasoning", None)
    )
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
            evidence_eligibility=_public_evidence_eligibility(state),
        )
        if isinstance(getattr(state.kg_context, "reasoning", None), dict):
            state.kg_context.reasoning["candidate_families"] = graph_counts
    # External support-case priors: exact error-signature match against the run's
    # observed evidence (available only post-collection, so this cannot run at plan
    # time). Labelled historical context — never a ranking input and never presented
    # as a verified resolution (see synthesis prompt rule + general-guidance labels).
    # The resolved component identity joins the match text: case keywords carry the
    # canonical hyphenated component token (runai-backend-thanos-receive), which an
    # operator's question ("Thanos Receive 가 OOMKilled...") never spells out, so an
    # evidence-free run would otherwise miss the one case that answers it.
    try:
        from app.services.kg_enrichment import external_case_cards

        case_entry = (
            component_for_text(load_architecture(settings.architecture_file), _alert_text(request))
            if not comp_name
            else None
        )
        case_component = comp_name or (case_entry["component"] if case_entry else "")
        case_match_text = f"{state.observed}\n{case_component}" if case_component else state.observed
        ext_cards, ext_warnings = await external_case_cards(settings, case_match_text)
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
    # database-disk known issue). ``state.alert_fuzzy`` only ever reaches the
    # self-check verify pass below (synthesize_stage), which can only REMOVE a
    # candidate, never add one, so the permissive text is safe there. The
    # actions/playbook/knowledge-base surfaces that can RENDER a fuzzy match's
    # actions into the report recompute their own fuzzy text from
    # ``_alert_signature_text`` instead — see that function's docstring.
    state.alert_fuzzy = _alert_text(request)
    known_issue_matches = match_runai_known_issues(state.known_issues, state.observed)
    symptom_matches = _gate_lifecycle_symptoms(
        match_failure_mode_symptoms(state.failure_modes, state.observed), lifecycle
    )
    state.root_cause_candidates = _promote_signature_cause(
        state.root_cause_candidates,
        state.xid_codes,
        known_issue_matches,
        symptom_matches,
        evidence_text=evidence_observed,
        known_issue_support=_known_issue_signature_support(
            state.results, known_issue_matches, eligible_support_ids
        ),
        symptom_support=_curated_symptom_signature_support(
            state.results, symptom_matches, eligible_support_ids
        ),
        typed_state=_dispositive_typed_state(state.results, eligible_support_ids),
    )
    open_world = _merge_open_world_candidates(state, state.root_cause_candidates)
    # Shadow and assist expose evidence-gated novel reasoning in context without
    # changing the headline.  Only authoritative mode may replace the final RCA.
    if getattr(settings, "open_world_rca_mode", "off") == "authoritative":
        state.root_cause_candidates = open_world
    if state.root_cause_candidates:
        top = state.root_cause_candidates[0]
        state.ranking_candidate_before_self_check = replace(top)
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


def _evidence_gap_report_line(dominant: str, count: int, total: int, language: str) -> str:
    """One line telling the operator WHY there is no cause, not just THAT there
    isn't one.

    ``analysis_summary`` already says insufficient evidence; without this an
    operator reading the report cannot tell a quiet cluster from a
    misconfigured agent. Only reached from the single call site inside
    ``_warn_on_starved_evidence`` that fires while ``final_family ==
    "insufficient_evidence"``, so a run that concluded a cause never carries
    it.
    """
    if language == "ko":
        return (
            f"- **증거가 부족한 이유**: 수집된 관측 {total}건 중 {count}건이 유효한 증거로 "
            f"이어지지 못했습니다 (가장 흔한 사유: {dominant})."
        )
    return (
        f"- **Why evidence is insufficient**: {count} of {total} observation(s) "
        f"never became usable evidence (most common reason: {dominant})."
    )


def _warn_on_starved_evidence(state: PipelineState, response: AlertAnalysisResponse) -> None:
    """Zero eligible support beside scoped positive facts is a TARGET bug.

    Eligibility answers "is this observation about the incident we are analysing".
    When it rejects every scoped positive fact on the board, the wrong thing is
    almost never the evidence — it is the identity/window the run is comparing
    against (INC-…-000001: 94 facts, 0 eligible, because the plan had moved the
    target to the ``runai`` namespace). That is invisible to
    ``rejected_evidence_links``, which only records links somebody tried to cite.

    A board that never produced a single present+scoped fact is the more common
    shape (a real run: 121 artifacts, 3 usable) and used to stay silent as an
    "honest evidence gap" even when every fact carried a ``demotion_reason``
    (see ``evidence_blackboard.EvidenceFact``) explaining exactly why it never
    became evidence. Diagnose by absence only when there is truly nothing to
    explain -- no facts at all, or facts with no identifiable reason.
    """
    facts_method = getattr(state.blackboard, "facts", None)
    if not callable(facts_method):
        return
    try:
        all_facts = list(facts_method())
    except Exception:  # noqa: BLE001 - a diagnostic signal is never fatal
        return
    usable = [
        fact
        for fact in all_facts
        if str(getattr(fact, "polarity", "")) == "present"
        and str(getattr(fact, "coverage", "")) == "scoped"
    ]
    if not usable:
        demoted = [fact for fact in all_facts if getattr(fact, "demotion_reason", "")]
        if not demoted:
            return  # honest gap: nothing to explain
        reasons = Counter(getattr(fact, "demotion_reason", "") for fact in demoted)
        dominant, count = reasons.most_common(1)[0]
        message = (
            f"no observation ever reached present+scoped: {count} of {len(all_facts)} "
            f"fact(s) were demoted, most commonly ({dominant})"
        )
        _log.warning("evidence: %s", message)
        response.warnings = sorted(set(response.warnings) | {message})
        response.analysis_detail = _insert_before_appendix(
            response.analysis_detail,
            _evidence_gap_report_line(
                dominant, count, len(all_facts), getattr(state.settings, "language", "en")
            ),
        )
        return
    eligibility = _blackboard_eligibility(state)
    if any(getattr(item, "support", False) for item in eligibility.values()):
        return
    reasons = Counter(
        str(getattr(eligibility.get(str(getattr(fact, "fact_id", ""))), "reason", ""))
        for fact in usable
    )
    dominant = next((reason for reason, _ in reasons.most_common() if reason), "ineligible")
    message = (
        f"no observation was eligible to support a cause: all {len(usable)} scoped "
        f"positive fact(s) were rejected ({dominant}) — check the analysis target "
        f"identity, not the evidence"
    )
    _log.warning("evidence: %s", message)
    response.warnings = sorted(set(response.warnings) | {message})


def _warn_on_discarded_support(state: PipelineState, response: AlertAnalysisResponse) -> None:
    """Concluding nothing WHILE discarding support links is a wiring bug.

    ``rejected_evidence_links`` was recorded in the v3 trace and read by nobody,
    so a run could spend ten minutes reporting "no evidence" about evidence it
    was holding (INC-…-000001: every runai-test1 observation dropped because the
    plan had moved the target to the ``runai`` namespace).  Only fires when the
    run concluded nothing — an ordinary run with a real cause stays silent.
    """
    trace = state.investigation_context.get("reasoning_trace_v3")
    links = trace.get("rejected_evidence_links") or [] if isinstance(trace, dict) else []
    rejected = [
        item for item in links if isinstance(item, dict) and item.get("role") == "support"
    ]
    if not rejected:
        return
    reasons = sorted({str(item.get("reason") or "") for item in rejected if item.get("reason")})
    message = (
        f"concluded without a cause while discarding {len(rejected)} support link(s) "
        f"as ineligible: {', '.join(reasons[:2])}"
    )
    _log.warning("evidence: %s", message)
    response.warnings = sorted(set(response.warnings) | {message})


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
    known = (
        {str(item.get("hypothesis_id") or "") for item in hypotheses if isinstance(item, dict)}
        if isinstance(hypotheses, list)
        else set()
    )
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
            state.self_check_confidence_before = state.root_cause_candidates[0].confidence
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
            state.self_check_confidence_after = state.root_cause_candidates[0].confidence
            state.progress.emit(
                "self_check",
                "Self-check complete",
                refuted=state.self_check_refuted,
                caveat=state.self_check_caveat,
                next_check=state.self_check_next,
            )
    return state


async def _resolve_refuted_top_from_existing_candidates(state: PipelineState) -> None:
    """Fail over to an already-ranked alternative and self-check it immediately.

    A refuted family must never reach synthesis merely because the investigation
    loop is disabled, out of budget, or unable to find a new probe.  Alternatives
    are still hypotheses, so each is checked before it can become the headline.
    """
    if not state.self_check_refuted or not state.root_cause_candidates:
        return
    from app.services.self_check import refute_top_cause

    previous = state.root_cause_candidates[0]
    alternatives = [
        candidate
        for candidate in state.root_cause_candidates[1:]
        if candidate.family != "insufficient_evidence"
    ]
    last_caveat = state.self_check_caveat
    last_next = state.self_check_next
    for candidate in alternatives:
        kwargs: dict[str, object] = {"plan": state.investigation_context}
        if _accepts_keyword(refute_top_cause, "evidence_eligibility"):
            kwargs["evidence_eligibility"] = _public_evidence_eligibility(state)
        check = await refute_top_cause(
            state.settings,
            candidate,
            state.results,
            **kwargs,
        )
        if not isinstance(check, dict):
            continue
        calibrated = check.get("confidence")
        if calibrated in ("low", "medium", "high"):
            candidate.confidence = calibrated
        last_caveat = str(check.get("caveat") or "").strip()
        last_next = str(check.get("next_check") or "").strip()
        if not bool(check.get("refuted")):
            state.root_cause_candidates = [
                candidate,
                *[
                    item
                    for item in state.root_cause_candidates
                    if item is not candidate and item is not previous
                ],
                replace(previous, confidence="low"),
            ]
            state.self_check_caveat = last_caveat
            state.self_check_next = last_next
            state.self_check_refuted = False
            state.self_check_confidence_after = candidate.confidence
            return

    state.root_cause_candidates = [
        RankedCause(
            family="insufficient_evidence",
            confidence="low",
            score=0.0,
            rationale=["All ranked candidates were refuted by scoped evidence."],
        ),
        replace(previous, confidence="low"),
        *[replace(candidate, confidence="low") for candidate in alternatives],
    ]
    state.self_check_caveat = last_caveat
    state.self_check_next = last_next
    state.self_check_refuted = True
    state.self_check_confidence_after = "low"


async def _self_check_if_top_changed(state: PipelineState, previous_family: str) -> None:
    current = state.root_cause_candidates[0] if state.root_cause_candidates else None
    if current is None or current.family in {"", "insufficient_evidence", previous_family}:
        return
    from app.services.self_check import refute_top_cause

    confidence_before = current.confidence
    kwargs: dict[str, object] = {"plan": state.investigation_context}
    if _accepts_keyword(refute_top_cause, "evidence_eligibility"):
        kwargs["evidence_eligibility"] = _public_evidence_eligibility(state)
    check = await refute_top_cause(state.settings, current, state.results, **kwargs)
    if not isinstance(check, dict):
        return
    calibrated = check.get("confidence")
    if calibrated in ("low", "medium", "high"):
        current.confidence = calibrated
    state.self_check_caveat = str(check.get("caveat") or "").strip()
    state.self_check_next = str(check.get("next_check") or "").strip()
    state.self_check_refuted = bool(check.get("refuted"))
    state.self_check_confidence_before = confidence_before
    state.self_check_confidence_after = current.confidence
    await _resolve_refuted_top_from_existing_candidates(state)


def _confidence_diagnostics(
    state: PipelineState,
    *,
    harness: Mapping[str, object] | None = None,
    candidate_before_harness: RankedCause | None = None,
) -> dict[str, Any]:
    top = state.root_cause_candidates[0] if state.root_cause_candidates else None
    ranked = state.ranking_candidate_before_self_check or candidate_before_harness or top
    return {
        "schema_version": 1,
        "ranking_candidate": ranked.as_dict() if ranked is not None else None,
        "pre_harness_candidate": (
            candidate_before_harness.as_dict()
            if candidate_before_harness is not None
            else None
        ),
        "final_candidate": top.as_dict() if top is not None else None,
        "self_check": {
            "confidence_before": state.self_check_confidence_before,
            "confidence_after": state.self_check_confidence_after,
            "changed": bool(
                state.self_check_confidence_before
                and state.self_check_confidence_after
                and state.self_check_confidence_before != state.self_check_confidence_after
            ),
            "refuted": state.self_check_refuted,
            "caveat": state.self_check_caveat,
            "next_check": state.self_check_next,
        },
        "harness": dict(harness or {}),
    }


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
    verified_top_before = (
        state.root_cause_candidates[0].family if state.root_cause_candidates else ""
    )
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
                # The self-check prompt tells the LLM "an explicit positive
                # signature [in the declared alert] may support a match" — the
                # narrow text, or operator/runbook prose could talk it out of
                # refuting a match that should never have been made.
                verify_known_kwargs["declared_alert"] = _alert_signature_text(request)
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
                # Same reasoning as verify_known_issues above: this text can
                # talk the LLM out of refuting a match, so it must be narrow.
                verify_match_kwargs["declared_alert"] = _alert_signature_text(request)
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
    await _self_check_if_top_changed(state, verified_top_before)
    await _refresh_similar_incidents_from_evidence(settings, request, state)
    state.summary = _summary_from(
        request,
        state.results,
        state.root_cause_candidates,
        state.failure_modes,
        language=getattr(settings, "language", "en"),
        eligible_support_ids=eligible_support_ids,
    )
    playbook_fallback = load_troubleshooting_cases(settings.troubleshooting_cases_file)
    state.detail = _detail_from(
        request,
        state.results,
        state.missing,
        state.agent_souls,
        state.root_cause_candidates,
        state.kg_context.as_dict(),
        plan,
        state.graph_fixes,
        knowledge=ReportKnowledge(
            failure_modes=state.failure_modes,
            known_issues=state.known_issues,
            components=load_architecture(settings.architecture_file),
            cases=playbook_fallback,
            language=getattr(settings, "language", "en"),
            masker=state.masker,
        ),
        eligible_support_ids=eligible_support_ids,
        self_check_next=state.self_check_next,
        runtime_knowledge_hints=state.runtime_knowledge_hints,
        xid_codes=state.xid_codes,
    )
    # Restore the explicitly non-diagnostic guide when the RCA had no supported
    # action and the report builder did not already carry one.
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
                        component=getattr(plan, "component", "") if plan else "",
                        component_source=getattr(plan, "component_source", "") if plan else "",
                        components=load_architecture(settings.architecture_file),
                        matched_alert=getattr(plan, "matched_alert", None) if plan else None,
                        families=_plan_families(plan),
                        case_cards=state.kg_context.case_cards,
                    ),
                ]
            )
            state.detail = _append_general_guidance(state.detail, block)

    # Self-check caveat (optional hook) + re-analysis note — inserted BEFORE the
    # appendix so the document reads problem -> cause -> actions -> checks -> appendix.
    self_check_lines = [text for text in (state.self_check_caveat, state.reanalysis_note) if text]
    if state.self_check_next and state.self_check_next not in state.detail:
        next_label = "다음 확인" if getattr(settings, "language", "en") == "ko" else "Next check"
        self_check_lines.append(f"- **{next_label}**: {state.self_check_next}")
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
                settings,
                state.missing,
                plan,
                state.target,
                state.self_check_next,
                _executed_evidence_queries(state.artifacts),
                _held_evidence_summaries(state.artifacts, eligible_support_ids),
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

    # Korean localization runs LAST so the Self-Check, operator-question and
    # general-guidance blocks appended above are localized too — they used to be
    # added after the translator and stayed English.
    if getattr(settings, "language", "en") == "ko" and llm_configured(
        settings, settings.llm_model_synthesis
    ):
        state.synthesis_status = "running"
        synthesis_diagnostics: list[str] = []
        started_at = time.monotonic()
        # Every batch that succeeded is kept: a partially localized report beats
        # discarding good Korean because one batch failed.
        state.detail, untranslated = await _translate_report_lines_ko(
            settings, state.detail, synthesis_diagnostics
        )
        # Warnings are a flat list, not part of the markdown document above --
        # without this they shipped English verbatim in an otherwise-Korean
        # report (a real run: 9/9 warnings stayed English).
        state.warnings, untranslated_warnings = await _translate_warnings_ko(
            settings, state.warnings, synthesis_diagnostics
        )
        untranslated += untranslated_warnings
        state.synthesis_duration = round(time.monotonic() - started_at, 3)
        if untranslated:
            state.synthesis_status = "failed"
            state.synthesis_error = _short_sentence(
                synthesis_diagnostics[-1]
                if synthesis_diagnostics
                else f"{untranslated} report line(s) were left untranslated",
                limit=500,
            )
            state.quality = "degraded"
            state.warnings.append(f"한국어 LLM synthesis 실패: {state.synthesis_error}")
        else:
            state.synthesis_status = "completed"

    affected_pods = _affected_pods_from_results(state.results)
    specific_cause = _specific_cause_statement(
        state.root_cause_candidates[0] if state.root_cause_candidates else None,
        state.results,
        eligible_support_ids,
        language=getattr(settings, "language", "en"),
        request=request,
    )

    state.response = AlertAnalysisResponse(
        status="ok",
        terminal_reason=None,
        thread_ts=request.thread_ts,
        analysis=state.detail,
        analysis_summary=state.summary,
        analysis_detail=state.detail,
        analysis_type=request.analysis_type or request.alert.status or "firing",
        analysis_quality=state.quality,
        root_cause_family=(
            state.root_cause_candidates[0].family if state.root_cause_candidates else ""
        ),
        specific_cause=specific_cause,
        missing_data=state.missing,
        warnings=state.warnings,
        capabilities=state.capabilities,
        affected_pods=affected_pods,
        context={
            "target": state.target.__dict__,
            "nemo_runtime": "enabled" if state.runtime_label == "enabled" else "fallback",
            "synthesis": {
                "status": state.synthesis_status,
                **({"error": state.synthesis_error} if state.synthesis_error else {}),
                **(
                    {"duration_seconds": state.synthesis_duration}
                    if state.synthesis_duration is not None
                    else {}
                ),
                "model": settings.llm_model_synthesis or settings.llm_model,
                "max_tokens": settings.llm_synthesis_max_tokens,
            },
            "occurrence_count": request.occurrence_count,
            "occurrence_pods": request.occurrence_pods,
            "seed_family": request.seed_family,
            "effective_seed_family": state.effective_seed_family,
            "effective_seed_provenance": state.effective_seed_provenance,
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
            "specific_cause": specific_cause,
            "confidence_diagnostics": _confidence_diagnostics(state),
            "knowledge_base": state.kg_context.public_dict(),
            "ontology_reasoning": state.kg_context.as_dict().get("reasoning", {}),
            "plan": plan.as_dict(),
            "hypothesis_ledger": state.investigation_context.get("hypothesis_ledger"),
            "investigation": state.investigation_context,
            "reasoning_trace_v2": state.investigation_context.get("reasoning_trace_v2", {}),
            "reasoning_trace_v3": state.investigation_context.get("reasoning_trace_v3", {}),
            **({"open_world_candidates": [{
                "family": candidate.family, "mechanism": candidate.mechanism,
                "mechanism_fingerprint": candidate.mechanism_fingerprint,
                "confidence": candidate.confidence, "hypothesis_id": candidate.hypothesis_id,
                "support_evidence_ids": candidate.support_evidence_ids,
                "independent_source_groups": candidate.independent_source_groups,
            } for candidate in state.open_world_candidates]} if state.open_world_candidates else {}),
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


# Generic state alerts describe a shared symptom (pod not ready, container
# waiting, replica mismatch), not a cause. Concluding a specific family for
# them requires target-verified evidence — enforced by the harness gate
# generic_alert_without_target_evidence.
GENERIC_STATE_ALERTS = frozenset(
    {
        "KubePodNotReady",
        "KubeContainerWaiting",
        "KubeDeploymentReplicasMismatch",
        "KubeDeploymentRolloutStuck",
        "KubeDaemonSetRolloutStuck",
        "RunaiDaemonSetRolloutStuck",
    }
)


def _final_conclusion_line(final_family: str, settings: Settings) -> str:
    """R1: restate the FINAL published family once more, placed as the very
    last content before the appendix, so a later harness decision that moved
    the headline off a reanalysis round's own conclusion cannot leave that
    round's "결론: X" / "conclusion: X" line as the last thing the operator
    reads. The per-round trail above it is left intact -- it is an honest
    history of how the run got here, not a wrong statement to scrub."""
    if getattr(settings, "language", "en") == "ko":
        return f"- **최종 결론** (위 재분석 메모를 대체함): {final_family}"
    return f"- **Final conclusion** (supersedes the re-analysis note above): {final_family}"


async def harness_stage(state: PipelineState) -> PipelineState:
    """Validate the already-synthesized RCA and make bounded safe repairs."""
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
    candidate_before_harness = (
        replace(state.root_cause_candidates[0]) if state.root_cause_candidates else None
    )
    if not state.settings.enable_rca_output_harness:
        response.context["harness"] = {
            "rubric_version": "1",
            "status": "disabled",
            "repair_attempts": 0,
        }
        response.context["confidence_diagnostics"] = _confidence_diagnostics(
            state,
            harness={"status": "disabled"},
            candidate_before_harness=candidate_before_harness,
        )
        response.context["analysis_hash"] = analysis_hash(response)
        return state

    repairs = 0
    verdict = evaluate(
        response,
        state.results,
        state.root_cause_candidates,
        next_check=state.self_check_next,
        evidence_eligibility=_public_evidence_eligibility(state),
        known_issues=state.known_issues,
        generic_state_alert=state.target.alert_name in GENERIC_STATE_ALERTS,
    )
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
            known_issues=state.known_issues,
            generic_state_alert=state.target.alert_name in GENERIC_STATE_ALERTS,
        )

    status = "pass"
    if verdict.failed_gates:
        # abstain() replaces the whole document, which would leave a gated run
        # with LESS non-diagnostic help than a zero-evidence one. The guide is
        # explicitly not a conclusion, so a failed gate is no reason to drop it.
        language = getattr(state.settings, "language", "en")
        carried_guidance = _general_guidance_block(response.analysis_detail, language)
        abstain(
            response,
            state.root_cause_candidates,
            verdict,
            historical_reanalysis=_is_resolved_reanalysis(state.request),
            language=language,
            next_check=state.self_check_next,
        )
        if not carried_guidance:
            # A gated run that HAD eligible evidence never emitted a guide —
            # its report carried cause-specific sections instead, and abstain
            # just replaced all of them with the stub. Build the guide now:
            # the bare stub leaves the operator with less help than a
            # zero-evidence run (live case: INC-1785128597…, a 318-char report).
            carried_guidance = _abstain_guidance_block(state, language)
        if carried_guidance:
            response.analysis_detail = _append_general_guidance(
                response.analysis_detail, carried_guidance
            )
            response.analysis = response.analysis_detail
        # Re-scoring the REWRITTEN document is right — the abstain stub is not
        # the document that was gated. Its gate map is not: every gate in
        # evaluate() is guarded by ``not insufficient``, and abstain() just set
        # the family to insufficient_evidence, so a fresh verdict reports every
        # hard gate as False. Persisting that erased WHY the run abstained, and
        # the backend's knowledge-promotion veto (harnessHardGatesPassed) reads
        # exactly this map — it could only ever fail on a missing/empty harness,
        # never on a real violation. Keep the score from the rewritten document
        # and the gates from the document that actually failed.
        gated_verdict = verdict
        verdict = replace(
            evaluate(
                response,
                state.results,
                state.root_cause_candidates,
                next_check=state.self_check_next,
                evidence_eligibility=_public_evidence_eligibility(state),
                known_issues=state.known_issues,
                generic_state_alert=state.target.alert_name in GENERIC_STATE_ALERTS,
            ),
            gates=dict(gated_verdict.gates),
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
    response.specific_cause = _specific_cause_statement(
        top,
        state.results,
        _eligible_support_ids_for_output(state),
        language=getattr(state.settings, "language", "en"),
        request=state.request,
    )
    # The harness is the final authority on the headline family.  Reconcile the
    # short summary after that decision so a demotion cannot leave a confident
    # mechanism sentence beside ``insufficient_evidence``.
    final_family = response.root_cause_family
    if final_family == "insufficient_evidence":
        _warn_on_discarded_support(state, response)
        _warn_on_starved_evidence(state, response)
        response.analysis_summary = _short_sentence(
            _ranked_root_cause_statement(
                [RankedCause("insufficient_evidence", "low", 0.0)],
                state.request,
                language=getattr(state.settings, "language", "en"),
            ),
            limit=280,
        )
    elif top is not None:
        response.analysis_summary = _summary_from(
            state.request,
            state.results,
            state.root_cause_candidates,
            state.failure_modes,
            language=getattr(state.settings, "language", "en"),
            eligible_support_ids=_eligible_support_ids_for_output(state),
        )
    state.summary = response.analysis_summary
    # R1: the Self-Check section was already written into analysis_detail (in
    # synthesize_stage) from state.reanalysis_note -- a per-round trail that
    # can go stale by the time the harness finishes: a later repair/abstain
    # here, or the refuted-top fallback before synthesis, can change the
    # headline AFTER that trail's last line asserted a different conclusion
    # (real report: headline insufficient_evidence, Self-Check's last line
    # "...결론: observability_accuracy"). The trail itself stays -- it is an
    # honest per-round history -- but the last thing the operator reads must
    # not contradict the headline.
    if state.reanalysis_note_family and state.reanalysis_note_family != final_family:
        response.analysis_detail = _insert_before_appendix(
            response.analysis_detail, _final_conclusion_line(final_family, state.settings)
        )
    response.context["root_cause_candidates"] = [
        candidate.as_dict() for candidate in state.root_cause_candidates
    ]
    response.context["top_root_cause"] = top.as_dict() if top else None
    response.context["specific_cause"] = response.specific_cause
    harness_payload = payload(verdict, status=status, repairs=repairs)
    response.context["harness"] = harness_payload
    response.context["confidence_diagnostics"] = _confidence_diagnostics(
        state,
        harness={
            "status": status,
            "overall_score": verdict.score,
            "hard_gates": verdict.gates,
            "repair_attempts": repairs,
            "confidence_before": (
                candidate_before_harness.confidence if candidate_before_harness else ""
            ),
            "confidence_after": top.confidence if top else "",
        },
        candidate_before_harness=candidate_before_harness,
    )
    response.context["analysis_hash"] = analysis_hash(response)
    response.analysis = response.analysis_detail
    state.response = response
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
    await _resolve_refuted_top_from_existing_candidates(state)

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
        # Each investigator pass starts a fresh ledger. Carry prior evidence by
        # family so a reused local ID (for example, H1) cannot erase evidence
        # gathered for a different family in an earlier pass.
        state.investigation_context = _merge_reanalysis_context(
            state.investigation_context, outcome.investigation_context
        )
        state.reanalysis_fresh_support_families = outcome.fresh_support_families
        state.root_cause_candidates = outcome.candidates
        state.ranking_candidate_before_self_check = outcome.ranking_candidate
        state.self_check_confidence_before = (
            outcome.ranking_candidate.confidence if outcome.ranking_candidate else ""
        )
        state.self_check_confidence_after = (
            outcome.candidates[0].confidence if outcome.candidates else ""
        )
        state.self_check_caveat = outcome.caveat
        state.reanalysis_note = _append_reanalysis_note(state.reanalysis_note, outcome.note)
        if outcome.note:
            state.reanalysis_note_family = (
                outcome.candidates[0].family if outcome.candidates else "insufficient_evidence"
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
        or bool(
            top.confidence == "medium"
            and getattr(state, "self_check_caveat", "")
            and getattr(state, "self_check_next", "")
        )
    )


def _next_reanalysis_target(
    state: PipelineState, attempted: set[str]
) -> _ReanalysisTarget | None:
    top = state.root_cause_candidates[0] if state.root_cause_candidates else None
    refuted_family = top.family if top and state.self_check_refuted else ""
    refuted_mechanism = top.mechanism if top and state.self_check_refuted else ""
    excluded = {
        family
        for family in (*attempted, refuted_family, "insufficient_evidence")
        if family
    }

    for family in state.reanalysis_fresh_support_families:
        if family not in excluded:
            return _ReanalysisTarget(
                family,
                "targeted follow-up for newly collected eligible evidence",
                refuted_family,
                refuted_mechanism,
                not state.reanalysis_note,
            )

    if state.self_check_refuted:
        for candidate in state.root_cause_candidates[1:]:
            if candidate.family not in excluded:
                return _ReanalysisTarget(
                    candidate.family,
                    "re-analysis after the previous conclusion was refuted",
                    refuted_family,
                    refuted_mechanism,
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
            evidence_eligibility=_public_evidence_eligibility(state),
        ):
            if candidate.family not in excluded:
                return _ReanalysisTarget(
                    candidate.family,
                    "re-analysis after the previous conclusion was refuted",
                    refuted_family,
                    refuted_mechanism,
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


def _merge_reanalysis_context(
    previous: Mapping[str, object], current: Mapping[str, object]
) -> dict[str, Any]:
    """Carry typed ledger links across fresh investigator contexts by family.

    Investigator-local hypothesis IDs restart on each bounded invocation. The
    family is therefore the stable identity for cross-round evidence carry-over;
    deduplicating IDs preserves the ledger without inflating support counts.
    """
    merged = dict(current)
    previous_ledger = previous.get("hypothesis_ledger")
    current_ledger = current.get("hypothesis_ledger")
    if not isinstance(previous_ledger, list):
        return merged
    if not isinstance(current_ledger, list):
        merged["hypothesis_ledger"] = [
            dict(item) for item in previous_ledger if isinstance(item, dict)
        ]
        return merged

    ledger = [dict(item) for item in current_ledger if isinstance(item, dict)]
    by_family = {
        str(item.get("family") or "").strip(): item
        for item in ledger
        if str(item.get("family") or "").strip()
    }
    used_ids = {str(item.get("id") or "").strip() for item in ledger}
    for prior in previous_ledger:
        if not isinstance(prior, dict):
            continue
        family = str(prior.get("family") or "").strip()
        if not family:
            continue
        item = by_family.get(family)
        if item is None:
            item = dict(prior)
            hypothesis_id = str(item.get("id") or "").strip()
            if hypothesis_id in used_ids:
                item["id"] = f"{hypothesis_id}:{family}"
            used_ids.add(str(item.get("id") or "").strip())
            ledger.append(item)
            by_family[family] = item
            continue
        for field_name in ("evidence_for", "evidence_against"):
            values = [
                value
                for source in (prior.get(field_name), item.get(field_name))
                for value in _ledger_evidence_values(source)
            ]
            if values:
                item[field_name] = list(dict.fromkeys(values))
    merged["hypothesis_ledger"] = ledger
    return merged


def _ledger_evidence_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _fresh_eligible_support_families(
    fresh_results: list[CollectorResult], evidence_eligibility: Mapping[str, object]
) -> tuple[str, ...]:
    """Map newly collected, eligible artifacts to catalog families.

    ``artifact_supports_family`` is the ranker's own typed semantic matcher, so
    unknown or partially scoped artifacts cannot influence investigation order.
    """
    families: list[str] = []
    for result in fresh_results:
        for artifact in result.artifacts:
            evidence_id = str(getattr(artifact, "evidence_id", "") or "")
            eligibility = evidence_eligibility.get(evidence_id)
            permits = getattr(eligibility, "permits", None)
            if not callable(permits) or not permits("support"):
                continue
            for family in FAMILIES:
                if family not in families and artifact_supports_family(family, artifact):
                    families.append(family)
    return tuple(families)


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


def _append_reanalysis_note(existing: str, note: str) -> str:
    return (
        existing
        if not note or note in existing.split("\n\n")
        else "\n\n".join((existing, note)).strip()
    )


def _artifact_signature(artifact: object) -> tuple[object, ...]:
    return (
        getattr(artifact, "title", ""),
        getattr(artifact, "status", ""),
        getattr(artifact, "summary", ""),
        _json_fingerprint(getattr(artifact, "result", None)),
    )


def _fresh_collector_results(
    previous: list[CollectorResult], current: list[CollectorResult]
) -> list[CollectorResult]:
    """Return only artifacts added by a continuation-style investigation."""
    prior_by_agent = {item.agent: item for item in previous}
    fresh: list[CollectorResult] = []
    for item in current:
        prior = prior_by_agent.get(item.agent)
        prior_artifacts = {
            (
                str(getattr(card, "agent", "") or ""),
                str(getattr(card, "type", "") or ""),
                str(getattr(card, "query", "") or ""),
                str(getattr(card, "title", "") or ""),
                _json_fingerprint(getattr(card, "result", None)),
            )
            for card in (prior.artifacts if prior is not None else [])
        }
        added = [
            card
            for card in item.artifacts
            if (
                str(getattr(card, "agent", "") or ""),
                str(getattr(card, "type", "") or ""),
                str(getattr(card, "query", "") or ""),
                str(getattr(card, "title", "") or ""),
                _json_fingerprint(getattr(card, "result", None)),
            )
            not in prior_artifacts
        ]
        if added:
            fresh.append(replace(item, artifacts=added))
    return fresh


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
        if _accepts_keyword(investigate, "blackboard"):
            investigation_kwargs["blackboard"] = state.blackboard
        if _accepts_keyword(investigate, "query_memory"):
            investigation_kwargs["query_memory"] = state.query_memory
        if _accepts_keyword(investigate, "deadline_monotonic"):
            investigation_kwargs["deadline_monotonic"] = _evidence_deadline_monotonic(state)
        continues_existing_evidence = _accepts_keyword(investigate, "initial_evidence")
        if continues_existing_evidence:
            # Re-analysis is a continuation of this run, not a fresh scrape.
            # The investigator may add a genuinely new scoped read, but it must
            # remember the Pod/Event/Node observations already on the board.
            investigation_kwargs["initial_evidence"] = state.results
        investigated, re_context = await investigate(
            state.settings,
            state.target,
            state.collectors,
            replan,
            kg_dict,
            min(state.settings.max_reanalysis_steps, state.settings.max_investigation_steps),
            **investigation_kwargs,
        )
        fresh = (
            _fresh_collector_results(state.results, investigated)
            if continues_existing_evidence
            else investigated
        )
        merged = {result.agent: result for result in state.results}
        for result in investigated:
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
            fresh_support_families = _fresh_eligible_support_families(
                fresh, evidence_eligibility
            )
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
            evidence_eligibility=evidence_eligibility,
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
        evidence_observed = _observed_text(
            merged_results, None, eligible_support_ids=eligible_support_ids
        )
        known_issue_matches = match_runai_known_issues(state.known_issues, observed)
        symptom_matches = _gate_lifecycle_symptoms(
            match_failure_mode_symptoms(state.failure_modes, observed), lifecycle
        )
        candidates = _promote_signature_cause(
            candidates,
            _xid_codes_from_results(
                merged_results,
                # Same reasoning as rank_stage: XID promotion is dispositive and
                # ungated, so the re-rank must use the narrow (signature) text too.
                _alert_signature_text(state.request),
                eligible_support_ids=eligible_support_ids,
            ),
            known_issue_matches,
            symptom_matches,
            evidence_text=evidence_observed,
            known_issue_support=_known_issue_signature_support(
                merged_results, known_issue_matches, eligible_support_ids
            ),
            symptom_support=_curated_symptom_signature_support(
                merged_results, symptom_matches, eligible_support_ids
            ),
            typed_state=_dispositive_typed_state(merged_results, eligible_support_ids),
        )
        candidates = _exclude_refuted_reanalysis_candidates(candidates, target)
        skip_self_check = _evidence_budget_exceeded(state)
        if skip_self_check:
            # The targeted probes already completed and were normalized/ranked.
            # Preserve that fresh evidence; only the optional LLM self-check is
            # skipped so final synthesis can use the last bounded observation.
            _record_evidence_budget_stop(state, "post-reanalysis self-check")
        ranking_candidate = replace(candidates[0]) if candidates else None
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
            note = f"낮은 확신/증거 공백 때문에 추가 조사를 수행했습니다 → 결론: {new_family}"
        else:
            note = (
                "A targeted investigation pass was performed for low confidence "
                f"or evidence gaps → revised conclusion: {new_family}."
            )
        return _ReanalysisOutcome(
            merged_results,
            candidates,
            ranking_candidate,
            re_context if isinstance(re_context, dict) else {},
            caveat,
            note,
            refuted,
            next_check,
            fresh_support_families,
        )
    except Exception:  # noqa: BLE001 - re-analysis is best-effort; keep 1st result
        return None


def _exclude_refuted_reanalysis_candidates(
    candidates: list[RankedCause], target: _ReanalysisTarget
) -> list[RankedCause]:
    """Do not let an unchanged self-refuted family/mechanism win again."""
    if not target.refuted_family:
        return candidates
    refuted_mechanism = " ".join(target.refuted_mechanism.casefold().split())
    kept = [
        candidate
        for candidate in candidates
        if not (
            candidate.family == target.refuted_family
            and (
                not refuted_mechanism
                or " ".join(candidate.mechanism.casefold().split()) == refuted_mechanism
            )
        )
    ]
    if kept:
        return kept
    return [
        RankedCause(
            family="insufficient_evidence",
            confidence="low",
            score=0.0,
            rationale=[
                "The re-analysis conclusion repeated a family/mechanism "
                "that the self-check refuted."
            ],
        )
    ]


_HANGUL_RE = re.compile(r"[가-힣]")
_LIST_PREFIX_RE = re.compile(r"^(\s*(?:[-*+]|\d+[.)])\s+)")
_BACKTICK_SPAN_RE = re.compile(r"`[^`]*`")
# Double quotes only. English possessives ("the Master's spec") make apostrophes
# pair across unrelated words and would demand nonsense substrings verbatim.
_QUOTED_SPAN_RE = re.compile(r"\"[^\"]+\"")
# camelCase/PascalCase API vocabulary, and dotted/underscored/colon-separated
# identifiers. Two guards keep ordinary text out, both found by replaying the
# real knowledge base through this: anchoring at a token boundary (unanchored,
# "NVLink" demanded "VLink" and "GPUs" demanded "PUs"), and requiring two
# lowercase characters per hump (else "IDs"/"IPs" were demanded verbatim and a
# translation that correctly wrote "ID" was rejected). Plain hyphenated or
# slashed English ("cross-namespace", "and/or") is intentionally NOT matched.
_IDENTIFIER_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"[A-Za-z][a-z0-9]*(?:[A-Z][a-z0-9]{2,})+"
    r"|[A-Za-z0-9]+(?:[._:][A-Za-z0-9]+)+"
    r")"
)
_PROSE_ABBREVIATIONS = frozenset({"e.g", "i.e", "vs", "etc"})

_TRANSLATOR_SYSTEM = (
    "당신은 기술 문서 전문 번역가입니다. 입력 JSON은 이미 완성된 장애 분석 보고서의 "
    "영어 문장들이며, 키는 줄 번호입니다. 내용을 판단·수정·추가·삭제하지 말고 각 "
    "문장을 자연스러운 한국어로 번역하세요.\n"
    "규칙:\n"
    "- 모든 키를 빠짐없이 포함하고, 키는 바꾸지 마세요.\n"
    "- 백틱(`)이나 따옴표로 감싼 부분은 한 글자도 바꾸지 말고 그대로 두세요.\n"
    "- pod/네임스페이스/노드/알림 이름, 명령어, 에러 문자열, 코드, URL, 라벨 값, "
    "그리고 CreateContainerConfigError·secretKeyRef·nvidia.com/gpu 같은 API 용어는 "
    "번역하거나 표기를 바꾸지 말고 원문 그대로 두세요.\n"
    "- 굵기(**) 같은 마크다운 표기는 원문 위치 그대로 유지하세요.\n"
    "- 문장은 정중한 경어체로 끝맺으세요(예: '~하세요', '~합니다'). "
    "'~하라', '~해라' 같은 명령형 반말은 쓰지 마세요. 큐레이션된 한국어 문장이 "
    "경어체이므로 번역문의 어체가 다르면 한 보고서 안에서 문체가 섞입니다.\n"
    "- 출력에는 한국어와 보존 대상 원문 토큰(명령어·에러 문자열·API 용어)만 "
    "쓰세요. 일본어(히라가나·가타카나·일본식 한자어)나 중국어 등 다른 언어 "
    "문자가 한 글자라도 섞이면 안 됩니다.\n"
    '- JSON 객체 하나로만, 코드펜스 없이 응답하세요: {"12": "<한국어>", ...}'
)


def _translatable_report_lines(detail: str) -> dict[str, str]:
    """Map line index -> English prose that needs localizing.

    Structure is never sent to the LLM: headings, fenced blocks (which include
    the Alert Labels JSON), commands, identifiers and already-Korean lines are
    skipped, so a translation can only ever change sentence surface — never the
    report's conclusions, ordering, or executable text.
    """
    pending: dict[str, str] = {}
    fenced = False
    for index, line in enumerate(detail.split("\n")):
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced or not stripped or stripped.startswith("#"):
            continue
        if _HANGUL_RE.search(stripped):
            continue
        prefix = _LIST_PREFIX_RE.match(line)
        text = line[prefix.end():].strip() if prefix else stripped
        if not text or _COMMAND_ONLY_ACTION.match(text):
            continue
        # Punctuation/code-only lines carry no prose to localize.
        prose = _BACKTICK_SPAN_RE.sub("", re.sub(r"https?://\S+", "", text))
        if len(re.findall(r"[A-Za-z]{3,}", prose)) < 2:
            continue
        pending[str(index)] = text
    return pending


def _apply_line_translations(detail: str, translations: dict[str, str]) -> str:
    lines = detail.split("\n")
    for key, translated in translations.items():
        index = int(key)
        prefix = _LIST_PREFIX_RE.match(lines[index])
        lines[index] = (prefix.group(1) if prefix else "") + translated
    return "\n".join(lines)


def _preserved_spans(source: str) -> list[str]:
    """Substrings a translation must carry through byte-for-byte.

    Asking the model nicely is not enough: an operator acts on these literally.
    Quoted spans cover the object names the mechanism sentence extracts
    (``Secret 'app-secret'``, ``secret "app-secret" not found``); the token
    classes cover unquoted API vocabulary (``CreateContainerConfigError``,
    ``secretKeyRef``, ``nvidia.com/gpu``). Both classes are deliberately narrow
    so ordinary English — ``SAME``, ``cross-namespace``, ``and/or`` — is still
    free to become Korean.
    """
    spans = _BACKTICK_SPAN_RE.findall(source)
    spans += _QUOTED_SPAN_RE.findall(source)
    spans += [
        token
        for token in _IDENTIFIER_TOKEN_RE.findall(source)
        if token.casefold() not in _PROSE_ABBREVIATIONS
    ]
    return list(dict.fromkeys(spans))


# Hiragana, katakana (incl. halfwidth), and the katakana middle dot: any hit
# means the "Korean" line leaked Japanese. CJK ideographs are NOT matched —
# preserved error strings may legitimately carry them.
_JAPANESE_KANA = re.compile(r"[぀-ヿｦ-ﾟ]")


def _valid_line_translation(source: str, translated: object) -> bool:
    """Accept a translation only when every protected span survived verbatim
    and no Japanese kana leaked in (a real reasoning-model failure mode; the
    line falls back to its English source instead of shipping Japanese)."""
    if not isinstance(translated, str) or not translated.strip():
        return False
    if _JAPANESE_KANA.search(translated) and not _JAPANESE_KANA.search(source):
        return False
    return all(span in translated for span in _preserved_spans(source))


# One call per ~2000 source characters. A long report translated in a single
# reply has to fit reasoning + every localized line under one completion cap;
# that is how a report silently came back shorter than it went in. Batching
# keeps each reply small enough to finish, and a batch that fails only costs
# its own lines.
_TRANSLATION_BATCH_CHARS = 2000
_TRANSLATION_BATCH_CONCURRENCY = 4


def _translation_batches(pending: dict[str, str]) -> list[dict[str, str]]:
    batches: list[dict[str, str]] = []
    current: dict[str, str] = {}
    size = 0
    for key, text in pending.items():
        if current and size + len(text) > _TRANSLATION_BATCH_CHARS:
            batches.append(current)
            current, size = {}, 0
        current[key] = text
        size += len(text)
    if current:
        batches.append(current)
    return batches


async def _translate_line_batch(
    settings: Settings,
    batch: dict[str, str],
    translations: dict[str, str],
    diagnostics: list[str] | None,
) -> bool:
    """Translate one batch in place. Returns False on transport failure (stop)."""
    pending = dict(batch)
    for attempt in range(2):
        estimated = sum(len(text) for text in pending.values()) // 2
        max_tokens = min(settings.llm_synthesis_max_tokens, max(3072, 3 * estimated))
        text, error = await complete_with_error(
            settings,
            system=_TRANSLATOR_SYSTEM
            + (
                "\n(직전 응답에서 일부 항목이 빠졌습니다 — 아래 키를 모두 포함하세요.)"
                if attempt
                else ""
            ),
            user=json.dumps(pending, ensure_ascii=False),
            temperature=0.2,
            max_tokens=max_tokens,
            model=settings.llm_model_synthesis,
            purpose="korean_synthesis",
        )
        parsed = parse_json_object(text or "")
        if parsed:
            for key, value in parsed.items():
                source = pending.get(str(key))
                if source is not None and _valid_line_translation(source, value):
                    translations[str(key)] = str(value).strip()
            pending = {k: v for k, v in pending.items() if k not in translations}
            if not pending:
                return True
        diagnostic = (
            f"attempt={attempt + 1}, model="
            f"{settings.llm_model_synthesis or settings.llm_model}, "
            f"requested_max_tokens={max_tokens}: "
        )
        if text is None:
            diagnostic += error or "no reply without transport diagnostic"
            if diagnostics is not None:
                diagnostics.append(diagnostic)
            _log.warning("korean synthesis call failed: %s", diagnostic)
            # Transport failure is not a malformed reply. Retrying (or starting
            # the next batch) would only burn the remaining finalization budget.
            return False
        if parsed is None:
            truncated = not text.rstrip().endswith("}")
            diagnostic += f"invalid JSON{' (looks truncated)' if truncated else ''}"
        else:
            diagnostic += f"{len(pending)} line(s) missing or malformed"
        if diagnostics is not None:
            diagnostics.append(diagnostic)
        _log.warning("korean synthesis reply incomplete: %s", diagnostic)
    return True


async def _translate_report_lines_ko(
    settings: Settings,
    detail: str,
    diagnostics: list[str] | None = None,
) -> tuple[str, int]:
    """Localize the deterministic report by translating its English lines only.

    Owner directive (2026-07-22): synthesis must NOT re-analyze, re-judge or
    re-write the RCA. Sending the whole report let the model do exactly that and
    cost a 16k-token reasoning generation; sending the English lines alone makes
    changing a conclusion structurally impossible, keeps every call small, and
    guarantees the report cannot come back shorter than it went in.

    Returns ``(report, untranslated_line_count)``. The report is always usable —
    lines that failed keep their deterministic text. Never raises into analyze().
    """
    pending = _translatable_report_lines(detail)
    if not pending:
        return detail, 0
    translations = await _translate_pending_lines(settings, pending, diagnostics)
    missing = len(pending) - len(translations)
    return _apply_line_translations(detail, translations), missing


async def _translate_pending_lines(
    settings: Settings, pending: dict[str, str], diagnostics: list[str] | None
) -> dict[str, str]:
    """Batch-translate a keyed dict of English lines. Shared by the report-body
    and warnings localization passes -- both need the identical batching/
    concurrency/failure handling, just different line extraction."""
    translations: dict[str, str] = {}
    try:
        semaphore = asyncio.Semaphore(_TRANSLATION_BATCH_CONCURRENCY)

        async def translate(batch: dict[str, str]) -> None:
            async with semaphore:
                await _translate_line_batch(settings, batch, translations, diagnostics)

        await asyncio.gather(*(translate(batch) for batch in _translation_batches(pending)))
    except Exception as exc:  # noqa: BLE001 - synthesis is best-effort
        message = _masked_exception_text(exc)
        if diagnostics is not None:
            diagnostics.append(message)
        _log.warning("korean synthesis call failed: %s", message)
    return translations


async def _translate_warnings_ko(
    settings: Settings, warnings: list[str], diagnostics: list[str] | None = None
) -> tuple[list[str], int]:
    """Localize warning strings the same way the report body is localized.

    ``state.warnings`` never passed through ``_translate_report_lines_ko`` -- it
    is a flat list, not the markdown document that function parses -- so a
    Korean report always shipped English warnings verbatim (a real run: 9/9
    warnings stayed English). Returns ``(warnings, untranslated_count)``; a
    line that already contains Hangul, or that fails to translate, keeps its
    original text.
    """
    pending = {
        str(index): warning
        for index, warning in enumerate(warnings)
        if warning.strip() and not _HANGUL_RE.search(warning)
    }
    if not pending:
        return warnings, 0
    translations = await _translate_pending_lines(settings, pending, diagnostics)
    missing = len(pending) - len(translations)
    return [
        translations.get(str(index), warning) for index, warning in enumerate(warnings)
    ], missing


_COMMAND_ONLY_ACTION = re.compile(
    r"^(?:`+)?(?:kubectl|helm|docker|crictl|ctr|crane|skopeo|nvidia-smi|journalctl|"
    r"systemctl|curl|wget|grep|awk|sed|cat|ls|df|du|find|nslookup|getent)\b",
    re.IGNORECASE,
)


_SYNTHESIS_OMIT = object()



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
    eligible_support_ids: set[str] | None = None,
) -> str:
    observed = _observed_text(results, request)
    return _short_sentence(
        _failure_mode_root_cause_statement(
            root_cause_candidates,
            request,
            observed,
            failure_modes or {},
            language,
            results=results,
            eligible_evidence_ids=eligible_support_ids,
        ),
        limit=320,
    )


def _failure_mode_root_cause_statement(
    candidates: list[RankedCause],
    request: AlertAnalysisRequest,
    observed_text: str,
    failure_modes: dict[str, list[dict]],
    language: str,
    *,
    results: list[CollectorResult] | None = None,
    eligible_evidence_ids: set[str] | None = None,
) -> str:
    """Prefer an exact, curated mechanism over a coarse ranked-family sentence."""
    matches = _actionable_failure_mode_matches(failure_modes, observed_text, candidates)
    top_family = candidates[0].family if candidates else ""
    if not _top_family_settled(candidates):
        matches = []
    curated = ""
    for _family, symptom in matches:
        if top_family and _family != top_family:
            continue
        reason = str(symptom.get("reason_ko" if language == "ko" else "reason") or "").strip()
        if reason:
            curated = reason
            break
    if curated:
        # A curated reason is already mechanism-level; the observed detail sharpens
        # it with the concrete object from this incident.
        detail = _specific_cause_statement(
            candidates[0] if candidates else None,
            results or [],
            eligible_evidence_ids,
            language=language,
            request=request,
        )
        statement = f"{curated} {detail}" if detail else curated
    else:
        # _ranked_root_cause_statement already folds the observed detail in.
        statement = _ranked_root_cause_statement(
            candidates,
            request,
            results=results,
            eligible_evidence_ids=eligible_evidence_ids,
            language=language,
        )
    provenance = _runtime_failure_mode_provenance(matches, candidates, language)
    return f"{statement} ({provenance})" if provenance else statement


def _runtime_failure_mode_provenance(
    matches: list[tuple[str, dict]],
    candidates: list[RankedCause] | None,
    language: str = "en",
) -> str:
    """Describe the runtime symptom that supplied the selected conclusion."""
    top_family = candidates[0].family if candidates else ""
    for family, symptom in matches:
        package_id = str(symptom.get("runtime_package_id") or "").strip()
        if package_id and (not top_family or family == top_family):
            symptom_name = localized_failure_mode_name(symptom, language)
            status = str(symptom.get("runtime_status") or "").strip()
            if symptom_name and status:
                if language == "ko":
                    return (
                        "런타임 지식 출처: "
                        f"패키지 {package_id}; family {family}; 매칭된 symptom "
                        f"{symptom_name}; 상태 {status}"
                    )
                return (
                    "Runtime knowledge provenance: "
                    f"package {package_id}; family {family}; matched symptom "
                    f"{symptom_name}; status {status}"
                )
    return ""


def _localized_failure_mode_name(symptom: dict, language: str) -> str:
    if language == "ko" and symptom.get("symptom_ko"):
        return str(symptom["symptom_ko"])
    return str(symptom.get("symptom") or "")


_localized_failure_mode_actions = localized_failure_mode_actions


def _runtime_knowledge_hint_lines(
    hints: list[tuple[str, dict]], masker: Masker | None = None
) -> list[str]:
    if not hints:
        return []
    active_masker = masker or build_masker(())
    lines = ["", "### Learned Knowledge (Pending Activation)", ""]
    for family, symptom in hints:
        package_id = _safe_line(
            symptom.get("runtime_package_id"), limit=120, masker=active_masker
        )
        name = _safe_line(symptom.get("symptom"), limit=180, masker=active_masker)
        suggestion = symptom.get("reason") or (symptom.get("actions") or [""])[0]
        suggestion = _safe_line(suggestion, limit=360, masker=active_masker) or name
        if not package_id or not name:
            continue
        lines.append(
            f"- package {package_id} family {family} matched symptom {name} "
            f"— would suggest: {suggestion}"
        )
    return lines if len(lines) > 3 else []


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
        if not filter_to_top or family == top_family or is_matcher_only_family(family)
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
        "appendix": "## Appendix",
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
        "appendix": "## 부록 (Appendix)",
        "fired": "발생",
        "severity": "심각도",
        "target": "대상",
        "what": "증상",
        "where": "위치",
        "impact": "영향",
    },
}


@dataclass(frozen=True)
class ReportKnowledge:
    """The curated catalogs a deterministic report is rendered against.

    These six travelled together as separate parameters through every rendering
    layer — the report body, the numbered actions, the playbook — so adding one
    more knowledge source meant widening four signatures. They travel as one
    value instead, and every field defaults: most callers care about one catalog
    at a time.
    """

    failure_modes: dict[str, list[dict]] = field(default_factory=dict)
    known_issues: list[dict] = field(default_factory=list)
    components: dict[str, dict] = field(default_factory=dict)
    cases: str = ""
    language: str = "en"
    masker: Masker | None = None


def _detail_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    missing: list[str],
    agent_souls: str = "",
    root_cause_candidates: list[RankedCause] | None = None,
    kg_context: dict | None = None,
    plan: InvestigationPlan | None = None,
    graph_fixes: GraphRemediation | None = None,
    eligible_support_ids: set[str] | None = None,
    self_check_next: str = "",
    runtime_knowledge_hints: list[tuple[str, dict[str, Any]]] | None = None,
    xid_codes: list[int] | None = None,
    *,
    knowledge: ReportKnowledge,
) -> str:
    """Problem -> Root Cause -> Recommended Actions, then everything else in an
    appendix. Sections 1-3 are the ~1-page report an operator (or a Word export)
    actually reads; the harness-owned Evidence Trace carries citable evidence."""
    h = _HEADINGS.get(knowledge.language, _HEADINGS["en"])
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
    lines.append(f"- {h['what']}: {_root_cause_statement(request, language=knowledge.language)}")
    if where:
        lines.append(f"- {h['where']}: {where}")
    if request.occurrence_count > 1:
        impact = (
            f"같은 워크로드에서 {request.occurrence_count}회 반복 발생"
            if knowledge.language == "ko"
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
            knowledge.failure_modes or {},
            knowledge.language,
            results=results,
            eligible_evidence_ids=eligible_support_ids,
        )
    )
    # Multi-axis facets (Locus / Nature / Trigger) for the top cause — names the
    # subsystem, the KIND of cause, and (when known) what set it off.
    if root_cause_candidates:
        facets = _facets_line(root_cause_candidates[0], knowledge.language)
        if facets:
            lines.append(facets)
    # What the failing entity was configured with — the limit that was exceeded,
    # the request no node could satisfy, the capacity a node ran out of.
    lines.extend(_observed_configuration_lines(results, eligible_support_ids, knowledge.language))
    # Ground the coarse family in the most specific signature match when one exists:
    # a recognised known issue (with its affected/fixed version) is far more precise.
    lines.extend(
        # This section headlines "Recognised known issue: **X**" as settled fact
        # (not a hedged suggestion), so its fuzzy_query must be the narrow text —
        # match_runai_known_issues ignores fuzzy_query today, but this call site
        # should not depend on that staying true to remain safe.
        _known_issue_cause_lines(
            knowledge.known_issues, observed_text, knowledge.language, _alert_signature_text(request)
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
    # The run's own observed XID codes (alert text + evidence), distinct from
    # graph_fixes.root_xids -- a pure catalog "what can escalate into this"
    # lookup that never checked whether this run actually saw its upstream
    # codes. Passing this through lets _causal_chain_line/_numbered_actions
    # tell a confirmed upstream cause from a catalog-only candidate.
    observed_xid_codes = set(xid_codes) if xid_codes is not None else None
    causal = (
        _causal_chain_line(graph_fixes, knowledge.language, observed_xid_codes)
        if allow_cause_specific_actions
        else ""
    )
    if causal:
        lines.extend(["", causal])
    if allow_cause_specific_actions:
        lines.extend(_xid_diagnostic_guidance_lines(graph_fixes, knowledge.language))

    # --- 3. Recommended Actions ------------------------------------------------
    lines.extend(["", h["actions"], ""])
    numbered = _numbered_actions(
        plan,
        graph_fixes,
        root_cause_candidates,
        observed_text,
        missing,
        request,
        knowledge=knowledge,
        allow_cause_specific_actions=allow_cause_specific_actions,
        self_check_next=self_check_next,
        facts=_remediation_facts(results, eligible_support_ids, target),
        observed_codes=observed_xid_codes,
    )
    if numbered:
        lines.extend(numbered)
    else:
        # Never a dangling empty section — say honestly why there are no actions.
        lines.append(
            "증거가 부족하여 구체적인 조치를 제시하기 어렵습니다. "
            "아래 확인 요청을 먼저 진행해 주세요."
            if knowledge.language == "ko"
            else "Not enough evidence for concrete actions yet — please address the "
            "questions below first."
        )

    # --- 4. Appendix (reference material; evidence lives in Evidence Trace) ---
    lines.extend(["", h["appendix"]])
    lines.extend(_investigation_plan_lines(plan))
    lines.extend(
        # fuzzy_query here reaches match_failure_mode_symptoms's BM25 recall and
        # can render "Matched symptom **X**; known fixes ..." unconditionally —
        # the narrow text, not investigation-order guidance.
        _knowledge_base_lines(
            kg_context,
            root_cause_candidates,
            observed_text,
            _alert_signature_text(request),
            knowledge.masker,
            allow_remediation=allow_cause_specific_actions,
        )
    )
    lines.extend(_runtime_knowledge_hint_lines(runtime_knowledge_hints or [], knowledge.masker))
    operator_prompt = annotations.get("operator_prompt")
    if operator_prompt:
        active_masker = knowledge.masker or build_masker(())
        lines.extend(
            [
                "",
                "### Operator Guidance" if knowledge.language != "ko" else "### 운영자 요청",
                "",
                _short_sentence(active_masker.mask_text(str(operator_prompt)), limit=500),
            ]
        )
        # What the operator already tried belongs next to their request, above the
        # recommendations — a reader who scrolls to the actions first should
        # already know which step is off the table.
        attempted = list(getattr(plan, "attempted_actions", None) or [])
        if attempted:
            lines.extend(
                [
                    "",
                    "이미 시도한 조치 (효과 없음)" if knowledge.language == "ko" else "Already attempted (did not resolve it)",
                    "",
                ]
            )
            lines.extend(
                f"- {_safe_line(item, limit=300, masker=active_masker)}" for item in attempted[:5]
            )
    # ponytail: no "Agent Role Coverage" section — it was the same static
    # collector-catalog text in every report, telling the operator nothing about
    # THIS incident. (Kept in prompts.py for the NAT workflow's system prompt.)
    if not agent_souls:
        lines.append("- Agent role contract file was not loaded; fallback guidance was used.")
    lines.extend(_affected_pods_lines(request, knowledge.language))
    lines.extend(["", "### Troubleshooting Playbook", ""])
    lines.extend(
        # Same reasoning as _knowledge_base_lines above: a fuzzy hit here can
        # become the headline playbook entry (including the exclusive_actions
        # short-circuit), so it must not be sourced from operator/runbook prose.
        _playbook_lines(
            root_cause_candidates,
            observed_text,
            _alert_signature_text(request),
            knowledge=knowledge,
            component=getattr(plan, "component", "") if plan is not None else "",
            allow_remediation=allow_cause_specific_actions,
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
                _general_guidance_heading(knowledge.language),
                "",
                *general_guidance_lines(
                    _alert_text(request),
                    knowledge.failure_modes or {},
                    knowledge.known_issues or [],
                    language=knowledge.language,
                    masker=knowledge.masker,
                    component=getattr(plan, "component", "") if plan else "",
                    component_source=getattr(plan, "component_source", "") if plan else "",
                    components=knowledge.components,
                    matched_alert=getattr(plan, "matched_alert", None) if plan else None,
                    families=_plan_families(plan),
                    case_cards=list((kg_context or {}).get("case_cards") or []),
                ),
            ]
        )
    return "\n".join(lines)


def _plan_families(plan: InvestigationPlan | None) -> list[str]:
    """Hypothesis families, but only when the LLM actually read the request.

    The deterministic router orders families from the alert NAME, so for a
    free-form request ("OperatorRequestedAnalysis") it leads with a default —
    node_kubelet_pressure for anything label-less. Presenting that as what the
    request is about would be a fabricated interpretation.
    """
    if not getattr(plan, "llm_refined", False):
        return []
    families = [
        str(h.get("family") or "") for h in (getattr(plan, "hypotheses", None) or []) if h
    ]
    return list(dict.fromkeys(f for f in families if f))


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


def _insert_before_appendix(detail: str, block: str) -> str:
    """Insert a section before the appendix so it reads as part of the report body.

    Falls back to appending at the end when no appendix heading exists (e.g. an
    LLM-synthesized or NAT-produced detail with a different shape).
    """
    for heading in ("\n## 부록", "\n## Appendix", "\n## 4. 부록", "\n## 4. Appendix"):
        idx = detail.find(heading)
        if idx >= 0:
            return f"{detail[:idx]}\n{block}\n{detail[idx:]}"
    return f"{detail}\n\n{block}"


def _append_general_guidance(detail: str, block: str) -> str:
    """Keep non-diagnostic guidance outside the RCA conclusion and action sections."""
    return f"{detail.rstrip()}\n\n{block}"


def _abstain_guidance_block(state: "PipelineState", language: str) -> str:
    """The guide built fresh at abstain time when the pre-abstain report had
    none: a run with eligible evidence carried cause-specific sections instead,
    and abstain() replaced the whole document with the stub."""
    plan = state.plan
    return "\n".join(
        [
            _general_guidance_heading(language),
            "",
            *general_guidance_lines(
                _alert_text(state.request),
                state.failure_modes,
                state.known_issues,
                language=language,
                masker=state.masker,
                component=getattr(plan, "component", "") if plan else "",
                component_source=getattr(plan, "component_source", "") if plan else "",
                components=load_architecture(state.settings.architecture_file),
                matched_alert=getattr(plan, "matched_alert", None) if plan else None,
                families=_plan_families(plan),
                case_cards=list(
                    getattr(getattr(state, "kg_context", None), "case_cards", None) or []
                ),
            ),
        ]
    )


def _general_guidance_block(detail: str, language: str) -> str:
    """The guide section of a report, heading included, or "" when absent.

    ``_append_general_guidance`` always puts it last, so the heading to the end
    of the document is the whole section. Both language headings are checked: a
    stored report may have been written under a different language setting.
    """
    for heading in (_general_guidance_heading(language), _general_guidance_heading("en"),
                    _general_guidance_heading("ko")):
        index = (detail or "").find(heading)
        if index >= 0:
            return detail[index:].rstrip()
    return ""


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


def _causal_chain_line(
    graph_fixes: GraphRemediation | None,
    language: str,
    observed_codes: set[int] | None = None,
) -> str:
    """One line naming the XID causal picture when the graph produced one.

    When the ontology's leads_to chain resolves a ROOT fault for an observed XID
    (e.g. NVLink Xid 74 -> app-crash Xid 45), name the chain so the operator fixes
    the origin, not the downstream symptom — the drill-down precision win.

    ``root_xids`` is a pure catalog reachability lookup (leads_to, reversed):
    for an observed XID it lists every upstream fault the CATALOG says CAN
    escalate into it, whether or not this run's own evidence ever saw that
    upstream code. ``observed_codes`` (this run's own XID codes — alert text +
    evidence, see ``_xid_codes_from_results``) tells this function which of
    those upstream codes were actually witnessed here. A root list with at
    least one witnessed member keeps the "fix the origin" instruction; a root
    list with NONE witnessed renders as candidates to rule out, never as a
    cause to act on. ``observed_codes=None`` (no caller opinion) keeps every
    root at face value, matching this function's behavior before the
    distinction existed.
    """
    if graph_fixes is None:
        return ""
    codes = sorted(set(graph_fixes.xid_fixes) | set(graph_fixes.xid_triggers))
    if not codes:
        return ""
    rendered_codes = ", ".join(str(code) for code in codes)
    roots = getattr(graph_fixes, "root_xids", None) or {}
    root_status = getattr(graph_fixes, "root_xid_status", {}) or {}

    def _witnessed(root_list: list[int]) -> bool:
        return observed_codes is None or any(root in observed_codes for root in root_list)

    # A flat root list carries no edge structure, so an arrow chain is provable
    # only for a single ancestor. Two or more roots can be independent faults
    # that each lead to the observed XID (a fan-in) rather than a sequence —
    # e.g. XID 144/145/146 are three unrelated NVLink faults that all lead to
    # XID 48 — so "ordered" with multiple roots still renders as the plain
    # upstream-fault list below, not an invented chain.
    ordered_chains = [
        " → ".join(f"XID {node}" for node in [*root_list, observed])
        for observed, root_list in sorted(roots.items())
        if root_status.get(observed, "ordered") == "ordered"
        and len(root_list) == 1
        and _witnessed(root_list)
    ]
    unordered = [
        (observed, root_list)
        for observed, root_list in sorted(roots.items())
        if (
            root_status.get(observed) == "complete-but-unordered"
            or (root_status.get(observed, "ordered") == "ordered" and len(root_list) > 1)
        )
        and _witnessed(root_list)
    ]
    # Roots this run never witnessed at all: catalog possibilities only. Never
    # folded into the two confirmed buckets above, and never given their "fix
    # it" instruction — rendered separately below as candidates to rule out.
    candidates = [
        (observed, root_list)
        for observed, root_list in sorted(roots.items())
        if (
            root_status.get(observed, "ordered") == "ordered"
            or root_status.get(observed) == "complete-but-unordered"
        )
        and root_list
        and not _witnessed(root_list)
    ]
    # xid_catalog.yaml's linkage_note documents the driver/CUDA version an
    # escalating XID's leads_to edge was actually CONFIRMED under. This line can
    # carry up to 21 codes across unrelated chains, so a parenthetical per code
    # does not scale here (see _xid_diagnostic_guidance_lines / _numbered_actions
    # for the per-code identity clause); add at most one short clause per
    # resolved chain, keyed to that chain's causal root (root_list[0] -- the
    # topological origin _root_chain_for already resolved).
    root_notes = list(
        dict.fromkeys(
            note
            for observed, root_list in sorted(roots.items())
            if root_status.get(observed, "ordered") == "ordered"
            and root_list
            and (note := graph_fixes.xid_linkage_notes.get(root_list[0]))
        )
    )
    if language == "ko":
        # Same rule as the mnemonic/description/fix text elsewhere in this file:
        # the catalog carries no Korean linkage_note, so do not leak raw English
        # into a ko report.
        root_notes = [note for note in root_notes if re.search(r"[가-힣]", note)]
    note_suffix = f" Escalation confirmed on: {'; '.join(root_notes)}." if root_notes else ""
    note_suffix_ko = f" 승격 확인 환경: {'; '.join(root_notes)}." if root_notes else ""
    statuses = set(root_status.values())
    if "degraded" in statuses:
        qualification = (
            " Causal-chain lookup was degraded by a query failure; shown upstream XIDs "
            "may not include the root."
        )
        qualification_ko = " 인과 사슬 조회가 쿼리 실패로 불완전합니다."
    else:
        qualification = ""
        qualification_ko = ""
    # Candidates get their own clause, appended to whichever branch fires below
    # (or their own branch, when nothing was confirmed at all) — named exactly
    # like a confirmed upstream-fault list, but framed as unconfirmed and never
    # carrying the "fix it" instruction.
    candidate_details = "; ".join(
        f"upstream candidates of {observed} (not observed in this run): "
        + ", ".join(str(root) for root in root_list)
        for observed, root_list in candidates
    )
    candidate_details_ko = "; ".join(
        f"XID {observed}의 상류 후보(이번 실행에서 미관측): "
        + ", ".join(str(root) for root in root_list)
        for observed, root_list in candidates
    )
    candidate_tail = (
        f" {candidate_details}. Not confirmed for this incident — rule these out, "
        "do not act on them as a root cause."
        if candidate_details
        else ""
    )
    candidate_tail_ko = (
        f" {candidate_details_ko}. 이번 사건에서는 확인되지 않았습니다 — 조치 대상이 아니라 "
        "배제 대상입니다."
        if candidate_details_ko
        else ""
    )
    if language == "ko":
        if ordered_chains:
            if unordered:
                details = "; ".join(
                    f"XID {observed}의 상류 장애(완전): "
                    + ", ".join(str(root) for root in root_list)
                    for observed, root_list in unordered
                )
                return (
                    f"- 관련 GPU 오류(XID): {rendered_codes} — "
                    f"인과 사슬(뿌리→관측): {'; '.join(ordered_chains)}; {details}. "
                    "근본 원인을 먼저 조치하세요." + note_suffix_ko + candidate_tail_ko
                )
            return (
                f"- 관련 GPU 오류(XID): {rendered_codes} — "
                f"인과 사슬(뿌리→관측): {'; '.join(ordered_chains)}. "
                + (
                    "뿌리 XID를 먼저 조치하세요."
                    if not qualification_ko
                    else qualification_ko.strip()
                )
                + note_suffix_ko
                + candidate_tail_ko
            )
        if unordered:
            details = "; ".join(
                f"XID {observed}의 상류 장애(완전): "
                + ", ".join(str(root) for root in root_list)
                for observed, root_list in unordered
            )
            return (
                f"- 관련 GPU 오류(XID): {rendered_codes} — {details}. "
                "근본 원인을 먼저 조치하세요." + candidate_tail_ko
            )
        if candidates:
            return f"- 관련 GPU 오류(XID): {rendered_codes} —{candidate_tail_ko}"
        return (
            f"- 관련 GPU 오류(XID): {rendered_codes} — "
            "세부 조치는 아래 권장 조치를 참고."
            + qualification_ko
        )
    if ordered_chains:
        if unordered:
            details = "; ".join(
                f"upstream faults of {observed} (complete): "
                + ", ".join(str(root) for root in root_list)
                for observed, root_list in unordered
            )
            return (
                f"- Related GPU errors (XID): {rendered_codes} — causal chain "
                f"(root → observed): {'; '.join(ordered_chains)}; {details}. "
                "Fix the origin first." + note_suffix + candidate_tail
            )
        return (
            f"- Related GPU errors (XID): {rendered_codes} — causal chain (root → observed): "
            f"{'; '.join(ordered_chains)}."
            + (" Fix the root XID first." if not qualification else qualification)
            + note_suffix
            + candidate_tail
        )
    if unordered:
        details = "; ".join(
            f"upstream faults of {observed} (complete): "
            + ", ".join(str(root) for root in root_list)
            for observed, root_list in unordered
        )
        return (
            f"- Related GPU errors (XID): {rendered_codes} — {details}. "
            "Fix the origin first." + candidate_tail
        )
    if candidates:
        return f"- Related GPU errors (XID): {rendered_codes} —{candidate_tail}"
    return (
        f"- Related GPU errors (XID): {rendered_codes} — "
        "see the recommended actions below."
        + qualification
    )


def _xid_identity_clause(
    graph_fixes: GraphRemediation | None, code: int, masker: Masker | None = None
) -> str:
    """"name (severity)" naming what an XID itself IS -- e.g. "GPU has fallen
    off the bus (fatal)" -- not just its fix. Prefers the graph's own catalog
    projection (kg_enrichment._fill_xid_detail); falls back to the local
    knowledge/xid_catalog.yaml when the graph has no detail for this code (a
    full TypeDB outage, or a partial/stale ingest), so that outage degrades
    the wording rather than deleting it. Empty when neither source has a
    mnemonic/description for this code -- never invented.
    """
    name = ""
    severity = ""
    if graph_fixes is not None:
        name = str(
            (graph_fixes.xid_descriptions or {}).get(code)
            or (graph_fixes.xid_mnemonics or {}).get(code)
            or ""
        ).strip()
        severity = str((graph_fixes.xid_severities or {}).get(code) or "").strip()
    if not name:
        entry = load_xid_catalog(os.getenv("XID_CATALOG_FILE", "knowledge/xid_catalog.yaml")).get(
            code
        )
        if entry:
            name = str(entry.get("description") or entry.get("mnemonic") or "").strip()
            severity = severity or str(entry.get("severity") or "").strip()
    if not name:
        return ""
    name = _safe_line(name, limit=80, masker=masker)
    return f"{name} ({severity})" if severity else name


def _xid_diagnostic_guidance_lines(
    graph_fixes: GraphRemediation | None, language: str
) -> list[str]:
    if graph_fixes is None or not graph_fixes.xid_triggers:
        return []
    masker = build_masker(())
    label = "진단 안내" if language == "ko" else "Diagnostic guidance"
    lines: list[str] = []
    for code, trigger in sorted(graph_fixes.xid_triggers.items()):
        if language == "ko" and not re.search(r"[가-힣]", str(trigger)):
            continue
        identity = _xid_identity_clause(graph_fixes, code, masker)
        # Same rule as the trigger text above: the catalog carries no Korean
        # mnemonic/description, so do not leak raw English into a ko report.
        if identity and language == "ko" and not re.search(r"[가-힣]", identity):
            identity = ""
        header = f"XID {code} — {identity}" if identity else f"XID {code}"
        lines.append(f"- {label} ({header}): {_safe_line(trigger, limit=360, masker=masker)}")
    return lines


def _specific_keyword(kw: str) -> bool:
    return len(kw) >= 8 or any(not ch.isalnum() for ch in kw)


def _promotable(matched: list[str], family: str) -> bool:
    if not matched:
        return False
    if family not in FAMILIES:
        return len(matched) >= 2
    return len(matched) >= 2 or any(_specific_keyword(k) for k in matched)


def _known_issue_signature_support(
    results: list[CollectorResult],
    matches: list[dict[str, Any]],
    eligible_support_ids: set[str] | None,
) -> dict[str, dict[str, list[str]]]:
    """Resolve each promoted known issue to the exact scoped evidence cards."""
    from app.services.evidence_blackboard import source_independence_group
    from app.services.root_cause_ranking import COLLECTOR_TEXT_DROP_KEYS

    support: dict[str, dict[str, list[str]]] = {}
    for entry in matches:
        issue = str(entry.get("issue") or "")
        keywords = [str(item) for item in entry.get("matched_keywords") or []]
        if not issue or not keywords:
            continue
        evidence_ids: list[str] = []
        agents: list[str] = []
        groups: list[str] = []
        for result in results:
            drop_keys = COLLECTOR_TEXT_DROP_KEYS.get(str(result.agent or ""))
            for item in result.artifacts:
                evidence_id = str(getattr(item, "evidence_id", "") or "")
                if not evidence_id or not _artifact_is_scoped_support(
                    item, eligible_support_ids=eligible_support_ids
                ):
                    continue
                semantic_text = " ".join(
                    part
                    for part in (
                        str(getattr(item, "summary", "") or ""),
                        _evidence_leaf_text(
                            getattr(item, "result", None),
                            limit=2000,
                            drop_keys=drop_keys,
                        ),
                    )
                    if part
                ).casefold()
                if not _keyword_hits(semantic_text, keywords)[0]:
                    continue
                evidence_ids.append(evidence_id)
                agent = str(getattr(item, "agent", "") or result.agent or "")
                agents.append(agent)
                source = str(getattr(item, "source", "") or agent)
                groups.append(source_independence_group(source))
        if evidence_ids:
            support[issue] = {
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
                "agents": list(dict.fromkeys(agents)),
                "groups": list(dict.fromkeys(groups)),
            }
    return support


def _curated_symptom_signature_support(
    results: list[CollectorResult],
    matches: list[tuple[str, dict[str, Any]]],
    eligible_support_ids: set[str] | None,
) -> dict[str, dict[str, list[str]]]:
    """Resolve a promoted curated symptom to its scoped evidence cards."""
    from app.services.evidence_blackboard import source_independence_group
    from app.services.root_cause_ranking import COLLECTOR_TEXT_DROP_KEYS

    support: dict[str, dict[str, list[str]]] = {}
    for family, symptom in matches:
        name = str(symptom.get("symptom") or "")
        keywords = [str(item) for item in symptom.get("matched_keywords") or []]
        if not family or not name or not keywords:
            continue
        ids: list[str] = []
        agents: list[str] = []
        groups: list[str] = []
        for result in results:
            drop_keys = COLLECTOR_TEXT_DROP_KEYS.get(str(result.agent or ""))
            for item in result.artifacts:
                evidence_id = str(getattr(item, "evidence_id", "") or "")
                if not evidence_id or not _artifact_is_scoped_support(
                    item, eligible_support_ids=eligible_support_ids
                ):
                    continue
                text = " ".join(
                    part
                    for part in (
                        str(getattr(item, "summary", "") or ""),
                        _evidence_leaf_text(
                            getattr(item, "result", None), limit=2000, drop_keys=drop_keys
                        ),
                    )
                    if part
                ).casefold()
                if not _keyword_hits(text, keywords)[0]:
                    continue
                ids.append(evidence_id)
                agent = str(getattr(item, "agent", "") or result.agent or "")
                agents.append(agent)
                groups.append(source_independence_group(str(getattr(item, "source", "") or agent)))
        if ids:
            support[f"{family}\0{name}"] = {
                "evidence_ids": list(dict.fromkeys(ids)),
                "agents": list(dict.fromkeys(agents)),
                "groups": list(dict.fromkeys(groups)),
            }
    return support


def _promote_signature_cause(
    candidates: list[RankedCause],
    xid_codes: list[int],
    known_issue_matches: list[dict],
    symptom_matches: list[tuple[str, dict]],
    *,
    evidence_text: str = "",
    known_issue_support: Mapping[str, dict[str, list[str]]] | None = None,
    symptom_support: Mapping[str, dict[str, list[str]]] | None = None,
    typed_state: tuple[str, str, list[str]] = ("", "", []),
) -> list[RankedCause]:
    """A specific signature names the headline family; the keyword ranker is only
    the no-signal fallback. Precedence: NVIDIA XID (dispositive) > known-issue
    signature > curated symptom keyword > ranker. When the signature agrees with
    the ranker's top family the richer ranked entry is kept as-is.

    Every match -- agreement with the ranker included -- passes a specificity
    gate first (``_promotable``): a match too weak to promote must not floor
    an unearned score, and (being a ``continue`` rather than a ``return``)
    must not stop a later, stronger signature for a DIFFERENT family from
    being evaluated in this same loop (S3).

    A non-catalog family additionally requires the keyword to appear in
    ``evidence_text`` (observed EVIDENCE, no alert text) -- an unvalidated
    label needs more than the alert's own word for it (S7's non-catalog case,
    unchanged). A CATALOG family does not: the alert's own text is a
    first-class signature source everywhere else in this pipeline
    (``_alert_signature_text``'s docstring: "it often carries the signature
    ... even when every collector comes back empty"), proven by dozens of
    tests where an alert's summary/description alone must reach the correct
    catalog family with zero collector evidence -- gating catalog promotion
    on non-alert evidence would kill exactly the promotions S7's own
    guardrail protects ("must not kill a promotion whose keyword IS in the
    evidence" -- alert text, by this codebase's own definition, counts). The
    real fix for S7's confirmed harm (a non-evidence alert FIELD like
    runbook_url contaminating the match) is S1, which keeps that text out of
    ``state.observed`` in the first place by building it from
    ``_alert_signature_text`` rather than the permissive ``_alert_text``
    (see that pair's docstrings for the guidance-vs-promotion boundary); S2
    additionally stops a support-less promotion (catalog or not) from
    outranking a stronger evidence-backed one.

    A promotion may also not displace a candidate that already scores higher
    AND carries real evidence support -- a bare signature must not leapfrog a
    stronger, evidence-backed ranked cause (S2).
    """
    if xid_codes:
        return _promote_xid_cause(candidates, xid_codes)
    if typed_state[0]:
        return _promote_typed_state_cause(candidates, *typed_state)
    top_family = candidates[0].family if candidates else ""
    for entry in known_issue_matches:
        family = str(entry.get("family") or "")
        if not family:
            continue
        issue = str(entry.get("issue") or "")
        support = (known_issue_support or {}).get(issue, {})
        support_ids = support.get("evidence_ids") or []
        support_agents = support.get("agents") or []
        support_groups = support.get("groups") or []
        matched_keywords = entry.get("matched_keywords") or []
        if not _promotable(matched_keywords, family):
            continue
        if family not in FAMILIES and not _keyword_hits(evidence_text, matched_keywords)[0]:
            continue
        if family == top_family:
            return [
                _with_signature_support(
                    candidates[0],
                    f"matched known-issue signature: {issue}",
                    8.0,
                    support_evidence_ids=support_ids,
                    evidence_agents=support_agents,
                    independent_source_groups=support_groups,
                ),
                *candidates[1:],
            ]
        rationale = f"matched known-issue signature: {issue}"
        existing = next((candidate for candidate in candidates if candidate.family == family), None)
        lead = (
            _with_signature_support(
                existing,
                rationale,
                8.0,
                support_evidence_ids=support_ids,
                evidence_agents=support_agents,
                independent_source_groups=support_groups,
            )
            if existing is not None
            else RankedCause(
                family=family,
                confidence="medium",
                score=8.0,
                rationale=[rationale],
                evidence_agents=sorted({"signature", *support_agents}),
                trigger=_trigger_for_family(candidates, family),
                support_evidence_ids=list(dict.fromkeys(support_ids)),
                independent_source_groups=list(dict.fromkeys(support_groups)),
                score_breakdown=[
                    {
                        "stage": "signature",
                        "kind": "known_issue",
                        "label": rationale,
                        "score_floor": 8.0,
                        "evidence_ids": list(dict.fromkeys(support_ids)),
                    }
                ],
            )
        )
        # S2: a promotion may not displace a candidate that already scores
        # higher AND carries real evidence support.
        if candidates and candidates[0].score > lead.score and candidates[0].support_evidence_ids:
            continue
        return [lead] + [c for c in candidates if c.family != family]
    for family, symptom in symptom_matches:
        if not family or is_matcher_only_family(family):
            continue
        support = (symptom_support or {}).get(
            f"{family}\0{str(symptom.get('symptom') or '')}", {}
        )
        support_ids = support.get("evidence_ids") or []
        support_agents = support.get("agents") or []
        support_groups = support.get("groups") or []
        matched_keywords = [str(item) for item in symptom.get("matched_keywords") or []]
        if not _promotable(matched_keywords, family):
            continue
        # No evidence_text gate here: every curated symptom family is a
        # catalog family (the closed-vocabulary invariant), so this loop's
        # matches are the SAME "alert text is a legitimate signature source"
        # case documented on this function -- see the known-issue loop above.
        if family == top_family:
            return [
                _with_signature_support(
                    candidates[0],
                    f"matched curated symptom: {symptom.get('symptom')}",
                    7.0,
                    support_evidence_ids=support_ids,
                    evidence_agents=support_agents,
                    independent_source_groups=support_groups,
                    signature_kind="curated_symptom",
                    signature_keywords=matched_keywords,
                ),
                *candidates[1:],
            ]
        rationale = f"matched curated symptom: {symptom.get('symptom')}"
        existing = next((candidate for candidate in candidates if candidate.family == family), None)
        lead = (
            _with_signature_support(
                existing,
                rationale,
                7.0,
                support_evidence_ids=support_ids,
                evidence_agents=support_agents,
                independent_source_groups=support_groups,
                signature_kind="curated_symptom",
                signature_keywords=matched_keywords,
            )
            if existing is not None
            else RankedCause(
                family=family,
                confidence="medium",
                score=7.0,
                rationale=[rationale],
                evidence_agents=sorted({"signature", *support_agents}),
                trigger=_trigger_for_family(candidates, family),
                support_evidence_ids=list(dict.fromkeys(support_ids)),
                independent_source_groups=list(dict.fromkeys(support_groups)),
                score_breakdown=[
                    {
                        "stage": "signature",
                        "kind": "curated_symptom",
                        "label": rationale,
                        "score_floor": 7.0,
                        "evidence_ids": list(dict.fromkeys(support_ids)),
                        "matched_keywords": matched_keywords,
                    }
                ],
            )
        )
        # S2: same "cannot displace a stronger evidence-backed candidate" rule
        # as the known-issue loop above.
        if candidates and candidates[0].score > lead.score and candidates[0].support_evidence_ids:
            continue
        return [lead] + [c for c in candidates if c.family != family]
    return candidates


def _typed_cause(family: str, reason: str, evidence_id: str) -> tuple[str, str, list[str]]:
    return (
        family,
        f"typed container state {reason} on the alert Pod "
        "(machine-reported, not keyword-matched)",
        [evidence_id],
    )


def _lifecycle_typed_cause(payload: dict, evidence_id: str) -> tuple[str, str, list[str]] | None:
    """A waiting/terminated container state whose reason is a known signature."""
    containers = payload.get("containers")
    for container in containers if isinstance(containers, list) else []:
        if not isinstance(container, dict):
            continue
        for state_key in ("state", "lastTerminated"):
            state = container.get(state_key)
            if not isinstance(state, dict):
                continue
            reason = str(state.get("reason") or "")
            if state_key == "state" and state.get("phase") not in {"waiting", "terminated"}:
                continue
            exit_code = state.get("exitCode")
            if state_key == "lastTerminated" and not (reason or exit_code is not None):
                continue
            if family := _typed_reason_family(reason):
                return _typed_cause(family, reason, evidence_id)
    return None


def _warning_event_typed_cause(
    payload: dict, evidence_id: str
) -> tuple[str, str, list[str]] | None:
    """A repeated (>=3), target-verified Warning Event with a known reason."""
    events = payload.get("events")
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        if (
            str(event.get("type") or "") != "Warning"
            or event.get("target_identity_verified") is not True
        ):
            continue
        try:
            count = int(event.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        if count < 3:
            continue
        reason = str(event.get("reason") or "")
        if family := _typed_reason_family(reason):
            return _typed_cause(family, reason, evidence_id)
    return None


def _scheduling_typed_cause(
    payload: dict, observation: dict, evidence_id: str
) -> tuple[str, str, list[str]] | None:
    """A PodScheduled reason, attributed to the scheduler that owns it."""
    reason = _canonical_scheduling_reason(payload)
    family = _typed_reason_family(reason) if reason else ""
    if not family:
        return None
    # The dispositive table decides WHETHER this reason is a signature; the
    # owning scheduler decides WHOSE. Same choke point as the ranker, or the
    # floor-scored signature and the support gate would name different families
    # for one Pod.
    scheduled_by = observation.get("scheduler") if isinstance(observation, dict) else ""
    family = scheduling_reason_family(reason, scheduled_by) or family
    return _typed_cause(family, reason, evidence_id)


_TYPED_STATE_CAUSES = {
    "kubernetes_container_lifecycle": lambda payload, observation, evidence_id: (
        _lifecycle_typed_cause(payload, evidence_id)
    ),
    "kubernetes_warning_events": lambda payload, observation, evidence_id: (
        _warning_event_typed_cause(payload, evidence_id)
    ),
    "kubernetes_pod_scheduling": _scheduling_typed_cause,
}


def _dispositive_typed_state(
    results: list[CollectorResult],
    eligible_support_ids: set[str] | None,
) -> tuple[str, str, list[str]]:
    """Find a verified Kubernetes machine-reported cause reason.

    Free-form summaries are intentionally ignored. Only scoped, verified typed
    lifecycle observations and repeated typed Warning Events can promote a
    cause when they are eligible for the final evidence trace.
    """
    if not eligible_support_ids:
        return "", "", []
    for result in results:
        for item in result.artifacts:
            evidence_id = str(getattr(item, "evidence_id", "") or "")
            if evidence_id not in eligible_support_ids:
                continue
            payload = getattr(item, "result", None)
            if not isinstance(payload, dict):
                continue
            observation = payload.get("observation")
            if not (
                isinstance(observation, dict)
                and observation.get("polarity") == "present"
                and observation.get("coverage") == "scoped"
                and observation.get("target_identity_verified") is True
            ):
                continue
            find = _TYPED_STATE_CAUSES.get(str(getattr(item, "type", "")))
            if find and (cause := find(payload, observation, evidence_id)):
                return cause
    return "", "", []


# The scheduling collector stores the PodScheduled reason casefolded; the
# dispositive table and the specific-cause layer key on the canonical casing.
_SCHEDULING_REASON_CANONICAL = {
    "unschedulable": "Unschedulable",
    "schedulinggated": "SchedulingGated",
}


def _canonical_scheduling_reason(payload: dict[str, Any]) -> str:
    condition = payload.get("condition")
    if not isinstance(condition, dict):
        return ""
    return _SCHEDULING_REASON_CANONICAL.get(
        str(condition.get("reason") or "").strip().casefold(), ""
    )


def _typed_reason_family(reason: str) -> str:
    for family, reasons in _DISPOSITIVE_TYPED_REASONS.items():
        if reason in reasons:
            return family
    return ""


def _promote_typed_state_cause(
    candidates: list[RankedCause], family: str, rationale: str, support_ids: list[str]
) -> list[RankedCause]:
    existing = next((candidate for candidate in candidates if candidate.family == family), None)
    support_evidence_ids = list(
        dict.fromkeys([*(existing.support_evidence_ids if existing else []), *support_ids])
    )
    if existing is not None:
        promoted = replace(
            existing,
            confidence="high",
            score=max(existing.score, 9.0),
            rationale=[
                *existing.rationale,
                *([] if rationale in existing.rationale else [rationale]),
            ],
            evidence_agents=sorted({*existing.evidence_agents, "signature", "kubernetes"}),
            mechanism=rationale,
            support_evidence_ids=support_evidence_ids,
            score_breakdown=[
                *existing.score_breakdown,
                {
                    "stage": "signature",
                    "kind": "typed_container_state",
                    "label": rationale,
                    "score_floor": 9.0,
                    "evidence_ids": list(dict.fromkeys(support_ids)),
                    "force_high": True,
                },
            ],
            confidence_gate={
                **existing.confidence_gate,
                "score_floor_passed": True,
                "medium_score_passed": True,
                "high_score_passed": True,
                "force_high": True,
                "signature_promoted": True,
            },
        )
    else:
        promoted = RankedCause(
            family=family,
            confidence="high",
            score=9.0,
            rationale=[rationale],
            evidence_agents=["kubernetes", "signature"],
            mechanism=rationale,
            support_evidence_ids=support_evidence_ids,
            score_breakdown=[
                {
                    "stage": "signature",
                    "kind": "typed_container_state",
                    "label": rationale,
                    "score_floor": 9.0,
                    "evidence_ids": list(dict.fromkeys(support_ids)),
                    "force_high": True,
                }
            ],
            confidence_gate={
                "score_floor_passed": True,
                "medium_score_passed": True,
                "high_score_passed": True,
                "force_high": True,
                "signature_promoted": True,
            },
        )
    return [promoted] + [candidate for candidate in candidates if candidate.family != family]


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
    candidate: RankedCause,
    rationale: str,
    score_floor: float,
    *,
    support_evidence_ids: list[str] | None = None,
    evidence_agents: list[str] | None = None,
    independent_source_groups: list[str] | None = None,
    signature_kind: str = "signature_floor",
    signature_keywords: list[str] | None = None,
) -> RankedCause:
    rationale_items = [*candidate.rationale]
    if rationale not in rationale_items:
        rationale_items.append(rationale)
    score = max(candidate.score, score_floor)
    confidence_gate = dict(candidate.confidence_gate)
    if confidence_gate:
        confidence_gate.update(
            {
                "score_floor_passed": score
                >= float(confidence_gate.get("score_floor") or 0.0),
                "medium_score_passed": score
                >= float(confidence_gate.get("medium_score_threshold") or 0.0),
                "high_score_passed": score
                >= float(confidence_gate.get("high_score_threshold") or 0.0),
                "signature_promoted": True,
            }
        )
    return replace(
        candidate,
        confidence=(
            "medium"
            if candidate.confidence == "low" and not candidate.contradiction_evidence_ids
            else candidate.confidence
        ),
        score=score,
        rationale=rationale_items,
        evidence_agents=sorted(
            {*candidate.evidence_agents, "signature", *(evidence_agents or [])}
        ),
        support_evidence_ids=list(
            dict.fromkeys([*candidate.support_evidence_ids, *(support_evidence_ids or [])])
        ),
        independent_source_groups=list(
            dict.fromkeys(
                [
                    *candidate.independent_source_groups,
                    *(independent_source_groups or []),
                ]
            )
        ),
        score_breakdown=[
            *candidate.score_breakdown,
            {
                "stage": "signature",
                "kind": signature_kind,
                "label": rationale,
                "score_floor": score_floor,
                "delta": score - candidate.score,
                "evidence_ids": list(dict.fromkeys(support_evidence_ids or [])),
                **({"matched_keywords": signature_keywords} if signature_keywords else {}),
            },
        ],
        confidence_gate=confidence_gate,
    )


def _promote_xid_cause(candidates: list[RankedCause], xid_codes: list[int]) -> list[RankedCause]:
    """Lead with gpu_hardware_error when an NVIDIA XID is present.

    An XID in the alert/evidence is dispositive for the cause CATEGORY (the GPU
    driver itself reported the fault); the generic keyword families then describe
    downstream effects at best. Deterministic — no LLM, no score fight."""
    if not xid_codes:
        return candidates
    codes = ", ".join(str(code) for code in xid_codes)
    rationale = f"NVIDIA XID {codes} present in the alert/evidence"
    existing = next(
        (candidate for candidate in candidates if candidate.family == "gpu_hardware_error"),
        None,
    )
    gpu = (
        replace(
            existing,
            confidence="high",
            score=10.0,
            rationale=[*existing.rationale, rationale],
            evidence_agents=sorted({*existing.evidence_agents, "alert"}),
            score_breakdown=[
                *existing.score_breakdown,
                {
                    "stage": "signature",
                    "kind": "nvidia_xid",
                    "label": rationale,
                    "score_floor": 10.0,
                    "delta": 10.0 - existing.score,
                    "evidence_ids": list(existing.support_evidence_ids),
                    "force_high": True,
                },
            ],
            confidence_gate={
                **existing.confidence_gate,
                "score_floor_passed": True,
                "medium_score_passed": True,
                "high_score_passed": True,
                "force_high": True,
                "signature_promoted": True,
            },
        )
        if existing is not None
        else RankedCause(
            family="gpu_hardware_error",
            confidence="high",
            score=10.0,
            rationale=[rationale],
            evidence_agents=["alert"],
            score_breakdown=[
                {
                    "stage": "signature",
                    "kind": "nvidia_xid",
                    "label": rationale,
                    "score_floor": 10.0,
                    "evidence_ids": [],
                    "force_high": True,
                }
            ],
        )
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
        # Source/KB citations (e.g. "NVIDIA Case 01074073") -- identifiers, not
        # prose, so (like the affected/fixed version above) they render in both
        # languages rather than going through the no-Korean-text ko suppression
        # used for catalog mnemonics/descriptions elsewhere in this file.
        if refs := [str(r) for r in (issue.get("refs") or []) if str(r).strip()]:
            line += f" ({', '.join(refs)})"
        out.append(line)
    return out


_OOM_REASONS = frozenset({"OOMKilled"})
_IMAGE_PULL_REASONS = frozenset(
    {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull"}
)


def _remediation_facts(
    results: list[CollectorResult],
    eligible_evidence_ids: set[str] | None,
    target: AnalysisTarget,
) -> dict[str, str]:
    """Observed values that make curated guidance executable for THIS incident.

    Curated actions are family-level knowledge written with placeholders, and the
    sizing advice for an OOMKill needs a number no catalogue can carry.  Both come
    from the same eligible, target-verified typed artifacts the cause statement
    uses, so a rendered command can never name a pod, image, or limit this run did
    not actually observe.
    """
    facts = {
        "namespace": target.namespace,
        "pod": target.pod,
        "node": target.node,
        "workload": target.workload_name,
        "workload_kind": target.workload_type,
    }
    facts = {key: value for key, value in facts.items() if value}
    if not eligible_evidence_ids:
        return facts
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            payload = getattr(item, "result", None)
            if getattr(item, "type", "") != "kubernetes_container_lifecycle":
                continue
            if not _typed_artifact_is_verified(payload):
                continue
            # The live Pod the collector actually read beats a stale alert label.
            for key in ("pod", "namespace"):
                if str(payload.get(key) or ""):
                    facts[key] = str(payload[key])
            for container in payload.get("containers", []):
                if not isinstance(container, dict):
                    continue
                reasons = {
                    str(state.get("reason") or "")
                    for key in ("state", "lastTerminated")
                    if isinstance(state := container.get(key), dict)
                }
                resources = container.get("resources")
                resources = resources if isinstance(resources, dict) else {}
                if reasons & _OOM_REASONS and "oom" not in facts:
                    limits = resources.get("limits")
                    requests = resources.get("requests")
                    facts["oom"] = "true"
                    facts["container"] = str(container.get("name") or "")
                    if isinstance(limits, dict) and limits.get("memory"):
                        facts["memory_limit"] = str(limits["memory"])
                    if isinstance(requests, dict) and requests.get("memory"):
                        facts["memory_request"] = str(requests["memory"])
                if reasons & _IMAGE_PULL_REASONS and "image" not in facts:
                    image = str(container.get("image") or "")
                    if image:
                        facts["image"] = image
                        facts["repo"] = image_repository(image)
                        facts.setdefault("container", str(container.get("name") or ""))
    return {key: value for key, value in facts.items() if value}


def _numbered_actions(
    plan: InvestigationPlan | None,
    graph_fixes: GraphRemediation | None,
    candidates: list[RankedCause] | None,
    observed_text: str,
    missing: list[str],
    request: AlertAnalysisRequest,
    *,
    knowledge: ReportKnowledge,
    allow_graph_remediation: bool = True,
    allow_cause_specific_actions: bool | None = None,
    self_check_next: str = "",
    facts: dict[str, str] | None = None,
    observed_codes: set[int] | None = None,
) -> list[str]:
    """One deduped priority list: self-check and matched symptom first, then
    alert/component/known-issue and signature-specific graph guidance."""
    # ``allow_graph_remediation`` predates the broader action gate and remains
    # for callers outside the pipeline. In a real report, every remedy that
    # depends on a candidate (catalog, component, prior, graph, playbook) must
    # obey the same evidence boundary as graph remediation.
    if allow_cause_specific_actions is None:
        allow_cause_specific_actions = allow_graph_remediation
    ordered: list[str] = []
    specific_actions = 0
    # NOT ``_alert_text``: this fuzzy-matches a symptom whose actions get
    # rendered straight into the numbered list below (including the
    # exclusive_actions short-circuit) with no LLM verify gate in front of it
    # here, so it must be the narrow, non-evidence-field-free text.
    fuzzy = _alert_signature_text(request)
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    symptom_matches = _actionable_failure_mode_matches(
        knowledge.failure_modes, observed_text, candidates, fuzzy_query=fuzzy
    )
    # Self-check is the final evidence-aware critic. Its concrete next probe is
    # more incident-specific than catalog/component/graph guidance and must not
    # disappear when Korean synthesis fails and the deterministic report wins.
    if self_check_next.strip():
        ordered.append(self_check_next)
    # Sizing and spelling advice derived from the observed spec. The catalogue can
    # only say "compare the limit with the working set"; these carry the actual
    # values, so they lead the list — including under ``exclusive_actions``, whose
    # curated text they quantify rather than contradict.
    observed = facts or {}
    if allow_cause_specific_actions:
        ordered.extend(
            line
            for line in (
                memory_sizing_action(observed, knowledge.language),
                image_typo_hint(observed, knowledge.language),
            )
            if line
        )
    if (
        allow_cause_specific_actions
        and symptom_matches[0:1]
        and symptom_matches[0][1].get("exclusive_actions")
    ):
        actions = [
            *ordered,
            *_localized_failure_mode_actions(symptom_matches[0][1], knowledge.language),
        ]
        masker = build_masker(())
        rendered = list(
            dict.fromkeys(
                action
                for raw in actions
                if (
                    action := _safe_line(
                        fill_placeholders(str(raw), observed), limit=420, masker=masker
                    )
                )
            )
        )
        return [f"{index}. {action}" for index, action in enumerate(rendered[:8], start=1)]
    # The strongest exact symptom is the primary remediation source. Catalog,
    # component, known-issue, and graph knowledge remain useful additions, but
    # they must not crowd the observed mechanism out of the report cap.
    if allow_cause_specific_actions and top_family != "insufficient_evidence":
        for _family, symptom in symptom_matches[:1]:
            actions = _localized_failure_mode_actions(symptom, knowledge.language)
            specific_actions += len(actions)
            ordered.extend(actions)
    if allow_cause_specific_actions and plan is not None and plan.matched_alert:
        alert_family = str(plan.matched_alert.get("family") or "")
        if (not top_family or alert_family == top_family) and top_family != "insufficient_evidence":
            ordered.extend(str(a) for a in plan.matched_alert.get("actions", []))
    # Component identity: the alert target IS this platform component, so its
    # own checks + dependency chain (e.g. runai-container-toolkit → the NVIDIA
    # GPU Operator stack) come before any keyword-matched guidance.
    if allow_cause_specific_actions and plan is not None and getattr(plan, "component", ""):
        component_actions = component_action_lines(knowledge.components or {}, plan.component)
        specific_actions += len(component_actions)
        ordered.extend(component_actions)
    # Known operator cases recognised by their signature keywords in the evidence
    # (ranking-independent): version-regression / observability / expected-behavior
    # fixes surface even when the coarse family ranking points elsewhere.
    if allow_cause_specific_actions and top_family != "insufficient_evidence":
        for issue in match_runai_known_issues(knowledge.known_issues or [], observed_text, fuzzy_query=fuzzy):
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
        # Family-wide graph fixes contain actions for every sibling symptom
        # (for image_pull_error: rate-limit, TLS, auth, bad tag, DNS, ...).
        # They are ontology guidance, not evidence-matched remediation, and used
        # to crowd the exact symptom actions out of the eight-item report cap.
        # Keep only signature-specific graph fixes (XIDs) in executable actions;
        # symptom remediation below is selected from the observed evidence.
        # root_xids is a catalog "what can escalate into this" lookup, not
        # proof this run saw the ancestor fire — an unconfirmed one must not
        # outrank (sort before, in the "root first" key below) the code this
        # run actually observed, or its own fix can miss the 8-item cap
        # entirely behind several catalog-only candidates. observed_codes=None
        # (no caller opinion) keeps every root, matching prior behavior.
        root_codes = {
            root
            for observed, roots in graph_fixes.root_xids.items()
            if graph_fixes.root_xid_status.get(observed, "ordered") == "ordered"
            for root in roots
            if observed_codes is None or root in observed_codes
        }
        masker = build_masker(())
        # Fix the ROOT of the causal chain before its downstream symptoms.
        for code in sorted(graph_fixes.xid_fixes, key=lambda c: (c not in root_codes, c)):
            # Label, identity and fix text are all built in ENGLISH on purpose,
            # and _translate_report_lines_ko localizes the finished line.
            # _translatable_report_lines skips any line that ALREADY contains
            # Hangul, so pre-localizing the label ("근본 XID") is precisely what
            # made the catalog's English text untranslatable — and the two
            # Hangul filters that used to stand here deleted it instead, which
            # is how a ko report lost WORKFLOW_XID_48 entirely. One English
            # line survives translation whole; when translation is unavailable
            # the operator reads English rather than nothing.
            label = "root XID" if code in root_codes else "XID"
            identity = _xid_identity_clause(graph_fixes, code, masker)
            header = f"{label} {code} — {identity}" if identity else f"{label} {code}"
            fixes = [f"({header}) {fix}" for fix in graph_fixes.xid_fixes[code]]
            specific_actions += len(fixes)
            ordered.extend(fixes)
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
    attempted = list(getattr(plan, "attempted_actions", None) or [])
    for action in ordered:
        action = _safe_line(
            fill_placeholders(str(action), observed), limit=420, masker=action_masker
        )
        if not action or action in seen:
            continue
        seen.add(action)
        # Marked, not removed. The operator saying "I raised the memory" does not
        # make the memory path wrong — it may have been applied to the wrong
        # container, or undone by a restart. Dropping the step would hide that;
        # labelling it stops the report from reading as "do the thing you said
        # you already did".
        if _matches_attempted_action(action, attempted):
            action = f"{action} {_already_attempted_note(knowledge.language)}"
        numbered.append(f"{len(numbered) + 1}. {action}")
        if len(numbered) >= 8:
            break
    return numbered


# Short, content-bearing tokens only: "the", "and", "memory" in both strings is
# not a match, "resources.limits.memory" is.
_ATTEMPTED_STOPWORDS = frozenset(
    {"the", "and", "for", "with", "that", "this", "from", "into", "your", "its", "already"}
)


def _attempted_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9._-]{4,}", str(text).lower())
        if token not in _ATTEMPTED_STOPWORDS
    }


def _matches_attempted_action(action: str, attempted: list[str]) -> bool:
    """Whether a recommended action restates something the operator already did.

    Deliberately a blunt token overlap. The operator writes free prose in any
    language and the catalogue writes English imperatives, so there is no exact
    key to join on; the planner LLM normalises the claim to a short English
    statement first, which is what makes even this much possible.
    # ponytail: token overlap, not embeddings — a missed mark costs a redundant
    # line, and the report states the attempt separately either way.
    """
    if not attempted:
        return False
    action_tokens = _attempted_tokens(action)
    if not action_tokens:
        return False
    for claim in attempted:
        claim_tokens = _attempted_tokens(claim)
        if len(claim_tokens) >= 2 and len(claim_tokens & action_tokens) >= 2:
            return True
    return False


def _already_attempted_note(language: str) -> str:
    return (
        "(운영자가 이미 시도했다고 보고한 조치입니다 — 실제로 반영되었는지, 왜 효과가 없었는지 먼저 확인하세요.)"
        if language == "ko"
        else "(the operator reports already doing this — verify it took effect and why it did not hold)"
    )


def _root_cause_statement(request: AlertAnalysisRequest, *, language: str = "en") -> str:
    annotations = request.alert.annotations
    labels = request.alert.labels
    text = (
        annotations.get("description")
        or annotations.get("summary")
        or labels.get("alertname")
        or "The alert fired before the agent could identify a precise root cause."
    )
    text = _short_sentence(text, limit=320)
    if language != "ko" or re.search(r"[가-힣]", text):
        return text
    alert_name = str(labels.get("alertname") or "alert")
    if alert_name == "KubePodNotReady":
        return "대상 Pod가 15분 이상 Ready 상태가 되지 않아 KubePodNotReady 알림이 발생했습니다."
    return f"대상에서 {alert_name} 알림이 발생했습니다."


def _top_family_settled(candidates: list[RankedCause] | None) -> bool:
    if not candidates:
        return False
    top = candidates[0]
    return top.family != "insufficient_evidence" and (top.confidence != "low" or top.score >= 2.0)


def _ranked_root_cause_statement(
    candidates: list[RankedCause],
    request: AlertAnalysisRequest,
    *,
    results: list[CollectorResult] | None = None,
    eligible_evidence_ids: set[str] | None = None,
    language: str = "en",
) -> str:
    subject = _as_sentence(_root_cause_statement(request, language=language))
    if not candidates:
        return subject
    top = candidates[0]
    if top.family == "insufficient_evidence":
        if language == "ko":
            return _short_sentence(
                f"{subject} 현재 수집된 신호만으로는 특정 원인을 확정할 근거가 충분하지 않습니다.",
                limit=320,
            )
        return _short_sentence(
            f"{subject} Insufficient evidence: there is not yet enough evidence to point "
            "at a specific cause; the collected signals are inconclusive.",
            limit=320,
        )
    explanation = (
        _FAMILY_EXPLANATION_KO.get(top.family)
        if language == "ko"
        else _FAMILY_EXPLANATION.get(top.family)
    ) or _family_label(top.family)
    detail = _specific_cause_statement(
        top, results or [], eligible_evidence_ids, language=language, request=request
    )
    # The concrete mechanism is what an operator can act on, so it leads and the
    # ranked family stays as the classification behind it.  Without one, the
    # family sentence is all we honestly have.
    if detail:
        statement = (
            f"{subject} {detail} (분류: {explanation})"
            if language == "ko"
            else f"{subject} {detail} (Classification: {explanation}.)"
        )
    elif language == "ko":
        statement = f"{subject} 가장 가능성 높은 원인은 {explanation}입니다."
    else:
        statement = f"{subject} Likely cause: {explanation}."
    return _short_sentence(statement, limit=320)


_TYPED_MECHANISM_REASON = re.compile(
    r"^typed container state ([A-Za-z][A-Za-z0-9]*) on the alert Pod "
    r"\(machine-reported, not keyword-matched\)$"
)
_CONFIGMAP_NOT_FOUND = re.compile(r'configmap "([^"]+)" not found', re.IGNORECASE)
_SECRET_NOT_FOUND = re.compile(r'secret "([^"]+)" not found', re.IGNORECASE)
_MISSING_KEY = re.compile(r"couldn't find key (\S+)", re.IGNORECASE)
_EXECUTABLE_TOKEN = re.compile(
    r'(?:exec:\s*)?["\']?([^\s:"\']+)["\']?:?\s*.*executable file not found in \$?PATH',
    re.IGNORECASE,
)
_IMAGE_REFERENCE = re.compile(
    r'(?:failed to pull image|unpack image|container image|(?:image|image tag) name|image tag|image)'
    r'\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _specific_cause_statement(
    top: RankedCause | None,
    results: list[CollectorResult],
    eligible_evidence_ids: set[str] | None,
    *,
    language: str,
    request: AlertAnalysisRequest | None = None,
) -> str:
    """Render a closed-vocabulary typed-state detail from eligible message fields only.

    The typed mechanism is the primary source, but ranking can also settle on a
    family through a Warning event or an explicit alert signature. Those runs
    carry the same dispositive reason token in eligible evidence, so they get the
    same deterministic mechanism sentence instead of a family-level headline.
    """
    if top is None or not eligible_evidence_ids:
        return ""
    matched = _TYPED_MECHANISM_REASON.match(str(top.mechanism or "").strip())
    if matched:
        reason = matched.group(1)
        observations = _typed_reason_observations(results, eligible_evidence_ids, reason)
        return _reason_specific_detail(
            reason, observations, results, eligible_evidence_ids, language=language
        )
    family = str(getattr(top, "family", "") or "")
    for reason in _dispositive_reason_order(family):
        observations = _typed_reason_observations(results, eligible_evidence_ids, reason)
        if observations:
            # Only the typed match may open this branch, but the kubelet Event
            # usually holds the message naming the object, so pool both.
            observations += _event_message_observations(
                results, eligible_evidence_ids, reason
            )
            return _reason_specific_detail(
                reason, observations, results, eligible_evidence_ids, language=language
            )
    if request is None:
        return ""
    for reason in _asserted_signature_reasons(results, eligible_evidence_ids, family):
        # The alert asserted the reason; the cluster's own Event message is the
        # better source for WHICH object failed, so it is consulted first.
        observations = _event_message_observations(
            results, eligible_evidence_ids, reason
        ) + [(reason, text, None, {}) for text in _asserted_alert_texts(request)]
        detail = _reason_specific_detail(
            reason, observations, results, eligible_evidence_ids, language=language
        )
        if detail:
            return detail
    return ""


# Kubernetes reports these mechanisms twice: the container state carries the
# reason token, while the Event that carries the human-readable message uses the
# kubelet's own generic reason ("Failed" for a missing Secret/ConfigMap). Mapping
# the pair keeps object-name extraction on a closed vocabulary instead of
# grepping every event message in the run.
_EVENT_REASONS_FOR_STATE: dict[str, frozenset[str]] = {
    "CreateContainerConfigError": frozenset({"Failed"}),
    "CreateContainerError": frozenset({"Failed"}),
    "RunContainerError": frozenset({"Failed"}),
    "StartError": frozenset({"Failed"}),
    "ImagePullBackOff": frozenset({"Failed", "BackOff"}),
    "ErrImagePull": frozenset({"Failed", "BackOff"}),
    "ErrImageNeverPull": frozenset({"Failed", "ErrImageNeverPull"}),
    "InvalidImageName": frozenset({"Failed", "InvalidImageName"}),
    "Unschedulable": frozenset({"FailedScheduling"}),
    "SchedulingGated": frozenset({"FailedScheduling"}),
}


def _event_message_observations(
    results: list[CollectorResult], eligible_evidence_ids: set[str], reason: str
) -> list[tuple[str, str, object | None, dict[str, Any]]]:
    """Messages from eligible target-verified Warning events for this mechanism.

    Same identity bar as ``_typed_reason_observations`` — the artifact must be
    scoped/present/target-verified and the individual event target-verified, so a
    neighbouring workload's failure can never name this incident's object — but
    deliberately WITHOUT its ``count >= 3`` threshold. That threshold guards
    treating a reason token as the mechanism; here the mechanism is already
    established by typed state or an asserted alert signature, and a single
    kubelet Event is enough to say WHICH object it was about.
    """
    allowed = _EVENT_REASONS_FOR_STATE.get(reason) or frozenset()
    if not allowed:
        return []
    found: list[tuple[str, str, object | None, dict[str, Any]]] = []
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            if getattr(item, "type", "") != "kubernetes_warning_events":
                continue
            payload = getattr(item, "result", None)
            if not _typed_artifact_is_verified(payload):
                continue
            for event in payload.get("events", []):
                if not (
                    isinstance(event, dict)
                    and str(event.get("type") or "") == "Warning"
                    and event.get("target_identity_verified") is True
                    and str(event.get("reason") or "") in allowed
                ):
                    continue
                message = str(event.get("message") or "")
                if message:
                    found.append((reason, message, None, {"event": event}))
    return found


def _dispositive_reason_order(family: str) -> list[str]:
    """Dispositive reasons for a family, deepest mechanism first.

    ``CrashLoopBackOff`` only says the container keeps restarting; when a more
    specific reason is also present it is the one worth reporting.
    """
    reasons = _DISPOSITIVE_TYPED_REASONS.get(family) or frozenset()
    return sorted(reasons, key=lambda reason: (reason == "CrashLoopBackOff", reason))


def _asserted_signature_reasons(
    results: list[CollectorResult], eligible_evidence_ids: set[str], family: str
) -> list[str]:
    """Reason tokens the alert payload itself asserted for this family.

    Only markers carried by an *eligible* ``alert_signature`` artifact count, and
    only those that are also dispositive typed reasons — the alert text is never
    re-scanned here, so probe/runbook wording cannot reach the headline.
    """
    dispositive = _DISPOSITIVE_TYPED_REASONS.get(family) or frozenset()
    if not dispositive:
        return []
    predicate = f"alert_signature:{family}"
    signals: list[str] = []
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            if getattr(item, "type", "") != "alert_signature":
                continue
            payload = getattr(item, "result", None)
            if not isinstance(payload, dict):
                continue
            observation = payload.get("observation")
            if not (
                isinstance(observation, dict)
                and observation.get("predicate") == predicate
                and observation.get("polarity") == "present"
            ):
                continue
            for signal in payload.get("matched_signals") or []:
                marker = str(signal)
                if marker in dispositive and marker not in signals:
                    signals.append(marker)
    return sorted(signals, key=lambda reason: (reason == "CrashLoopBackOff", reason))


def _reason_specific_detail(
    reason: str,
    observations: list[tuple[str, str, object | None, dict[str, Any]]],
    results: list[CollectorResult],
    eligible_evidence_ids: set[str],
    *,
    language: str,
) -> str:
    if reason == "CrashLoopBackOff":
        terminated = _typed_last_terminated_observations(results, eligible_evidence_ids)
        deeper = next(
            (
                item
                for item in terminated
                if item[0]
                in {
                    "CreateContainerConfigError",
                    "StartError",
                    "RunContainerError",
                    "ContainerCannotRun",
                    "OOMKilled",
                }
            ),
            None,
        )
        if deeper:
            reason, observations = deeper[0], [deeper]
        else:
            exit_code = next((item[2] for item in terminated if item[2] is not None), None)
            return _restart_loop_detail(exit_code, _observed_restarts(terminated), language)
    if reason == "CreateContainerConfigError":
        detail = _config_error_detail([item[1] for item in observations], language)
        return detail or _config_error_generic(language)
    if reason in {"StartError", "RunContainerError", "ContainerCannotRun"}:
        messages = [item[1] for item in observations]
        if not any(messages):
            return ""
        detail = _command_error_detail(messages, language)
        return detail or _command_error_generic(language)
    if reason == "CreateContainerError":
        return _container_create_detail([item[1] for item in observations], language)
    if reason == "OOMKilled":
        return _oom_detail(_memory_sizing(observations), language)
    if reason in {"Unschedulable", "SchedulingGated"}:
        detail = _scheduling_detail([item[1] for item in observations], language)
        return detail or _scheduling_error_generic(language)
    if reason in {"ImagePullBackOff", "ErrImagePull"}:
        observed = _observed_image(observations)
        detail = _image_pull_detail([item[1] for item in observations], language, observed)
        return detail or _image_pull_generic(language, observed)
    if reason == "InvalidImageName":
        return _invalid_image_name_detail(
            [item[1] for item in observations], language, _observed_image(observations)
        )
    if reason == "ErrImageNeverPull":
        return _never_pull_detail(
            [item[1] for item in observations], language, _observed_image(observations)
        )
    return ""


def _typed_reason_observations(
    results: list[CollectorResult], eligible_evidence_ids: set[str], reason: str
) -> list[tuple[str, str, object | None, dict[str, Any]]]:
    found: list[tuple[str, str, object | None, dict[str, Any]]] = []
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            payload = getattr(item, "result", None)
            if not _typed_artifact_is_verified(payload):
                continue
            if getattr(item, "type", "") == "kubernetes_container_lifecycle":
                for container in payload.get("containers", []):
                    if not isinstance(container, dict):
                        continue
                    for key in ("state", "lastTerminated"):
                        state = container.get(key)
                        if not isinstance(state, dict) or str(state.get("reason") or "") != reason:
                            continue
                        if key == "state" and state.get("phase") not in {"waiting", "terminated"}:
                            continue
                        if key == "lastTerminated" and not (
                            reason or state.get("exitCode") is not None
                        ):
                            continue
                        if isinstance(state, dict):
                            found.append(
                                (
                                    reason,
                                    str(state.get("message") or ""),
                                    state.get("exitCode"),
                                    {"container": container, "payload": payload},
                                )
                            )
            elif getattr(item, "type", "") == "kubernetes_pod_scheduling":
                if _canonical_scheduling_reason(payload) == reason:
                    condition = payload.get("condition")
                    message = (
                        str(condition.get("message") or "")
                        if isinstance(condition, dict)
                        else ""
                    )
                    found.append((reason, message, None, {"payload": payload}))
            elif getattr(item, "type", "") == "kubernetes_warning_events":
                for event in payload.get("events", []):
                    if not (
                        isinstance(event, dict)
                        and str(event.get("type") or "") == "Warning"
                        and event.get("target_identity_verified") is True
                        and str(event.get("reason") or "") == reason
                    ):
                        continue
                    try:
                        count = int(event.get("count") or 0)
                    except (TypeError, ValueError):
                        count = 0
                    if count >= 3:
                        found.append(
                            (
                                reason,
                                str(event.get("message") or ""),
                                None,
                                {"event": event, "payload": payload},
                            )
                        )
    return found


def _typed_last_terminated_observations(
    results: list[CollectorResult], eligible_evidence_ids: set[str]
) -> list[tuple[str, str, object | None, dict[str, Any]]]:
    found: list[tuple[str, str, object | None, dict[str, Any]]] = []
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            payload = getattr(item, "result", None)
            if (
                not _typed_artifact_is_verified(payload)
                or getattr(item, "type", "") != "kubernetes_container_lifecycle"
            ):
                continue
            for container in payload.get("containers", []):
                state = container.get("lastTerminated") if isinstance(container, dict) else None
                if isinstance(state, dict):
                    found.append(
                        (
                            str(state.get("reason") or ""),
                            str(state.get("message") or ""),
                            state.get("exitCode"),
                            {"container": container, "payload": payload},
                        )
                    )
    return found


def _scoped_present(payload: object) -> bool:
    """A typed observation that actually happened inside the incident window."""
    observation = payload.get("observation") if isinstance(payload, dict) else None
    return bool(
        isinstance(observation, dict)
        and observation.get("polarity") == "present"
        and observation.get("coverage") == "scoped"
    )


def _typed_artifact_is_verified(payload: object) -> bool:
    observation = payload.get("observation") if isinstance(payload, dict) else None
    return _scoped_present(payload) and bool(
        isinstance(observation, dict) and observation.get("target_identity_verified") is True
    )


def _config_error_detail(messages: list[str], language: str) -> str:
    for message in messages:
        if match := _CONFIGMAP_NOT_FOUND.search(message):
            name = match.group(1)
            return _missing_reference_detail("ConfigMap", name, language)
        if match := _SECRET_NOT_FOUND.search(message):
            name = match.group(1)
            return _missing_reference_detail("Secret", name, language)
        if match := _MISSING_KEY.search(message):
            key = match.group(1)
            return (
                f"구체적으로는 Pod가 참조하는 ConfigMap/Secret 키 '{key}'을(를) 찾지 못해 "
                "컨테이너를 생성하지 못했습니다 (configMapKeyRef/secretKeyRef의 이름·키를 확인)."
                if language == "ko"
                else (
                    f"Specifically, Kubernetes could not find referenced ConfigMap/Secret key "
                    f"'{key}', so it cannot create the container; check "
                    "configMapKeyRef/secretKeyRef names and keys."
                )
            )
    return ""


def _missing_reference_detail(kind: str, name: str, language: str) -> str:
    if language == "ko":
        return (
            f"구체적으로는 Pod가 참조하는 {kind} '{name}'이(가) 존재하지 않아 컨테이너를 "
            "생성하지 못했습니다 (configMapKeyRef/secretKeyRef의 이름·키를 확인)."
        )
    return (
        f"Specifically, {kind} '{name}' referenced by the Pod is missing, so Kubernetes "
        "cannot create the container; check configMapKeyRef/secretKeyRef names and keys."
    )


def _config_error_generic(language: str) -> str:
    return (
        "참조된 ConfigMap/Secret이 없거나 키가 잘못되었습니다."
        if language == "ko"
        else "A referenced ConfigMap/Secret is missing or its key is invalid."
    )


def _command_error_detail(messages: list[str], language: str) -> str:
    for message in messages:
        if not re.search(
            r"executable file not found in \$?PATH|no such file or directory|permission denied",
            message,
            re.IGNORECASE,
        ):
            continue
        token = _EXECUTABLE_TOKEN.search(message)
        name = f" '{token.group(1)}'" if token else ""
        if language == "ko":
            return (
                "구체적으로는 컨테이너 command/entrypoint가 잘못되었습니다: 지정한 실행파일"
                f"{name}이(가) 이미지 안에 없거나 실행할 수 없습니다."
            )
        return (
            "Specifically, the container command/entrypoint is invalid: executable"
            f"{name} is missing from the image or cannot run."
        )
    return ""


def _command_error_generic(language: str) -> str:
    return (
        "구체적으로는 컨테이너 command/entrypoint 또는 런타임 설정 때문에 시작하지 못했습니다."
        if language == "ko"
        else "Specifically, the container could not start because of its command, entrypoint, or runtime setup."
    )


def _container_create_detail(messages: list[str], language: str) -> str:
    if any("context deadline exceeded" in message.casefold() for message in messages):
        return (
            "구체적으로는 컨테이너 런타임 생성이 시간 초과되었습니다 (context deadline exceeded)."
            if language == "ko"
            else "Specifically, container runtime creation timed out (context deadline exceeded)."
        )
    return (
        "구체적으로는 컨테이너 런타임이 컨테이너를 생성하지 못했습니다."
        if language == "ko"
        else "Specifically, the container runtime could not create the container."
    )


def _observed_restarts(
    observations: list[tuple[str, str, object | None, dict[str, Any]]],
) -> int | None:
    """Kubernetes' own restart counter for the target container."""
    for _, _, _, source in observations:
        container = source.get("container", {})
        if isinstance(container, dict) and isinstance(container.get("restartCount"), int):
            return int(container["restartCount"])
    return None


def _restart_loop_detail(
    exit_code: object | None, restarts: int | None = None, language: str = "en"
) -> str:
    """"Restarting" without the counter reads the same at 2 restarts and at 400."""
    facts = []
    if exit_code is not None:
        facts.append(f"exit {exit_code}")
    if restarts:
        facts.append(f"{restarts}회 재시작" if language == "ko" else f"{restarts} restarts")
    suffix = f" ({', '.join(facts)})" if facts else ""
    return (
        f"컨테이너가 반복 재시작 중입니다{suffix}."
        if language == "ko"
        else f"The container is repeatedly restarting{suffix}."
    )


def _oom_detail(sizing: tuple[str, str, str], language: str) -> str:
    """Name the configured ceiling and reservation that the kill happened under."""
    container, limit, request = sizing
    if language == "ko":
        base = "컨테이너가 메모리 limit을 초과해 커널이 OOM kill(exit 137) 했습니다"
        if not limit:
            return f"{base}."
        subject = f"컨테이너 `{container}`의 현재 설정은" if container else "현재 설정은"
        reservation = f"request {request}" if request else "request 미설정"
        return f"{base}. {subject} memory limit {limit}, {reservation}입니다."
    base = "The container exceeded its memory limit and the kernel OOM-killed it (exit 137)"
    if not limit:
        return f"{base}."
    subject = f"container `{container}` is" if container else "it is"
    reservation = f"request {request}" if request else "no memory request"
    return f"{base}. Currently {subject} configured with memory limit {limit} and {reservation}."


def _memory_sizing(
    observations: list[tuple[str, str, object | None, dict[str, Any]]],
) -> tuple[str, str, str]:
    """Observed ``(container, limits.memory, requests.memory)`` for the OOM detail.

    An operator's first question on an OOMKill is which ceiling was exceeded and
    what was reserved, so both sides of the spec are reported — a set limit with
    an unset request is itself a finding.
    """
    for _, _, _, source in observations:
        container = source.get("container", {})
        resources = container.get("resources") if isinstance(container, dict) else None
        if not isinstance(resources, dict):
            resources = source.get("payload", {}).get("resources", {})
        limits = resources.get("limits") if isinstance(resources, dict) else None
        if isinstance(limits, dict) and limits.get("memory"):
            requests = resources.get("requests") if isinstance(resources, dict) else None
            request = (
                str(requests["memory"])
                if isinstance(requests, dict) and requests.get("memory")
                else ""
            )
            name = str(container.get("name") or "") if isinstance(container, dict) else ""
            return name, str(limits["memory"]), request
    return "", "", ""


def _scheduling_detail(messages: list[str], language: str) -> str:
    for message in messages:
        # One canned sentence per pattern loses the rest of the scheduler's own
        # per-node tally ("2 Insufficient gpu, 3 didn't match affinity"), which is
        # the whole breakdown an operator needs. Quote the verdict alongside it.
        verdict = _scheduler_verdict(message, language)
        if "didn't match Pod's node affinity/selector" in message:
            return (
                "구체적으로는 Pod의 nodeSelector/affinity 불일치로 스케줄링할 수 없습니다."
                if language == "ko"
                else "Specifically, a nodeSelector/affinity mismatch prevents scheduling."
            ) + verdict
        if match := re.search(r"Insufficient (\S+)", message, re.IGNORECASE):
            # The scheduler ends the sentence right after the resource name, and
            # `nvidia.com/gpu` has internal dots — strip only trailing punctuation.
            resource = match.group(1).rstrip(".,;")
            return (
                f"구체적으로는 스케줄 가능한 노드의 {resource} 리소스가 부족합니다."
                if language == "ko"
                else (
                    f"Specifically, schedulable nodes have insufficient {resource} resources."
                )
            ) + verdict
        if re.search(r"untolerated taint", message, re.IGNORECASE):
            return (
                "구체적으로는 Pod가 노드 taint를 tolerate하지 않아 스케줄링할 수 없습니다."
                if language == "ko"
                else (
                    "Specifically, the Pod does not tolerate a node taint, so it cannot be "
                    "scheduled."
                )
            ) + verdict
    return ""


_SCHEDULER_VERDICT = re.compile(r"\d+/\d+ nodes are available", re.IGNORECASE)


def _scheduler_verdict(message: str, language: str) -> str:
    """The scheduler's verbatim node tally, bounded — machine text, not a guess.

    Quoted whole rather than cut at the first period: resource names carry dots
    ("2 Insufficient nvidia.com/gpu"), and the tail of the tally is the part that
    lists every OTHER reason nodes were rejected.
    """
    if not _SCHEDULER_VERDICT.search(message or ""):
        return ""
    verdict = _short_sentence(message, limit=220)
    return f" (스케줄러: {verdict})" if language == "ko" else f" (scheduler: {verdict})"


def _scheduling_error_generic(language: str) -> str:
    return (
        "구체적으로는 scheduler가 Pod를 배치할 수 있는 노드를 찾지 못했습니다."
        if language == "ko"
        else "Specifically, the scheduler could not find a node for the Pod."
    )


def _observed_image(
    observations: list[tuple[str, str, object | None, dict[str, Any]]],
) -> str:
    """The image the target container is configured to run, from typed state.

    The kubelet Event message usually repeats the reference, but not in every
    failure mode; the Pod's own container status always carries it, so the report
    can name the exact reference instead of a bare "could not pull the image".
    """
    for _, _, _, source in observations:
        container = source.get("container", {})
        if isinstance(container, dict) and container.get("image"):
            return str(container["image"])
    return ""


def _image_pull_detail(messages: list[str], language: str, observed: str = "") -> str:
    for message in messages:
        image = _IMAGE_REFERENCE.search(message)
        reference = image.group(1) if image else observed
        suffix = f" ('{reference}')" if reference else ""
        if re.search(r"not found|manifest unknown", message, re.IGNORECASE):
            return (
                f"구체적으로는 이미지 또는 tag{suffix}가 registry에 없습니다."
                if language == "ko"
                else f"Specifically, image or tag{suffix} does not exist in the registry."
            )
        if re.search(r"unauthorized|authentication required|pull access denied", message, re.IGNORECASE):
            return (
                f"구체적으로는 registry 인증 실패로 이미지{suffix}를 pull하지 못했습니다."
                if language == "ko"
                else f"Specifically, registry authentication failed, so image{suffix} cannot be pulled."
            )
    return ""


def _image_pull_generic(language: str, observed: str = "") -> str:
    suffix = f" '{observed}'" if observed else ""
    return (
        f"구체적으로는 registry에서 이미지{suffix}를 pull하지 못했습니다."
        if language == "ko"
        else f"Specifically, Kubernetes could not pull image{suffix} from the registry."
    )


def _invalid_image_name_detail(messages: list[str], language: str, observed: str = "") -> str:
    name = (
        next((match.group(1) for message in messages if (match := _IMAGE_REFERENCE.search(message))), "")
        or observed
    )
    suffix = f" '{name}'" if name else ""
    return (
        f"구체적으로는 이미지 참조{suffix} 형식이 올바르지 않습니다."
        if language == "ko"
        else f"Specifically, image reference{suffix} has an invalid format."
    )


def _never_pull_detail(messages: list[str], language: str, observed: str = "") -> str:
    name = (
        next((match.group(1) for message in messages if (match := _IMAGE_REFERENCE.search(message))), "")
        or observed
    )
    suffix = f" '{name}'" if name else ""
    return (
        f"구체적으로는 imagePullPolicy Never인데 이미지{suffix}가 노드에 없습니다."
        if language == "ko"
        else f"Specifically, imagePullPolicy Never is set but image{suffix} is absent from the node."
    )


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


# Typed artifacts that carry the configuration of the entity they type, in the
# order the report reads: the container, then the Pod's demand, then the node.
_CONFIGURATION_KINDS = (
    "kubernetes_container_lifecycle",
    "kubernetes_probe",
    "kubernetes_pod_scheduling",
    "runai_queue_quota",
    "kubernetes_storage_claim",
    "kubernetes_node_gpu_resources",
    "kubernetes_node_condition",
)
# Node-scoped artifacts carry no ``target_identity_verified`` flag: they are only
# ever collected for the alert's own node, so requiring one would drop every line.
_NODE_SCOPED_CONFIGURATION_KINDS = frozenset(
    {"kubernetes_node_condition", "kubernetes_node_gpu_resources"}
)
# Reasons that make a Bound claim's configuration worth printing: the claim is
# not itself blocked, but the volume it points at failed to attach or mount.
_STORAGE_EVENT_REASONS = frozenset(
    {
        "FailedAttachVolume",
        "FailedBinding",
        "FailedDetachVolume",
        "FailedMount",
        "ProvisioningFailed",
        "VolumeResizeFailed",
    }
)
# Resource keys worth printing, in the order an operator reads them. Anything
# else the spec carries (hugepages, extended devices) stays in the artifact.
_CONTAINER_RESOURCE_KEYS = ("memory", "cpu", "nvidia.com/gpu", "ephemeral-storage")
_NODE_RESOURCE_KEYS = ("memory", "cpu", "ephemeral-storage", "pods", "nvidia.com/gpu")
_CONFIG_LABELS = {
    "en": {
        "container": "Configured",
        "probe": "Probe settings",
        "requested": "Requested",
        "storage": "Storage claim",
        "requested_size": "requested",
        "bound_size": "bound",
        "gpu": "Node GPUs",
        "gpu_free": "free",
        "gpu_held": "held by scheduled Pods",
        "gpu_pods": "pods",
        "node": "Node capacity",
        "selector": "nodeSelector",
        "scheduler": "scheduler",
        "runai_gpus": "Run:ai GPUs allocated/requested",
        "runai_allocated": "Run:ai GPUs allocated",
        "runai_fraction": "GPU fraction",
        "runai_gang": "pod group requests",
        "runai_pods": "gang",
        "runai_type": "resource type",
        "runai_state": "Run:ai status",
        "quota": "Project quota",
        "quota_gpu": "GPUs requested/quota",
        "quota_allocated": "allocated",
        "quota_limit": "hard limit",
        "quota_weight": "over-quota weight",
        "quota_pool": "node pool",
        "unlimited": "unlimited",
        "unset": "unset",
    },
    "ko": {
        "container": "현재 설정",
        "probe": "프로브 설정",
        "requested": "요청 리소스",
        "storage": "스토리지 클레임",
        "requested_size": "요청",
        "bound_size": "실제 bound",
        "gpu": "노드 GPU",
        "gpu_free": "여유",
        "gpu_held": "기존 Pod 점유",
        "gpu_pods": "Pod 수",
        "node": "노드 용량",
        "selector": "nodeSelector",
        "scheduler": "scheduler",
        "runai_gpus": "Run:ai GPU 할당/요청",
        "runai_allocated": "Run:ai GPU 할당",
        "runai_fraction": "GPU fraction",
        "runai_gang": "pod group 요청",
        "runai_pods": "gang",
        "runai_type": "리소스 유형",
        "runai_state": "Run:ai 상태",
        "quota": "프로젝트 quota",
        "quota_gpu": "GPU 요청/quota",
        "quota_allocated": "할당",
        "quota_limit": "상한",
        "quota_weight": "over-quota 가중치",
        "quota_pool": "node pool",
        "unlimited": "무제한",
        "unset": "미설정",
    },
}


_BYTE_RESOURCE_KEYS = frozenset({"memory", "ephemeral-storage"})


def _resource_display(key: str, value: object) -> str:
    """Show `memory: 419430400` as 400Mi — a real spec writes plain bytes.

    Only when the unit form is EXACT: ``format_memory`` rounds up for anything
    that is not a whole binary unit, and a report must not restate a limit as a
    number the spec does not contain.
    """
    text = str(value)
    if key not in _BYTE_RESOURCE_KEYS or not text.isdigit():
        return text
    size = parse_memory(text)
    if size is None:
        return text
    formatted = format_memory(size)
    return formatted if parse_memory(formatted) == size else text


def _resource_pairs(resources: object, keys: tuple[str, ...], unset: str) -> list[str]:
    """``memory limit 512Mi / request 256Mi`` for every key the spec actually sets."""
    if not isinstance(resources, dict):
        return []
    limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
    requests = resources.get("requests") if isinstance(resources.get("requests"), dict) else {}
    pairs: list[str] = []
    for key in keys:
        limit, request = limits.get(key), requests.get(key)
        if not limit and not request:
            continue
        sides = [f"limit {_resource_display(key, limit)}" if limit else f"limit {unset}"]
        sides.append(
            f"request {_resource_display(key, request)}" if request else f"request {unset}"
        )
        pairs.append(f"{key} " + " / ".join(sides))
    return pairs


def _flat_resource_pairs(resources: object, keys: tuple[str, ...]) -> list[str]:
    """``memory 128Gi`` for a single-sided mapping (node allocatable, requests)."""
    if not isinstance(resources, dict):
        return []
    return [
        f"{key} {_resource_display(key, resources[key])}" for key in keys if resources.get(key)
    ]


def _gpu_fraction_total(fraction: str, devices: str) -> str:
    """``0.8`` × ``8`` -> ``" (6.4)"``, the whole-GPU equivalent of the request.

    Decimal, not float: ``0.8 * 8`` prints as 6.4000000000000005 in binary
    floating point, and a resource figure that looks like that reads as a bug.
    Values come from Run:ai's own annotations, so anything unparseable is
    skipped rather than guessed at.
    """
    if not devices or devices == "1":
        return ""
    try:
        total = Decimal(fraction) * Decimal(devices)
    except (ArithmeticError, ValueError):
        return ""
    return f" ({total.normalize():f})"


def _runai_allocation_parts(allocation: object, labels: dict[str, str]) -> list[str]:
    """Run:ai's own accounting: what it asked the scheduler for, what it got.

    ``allocated < requested`` is the pending workload's answer, and it is a
    DIFFERENT limit from node capacity — a project can be at its quota while GPUs
    sit free. Values are printed verbatim; the scheduler's vocabulary for the
    resource type is its own.
    """
    if not isinstance(allocation, dict) or not allocation:
        return []
    parts: list[str] = []
    requested = str(allocation.get("requested_gpus") or "")
    # What the Pod holds NOW beats the assigned figure when both are present.
    allocated = str(
        allocation.get("current_allocated_gpus") or allocation.get("allocated_gpus") or ""
    )
    if requested and allocated:
        parts.append(f"{labels['runai_gpus']} {allocated}/{requested}")
    elif allocated:
        # A fractional workload publishes no requested figure — only its slice.
        parts.append(f"{labels['runai_allocated']} {allocated}")
    if fraction := str(allocation.get("gpu_fraction") or ""):
        devices = str(allocation.get("gpu_fraction_devices") or "")
        suffix = f" × {devices}" if devices and devices != "1" else ""
        # "0.8 × 8" is not comparable to the project quota printed beside it
        # until it is multiplied out; print the total the scheduler had to find.
        parts.append(
            f"{labels['runai_fraction']} {fraction}{suffix}"
            + _gpu_fraction_total(fraction, devices)
        )
    gang = str(allocation.get("podgroup_requested_gpus") or "")
    if gang and gang != requested:
        parts.append(f"{labels['runai_gang']} {gang}")
    pending, running = (
        str(allocation.get("pending_pods") or ""),
        str(allocation.get("running_pods") or ""),
    )
    # A gang that is partly up is the classic Run:ai pending shape.
    if pending and pending != "0":
        parts.append(f"{labels['runai_pods']} {running or '0'} running / {pending} pending")
    for key, label in (("resource_type", "runai_type"), ("runai_status", "runai_state")):
        if value := str(allocation.get(key) or ""):
            parts.append(f"{labels[label]} {value}")
    return parts



# The backend caps an embedding query at 4000 bytes; stay under it with room for
# the family prefix rather than having the search rejected outright.
_SIMILAR_RESEARCH_QUERY_CHARS = 3500
# One short call. The analysis deadline is shared with evidence gathering and
# synthesis, so a slow backend must cost a few seconds of context, never a run.
_SIMILAR_RESEARCH_TIMEOUT_SECONDS = 5.0


async def _refresh_similar_incidents_from_evidence(
    settings: Settings, request: AlertAnalysisRequest, state: PipelineState
) -> None:
    """Re-run similar-incident retrieval on the evidence THIS run collected.

    Similar incidents are attached to the request at run CREATION, before any
    evidence exists, so a first analysis matched on the alert alone -- labels and
    the Alertmanager boilerplate every incident of that alertname shares. The
    backend re-resolves again once the RCA lands, but that is too late for this
    report: the "Similar past incident ..." line is written below.

    By this point the run has its observed evidence and a ranked family, which is
    what "what broke" actually looks like. Searching on that is a closer question
    than the alert, and a weaker one than the finished RCA -- symptom-alike
    incidents can still surface (two OOMKills with different causes), so the
    ranked family goes into the query to pull toward mechanism over symptom.

    Best-effort CONTEXT, never evidence: no backend, no evidence, an exhausted
    deadline or any transport failure keeps the run-creation set untouched.
    """
    backend_url = str(getattr(settings, "backend_url", "") or "").strip().rstrip("/")
    observed = (state.observed or "").strip()
    if not backend_url or not observed:
        return
    remaining = _analysis_time_remaining()
    if remaining is not None and remaining <= _SIMILAR_RESEARCH_TIMEOUT_SECONDS:
        return
    family = state.root_cause_candidates[0].family if state.root_cause_candidates else ""
    query = f"{family} {observed}".strip()[:_SIMILAR_RESEARCH_QUERY_CHARS]
    try:
        response = await post_json(
            url=f"{backend_url}/api/v1/embeddings/search",
            timeout_seconds=_SIMILAR_RESEARCH_TIMEOUT_SECONDS,
            json_body={
                "query": query,
                "limit": len(request.similar_incidents) or 3,
                # Never match this incident against its own stored memory row.
                "exclude_incident_id": request.incident_id or "",
            },
        )
    except Exception as exc:  # noqa: BLE001 - context, never worth failing a run
        _log.warning("similar-incident re-search failed: %s: %s", type(exc).__name__, exc)
        return
    if not response.ok or not isinstance(response.data, dict):
        _log.warning(
            "similar-incident re-search returned no usable result (status=%s)",
            response.status_code,
        )
        return
    payload = response.data.get("data")
    rows = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        return
    refreshed: list[SimilarIncidentContext] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            refreshed.append(SimilarIncidentContext(**row))
        except ValidationError:
            continue
    if refreshed:
        # The request field IS "the similar incidents for this analysis"; the
        # report line and its trust floor both read it from here.
        request.similar_incidents = refreshed

def _observed_configuration_lines(
    results: list[CollectorResult],
    eligible_evidence_ids: set[str] | None,
    language: str,
) -> list[str]:
    """The problem entity's own settings, from the typed artifacts that named it.

    Every mechanism sentence answers WHAT failed; an operator's next question is
    always what the thing was configured with — the limit that was exceeded, the
    request no node could satisfy, the capacity a node ran out of.  Each typed
    artifact carries the configuration of the entity it types, so this walks the
    same eligible, target-verified evidence and needs no per-family table.
    """
    if not eligible_evidence_ids:
        return []
    labels = _CONFIG_LABELS.get(language, _CONFIG_LABELS["en"])
    unset = labels["unset"]
    lines: dict[str, str] = {}
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            kind = getattr(item, "type", "")
            payload = getattr(item, "result", None)
            if kind in lines or kind not in _CONFIGURATION_KINDS:
                continue
            # Pod-scoped artifacts prove they are about the alert Pod and use the
            # full bar. Node-scoped ones are only ever collected for the alert's own
            # node, so they carry no identity flag to check — requiring one would
            # silently drop every node-capacity line.
            verified = (
                _scoped_present(payload)
                if kind in _NODE_SCOPED_CONFIGURATION_KINDS
                else _typed_artifact_is_verified(payload)
            )
            if verified and (line := _configuration_line(kind, payload, labels, unset)):
                lines[kind] = line
    # Two failures leave the responsible SETTING in a different artifact from the
    # evidence, so they are resolved after the eligible walk and never override it:
    # a not-Ready container has no causal container state (the kubelet reports an
    # Unhealthy Event), and a Bound claim is not itself blocked when the volume it
    # points at fails to attach or mount. In both cases the event must be eligible
    # evidence; the settings are then read off the identity-verified spec.
    if "kubernetes_probe" not in lines and _probe_failure_observed(
        results, eligible_evidence_ids
    ):
        if line := _probe_configuration_line(results, labels):
            lines["kubernetes_probe"] = line
    # Quota is a policy object read live: it states the ceiling, never that the
    # ceiling was hit in this window. The eligible unschedulable observation is
    # what makes it relevant, exactly as the event does for probes and claims.
    if "runai_queue_quota" not in lines and "kubernetes_pod_scheduling" in lines:
        if line := _identity_verified_configuration_line(
            results, "runai_queue_quota", labels, unset
        ):
            lines["runai_queue_quota"] = line
    # The node's GPU ledger is context, not proof. "A live snapshot showing free
    # GPUs must never substantiate a shortage" stays enforced where it belongs —
    # the collector's observation polarity, which the ranker reads — and that is
    # why the eligible walk above admits this artifact only when the node is
    # exhausted. But an operator whose 6.4-GPU request did not start asks "what
    # does the node actually have left?" precisely in the NOT-exhausted case, so
    # printing it beside the quota ceiling is the same trade the quota line makes.
    if "kubernetes_node_gpu_resources" not in lines and "kubernetes_pod_scheduling" in lines:
        if line := _node_verified_configuration_line(
            results, "kubernetes_node_gpu_resources", labels, unset
        ):
            lines["kubernetes_node_gpu_resources"] = line
    if "kubernetes_storage_claim" not in lines and _warning_event_observed(
        results, eligible_evidence_ids, _STORAGE_EVENT_REASONS
    ):
        if line := _identity_verified_configuration_line(
            results, "kubernetes_storage_claim", labels, unset
        ):
            lines["kubernetes_storage_claim"] = line
    return [_safe_line(lines[kind], limit=400) for kind in _CONFIGURATION_KINDS if kind in lines]


def _warning_event_observed(
    results: list[CollectorResult],
    eligible_evidence_ids: set[str],
    reasons: frozenset[str],
) -> bool:
    """An eligible, target-verified Warning event with one of these exact reasons."""
    for result in results:
        for item in result.artifacts:
            if str(getattr(item, "evidence_id", "") or "") not in eligible_evidence_ids:
                continue
            if getattr(item, "type", "") != "kubernetes_warning_events":
                continue
            payload = getattr(item, "result", None)
            if not _typed_artifact_is_verified(payload):
                continue
            for event in payload.get("events", []):
                if (
                    isinstance(event, dict)
                    and str(event.get("reason") or "") in reasons
                    and event.get("target_identity_verified") is True
                ):
                    return True
    return False


def _probe_failure_observed(
    results: list[CollectorResult], eligible_evidence_ids: set[str]
) -> bool:
    return _warning_event_observed(results, eligible_evidence_ids, frozenset({"Unhealthy"}))


def _identity_verified_configuration_line(
    results: list[CollectorResult], kind: str, labels: dict[str, str], unset: str
) -> str:
    """Render a config line from an identity-verified artifact of any polarity.

    Used only when a separate eligible event already established the failure: the
    artifact supplies WHAT the entity is configured with, never THAT it failed.
    """
    for result in results:
        for item in result.artifacts:
            if getattr(item, "type", "") != kind:
                continue
            payload = getattr(item, "result", None)
            observation = payload.get("observation") if isinstance(payload, dict) else None
            if not (
                isinstance(observation, dict)
                and observation.get("target_identity_verified") is True
            ):
                continue
            if line := _configuration_line(kind, payload, labels, unset):
                return line
    return ""


def _node_verified_configuration_line(
    results: list[CollectorResult], kind: str, labels: dict[str, str], unset: str
) -> str:
    """The same, for NODE-scoped artifacts, which carry no identity flag.

    A node snapshot proves which node it read by naming it in ``observed_entity``,
    and the collector sets that only after matching the response to the node it
    asked for — the node-side equivalent of ``target_identity_verified``.
    """
    for result in results:
        for item in result.artifacts:
            if getattr(item, "type", "") != kind:
                continue
            payload = getattr(item, "result", None)
            observation = payload.get("observation") if isinstance(payload, dict) else None
            entity = (
                observation.get("observed_entity") if isinstance(observation, dict) else None
            )
            if not (
                isinstance(entity, dict)
                and entity.get("kind") == "node"
                and entity.get("name")
            ):
                continue
            if line := _configuration_line(kind, payload, labels, unset):
                return line
    return ""


def _probe_configuration_line(results: list[CollectorResult], labels: dict[str, str]) -> str:
    """Probe handler and thresholds from the identity-verified target Pod spec."""
    for result in results:
        for item in result.artifacts:
            if getattr(item, "type", "") != "kubernetes_container_lifecycle":
                continue
            payload = getattr(item, "result", None)
            observation = payload.get("observation") if isinstance(payload, dict) else None
            if not (
                isinstance(observation, dict)
                and observation.get("target_identity_verified") is True
            ):
                continue
            for container in payload.get("containers", []):
                probes = container.get("probes") if isinstance(container, dict) else None
                if not isinstance(probes, dict) or not probes:
                    continue
                rendered = [
                    f"{kind} " + _probe_text(settings)
                    for kind, settings in probes.items()
                    if isinstance(settings, dict)
                ]
                name = str(container.get("name") or "")
                subject = f"{labels['probe']} ({name})" if name else labels["probe"]
                return f"- {subject}: " + " · ".join(rendered)
    return ""


def _probe_text(settings: dict[str, Any]) -> str:
    handler = str(settings.get("handler") or "")
    timings = ", ".join(
        f"{_PROBE_LABELS[field]} {settings[field]}" + ("s" if field.endswith("Seconds") else "")
        for field in _PROBE_LABELS
        if settings.get(field) is not None
    )
    return f"{handler} ({timings})" if handler and timings else handler or timings


# Kubernetes' own field names, shortened but not renamed — an operator has to
# find these keys in the spec to change them.
_PROBE_LABELS = {
    "initialDelaySeconds": "delay",
    "periodSeconds": "period",
    "timeoutSeconds": "timeout",
    "failureThreshold": "failures",
    "successThreshold": "successes",
}


def _container_lifecycle_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    for container in payload.get("containers", []):
        if not isinstance(container, dict):
            continue
        pairs = _resource_pairs(container.get("resources"), _CONTAINER_RESOURCE_KEYS, unset)
        if image := str(container.get("image") or ""):
            pairs.append(f"image {image}")
        if pairs:
            name = str(container.get("name") or "")
            subject = f"{labels['container']} ({name})" if name else labels["container"]
            return f"- {subject}: " + " · ".join(pairs)
    return ""


def _pod_scheduling_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    resources = payload.get("resources")
    parts: list[str] = []
    for name, spec in (resources or {}).items() if isinstance(resources, dict) else ():
        requested = spec.get("requests") if isinstance(spec, dict) else None
        if pairs := _flat_resource_pairs(requested, _CONTAINER_RESOURCE_KEYS):
            parts.append(f"{name}: " + ", ".join(pairs))
    selector = payload.get("node_selector")
    if isinstance(selector, dict) and selector:
        rendered = ", ".join(f"{key}={value}" for key, value in sorted(selector.items()))
        parts.append(f"{labels['selector']} {rendered}")
    if scheduler := str(payload.get("scheduler") or ""):
        parts.append(f"{labels['scheduler']} {scheduler}")
    parts.extend(_runai_allocation_parts(payload.get("runai_allocation"), labels))
    return f"- {labels['requested']}: " + " · ".join(parts) if parts else ""


def _queue_quota_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    parts = []
    quota = str(payload.get("gpu_quota") or "")
    requested = str(payload.get("gpu_requested") or "")
    if quota or requested:
        # requested/quota is the borrow question: above quota, the project is
        # only served from idle capacity, and only if its weight allows it.
        parts.append(
            f"{labels['quota_gpu']} {requested or '?'}/{quota or labels['unlimited']}"
        )
    if allocated := str(payload.get("gpu_allocated") or ""):
        parts.append(f"{labels['quota_allocated']} {allocated}")
    if limit := str(payload.get("gpu_limit") or ""):
        parts.append(f"{labels['quota_limit']} {limit}")
    if weight := str(payload.get("gpu_over_quota_weight") or ""):
        parts.append(f"{labels['quota_weight']} {weight}")
    if pool := str(payload.get("node_pool") or ""):
        parts.append(f"{labels['quota_pool']} {pool}")
    if not parts:
        return ""
    queue = str(payload.get("queue") or "")
    subject = f"{labels['quota']} ({queue})" if queue else labels["quota"]
    return f"- {subject}: " + " · ".join(parts)


def _storage_claim_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    claim = str(payload.get("claim") or "")
    parts = []
    if requested := payload.get("requested_storage"):
        actual = payload.get("actual_storage")
        # A bound PV can be larger than the request; both numbers matter.
        parts.append(
            f"{labels['requested_size']} {requested}"
            + (f" ({labels['bound_size']} {actual})" if actual and actual != requested else "")
        )
    for key, label in (("storage_class", "storageClass"), ("volume_mode", "volumeMode")):
        if value := payload.get(key):
            parts.append(f"{label} {value}")
    if modes := payload.get("access_modes"):
        parts.append(", ".join(str(mode) for mode in modes))
    if phase := payload.get("phase"):
        parts.append(f"phase {phase}")
    if volume := payload.get("volume_name"):
        parts.append(f"PV {volume}")
    if not parts:
        return ""
    subject = f"{labels['storage']} ({claim})" if claim else labels["storage"]
    return f"- {subject}: " + " · ".join(parts)


def _node_gpu_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    # The comparison a pending GPU workload turns on: what the node can give
    # against what the Pods already on it hold.
    node = str(payload.get("node") or "")
    free, allocatable = payload.get("gpu_estimated_free"), payload.get("gpu_allocatable")
    if free is None or allocatable is None:
        return ""
    parts = [
        f"{labels['gpu_free']} {free}/{allocatable}",
        f"{labels['gpu_held']} {payload.get('gpu_requested')}",
    ]
    if capacity := payload.get("gpu_capacity"):
        parts.append(f"capacity {capacity}")
    if pods := payload.get("scheduled_non_terminal_pods"):
        parts.append(f"{labels['gpu_pods']} {pods}")
    subject = f"{labels['gpu']} ({node})" if node else labels["gpu"]
    return f"- {subject}: " + " · ".join(parts)


def _node_condition_config(payload: dict[str, Any], labels: dict[str, str], unset: str) -> str:
    pairs = _flat_resource_pairs(payload.get("allocatable"), _NODE_RESOURCE_KEYS)
    node = str(payload.get("node") or "")
    if not pairs:
        return ""
    subject = f"{labels['node']} ({node})" if node else labels["node"]
    return f"- {subject}: " + ", ".join(pairs)


# Each observation kind renders the settings an operator would have to change,
# never the observed values themselves.
_CONFIGURATION_LINES: dict[str, Callable[[dict[str, Any], dict[str, str], str], str]] = {
    "kubernetes_container_lifecycle": _container_lifecycle_config,
    "kubernetes_pod_scheduling": _pod_scheduling_config,
    "runai_queue_quota": _queue_quota_config,
    "kubernetes_storage_claim": _storage_claim_config,
    "kubernetes_node_gpu_resources": _node_gpu_config,
    "kubernetes_node_condition": _node_condition_config,
}


def _configuration_line(
    kind: str, payload: dict[str, Any], labels: dict[str, str], unset: str
) -> str:
    render = _CONFIGURATION_LINES.get(kind)
    return render(payload, labels, unset) if render else ""


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


_FAMILY_EXPLANATION_KO = {
    "node_kubelet_pressure": "호스팅 노드의 디스크·메모리·PID 리소스 압박",
    "runai_scheduling_quota": "Run:ai 스케줄러의 GPU quota·fairshare·preemption 제약",
    "k8s_scheduling_error": "taint·affinity·topology·ResourceQuota에 따른 Kubernetes 스케줄링 실패",
    "runai_control_plane_error": "Run:ai control plane 오류",
    "k8s_control_plane_error": "Kubernetes control plane 오류",
    "workload_startup_error": "이미지 pull 이후 컨테이너 시작·설정 단계의 오류",
    "image_pull_error": "이미지 이름·tag·manifest 또는 registry 인증 문제로 인한 이미지 pull 실패",
    "gpu_hardware_error": "GPU 하드웨어 오류",
    "network_fabric_error": "NCCL·InfiniBand·NVLink 계층의 GPU fabric 오류",
    "cluster_network_error": "CNI·DNS 등 클러스터 네트워크 오류",
    "k8s_storage_error": "CSI·PVC·StorageClass 계층의 Kubernetes 스토리지 오류",
    "storage_backend_error": "NFS·Ceph 등 스토리지 backend 오류",
    "workload_runtime_error": "애플리케이션 실행 중 오류",
    "platform_auth_error": "로그인·권한·SAML·OIDC 인증 오류",
    "platform_version_bug": "Run:ai 버전 결함",
    "observability_accuracy": "워크로드가 아닌 메트릭·관측 정확도 문제",
    "expected_known_behavior": "제품의 알려진 정상 동작",
    "platform_lifecycle_change": (
        "플랫폼 rollout·업그레이드 진행 중 발생한 예상된 변동(GPU Operator·컨트롤러·"
        "Helm 릴리스) — 결함이 아니므로 먼저 rollout·Helm 릴리스 완료 여부를 확인"
    ),
}


def _catalog_only_candidate_counts(
    graph_counts: dict[str, int], reasoning: object
) -> dict[str, int]:
    """Apply the closed family vocabulary to graph candidate priors.

    Legacy TypeDB rows still carry pre-catalog names; they must not leak into
    ranking priors or per-run ontology metadata. Dropped names are recorded in
    the reasoning metadata so the leak stays visible instead of silent.
    """
    dropped = sorted(set(graph_counts) - set(FAMILIES))
    if not dropped:
        return graph_counts
    _log.warning("dropping non-catalog candidate families from graph prior: %s", dropped)
    if isinstance(reasoning, dict):
        reasoning["dropped_candidate_families"] = dropped
    return {family: count for family, count in graph_counts.items() if family in FAMILIES}


def _catalog_only_knowledge(
    knowledge: dict[str, list[dict[str, Any]]] | None,
) -> dict[str, list[dict[str, Any]]]:
    """Drop graph-supplied families outside the closed catalog vocabulary.

    An LLM-authored family ingested into TypeDB must never be consumed as a
    curated symptom: the symptom matcher would headline a name the harness
    cannot ground, forcing an abstain over a signature-clean catalog family.
    """
    if not knowledge:
        return {}
    non_catalog = sorted(set(knowledge) - set(FAMILIES))
    if not non_catalog:
        return knowledge
    _log.warning("dropping non-catalog families from graph knowledge: %s", non_catalog)
    return {
        family: symptoms for family, symptoms in knowledge.items() if family in FAMILIES
    }


# A link says where to READ about an alert; it never observes one. Every
# kube-prometheus-stack rule ships runbook_url=https://runbooks.prometheus-
# operator.dev/..., so leaving a raw link in made the vendor's own
# documentation host a matchable signature: INC-…-000001 headlined
# observability_accuracy ("this alert is a false alarm", 7.0/medium, zero
# supporting evidence) on the single keyword "prometheus-operator" taken from
# that URL. Same rule as the ranker's METADATA_VALUE_KEYS — what we ASKED or
# where to look is not what came back. A URL is never a signal either way
# (guidance has no use for a doc host name any more than the matcher does), so
# both ``_alert_text`` and ``_alert_signature_text`` below strip it out of
# annotation prose while keeping the human-readable text around it.
_ALERT_LINK_RE = re.compile(r"https?://\S+", re.I)


def _compose_alert_text(labels: dict[str, Any], annotations: dict[str, Any]) -> str:
    """Shared assembly for ``_alert_text``/``_alert_signature_text``: recompose
    Boolean condition/status label pairs, then append the remaining label and
    annotation values (links stripped out of the latter). Callers choose what
    goes IN via ``labels``/``annotations`` — this function only renders it."""
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
    parts.extend(
        stripped
        for value in annotations.values()
        if (stripped := _ALERT_LINK_RE.sub(" ", str(value)).strip())
    )
    return " ".join(parts)


def _alert_text(request: AlertAnalysisRequest) -> str:
    """The alert's own labels+annotations text, permissively — every field
    (including ``runbook_url`` and the operator's own ``operator_prompt``
    speculation) is available here. This feeds investigation ORDER: component
    identification, fuzzy recall, and the non-diagnostic guidance block, where
    the operator saying "check CoreDNS" should steer what gets shown. It must
    never be used as the haystack a signature/symptom match can be PROMOTED
    from — that is ``_alert_signature_text``, the deliberately narrower
    sibling below. (A bare link is still stripped out of annotation prose: a
    URL is not useful investigation-order signal either, and dropping it keeps
    the human-readable text around it.)"""
    alert = request.alert
    return _compose_alert_text(alert.labels or {}, alert.annotations or {})


def _alert_signature_text(request: AlertAnalysisRequest) -> str:
    """The alert's own text, narrowed to what may support a signature/symptom
    match — it often carries the signature (e.g. 'XID 79 ... GPU has fallen
    off the bus') even when every collector comes back empty. Non-evidence
    fields (runbook/operator_prompt/query/..., see
    ``_ALERT_NON_EVIDENCE_FIELD_RE``) are excluded entirely: operator guidance
    may steer investigation order (``_alert_text``) but must never promote a
    cause. Feeds ``_observed_text``'s alert branch (state.observed, XID
    extraction, self-check's declared-alert, and the actions/playbook/
    knowledge-base fuzzy recall that can render a matched symptom's actions
    into the report) — every consumer that can turn a match into rendered
    output, as opposed to a conditional suggestion."""
    alert = request.alert
    labels = {
        key: value
        for key, value in (alert.labels or {}).items()
        if not _ALERT_NON_EVIDENCE_FIELD_RE.search(str(key))
    }
    annotations = {
        key: value
        for key, value in (alert.annotations or {}).items()
        if not _ALERT_NON_EVIDENCE_FIELD_RE.search(str(key))
    }
    return _compose_alert_text(labels, annotations)


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
        # empty matches NOTHING even though its own text names the fault. Use the
        # NARROW alert text here (not ``_alert_text``): this haystack feeds
        # ``state.observed``, which promotes causes — see ``_alert_signature_text``.
        parts.append(_alert_signature_text(request))
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
    history = kg_context.get("location_history") or []
    if history:
        history_truncated = bool(kg_context.get("location_history_truncated"))
        rendered_history = min(len(history), 4)
        history_count = (
            f"At least {len(history)} past resolved incident(s)"
            if history_truncated
            else f"{len(history)} past resolved incident(s)"
        )
        body.append(
            f"- {history_count} at this alert's location "
            "(different alerts, same node/namespace"
            + (f"; showing {rendered_history}" if history_truncated else "")
            + "):"
        )
        for item in history[:4]:
            where = active_masker.mask_text(str(item.get("where") or "location"))
            incident_id = _short_sentence(
                active_masker.mask_text(str(item.get("incident_id") or "(unknown)")), limit=80
            )
            summary = _short_sentence(
                active_masker.mask_text(
                    str(item.get("analysis_summary") or "(no stored RCA summary)")
                ),
                limit=240,
            )
            body.append(f"  - {incident_id} ({where}): {summary}")
    topology = kg_context.get("workload_topology") or {}
    topology_status = kg_context.get("workload_topology_status") or ""
    if topology.get("services") or topology.get("pvcs"):
        parts = []
        if topology.get("services"):
            parts.append("Service(s) " + ", ".join(topology["services"][:5]))
        if topology.get("pvcs"):
            parts.append("PVC(s) " + ", ".join(topology["pvcs"][:5]))
        line = "- Workload topology (stable identity): " + "; ".join(parts)
        shared = topology.get("shared_storage_workloads") or []
        if shared:
            line += (
                f" — PVC shared with {len(shared)} other workload(s): "
                + ", ".join(shared[:5])
            )
        if topology.get("shared_storage_truncated"):
            searched = ", ".join(topology.get("shared_storage_pvcs") or [])
            line += f" — shared-storage checked only on PVC(s) {searched}"
        body.append(active_masker.mask_text(line))
    elif topology_status == "complete":
        body.append("- Workload topology (stable identity): no Services or PVCs found.")
    elif topology_status == "skipped_missing_namespace":
        body.append(
            "- Workload topology (stable identity): lookup skipped because the alert has no namespace."
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
        if filter_to_top and family != top_family and not is_matcher_only_family(family):
            continue
        actions = symptom.get("actions", [])
        if actions:
            symptom_name = _safe_line(symptom.get("symptom"), limit=160, masker=active_masker)
            learned = is_matcher_only_family(family)
            header = ("- Learned from a previous incident (not a catalog family): " if learned else "") + (
                f"Matched symptom **{symptom_name}** ({_family_label(family)}); known fixes from the knowledge base:"
            )
            return [
                header,
                *[f"  - {_safe_line(a, limit=360, masker=active_masker)}" for a in actions[:5]],
            ]
        symptom_name = _safe_line(symptom.get("symptom"), limit=160, masker=active_masker)
        return [
            f"Matched symptom **{symptom_name}** ({_family_label(family)}); "
            "family prior from the knowledge base (no verified action recorded)."
        ]
    # No symptom keyword matched the observed evidence: don't dump a generic family
    # checklist as if it were a match — say so plainly.
    return ["- No closely-matching prior knowledge for this evidence yet."]


def _playbook_lines(
    candidates: list[RankedCause] | None,
    observed_text: str,
    fuzzy_query: str = "",
    component: str = "",
    *,
    knowledge: ReportKnowledge,
    allow_remediation: bool = True,
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
    active_masker = knowledge.masker or build_masker(())
    top_family = candidates[0].family if candidates else ""
    filter_to_top = _top_family_settled(candidates)
    if component:
        comp_lines = component_check_lines(knowledge.components or {}, component)
        if comp_lines:
            lines.append(f"- **{component}** (the alert target itself)")
            lines.extend(comp_lines)
    for issue in match_runai_known_issues(
        knowledge.known_issues or [], observed_text, fuzzy_query=fuzzy_query
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
        knowledge.failure_modes, observed_text, candidates, fuzzy_query=fuzzy_query
    )
    if symptom_matches[0:1] and symptom_matches[0][1].get("exclusive_actions"):
        lines = []
    for family, symptom in symptom_matches[:1]:
        symptom_name = _safe_line(
            _localized_failure_mode_name(symptom, knowledge.language),
            limit=180,
            masker=active_masker,
        )
        learned = is_matcher_only_family(family)
        lines.append(("- 이전 인시던트에서 학습된 지식(카탈로그 계열 아님): " if learned and knowledge.language == "ko" else "- Learned from a previous incident (not a catalog family): " if learned else "- ") + f"**{symptom_name}** ({_family_label(family)})")
        lines.extend(
            f"  - {_safe_line(action, limit=360, masker=active_masker)}"
            for action in _localized_failure_mode_actions(symptom, knowledge.language)[:5]
        )
        # Architecture layer: the implicated platform component's failure effect,
        # dependency check order, and ready-to-run checks (runai_architecture.yaml).
        if symptom.get("component"):
            lines.extend(component_check_lines(knowledge.components or {}, str(symptom["component"])))
    if lines:
        # Preserve sibling symptom discriminators as explicitly unconfirmed
        # appendix context. The family has no independent executable remedy.
        if symptom_matches and not symptom_matches[0][1].get("exclusive_actions"):
            lines.extend(
                _family_supplemental_playbook_lines(
                    top_family,
                    knowledge=replace(knowledge, masker=active_masker),
                    exclude_symptom=str(symptom_matches[0][1].get("symptom") or ""),
                )
            )
        return lines
    if top_family == "insufficient_evidence":
        return [
            "- 현재 증거와 정확히 일치하는 트러블슈팅 playbook이 없습니다."
            if knowledge.language == "ko"
            else "- No troubleshooting playbook matched the available evidence yet."
        ]
    if top_family:
        family_context = [
            "- 원인 family는 추정됐지만 세부 증상은 확인되지 않았습니다. "
            "아래 항목은 확정 조치가 아니라 추가 증거 수집용 보조 점검입니다."
            if knowledge.language == "ko"
            else "- The cause family is ranked, but no specific symptom is confirmed; "
            "the items below are supplemental checks for collecting evidence, not confirmed fixes."
        ]
        family_context.extend(
            _family_supplemental_playbook_lines(
                top_family, knowledge=replace(knowledge, masker=active_masker)
            )
        )
        return family_context
    if knowledge.cases:
        return [knowledge.cases]
    return ["- No troubleshooting guidance is available for this cause yet."]


def _family_supplemental_playbook_lines(
    family: str,
    *,
    knowledge: ReportKnowledge,
    exclude_symptom: str = "",
) -> list[str]:
    """Render sibling symptoms as discriminators, never as executable fixes."""
    symptoms = knowledge.failure_modes.get(family) or []
    rendered: list[str] = []
    for symptom in symptoms:
        if str(symptom.get("symptom") or "") == exclude_symptom:
            continue
        name = _safe_line(
            _localized_failure_mode_name(symptom, knowledge.language), limit=160, masker=knowledge.masker
        )
        signals = [
            _safe_line(keyword, limit=100, masker=knowledge.masker)
            for keyword in symptom.get("keywords", [])[:4]
        ]
        signals = [signal for signal in signals if signal]
        if not name or not signals:
            continue
        signal_text = ", ".join(f"`{signal}`" for signal in signals)
        discriminator = (
            f"구분 신호: {signal_text}"
            if knowledge.language == "ko"
            else f"Distinguishing signals: {signal_text}"
        )
        rendered.append(f"  - **{name}** — {discriminator}")
        if len(rendered) >= 4:  # at most four sibling mechanisms
            break
    if not rendered:
        return []
    heading = (
        "- **같은 family의 대안 symptom (현재 증거로 확인되지 않음)**"
        if knowledge.language == "ko"
        else "- **Alternative symptoms in the same family (not confirmed by current evidence)**"
    )
    return [heading, *rendered]


_family_label = family_label


def _short_sentence(value: str, *, limit: int) -> str:
    text = " ".join(value.split())
    if not text:
        return "The agent has not received enough alert context to name a root cause."
    # ponytail: textwrap.shorten cuts at a word boundary instead of mid-word --
    # the naive text[:limit] slice this replaced produced garbage like
    # "...ResourceQu…입니다." in a real report (word chopped, then a Korean
    # copula glued onto the fragment). Same fix as general_guidance._safe.
    return textwrap.shorten(text, width=limit, placeholder="…")


def _safe_line(value: object, *, limit: int, masker: Masker | None = None) -> str:
    active_masker = masker or build_masker(())
    text = " ".join(active_masker.mask_text(str(value or "")).split())
    return textwrap.shorten(text, width=limit, placeholder="…") if text else text


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


# Backend blended scale: identity contributes at most labelWeight, so scores no
# longer saturate near 1.0 the way the old additive label bonus made them. Same
# bar in meaning, different units — see minFeedbackHintSimilarity in the backend.
_SIMILARITY_FLOOR = 0.70


def approved_similar_seed(similar_incidents: list[object], families_catalog: object) -> str:
    """Return the unambiguous approved prior family trusted for recurrence replay."""
    catalog_families = set(getattr(families_catalog, "families", ()))
    qualified = [
        incident
        for incident in similar_incidents
        if bool(getattr(incident, "approved", False))
        and (getattr(incident, "similarity", 0) or 0) >= _SIMILARITY_FLOOR
        and (family := str(getattr(incident, "root_cause_family", "") or "").strip())
        and family in catalog_families
    ]
    if not qualified:
        return ""
    highest_similarity = max((incident.similarity or 0) for incident in qualified)
    best = [
        incident for incident in qualified if (incident.similarity or 0) == highest_similarity
    ]
    if len(best) != 1:
        return ""
    return str(best[0].root_cause_family).strip()


def _recommended_action_lines(
    missing: list[str],
    request: AlertAnalysisRequest | None = None,
    *,
    include_similar: bool = True,
) -> list[str]:
    # Concrete actions only — no generic "trust the evidence" filler.
    #
    # R2: this used to also emit "Restore Run:ai API authentication" /
    # "Fix Loki reachability" / "Restore Postgres connectivity" whenever
    # ``missing`` carried the matching key — regardless of WHY it was missing.
    # In a real run that gap was OUR OWN transport failure (MCP unavailable:
    # self-signed certificate, HTTP 404), and it was the ONLY action on a
    # GPU-exhaustion incident: fixing our own tooling is not incident
    # remediation. ``missing`` (kept for callers/signature stability) and its
    # human-readable cause already surface honestly via ``response.missing_data``
    # and ``response.warnings`` (populated straight from each collector's own
    # ``missing_data``/``warnings``, see ``_aggregate_evidence``) and, when the
    # RCA could not settle, via ``_operator_questions``'s "is X reachable?" —
    # this list stays reserved for fixing the CLUSTER problem.
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
    return lines


async def _operator_questions(
    settings: Settings,
    missing: list[str],
    plan: InvestigationPlan | None,
    target: AnalysisTarget,
    next_check: str,
    executed_queries: list[str] | None = None,
    held_evidence: list[str] | None = None,
) -> list[str]:
    """2-4 concrete follow-up questions when the RCA could not settle.

    Derived deterministically from missing_data + the plan; the LLM only sharpens
    the wording when configured (deterministic list is the fallback).

    ``held_evidence`` (eligible artifact summaries, e.g. "E01: gpu_capacity 8 /
    gpu_requested 8") cross-checks every draft question -- R4: a real run asked
    for kube-scheduler logs already held as E113 and per-node GPU usage already
    held as E01, because this function previously saw only executed QUERY
    strings, never what they returned.
    """
    ko = getattr(settings, "language", "en") == "ko"
    held_text = " ".join(held_evidence or [])

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
    # R4: drop any draft an eligible artifact already answers BEFORE the
    # "ensure at least 2" fallback, so a filtered-out ask is genuinely replaced
    # rather than just padding a list that already had one held-evidence dup.
    questions = [q for q in questions if not _already_answered(q, held_text)]
    if len(questions) < 2:
        questions.append(
            "알림 발생 시각 전후에 배포나 설정 변경이 있었는지 확인해 주세요."
            if ko
            else "Were there any deployments or config changes around the alert time?"
        )
    questions = questions[:4]

    if llm_configured(settings, getattr(settings, "llm_model_insight", "")):
        try:
            sharpened = await _sharpen_operator_questions(
                settings, questions, missing, plan, executed_queries or [], held_evidence or []
            )
        except Exception:  # noqa: BLE001 - sharpening is best-effort
            sharpened = None
        if sharpened:
            sharpened = [q for q in sharpened if not _already_answered(q, held_text)]
        if sharpened:
            return sharpened
    return [_short_sentence(question, limit=240) for question in questions]


_QUESTION_STOPWORDS = frozenset(
    {
        "the", "is", "are", "was", "were", "this", "that", "for", "and", "or",
        "please", "check", "confirm", "verify", "provide", "does", "did",
        "확인해", "주세요", "있는지", "설정되어", "가능한지", "대한", "관련",
    }
)


def _already_answered(question: str, held_text: str) -> bool:
    """True when an eligible artifact's own text already covers a draft
    question -- most of its salient (4+ char) words already appear in
    ``held_text``. Deliberately conservative (>=60% overlap, needs 2+ salient
    words) so a generic connectivity question ("Is the Kubernetes token
    valid?") is never spuriously dropped; it only catches a near-duplicate ask
    for content an eligible artifact literally already carries."""
    if not question or not held_text:
        return False
    words = [
        w
        for w in re.findall(r"[a-z0-9가-힣]+", question.casefold())
        if len(w) > 3 and w not in _QUESTION_STOPWORDS
    ]
    if len(words) < 2:
        return False
    held = held_text.casefold()
    hits = sum(1 for w in words if w in held)
    return hits / len(words) >= 0.6


def _executed_evidence_queries(artifacts: list[object], limit: int = 12) -> list[str]:
    queries: list[str] = []
    seen: set[str] = set()
    for item in artifacts:
        query = getattr(item, "query", None)
        if not isinstance(query, str):
            continue
        compact = " ".join(query.split())
        if not compact or compact in seen:
            continue
        seen.add(compact)
        queries.append(compact)
        if len(queries) == limit:
            break
    return queries


def _held_evidence_summaries(
    artifacts: list[object], eligible_support_ids: set[str] | None, limit: int = 12
) -> list[str]:
    """What an eligible artifact already SAYS -- R4's other half. Query strings
    alone (``_executed_evidence_queries``) tell a reader what was ASKED, not
    what came back, so a probe that ran and returned "gpu_capacity 8 /
    gpu_requested 8" gave no signal that the question was already answered."""
    out: list[str] = []
    for item in artifacts:
        evidence_id = str(getattr(item, "evidence_id", "") or "")
        if not evidence_id or not _artifact_is_scoped_support(
            item, eligible_support_ids=eligible_support_ids
        ):
            continue
        summary = " ".join(str(getattr(item, "summary", "") or "").split())
        if not summary:
            continue
        out.append(f"{evidence_id}: {summary}")
        if len(out) == limit:
            break
    return out


async def _sharpen_operator_questions(
    settings: Settings,
    questions: list[str],
    missing: list[str],
    plan: InvestigationPlan | None,
    executed_queries: list[str] | None = None,
    held_evidence: list[str] | None = None,
) -> list[str] | None:
    """LLM-sharpened operator questions; None keeps the deterministic list."""
    ko = getattr(settings, "language", "en") == "ko"
    system = (
        "You review operator-facing follow-up questions for an RCA that could not "
        "settle on a root cause. Rewrite the draft questions to be sharper and more "
        "specific to the missing data and investigation plan. Do not invent facts, "
        "do not add generic filler. Do not ask the operator to run checks equivalent "
        "to any query in the already-executed evidence list, and never ask for "
        "something an item in held_evidence already states; target only genuinely "
        "missing evidence. "
        + ("반드시 한국어로 작성하세요. " if ko else "Write in English. ")
        + 'Respond with ONLY JSON: {"questions": [str, ...]} containing 2 to 4 questions.'
    )
    user = _build_settings_masker(settings).mask_text(json.dumps(
        {
            "draft_questions": questions,
            "missing_data": missing,
            "plan": plan.as_dict() if plan else {},
            "already_executed_evidence_queries": executed_queries or [],
            "held_evidence": held_evidence or [],
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
            f"- {hint.sentiment} from {hint.source_id}: {_short_sentence(hint.text, limit=320)}"
        )
    return lines
