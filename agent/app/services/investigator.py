"""Iterative, hypothesis-driven investigation loop (LLM-gated).

Replaces the one-shot "gather every collector once" with a senior-SRE ReAct
loop: each step the LLM looks at the plan, the hypotheses, and the evidence
gathered so far, then either probes specific collectors (optionally scoped to a
namespace/pod/node/workload) or concludes. The loop is bounded by max_steps and
by a supported hypothesis citing a scoped positive observation. Collectors that
have not run are not mandatory once that bar is met. If no such evidence exists
(including LLM/JSON failure), the safe fallback still gathers the remaining
collectors once.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any

from app.collectors.base import (
    AnalysisTarget,
    CollectorResult,
    artifact,
    causal_evidence_time_range,
    incident_time_range,
    kubernetes_salient_markers,
    signals_line,
)
from app.collectors.kubernetes import (
    _READ_KINDS,
    k8s_describe,
    k8s_read,
    kind_lookup_title,
    kubectl_repr,
    pod_inspection_repr,
    resolve_read_kind,
)
from app.config import Settings
from app.llm import complete_json
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.services.evidence_blackboard import EvidenceEligibility, source_independence_group
from app.services.query_memory import QueryMemory, collector_probe_key, domain_query_key
from app.services.root_cause_ranking import (
    artifact_contradicts_family,
    artifact_supports_family,
    typed_reason_family,
)

_log = logging.getLogger(__name__)

_LEDGER_STATUSES = {"open", "testing", "supported", "refuted", "uncertain"}
_USER_PROMPT_CHARS = 8000


def _incident_window_for_target(target: object) -> dict[str, str] | None:
    """Best-effort window for compatibility collectors/tests with loose targets."""
    if not isinstance(target, AnalysisTarget):
        return None
    return incident_time_range(target)


def _budget_remaining(deadline_monotonic: float | None) -> float | None:
    return None if deadline_monotonic is None else deadline_monotonic - time.monotonic()


async def _within_budget(
    deadline_monotonic: float | None, factory: Callable[[], Awaitable[Any]]
) -> Any:
    remaining = _budget_remaining(deadline_monotonic)
    if remaining is not None and remaining <= 0:
        raise TimeoutError("shared evidence budget exhausted")
    awaitable = factory()
    return await awaitable if remaining is None else await asyncio.wait_for(awaitable, remaining)


# What each collector is good for — fed to the LLM so it picks the right probe.
_COLLECTOR_HINTS = {
    "runai": "Run:ai control plane: workload/project/queue state, GPU quota.",
    "kubernetes": "Pod phases, warning events (OOM, evictions, image pulls), node conditions.",
    "postgres": "RCA memory / prior-incident evidence from the backend database.",
    "prometheus": "GPU/node/scheduling metrics, saturation, pending/unschedulable signals.",
    "loki": "Container and control-plane logs (crashes, errors, Xid, stack traces).",
    "system": "Node infra via the per-node agent: syslog/journalctl/dmesg, kernel/Xid.",
    "change": "Recent Deployment/DaemonSet/Helm/node changes and rollout timing.",
}


def _prioritize_probes(
    probes: list[dict[str, Any]],
    *,
    evidence: dict[str, CollectorResult],
    ledger: list[dict[str, Any]],
    plan: InvestigationPlan | None,
    selected_hypothesis: str = "",
) -> list[dict[str, Any]]:
    """Order probes by expected discrimination before collector-name tie-breaks.

    This is intentionally only a deterministic tie-breaker for the LLM's
    proposed reads: a new telemetry plane is more useful than a duplicate,
    and a probe explicitly bound to an unresolved hypothesis is more useful
    than a generic one.  It never discards a valid requested probe.
    """
    unresolved = {
        str(item.get("id") or "")
        for item in ledger
        if str(item.get("status") or "open") in {"open", "testing", "uncertain", "untested"}
        # A hypothesis flagged untestable (see `_hypothesis_testable`) has no
        # reachable read-only discriminator; scoring it as "unresolved work"
        # would keep rewarding probes that can never move it, at the expense
        # of a probe covering a hypothesis this loop can actually test.
        and not item.get("untestable_reason")
    }
    used_groups = {source_independence_group(name) for name in evidence}
    directive = plan.diagnostic_directive if plan else {}
    recommended = (
        {str(item) for item in (directive.get("recommended_collectors") or []) if str(item).strip()}
        if isinstance(directive, dict)
        else set()
    )

    def score(probe: dict[str, Any]) -> tuple[int, int, int, int, str, str]:
        collector = str(probe.get("collector") or "")
        hypothesis_ids = {
            str(item) for item in (probe.get("hypothesis_ids") or []) if str(item).strip()
        }
        selected = str(probe.get("hypothesis_id") or "")
        if selected:
            hypothesis_ids.add(selected)
        covered = len(hypothesis_ids & unresolved) if hypothesis_ids else len(unresolved)
        group = source_independence_group(collector)
        # Coverage, independence, and unresolved-hypothesis discrimination are
        # separate so a stable collector-name tie-break cannot hide a duplicate.
        return (
            -int(collector not in evidence),
            -int(group not in used_groups),
            -covered,
            -int(collector in recommended or selected_hypothesis in hypothesis_ids),
            collector,
            json.dumps(probe.get("scope") or {}, sort_keys=True, default=str),
        )

    return sorted(probes, key=score)


def _fallback_probe(
    collector_names: set[str],
    *,
    evidence: dict[str, CollectorResult],
    ledger: list[dict[str, Any]],
    plan: InvestigationPlan | None,
    selected_hypothesis: str,
) -> dict[str, Any] | None:
    """Pick one unused collector when an LLM asks to probe but names none."""
    candidates = [
        {"collector": name, "scope": {}} for name in collector_names if name not in evidence
    ]
    ordered = _prioritize_probes(
        candidates,
        evidence=evidence,
        ledger=ledger,
        plan=plan,
        selected_hypothesis=selected_hypothesis,
    )
    return ordered[0] if ordered else None


# The model is told (in the decision system prompt) to use the TOOL names from
# diagnostic_directive.probes[].tool as discriminators, but probes[].collector
# expects a COLLECTOR name from `all_names`. Confirmed production failure: two
# re-analysis rounds named only "k8s_read"/"k8s_describe" there, every probe
# was silently dropped, and 191.6s produced zero evidence. Every tool name in
# knowledge/*.yaml maps to exactly one collector (see
# app.services.drilldown._domain_tools), so accepting the alias is safe; kept
# as a static table instead of importing drilldown's registry to avoid coupling
# this file to that module's internals.
_PROBE_COLLECTOR_ALIASES = {
    "k8s_read": "kubernetes",
    "k8s_describe": "kubernetes",
    "k8s_logs": "kubernetes",
    "k8s_change_timeline": "kubernetes",
    "k8s_exec": "kubernetes",
    "promql_query": "prometheus",
    "logql_query": "loki",
    "system_log_query": "system",
    "change_query": "change",
}


def _resolve_probe_collector(raw: object, all_names: set[str]) -> str:
    """Canonical collector name for a probe, accepting a known tool-name alias."""
    name = str(raw or "").strip()
    if name in all_names:
        return name
    alias = _PROBE_COLLECTOR_ALIASES.get(name, "")
    return alias if alias in all_names else ""


def _rejected_probe_feedback(offending: object, all_names: set[str]) -> dict[str, Any]:
    """Same shape/purpose as `_rejected_adhoc_query_feedback`, for a probe naming
    an unknown collector. Inlines the allowed collector names: burying them at
    the top of a 3k+ token prompt previously let a model "correct" the spelling
    of an invalid value instead of the vocabulary (see that function)."""
    return {
        "probe": {"collector": str(offending or "")[:120]},
        "failure": {
            "message": "probe rejected",
            "category": "unknown_collector",
            "retryable_by_query_change": True,
            "correction_hint": (
                "probes[].collector must be a collector name, not a tool name. Use one of: "
                f"{', '.join(sorted(all_names))}."
            ),
            "evidence": False,
        },
    }


def _resolve_probe(
    probe: object,
    all_names: set[str],
    *,
    query_feedback: list[dict[str, Any]],
    reporter: ProgressReporter | None,
    step: int | None = None,
) -> dict[str, Any] | None:
    """Validate/normalize one LLM-proposed probe, or reject it loudly.

    A dropped probe used to vanish with no feedback, no progress event, and no
    warning, so a model that kept naming a tool instead of a collector could
    burn an entire re-analysis on it. Shared by the main decision loop and the
    post-reflection verification loop, which duplicate this exact intake.
    """
    offending = probe.get("collector") if isinstance(probe, dict) else probe
    collector = _resolve_probe_collector(offending, all_names) if isinstance(probe, dict) else ""
    if collector:
        return {**probe, "collector": collector}
    _log.warning(
        "dropped probe naming unknown collector %r; allowed collectors: %s",
        offending,
        sorted(all_names),
    )
    query_feedback.append(_rejected_probe_feedback(offending, all_names))
    query_feedback[:] = query_feedback[-8:]
    if reporter:
        reporter.emit(
            "investigation",
            "Dropped probe naming an unknown collector",
            collector=str(offending or ""),
            **({"step": step} if step is not None else {}),
        )
    return None


def _collector_name(collector: object) -> str:
    name = collector.__class__.__name__
    if name.endswith("Collector"):
        name = name[: -len("Collector")]
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return normalized.replace("_a_i", "ai") or "collector"


def _valid_adhoc_kubernetes_query(query: object) -> bool:
    """Accept only read-only Kubernetes resource queries from the shared loop.

    Collector-specific operations such as PromQL, Pod logs, and deployment
    history have their own typed drill-down tools. Treating their names as
    Kubernetes kinds generated misleading kubectl artifacts and allowlist
    failures instead of running the correct collector.
    """
    return isinstance(query, dict) and resolve_read_kind(str(query.get("kind") or "")) is not None


async def _collect_safely(collector: object, target: object, plan: object) -> CollectorResult:
    # Mirror the orchestrator: a collector must never raise into the loop.
    try:
        agent = _collector_name(collector)
        scoped_plan = plan.for_collector(agent) if isinstance(plan, InvestigationPlan) else plan
        return await collector.collect(target, scoped_plan)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - graceful degradation
        agent = _collector_name(collector)
        return CollectorResult(
            agent=agent,
            status="unavailable",
            summary=f"{agent} collector failed unexpectedly before returning evidence.",
            confidence="low",
            details={"error": type(exc).__name__},
            missing_data=[f"{agent}.collector_exception"],
            warnings=[f"{agent} failed unexpectedly: {type(exc).__name__}"],
        )


def _scoped_plan(plan: InvestigationPlan | None, scope: dict) -> InvestigationPlan:
    """A per-probe copy of the plan narrowed to the LLM-requested scope."""
    base = plan or InvestigationPlan()
    namespace = scope.get("namespace")
    return replace(
        base,
        namespaces=[namespace] if isinstance(namespace, str) and namespace else base.namespaces,
        node=scope.get("node") if isinstance(scope.get("node"), str) else base.node,
        pod=scope.get("pod") if isinstance(scope.get("pod"), str) else base.pod,
        workload=scope.get("workload") if isinstance(scope.get("workload"), str) else base.workload,
    )


def _effective_probe_scope(
    target: object,
    plan: InvestigationPlan | None,
    scope: dict[str, Any],
) -> dict[str, str]:
    """Canonical resource identity a collector will actually receive.

    The LLM commonly alternates between ``{}``, ``{"pod": target.pod}``, and
    ``{"namespace": target.namespace}``.  Those were different JSON strings
    but resolve to the same collector target, so they must share one execution
    identity within an analysis run.
    """
    namespaces = plan.namespaces if plan else []
    defaults = {
        "namespace": (namespaces[0] if namespaces else "")
        or str(getattr(target, "namespace", "") or ""),
        "pod": str((plan.pod if plan else "") or getattr(target, "pod", "") or ""),
        "node": str((plan.node if plan else "") or getattr(target, "node", "") or ""),
        "workload": str(
            (plan.workload if plan else "")
            or getattr(target, "workload_name", "")
            or ""
        ),
    }
    canonical: dict[str, str] = {}
    for key, default in defaults.items():
        requested = scope.get(key)
        value = (
            str(requested).strip()
            if isinstance(requested, str) and requested.strip()
            else default
        )
        if value:
            canonical[key] = value
    return canonical


def _probe_fingerprint(
    collector: str,
    target: object,
    plan: InvestigationPlan | None,
    scope: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "collector": collector,
            "scope": _effective_probe_scope(target, plan, scope),
        },
        sort_keys=True,
        default=str,
    )


def _adhoc_query_fingerprint(query: dict[str, Any]) -> str:
    # An unresolvable kind (not in the allowlist) falls back to the raw text;
    # lowercase it too so a resubmitted case-variant of an already-rejected
    # invalid kind still fingerprints identically instead of buying another
    # bounded round to re-discover the same rejection.
    kind = resolve_read_kind(str(query.get("kind") or "")) or str(
        query.get("kind") or ""
    ).strip().lower()
    return json.dumps(
        {
            "kind": kind,
            "namespace": str(query.get("namespace") or ""),
            "name": str(query.get("name") or ""),
            "label_selector": str(query.get("label_selector") or ""),
        },
        sort_keys=True,
    )


def _resolve_adhoc_query(
    query: object,
    *,
    seen_queries: set[str],
    failed_queries: set[str],
    query_feedback: list[dict[str, Any]],
    reporter: ProgressReporter | None,
    step: int | None = None,
) -> tuple[bool, bool]:
    """Validate/dedupe one LLM-proposed ad-hoc query.

    Returns ``(accepted, retryable_rejection)``; mutates `seen_queries` and
    `query_feedback` in place. Shared by the main decision loop and the
    post-reflection verification loop, which duplicate this exact intake.

    A rejected (invalid-kind) query previously never entered `seen_queries` —
    only the trimmed `query_feedback[-8:]` remembered it — so the identical
    request (or a same/case-variant kind) could be resubmitted and rejected
    again every round instead of being recognised as already answered.
    """
    fingerprint = _adhoc_query_fingerprint(query) if isinstance(query, dict) else ""
    if fingerprint and fingerprint in seen_queries:
        if fingerprint in failed_queries:
            query_feedback.append(_duplicate_failed_query_feedback(query))
            query_feedback[:] = query_feedback[-8:]
            return False, True
        # Already rejected (invalid kind) or already executed: repeating it
        # is not new work and must not re-justify another LLM decision round.
        return False, False
    if not _valid_adhoc_kubernetes_query(query):
        query_feedback.append(_rejected_adhoc_query_feedback(query))
        query_feedback[:] = query_feedback[-8:]
        if fingerprint:
            seen_queries.add(fingerprint)
        if reporter and isinstance(query, dict):
            reporter.emit(
                "investigation",
                "Rejected non-Kubernetes ad-hoc query kind",
                kind=str(query.get("kind") or ""),
                **({"step": step} if step is not None else {}),
            )
        return False, True
    return True, False


def _remember_kubernetes_queries(
    seen: set[str],
    result: CollectorResult,
    target: object,
    plan: InvestigationPlan | None,
) -> None:
    """Seed ad-hoc query memory from typed base-collector artifacts."""
    if result.agent != "kubernetes":
        return
    scope = _effective_probe_scope(target, plan, {})
    namespace = scope.get("namespace", "")
    pod = scope.get("pod", "")
    node = scope.get("node", "")
    for item in result.artifacts:
        if str(getattr(item, "status", "") or "") != "ok":
            continue
        artifact_type = str(getattr(item, "type", "") or "")
        if artifact_type == "kubernetes_warning_events" and namespace:
            seen.add(_adhoc_query_fingerprint({"kind": "events", "namespace": namespace}))
        elif artifact_type == "kubernetes_node_condition" and node:
            seen.add(_adhoc_query_fingerprint({"kind": "nodes", "name": node}))
        elif artifact_type == "pod_inspection" and pod:
            seen.add(
                _adhoc_query_fingerprint(
                    {"kind": "pods", "namespace": namespace, "name": pod}
                )
            )
        elif artifact_type in {
            "adhoc_query",
            "followup_query",
            "ontology_probe",
            "drilldown_query",
        }:
            payload = getattr(item, "result", None)
            if isinstance(payload, dict):
                kind = str(payload.get("kind") or "")
                if kind:
                    seen.add(
                        _adhoc_query_fingerprint(
                            {
                                "kind": kind,
                                "namespace": payload.get("namespace") or "",
                                "name": payload.get("name") or "",
                                "label_selector": payload.get("label_selector") or "",
                            }
                        )
                    )


def _adhoc_query_repr(item: dict) -> str:
    """The ad-hoc read as the real kubectl command an operator would have typed
    ("kubectl get pods -n runai -l app=x") — operators asked for the actual
    query, not an internal 'ns=... name=...' param dump."""
    if item.get("operation") == "describe":
        return pod_inspection_repr(
            str(item.get("namespace") or ""), str(item.get("name") or "")
        )
    return kubectl_repr(
        str(item.get("kind") or ""),
        namespace=str(item.get("namespace") or ""),
        name=str(item.get("name") or ""),
        label_selector=str(item.get("label_selector") or ""),
    )


async def _run_adhoc_kubernetes_query(
    settings: Settings,
    query: dict,
    *,
    time_range: dict[str, str] | None = None,
) -> dict:
    """Promote a named Pod read to full MCP-backed YAML + describe evidence."""
    kind = str(query.get("kind") or "")
    namespace = str(query.get("namespace") or "")
    name = str(query.get("name") or "")
    label_selector = str(query.get("label_selector") or "")
    try:
        if resolve_read_kind(kind) == "pods" and name:
            described = await k8s_describe(
                settings,
                "pods",
                namespace=namespace,
                name=name,
                time_range=time_range,
            )
            return {
                **described,
                "operation": "describe",
                "data": {"object": described.get("object"), "events": described.get("events")},
                **({"time_range": time_range} if time_range else {}),
            }
        read = await k8s_read(
            settings,
            kind,
            namespace=namespace,
            name=name,
            label_selector=label_selector,
        )
        # k8s_read is a live snapshot. Unlike the named-Pod describe path it
        # cannot apply the incident window, so never label it as historical
        # evidence merely because the caller supplied that window.
        return read
    except Exception as exc:  # noqa: BLE001 - failure feeds the bounded correction loop
        # Preserve query identity but never replay exception text: an API error
        # body can contain stale signals, secrets, or prompt-injection content.
        return {
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "label_selector": label_selector,
            "status_code": None,
            "error": f"{type(exc).__name__}: query failed",
            **({"time_range": time_range} if time_range else {}),
        }


def _evidence_summary(evidence: dict[str, CollectorResult]) -> list[dict]:
    summaries = []
    for name, r in evidence.items():
        item = {
            "collector": name,
            "status": r.status,
            "confidence": r.confidence,
        }
        if r.status in ("ok", "partial"):
            item["summary"] = (r.summary or "")[:400]
        else:
            item["summary"] = "collector unavailable; no evidence collected"
            if r.missing_data:
                item["missing_data"] = r.missing_data[:5]
            if r.warnings:
                item["warnings"] = r.warnings[:3]
        summaries.append(item)
    return summaries


def _initial_ledger(plan: InvestigationPlan | None) -> list[dict[str, Any]]:
    hypotheses = plan.hypotheses if plan else []
    ledger: list[dict[str, Any]] = []
    for idx, item in enumerate(hypotheses, start=1):
        if not isinstance(item, dict):
            continue
        family = str(item.get("family") or "").strip()
        reason = str(item.get("reason") or item.get("statement") or "").strip()
        if not family and not reason:
            continue
        statement = reason or family.replace("_", " ")
        mechanism = str(item.get("mechanism") or "").strip()
        hypothesis_id = str(item.get("id") or f"H{idx}").strip() or f"H{idx}"
        entry: dict[str, Any] = {
            "id": hypothesis_id,
            "family": family,
            "statement": statement,
            "confidence": 0.5,
            "status": "open",
        }
        if mechanism and not _same_ledger_text(mechanism, statement):
            entry["mechanism"] = mechanism
        for key in ("expected_observations", "falsifiers"):
            if values := _texts(item.get(key)):
                entry[key] = values
        if next_test := str(item.get("next_discriminating_test") or "").strip():
            entry["next_discriminating_test"] = next_test
        ledger.append(entry)
    return ledger


def _ledger_summary(ledger: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_ledger_public_item(item) for item in ledger]


def _ledger_public_item(item: dict[str, Any]) -> dict[str, Any]:
    """Canonical response/progress view; preserve semantic state, drop only noise."""
    output: dict[str, Any] = {
        "id": item.get("id"),
        "family": item.get("family"),
        "statement": item.get("statement"),
        "confidence": item.get("confidence", 0.5),
        "status": item.get("status") or "open",
    }
    statement = str(item.get("statement") or "")
    mechanism = str(item.get("mechanism") or "").strip()
    if mechanism and not _same_ledger_text(mechanism, statement):
        output["mechanism"] = mechanism
    for key in (
        "evidence_for",
        "evidence_against",
        "expected_observations",
        "falsifiers",
    ):
        if values := _texts(item.get(key))[-3:]:
            output[key] = values
    if next_test := str(item.get("next_discriminating_test") or "").strip():
        output["next_discriminating_test"] = next_test
    if untestable_reason := str(item.get("untestable_reason") or "").strip():
        output["untestable_reason"] = untestable_reason
    return output


def _ledger_prompt_view(ledger: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sparse bounded view used only inside repeated LLM decision prompts."""
    return [_compact_ledger_item(item) for item in ledger]


def _compact_ledger_item(item: dict[str, Any]) -> dict[str, Any]:
    """Prompt projection with defaults, empty fields, and duplicates removed."""
    output: dict[str, Any] = {}
    for key in ("id", "family", "statement"):
        if value := _bounded_ledger_text(item.get(key), limit=320):
            output[key] = value

    statement = str(item.get("statement") or "")
    mechanism = _bounded_ledger_text(item.get("mechanism"), limit=320)
    if mechanism and not _same_ledger_text(mechanism, statement):
        output["mechanism"] = mechanism

    status = str(item.get("status") or "open").strip().lower()
    confidence = item.get("confidence")
    # open/0.5 is the seed default, not a calculated probability.  The UI and
    # investigator already treat omitted status as open, so transmitting it on
    # every round only bloats the prompt/progress payload.
    if status != "open":
        output["status"] = status
    if confidence is not None and not (status == "open" and confidence == 0.5):
        output["confidence"] = confidence

    for key in (
        "evidence_for",
        "evidence_against",
        "expected_observations",
        "falsifiers",
    ):
        values = [
            value
            for raw in _texts(item.get(key))[-3:]
            if (value := _bounded_ledger_text(raw, limit=240))
        ]
        if values:
            output[key] = values
    if next_test := _bounded_ledger_text(item.get("next_discriminating_test"), limit=320):
        output["next_discriminating_test"] = next_test
    # Surfaced so the model stops re-proposing probes/queries for a
    # hypothesis this loop structurally cannot test (see `_hypothesis_testable`).
    if reason := _bounded_ledger_text(item.get("untestable_reason"), limit=200):
        output["untestable_reason"] = reason
    return output


def _bounded_ledger_text(value: object, *, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _same_ledger_text(left: object, right: object) -> bool:
    return " ".join(str(left or "").casefold().split()) == " ".join(
        str(right or "").casefold().split()
    )


def _apply_ledger_updates(
    ledger: list[dict[str, Any]],
    updates: object,
    *,
    allow_supported: bool = True,
    eligible_support_ids: set[str] | None = None,
    blackboard: Any = None,
    artifacts: object = (),
) -> list[dict[str, Any]]:
    if isinstance(updates, list):
        by_id = {str(item.get("id")): item for item in ledger}
        for update in updates:
            if not isinstance(update, dict):
                continue
            item = by_id.get(str(update.get("id") or ""))
            if item is None:
                continue
            if "confidence" in update:
                item["confidence"] = _clamp_confidence(update.get("confidence"), item["confidence"])
            allowed_evidence = _texts(update.get("evidence_for"))
            if eligible_support_ids is not None:
                allowed_evidence = [
                    evidence_id
                    for evidence_id in allowed_evidence
                    if evidence_id in eligible_support_ids
                ]
            status = str(update.get("status") or "").strip().lower()
            can_support = bool(
                set(_texts(item.get("evidence_for"))) | set(allowed_evidence)
            )
            if status == "supported" and (
                not allow_supported
                or (eligible_support_ids is not None and not can_support)
            ):
                status = "testing"
            if status in _LEDGER_STATUSES:
                item["status"] = status
            _extend_text_list(item, "evidence_for", allowed_evidence)
            _extend_text_list(item, "evidence_against", update.get("evidence_against"))
            _extend_text_list(item, "expected_observations", update.get("expected_observations"))
            _extend_text_list(item, "falsifiers", update.get("falsifiers"))
            for key in ("mechanism", "next_discriminating_test"):
                value = str(update.get(key) or "").strip()
                if value:
                    item[key] = value
    _attach_typed_artifacts(
        ledger,
        artifacts,
        blackboard=blackboard,
        eligible_support_ids=eligible_support_ids,
    )
    return ledger


def _attach_typed_artifacts(
    ledger: list[dict[str, Any]],
    artifacts: object,
    *,
    blackboard: Any,
    eligible_support_ids: set[str] | None,
) -> None:
    """Attach verified typed support the model omitted from its ledger links."""
    if not ledger or not isinstance(artifacts, (list, tuple)):
        return
    if not callable(getattr(blackboard, "facts", None)):
        return
    for candidate in artifacts:
        result = getattr(candidate, "result", None)
        observation = result.get("observation") if isinstance(result, dict) else None
        if not (
            isinstance(observation, dict)
            and observation.get("polarity") == "present"
            and observation.get("coverage") == "scoped"
            and observation.get("target_identity_verified") is True
        ):
            continue
        fact_id = _board_fact_id(blackboard, candidate)
        if not fact_id or (
            eligible_support_ids is not None and fact_id not in eligible_support_ids
        ):
            continue
        for item in ledger:
            family = str(item.get("family") or "").strip()
            if family and artifact_supports_family(family, candidate):
                _extend_text_list(item, "evidence_for", [fact_id])


def _board_fact_id(blackboard: Any, candidate: object) -> str:
    """Resolve the board's OWN fact ID for a collector artifact.

    ``evidence_id_for`` re-hashes the artifact without the incident entity,
    timestamp, and causal window the pipeline seeds facts with, so the ID it
    returns never matches a seeded fact and this attachment silently did
    nothing in every real run.  The artifact identity is context-free and
    stable; require a UNIQUE match so an identically worded observation for
    another Pod can never be cited here.
    """
    from app.services.evidence_blackboard import normalize_artifact

    try:
        artifact_id = normalize_artifact(candidate).artifact_id
        matches = [
            fact
            for fact in blackboard.facts()
            if str(getattr(fact, "artifact_id", "")) == artifact_id
        ]
    except Exception:  # noqa: BLE001 - attachment is advisory, never fatal
        return ""
    return str(getattr(matches[0], "fact_id", "")) if len(matches) == 1 else ""


def _hypothesis_testable(candidate: dict[str, Any], all_names: set[str]) -> tuple[bool, str]:
    """Whether `candidate` names a discriminator this loop can actually reach.

    `next_discriminating_test`/`statement` are free-form model prose and do
    not reliably contain the exact collector/kind token — keyword-matching
    prose against a controlled vocabulary is the anti-pattern this codebase
    avoids elsewhere — so only the structured `discriminator` field is
    trusted. Omitting it is NOT treated as untestable (most hypotheses are
    fine with ordinary collector probing); this only catches a hypothesis
    that explicitly names a surface this loop cannot reach. Confirmed
    production case: a reflection-added "runai_scheduling_permission"
    hypothesis whose only discriminator was RBAC roles/rolebindings, which
    are not in `_READ_KINDS` and have no owning collector, so every
    following round chasing it was dead before it started.
    """
    named = str(candidate.get("discriminator") or "").strip()
    if not named:
        return True, ""
    if named in all_names or resolve_read_kind(named) is not None:
        return True, ""
    return (
        False,
        f"no reachable read-only surface named '{named}' (not a collector or adhoc_query_kind)",
    )


def _add_reflected_hypotheses(
    ledger: list[dict[str, Any]], candidates: object, all_names: set[str] | None = None
) -> list[dict[str, Any]]:
    if not isinstance(candidates, list):
        return ledger
    existing = {
        str(item.get("family") or "").strip() or _normalise_hypothesis(item.get("statement"))
        for item in ledger
    }
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        family = str(candidate.get("family") or "").strip()
        statement = str(candidate.get("statement") or candidate.get("reason") or "").strip()
        hypothesis_key = family or _normalise_hypothesis(statement)
        if not hypothesis_key or hypothesis_key in existing:
            continue
        statement = statement or family.replace("_", " ")
        mechanism = str(candidate.get("mechanism") or "").strip()
        status = str(candidate.get("status") or "open")
        entry: dict[str, Any] = {
            "id": f"H{len(ledger) + 1}",
            "family": family,
            "statement": statement,
            "confidence": _clamp_confidence(candidate.get("confidence"), 0.4),
            "status": status if status in _LEDGER_STATUSES else "open",
        }
        if mechanism and not _same_ledger_text(mechanism, statement):
            entry["mechanism"] = mechanism
        for key in (
            "evidence_for",
            "evidence_against",
            "expected_observations",
            "falsifiers",
        ):
            if values := _texts(candidate.get(key))[:5]:
                entry[key] = values
        if next_test := str(candidate.get("next_discriminating_test") or "").strip():
            entry["next_discriminating_test"] = next_test
        # Never silently drop an untestable hypothesis — it is still worth
        # recording for the operator — but flag it so the ledger view/prompt
        # can stop the loop from spending rounds chasing a dead discriminator.
        testable, reason = _hypothesis_testable(candidate, all_names or set())
        if not testable:
            entry["untestable_reason"] = reason
        ledger.append(entry)
        existing.add(hypothesis_key)
    return ledger


def _extend_text_list(item: dict[str, Any], key: str, value: object) -> None:
    texts = _texts(value)
    if not texts:
        return
    current = item.get(key)
    if not isinstance(current, list):
        current = []
    item[key] = [*current, *texts][-8:]


def _texts(value: object) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := str(item).strip())]


def _normalise_hypothesis(value: object) -> str:
    return re.sub(r"\W+", " ", str(value or "").lower()).strip()


def _evidence_sufficiency(
    ledger: list[dict[str, Any]],
    evidence: dict[str, CollectorResult] | list[CollectorResult],
    blackboard: Any,
    target: AnalysisTarget | None = None,
) -> dict[str, Any]:
    """Return a conservative terminal verdict for adaptive collection.

    One scoped-positive fact is valid evidence, but it is not enough to stop
    unrelated collection. Early-stop requires family-semantic support from two
    independent telemetry groups, no scoped family contradiction, and no
    hypothesis-bound probe that already refuted the candidate.

    Single-source exceptions are dispositive OBSERVATIONS, never prose: the
    explicit NVIDIA XID alert signature, and a controlled-vocabulary Kubernetes
    reason that names its family outright. An ``OOMKilled`` container or an
    ``unschedulable`` Pod condition exists in the Kubernetes API and nowhere
    else, so a two-group floor would make those causes permanently unreachable
    while the run keeps collecting telemetry that cannot corroborate them.
    """
    facts_method = getattr(blackboard, "facts", None)
    get_fact = getattr(blackboard, "get", None)
    if not callable(facts_method) or not callable(get_fact):
        return {"sufficient": False, "reason": "no_typed_blackboard"}
    try:
        facts = list(facts_method())
    except Exception:  # noqa: BLE001 - malformed advisory state fails closed
        return {"sufficient": False, "reason": "invalid_typed_blackboard"}

    results = list(evidence.values()) if isinstance(evidence, dict) else list(evidence)
    eligibility_context = _eligibility_context(target)
    for hypothesis in ledger:
        if str(hypothesis.get("status") or "") != "supported":
            continue
        hypothesis_id = str(hypothesis.get("id") or "")
        family = str(hypothesis.get("family") or "")
        cited_ids = _texts(hypothesis.get("evidence_for"))
        if not hypothesis_id or not family or not cited_ids:
            continue

        supporting_ids: list[str] = []
        support_groups: set[str] = set()
        dispositive = False
        for fact_id in cited_ids:
            fact = get_fact(fact_id)
            if fact is None:
                continue
            eligibility = EvidenceEligibility.from_fact(
                fact, context=eligibility_context or None
            )
            if not eligibility.support:
                continue
            card = _fact_as_artifact(fact)
            if not artifact_supports_family(family, card):
                continue
            supporting_ids.append(fact_id)
            support_groups.add(str(getattr(fact, "independence_group", "") or "unknown"))
            dispositive = dispositive or (
                family == "gpu_hardware_error"
                and str(getattr(fact, "predicate", "")) == "alert_signature:nvidia_xid"
            ) or typed_reason_family(str(getattr(fact, "typed_reason", ""))) == family

        contradicted = any(
            artifact_contradicts_family(family, _fact_as_artifact(fact))
            for fact in facts
            if EvidenceEligibility.from_fact(
                fact, context=eligibility_context or None
            ).refutation
        )
        probe_refuted = any(
            str(assessment.get("verdict") or "") == "refutes"
            and hypothesis_id in _texts(assessment.get("hypothesis_ids"))
            for result in results
            for assessment in (
                result.details.get("ontology_probe_assessments", [])
                if isinstance(result.details, dict)
                else []
            )
            if isinstance(assessment, dict)
        )
        if supporting_ids and (len(support_groups) >= 2 or dispositive):
            if not contradicted and not probe_refuted:
                return {
                    "sufficient": True,
                    "reason": "independent_family_support" if not dispositive else "dispositive_signature",
                    "hypothesis_id": hypothesis_id,
                    "family": family,
                    "support_ids": supporting_ids,
                    "independence_groups": sorted(support_groups),
                }
    return {"sufficient": False, "reason": "needs_independent_corroboration"}


def _fact_as_artifact(fact: Any) -> object:
    provenance = dict(getattr(fact, "provenance", ()) or ())
    agent = str(provenance.get("agent") or getattr(fact, "source", "") or "")
    return artifact(
        agent=agent,
        source=str(getattr(fact, "source", "") or agent),
        type=str(getattr(fact, "predicate", "") or "observation"),
        status="ok",
        confidence=str(getattr(fact, "quality", "") or "low"),
        summary=str(getattr(fact, "summary", "") or ""),
        highlights=list(getattr(fact, "highlights", ()) or ()),
        result={
            "value": str(getattr(fact, "value", "") or ""),
            "observation": {
                "predicate": str(getattr(fact, "predicate", "") or ""),
                "polarity": str(getattr(fact, "polarity", "") or "unknown"),
                "coverage": str(getattr(fact, "coverage", "") or "unknown"),
                # Re-emit the collector's typed reason so the shared family gate
                # takes its controlled-vocabulary path here too, instead of
                # keyword-matching this card's summary prose.  POSITIVE facts
                # only: the reason makes a card relevant to exactly one family,
                # and refutation reads scoped ABSENCES — no collector types a
                # reason onto one today, and this keeps that true by
                # construction rather than by coincidence.
                **(
                    {"container_reason": reason}
                    if (reason := str(getattr(fact, "typed_reason", "") or ""))
                    and str(getattr(fact, "polarity", "")) == "present"
                    else {}
                ),
            },
        },
    )


def _eligibility_context(target: AnalysisTarget | None) -> dict[str, object]:
    """The incident window and identities every citation is judged against."""
    if target is None:
        return {}
    window = causal_evidence_time_range(target) or {}
    return {
        "window_start": str(window.get("start") or ""),
        "window_end": str(window.get("end") or ""),
        "entities": [
            f"{field}:{value}"
            for field in (
                "pod",
                "node",
                "workload_name",
                "runai_workload_id",
                "project",
                "queue",
                "namespace",
            )
            if (value := str(getattr(target, field, "") or "").strip())
        ],
    }


def _eligible_support_ids(
    blackboard: Any, target: AnalysisTarget | None = None
) -> set[str]:
    """Return only scoped positive fact IDs the investigator may cite as support.

    ``fact.eligibility`` answers polarity/coverage alone.  Judging citations by
    that at this layer while the trace, the harness, and candidate promotion all
    apply the incident window and target identity let the ledger claim support
    from an observation those layers had already discarded.  One context, one
    verdict — ``target`` stays optional so callers without one keep the old,
    looser behaviour rather than silently starving.
    """
    facts = getattr(blackboard, "facts", None)
    if not callable(facts):
        return set()
    context = _eligibility_context(target) or None
    try:
        return {
            str(fact.fact_id)
            for fact in facts()
            if str(getattr(fact, "fact_id", ""))
            and EvidenceEligibility.from_fact(fact, context=context).support
        }
    except Exception:  # noqa: BLE001 - malformed shared observations cannot support a claim
        return set()


def _ledger_fingerprint(
    ledger: list[dict[str, Any]],
) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    return tuple(
        (
            str(item.get("id") or ""),
            str(item.get("status") or ""),
            str(item.get("mechanism") or item.get("statement") or ""),
            tuple(_texts(item.get("evidence_for"))),
        )
        for item in ledger
        # A hypothesis flagged untestable has no reachable read-only
        # discriminator (see `_hypothesis_testable`).  Excluding it here means
        # reflection adding ONLY such a hypothesis does not, by itself, look
        # like a ledger change worth spending a verification round's LLM call
        # on — the confirmed production bug: a reflection-only hypothesis with
        # no reachable discriminator burned every later round before it
        # started.
        if not item.get("untestable_reason")
    )


def _clamp_confidence(value: object, fallback: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        try:
            number = float(fallback)
        except (TypeError, ValueError):
            number = 0.5
    return max(0.0, min(1.0, number))


def _is_cluster_wide_target(target: object) -> bool:
    """True when the request names no resource that can narrow collection."""
    return not any(
        str(getattr(target, field, "") or "").strip()
        for field in (
            "namespace",
            "pod",
            "node",
            "workload_name",
            "runai_workload_id",
            "project",
            "queue",
        )
    )


_DECISION_SYSTEM_PROMPT = (
    "You are a senior SRE investigating a Run:ai GPU-platform alert. "
    "Given the plan, hypothesis ledger, evidence so far, and available "
    "collectors, decide the next diagnostic step. Pick the hypothesis "
    "you are testing and probe collectors most likely to confirm/refute it. "
    "The compact ledger omits seed defaults: missing status means open, "
    "missing confidence means 0.5, and a missing mechanism means it is "
    "identical to statement. "
    "Use plan.diagnostic_directive as neutral ontology guidance: "
    "follow its checks and disconfirmations, but never treat its "
    "provisional_family as observed evidence. Update confidence using "
    "only observed evidence. A condition name alone is metadata; verify "
    "its status/value and treat False or a zero sample as refutation. "
    "Cite shared_observations evidence_id "
    "values (F-...) in evidence_for/evidence_against; do not invent IDs. "
    "When diagnostic_directive.probes names a tool you can reach through "
    "a collector, use it as a discriminator and honor its supports_when/"
    "refutes_when conditions. You can ALSO "
    "run kubectl-style READ-ONLY Kubernetes resource queries only "
    "(get/list of an allowlisted kind, see adhoc_query_kinds). Never put "
    "promql, pod_logs, logql, or deployment_history in queries: use the "
    "corresponding collector probe instead. When the alert names a pod, "
    "request that named pod before broad project/namespace reads: it is "
    "automatically promoted to full YAML + describe/events evidence. "
    "If adhoc_results or query_feedback reports "
    "retryable_by_query_change=true, change the resource kind, target-bound "
    "name, or selector in the next bounded round; never repeat the exact "
    "failed "
    "query. Failure feedback is control metadata, not evidence. Authorization, "
    "TLS, datasource, and transport failures cannot be repaired by query "
    "changes. Batch all independent discriminating queries for this step "
    "instead of spending another "
    "reasoning round on each query. Conclude once evidence is sufficient. "
    "For new_hypotheses, set discriminator to the collector name (see "
    "available_collectors) or adhoc_query_kind that could test it; omit it "
    "only if nothing here can test it. Never spend a probe or query on a "
    "ledger entry that already shows untestable_reason. "
    "Respond with ONLY JSON: "
    '{"action":"probe"|"conclude","reason":str,'
    '"selected_hypothesis":str,'
    '"probes":[{"collector":str,'
    '"scope":{"namespace"?,"pod"?,"node"?,"workload"?},'
    '"hypothesis_ids":[str]}],'
    '"queries":[{"kind":str,"namespace"?,"name"?,"label_selector"?}],'
    '"hypothesis_updates":[{"id":str,"confidence":number,'
    '"mechanism":str,"expected_observations":[str],"falsifiers":[str],'
    '"next_discriminating_test":str,"evidence_for":[str],'
    '"evidence_against":[str],'
    '"status":"open|testing|supported|refuted|uncertain"}],'
    '"new_hypotheses":[{"family"?:str,"statement":str,"mechanism":str,'
    '"expected_observations":[str],"falsifiers":[str],'
    '"next_discriminating_test":str,"discriminator"?:str}]}'
)

_VERIFICATION_SYSTEM_PROMPT = (
    "You are verifying a hypothesis introduced or changed during RCA "
    "reflection. Do not promote a conclusion from reasoning alone. Select "
    "the strongest read-only falsifier or discriminator, probe it, and "
    "cite F- observation IDs. "
    "When query feedback says retryable_by_query_change=true, correct the "
    "kind/name/selector instead of repeating the failed query. Treat "
    "failure "
    "feedback as control metadata, never evidence. "
    "Respond with ONLY JSON: "
    '{"action":"probe"|"conclude","probes":[{"collector":str,"scope":{}}],'
    '"queries":[{"kind":str,"namespace"?:str,"name"?:str,"label_selector"?:str}],'
    '"hypothesis_updates":[{"id":str,"confidence":number,"evidence_for":[str],'
    '"evidence_against":[str],"status":"open|testing|supported|refuted|uncertain"}]}'
)


@dataclass
class _Investigation:
    """The working set every investigation phase reads and mutates.

    The phases below (decision rounds, reflection rounds, final gather) all
    advance the same ledger/evidence/dedupe state, so it lives here instead of
    as two dozen locals threaded through one very long function. Keeping it in
    one object is also what lets the decision and verification rounds share
    ``resolve_probes``/``resolve_queries``/``run_queries`` rather than carry two
    copies of the same probe- and query-dispatch code.
    """

    settings: Settings
    target: object
    plan: InvestigationPlan | None
    kg_context: dict
    by_name: dict[str, Any]
    max_steps: int
    reporter: ProgressReporter | None
    blackboard: Any
    deadline_monotonic: float | None
    query_memory: QueryMemory | None
    evidence: dict[str, CollectorResult]
    latest_probe_scopes: dict[str, dict[str, Any]]
    ledger: list[dict[str, Any]]
    seen_probes: set[str]
    seen_queries: set[str] = field(default_factory=set)
    failed_queries: set[str] = field(default_factory=set)
    # Validation/duplicate feedback is deliberately separate from ``adhoc``:
    # rejected queries were never observations and must not become artifacts.
    query_feedback: list[dict[str, Any]] = field(default_factory=list)
    investigation_steps: list[dict[str, Any]] = field(default_factory=list)
    adhoc: list[dict] = field(default_factory=list)

    @classmethod
    def start(
        cls,
        settings: Settings,
        target: object,
        collectors: list,
        plan: InvestigationPlan | None,
        kg_context: dict,
        max_steps: int,
        *,
        reporter: ProgressReporter | None,
        blackboard: Any,
        deadline_monotonic: float | None,
        initial_evidence: list[CollectorResult] | None,
        query_memory: QueryMemory | None,
    ) -> _Investigation:
        by_name = {_collector_name(c): c for c in collectors}
        # Re-analysis must continue from the observations already collected in
        # this analysis run.  Starting every pass with an empty mapping caused
        # the full Kubernetes collector (Pod, Events and Node conditions) to run
        # again up to MAX_REANALYSIS_STEPS times.  Clone the envelopes because
        # ad-hoc artifacts are appended below and the caller owns its existing
        # result list.
        evidence: dict[str, CollectorResult] = {
            item.agent: replace(
                item,
                details=dict(item.details),
                missing_data=list(item.missing_data),
                warnings=list(item.warnings),
                artifacts=list(item.artifacts),
            )
            for item in (initial_evidence or [])
            if item.agent in by_name
        }
        latest_probe_scopes: dict[str, dict[str, Any]] = {
            name: _effective_probe_scope(target, plan, {})
            for name, item in evidence.items()
            # Partial means this exact collector scope already executed and kept
            # every usable sub-result. Replaying the full scope repeats those
            # reads (often Pod/Events/Node) and was the source of three
            # identical passes. Failed gaps remain visible in
            # missing_data/query receipts and must be retried through a
            # changed/narrower scope or domain query, not by scraping the
            # identical collector scope again.
            if item.status in {"ok", "partial"}
        }
        state = cls(
            settings=settings,
            target=target,
            plan=plan,
            kg_context=kg_context,
            by_name=by_name,
            max_steps=max_steps,
            reporter=reporter,
            blackboard=blackboard,
            deadline_monotonic=deadline_monotonic,
            query_memory=query_memory,
            evidence=evidence,
            latest_probe_scopes=latest_probe_scopes,
            ledger=_initial_ledger(plan),
            seen_probes={
                _probe_fingerprint(name, target, plan, scope)
                for name, scope in latest_probe_scopes.items()
            },
        )
        for item in evidence.values():
            _remember_kubernetes_queries(state.seen_queries, item, target, plan)
            if query_memory is not None:
                query_memory.seed_result(item, target)
        if query_memory is not None:
            for name, scope in latest_probe_scopes.items():
                query_memory.remember(collector_probe_key(name, target, scope))
        return state

    # --- shared state helpers -------------------------------------------------

    @property
    def all_names(self) -> set[str]:
        return set(self.by_name)

    @property
    def round_limit(self) -> int:
        # Bound LLM decision rounds while allowing every round to batch many
        # independent read-only queries. Older zero-valued callers use 3.
        return self.max_steps if self.max_steps > 0 else 3

    def sufficiency(self) -> dict[str, Any]:
        return _evidence_sufficiency(self.ledger, self.evidence, self.blackboard, self.target)

    def is_sufficient(self) -> bool:
        return bool(self.sufficiency()["sufficient"])

    def budget_remaining(self) -> float | None:
        return _budget_remaining(self.deadline_monotonic)

    def out_of_budget(self) -> bool:
        remaining = self.budget_remaining()
        return remaining is not None and remaining <= 0

    def apply_updates(self, updates: object) -> None:
        self.ledger = _apply_ledger_updates(
            self.ledger,
            updates,
            blackboard=self.blackboard,
            artifacts=[item for result in self.evidence.values() for item in result.artifacts],
            eligible_support_ids=_eligible_support_ids(self.blackboard, self.target),
        )

    def user_prompt(self) -> str:
        return _investigator_masker(self.settings).mask_text(
            _build_user_prompt(
                self.plan,
                self.kg_context,
                self.evidence,
                self.by_name,
                self.ledger,
                self.adhoc,
                query_feedback=self.query_feedback,
                blackboard=self.blackboard,
            )
        )

    # --- probe and query dispatch (shared by both LLM round loops) ------------

    async def run_probe(self, name: str, scope: dict) -> None:
        collector = self.by_name.get(name)
        if collector is None:
            return
        probe_key = collector_probe_key(name, self.target, scope)
        if self.query_memory is not None and not self.query_memory.claim(probe_key):
            return
        if self.reporter:
            self.reporter.emit(
                "investigation",
                f"Probing {name}",
                collector=name,
                scope=scope,
                hypothesis_ledger=_ledger_summary(self.ledger),
            )
        result = await _within_budget(
            self.deadline_monotonic,
            lambda: _collect_safely(collector, self.target, _scoped_plan(self.plan, scope)),
        )
        self.evidence[name] = _merge_collector_results(
            self.evidence.get(name),
            result,
            previous_scope=self.latest_probe_scopes.get(name),
            current_scope=scope,
        )
        self.latest_probe_scopes[name] = dict(scope)
        _remember_kubernetes_queries(self.seen_queries, result, self.target, self.plan)
        if self.query_memory is not None:
            self.query_memory.complete(probe_key, succeeded=result.status in {"ok", "partial"})
            self.query_memory.seed_result(result, self.target)
        _record_blackboard(self.blackboard, name, result, self.target)
        if self.reporter:
            self.reporter.emit(
                "investigation",
                f"{name} evidence collected",
                collector=name,
                status=result.status,
                summary=(result.summary or "")[:300],
                hypothesis_ledger=_ledger_summary(self.ledger),
            )

    async def run_probes(self, fresh: list[dict]) -> None:
        await _within_budget(
            self.deadline_monotonic,
            lambda fresh=fresh: asyncio.gather(
                *(self.run_probe(p["collector"], p.get("scope") or {}) for p in fresh)
            ),
        )

    def resolve_probes(
        self, probes: object, *, step: int | None = None, selected_hypothesis: str = ""
    ) -> list[dict]:
        """Accepted, not-yet-seen probes for this round, strongest first."""
        fresh: list[dict] = []
        for probe in probes if isinstance(probes, list) else []:
            resolved = _resolve_probe(
                probe,
                self.all_names,
                query_feedback=self.query_feedback,
                reporter=self.reporter,
                step=step,
            )
            if resolved is None:
                continue
            fingerprint = _probe_fingerprint(
                str(resolved.get("collector") or ""),
                self.target,
                self.plan,
                resolved.get("scope") or {},
            )
            if fingerprint in self.seen_probes:
                continue
            self.seen_probes.add(fingerprint)
            fresh.append(resolved)
        return _prioritize_probes(
            fresh,
            evidence=self.evidence,
            ledger=self.ledger,
            plan=self.plan,
            selected_hypothesis=selected_hypothesis,
        )

    def add_fallback_probe(self, fresh: list[dict], selected_hypothesis: str) -> None:
        fallback = _fallback_probe(
            self.all_names,
            evidence=self.evidence,
            ledger=self.ledger,
            plan=self.plan,
            selected_hypothesis=selected_hypothesis,
        )
        if fallback is not None:
            self.seen_probes.add(
                _probe_fingerprint(
                    str(fallback["collector"]), self.target, self.plan, fallback["scope"]
                )
            )
            fresh.append(fallback)

    def resolve_queries(
        self, queries: object, *, step: int | None = None
    ) -> tuple[list[dict], bool]:
        """Accepted ad-hoc queries, plus whether a rejection is worth retrying."""
        wanted: list[dict] = []
        retryable_rejection = False
        for query in queries if isinstance(queries, list) else []:
            accepted, retryable = _resolve_adhoc_query(
                query,
                seen_queries=self.seen_queries,
                failed_queries=self.failed_queries,
                query_feedback=self.query_feedback,
                reporter=self.reporter,
                step=step,
            )
            retryable_rejection = retryable_rejection or retryable
            if not accepted:
                continue
            shared_key = domain_query_key(
                "kubernetes", {"tool": "k8s_read", "args": query}, self.target
            )
            if self.query_memory is not None and not self.query_memory.claim(shared_key):
                continue
            self.seen_queries.add(_adhoc_query_fingerprint(query))
            wanted.append(query)
        return wanted, retryable_rejection

    async def run_queries(self, wanted: list[dict]) -> None:
        query_results = await _within_budget(
            self.deadline_monotonic,
            lambda wanted=wanted: asyncio.gather(
                *(
                    _run_adhoc_kubernetes_query(
                        self.settings,
                        query,
                        time_range=_incident_window_for_target(self.target),
                    )
                    for query in wanted
                )
            ),
        )
        self.adhoc.extend(query_results)
        for query, item in zip(wanted, query_results, strict=True):
            if self.query_memory is not None:
                self.query_memory.complete(
                    domain_query_key(
                        "kubernetes", {"tool": "k8s_read", "args": query}, self.target
                    ),
                    succeeded=not bool(item.get("error")),
                )
            if item.get("error"):
                self.failed_queries.add(_adhoc_query_fingerprint(query))

    # --- phase 1: bounded LLM decision rounds ---------------------------------

    async def decision_rounds(self) -> None:
        # A target-less request is a cluster investigation, not a request to
        # skip collection.  Get every evidence plane's bounded discovery view
        # first; only pod/name-dependent probes remain unavailable until that
        # evidence identifies an entity for a narrower follow-up.
        if _is_cluster_wide_target(self.target) and not self.evidence:
            await asyncio.gather(*(self.run_probe(name, {}) for name in self.by_name))
        ran_queries_last_step = False
        step = 0
        while step < self.round_limit:
            if self.out_of_budget():
                break
            step += 1
            if not ran_queries_last_step and self.is_sufficient():
                break  # scoped evidence already grounds a supported hypothesis
            if self.reporter:
                self.reporter.emit(
                    "investigation",
                    "Choosing next diagnostic step",
                    step=step,
                    hypothesis_ledger=_ledger_summary(self.ledger),
                )
            decision = await _within_budget(
                self.deadline_monotonic,
                lambda: complete_json(
                    self.settings,
                    system=_DECISION_SYSTEM_PROMPT,
                    user=self.user_prompt(),
                    model=self.settings.llm_model_investigation,
                ),
            )
            if not isinstance(decision, dict):
                break  # unusable response -> fall through to full gather
            self.apply_updates(decision.get("hypothesis_updates"))
            self.ledger = _add_reflected_hypotheses(
                self.ledger, decision.get("new_hypotheses"), self.all_names
            )
            self.investigation_steps.append(
                {
                    "step": step,
                    "action": str(decision.get("action") or ""),
                    "reason": str(decision.get("reason") or "")[:300],
                    "selected_hypothesis": str(decision.get("selected_hypothesis") or ""),
                }
            )
            if self.reporter:
                self.reporter.emit(
                    "investigation",
                    str(decision.get("reason") or "Diagnostic step selected")[:300],
                    step=step,
                    action=str(decision.get("action") or ""),
                    selected_hypothesis=str(decision.get("selected_hypothesis") or ""),
                    probes=decision.get("probes"),
                    queries=decision.get("queries"),
                    hypothesis_updates=decision.get("hypothesis_updates"),
                    hypothesis_ledger=_ledger_summary(self.ledger),
                )
            unverified_conclusion = (
                decision.get("action") == "conclude" and not self.is_sufficient()
            )
            if decision.get("action") == "conclude" and not unverified_conclusion:
                break
            selected_hypothesis = str(decision.get("selected_hypothesis") or "")
            fresh = self.resolve_probes(
                decision.get("probes"), step=step, selected_hypothesis=selected_hypothesis
            )
            wanted, retryable_query_rejection = self.resolve_queries(
                decision.get("queries"), step=step
            )
            if unverified_conclusion and not fresh and not wanted:
                # Never let a model conclude from its initial, evidence-free
                # prompt. Run the strongest remaining discriminator, then let
                # the next bounded round decide whether its scoped observation
                # is sufficient. Launching every collector here defeated the
                # adaptive loop and caused avoidable duplicate evidence work.
                self.add_fallback_probe(fresh, selected_hypothesis)
            if not fresh and not wanted and decision.get("action") == "probe":
                self.add_fallback_probe(fresh, selected_hypothesis)
            if not fresh and not wanted:
                if retryable_query_rejection and step < self.round_limit:
                    # The rejected/duplicate request is not evidence. Give the
                    # LLM one of its remaining bounded rounds to change the
                    # kind/name/selector instead of silently ending the loop.
                    continue
                if unverified_conclusion and step < self.round_limit:
                    # Keep the remaining bounded rounds available for the
                    # model to reconsider the newly collected base evidence.
                    continue
                break
            if fresh:
                await self.run_probes(fresh)
            for query in wanted:
                if self.reporter:
                    self.reporter.emit(
                        "investigation",
                        f"Running {_adhoc_query_repr(query)}",
                        step=step,
                        query=_adhoc_query_repr(query),
                    )
            if wanted:
                await self.run_queries(wanted)
            ran_queries_last_step = bool(wanted)
            # A bounded investigation may finish early only when the ledger
            # cites an actual scoped fact. Model prose or partial observations
            # must consume the remaining (at most three) reasoning rounds.
            if self.is_sufficient():
                break

    # --- phase 2: reflection, then verification of what it changed ------------

    async def reflection_rounds(self) -> None:
        before_reflection = _ledger_fingerprint(self.ledger)
        reflection_budget = self.budget_remaining()
        if not self.is_sufficient() and (reflection_budget is None or reflection_budget > 0):
            self.ledger = await _within_budget(
                self.deadline_monotonic,
                lambda ledger=self.ledger: _reflect_hypotheses(
                    self.settings,
                    self.plan,
                    self.kg_context,
                    self.evidence,
                    self.by_name,
                    ledger,
                    self.adhoc,
                    query_feedback=self.query_feedback,
                    blackboard=self.blackboard,
                    target=self.target,
                ),
            )
        if _ledger_fingerprint(self.ledger) != before_reflection:
            await self._verification_rounds()
        if self.reporter:
            self.reporter.emit(
                "reflection",
                "Checked for missing or contradictory hypotheses",
                hypothesis_ledger=_ledger_summary(self.ledger),
            )

    async def _verification_rounds(self) -> None:
        # A reflection is useful only if its new/changed hypothesis is put back
        # through a discriminating read-only probe. Keep this phase bounded too:
        # otherwise a model returning endless distinct reads can consume the
        # entire shared evidence budget before synthesis.
        verification_round = 0
        while verification_round < self.round_limit:
            if self.out_of_budget():
                break
            verification_round += 1
            verification = await _within_budget(
                self.deadline_monotonic,
                lambda: complete_json(
                    self.settings,
                    system=_VERIFICATION_SYSTEM_PROMPT,
                    user=self.user_prompt(),
                    model=self.settings.llm_model_investigation,
                ),
            )
            if not isinstance(verification, dict):
                break
            self.apply_updates(verification.get("hypothesis_updates"))
            if self.is_sufficient():
                break
            if verification.get("action") == "conclude":
                break
            fresh = self.resolve_probes(verification.get("probes"))
            wanted, retryable_query_rejection = self.resolve_queries(verification.get("queries"))
            if not fresh and not wanted:
                if retryable_query_rejection and verification_round < self.round_limit:
                    continue
                break
            if fresh:
                await self.run_probes(fresh)
            if wanted:
                await self.run_queries(wanted)
            if self.is_sufficient():
                break

    # --- phase 3: safe full gather, then the typed-core floor -----------------

    async def final_gather(self, *, evidence_sufficient: bool) -> None:
        remaining = (
            []
            if evidence_sufficient
            else [name for name in self.by_name if name not in self.evidence]
        )
        if not remaining:
            return
        if self.query_memory is not None:
            remaining = [
                name
                for name in remaining
                if self.query_memory.claim(collector_probe_key(name, self.target, {}))
            ]
        tasks = {
            asyncio.create_task(_collect_safely(self.by_name[name], self.target, self.plan)): name
            for name in remaining
        }
        budget = self.budget_remaining()
        timeout = None if budget is None else max(0.0, budget)
        done, pending = await asyncio.wait(tasks, timeout=timeout)
        for task in done:
            name = tasks[task]
            try:
                result = task.result()
            except Exception as exc:  # noqa: BLE001 - collector failure is an observation
                result = CollectorResult(
                    agent=name,
                    status="unavailable",
                    summary=f"{name} collector failed before returning evidence.",
                    missing_data=[f"{name}.collector_exception"],
                    warnings=[f"{name} failed unexpectedly: {type(exc).__name__}"],
                )
            self.evidence[name] = _merge_collector_results(self.evidence.get(name), result)
            if self.query_memory is not None:
                self.query_memory.complete(
                    collector_probe_key(name, self.target, {}),
                    succeeded=result.status in {"ok", "partial"},
                )
                self.query_memory.seed_result(result, self.target)
            _record_blackboard(self.blackboard, name, result, self.target)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for task in pending:
            name = tasks[task]
            if self.query_memory is not None:
                self.query_memory.complete(
                    collector_probe_key(name, self.target, {}), succeeded=False
                )
            self.evidence[name] = CollectorResult(
                agent=name,
                status="unavailable",
                summary=f"{name} collector skipped when the shared evidence budget expired.",
                missing_data=[f"{name}.analysis_budget"],
                warnings=["shared investigation/drill-down budget exhausted"],
            )

    async def kubernetes_floor(self, *, evidence_sufficient: bool) -> None:
        # Typed-core floor: a run must not end with zero target-scoped
        # kubernetes evidence just because LLM rounds and broad collectors
        # consumed the shared window (2026-07-24 audit: 15/60 runs ended
        # artifact-free, all carrying "shared evidence budget expired" skips).
        # One bounded pass fits inside the backend's deadline slack. A
        # deliberate early stop on a supported scoped hypothesis is respected —
        # the floor only rescues starved runs.
        # ponytail: fixed 25s floor; make it a setting if the deadline slack tightens.
        floor_target = self.evidence.get("kubernetes")
        budget_skipped = floor_target is not None and "kubernetes.analysis_budget" in (
            floor_target.missing_data or []
        )
        if (
            "kubernetes" not in self.by_name
            or evidence_sufficient
            or not (floor_target is None or budget_skipped)
        ):
            return
        try:
            floor_result = await asyncio.wait_for(
                _collect_safely(self.by_name["kubernetes"], self.target, self.plan), 25.0
            )
        except Exception:  # noqa: BLE001 - the floor pass is best-effort
            floor_result = None
        if floor_result is not None:
            # The budget-skip stub carries no observations; replace it outright.
            self.evidence["kubernetes"] = _merge_collector_results(None, floor_result)
            _record_blackboard(self.blackboard, "kubernetes", floor_result, self.target)

    # --- phase 4: ad-hoc reads become kubernetes artifacts --------------------

    def attach_adhoc_artifacts(self) -> None:
        # Ad-hoc reads are evidence too: attach them to the kubernetes result so
        # the report's evidence trail (and signature matching) sees what was
        # drilled into.
        kubernetes_result = self.evidence.get("kubernetes")
        if not self.adhoc or kubernetes_result is None:
            return
        language = getattr(self.settings, "language", "en")
        for item in self.adhoc:
            kubernetes_result.artifacts.append(_adhoc_artifact(item, language))
        _record_blackboard(self.blackboard, "kubernetes", kubernetes_result, self.target)

    # --- phase 5: the context the pipeline reasons about ----------------------

    def finish(self, *, evidence_sufficient: bool) -> tuple[list[CollectorResult], dict]:
        # The normal collector gather happens after the LLM/reflection rounds.
        # Make its typed facts available to the same ledger attachment path as
        # probe results; otherwise a valid final Kubernetes observation can
        # never move a hypothesis beyond testing.
        self.apply_updates([])
        context = {
            "hypothesis_ledger": _ledger_summary(self.ledger),
            "investigation_steps": self.investigation_steps,
            "adhoc_query_count": len(self.adhoc),
            "evidence_sufficiency": self.sufficiency(),
            "skipped_collectors": (
                [name for name in self.by_name if name not in self.evidence]
                if evidence_sufficient
                else []
            ),
            "reasoning_trace_v2": {
                "schema_version": 2,
                "hypotheses": _ledger_summary(self.ledger),
                "referenced_facts": _blackboard_prompt_view(self.blackboard, limit=30),
                "stop_reason": (
                    "analysis_budget_exhausted"
                    if self.out_of_budget()
                    else "supported_hypothesis"
                    if evidence_sufficient
                    else "all_collectors_probed"
                ),
            },
        }
        safe_context = _investigator_masker(self.settings).mask_object(context)
        return list(self.evidence.values()), (
            safe_context if isinstance(safe_context, dict) else context
        )


def _adhoc_artifact(item: dict, language: str) -> Any:
    """One ad-hoc Kubernetes read, projected as never-automatic RCA support."""
    error = item.get("error")
    incident_window_verified = bool(item.get("time_range"))
    # Finding-first summary: name the problem signals in the data, not the
    # transport ("HTTP 200" tells the operator nothing).
    markers = [] if error else kubernetes_salient_markers(item.get("data"))
    if error:
        summary = str(error)
    elif markers:
        summary = signals_line(markers, language)
        if not incident_window_verified:
            summary = (
                f"현재 스냅샷 전용: {summary}"
                if language == "ko"
                else f"current snapshot only: {summary}"
            )
    else:
        summary = (
            "특이 신호 없음 (HTTP {code})"
            if language == "ko"
            else "no problem signals (HTTP {code})"
        ).format(code=item.get("status_code"))
    return artifact(
        agent="kubernetes",
        source="kubernetes",
        type="adhoc_query",
        status="unavailable" if error else "ok",
        confidence="medium",
        query=_adhoc_query_repr(item),
        title=(
            "Pod YAML + 상세 점검"
            if language == "ko" and item.get("operation") == "describe"
            else "Pod YAML + describe"
            if item.get("operation") == "describe"
            else kind_lookup_title(str(item.get("kind") or ""), language)
        ),
        highlights=markers or None,
        summary=summary,
        result={
            **item,
            # Full YAML/describe is valuable operator context, but it is a
            # current snapshot. Its filtered events retain the incident window
            # separately; the combined ad-hoc artifact must never become
            # automatic RCA support.
            "observation": {
                "kind": "kubernetes_adhoc_query",
                "predicate": "kubernetes_adhoc_query",
                "polarity": "unavailable" if error else "unknown",
                "coverage": "unknown" if error else "partial",
                "observation_window": item.get("time_range") or {},
                "incident_window_verified": incident_window_verified,
            },
        },
    )


async def investigate(
    settings: Settings,
    target: object,
    collectors: list,
    plan: InvestigationPlan | None,
    kg_context: dict,
    max_steps: int,
    reporter: ProgressReporter | None = None,
    blackboard: Any = None,
    deadline_monotonic: float | None = None,
    initial_evidence: list[CollectorResult] | None = None,
    query_memory: QueryMemory | None = None,
) -> tuple[list[CollectorResult], dict[str, Any]]:
    state = _Investigation.start(
        settings,
        target,
        collectors,
        plan,
        kg_context,
        max_steps,
        reporter=reporter,
        blackboard=blackboard,
        deadline_monotonic=deadline_monotonic,
        initial_evidence=initial_evidence,
        query_memory=query_memory,
    )
    try:
        await state.decision_rounds()
    except Exception:  # noqa: BLE001 - never raise into analyze; keep whatever we have
        pass
    try:
        await state.reflection_rounds()
    except Exception:  # noqa: BLE001 - reflection is best-effort
        pass

    # A supported hypothesis citing a scoped positive fact is a real terminal
    # condition: ranking/synthesis can consume a subset and must not force every
    # unrelated evidence plane to run. Without that proof, retain the safe full
    # gather fallback so transport/LLM failures do not yield an empty RCA.
    evidence_sufficient = state.is_sufficient()
    await state.final_gather(evidence_sufficient=evidence_sufficient)
    await state.kubernetes_floor(evidence_sufficient=evidence_sufficient)
    state.attach_adhoc_artifacts()
    return state.finish(evidence_sufficient=evidence_sufficient)


async def _reflect_hypotheses(
    settings: Settings,
    plan: InvestigationPlan | None,
    kg_context: dict,
    evidence: dict[str, CollectorResult],
    by_name: dict,
    ledger: list[dict[str, Any]],
    adhoc: list[dict] | None = None,
    *,
    query_feedback: list[dict[str, Any]] | None = None,
    blackboard: Any = None,
    target: AnalysisTarget | None = None,
) -> list[dict[str, Any]]:
    reflection = await complete_json(
        settings,
        system=(
            "You are doing one final skeptical reflection before concluding an RCA "
            "investigation. Look for a missed hypothesis, contradiction, or weakly "
            "supported confidence. Do not invent evidence; cite only F- observation IDs "
            "from shared_observations in evidence_for/evidence_against. For new_hypotheses, "
            "set discriminator to the collector name (see available_collectors) or "
            "adhoc_query_kind that could test it; omit it only if nothing here can test it. "
            "Respond with ONLY JSON: "
            '{"hypothesis_updates":[{"id":str,"confidence":number,"mechanism":str,'
            '"expected_observations":[str],"falsifiers":[str],'
            '"next_discriminating_test":str,"evidence_for":[str],'
            '"evidence_against":[str],"status":"open|testing|supported|refuted|uncertain"}],'
            '"new_hypotheses":[{"family"?:str,"statement":str,"mechanism":str,'
            '"expected_observations":[str],"falsifiers":[str],'
            '"next_discriminating_test":str,"discriminator"?:str}]}'
        ),
        user=_investigator_masker(settings).mask_text(
            _build_user_prompt(
                plan,
                kg_context,
                evidence,
                by_name,
                ledger,
                adhoc,
                query_feedback=query_feedback,
                blackboard=blackboard,
            )
        ),
        model=settings.llm_model_investigation,
    )
    if not isinstance(reflection, dict):
        return ledger
    ledger = _apply_ledger_updates(
        ledger,
        reflection.get("hypothesis_updates"),
        blackboard=blackboard,
        artifacts=[item for result in evidence.values() for item in result.artifacts],
        eligible_support_ids=_eligible_support_ids(blackboard, target),
    )
    return _add_reflected_hypotheses(ledger, reflection.get("new_hypotheses"), set(by_name))


def _build_user_prompt(
    plan: InvestigationPlan | None,
    kg_context: dict,
    evidence: dict[str, CollectorResult],
    by_name: dict,
    ledger: list[dict[str, Any]],
    adhoc: list[dict] | None = None,
    *,
    query_feedback: list[dict[str, Any]] | None = None,
    blackboard: Any = None,
) -> str:
    plan_view = plan.as_dict() if plan else {}
    # The ledger is the canonical hypothesis list for repeated investigator
    # turns. Planner hypotheses and case cards are already represented by the
    # ledger and knowledge_graph respectively, so carrying both copies can
    # consume almost the entire prompt before evidence is added.
    plan_view.pop("hypotheses", None)
    plan_view.pop("case_cards", None)
    stable = {
        "plan": plan_view,
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
            "historical_case_cards": kg_context.get("case_cards") or [],
        },
        "available_collectors": {name: _COLLECTOR_HINTS.get(name, "") for name in by_name},
        "adhoc_query_kinds": sorted(_READ_KINDS),
        "named_pod_query_behavior": (
            "A query for kind=pods with a specific name is executed as Kubernetes MCP-backed "
            "Pod YAML + describe/events, not a compact get. Use it before unrelated broad reads."
        ),
    }
    variable = {
        "hypothesis_ledger": _ledger_prompt_view(ledger),
        "evidence_so_far": _evidence_summary(evidence),
        "not_yet_probed": [name for name in by_name if name not in evidence],
        # The last few ad-hoc reads, trimmed — enough for the LLM to chain
        # "PVC is Pending -> check the storageclass" style drill-downs.
        "adhoc_results": _adhoc_prompt_results(adhoc),
        # Local validation failures are control feedback, never observations.
        # They let the next bounded round repair a kind/name/selector without
        # turning a rejected request into evidence or a report artifact.
        "query_feedback": list(query_feedback or [])[-6:],
        # Other evidence agents' findings are supplied as facts, not raw
        # transport/query text.  A domain agent can therefore test a CSI clue
        # in Loki/system without inheriting an unsafe executable query.
        "shared_observations": _blackboard_prompt_view(blackboard, limit=12),
    }
    return _capped_json_prompt(
        stable,
        variable,
        max_chars=_USER_PROMPT_CHARS,
        trim_keys=(
            "evidence_so_far",
            "adhoc_results",
            "query_feedback",
            "shared_observations",
        ),
    )


def _record_blackboard(
    blackboard: Any,
    agent: str,
    result: CollectorResult | None,
    target: AnalysisTarget | None = None,
) -> None:
    if blackboard is None or result is None:
        return
    for name in ("add_result", "add_collector_result"):
        method = getattr(blackboard, name, None)
        if callable(method):
            try:
                kwargs: dict[str, str] = {}
                if target is not None:
                    causal_window = causal_evidence_time_range(target) or {}
                    kwargs = {
                        "entity": next(
                            (
                                f"{field}:{value}"
                                for field in ("pod", "node", "workload_name", "namespace")
                                if (value := str(getattr(target, field, "") or "").strip())
                            ),
                            "",
                        ),
                        "timestamp": str(getattr(target, "fired_at", "") or ""),
                        "observed_window_start": str(causal_window.get("start") or ""),
                        "observed_window_end": str(causal_window.get("end") or ""),
                    }
                method(agent, result, **kwargs)
            except TypeError:
                try:
                    method(agent, result)
                except TypeError:
                    method(result)
            except Exception:  # noqa: BLE001 - blackboard is advisory
                pass
            return


def _probe_history_record(
    result: CollectorResult, scope: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "agent": result.agent,
        "scope": dict(scope or {}),
        "status": result.status,
        "summary": (result.summary or "")[:500],
        "missing_data": list(dict.fromkeys(result.missing_data)),
    }


def _artifact_merge_fingerprint(item: Any) -> str:
    """Fingerprint semantic card content, not its response-local display ID."""
    if isinstance(item, dict):
        payload: Any = dict(item)
    else:
        dump = getattr(item, "model_dump", None)
        if callable(dump):
            payload = dump(mode="json")
        else:
            payload = dict(getattr(item, "__dict__", {})) or item
    if isinstance(payload, dict):
        payload.pop("evidence_id", None)
    try:
        return json.dumps(payload, sort_keys=True, default=str)
    except TypeError:
        return repr(payload)


def _merge_collector_results(
    previous: CollectorResult | None,
    current: CollectorResult,
    *,
    previous_scope: dict[str, Any] | None = None,
    current_scope: dict[str, Any] | None = None,
) -> CollectorResult:
    """Retain evidence from repeated collector probes with distinct scopes."""
    if previous is None:
        return current
    summaries: list[str] = []
    for candidate in (previous.summary, current.summary):
        if candidate and candidate not in summaries:
            summaries.append(candidate)
    summary = " | ".join(summaries[-4:])[:1600]
    previous_history = (
        previous.details.get("probe_results")
        if isinstance(previous.details, dict)
        else []
    )
    history = list(previous_history) if isinstance(previous_history, list) else []
    if not history:
        history.append(_probe_history_record(previous, previous_scope))
    current_history = (
        current.details.get("probe_results")
        if isinstance(current.details, dict)
        else []
    )
    if isinstance(current_history, list) and current_history:
        history.extend(current_history)
    else:
        history.append(_probe_history_record(current, current_scope))

    scope_aware = previous_scope is not None or current_scope is not None
    if scope_aware:
        latest_by_scope: dict[str, dict[str, Any]] = {}
        for record in history:
            if not isinstance(record, dict):
                continue
            scope = record.get("scope")
            scope_key = json.dumps(
                scope if isinstance(scope, dict) else {},
                sort_keys=True,
                default=str,
            )
            latest_by_scope[scope_key] = record
        latest_records = list(latest_by_scope.values())
        missing_data = list(
            dict.fromkeys(
                str(item)
                for record in latest_records
                for item in (
                    record.get("missing_data")
                    if isinstance(record.get("missing_data"), list)
                    else []
                )
                if str(item)
            )
        )
        all_latest_ok = bool(latest_records) and all(
            str(record.get("status") or "") == "ok" for record in latest_records
        )
        any_usable = any(
            str(record.get("status") or "") in {"ok", "partial"}
            for record in history
            if isinstance(record, dict)
        )
        if all_latest_ok and not missing_data:
            status = "ok"
        elif any_usable:
            status = "partial"
        else:
            status = "unavailable"
    else:
        # Non-scoped callers retain the historical latest-pass semantics.
        if current.status == "ok":
            status = "ok"
        elif current.status == "partial" or previous.status in {"ok", "partial"}:
            status = "partial"
        else:
            status = "unavailable"
        missing_data = list(dict.fromkeys(current.missing_data))

    artifacts: list[Any] = []
    seen_artifacts: set[str] = set()
    for item in (*previous.artifacts, *current.artifacts):
        fingerprint = _artifact_merge_fingerprint(item)
        if fingerprint in seen_artifacts:
            continue
        seen_artifacts.add(fingerprint)
        artifacts.append(item)
    return CollectorResult(
        agent=current.agent or previous.agent,
        status=status,
        summary=summary,
        confidence=max(
            (previous.confidence, current.confidence),
            key=lambda value: {"low": 0, "medium": 1, "high": 2}.get(value, 0),
        ),
        details={
            **(previous.details if isinstance(previous.details, dict) else {}),
            **(current.details if isinstance(current.details, dict) else {}),
            "probe_results": history[-8:],
        },
        # Scoped gaps clear only when that same scope succeeds. A successful
        # node probe must not silently resolve a failed historical pod query.
        missing_data=missing_data,
        warnings=list(dict.fromkeys([*previous.warnings, *current.warnings])),
        artifacts=artifacts,
    )


def _blackboard_prompt_view(blackboard: Any, *, limit: int) -> list[dict[str, Any]]:
    if blackboard is None:
        return []
    method = getattr(blackboard, "prompt_view", None)
    if not callable(method):
        return []
    try:
        view = method(limit=limit)
    except TypeError:
        view = method()
    except Exception:  # noqa: BLE001 - blackboard is advisory
        return []
    return view if isinstance(view, list) else []


def _capped_json_prompt(
    stable: dict[str, Any],
    variable: dict[str, Any],
    *,
    max_chars: int,
    trim_keys: tuple[str, ...],
) -> str:
    variable = {
        key: list(value) if isinstance(value, list) else value for key, value in variable.items()
    }
    payload = {**stable, **variable}
    text = json.dumps(payload, ensure_ascii=False, default=str)
    while len(text) > max_chars:
        for key in trim_keys:
            value = variable.get(key)
            if isinstance(value, list) and len(value) > 1:
                variable[key] = value[1:]
                payload = {**stable, **variable}
                text = json.dumps(payload, ensure_ascii=False, default=str)
                break
        else:
            break
    if len(text) <= max_chars:
        return text
    marker = '"...truncated older prompt context..."'
    tail = max_chars // 4
    head = max_chars - tail - len(marker)
    return text[:head] + marker + text[-tail:]


def _adhoc_failure_feedback(item: dict[str, Any]) -> dict[str, Any]:
    """Return query-correction metadata without replaying a failed response.

    Kubernetes/API errors can include response bodies and stale resource text.
    Feeding those strings back to the LLM made failed telemetry look like an
    observed signal. Only adapter-owned status plus a fixed classification and
    correction hint cross the prompt boundary here.
    """
    raw_status = item.get("status_code")
    try:
        status = int(raw_status)
    except (TypeError, ValueError):
        status = 0
    error = " ".join(str(item.get("error") or "").lower().split())

    category = "query_failure"
    retryable = False
    hint = "Choose another available evidence source; do not treat this failure as evidence."
    if status in {401, 403} or any(
        token in error for token in ("unauthorized", "forbidden", "permission denied")
    ):
        category = "authorization"
        hint = "Query changes cannot repair authorization; use another configured evidence source."
    elif any(
        token in error
        for token in (
            "self-signed certificate",
            "certificate verify failed",
            "tls handshake",
            "x509:",
        )
    ):
        category = "tls_configuration"
        hint = (
            "Query changes cannot repair TLS configuration; use another configured "
            "evidence source."
        )
    elif any(
        token in error
        for token in (
            "datasource uid",
            "datasourceuid",
            "get datasource by uid",
            "no accessible datasource",
            "id is invalid",
        )
    ):
        category = "datasource_configuration"
        hint = "Query changes cannot repair datasource configuration; use another evidence source."
    elif status == 404 or "not found" in error:
        category = "target_not_found"
        retryable = True
        hint = (
            "Use a target-bound identity already present in evidence, or list the same kind "
            "inside the same namespace before retrying; do not broaden cluster scope."
        )
    elif status in {400, 422} or any(
        token in error
        for token in (
            "bad request",
            "invalid selector",
            "invalid field selector",
            "invalid resource",
            "parse error",
        )
    ):
        category = "invalid_request"
        retryable = True
        hint = (
            "Correct the allowlisted resource kind, target-bound name, or selector and issue "
            "a different read-only query."
        )
    elif status == 429:
        category = "rate_limited"
        hint = "Query mutation will not repair rate limiting; avoid immediate duplicate retries."
    elif status >= 500 or any(
        token in error
        for token in (
            "timed out",
            "timeout",
            "connection refused",
            "no route to host",
            "temporary failure",
        )
    ):
        category = "transport_unavailable"
        hint = "Query changes cannot repair this transport failure; use another evidence source."

    feedback: dict[str, Any] = {
        "message": "query failed",
        "category": category,
        "retryable_by_query_change": retryable,
        "correction_hint": hint,
        "evidence": False,
    }
    if 100 <= status <= 599:
        feedback["http_status"] = status
    return feedback


def _feedback_query_identity(query: object) -> dict[str, str]:
    if not isinstance(query, dict):
        return {}
    identity: dict[str, str] = {}
    for key in ("kind", "namespace", "name"):
        value = str(query.get(key) or "").strip()
        # These fields are Kubernetes identifiers/resource aliases. Keep only
        # their safe vocabulary when reflecting an LLM-generated rejection.
        if value and re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", value):
            identity[key] = value
    return identity


def _rejected_adhoc_query_feedback(query: object) -> dict[str, Any]:
    # Inline the actual allowlist: adhoc_query_kinds is buried at the top of a
    # 3k+ token prompt while this feedback item is the freshest thing the
    # model sees, and a model corrected only the SPELLING of an invalid kind
    # (RoleBinding -> rolebindings) when the vocabulary itself was never shown
    # here.
    return {
        "query": _feedback_query_identity(query),
        "failure": {
            "message": "query rejected",
            "category": "invalid_resource_kind",
            "retryable_by_query_change": True,
            "correction_hint": (
                "Use one of adhoc_query_kinds for Kubernetes get/list: "
                f"{', '.join(sorted(_READ_KINDS))}. Use the matching collector probe for "
                "logs, metrics, or deployment history."
            ),
            "evidence": False,
        },
    }


def _duplicate_failed_query_feedback(query: object) -> dict[str, Any]:
    return {
        "query": _feedback_query_identity(query),
        "failure": {
            "message": "failed query repeated",
            "category": "duplicate_failed_query",
            "retryable_by_query_change": True,
            "correction_hint": (
                "Do not repeat the exact failed query; change the target-bound name, kind, "
                "or selector while staying in incident scope."
            ),
            "evidence": False,
        },
    }


def _adhoc_prompt_results(adhoc: list[dict] | None) -> list[Any]:
    results: list[Any] = []
    for item in (adhoc or [])[-6:]:
        if item.get("error"):
            # Keep failure metadata structured so the next model round can
            # reliably branch on retryability; no remote error/body is copied.
            results.append(
                {
                    "query": _adhoc_query_repr(item),
                    "failure": _adhoc_failure_feedback(item),
                }
            )
        else:
            results.append(_adhoc_prompt_result(item))
    return results


def _adhoc_prompt_result(item: dict) -> str:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    object_data = data.get("object") if isinstance(data.get("object"), dict) else data
    status = object_data.get("status") if isinstance(object_data.get("status"), dict) else {}
    conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
    containers = (
        status.get("containerStatuses")
        if isinstance(status.get("containerStatuses"), list)
        else []
    )
    status_extract = {
        "phase": status.get("phase"),
        "reason": status.get("reason"),
        "message": status.get("message"),
        "conditions": [
            {
                key: condition.get(key)
                for key in ("type", "status", "reason", "message")
                if condition.get(key) is not None
            }
            for condition in conditions[:4]
            if isinstance(condition, dict)
        ],
        "containerStatuses": [
            {
                "name": container.get("name"),
                "restartCount": container.get("restartCount"),
                "waiting": (
                    container["state"].get("waiting")
                    if isinstance(container.get("state"), dict)
                    else None
                ),
                "terminated": (
                    container["state"].get("terminated")
                    if isinstance(container.get("state"), dict)
                    else None
                ),
            }
            for container in containers[:4]
            if isinstance(container, dict)
        ],
    }
    projection = {
        "query": _adhoc_query_repr(item),
        "time_scope": "incident_window_verified" if item.get("time_range") else "current_snapshot_only",
        "signals": kubernetes_salient_markers(data),
        "status": status_extract,
    }
    return json.dumps(projection, default=str)[:600]


def _investigator_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )
