"""Iterative, hypothesis-driven investigation loop (LLM-gated).

Replaces the one-shot "gather every collector once" with a senior-SRE ReAct
loop: each step the LLM looks at the plan, the hypotheses, and the evidence
gathered so far, then either probes specific collectors (optionally scoped to a
namespace/pod/node/workload) or concludes. The loop is bounded by max_steps and
by "every collector probed at least once".

Downstream ranking/synthesis still needs EVERY collector's result, so before
returning we run any collector the loop never touched. On ANY LLM/JSON failure
we fall back to running all collectors once — i.e. current behaviour.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
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
from app.services.evidence_blackboard import source_independence_group

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
        return {**read, **({"time_range": time_range} if time_range else {})}
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
) -> list[dict[str, Any]]:
    if not isinstance(updates, list):
        return ledger
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
    return ledger


def _add_reflected_hypotheses(
    ledger: list[dict[str, Any]], candidates: object
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
        for field in (
            "evidence_for",
            "evidence_against",
            "expected_observations",
            "falsifiers",
        ):
            if values := _texts(candidate.get(field))[:5]:
                entry[field] = values
        if next_test := str(candidate.get("next_discriminating_test") or "").strip():
            entry["next_discriminating_test"] = next_test
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


def _legacy_supported(
    ledger: list[dict[str, Any]], *, eligible_support_ids: set[str] | None = None
) -> bool:
    return any(
        item.get("status") == "supported"
        and bool(
            set(_texts(item.get("evidence_for")))
            & (eligible_support_ids if eligible_support_ids is not None else set())
        )
        for item in ledger
    )


def _eligible_support_ids(blackboard: Any) -> set[str]:
    """Return only scoped positive fact IDs the investigator may cite as support."""
    facts = getattr(blackboard, "facts", None)
    if not callable(facts):
        return set()
    try:
        return {
            str(fact.fact_id)
            for fact in facts()
            if str(getattr(fact, "fact_id", ""))
            and bool(getattr(getattr(fact, "eligibility", None), "support", False))
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
) -> tuple[list[CollectorResult], dict[str, Any]]:
    by_name = {_collector_name(c): c for c in collectors}
    all_names = set(by_name)
    evidence: dict[str, CollectorResult] = {}
    latest_probe_scopes: dict[str, dict[str, Any]] = {}
    ledger = _initial_ledger(plan)
    investigation_steps: list[dict[str, Any]] = []
    seen_probes: set[str] = set()
    seen_queries: set[str] = set()
    failed_queries: set[str] = set()
    # Validation/duplicate feedback is deliberately separate from ``adhoc``:
    # rejected queries were never observations and must not become artifacts.
    query_feedback: list[dict[str, Any]] = []

    async def run_probe(name: str, scope: dict) -> None:
        collector = by_name.get(name)
        if collector is None:
            return
        if reporter:
            reporter.emit(
                "investigation",
                f"Probing {name}",
                collector=name,
                scope=scope,
                hypothesis_ledger=_ledger_summary(ledger),
            )
        result = await _within_budget(
            deadline_monotonic,
            lambda: _collect_safely(collector, target, _scoped_plan(plan, scope)),
        )
        evidence[name] = _merge_collector_results(
            evidence.get(name),
            result,
            previous_scope=latest_probe_scopes.get(name),
            current_scope=scope,
        )
        latest_probe_scopes[name] = dict(scope)
        _record_blackboard(blackboard, name, result, target)
        if reporter:
            reporter.emit(
                "investigation",
                f"{name} evidence collected",
                collector=name,
                status=result.status,
                summary=(result.summary or "")[:300],
                hypothesis_ledger=_ledger_summary(ledger),
            )

    adhoc: list[dict] = []
    try:
        ran_queries_last_step = False
        step = 0
        # Bound LLM decision rounds while allowing every round to batch many
        # independent read-only queries. Older zero-valued callers use 3.
        decision_round_limit = max_steps if max_steps > 0 else 3
        while step < decision_round_limit:
            remaining_budget = _budget_remaining(deadline_monotonic)
            if remaining_budget is not None and remaining_budget <= 0:
                break
            step += 1
            if (
                all_names <= set(evidence)
                and not ran_queries_last_step
                and _legacy_supported(
                    ledger, eligible_support_ids=_eligible_support_ids(blackboard)
                )
            ):
                break  # scoped evidence already grounds a supported hypothesis
            if reporter:
                reporter.emit(
                    "investigation",
                    "Choosing next diagnostic step",
                    step=step,
                    hypothesis_ledger=_ledger_summary(ledger),
                )
            decision = await _within_budget(
                deadline_monotonic,
                lambda ledger=ledger: complete_json(
                    settings,
                    system=(
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
                        '"next_discriminating_test":str}]}'
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
                ),
            )
            if not isinstance(decision, dict):
                break  # unusable response -> fall through to full gather
            eligible_support_ids = _eligible_support_ids(blackboard)
            ledger = _apply_ledger_updates(
                ledger,
                decision.get("hypothesis_updates"),
                eligible_support_ids=eligible_support_ids,
            )
            ledger = _add_reflected_hypotheses(ledger, decision.get("new_hypotheses"))
            investigation_steps.append(
                {
                    "step": step,
                    "action": str(decision.get("action") or ""),
                    "reason": str(decision.get("reason") or "")[:300],
                    "selected_hypothesis": str(decision.get("selected_hypothesis") or ""),
                }
            )
            if reporter:
                reporter.emit(
                    "investigation",
                    str(decision.get("reason") or "Diagnostic step selected")[:300],
                    step=step,
                    action=str(decision.get("action") or ""),
                    selected_hypothesis=str(decision.get("selected_hypothesis") or ""),
                    probes=decision.get("probes"),
                    queries=decision.get("queries"),
                    hypothesis_updates=decision.get("hypothesis_updates"),
                    hypothesis_ledger=_ledger_summary(ledger),
                )
            unverified_conclusion = decision.get("action") == "conclude" and not _legacy_supported(
                ledger, eligible_support_ids=eligible_support_ids
            )
            if decision.get("action") == "conclude" and not unverified_conclusion:
                break
            selected_hypothesis = str(decision.get("selected_hypothesis") or "")
            probes = decision.get("probes")
            queries = decision.get("queries")
            retryable_query_rejection = False
            fresh = []
            for probe in probes if isinstance(probes, list) else []:
                if not isinstance(probe, dict) or probe.get("collector") not in all_names:
                    continue
                fingerprint = json.dumps(
                    {"collector": probe.get("collector"), "scope": probe.get("scope") or {}},
                    sort_keys=True,
                    default=str,
                )
                if fingerprint in seen_probes:
                    continue
                seen_probes.add(fingerprint)
                fresh.append(probe)
            fresh = _prioritize_probes(
                fresh,
                evidence=evidence,
                ledger=ledger,
                plan=plan,
                selected_hypothesis=selected_hypothesis,
            )
            wanted = []
            for query in queries if isinstance(queries, list) else []:
                if not _valid_adhoc_kubernetes_query(query):
                    query_feedback.append(_rejected_adhoc_query_feedback(query))
                    query_feedback[:] = query_feedback[-8:]
                    retryable_query_rejection = True
                    if reporter and isinstance(query, dict):
                        reporter.emit(
                            "investigation",
                            "Rejected non-Kubernetes ad-hoc query kind",
                            step=step,
                            kind=str(query.get("kind") or ""),
                        )
                    continue
                fingerprint = json.dumps(query, sort_keys=True, default=str)
                if fingerprint in seen_queries:
                    if fingerprint in failed_queries:
                        query_feedback.append(_duplicate_failed_query_feedback(query))
                        query_feedback[:] = query_feedback[-8:]
                        retryable_query_rejection = True
                    continue
                seen_queries.add(fingerprint)
                wanted.append(query)
            if unverified_conclusion and not fresh and not wanted:
                # Never let a model conclude from its initial, evidence-free
                # prompt. Collect every remaining base plane concurrently, so
                # the next bounded reasoning round sees observations to cite.
                fresh = [
                    {"collector": collector, "scope": {}}
                    for collector in sorted(all_names - set(evidence))
                ]
            if not fresh and not wanted and decision.get("action") == "probe":
                fallback = _fallback_probe(
                    all_names,
                    evidence=evidence,
                    ledger=ledger,
                    plan=plan,
                    selected_hypothesis=selected_hypothesis,
                )
                if fallback is not None:
                    fingerprint = json.dumps(
                        {"collector": fallback["collector"], "scope": fallback["scope"]},
                        sort_keys=True,
                    )
                    seen_probes.add(fingerprint)
                    fresh.append(fallback)
            if not fresh and not wanted:
                if retryable_query_rejection and step < decision_round_limit:
                    # The rejected/duplicate request is not evidence. Give the
                    # LLM one of its remaining bounded rounds to change the
                    # kind/name/selector instead of silently ending the loop.
                    continue
                if unverified_conclusion and step < decision_round_limit:
                    # Keep the remaining bounded rounds available for the
                    # model to reconsider the newly collected base evidence.
                    continue
                break
            if fresh:
                await _within_budget(
                    deadline_monotonic,
                    lambda fresh=fresh: asyncio.gather(
                        *(run_probe(p["collector"], p.get("scope") or {}) for p in fresh)
                    ),
                )
            for q in wanted:
                if reporter:
                    reporter.emit(
                        "investigation",
                        f"Running {_adhoc_query_repr(q)}",
                        step=step,
                        query=_adhoc_query_repr(q),
                    )
            if wanted:
                query_results = await _within_budget(
                    deadline_monotonic,
                    lambda wanted=wanted: asyncio.gather(
                        *(
                            _run_adhoc_kubernetes_query(
                                settings,
                                q,
                                time_range=_incident_window_for_target(target),
                            )
                            for q in wanted
                        )
                    ),
                )
                adhoc.extend(query_results)
                for query, item in zip(wanted, query_results, strict=True):
                    if item.get("error"):
                        failed_queries.add(json.dumps(query, sort_keys=True, default=str))
            ran_queries_last_step = bool(wanted)
            # A bounded investigation may finish early only when the ledger
            # cites an actual scoped fact. Model prose or partial observations
            # must consume the remaining (at most three) reasoning rounds.
            if _legacy_supported(ledger, eligible_support_ids=_eligible_support_ids(blackboard)):
                break
    except Exception:  # noqa: BLE001 - never raise into analyze; keep whatever we have
        pass

    try:
        before_reflection = _ledger_fingerprint(ledger)
        reflection_budget = _budget_remaining(deadline_monotonic)
        if reflection_budget is None or reflection_budget > 0:
            ledger = await _within_budget(
                deadline_monotonic,
                lambda ledger=ledger: _reflect_hypotheses(
                    settings,
                    plan,
                    kg_context,
                    evidence,
                    by_name,
                    ledger,
                    adhoc,
                    query_feedback=query_feedback,
                    blackboard=blackboard,
                ),
            )
        if _ledger_fingerprint(ledger) != before_reflection:
            # A reflection is useful only if its new/changed hypothesis is put
            # back through a discriminating read-only probe. Keep this phase
            # bounded too: otherwise a model returning endless distinct reads
            # can consume the entire shared evidence budget before synthesis.
            verification_round = 0
            verification_round_limit = max_steps if max_steps > 0 else 3
            while verification_round < verification_round_limit:
                remaining_budget = _budget_remaining(deadline_monotonic)
                if remaining_budget is not None and remaining_budget <= 0:
                    break
                verification_round += 1
                verification = await _within_budget(
                    deadline_monotonic,
                    lambda ledger=ledger: complete_json(
                        settings,
                        system=(
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
                    ),
                )
                if not isinstance(verification, dict):
                    break
                ledger = _apply_ledger_updates(
                    ledger,
                    verification.get("hypothesis_updates"),
                    eligible_support_ids=_eligible_support_ids(blackboard),
                )
                if verification.get("action") == "conclude":
                    break
                retryable_query_rejection = False
                fresh = []
                for probe in verification.get("probes") or []:
                    if not isinstance(probe, dict) or probe.get("collector") not in all_names:
                        continue
                    fingerprint = json.dumps(
                        {"collector": probe.get("collector"), "scope": probe.get("scope") or {}},
                        sort_keys=True,
                        default=str,
                    )
                    if fingerprint not in seen_probes:
                        seen_probes.add(fingerprint)
                        fresh.append(probe)
                fresh = _prioritize_probes(
                    fresh,
                    evidence=evidence,
                    ledger=ledger,
                    plan=plan,
                )
                wanted = []
                for query in verification.get("queries") or []:
                    if not _valid_adhoc_kubernetes_query(query):
                        query_feedback.append(_rejected_adhoc_query_feedback(query))
                        query_feedback[:] = query_feedback[-8:]
                        retryable_query_rejection = True
                        if reporter and isinstance(query, dict):
                            reporter.emit(
                                "investigation",
                                "Rejected non-Kubernetes ad-hoc query kind",
                                kind=str(query.get("kind") or ""),
                            )
                        continue
                    fingerprint = json.dumps(query, sort_keys=True, default=str)
                    if fingerprint in seen_queries:
                        if fingerprint in failed_queries:
                            query_feedback.append(_duplicate_failed_query_feedback(query))
                            query_feedback[:] = query_feedback[-8:]
                            retryable_query_rejection = True
                        continue
                    seen_queries.add(fingerprint)
                    wanted.append(query)
                if not fresh and not wanted:
                    if (
                        retryable_query_rejection
                        and verification_round < verification_round_limit
                    ):
                        continue
                    break
                if fresh:
                    await _within_budget(
                        deadline_monotonic,
                        lambda fresh=fresh: asyncio.gather(
                            *(
                                run_probe(probe["collector"], probe.get("scope") or {})
                                for probe in fresh
                            )
                        ),
                    )
                if wanted:
                    query_results = await _within_budget(
                        deadline_monotonic,
                        lambda wanted=wanted: asyncio.gather(
                            *(
                                _run_adhoc_kubernetes_query(
                                    settings,
                                    query,
                                    time_range=_incident_window_for_target(target),
                                )
                                for query in wanted
                            )
                        ),
                    )
                    adhoc.extend(query_results)
                    for query, item in zip(wanted, query_results, strict=True):
                        if item.get("error"):
                            failed_queries.add(
                                json.dumps(query, sort_keys=True, default=str)
                            )
        if reporter:
            reporter.emit(
                "reflection",
                "Checked for missing or contradictory hypotheses",
                hypothesis_ledger=_ledger_summary(ledger),
            )
    except Exception:  # noqa: BLE001 - reflection is best-effort
        pass

    # Synthesis waits for ALL collectors: run any we never probed, unscoped.
    remaining = [name for name in by_name if name not in evidence]
    if remaining:
        tasks = {
            asyncio.create_task(_collect_safely(by_name[name], target, plan)): name
            for name in remaining
        }
        budget = _budget_remaining(deadline_monotonic)
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
            evidence[name] = _merge_collector_results(evidence.get(name), result)
            _record_blackboard(blackboard, name, result, target)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for task in pending:
            name = tasks[task]
            evidence[name] = CollectorResult(
                agent=name,
                status="unavailable",
                summary=f"{name} collector skipped when the shared evidence budget expired.",
                missing_data=[f"{name}.analysis_budget"],
                warnings=["shared investigation/drill-down budget exhausted"],
            )

    # Ad-hoc reads are evidence too: attach them to the kubernetes result so the
    # report's evidence trail (and signature matching) sees what was drilled into.
    kubernetes_result = evidence.get("kubernetes")
    if adhoc and kubernetes_result is not None:
        language = getattr(settings, "language", "en")
        for item in adhoc:
            error = item.get("error")
            # Finding-first summary: name the problem signals in the data, not
            # the transport ("HTTP 200" tells the operator nothing).
            markers = [] if error else kubernetes_salient_markers(item.get("data"))
            if error:
                summary = str(error)
            elif markers:
                summary = signals_line(markers, language)
            else:
                summary = (
                    "특이 신호 없음 (HTTP {code})"
                    if language == "ko"
                    else "no problem signals (HTTP {code})"
                ).format(code=item.get("status_code"))
            kubernetes_result.artifacts.append(
                artifact(
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
                        # Full YAML/describe is valuable operator context, but
                        # it is a current snapshot. Its filtered events retain
                        # the incident window separately; the combined ad-hoc
                        # artifact must never become automatic RCA support.
                        "observation": {
                            "kind": "kubernetes_adhoc_query",
                            "predicate": "kubernetes_adhoc_query",
                            "polarity": "unavailable" if error else "unknown",
                            "coverage": "unknown" if error else "partial",
                            "observation_window": item.get("time_range") or {},
                        },
                    },
                )
            )
        _record_blackboard(blackboard, "kubernetes", kubernetes_result, target)

    results = list(evidence.values())
    context = {
        "hypothesis_ledger": _ledger_summary(ledger),
        "investigation_steps": investigation_steps,
        "adhoc_query_count": len(adhoc),
        "reasoning_trace_v2": {
            "schema_version": 2,
            "hypotheses": _ledger_summary(ledger),
            "referenced_facts": _blackboard_prompt_view(blackboard, limit=30),
            "stop_reason": (
                "analysis_budget_exhausted"
                if (_budget_remaining(deadline_monotonic) is not None)
                and (_budget_remaining(deadline_monotonic) or 0) <= 0
                else "all_collectors_probed"
            ),
        },
    }
    safe_context = _investigator_masker(settings).mask_object(context)
    return results, safe_context if isinstance(safe_context, dict) else context


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
) -> list[dict[str, Any]]:
    reflection = await complete_json(
        settings,
        system=(
            "You are doing one final skeptical reflection before concluding an RCA "
            "investigation. Look for a missed hypothesis, contradiction, or weakly "
            "supported confidence. Do not invent evidence; cite only F- observation IDs "
            "from shared_observations in evidence_for/evidence_against. Respond with ONLY JSON: "
            '{"hypothesis_updates":[{"id":str,"confidence":number,"mechanism":str,'
            '"expected_observations":[str],"falsifiers":[str],'
            '"next_discriminating_test":str,"evidence_for":[str],'
            '"evidence_against":[str],"status":"open|testing|supported|refuted|uncertain"}],'
            '"new_hypotheses":[{"family"?:str,"statement":str,"mechanism":str,'
            '"expected_observations":[str],"falsifiers":[str],'
            '"next_discriminating_test":str}]}'
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
        eligible_support_ids=_eligible_support_ids(blackboard),
    )
    return _add_reflected_hypotheses(ledger, reflection.get("new_hypotheses"))


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
    return {
        "query": _feedback_query_identity(query),
        "failure": {
            "message": "query rejected",
            "category": "invalid_resource_kind",
            "retryable_by_query_change": True,
            "correction_hint": (
                "Use one of adhoc_query_kinds for Kubernetes get/list. Use the matching "
                "collector probe for logs, metrics, or deployment history."
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
