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

from app.collectors.base import CollectorResult, artifact, salient_markers, signals_line
from app.collectors.kubernetes import _READ_KINDS, k8s_read, kind_lookup_title, kubectl_repr
from app.config import Settings
from app.llm import complete_json
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.services.evidence_blackboard import source_independence_group

_LEDGER_STATUSES = {"open", "testing", "supported", "refuted", "uncertain"}
_USER_PROMPT_CHARS = 8000


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
    return kubectl_repr(
        str(item.get("kind") or ""),
        namespace=str(item.get("namespace") or ""),
        name=str(item.get("name") or ""),
        label_selector=str(item.get("label_selector") or ""),
    )


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
        ledger.append(
            {
                "id": f"H{idx}",
                "family": family,
                "statement": reason or family.replace("_", " "),
                "mechanism": str(item.get("mechanism") or reason or family.replace("_", " ")),
                "confidence": 0.5,
                "evidence_for": [],
                "evidence_against": [],
                "expected_observations": _texts(item.get("expected_observations")),
                "falsifiers": _texts(item.get("falsifiers")),
                "next_discriminating_test": str(item.get("next_discriminating_test") or ""),
                "status": "open",
            }
        )
    return ledger


def _ledger_summary(ledger: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "family": item.get("family"),
            "statement": item.get("statement"),
            "mechanism": item.get("mechanism") or item.get("statement"),
            "confidence": item.get("confidence"),
            "status": item.get("status"),
            "evidence_for": item.get("evidence_for", [])[-3:],
            "evidence_against": item.get("evidence_against", [])[-3:],
            "expected_observations": item.get("expected_observations", [])[-3:],
            "falsifiers": item.get("falsifiers", [])[-3:],
            "next_discriminating_test": item.get("next_discriminating_test", ""),
        }
        for item in ledger
    ]


def _apply_ledger_updates(
    ledger: list[dict[str, Any]], updates: object, *, allow_supported: bool = True
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
        status = str(update.get("status") or "").strip().lower()
        if status == "supported" and not allow_supported:
            status = "testing"
        if status in _LEDGER_STATUSES:
            item["status"] = status
        _extend_text_list(item, "evidence_for", update.get("evidence_for"))
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
        key = family or _normalise_hypothesis(statement)
        if not key or key in existing:
            continue
        ledger.append(
            {
                "id": f"H{len(ledger) + 1}",
                "family": family,
                "statement": statement or family.replace("_", " "),
                "mechanism": str(
                    candidate.get("mechanism") or statement or family.replace("_", " ")
                ),
                "confidence": _clamp_confidence(candidate.get("confidence"), 0.4),
                "evidence_for": _texts(candidate.get("evidence_for"))[:5],
                "evidence_against": _texts(candidate.get("evidence_against"))[:5],
                "expected_observations": _texts(candidate.get("expected_observations")),
                "falsifiers": _texts(candidate.get("falsifiers")),
                "next_discriminating_test": str(candidate.get("next_discriminating_test") or ""),
                "status": str(candidate.get("status") or "open")
                if str(candidate.get("status") or "open") in _LEDGER_STATUSES
                else "open",
            }
        )
        existing.add(key)
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


def _legacy_supported(ledger: list[dict[str, Any]]) -> bool:
    return any(
        item.get("status") == "supported" and bool(item.get("evidence_for")) for item in ledger
    )


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
    ledger = _initial_ledger(plan)
    investigation_steps: list[dict[str, Any]] = []
    seen_probes: set[str] = set()
    seen_queries: set[str] = set()

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
        evidence[name] = result
        _record_blackboard(blackboard, name, result)
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
            if all_names <= set(evidence) and not ran_queries_last_step:
                break  # every collector probed and no ad-hoc drill-down pending
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
                        "you are testing, probe collectors most likely to confirm/refute it, "
                        "and use plan.diagnostic_directive as neutral ontology guidance: "
                        "follow its checks and disconfirmations, but never treat its "
                        "provisional_family as observed evidence. Update confidence using "
                        "only observed evidence. A condition name alone is metadata; verify "
                        "its status/value and treat False or a zero sample as refutation. "
                        "Cite shared_observations evidence_id "
                        "values (F-...) in evidence_for/evidence_against; do not invent IDs. "
                        "When diagnostic_directive.probes names a tool you can reach through a collector, "
                        "use it as a discriminator and honor its supports_when/refutes_when conditions. You can ALSO "
                        "run kubectl-style READ-ONLY Kubernetes queries (get/list of an "
                        "allowlisted kind, see adhoc_query_kinds). Batch all independent "
                        "discriminating queries for this step instead of spending another "
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
                            blackboard=blackboard,
                        )
                    ),
                    model=settings.llm_model_investigation,
                ),
            )
            if not isinstance(decision, dict):
                break  # unusable response -> fall through to full gather
            ledger = _apply_ledger_updates(ledger, decision.get("hypothesis_updates"))
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
            if decision.get("action") == "conclude":
                break
            selected_hypothesis = str(decision.get("selected_hypothesis") or "")
            probes = decision.get("probes")
            queries = decision.get("queries")
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
                if not isinstance(query, dict) or not str(query.get("kind") or "").strip():
                    continue
                fingerprint = json.dumps(query, sort_keys=True, default=str)
                if fingerprint in seen_queries:
                    continue
                seen_queries.add(fingerprint)
                wanted.append(query)
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
                adhoc.append(
                    await _within_budget(
                        deadline_monotonic,
                        lambda q=q: k8s_read(
                            settings,
                            str(q.get("kind")),
                            namespace=str(q.get("namespace") or ""),
                            name=str(q.get("name") or ""),
                            label_selector=str(q.get("label_selector") or ""),
                        ),
                    )
                )
            ran_queries_last_step = bool(wanted)
            # Legacy bounded callers keep the historical early-stop behaviour.
            # Open-world callers pass 0 and require semantic completion instead.
            if max_steps > 0 and _legacy_supported(ledger):
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
                    blackboard=blackboard,
                ),
            )
        if _ledger_fingerprint(ledger) != before_reflection:
            # A reflection is useful only if its new/changed hypothesis is put
            # back through a discriminating read-only probe.  Continue until
            # the model concludes or it can offer no non-duplicate test.
            while True:
                remaining_budget = _budget_remaining(deadline_monotonic)
                if remaining_budget is not None and remaining_budget <= 0:
                    break
                verification = await _within_budget(
                    deadline_monotonic,
                    lambda ledger=ledger: complete_json(
                        settings,
                        system=(
                            "You are verifying a hypothesis introduced or changed during RCA reflection. "
                            "Do not promote a conclusion from reasoning alone. Select the strongest "
                            "read-only falsifier or discriminator, probe it, and cite F- observation IDs. "
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
                                blackboard=blackboard,
                            )
                        ),
                        model=settings.llm_model_investigation,
                    ),
                )
                if not isinstance(verification, dict):
                    break
                ledger = _apply_ledger_updates(ledger, verification.get("hypothesis_updates"))
                if verification.get("action") == "conclude":
                    break
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
                    if not isinstance(query, dict) or not str(query.get("kind") or "").strip():
                        continue
                    fingerprint = json.dumps(query, sort_keys=True, default=str)
                    if fingerprint not in seen_queries:
                        seen_queries.add(fingerprint)
                        wanted.append(query)
                if not fresh and not wanted:
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
                for query in wanted:
                    adhoc.append(
                        await _within_budget(
                            deadline_monotonic,
                            lambda query=query: k8s_read(
                                settings,
                                str(query.get("kind")),
                                namespace=str(query.get("namespace") or ""),
                                name=str(query.get("name") or ""),
                                label_selector=str(query.get("label_selector") or ""),
                            ),
                        )
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
            evidence[name] = result
            _record_blackboard(blackboard, name, result)
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
            markers = [] if error else salient_markers(item.get("data"))
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
                    title=kind_lookup_title(str(item.get("kind") or ""), language),
                    highlights=markers or None,
                    summary=summary,
                    result=item,
                )
            )
        _record_blackboard(blackboard, "kubernetes", kubernetes_result)

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
                plan, kg_context, evidence, by_name, ledger, adhoc, blackboard=blackboard
            )
        ),
        model=settings.llm_model_investigation,
    )
    if not isinstance(reflection, dict):
        return ledger
    ledger = _apply_ledger_updates(ledger, reflection.get("hypothesis_updates"))
    return _add_reflected_hypotheses(ledger, reflection.get("new_hypotheses"))


def _build_user_prompt(
    plan: InvestigationPlan | None,
    kg_context: dict,
    evidence: dict[str, CollectorResult],
    by_name: dict,
    ledger: list[dict[str, Any]],
    adhoc: list[dict] | None = None,
    *,
    blackboard: Any = None,
) -> str:
    stable = {
        "plan": plan.as_dict() if plan else {},
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
            "historical_case_cards": kg_context.get("case_cards") or [],
        },
        "available_collectors": {name: _COLLECTOR_HINTS.get(name, "") for name in by_name},
        "adhoc_query_kinds": sorted(_READ_KINDS),
    }
    variable = {
        "hypothesis_ledger": _ledger_summary(ledger),
        "evidence_so_far": _evidence_summary(evidence),
        "not_yet_probed": [name for name in by_name if name not in evidence],
        # The last few ad-hoc reads, trimmed — enough for the LLM to chain
        # "PVC is Pending -> check the storageclass" style drill-downs.
        "adhoc_results": _adhoc_prompt_results(adhoc),
        # Other evidence agents' findings are supplied as facts, not raw
        # transport/query text.  A domain agent can therefore test a CSI clue
        # in Loki/system without inheriting an unsafe executable query.
        "shared_observations": _blackboard_prompt_view(blackboard, limit=12),
    }
    return _capped_json_prompt(
        stable,
        variable,
        max_chars=_USER_PROMPT_CHARS,
        trim_keys=("evidence_so_far", "adhoc_results", "shared_observations"),
    )


def _record_blackboard(blackboard: Any, agent: str, result: CollectorResult | None) -> None:
    if blackboard is None or result is None:
        return
    for name in ("add_result", "add_collector_result"):
        method = getattr(blackboard, name, None)
        if callable(method):
            try:
                method(agent, result)
            except TypeError:
                method(result)
            except Exception:  # noqa: BLE001 - blackboard is advisory
                pass
            return


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
    text = json.dumps(payload, default=str)
    while len(text) > max_chars:
        for key in trim_keys:
            value = variable.get(key)
            if isinstance(value, list) and len(value) > 1:
                variable[key] = value[1:]
                payload = {**stable, **variable}
                text = json.dumps(payload, default=str)
                break
        else:
            break
    if len(text) <= max_chars:
        return text
    marker = '"...truncated older prompt context..."'
    tail = max_chars // 4
    head = max_chars - tail - len(marker)
    return text[:head] + marker + text[-tail:]


def _adhoc_prompt_results(adhoc: list[dict] | None) -> list[str]:
    return [
        json.dumps(
            {"query": _adhoc_query_repr(item), "error": "query failed"}
            if item.get("error")
            else item,
            default=str,
        )[:600]
        for item in (adhoc or [])[-6:]
    ]


def _investigator_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )
