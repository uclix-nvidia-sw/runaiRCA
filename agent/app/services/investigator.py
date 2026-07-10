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
from dataclasses import replace
from typing import Any

from app.collectors.base import CollectorResult, artifact, salient_markers, signals_line
from app.collectors.kubernetes import _READ_KINDS, k8s_read, kind_lookup_title, kubectl_repr
from app.config import Settings
from app.llm import complete_json, token_budget_exceeded, token_budget_warning
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter

# Ad-hoc kubectl-style reads per step are capped so a chatty LLM can't turn one
# investigation into an API-server sweep.
_MAX_QUERIES_PER_STEP = 4
_MAX_HYPOTHESES = 8
_CONFIDENT_STOP = 0.80
_CONFIDENT_GAP = 0.25
_LEDGER_STATUSES = {"open", "testing", "supported", "refuted", "uncertain"}
_USER_PROMPT_CHARS = 8000

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
    for idx, item in enumerate(hypotheses[:_MAX_HYPOTHESES], start=1):
        if not isinstance(item, dict):
            continue
        family = str(item.get("family") or "").strip()
        if not family:
            continue
        reason = str(item.get("reason") or "").strip()
        ledger.append(
            {
                "id": f"H{idx}",
                "family": family,
                "statement": reason or family.replace("_", " "),
                "confidence": 0.5,
                "evidence_for": [],
                "evidence_against": [],
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
            "confidence": item.get("confidence"),
            "status": item.get("status"),
            "evidence_for": item.get("evidence_for", [])[-3:],
            "evidence_against": item.get("evidence_against", [])[-3:],
        }
        for item in ledger
    ]


def _apply_ledger_updates(
    ledger: list[dict[str, Any]], updates: object
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
        if status in _LEDGER_STATUSES:
            item["status"] = status
        _extend_text_list(item, "evidence_for", update.get("evidence_for"))
        _extend_text_list(item, "evidence_against", update.get("evidence_against"))
    return ledger


def _add_reflected_hypotheses(
    ledger: list[dict[str, Any]], candidates: object
) -> list[dict[str, Any]]:
    if not isinstance(candidates, list):
        return ledger
    existing = {str(item.get("family")) for item in ledger}
    for candidate in candidates:
        if len(ledger) >= _MAX_HYPOTHESES:
            break
        if not isinstance(candidate, dict):
            continue
        family = str(candidate.get("family") or "").strip()
        if not family or family in existing:
            continue
        statement = str(candidate.get("statement") or candidate.get("reason") or "").strip()
        ledger.append(
            {
                "id": f"H{len(ledger) + 1}",
                "family": family,
                "statement": statement or family.replace("_", " "),
                "confidence": _clamp_confidence(candidate.get("confidence"), 0.4),
                "evidence_for": _texts(candidate.get("evidence_for"))[:5],
                "evidence_against": _texts(candidate.get("evidence_against"))[:5],
                "status": str(candidate.get("status") or "open")
                if str(candidate.get("status") or "open") in _LEDGER_STATUSES
                else "open",
            }
        )
        existing.add(family)
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


def _clamp_confidence(value: object, fallback: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        try:
            number = float(fallback)
        except (TypeError, ValueError):
            number = 0.5
    return max(0.0, min(1.0, number))


def _confident_enough(ledger: list[dict[str, Any]]) -> bool:
    scores = sorted(
        (
            _clamp_confidence(item.get("confidence"), 0)
            for item in ledger
            if item.get("status") != "refuted"
        ),
        reverse=True,
    )
    if not scores or scores[0] < _CONFIDENT_STOP:
        return False
    runner_up = scores[1] if len(scores) > 1 else 0.0
    return scores[0] - runner_up >= _CONFIDENT_GAP


async def investigate(
    settings: Settings,
    target: object,
    collectors: list,
    plan: InvestigationPlan | None,
    kg_context: dict,
    max_steps: int,
    reporter: ProgressReporter | None = None,
) -> tuple[list[CollectorResult], dict[str, Any]]:
    by_name = {_collector_name(c): c for c in collectors}
    all_names = set(by_name)
    evidence: dict[str, CollectorResult] = {}
    ledger = _initial_ledger(plan)
    investigation_steps: list[dict[str, Any]] = []

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
        result = await _collect_safely(collector, target, _scoped_plan(plan, scope))
        evidence[name] = result
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
    budget_warning = ""
    try:
        ran_queries_last_step = False
        for step in range(max(1, max_steps)):
            if token_budget_exceeded(settings):
                budget_warning = token_budget_warning(settings)
                break
            if all_names <= set(evidence) and not ran_queries_last_step:
                break  # every collector probed and no ad-hoc drill-down pending
            if reporter:
                reporter.emit(
                    "investigation",
                    "Choosing next diagnostic step",
                    step=step + 1,
                    hypothesis_ledger=_ledger_summary(ledger),
                )
            decision = await complete_json(
                settings,
                system=(
                    "You are a senior SRE investigating a Run:ai GPU-platform alert. "
                    "Given the plan, hypothesis ledger, evidence so far, and available "
                    "collectors, decide the next diagnostic step. Pick the hypothesis "
                    "you are testing, probe collectors most likely to confirm/refute it, "
                    "and use plan.diagnostic_directive as neutral ontology guidance: "
                    "follow its checks and disconfirmations, but never treat its "
                    "provisional_family as observed evidence. Update confidence using "
                    "only observed evidence. You can ALSO "
                    "run kubectl-style READ-ONLY Kubernetes queries (get/list of an "
                    "allowlisted kind, see adhoc_query_kinds). Conclude once evidence "
                    "is sufficient. Respond with ONLY JSON: "
                    '{"action":"probe"|"conclude","reason":str,'
                    '"selected_hypothesis":str,'
                    '"probes":[{"collector":str,'
                    '"scope":{"namespace"?,"pod"?,"node"?,"workload"?}}],'
                    '"queries":[{"kind":str,"namespace"?,"name"?,"label_selector"?}],'
                    '"hypothesis_updates":[{"id":str,"confidence":number,'
                    '"evidence_for":[str],"evidence_against":[str],'
                    '"status":"open|testing|supported|refuted|uncertain"}]}'
                ),
                user=_investigator_masker(settings).mask_text(
                    _build_user_prompt(plan, kg_context, evidence, by_name, ledger, adhoc)
                ),
                model=settings.llm_model_investigation,
            )
            if not isinstance(decision, dict):
                break  # unusable response -> fall through to full gather
            ledger = _apply_ledger_updates(ledger, decision.get("hypothesis_updates"))
            investigation_steps.append(
                {
                    "step": step + 1,
                    "action": str(decision.get("action") or ""),
                    "reason": str(decision.get("reason") or "")[:300],
                    "selected_hypothesis": str(decision.get("selected_hypothesis") or ""),
                }
            )
            if reporter:
                reporter.emit(
                    "investigation",
                    str(decision.get("reason") or "Diagnostic step selected")[:300],
                    step=step + 1,
                    action=str(decision.get("action") or ""),
                    selected_hypothesis=str(decision.get("selected_hypothesis") or ""),
                    hypothesis_ledger=_ledger_summary(ledger),
                )
            if decision.get("action") == "conclude":
                break
            probes = decision.get("probes")
            queries = decision.get("queries")
            fresh = [
                p
                for p in (probes if isinstance(probes, list) else [])
                if isinstance(p, dict) and p.get("collector") in all_names
            ]
            wanted = [
                q
                for q in (queries if isinstance(queries, list) else [])
                if isinstance(q, dict) and str(q.get("kind") or "").strip()
            ][:_MAX_QUERIES_PER_STEP]
            if not fresh and not wanted:
                break
            if fresh:
                await asyncio.gather(
                    *(run_probe(p["collector"], p.get("scope") or {}) for p in fresh)
                )
            for q in wanted:
                if reporter:
                    reporter.emit(
                        "investigation",
                        f"Running {_adhoc_query_repr(q)}",
                        step=step + 1,
                        query=_adhoc_query_repr(q),
                    )
                adhoc.append(
                    await k8s_read(
                        settings,
                        str(q.get("kind")),
                        namespace=str(q.get("namespace") or ""),
                        name=str(q.get("name") or ""),
                        label_selector=str(q.get("label_selector") or ""),
                    )
                )
            ran_queries_last_step = bool(wanted)
            if _confident_enough(ledger):
                break
    except Exception:  # noqa: BLE001 - never raise into analyze; keep whatever we have
        pass

    try:
        ledger = await _reflect_hypotheses(
            settings, plan, kg_context, evidence, by_name, ledger, adhoc
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
        try:
            results = await asyncio.gather(
                *(_collect_safely(by_name[name], target, plan) for name in remaining)
            )
            for name, result in zip(remaining, results, strict=True):
                evidence[name] = result
        except Exception:  # noqa: BLE001 - last-resort guard
            pass

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

    results = list(evidence.values())
    if budget_warning and results:
        results[0].warnings.append(budget_warning)
    context = {
        "hypothesis_ledger": _ledger_summary(ledger),
        "investigation_steps": investigation_steps,
        "adhoc_query_count": len(adhoc),
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
) -> list[dict[str, Any]]:
    if token_budget_exceeded(settings):
        return ledger
    reflection = await complete_json(
        settings,
        system=(
            "You are doing one final skeptical reflection before concluding an RCA "
            "investigation. Look for a missed hypothesis, contradiction, or weakly "
            "supported confidence. Do not invent evidence. Respond with ONLY JSON: "
            '{"hypothesis_updates":[{"id":str,"confidence":number,'
            '"evidence_for":[str],"evidence_against":[str],'
            '"status":"open|testing|supported|refuted|uncertain"}],'
            '"new_hypotheses":[{"family":str,"statement":str,"confidence":number,'
            '"evidence_for":[str],"evidence_against":[str],"status":str}]}'
        ),
        user=_investigator_masker(settings).mask_text(
            _build_user_prompt(plan, kg_context, evidence, by_name, ledger, adhoc)
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
) -> str:
    stable = {
        "plan": plan.as_dict() if plan else {},
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
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
    }
    return _capped_json_prompt(
        stable,
        variable,
        max_chars=_USER_PROMPT_CHARS,
        trim_keys=("evidence_so_far", "adhoc_results"),
    )


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
