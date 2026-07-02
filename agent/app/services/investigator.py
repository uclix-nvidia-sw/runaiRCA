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

from app.collectors.base import CollectorResult
from app.config import Settings
from app.llm import complete_json
from app.plan import InvestigationPlan

# What each collector is good for — fed to the LLM so it picks the right probe.
_COLLECTOR_HINTS = {
    "runai": "Run:ai control plane: workload/project/queue state, GPU quota.",
    "kubernetes": "Pod phases, warning events (OOM, evictions, image pulls), node conditions.",
    "postgres": "RCA memory / prior-incident evidence from the backend database.",
    "prometheus": "GPU/node/scheduling metrics, saturation, pending/unschedulable signals.",
    "loki": "Container and control-plane logs (crashes, errors, Xid, stack traces).",
    "system": "Node infra via the per-node agent: syslog/journalctl/dmesg, kernel/Xid.",
}


def _collector_name(collector: object) -> str:
    name = collector.__class__.__name__
    if name.endswith("Collector"):
        name = name[: -len("Collector")]
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return normalized.replace("_a_i", "ai") or "collector"


async def _collect_safely(
    collector: object, target: object, plan: object
) -> CollectorResult:
    # Mirror the orchestrator: a collector must never raise into the loop.
    try:
        return await collector.collect(target, plan)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - graceful degradation
        agent = _collector_name(collector)
        return CollectorResult(
            agent=agent,
            status="unavailable",
            summary=f"{agent} collector failed unexpectedly before returning evidence.",
            confidence="low",
            details={"error": f"{type(exc).__name__}: {exc}"},
            missing_data=[f"{agent}.collector_exception"],
            warnings=[f"{agent} failed unexpectedly: {type(exc).__name__}: {exc}"],
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
        workload=scope.get("workload") if isinstance(scope.get("workload"), str)
        else base.workload,
    )


def _evidence_summary(evidence: dict[str, CollectorResult]) -> list[dict]:
    return [
        {
            "collector": name,
            "status": r.status,
            "confidence": r.confidence,
            "summary": (r.summary or "")[:400],
        }
        for name, r in evidence.items()
    ]


async def investigate(
    settings: Settings,
    target: object,
    collectors: list,
    plan: InvestigationPlan | None,
    kg_context: dict,
    max_steps: int,
) -> list[CollectorResult]:
    by_name = {_collector_name(c): c for c in collectors}
    all_names = set(by_name)
    evidence: dict[str, CollectorResult] = {}

    async def run_probe(name: str, scope: dict) -> None:
        collector = by_name.get(name)
        if collector is None:
            return
        evidence[name] = await _collect_safely(
            collector, target, _scoped_plan(plan, scope)
        )

    try:
        for _ in range(max(1, max_steps)):
            if all_names <= set(evidence):
                break  # every collector already probed
            decision = await complete_json(
                settings,
                system=(
                    "You are a senior SRE investigating a Run:ai GPU-platform alert. "
                    "Given the plan, hypotheses, evidence so far, and the available "
                    "collectors, decide the next diagnostic step. Probe the collectors "
                    "most likely to confirm or refute a hypothesis; conclude once the "
                    "evidence is sufficient. Respond with ONLY JSON: "
                    '{"action":"probe"|"conclude","reason":str,'
                    '"probes":[{"collector":str,'
                    '"scope":{"namespace"?,"pod"?,"node"?,"workload"?}}]}'
                ),
                user=_build_user_prompt(plan, kg_context, evidence, by_name),
            )
            if not isinstance(decision, dict):
                break  # unusable response -> fall through to full gather
            if decision.get("action") == "conclude":
                break
            probes = decision.get("probes")
            if not isinstance(probes, list) or not probes:
                break
            fresh = [
                p
                for p in probes
                if isinstance(p, dict) and p.get("collector") in all_names
            ]
            if not fresh:
                break
            await asyncio.gather(
                *(
                    run_probe(p["collector"], p.get("scope") or {})
                    for p in fresh
                )
            )
    except Exception:  # noqa: BLE001 - never raise into analyze; keep whatever we have
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

    return list(evidence.values())


def _build_user_prompt(
    plan: InvestigationPlan | None,
    kg_context: dict,
    evidence: dict[str, CollectorResult],
    by_name: dict,
) -> str:
    payload = {
        "plan": plan.as_dict() if plan else {},
        "hypotheses": plan.hypotheses if plan else [],
        "knowledge_graph": {
            "blast_radius_workloads": kg_context.get("blast_radius_workloads"),
            "prior_incidents": kg_context.get("prior_incidents"),
        },
        "available_collectors": {
            name: _COLLECTOR_HINTS.get(name, "") for name in by_name
        },
        "evidence_so_far": _evidence_summary(evidence),
        "not_yet_probed": [name for name in by_name if name not in evidence],
    }
    return json.dumps(payload, default=str)[:8000]
