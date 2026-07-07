"""Agentic RCA chat: the copilot can query the live cluster (read-only) and run a
full RCA on demand — not just answer from the pre-loaded workspace context.

The operator can ask about anything on the platform ("what pods are pending in
runai?", "GPU pressure on node dgx01?", "analyze the runai-backend namespace"),
even when no incident/alert is loaded. The chat LLM runs a bounded ReAct loop:
each turn it either answers from what it has, fires read-only cluster queries, or
hands an arbitrary target to the same orchestrator RCA pipeline.

Reuses the drill-down tools (kubectl / PromQL / LogQL / Run:ai API / SQL) as a
flat registry (the chat is NOT domain-scoped like drill-down — the operator may
ask across domains). Read-only by construction: the tools are the same
allowlisted reads drill-down uses. Untrusted cluster text feeds the loop, so the
PROMPT_INJECTION_GUARD in app.llm rides every decision. Best-effort: any failure
returns (None, error) and chat() falls back to the grounded context answer.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

from app.collectors.base import AnalysisTarget, resolve_target
from app.config import Settings
from app.llm import (
    complete_json,
    complete_with_error,
    token_budget_exceeded,
    token_budget_warning,
)
from app.schemas import Alert, AlertAnalysisRequest, AlertAnalysisResponse, ChatRequest
from app.services.drilldown import _call_tool_safely, _domain_tools

_log = logging.getLogger(__name__)

_MAX_STEPS = 4
_MAX_QUERIES_PER_STEP = 3
_RESULT_CHARS = 1500

AnalyzeFn = Callable[[AlertAnalysisRequest], Awaitable[AlertAnalysisResponse]]


def _flat_tools(settings: Settings) -> dict[str, dict]:
    """All domains' read-only tools in one registry (chat is cross-domain)."""
    flat: dict[str, dict] = {}
    for agent_tools in _domain_tools(settings).values():
        flat.update(agent_tools)
    return flat


async def answer_chat(
    settings: Settings,
    request: ChatRequest,
    grounding: str,
    *,
    analyze_fn: AnalyzeFn,
) -> tuple[str | None, str | None]:
    """(answer, error). Bounded ReAct over read-only cluster tools + on-demand RCA.

    Never raises: on any failure returns (None, error) so chat() degrades to the
    grounded context answer.
    """
    question = (request.message or "").strip()
    if not question:
        return None, "empty question"
    try:
        tools = _flat_tools(settings)
        target = resolve_target({}, {})  # tools read their params from args, not target
        history: list[dict] = []
        for _ in range(_MAX_STEPS):
            if token_budget_exceeded(settings):
                history.append({"note": token_budget_warning(settings)})
                break
            decision = await complete_json(
                settings,
                system=_system_prompt(tools, settings),
                user=_user_prompt(grounding, question, history),
                model=settings.llm_model_chat,
            )
            if not isinstance(decision, dict):
                break
            action = str(decision.get("action") or "")
            if action == "answer":
                text = str(decision.get("answer") or "").strip()
                if text:
                    return text, None
                break
            if action == "query":
                await _run_queries(settings, tools, target, decision, history)
            elif action == "analyze":
                await _run_analysis(settings, analyze_fn, decision, history)
            else:
                break
        # Loop ended without a direct answer (or hit the step cap): synthesize a
        # final answer from the grounding + whatever the tools/analysis returned.
        return await _final_answer(settings, grounding, question, history)
    except Exception as exc:  # noqa: BLE001 - chat is best-effort; caller degrades
        _log.debug("agentic chat aborted", exc_info=True)
        return None, f"{exc.__class__.__name__}: {exc}"


async def _run_queries(
    settings: Settings,
    tools: dict[str, dict],
    target: AnalysisTarget,
    decision: dict,
    history: list[dict],
) -> None:
    queries = [
        q
        for q in (decision.get("queries") or [])
        if isinstance(q, dict) and str(q.get("tool") or "") in tools
    ][:_MAX_QUERIES_PER_STEP]
    for q in queries:
        name = str(q.get("tool"))
        args = q.get("args") if isinstance(q.get("args"), dict) else {}
        outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
        history.append(
            {
                "tool": name,
                "query": outcome.get("query") or name,
                "summary": outcome.get("summary") or outcome.get("error"),
                "result": json.dumps(outcome.get("result"), default=str)[:_RESULT_CHARS],
            }
        )


async def _run_analysis(
    settings: Settings,
    analyze_fn: AnalyzeFn,
    decision: dict,
    history: list[dict],
) -> None:
    spec = decision.get("target") if isinstance(decision.get("target"), dict) else {}
    labels = {
        key: str(spec.get(key))
        for key in ("namespace", "node", "pod", "workload", "project", "queue", "alertname")
        if spec.get(key)
    }
    if "workload" in labels:  # normalise to the label resolve_target understands
        labels.setdefault("workload_name", labels.pop("workload"))
    annotations = {"summary": str(spec.get("reason") or "operator-requested analysis")}
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels=labels, annotations=annotations),
        analysis_type="chat",
    )
    try:
        response = await analyze_fn(request)
    except Exception as exc:  # noqa: BLE001 - a failed analysis is an observation
        history.append(
            {"tool": "analyze", "target": spec, "error": f"{exc.__class__.__name__}: {exc}"}
        )
        return
    history.append(
        {
            "tool": "analyze",
            "target": spec,
            "summary": (response.analysis_summary or "")[:600],
            "result": (response.analysis_detail or "")[:_RESULT_CHARS],
        }
    )


async def _final_answer(
    settings: Settings, grounding: str, question: str, history: list[dict]
) -> tuple[str | None, str | None]:
    language_rule = (
        "반드시 한국어로 답변하세요."
        if getattr(settings, "language", "en") == "ko"
        else "Reply in the operator's language."
    )
    system = (
        "You are the RCA copilot for an NVIDIA Run:AI GPU platform. Answer the operator's "
        "question DIRECTLY and concisely using the grounded context and the tool/analysis "
        "results gathered below. Lead with the answer. Cite the concrete evidence you found "
        "(the actual kubectl/PromQL/LogQL query or the analysis verdict). If nothing "
        f"answered it, say so and suggest the next diagnostic step. {language_rule}"
    )
    tool_dump = json.dumps(history, ensure_ascii=False, default=str)[:6000] if history else "(none)"
    user = (
        f"Grounded context:\n{grounding}\n\n"
        f"Tool/analysis results:\n{tool_dump}\n\n"
        f"Question: {question}"
    )
    # complete_with_error (not complete) so an LLM failure surfaces its detail
    # (HTTP status, provider error) instead of a generic "no answer".
    text, error = await complete_with_error(
        settings,
        system=system,
        user=user,
        temperature=0.2,
        model=settings.llm_model_chat,
    )
    if text and text.strip():
        return text.strip(), None
    return None, error or "the chat agent produced no answer"


def _system_prompt(tools: dict[str, dict], settings: Settings) -> str:
    tool_lines = "\n".join(f"- {name}: {spec['description']}" for name, spec in tools.items())
    language_rule = (
        "answer 필드는 반드시 한국어로 작성하세요."
        if getattr(settings, "language", "en") == "ko"
        else "Write the answer field in the operator's language."
    )
    return (
        f"{language_rule}\n"
        "You are the RCA copilot for an NVIDIA Run:AI GPU platform. The operator can ask "
        "about ANYTHING on the cluster, not just a loaded incident. Each turn, choose ONE:\n"
        "- answer: you can already answer from the grounded context or prior tool results.\n"
        "- query: run READ-ONLY cluster queries to fetch live data you need.\n"
        "- analyze: run a full root-cause analysis for a target (heavier; use when the "
        "operator asks to investigate/analyze a namespace, node, or workload).\n"
        f"Read-only tools:\n{tool_lines}\n"
        "Prefer answering from context or a couple of targeted queries; only use analyze "
        "when a real investigation is asked for. Stop as soon as you can answer.\n"
        'Respond with ONLY JSON, one of:\n'
        '{"action":"answer","answer":str}\n'
        '{"action":"query","reason":str,"queries":[{"tool":str,"args":{...}}]}'
        f"  (at most {_MAX_QUERIES_PER_STEP} queries)\n"
        '{"action":"analyze","reason":str,"target":{"namespace"?:str,"node"?:str,'
        '"workload"?:str,"pod"?:str,"reason"?:str}}'
    )


def _user_prompt(grounding: str, question: str, history: list[dict]) -> str:
    payload = {
        "grounded_context": grounding[:4000],
        "gathered_so_far": history[-8:],
        "question": question,
    }
    return json.dumps(payload, ensure_ascii=False, default=str)[:8000]
