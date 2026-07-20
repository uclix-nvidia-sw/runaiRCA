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
from app.llm import complete_json, complete_with_error
from app.masking import build_masker
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


def _chat_target(request: ChatRequest) -> AnalysisTarget:
    """Default drill-down scope = the loaded incident/alert's target (forwarded by
    the backend as context['target']). So a `query` the LLM fires without repeating
    pod/namespace/node still lands on the incident's own resources instead of an
    empty target. Empty (cluster-wide) when no alert target is in scope."""
    ctx = request.context or {}
    tgt = ctx.get("target") if isinstance(ctx.get("target"), dict) else {}
    labels = tgt.get("labels") if isinstance(tgt.get("labels"), dict) else {}
    annotations = tgt.get("annotations") if isinstance(tgt.get("annotations"), dict) else {}
    return resolve_target(
        {str(k): str(v) for k, v in labels.items() if v is not None},
        {str(k): str(v) for k, v in (annotations or {}).items() if v is not None},
    )


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
    masker = _chat_masker(settings)
    question = masker.mask_text(question)
    grounding = masker.mask_text(grounding)
    try:
        tools = _flat_tools(settings)
        if "promql_query" not in tools:
            # No live-metric tool in the registry, so metric questions (CPU
            # throttling, saturation, memory pressure) can only get conditional
            # guidance. Warn once so a missing Prometheus config is visible.
            _log.warning("chat: promql_query tool not registered — Prometheus not configured for the agent?")
        # Default drill-down scope = the loaded incident's target, so the copilot's
        # own queries reach the incident's pod/namespace/node without the LLM having
        # to restate them (they were empty before, so scoped queries silently missed).
        target = _chat_target(request)
        cluster_scope = _is_cluster_scope(request)
        history: list[dict] = []
        for step in range(_MAX_STEPS):
            safe_history = masker.mask_object(history)
            if not isinstance(safe_history, list):
                safe_history = []
            decision = await complete_json(
                settings,
                system=_system_prompt(tools, settings, cluster_scope=cluster_scope, target=target),
                user=_user_prompt(grounding, question, safe_history),
                model=settings.llm_model_chat,
            )
            if not isinstance(decision, dict):
                # The decision LLM returned nothing parseable as JSON (transport
                # failure or a model that ignored the JSON-only instruction). No
                # query fires; the loop degrades to the grounded final answer.
                _log.warning("chat step %d: no parseable decision JSON from LLM — loop ended without querying", step)
                break
            action = str(decision.get("action") or "")
            if action == "answer":
                text = str(decision.get("answer") or "").strip()
                if text:
                    return masker.mask_text(text), None
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
        return None, masker.mask_text(f"{exc.__class__.__name__}: {exc}")


async def _run_queries(
    settings: Settings,
    tools: dict[str, dict],
    target: AnalysisTarget,
    decision: dict,
    history: list[dict],
) -> None:
    requested = [q for q in (decision.get("queries") or []) if isinstance(q, dict)]
    dropped = sorted({str(q.get("tool") or "?") for q in requested if str(q.get("tool") or "") not in tools})
    if dropped:
        # The model asked for tool names that aren't in the registry (hallucinated
        # or a domain that isn't configured). Naming them makes "it ran nothing"
        # legible instead of a silent no-op.
        _log.warning("chat query: dropped %d unknown tool(s): %s", len(dropped), ", ".join(dropped)[:200])
    queries = [q for q in requested if str(q.get("tool") or "") in tools][:_MAX_QUERIES_PER_STEP]
    for q in queries:
        name = str(q.get("tool"))
        args = q.get("args") if isinstance(q.get("args"), dict) else {}
        outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
        outcome = _chat_masker(settings).mask_object(outcome)
        if not isinstance(outcome, dict):
            outcome = {"error": "tool returned no result"}
        error = outcome.get("error")
        if error:
            _log.warning("chat query failed: tool=%s error=%s", name, error)
        history.append(
            {
                "tool": name,
                "query": outcome.get("query") or name,
                "summary": "query failed" if error else outcome.get("summary"),
                "result": ""
                if error
                else json.dumps(outcome.get("result"), default=str)[:_RESULT_CHARS],
            }
        )


async def _run_analysis(
    settings: Settings,
    analyze_fn: AnalyzeFn,
    decision: dict,
    history: list[dict],
) -> None:
    masker = _chat_masker(settings)
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
        detail = masker.mask_text(f"{exc.__class__.__name__}: {exc}")
        _log.warning("chat analyze failed: %s", detail)
        history.append(
            {
                "tool": "analyze",
                "target": masker.mask_object(spec),
                "error": detail,
            }
        )
        return
    history.append(
        {
            "tool": "analyze",
            "target": masker.mask_object(spec),
            "summary": masker.mask_text((response.analysis_summary or "")[:600]),
            "result": masker.mask_text((response.analysis_detail or "")[:_RESULT_CHARS]),
        }
    )


async def _final_answer(
    settings: Settings, grounding: str, question: str, history: list[dict]
) -> tuple[str | None, str | None]:
    masker = _chat_masker(settings)
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
        "answered it, say so and suggest the next diagnostic step. When there is no current "
        "incident evidence, you may give general troubleshooting guidance, but clearly label "
        "it as conditional and do not state that a cause is present or a fix succeeded. "
        f"{language_rule}"
    )
    safe_history = masker.mask_object(history)
    tool_dump = (
        json.dumps(safe_history, ensure_ascii=False, default=str)[:6000]
        if safe_history
        else "(none)"
    )
    user = (
        f"Grounded context:\n{masker.mask_text(grounding)}\n\n"
        f"Tool/analysis results:\n{tool_dump}\n\n"
        f"Question: {masker.mask_text(question)}"
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
        return masker.mask_text(text.strip()), None
    return None, masker.mask_text(error or "the chat agent produced no answer")


def _chat_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _is_cluster_scope(request: ChatRequest) -> bool:
    """True when the conversation has no incident/alert context — the operator is
    deliberately asking about the whole live cluster (backend sets scope=cluster)."""
    context = request.context if isinstance(request.context, dict) else {}
    scope = str(context.get("scope") or "").strip().lower()
    if scope:
        return scope == "cluster"
    return not (
        request.incident_id
        or request.alert_id
        or context.get("incident")
        or context.get("alert")
    )


def _system_prompt(
    tools: dict[str, dict],
    settings: Settings,
    *,
    cluster_scope: bool = False,
    target: AnalysisTarget | None = None,
) -> str:
    tool_lines = "\n".join(f"- {name}: {spec['description']}" for name, spec in tools.items())
    language_rule = (
        "answer 필드는 반드시 한국어로 작성하세요."
        if getattr(settings, "language", "en") == "ko"
        else "Write the answer field in the operator's language."
    )
    scope_rule = (
        "NO incident/alert context is selected: the operator is asking about the live "
        "cluster as a whole. The dashboard_state numbers in the grounded context are the "
        "RCA backend's alert/analysis history, NOT live cluster inventory — never present "
        "them as node/pod/workload state. Fetch any cluster fact with a query THIS turn.\n"
        if cluster_scope
        else ""
    )
    target_rule = ""
    if target is not None and not cluster_scope:
        scope_bits = [
            f"{key}={value}"
            for key, value in (
                ("namespace", target.namespace),
                ("pod", target.pod),
                ("node", target.node),
                ("workload", target.workload_name),
            )
            if value
        ]
        if scope_bits:
            target_rule = (
                "The loaded incident's target is " + ", ".join(scope_bits) + ". Read-only "
                "queries and analyze default to this scope when you omit those args — pass "
                "them only to investigate something else.\n"
            )
    return (
        f"{language_rule}\n"
        f"{scope_rule}"
        f"{target_rule}"
        "You are the RCA copilot for an NVIDIA Run:AI GPU platform. The operator can ask "
        "about ANYTHING on the cluster, not just a loaded incident. Each turn, choose ONE:\n"
        "- answer: you can already answer from the grounded context or prior tool results.\n"
        "- query: run READ-ONLY cluster queries to fetch live data you need.\n"
        "- analyze: run a full root-cause analysis for a target (heavier; use when the "
        "operator asks to investigate/analyze a namespace, node, or workload).\n"
        f"Read-only tools:\n{tool_lines}\n"
        "For questions about the CURRENT state of the cluster — how many nodes/pods, "
        "what is running, live metrics (CPU throttling, memory, GPU), what is failing "
        "right now — you MUST fetch it with a query (or analyze) THIS turn before you "
        "answer. NEVER assert a cluster fact (a node/pod count, a status, a metric "
        "value) that a tool result this turn did not give you, and never hand the "
        "operator a query you could run yourself. Answer directly only when the grounded "
        "context or a prior tool result already contains the answer; use analyze for a "
        "real root-cause investigation of a target.\n"
        "When a tool genuinely returns no evidence, say what you ran and label any "
        "remaining guidance as general and conditional; never claim a cause is present "
        "or a remediation succeeded.\n"
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
