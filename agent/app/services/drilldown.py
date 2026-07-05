"""Per-collector autonomous drill-down loops (LLM-gated, read-only).

Each evidence agent (kubernetes / prometheus / loki / runai) runs its OWN small
bounded LLM loop after the base gather: it looks at ITS OWN evidence and decides
follow-up read-only queries in ITS OWN domain. Tool scoping is structural — each
loop receives only its domain's tool registry, so the kubernetes loop cannot
call the Run:ai API and vice versa. Follow-up results are appended to the
collector's artifacts, where the existing pipeline (masking, signature matching,
the verify pass, synthesis) consumes them with zero changes.

Best-effort like the central investigation loop: flag off (ENABLE_AGENT_DRILLDOWN),
no LLM, or ANY failure -> the base evidence stands. Read-only by construction:
the k8s tool is the allowlisted `k8s_read`, Run:ai calls are locked to GET under
/api/, and PromQL/LogQL only hit query endpoints. Untrusted log/event text feeds
these loops, so the PROMPT_INJECTION_GUARD in app.llm rides on every decision.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import get_json
from app.collectors.kubernetes import _READ_KINDS, k8s_read
from app.collectors.loki import _loki_headers, _loki_streams, _sample_lines
from app.collectors.prometheus import prom_query
from app.collectors.runai_mcp import _tool_json, _tool_text
from app.config import Settings
from app.llm import complete_json, llm_configured
from app.plan import InvestigationPlan

_log = logging.getLogger(__name__)

_MAX_QUERIES_PER_STEP = 3
_RESULT_CHARS = 1500  # per-query result excerpt fed back into the loop
_USER_PROMPT_CHARS = 6000


async def run_drilldowns(
    settings: Settings,
    results: list[CollectorResult],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
) -> None:
    """Run every domain's drill-down loop concurrently. Never raises."""
    if not settings.enable_agent_drilldown or not llm_configured(settings):
        return
    registry = _domain_tools(settings)
    tasks = [
        _drill_one(settings, result, registry[result.agent], target, plan)
        for result in results
        if result.agent in registry and result.status != "unavailable"
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _drill_one(
    settings: Settings,
    result: CollectorResult,
    tools: dict[str, dict[str, Any]],
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
) -> None:
    """One agent's bounded think->query->observe loop over its own evidence."""
    try:
        history: list[dict[str, Any]] = []
        for _ in range(max(1, settings.drilldown_max_steps)):
            decision = await complete_json(
                settings,
                system=_system_prompt(result.agent, tools),
                user=_user_prompt(result, target, plan, history),
            )
            if not isinstance(decision, dict) or decision.get("action") != "query":
                break
            queries = [
                q
                for q in (decision.get("queries") or [])
                if isinstance(q, dict) and str(q.get("tool") or "") in tools
            ][:_MAX_QUERIES_PER_STEP]
            if not queries:
                break
            for q in queries:
                name = str(q.get("tool"))
                args = q.get("args") if isinstance(q.get("args"), dict) else {}
                outcome = await _call_tool_safely(tools[name]["call"], settings, target, args)
                history.append(
                    {
                        "tool": name,
                        "args": json.dumps(args, default=str)[:300],
                        "outcome": json.dumps(outcome, default=str)[:_RESULT_CHARS],
                    }
                )
                result.artifacts.append(
                    artifact(
                        agent=result.agent,
                        source=result.agent,
                        type="drilldown_query",
                        status="unavailable" if outcome.get("error") else "ok",
                        confidence="medium",
                        query=str(outcome.get("query") or name),
                        summary=str(outcome.get("summary") or outcome.get("error") or name),
                        result=outcome.get("result"),
                    )
                )
    except Exception:  # noqa: BLE001 - drill-down is best-effort; base evidence stands
        _log.debug("drill-down for %s aborted", result.agent, exc_info=True)


async def _call_tool_safely(
    call: Any, settings: Settings, target: AnalysisTarget, args: dict
) -> dict:
    try:
        outcome = await call(settings, target, args)
        return outcome if isinstance(outcome, dict) else {"error": "tool returned no result"}
    except Exception as exc:  # noqa: BLE001 - a failing query is an observation
        return {"error": f"{exc.__class__.__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Prompts


def _system_prompt(agent: str, tools: dict[str, dict[str, Any]]) -> str:
    tool_lines = "\n".join(f"- {name}: {spec['description']}" for name, spec in tools.items())
    return (
        f"You are the {agent} evidence agent for a Run:ai GPU-platform RCA, autonomously "
        "drilling deeper into YOUR domain only. Look at your evidence so far and decide "
        "whether one more round of READ-ONLY follow-up queries would materially confirm or "
        "refute the investigation's hypotheses. Prefer narrowing: one pod, one namespace, "
        "one resource, a tighter filter. Conclude (action=done) as soon as the evidence is "
        "sufficient — never query for completeness.\n"
        f"Tools available to you (your only tools; there are no others):\n{tool_lines}\n"
        'Respond with ONLY JSON: {"action":"query"|"done","reason":str,'
        '"queries":[{"tool":str,"args":{...}}]} with at most '
        f"{_MAX_QUERIES_PER_STEP} queries per step."
    )


def _user_prompt(
    result: CollectorResult,
    target: AnalysisTarget,
    plan: InvestigationPlan | None,
    history: list[dict[str, Any]],
) -> str:
    plan_dict = plan.as_dict() if plan else {}
    payload = {
        "target": {
            key: getattr(target, key, "")
            for key in ("namespace", "workload_name", "pod", "node", "project")
        },
        "plan_focus": plan_dict.get("focus"),
        "hypotheses": (plan_dict.get("hypotheses") or [])[:4],
        "my_summary": (result.summary or "")[:1200],
        "my_artifacts": [
            {"type": art.type, "summary": (art.summary or "")[:300]}
            for art in result.artifacts[-8:]
        ],
        "drilldown_so_far": history[-8:],
    }
    return json.dumps(payload, default=str)[:_USER_PROMPT_CHARS]


# ---------------------------------------------------------------------------
# Domain tools. Each: async (settings, target, args) -> {query, summary, error?, result?}


def _domain_tools(settings: Settings) -> dict[str, dict[str, dict[str, Any]]]:
    """Per-agent tool registries — THE scoping boundary between domains."""
    registry: dict[str, dict[str, dict[str, Any]]] = {
        "kubernetes": {
            "k8s_read": {
                "description": (
                    "Read-only get/list of one Kubernetes kind. args: "
                    f"kind (one of: {', '.join(sorted(_READ_KINDS))}), "
                    "namespace?, name?, label_selector?"
                ),
                "call": _tool_k8s_read,
            }
        }
    }
    if settings.prometheus_url:
        registry["prometheus"] = {
            "promql_query": {
                "description": (
                    "One PromQL instant query against the cluster Prometheus. args: "
                    "query (PromQL, e.g. 'rate(kube_pod_container_status_restarts_"
                    'total{namespace="x"}[15m])\')'
                ),
                "call": _tool_promql,
            }
        }
    if settings.loki_url:
        registry["loki"] = {
            "logql_query": {
                "description": (
                    "One LogQL range query against Loki (recent window, backward). "
                    'args: query (LogQL, e.g. \'{namespace="runai"} |~ "(?i)(error|panic)"\')'
                ),
                "call": _tool_logql,
            }
        }
    if settings.runai_mcp_url:
        registry["runai"] = {
            "runai_api_search": {
                "description": (
                    "Find Run:ai REST API operations by keyword (BM25 over the full "
                    "OpenAPI spec, 426 operations). args: query (keywords, e.g. "
                    "'workload events history')"
                ),
                "call": _tool_runai_search,
            },
            "runai_api_get": {
                "description": (
                    "Call one Run:ai REST API operation — GET ONLY, path must start "
                    "with /api/. args: path (e.g. '/api/v1/workloads'), query? "
                    "(param map, e.g. {'name': 'job-1'})"
                ),
                "call": _tool_runai_get,
            },
        }
    return registry


async def _tool_k8s_read(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    item = await k8s_read(
        settings,
        str(args.get("kind") or ""),
        namespace=str(args.get("namespace") or ""),
        name=str(args.get("name") or ""),
        label_selector=str(args.get("label_selector") or ""),
    )
    error = item.get("error")
    return {
        "query": f"k8s_read {args.get('kind')} ns={args.get('namespace') or '-'}",
        "summary": (
            str(error)
            if error
            else f"read {item.get('kind')} returned HTTP {item.get('status_code')}"
        ),
        "error": error,
        "result": item,
    }


async def _tool_promql(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    promql = " ".join(str(args.get("query") or "").split())[:600]
    if not promql:
        return {"query": "", "summary": "empty PromQL query", "error": "empty PromQL query"}
    item = await prom_query(settings, "drilldown", promql)
    error = item.get("error")
    return {
        "query": promql,
        "summary": str(error) if error else f"promql returned HTTP {item.get('status_code')}",
        "error": error,
        "result": item,
    }


async def _tool_logql(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    logql = " ".join(str(args.get("query") or "").split())[:600]
    if not logql:
        return {"query": "", "summary": "empty LogQL query", "error": "empty LogQL query"}
    headers, _warnings = _loki_headers(settings)
    response = await get_json(
        base_url=settings.loki_url,
        path="/loki/api/v1/query_range",
        timeout_seconds=settings.loki_timeout_seconds,
        params={
            "query": logql,
            "limit": str(settings.loki_query_limit),
            "direction": "BACKWARD",
        },
        headers=headers,
    )
    if response.error or not response.ok:
        error = response.error or f"HTTP {response.status_code}"
        return {"query": logql, "summary": error, "error": error}
    lines = _sample_lines(_loki_streams(response.data), limit=10)
    return {
        "query": logql,
        "summary": f"{len(lines)} sample log line(s)" if lines else "no matching log lines",
        "error": None,
        "result": {"lines": lines},
    }


async def _mcp_call(settings: Settings, tool: str, arguments: dict) -> Any:
    # Lazy import mirrors app.collectors.runai_mcp: the agent runs without the
    # `mcp` package until the sidecar ships.
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(settings.runai_mcp_url) as (read, write, *_rest):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool, arguments)


async def _tool_runai_search(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    query = " ".join(str(args.get("query") or "").split())[:200]
    if not query:
        return {"query": "", "summary": "empty search query", "error": "empty search query"}
    result = await _mcp_call(settings, "search_runai_api_spec", {"query": query})
    text = _tool_text(result)[:_RESULT_CHARS]
    if getattr(result, "isError", False):
        return {"query": query, "summary": text or "tool error", "error": text or "tool error"}
    return {
        "query": f"runai_api_search {query}",
        "summary": "spec search ok",
        "error": None,
        "result": text,
    }


async def _tool_runai_get(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    path = str(args.get("path") or "").strip()
    # GET-only under /api/ regardless of what the LLM asks for — the drill-down
    # must never mutate Run:ai state or reach non-API routes.
    if not path.startswith("/api/"):
        error = "only GET requests under /api/ are allowed"
        return {"query": path, "summary": error, "error": error}
    raw_params = args.get("query") if isinstance(args.get("query"), dict) else {}
    params = {str(k)[:60]: str(v)[:120] for k, v in list(raw_params.items())[:8] if str(k).strip()}
    arguments: dict[str, Any] = {"method": "GET", "path": path[:300]}
    if params:
        arguments["query"] = params
    result = await _mcp_call(settings, "call_runai_api", arguments)
    query = f"GET {path}"
    if getattr(result, "isError", False):
        error = _tool_text(result)[:300] or "tool error"
        return {"query": query, "summary": error, "error": error}
    return {
        "query": query,
        "summary": f"GET {path} ok",
        "error": None,
        "result": _tool_json(result),
    }
