"""Optional Run:ai evidence gathering via the runai-mcp server.

When RUNAI_MCP_URL is set, the Run:ai collector pulls its context through the
runai-mcp server's `call_runai_api` tool (426 Run:ai APIs, spec-aware, auto-authed
by the managed service) instead of the fixed curl endpoints. ANY failure — the mcp package
not installed, the service unreachable, a tool error, an unparseable result —
returns None so the caller falls back to the direct-HTTP collector. The MCP path is
strictly additive and never breaks analysis.

The runai-mcp server is stdio-only; deploy it behind a stdio->HTTP
bridge (e.g. mcp-proxy) and point RUNAI_MCP_URL at the bridge's streamable-HTTP
endpoint (http://localhost:<port>/mcp).
"""

from __future__ import annotations

from typing import Any

from app.collectors.base import AnalysisTarget
from app.config import Settings
from app.masking import build_masker
from app.mcp_client import mcp_error, mcp_tool_json, mcp_tool_text


async def gather_runai_via_mcp(
    settings: Settings, target: AnalysisTarget
) -> list[dict[str, Any]] | None:
    """Return query_results (same shape as the direct collector) via the MCP, or
    None to signal the caller to fall back to direct HTTP."""
    if not settings.runai_mcp_url:
        return None
    try:
        return await _gather(settings, target)
    except Exception:  # noqa: BLE001 - MCP is best-effort; never break the collector
        return None


async def _gather(settings: Settings, target: AnalysisTarget) -> list[dict[str, Any]] | None:
    # Lazy import so the agent runs without the `mcp` package until MCP is configured.
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    # Per query: ordered path CANDIDATES, first success wins. Run:ai moved the
    # org tree under /api/v1/org-unit/… (2.18+); older control planes still
    # serve the flat paths — a 404 on one shape must not lose the whole
    # context (the "projects/queues 404 — only workloads collected" runs).
    # departments/clusters ride along: queue fairshare needs the department,
    # and /clusters carries control-plane connectivity state.
    plan: list[tuple[str, str, list[str], dict | None]] = [
        ("workloads", "GET", [settings.runai_workloads_path], _workload_params(target)),
        (
            "projects",
            "GET",
            _dedup([settings.runai_projects_path, "/api/v1/org-unit/projects"]),
            None,
        ),
        ("departments", "GET", ["/api/v1/org-unit/departments", "/api/v1/departments"], None),
        ("queues", "GET", [settings.runai_queues_path], None),
        ("clusters", "GET", ["/api/v1/clusters"], None),
        ("version", "GET", [settings.runai_version_path], None),
    ]
    out: list[dict[str, Any]] = []
    async with streamablehttp_client(settings.runai_mcp_url) as (read, write, *_rest):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name, method, paths, params in plan:
                paths = [path for path in paths if path]
                if not paths:
                    continue
                out.append(await _call_api(session, name, method, paths, params))
    return out or None


def _dedup(paths: list[str]) -> list[str]:
    return list(dict.fromkeys(path for path in paths if path))


async def _call_api(
    session: Any, name: str, method: str, paths: list[str], params: dict | None
) -> dict[str, Any]:
    last: dict[str, Any] | None = None
    for path in paths:
        args: dict[str, Any] = {"method": method, "path": path}
        if params:
            args["query"] = params
        query = f"MCP call_runai_api {method} {path}"
        try:
            result = await session.call_tool("call_runai_api", args)
        except Exception as exc:  # noqa: BLE001 - per-query failure is an observation
            last = {
                "name": name,
                "query": query,
                "status_code": None,
                "error": _safe_text(f"{exc.__class__.__name__}: {exc}", limit=300),
                "data": None,
            }
            continue
        if getattr(result, "isError", False):
            last = {
                "name": name,
                "query": query,
                "status_code": None,
                "error": mcp_error(result),
                "data": None,
            }
            continue
        return {
            "name": name,
            "query": query,
            "status_code": 200,
            "error": None,
            "data": _tool_json(result),
        }
    return last or {"name": name, "query": name, "status_code": None,
                    "error": "no path configured", "data": None}


def _tool_text(result: Any) -> str:
    return mcp_tool_text(result)


def _tool_json(result: Any) -> Any:
    return mcp_tool_json(result)


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _workload_params(target: AnalysisTarget) -> dict[str, str] | None:
    params: dict[str, str] = {}
    if target.workload_name:
        params["name"] = target.workload_name
    if target.project:
        params["projectName"] = target.project
    return params or None
