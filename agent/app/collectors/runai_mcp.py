"""Read-only Run:ai evidence gathering through NVIDIA's official MCP server.

The official ``nvcr.io/nvidia/runai/runai-mcp-server`` exposes focused Run:ai
tools over authenticated streamable HTTP.  It is deliberately *not* an OpenAPI
proxy: callers must use its supported workload, resource, cluster, and identity
tools rather than issuing arbitrary API paths.  Every request carries the
existing Run:ai bearer token (obtained from ``RUNAI_BEARER_TOKEN`` or client
credentials) because the server protects its ``/mcp`` endpoint with OIDC.

MCP remains additive.  An unavailable service, token, or unsupported response
returns ``None`` and the collector falls back to its direct HTTP reads.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.collectors.base import AnalysisTarget
from app.config import Settings
from app.masking import build_masker
from app.mcp_client import mcp_call, mcp_error, mcp_tool_json, mcp_tool_text


async def gather_runai_via_mcp(
    settings: Settings, target: AnalysisTarget, *, headers: dict[str, str]
) -> list[dict[str, Any]] | None:
    """Return official-MCP query results, or ``None`` for direct-HTTP fallback."""
    if not settings.runai_mcp_url:
        return None
    if not headers.get("Authorization"):
        # The official HTTP transport rejects unauthenticated MCP sessions.
        return None
    try:
        return await _gather(settings, target, headers=headers)
    except Exception:  # noqa: BLE001 - MCP is best-effort; never break analysis
        return None


async def _gather(
    settings: Settings, target: AnalysisTarget, *, headers: dict[str, str]
) -> list[dict[str, Any]]:
    # These are the read-only tools shipped by NVIDIA Run:ai MCP 2.26.13.  Keep
    # requests narrowly scoped to alert labels; in particular, do not recreate
    # the former generic ``call_runai_api`` proxy over this trusted server.
    plan: list[tuple[str, str, dict[str, str]]] = [
        ("workloads", "get_workloads_summary", _workload_summary_args(target)),
        ("identity", "whoami", {}),
        ("node_pools", "list_node_pools", {}),
    ]
    if valid_official_workload_id(target.runai_workload_id):
        plan.insert(
            1,
            ("workload_status", "get_workload_status", {"workloadId": target.runai_workload_id}),
        )
    if target.project:
        plan.append(
            ("project_resources", "list_project_resources", {"projectName": target.project})
        )

    return [
        await _call_tool(settings, name, tool, arguments, headers=headers)
        for name, tool, arguments in plan
    ]


async def _call_tool(
    settings: Settings,
    name: str,
    tool: str,
    arguments: dict[str, str],
    *,
    headers: dict[str, str],
) -> dict[str, Any]:
    query = f"MCP {tool}" + (f" {arguments}" if arguments else "")
    try:
        result = await mcp_call(settings.runai_mcp_url, tool, arguments, headers=headers)
    except Exception as exc:  # noqa: BLE001 - per-tool failure is evidence
        return {
            "name": name,
            "query": query,
            "transport": "mcp",
            "status_code": None,
            "error": _safe_text(f"{exc.__class__.__name__}: {exc}", limit=300),
            "data": None,
        }
    if getattr(result, "isError", False):
        return {
            "name": name,
            "query": query,
            "transport": "mcp",
            "status_code": None,
            "error": mcp_error(result),
            "data": None,
        }
    return {
        "name": name,
        "query": query,
        "transport": "mcp",
        "status_code": 200,
        "error": None,
        "data": _tool_json(result),
    }


def _tool_text(result: Any) -> str:
    return mcp_tool_text(result)


def _tool_json(result: Any) -> Any:
    return mcp_tool_json(result)


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _workload_summary_args(target: AnalysisTarget) -> dict[str, str]:
    # NVIDIA's summary tool scopes an organization with the paired
    # ``orgType``/``orgName`` fields. A workload name is not globally unique,
    # so keep the project boundary when available rather than pretending a
    # name-only lookup is scoped evidence.
    return (
        {"orgType": "project", "orgName": target.project}
        if target.project
        else {}
    )


def valid_official_workload_id(value: str) -> bool:
    """Whether a label can satisfy the official MCP's UUID workload schema."""
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError):
        return False
    return True
