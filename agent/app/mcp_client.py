from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

_log = logging.getLogger(__name__)

MCP_FALLBACK_WARNING = "MCP unavailable; used direct API fallback"


def mcp_fallback_warning(exc: Exception) -> str:
    """Fallback warning that names the ACTUAL failure, not just the class.

    'MCP unavailable: RuntimeError' is undiagnosable from a report; keep the
    message (truncated) so the operator can see WHY MCP fell back to direct API.
    """
    detail = " ".join(str(exc).split())[:160]
    label = f"{MCP_FALLBACK_WARNING}: {type(exc).__name__}"
    return f"{label}: {detail}" if detail else label


async def mcp_call(url: str, tool: str, arguments: dict[str, Any]) -> Any:
    """Call one tool on a streamable-HTTP MCP server.

    One retry on ANY failure: each call opens a fresh session, so a transient
    hiccup (service restarting, connection reset) used to demote the WHOLE
    collector run to the direct-API fallback. MCP is the preferred transport —
    give it a second chance before giving up."""
    if not url:
        raise RuntimeError("MCP URL is not configured")

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    for attempt in range(2):
        try:
            async with streamablehttp_client(url) as (read, write, *_rest):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(tool, arguments)
        except Exception:
            if attempt:
                raise
            await asyncio.sleep(0.5)


async def mcp_reachability(urls: dict[str, str]) -> dict[str, str]:
    """{name: 'ok (N tools)' | error} for each configured MCP URL.

    Startup answer to "are the agents actually on MCP?" — one tools/list per
    service, logged so a mis-wired URL is visible immediately, not mid-analysis."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    report: dict[str, str] = {}
    for name, url in urls.items():
        if not url:
            continue
        try:
            async with streamablehttp_client(url) as (read, write, *_rest):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    report[name] = f"ok ({len(tools.tools)} tools)"
        except Exception as exc:  # noqa: BLE001 - reachability is a report, not a gate
            report[name] = f"unreachable: {type(exc).__name__}: {str(exc)[:120]}"
        _log.info("mcp self-check %s (%s): %s", name, url, report[name])
    return report


def mcp_tool_text(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def mcp_tool_json(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured
    blob = mcp_tool_text(result).strip()
    if not blob:
        return {}
    try:
        return json.loads(blob)
    except (ValueError, TypeError):
        return {"raw": blob[:2000]}


def mcp_error(result: Any) -> str:
    if not getattr(result, "isError", False):
        return ""
    return mcp_tool_text(result)[:300] or "MCP tool error"
