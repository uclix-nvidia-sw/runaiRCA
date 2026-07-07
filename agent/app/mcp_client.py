from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.masking import build_masker

_log = logging.getLogger(__name__)

MCP_FALLBACK_WARNING = "MCP unavailable; used direct API fallback"


def mcp_fallback_warning(exc: Exception) -> str:
    """Fallback warning that names the ACTUAL failure, not just the class.

    'MCP unavailable: RuntimeError' is undiagnosable from a report; keep the
    message (truncated) so the operator can see WHY MCP fell back to direct API.
    """
    detail = _safe_text(str(exc), limit=160)
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
            report[name] = f"unreachable: {type(exc).__name__}: {_safe_text(str(exc), limit=120)}"
        _log.info("mcp self-check %s (%s): %s", name, url, report[name])
    return report


def mcp_tool_text(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(build_masker(()).mask_text(text))
    return "\n".join(parts)


def mcp_tool_json(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        return _mask_object(structured)
    blob = mcp_tool_text(result).strip()
    if not blob:
        return {}
    try:
        return _mask_object(json.loads(blob))
    except (ValueError, TypeError):
        return {"raw": _safe_text(blob, limit=2000)}


def mcp_error(result: Any) -> str:
    if not getattr(result, "isError", False):
        return ""
    return _safe_text(mcp_tool_text(result), limit=300) or "MCP tool error"


def _mask_object(value: Any) -> Any:
    return build_masker(()).mask_object(value)


def _safe_text(value: str, *, limit: int) -> str:
    text = " ".join(build_masker(()).mask_text(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
