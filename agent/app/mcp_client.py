from __future__ import annotations

import json
from typing import Any

MCP_FALLBACK_WARNING = "MCP unavailable; used direct API fallback"


async def mcp_call(url: str, tool: str, arguments: dict[str, Any]) -> Any:
    """Call one tool on a streamable-HTTP MCP server."""
    if not url:
        raise RuntimeError("MCP URL is not configured")

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(url) as (read, write, *_rest):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(tool, arguments)


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
