from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx

from app.masking import build_masker

_log = logging.getLogger(__name__)

MCP_FALLBACK_WARNING = "MCP unavailable; used direct API fallback"


def _mcp_client_factory():
    """httpx client factory for MCP streamable-HTTP calls.

    MCP endpoints here are internal and served with self-signed certs, so default
    to skipping TLS verification — otherwise every https MCP call fails the
    handshake and demotes the whole collector to the noisier direct-API fallback.
    This is an internal RCA tool; set MCP_TLS_VERIFY=true once the endpoints
    present a trusted cert to restore verification.
    ponytail: insecure-by-default MCP TLS; flip MCP_TLS_VERIFY=true to harden.
    """
    if os.getenv("MCP_TLS_VERIFY", "").strip().lower() in ("1", "true", "yes"):
        return None  # None → SDK's default client (system trust store)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        # Mirrors mcp.shared._httpx_utils.create_mcp_http_client (follow_redirects +
        # 30s/300s default timeout) with TLS verification disabled.
        kwargs: dict[str, Any] = {"follow_redirects": True, "verify": False}
        kwargs["timeout"] = timeout if timeout is not None else httpx.Timeout(30.0, read=300.0)
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


def mcp_fallback_warning(exc: Exception) -> str:
    """Fallback warning that names the ACTUAL failure, not just the class.

    'MCP unavailable: RuntimeError' is undiagnosable from a report; keep the
    message (truncated) so the operator can see WHY MCP fell back to direct API.
    """
    detail = _safe_text(str(exc), limit=160)
    label = f"{MCP_FALLBACK_WARNING}: {type(exc).__name__}"
    return f"{label}: {detail}" if detail else label


async def mcp_call(
    url: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> Any:
    """Call one tool on a streamable-HTTP MCP server.

    One retry on ANY failure: each call opens a fresh session, so a transient
    hiccup (service restarting, connection reset) used to demote the WHOLE
    collector run to the direct-API fallback. MCP is the preferred transport —
    give it a second chance before giving up."""
    if not url:
        raise RuntimeError("MCP URL is not configured")

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    factory = _mcp_client_factory()
    extra = {"httpx_client_factory": factory} if factory else {}

    for attempt in range(2):
        try:
            async with streamablehttp_client(
                url, headers=headers, **extra
            ) as (read, write, *_rest):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(tool, arguments)
        except Exception:
            if attempt:
                raise
            await asyncio.sleep(0.5)


async def mcp_call_many(
    url: str,
    calls: list[tuple[str, dict[str, Any]]],
    *,
    headers: dict[str, str] | None = None,
) -> list[Any]:
    """Call several tools through one initialized streamable-HTTP session.

    mcp-grafana performs per-session setup and logs it at INFO. Opening a new
    session for every PromQL/LogQL query produced dozens of identical session
    messages per analysis. A collector batch has one session (or two only when
    the whole batch needs its transport retry) while preserving result order.
    """
    if not url:
        raise RuntimeError("MCP URL is not configured")
    if not calls:
        return []

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    factory = _mcp_client_factory()
    extra = {"httpx_client_factory": factory} if factory else {}

    for attempt in range(2):
        try:
            async with streamablehttp_client(
                url, headers=headers, **extra
            ) as (read, write, *_rest):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return [
                        await session.call_tool(tool, arguments)
                        for tool, arguments in calls
                    ]
        except Exception:
            if attempt:
                raise
            await asyncio.sleep(0.5)


async def mcp_reachability(
    urls: dict[str, str],
    *,
    headers_by_name: dict[str, dict[str, str]] | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, str]:
    """{name: 'ok (N tools)' | error} for each configured MCP URL.

    Startup answer to "are the agents actually on MCP?" — one tools/list per
    service, logged so a mis-wired URL is visible immediately, not mid-analysis."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    factory = _mcp_client_factory()
    extra = {"httpx_client_factory": factory} if factory else {}
    async def probe(name: str, url: str) -> tuple[str, str]:
        try:
            async with asyncio.timeout(max(0.1, timeout_seconds)):
                async with streamablehttp_client(
                    url,
                    headers=(headers_by_name or {}).get(name),
                    timeout=timeout_seconds,
                    sse_read_timeout=timeout_seconds,
                    **extra,
                ) as (read, write, *_rest):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        status = f"ok ({len(tools.tools)} tools)"
        except Exception as exc:  # noqa: BLE001 - reachability is a report, not a gate
            detail = _safe_text(str(exc), limit=120)
            status = f"unreachable: {type(exc).__name__}"
            if detail:
                status += f": {detail}"
        _log.info("mcp self-check %s (%s): %s", name, url, status)
        return name, status

    # A hung Run:ai endpoint must not defer the Kubernetes/Grafana/Postgres
    # diagnostics behind it. Each configured service has its own deadline and
    # all probes start together.
    results = await asyncio.gather(
        *(probe(name, url) for name, url in urls.items() if url)
    )
    return dict(results)


def mcp_tool_text(result: Any) -> str:
    return build_masker(()).mask_text(mcp_tool_raw_text(result))


def mcp_tool_raw_text(result: Any) -> str:
    """UNMASKED tool text — for parsers only, never for display/evidence.

    Masking replaces secret-looking spans (base64 certs, tokens) with
    "[MASKED]" INSIDE the serialized YAML/JSON, which breaks the syntax
    ("MCP result was not JSON or YAML ... [MASKED] 420"). Parse the raw text
    first, then mask the parsed OBJECT — same protection, intact structure."""
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
        return _mask_object(structured)
    blob = mcp_tool_raw_text(result).strip()
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
