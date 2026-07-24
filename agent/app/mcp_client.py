from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import httpx

from app.masking import build_masker

_log = logging.getLogger(__name__)

MCP_FALLBACK_WARNING = "MCP unavailable; used direct API fallback"
_mcp_deadline: ContextVar[float | None] = ContextVar("mcp_deadline", default=None)
_QUERY_REJECTION_RE = re.compile(
    r"\b(?:HTTP|status(?:\s+code)?)\s*400\b|\b(?:parse error|invalid query|"
    r"invalid char escape|syntax error|unexpected (?:by|identifier|character))\b",
    re.IGNORECASE,
)


@asynccontextmanager
async def mcp_budget(timeout_seconds: float | int | None):
    """Share one total deadline across a collector's sequential MCP calls.

    The SDK's streamable-HTTP read timeout is intentionally generous. Without
    this outer budget, discovery plus several tool calls (and their retries)
    can consume the entire analysis deadline before the direct fallback gets a
    chance to run. Nested budgets only tighten an existing deadline, and normal
    task cancellation still enforces the orchestrator's analysis-wide ceiling.
    """
    configured = float(timeout_seconds or 0)
    deadline = time.monotonic() + configured if configured > 0 else None
    existing = _mcp_deadline.get()
    if existing is not None:
        deadline = existing if deadline is None else min(existing, deadline)
    token = _mcp_deadline.set(deadline)
    try:
        yield
    finally:
        _mcp_deadline.reset(token)


def _mcp_time_remaining() -> float | None:
    deadline = _mcp_deadline.get()
    return None if deadline is None else deadline - time.monotonic()


async def _within_mcp_budget(factory):
    remaining = _mcp_time_remaining()
    if remaining is not None and remaining <= 0:
        raise TimeoutError("MCP collector budget exhausted before direct fallback")
    try:
        awaitable = factory()
        if remaining is None:
            return await awaitable
        return await asyncio.wait_for(awaitable, remaining)
    except TimeoutError as exc:
        if remaining is None:
            raise
        still_remaining = _mcp_time_remaining()
        if still_remaining is not None and still_remaining > 0:
            raise
        raise TimeoutError("MCP collector budget exhausted before direct fallback") from exc


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes")


def _env_false(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("0", "false", "no")


def _mcp_ca_path() -> str:
    """Return the configured mounted CA bundle when it is present."""
    configured = os.getenv("MCP_TLS_CA_PATH", "").strip()
    if not configured:
        configured = os.getenv("KUBERNETES_CA_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").strip()
    return configured if configured and Path(configured).is_file() else ""


def mcp_tls_verify() -> bool | str:
    """Return the TLS verification policy for MCP and direct datasource calls.

    Verification is enabled by default.  A mounted/configured CA bundle is used
    when available; disabling verification requires an explicit opt-in.
    """
    if _env_true("MCP_TLS_INSECURE") or _env_false("MCP_TLS_VERIFY"):
        return False
    return _mcp_ca_path() or True


def _mcp_client_factory():
    """httpx client factory for MCP streamable-HTTP calls.

    Use the pod's mounted/configured CA bundle when available.  The insecure
    escape hatch is explicit and disabled by default.
    """
    verify = mcp_tls_verify()
    if verify is True:
        return None  # None → SDK's default client (system trust store)

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        # Mirrors mcp.shared._httpx_utils.create_mcp_http_client (follow_redirects
        # + 30s/300s default timeout), while preserving the selected CA policy.
        kwargs: dict[str, Any] = {"follow_redirects": True, "verify": verify}
        kwargs["timeout"] = timeout if timeout is not None else httpx.Timeout(30.0, read=300.0)
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


def mcp_fallback_warning(exc: Exception, *, source: str = "MCP") -> str:
    """Fallback warning that names the ACTUAL failure, not just the class.

    Query rejections are application-level answers, not transport outages. Keep
    their parser detail separate so a malformed query cannot impersonate an
    unavailable MCP service.
    """
    detail = _safe_text(str(exc), limit=160)
    if _QUERY_REJECTION_RE.search(detail):
        label = f"{source} query rejected"
        return f"{label}: {detail}" if detail else label
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

    async def invoke():
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

    return await _within_mcp_budget(invoke)


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

    async def invoke():
        # Retry resumes from the first unfinished call: completed results from
        # attempt one survive a mid-batch transport failure.
        results: list[Any | None] = [None] * len(calls)
        remaining = list(range(len(calls)))
        for attempt in range(2):
            try:
                async with streamablehttp_client(
                    url, headers=headers, **extra
                ) as (read, write, *_rest):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        for index in remaining[:]:
                            tool, arguments = calls[index]
                            results[index] = await session.call_tool(tool, arguments)
                            remaining.remove(index)
                        return list(results)
            except Exception:
                if attempt:
                    raise
                await asyncio.sleep(0.5)

    return await _within_mcp_budget(invoke)


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
