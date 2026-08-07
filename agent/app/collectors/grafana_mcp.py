from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from app.mcp_client import mcp_call, mcp_error, mcp_tool_json

# Module-local clock so a test can freeze THIS module's notion of time without
# patching the stdlib object, which is also the asyncio event loop's clock.
_now = time.monotonic

_GRAFANA_UID = re.compile(r"^[a-zA-Z0-9\-_]{1,40}$")
_SUCCESS_TTL_SECONDS = 300.0
_FAILURE_TTL_SECONDS = 30.0


@dataclass(frozen=True)
class _DatasourceCacheEntry:
    expires_at: float
    uid: str = ""
    error: str = ""


_DATASOURCE_CACHE: dict[tuple[str, str, str], _DatasourceCacheEntry] = {}


async def resolve_grafana_datasource_uid(
    url: str,
    datasource_type: str,
    configured_uid: str,
    *,
    call_json: Callable[[str, str, list[dict[str, object]]], Awaitable[object]],
) -> str:
    """Resolve one Grafana datasource UID, with short positive/negative caching.

    A configured UID removes an otherwise-required discovery session. Discovery
    failures are cached briefly so every drill-down step does not repeat the same
    list_datasources failure before falling back to the direct datasource API.
    """
    dtype = datasource_type.strip().lower()
    configured = configured_uid.strip()
    key = (url, dtype, configured)
    now = _now()
    cached = _DATASOURCE_CACHE.get(key)
    if cached and cached.expires_at > now:
        if cached.error:
            raise RuntimeError(cached.error)
        return cached.uid
    if cached:
        _DATASOURCE_CACHE.pop(key, None)

    try:
        if configured:
            uid = validate_grafana_datasource_uid(configured, dtype)
        else:
            # Current mcp-grafana supports server-side type filtering. Besides
            # returning less data, this avoids missing the desired datasource
            # when an installation has more than the default page size (50).
            data = await call_json(url, "list_datasources", [{"type": dtype}])
            uid = _select_datasource_uid(data, dtype)
            if not uid:
                env_name = f"{dtype.upper()}_DATASOURCE_UID"
                raise RuntimeError(
                    f"Grafana MCP returned no accessible {dtype} datasource; "
                    f"grant datasources:read or set {env_name}"
                )
    except Exception as exc:
        message = _resolution_error(dtype, exc)
        _DATASOURCE_CACHE[key] = _DatasourceCacheEntry(
            expires_at=now + _FAILURE_TTL_SECONDS,
            error=message,
        )
        raise RuntimeError(message) from exc

    _DATASOURCE_CACHE[key] = _DatasourceCacheEntry(
        expires_at=now + _SUCCESS_TTL_SECONDS,
        uid=uid,
    )
    return uid


def validate_grafana_datasource_uid(uid: str, datasource_type: str) -> str:
    normalized = uid.strip()
    if not normalized:
        raise RuntimeError(
            f"grafana datasource uid unresolved for {datasource_type}; set "
            f"{datasource_type.upper()}_DATASOURCE_UID or grant datasources:read"
        )
    if not _GRAFANA_UID.fullmatch(normalized):
        env_name = f"{datasource_type.upper()}_DATASOURCE_UID"
        raise RuntimeError(
            f"invalid {datasource_type} Grafana datasource UID in {env_name}"
        )
    return normalized


def mark_grafana_datasource_failure(
    url: str,
    datasource_type: str,
    configured_uid: str,
    exc: Exception,
) -> None:
    """Circuit-break repeated calls for a UID Grafana explicitly rejected."""
    detail = " ".join(str(exc).split())
    lowered = detail.lower()
    datasource_rejected = (
        "get datasource by uid" in lowered
        or "id is invalid" in lowered
        or (
            "datasource" in lowered
            and any(
                marker in lowered
                for marker in ("not found", "not accessible", "uid unresolved")
            )
        )
    )
    if not datasource_rejected:
        return
    key = (url, datasource_type.strip().lower(), configured_uid.strip())
    _DATASOURCE_CACHE[key] = _DatasourceCacheEntry(
        expires_at=_now() + _FAILURE_TTL_SECONDS,
        error=_resolution_error(datasource_type, exc),
    )


def clear_grafana_datasource_cache() -> None:
    _DATASOURCE_CACHE.clear()


def _resolution_error(datasource_type: str, exc: Exception) -> str:
    prefix = f"unable to resolve {datasource_type} Grafana datasource UID"
    detail = " ".join(str(exc).split())
    if detail.startswith(prefix):
        return detail[:500]
    return f"{prefix}: {detail}"[:500]


def _select_datasource_uid(data: object, datasource_type: str) -> str:
    candidates: list[dict[str, Any]] = []
    for datasource in _datasource_items(data):
        dtype = str(datasource.get("type") or "").strip().lower()
        if datasource_type not in dtype:
            continue
        uid = str(datasource.get("uid") or "").strip()
        if not _GRAFANA_UID.fullmatch(uid):
            continue
        candidates.append(datasource)
    if not candidates:
        return ""
    exact_type = [
        item
        for item in candidates
        if str(item.get("type") or "").strip().lower() == datasource_type
    ]
    pool = exact_type or candidates
    if len(pool) == 1:
        return str(pool[0].get("uid") or "").strip()

    defaults = [item for item in pool if bool(item.get("isDefault"))]
    if len(defaults) == 1:
        return str(defaults[0].get("uid") or "").strip()

    env_name = f"{datasource_type.upper()}_DATASOURCE_UID"
    candidate_labels = ", ".join(
        sorted(
            f"{str(item.get('name') or 'unnamed')}"
            f" ({str(item.get('uid') or 'no-uid')})"
            for item in pool
        )
    )
    default_detail = (
        "multiple defaults were returned"
        if len(defaults) > 1
        else "none is the unique default"
    )
    raise RuntimeError(
        f"multiple accessible {datasource_type} Grafana datasources are ambiguous; "
        f"{default_detail}. Set {env_name}. Candidates: {candidate_labels}"
    )


def _datasource_items(data: object) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("datasources", "items", "result"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    nested = data.get("data")
    if isinstance(nested, list):
        return [item for item in nested if isinstance(item, dict)]
    if isinstance(nested, dict):
        return _datasource_items(nested)
    return []


async def call_grafana_mcp_json(
    url: str, tool: str, args_list: list[dict[str, object]]
) -> object:
    """Call one Grafana MCP tool, trying each argument schema in turn.

    v0.x servers disagree on argument names, so callers pass every candidate
    shape and the first one the server accepts wins; the last failure is raised
    when none do.
    """
    last_error = ""
    for args in args_list:
        try:
            result = await mcp_call(url, tool, args)
        except Exception as exc:  # noqa: BLE001 - try the next schema candidate.
            last_error = f"{exc.__class__.__name__}: {exc}"
            continue
        try:
            return grafana_mcp_result_json(result, tool)
        except RuntimeError as exc:
            last_error = str(exc)
            continue
    raise RuntimeError(last_error or f"{tool} failed")


def grafana_mcp_result_json(result: object, tool: str) -> object:
    error = mcp_error(result)
    if error:
        raise RuntimeError(error)
    data = mcp_tool_json(result)
    if isinstance(data, dict) and "raw" in data:
        raise RuntimeError(f"{tool} result was not JSON")
    return data


def grafana_datasource_error(error: str) -> bool:
    """Whether a tool error means the datasource UID itself was rejected."""
    lowered = error.casefold()
    return "get datasource by uid" in lowered or "id is invalid" in lowered


async def grafana_datasource_uid(
    url: str, datasource_type: str, configured_uid: str = ""
) -> str:
    return await resolve_grafana_datasource_uid(
        url, datasource_type, configured_uid, call_json=call_grafana_mcp_json
    )


def raise_on_datasource_error(items: list[dict[str, object]]) -> None:
    """Abort the whole collector when Grafana rejected the datasource UID.

    That failure is not a property of any one query: every remaining query would
    fail identically, and reporting it per query turns one configuration problem
    into N unavailable evidence cards.
    """
    for item in items:
        error = str(item.get("error") or "")
        if grafana_datasource_error(error):
            raise RuntimeError(error)
