"""Read-only Run:ai evidence gathering through NVIDIA's official MCP server.

The official ``nvcr.io/nvidia/runai/runai-mcp-server`` exposes focused Run:ai
tools over authenticated streamable HTTP.  It is deliberately *not* an OpenAPI
proxy: callers must use its supported workload, resource, cluster, and identity
tools rather than issuing arbitrary API paths.  Every request carries the
existing Run:ai bearer token (obtained from ``RUNAI_BEARER_TOKEN`` or client
credentials) because the server protects its ``/mcp`` endpoint with OIDC.

MCP remains additive. Missing configuration/auth returns ``None``; setup and
tool failures are returned as bounded query errors so the collector can retain
the reason before falling back to its direct HTTP reads.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.collectors.base import AnalysisTarget
from app.collectors.http_json import get_json
from app.config import Settings
from app.masking import build_masker
from app.mcp_client import (
    mcp_budget,
    mcp_call,
    mcp_error,
    mcp_tls_verify,
    mcp_tool_json,
    mcp_tool_text,
)


async def gather_runai_via_mcp(
    settings: Settings, target: AnalysisTarget, *, headers: dict[str, str]
) -> list[dict[str, Any]] | None:
    """Return official-MCP results/errors, or ``None`` when MCP is not usable."""
    if not settings.runai_mcp_url:
        return None
    if not headers.get("Authorization"):
        # The official HTTP transport rejects unauthenticated MCP sessions.
        return None
    try:
        async with mcp_budget(settings.runai_timeout_seconds):
            return await _gather(settings, target, headers=headers)
    except Exception as exc:  # noqa: BLE001 - preserve the fallback reason
        return [
            {
                "name": "mcp_setup",
                "query": "initialize official Run:ai MCP session",
                "transport": "mcp",
                "status_code": None,
                "error": _safe_text(
                    f"{exc.__class__.__name__}: {exc}", limit=300
                ),
                "data": None,
            }
        ]


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

    results = [
        await _call_tool(settings, name, tool, arguments, headers=headers)
        for name, tool, arguments in plan
    ]
    results.extend(await _gather_physical_inventory(settings, target, headers=headers))
    return results


async def _gather_physical_inventory(
    settings: Settings, target: AnalysisTarget, *, headers: dict[str, str]
) -> list[dict[str, Any]]:
    """The cluster's GPU inventory, gathered unconditionally.

    This is not a drill-down. The GPU model is an invariant property of the
    cluster, in the same class as which node pools exist -- and it is the input
    to a CORRECTNESS gate, not to a hypothesis: without it the XID catalog will
    happily recommend acting on an upstream fault that cannot occur on that
    hardware (144/145/146 are B100/GB200-only). Leaving that to whether the
    model happened to pick the tool made one question answer differently on the
    same cluster from run to run.

    list_node_pools, which this gather already runs, carries no GPU field at
    all -- verified against the pinned MCP server's own tools/list output. Only
    get_cluster_physical_inventory does, and it needs a cluster UUID rather than
    the alert's cluster name.
    """
    try:
        cluster_id = await resolve_runai_cluster_id(settings, target)
    except Exception as exc:  # noqa: BLE001 - a per-tool failure stays evidence
        return [
            {
                "name": "cluster_inventory",
                "query": "MCP get_cluster_physical_inventory",
                "transport": "mcp",
                "status_code": None,
                "error": _safe_text(f"{exc.__class__.__name__}: {exc}", limit=300),
                "data": None,
            }
        ]
    return [
        await _call_tool(
            settings,
            "cluster_inventory",
            "get_cluster_physical_inventory",
            {"clusterId": cluster_id},
            headers=headers,
        )
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


_CLUSTER_ID_CACHE: dict[tuple[str, str], str] = {}


async def resolve_runai_cluster_id(settings: Settings, target: AnalysisTarget) -> str:
    """Resolve an alert's cluster name to the UUID required by official MCP tools."""
    if valid_official_workload_id(target.cluster):
        return target.cluster
    if not settings.runai_base_url:
        raise RuntimeError("Run:ai base URL is not configured; cannot resolve cluster ID")
    cache_key = (settings.runai_base_url, target.cluster)
    if cached := _CLUSTER_ID_CACHE.get(cache_key):
        return cached
    from app.collectors.runai import _runai_headers

    headers, _warnings = await _runai_headers(settings)
    if not headers.get("Authorization"):
        raise RuntimeError("Run:ai API authentication is unavailable; cannot resolve cluster ID")
    response = await get_json(
        base_url=settings.runai_base_url,
        path="/api/v1/clusters",
        timeout_seconds=settings.runai_timeout_seconds,
        headers=headers,
        verify=mcp_tls_verify(),
    )
    if not response.ok:
        raise RuntimeError(response.error or f"HTTP {response.status_code} resolving cluster ID")
    data = response.data
    rows = (
        data
        if isinstance(data, list)
        else data.get("clusters")
        if isinstance(data, dict)
        else None
    )
    clusters = [row for row in (rows or []) if isinstance(row, dict)]
    matches = [row for row in clusters if str(row.get("name") or "") == target.cluster]
    candidates = matches or (clusters if len(clusters) == 1 else [])
    if not candidates:
        raise RuntimeError(
            f"could not resolve Run:ai cluster ID for alert cluster {target.cluster!r}"
        )
    cluster_id = str(candidates[0].get("uuid") or candidates[0].get("id") or "")
    if not cluster_id:
        raise RuntimeError(
            f"Run:ai cluster {str(candidates[0].get('name') or target.cluster)!r} has no UUID"
        )
    _CLUSTER_ID_CACHE[cache_key] = cluster_id
    return cluster_id


def runai_cluster_gpu_model(payload: Any) -> str:
    """The cluster's one GPU model, from get_cluster_physical_inventory.

    ``byGpuModel`` groups every GPU-bearing node by its raw product string
    (the same GFD label kubernetes.py reads off a single node) -- a
    cluster-wide source that needs no alert node. A mixed cluster (more than
    one distinct model) is deliberately left unresolved: guessing either one
    would gate away the other model's own upstream-XID knowledge, which is
    worse than not gating at all.
    """
    by_model = payload.get("byGpuModel") if isinstance(payload, dict) else None
    if not isinstance(by_model, list):
        return ""
    models = {
        str(entry.get("gpuModel")).strip()
        for entry in by_model
        if isinstance(entry, dict) and str(entry.get("gpuModel") or "").strip()
    }
    return next(iter(models)) if len(models) == 1 else ""
