from __future__ import annotations

import re
from typing import Any

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.collectors.loki import _llm_insight
from app.config import Settings
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)


class PrometheusCollector:
    name = "prometheus"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.prometheus_url and not self._settings.prometheus_mcp_url:
            summary = f"{NO_EVIDENCE} Prometheus is not configured; metric evidence was skipped."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["prometheus.url"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="prometheus",
                        type="metrics",
                        status="unavailable",
                        confidence="low",
                        query=None,
                        summary=summary,
                        result={"prometheus_url_configured": False},
                    )
                ],
            )

        control_plane_namespaces = (
            self._settings.runai_log_namespaces
            if plan is not None and getattr(plan, "check_control_plane", False)
            else ()
        )
        queries = _queries_for(target, plan, control_plane_namespaces)
        query_results = []
        warnings: list[str] = []

        used_mcp = False
        if self._settings.prometheus_mcp_url:
            try:
                query_results = await _collect_prometheus_mcp(self._settings, queries)
                used_mcp = True
            except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
                warnings.append(mcp_fallback_warning(exc))
        else:
            warnings.append(f"{MCP_FALLBACK_WARNING}: PROMETHEUS_MCP_URL not configured")

        if not used_mcp:
            if not self._settings.prometheus_url:
                summary = f"{NO_EVIDENCE} Prometheus MCP failed and direct URL is not configured."
                return CollectorResult(
                    agent=self.name,
                    status="unavailable",
                    summary=summary,
                    confidence="low",
                    missing_data=["prometheus.url"],
                    warnings=warnings,
                    artifacts=[
                        artifact(
                            agent=self.name,
                            source="prometheus",
                            type="promql",
                            status="unavailable",
                            confidence="low",
                            query="; ".join(query for _, query in queries),
                            summary=summary,
                            result={"prometheus_mcp_url_configured": True},
                        )
                    ],
                )
            query_results = await _collect_prometheus_direct(self._settings, queries, warnings)

        successful = [item for item in query_results if not item["error"]]
        populated = [
            item
            for item in successful
            if item["series_count"] and item["name"] != "prometheus_up"
        ]
        if populated:
            status = "ok"
            confidence = "high"
            summary = (
                f"Prometheus {'MCP' if used_mcp else 'direct'} queries completed with "
                "matching metric series "
                f"for {len(populated)} of {len(query_results)} query group(s)."
            )
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = (
                f"{NO_EVIDENCE} Prometheus is reachable, but the workload metric queries "
                "returned no series. Check metric labels and scrape configuration."
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} Prometheus direct queries failed."

        insight = await _llm_insight(
            self._settings, "Prometheus metrics", summary, query_results
        )
        if insight:
            summary = insight
        result = {
            "prometheus_url": self._settings.prometheus_url,
            "prometheus_mcp_url": self._settings.prometheus_mcp_url,
            "used_mcp": used_mcp,
            "queries": query_results,
        }
        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=result,
            missing_data=(
                []
                if populated
                else ["prometheus.workload_metrics"]
                if successful
                else ["prometheus.query"]
            ),
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="prometheus",
                    type="promql",
                    status=status,
                    confidence=confidence,
                    query="; ".join(item["query"] for item in query_results),
                    summary=summary,
                    result=result,
                )
            ],
        )


def _queries_for(
    target: AnalysisTarget, plan=None, control_plane_namespaces: tuple[str, ...] = ()
) -> list[tuple[str, str]]:
    namespace = target.namespace
    pod = target.pod
    if plan is not None:
        if plan.namespaces:
            namespace = plan.namespaces[0]
        pod = plan.pod or pod
    selectors = []
    if namespace:
        selectors.append(f'namespace="{namespace}"')
    if pod:
        selectors.append(f'pod="{pod}"')
    pod_selector = ",".join(selectors)

    queries: list[tuple[str, str]] = [("prometheus_up", "up")]
    if pod_selector:
        queries.extend(
            [
                ("container_memory", f"container_memory_working_set_bytes{{{pod_selector}}}"),
                ("container_cpu", f"rate(container_cpu_usage_seconds_total{{{pod_selector}}}[5m])"),
                (
                    "container_restarts",
                    f"kube_pod_container_status_restarts_total{{{pod_selector}}}",
                ),
            ]
        )
    elif namespace:
        namespace_selector = f'namespace="{namespace}"'
        queries.extend(
            [
                (
                    "namespace_pending_pods",
                    f'kube_pod_status_phase{{{namespace_selector},phase="Pending"}}',
                ),
                (
                    "namespace_restarts",
                    f"kube_pod_container_status_restarts_total{{{namespace_selector}}}",
                ),
            ]
        )
    if target.queue:
        queries.append(
            (
                "runai_queue_allocated_gpus",
                f'runai_queue_allocated_gpus{{queue="{target.queue}"}}',
            )
        )
        queries.append(
            (
                "runai_queue_requested_gpus",
                f'runai_queue_requested_gpus{{queue="{target.queue}"}}',
            )
        )
    if target.project:
        queries.extend(
            [
                (
                    "runai_project_allocated_gpus",
                    f'runai_project_allocated_gpus{{project="{target.project}"}}',
                ),
                (
                    "runai_project_requested_gpus",
                    f'runai_project_requested_gpus{{project="{target.project}"}}',
                ),
            ]
        )
    # Control-plane health: when the alert implicates Run:ai, check whether the
    # scheduler/backend pods themselves are crashlooping or stuck Pending — a dying
    # workload's cause is often an unhealthy control plane, not the workload.
    ns_re = "|".join(re.escape(ns) for ns in control_plane_namespaces if ns)
    if ns_re:
        cp = f'namespace=~"{ns_re}"'
        queries.extend(
            [
                (
                    "runai_control_plane_restarts",
                    f"kube_pod_container_status_restarts_total{{{cp}}}",
                ),
                (
                    "runai_control_plane_pending",
                    f'kube_pod_status_phase{{{cp},phase="Pending"}}',
                ),
            ]
        )
    return queries


def _prometheus_status(data: object) -> str:
    if isinstance(data, dict):
        value = data.get("status")
        if isinstance(value, str):
            return value
    return "unknown"


def _prometheus_result(data: object) -> list[object]:
    if not isinstance(data, dict):
        return []
    payload = data.get("data")
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    return result if isinstance(result, list) else []


async def _collect_prometheus_direct(
    settings: Settings, queries: list[tuple[str, str]], warnings: list[str]
) -> list[dict[str, object]]:
    query_results: list[dict[str, object]] = []
    for name, query in queries:
        response = await get_json(
            base_url=settings.prometheus_url,
            path="/api/v1/query",
            timeout_seconds=settings.prometheus_timeout_seconds,
            params={"query": query},
        )
        result_data = _prometheus_result(response.data)
        query_results.append(
            {
                "name": name,
                "query": query,
                "url": response.url,
                "status_code": response.status_code,
                "status": _prometheus_status(response.data),
                "series_count": len(result_data),
                "sample": compact(result_data, limit=3),
                "error": response.error,
            }
        )
        if response.error:
            warnings.append(f"Prometheus query failed for {name}: {response.error}")
    return query_results


async def _collect_prometheus_mcp(
    settings: Settings, queries: list[tuple[str, str]]
) -> list[dict[str, object]]:
    datasource_uid = await _grafana_datasource_uid(settings.prometheus_mcp_url, "prometheus")
    return [
        await _mcp_query_prometheus(settings.prometheus_mcp_url, name, query, datasource_uid)
        for name, query in queries
    ]


async def prom_mcp_query(settings: Settings, name: str, promql: str) -> dict[str, object]:
    datasource_uid = await _grafana_datasource_uid(settings.prometheus_mcp_url, "prometheus")
    return await _mcp_query_prometheus(settings.prometheus_mcp_url, name, promql, datasource_uid)


async def _mcp_query_prometheus(
    url: str, name: str, promql: str, datasource_uid: str = ""
) -> dict[str, object]:
    args_list: list[dict[str, object]] = []
    if datasource_uid:
        args_list.extend(
            [
                {"datasourceUid": datasource_uid, "query": promql},
                {"datasourceUid": datasource_uid, "expr": promql},
                {"datasource_uid": datasource_uid, "query": promql},
            ]
        )
    args_list.extend([{"query": promql}, {"expr": promql}])
    data = await _call_mcp_json(url, "query_prometheus", args_list)
    result_data = _prometheus_result(data)
    if not result_data:
        result_data = _first_result_list(data)
    return {
        "name": name,
        "query": promql,
        "url": f"{url}#query_prometheus",
        "status_code": 200,
        "status": _prometheus_status(data),
        "series_count": len(result_data),
        "sample": compact(result_data, limit=3),
        "error": None,
    }


async def _grafana_datasource_uid(url: str, datasource_type: str) -> str:
    try:
        data = await _call_mcp_json(url, "list_datasources", [{}])
    except Exception:  # noqa: BLE001 - query tools may work without discovery.
        return ""
    for datasource in _datasource_items(data):
        dtype = str(datasource.get("type") or "").lower()
        name = str(datasource.get("name") or "").lower()
        if datasource_type in dtype or datasource_type in name:
            uid = datasource.get("uid") or datasource.get("id") or datasource.get("name")
            return str(uid) if uid else ""
    return ""


def _datasource_items(data: Any) -> list[dict[str, Any]]:
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
    return []


async def _call_mcp_json(
    url: str, tool: str, args_list: list[dict[str, object]]
) -> object:
    last_error = ""
    for args in args_list:
        try:
            result = await mcp_call(url, tool, args)
        except Exception as exc:  # noqa: BLE001 - try the next schema candidate.
            last_error = f"{exc.__class__.__name__}: {exc}"
            continue
        error = mcp_error(result)
        if error:
            last_error = error
            continue
        data = mcp_tool_json(result)
        if isinstance(data, dict) and "raw" in data:
            last_error = "MCP result was not JSON"
            continue
        return data
    raise RuntimeError(last_error or f"{tool} failed")


def _first_result_list(data: object) -> list[object]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for value in data.values():
        if isinstance(value, list):
            return value
        found = _first_result_list(value)
        if found:
            return found
    return []


# --- Cross-collector deterministic follow-up -----------------------------------
# The k8s->prometheus branches of the unified debug flowchart, as code: given what
# the kubernetes collector found, derive the PromQL a human runs next. Runs with or
# without the LLM. Read-only.
async def prom_query(settings: Settings, name: str, promql: str) -> dict:
    """One ad-hoc PromQL instant query; never raises."""
    if not settings.prometheus_url:
        return {"name": name, "query": promql, "error": "prometheus not configured", "data": None}
    resp = await get_json(
        base_url=settings.prometheus_url, path="/api/v1/query",
        timeout_seconds=settings.prometheus_timeout_seconds, params={"query": promql},
    )
    return {
        "name": name, "query": promql, "status_code": resp.status_code,
        "error": resp.error, "data": compact(resp.data, limit=8),
    }


def _prom_followup_queries(details: dict, target: AnalysisTarget) -> list[tuple[str, str]]:
    ns, pod, node = (target.namespace or ""), (target.pod or ""), (target.node or "")
    if not isinstance(details, dict):
        return []
    diags = details.get("container_diagnostics") or []
    statuses = details.get("pod_statuses") or []
    oom = any(
        isinstance(d, dict) and isinstance(d.get("lastTerminated"), dict)
        and "oomkilled" in str(d["lastTerminated"].get("reason", "")).lower()
        for d in diags
    )
    restarts = any(
        isinstance(d, dict) and isinstance(d.get("restartCount"), int) and d["restartCount"] > 0
        for d in diags
    )
    pending = any(
        isinstance(p, dict) and str(p.get("phase", "")).lower() == "pending" for p in statuses
    )
    out: list[tuple[str, str]] = []
    if oom and ns and pod:
        # ratio ~1 => own-limit OOM (raise limit / fix leak); <<1 => node pressure.
        out.append((
            "oom_working_set_vs_limit",
            f'max_over_time(container_memory_working_set_bytes{{namespace="{ns}",pod="{pod}",'
            f'container!="",container!="POD"}}[30m]) / on(namespace,pod,container) '
            f'kube_pod_container_resource_limits{{namespace="{ns}",pod="{pod}",resource="memory"}}',
        ))
        out.append((
            "oom_growth_shape",
            f'deriv(container_memory_working_set_bytes{{namespace="{ns}",pod="{pod}",'
            f'container!="",container!="POD"}}[30m])',
        ))
    if restarts and ns and pod:
        out.append((
            "active_restart_rate",
            f'increase(kube_pod_container_status_restarts_total{{namespace="{ns}",pod="{pod}"}}[15m])',
        ))
    if pending and node:
        out.append((
            "node_memory_headroom",
            f'node_memory_MemAvailable_bytes{{instance=~"{node}.*"}} / '
            f'node_memory_MemTotal_bytes{{instance=~"{node}.*"}}',
        ))
    return out


async def prometheus_followup(
    settings: Settings,
    prometheus_result: CollectorResult | None,
    kubernetes_result: CollectorResult | None,
    target: AnalysisTarget,
    max_reads: int = 6,
) -> list[dict]:
    """Fire k8s->prometheus follow-up queries and attach them as followup_query
    artifacts on the prometheus result. Best-effort, read-only, bounded."""
    if prometheus_result is None or getattr(prometheus_result, "agent", "") != "prometheus":
        return []
    details = getattr(kubernetes_result, "details", {}) or {}
    queries = _prom_followup_queries(details, target)[:max_reads]
    results: list[dict] = []
    for name, promql in queries:
        results.append(await prom_query(settings, name, promql))
    for res in results:
        err = res.get("error")
        prometheus_result.artifacts.append(
            artifact(
                agent="prometheus", source="prometheus", type="followup_query",
                status="unavailable" if err else "ok", confidence="medium",
                query=res.get("query"),
                summary=(str(err) if err else f"flowchart follow-up: {res.get('name')}"),
                result=res,
            )
        )
    return results
