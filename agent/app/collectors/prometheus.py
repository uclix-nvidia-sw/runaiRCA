from __future__ import annotations

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.collectors.loki import _llm_insight
from app.config import Settings


class PrometheusCollector:
    name = "prometheus"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.prometheus_url:
            summary = "Prometheus is not configured; metric evidence was skipped."
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

        queries = _queries_for(target, plan)
        query_results = []
        warnings: list[str] = []

        for name, query in queries:
            response = await get_json(
                base_url=self._settings.prometheus_url,
                path="/api/v1/query",
                timeout_seconds=self._settings.prometheus_timeout_seconds,
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
                "Prometheus direct queries completed with matching metric series "
                f"for {len(populated)} of {len(query_results)} query group(s)."
            )
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = (
                "Prometheus is reachable, but the workload metric queries returned no series. "
                "Check metric labels and scrape configuration."
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = "Prometheus direct queries failed."

        insight = await _llm_insight(
            self._settings, "Prometheus metrics", summary, query_results
        )
        if insight:
            summary = insight
        result = {
            "prometheus_url": self._settings.prometheus_url,
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


def _queries_for(target: AnalysisTarget, plan=None) -> list[tuple[str, str]]:
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
