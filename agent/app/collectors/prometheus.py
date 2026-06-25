from __future__ import annotations

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings


class PrometheusCollector:
    name = "prometheus"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
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

        selectors = []
        if target.namespace:
            selectors.append(f'namespace="{target.namespace}"')
        if target.pod:
            selectors.append(f'pod="{target.pod}"')
        selector = ",".join(selectors)
        query = f"container_memory_working_set_bytes{{{selector}}}" if selector else "up"
        summary = "Prometheus is configured; MVP collector prepared a workload metric query."
        result = {
            "prometheus_url": self._settings.prometheus_url,
            "query": query,
            "note": "Query execution will be wired through native client or MCP server.",
        }
        return CollectorResult(
            agent=self.name,
            status="ok",
            summary=summary,
            confidence="medium",
            details=result,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="prometheus",
                    type="promql",
                    status="ok",
                    confidence="medium",
                    query=query,
                    summary=summary,
                    result=result,
                )
            ],
        )
