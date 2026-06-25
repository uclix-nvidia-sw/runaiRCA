from __future__ import annotations

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings


class LokiCollector:
    name = "loki"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        if not self._settings.loki_url:
            summary = "Loki is not configured; log evidence was skipped."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["loki.url"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="loki",
                        type="logs",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"loki_url_configured": False},
                    )
                ],
            )

        selector_parts = []
        if target.namespace:
            selector_parts.append(f'namespace="{target.namespace}"')
        if target.pod:
            selector_parts.append(f'pod="{target.pod}"')
        selector = "{" + ",".join(selector_parts) + "}" if selector_parts else "{}"
        summary = "Loki is configured; MVP collector prepared a workload log query."
        result = {
            "loki_url": self._settings.loki_url,
            "query": selector,
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
                    source="loki",
                    type="logql",
                    status="ok",
                    confidence="medium",
                    query=selector,
                    summary=summary,
                    result=result,
                )
            ],
        )
