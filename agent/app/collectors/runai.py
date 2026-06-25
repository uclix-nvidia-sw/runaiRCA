from __future__ import annotations

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings


class RunAICollector:
    name = "runai"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        missing: list[str] = []
        if not target.project:
            missing.append("runai.project")
        if not target.queue:
            missing.append("runai.queue")
        if not target.workload_name and not target.runai_workload_id:
            missing.append("runai.workload")

        if not self._settings.runai_base_url:
            summary = (
                "Run:ai API is not configured. Using alert labels and annotations "
                "as scheduling context."
            )
            status = "partial" if len(missing) < 3 else "unavailable"
            confidence = "low"
        else:
            summary = (
                "Run:ai API configuration is present. MVP collector recorded the "
                "target identity and is ready for authenticated workload lookup."
            )
            status = "ok"
            confidence = "medium"

        details = {
            "cluster": target.cluster,
            "project": target.project,
            "queue": target.queue,
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "runai_workload_id": target.runai_workload_id,
            "gpu_context": {
                "gpu_request": "",
                "gpu_allocated": "",
                "scheduler": "runai-scheduler",
            },
        }

        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=details,
            missing_data=missing,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="runai",
                    type="workload_context",
                    status=status,
                    confidence=confidence,
                    query="runai workload/project/queue lookup",
                    summary=summary,
                    result=details,
                )
            ],
        )
