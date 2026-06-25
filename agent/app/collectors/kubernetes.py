from __future__ import annotations

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings


class KubernetesCollector:
    name = "kubernetes"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        missing: list[str] = []
        if not target.namespace:
            missing.append("kubernetes.namespace")
        if not target.pod and not target.workload_name and not target.node:
            missing.append("kubernetes.target")

        status = "partial" if missing else "ok"
        confidence = "medium" if not missing else "low"
        summary = (
            "Kubernetes target resolved from alert metadata."
            if not missing
            else "Kubernetes target is incomplete; namespace, pod, workload, or node labels are missing."
        )
        details = {
            "namespace": target.namespace,
            "pod": target.pod,
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "node": target.node,
            "expected_checks": [
                "pod phase and container restarts",
                "recent warning events",
                "workload controller status",
                "service and endpoint readiness",
                "node conditions for node-level alerts",
            ],
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
                    source="kubernetes",
                    type="target_context",
                    status=status,
                    confidence=confidence,
                    query="kubernetes context collection plan",
                    summary=summary,
                    result=details,
                )
            ],
        )
