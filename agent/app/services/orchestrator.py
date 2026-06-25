from __future__ import annotations

import asyncio
import json
import re
import subprocess
from collections import Counter
from uuid import uuid4

from app.collectors.base import CollectorResult, resolve_target
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import Settings
from app.schemas import (
    AlertAnalysisArtifact,
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)


class NemoWorkflowRunner:
    """Optional bridge to NeMo Agent Toolkit's `nat` CLI.

    The local collector orchestrator remains the default so the service is useful
    without external credentials. This runner is intentionally isolated: when it
    fails, the service falls back to deterministic synthesis.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def enabled(self) -> bool:
        return self._settings.enable_nat_runtime

    async def run(self, payload: dict[str, object]) -> str | None:
        if not self.enabled():
            return None

        proc = await asyncio.create_subprocess_exec(
            "nat",
            "run",
            "--config_file",
            self._settings.nat_config_file,
            "--input",
            json.dumps(payload, sort_keys=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self._settings.nat_timeout_seconds
            )
        except TimeoutError:
            proc.kill()
            return None
        if proc.returncode != 0:
            return None
        text = stdout.decode("utf-8", errors="replace").strip()
        return _extract_nat_result(text)


class AnalysisOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._nat = NemoWorkflowRunner(settings)
        self._collectors = [
            RunAICollector(settings),
            KubernetesCollector(settings),
            PostgresCollector(settings),
            PrometheusCollector(settings),
            LokiCollector(settings),
        ]

    async def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        target = resolve_target(request.alert.labels, request.alert.annotations)
        nat_text = await self._nat.run(
            {
                "mode": "alert_analysis",
                "alert": request.alert.model_dump(),
                "incident_id": request.incident_id,
            }
        )

        results = await asyncio.gather(
            *(collector.collect(target) for collector in self._collectors)
        )

        capabilities = {result.agent: result.status for result in results}
        artifacts = [artifact for result in results for artifact in result.artifacts]
        missing = sorted({item for result in results for item in result.missing_data})
        warnings = sorted({item for result in results for item in result.warnings})
        quality = _quality_from(results)
        summary = _summary_from(request, results)
        detail = nat_text if nat_text else _detail_from(request, results, missing)

        return AlertAnalysisResponse(
            status="ok",
            thread_ts=request.thread_ts,
            analysis=detail,
            analysis_summary=summary,
            analysis_detail=detail,
            analysis_type=request.analysis_type or request.alert.status or "firing",
            analysis_quality=quality,
            missing_data=missing,
            warnings=warnings,
            capabilities=capabilities,
            context={
                "target": target.__dict__,
                "nemo_runtime": "enabled" if self._nat.enabled() else "fallback",
            },
            artifacts=artifacts,
        )

    async def summarize_incident(
        self, request: IncidentSummaryRequest
    ) -> IncidentSummaryResponse:
        alerts = request.alerts
        title = request.title if request.title and request.title != "Ongoing" else "Run:AI incident"
        summaries = [
            alert.analysis_summary
            for alert in alerts
            if alert.analysis_summary and alert.analysis_summary.strip()
        ]
        summary = summaries[0] if summaries else f"{len(alerts)} alert(s) were correlated."
        detail_lines = [
            "## Incident Summary",
            "",
            f"- Incident: {request.incident_id}",
            f"- Severity: {request.severity}",
            f"- Alert count: {len(alerts)}",
            f"- Window: {request.fired_at} to {request.resolved_at}",
            "",
            "## Alert Evidence",
        ]
        for alert in alerts:
            detail_lines.append(
                f"- {alert.alert_name} ({alert.status}, {alert.severity}): "
                f"{alert.analysis_summary or 'No analysis summary yet.'}"
            )
        return IncidentSummaryResponse(
            status="ok",
            title=title,
            summary=summary,
            detail="\n".join(detail_lines),
        )

    async def chat(self, request: ChatRequest) -> ChatResponse:
        context = request.context or {}
        entity = context.get("incident_id") or context.get("alert_id") or "current page"
        answer = (
            f"I will reason over {entity}. In the MVP, use the RCA detail and "
            "Agent Evidence Trail on the same page to inspect Run:ai, Kubernetes, "
            "Postgres, Prometheus, and Loki findings. Question: "
            f"{request.message}"
        )
        return ChatResponse(
            status="ok",
            answer=answer,
            conversation_id=request.conversation_id or f"chat-{uuid4().hex[:10]}",
        )


def _quality_from(results: list[CollectorResult]) -> str:
    counts = Counter(result.status for result in results)
    if counts["ok"] >= 3:
        return "high"
    if counts["ok"] >= 1 or counts["partial"] >= 2:
        return "medium"
    return "low"


def _extract_nat_result(output: str) -> str | None:
    if not output:
        return None
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", output)
    marker = "Workflow Result:"
    if marker not in cleaned:
        return cleaned.strip() or None
    result = cleaned.split(marker, 1)[1]
    result = result.split("--------------------------------------------------", 1)[0]
    return result.strip() or None


def _summary_from(request: AlertAnalysisRequest, results: list[CollectorResult]) -> str:
    alert_name = request.alert.labels.get("alertname") or "Run:AI alert"
    unavailable = [result.agent for result in results if result.status == "unavailable"]
    if unavailable:
        return (
            f"{alert_name} analysis completed with partial evidence. Missing sources: "
            f"{', '.join(unavailable)}."
        )
    return f"{alert_name} analysis completed with Run:ai, Kubernetes, metrics, and logs context."


def _detail_from(
    request: AlertAnalysisRequest,
    results: list[CollectorResult],
    missing: list[str],
) -> str:
    labels = request.alert.labels
    annotations = request.alert.annotations
    lines = [
        "## Root Cause",
        "",
        (
            annotations.get("description")
            or annotations.get("summary")
            or "The exact root cause requires operator review of the collected evidence."
        ),
        "",
        "## Evidence",
        "",
    ]
    for result in results:
        lines.append(f"- **{result.agent}** [{result.status}]: {result.summary}")
    lines.extend(
        [
            "",
            "## Recommended Actions",
            "",
            "- Check Run:ai project and queue saturation for the affected workload.",
            "- Review Kubernetes events, pod status, and node conditions.",
            "- Check Postgres RCA store health if incident persistence or similar-incident search looks stale.",
            "- Compare Prometheus GPU, CPU, memory, and scheduling metrics around the alert window.",
            "- Inspect Loki logs for container errors or startup failures.",
            "",
            "## Missing Data",
            "",
        ]
    )
    if missing:
        lines.extend(f"- {item}" for item in missing)
    else:
        lines.append("- No required evidence source was marked missing by the MVP collectors.")
    lines.extend(
        [
            "",
            "## Alert Labels",
            "",
            "```json",
            json.dumps(labels, indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines)
