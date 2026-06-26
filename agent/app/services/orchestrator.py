from __future__ import annotations

import asyncio
import json
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from pydantic import BaseModel

from app.collectors.base import CollectorResult, resolve_target
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import Settings
from app.knowledge import load_troubleshooting_cases
from app.masking import Masker, build_masker
from app.prompts import agent_role_coverage_lines, load_agent_souls
from app.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    ChatRequest,
    ChatResponse,
    IncidentSummaryRequest,
    IncidentSummaryResponse,
)

TModel = TypeVar("TModel", bound=BaseModel)


class NemoWorkflowRunner:
    """Optional bridge to NeMo Agent Toolkit's `nat` CLI.

    The local collector orchestrator remains the default so the service is useful
    without external credentials. This runner is intentionally isolated: when it
    fails, the service falls back to deterministic synthesis.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._masker = _build_settings_masker(settings)

    def enabled(self) -> bool:
        return self._settings.enable_nat_runtime

    async def run(self, payload: dict[str, object]) -> str | None:
        if not self.enabled():
            return None

        config_file = self._materialize_config_file()
        proc = await asyncio.create_subprocess_exec(
            "nat",
            "run",
            "--config_file",
            config_file,
            "--input",
            json.dumps(self._masker.mask_object(payload), sort_keys=True),
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
        result = _extract_nat_result(text)
        return self._masker.mask_text(result) if result else None

    def _materialize_config_file(self) -> str:
        replacements = {
            "http://localhost:9901/mcp": self._settings.prometheus_mcp_url,
            "http://localhost:9902/mcp": self._settings.loki_mcp_url,
        }
        replacements = {old: new for old, new in replacements.items() if new}
        if not replacements:
            return self._settings.nat_config_file

        try:
            source = Path(self._settings.nat_config_file)
            text = source.read_text(encoding="utf-8")
        except OSError:
            return self._settings.nat_config_file

        rendered = text
        for old, new in replacements.items():
            rendered = rendered.replace(old, new)
        if rendered == text:
            return self._settings.nat_config_file

        target = Path(tempfile.gettempdir()) / "runai-rca-nat-workflow.yml"
        target.write_text(rendered, encoding="utf-8")
        return str(target)


class AnalysisOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._masker = _build_settings_masker(settings)
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
        nat_payload = request.model_dump(mode="json")
        nat_payload["mode"] = "alert_analysis"
        agent_souls = load_agent_souls(self._settings.agent_souls_file)
        nat_payload["agent_souls"] = agent_souls
        nat_text = await self._nat.run(nat_payload)

        results = await asyncio.gather(
            *(collector.collect(target) for collector in self._collectors)
        )

        capabilities = {result.agent: result.status for result in results}
        artifacts = [artifact for result in results for artifact in result.artifacts]
        missing = sorted({item for result in results for item in result.missing_data})
        warnings = sorted({item for result in results for item in result.warnings})
        quality = _quality_from(results)
        summary = _summary_from(request, results)
        playbook = load_troubleshooting_cases(self._settings.troubleshooting_cases_file)
        detail = nat_text if nat_text else _detail_from(
            request, results, missing, playbook, agent_souls
        )

        response = AlertAnalysisResponse(
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
                "similar_incidents": [
                    item.model_dump(mode="json") for item in request.similar_incidents
                ],
                "feedback_hints": [
                    item.model_dump(mode="json") for item in request.feedback_hints
                ],
                "agent_souls_file": self._settings.agent_souls_file,
                "agent_souls_applied": bool(agent_souls),
            },
            artifacts=artifacts,
        )
        return _mask_model(response, AlertAnalysisResponse, self._masker)

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
        response = IncidentSummaryResponse(
            status="ok",
            title=title,
            summary=summary,
            detail="\n".join(detail_lines),
        )
        return _mask_model(response, IncidentSummaryResponse, self._masker)

    async def chat(self, request: ChatRequest) -> ChatResponse:
        context = request.context or {}
        entity = (
            request.incident_id
            or request.alert_id
            or context.get("incident_id")
            or context.get("alert_id")
            or request.page
            or "current RCA workspace"
        )
        answer = _chat_answer_from_context(request, context, str(entity), self._masker)
        response = ChatResponse(
            status="ok",
            answer=answer,
            message=answer,
            response=answer,
            conversation_id=request.conversation_id or f"chat-{uuid4().hex[:10]}",
        )
        return _mask_model(response, ChatResponse, self._masker)


def _quality_from(results: list[CollectorResult]) -> str:
    counts = Counter(result.status for result in results)
    if counts["ok"] >= 3:
        return "high"
    if counts["ok"] >= 1 or counts["partial"] >= 2:
        return "medium"
    return "low"


def _build_settings_masker(settings: Settings) -> Masker:
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _mask_model(model: TModel, model_type: type[TModel], masker: Masker) -> TModel:
    payload = model.model_dump(mode="json")
    return model_type.model_validate(masker.mask_object(payload))


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
    troubleshooting_cases: str = "",
    agent_souls: str = "",
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
            "## Agent Role Coverage",
            "",
        ]
    )
    lines.extend(agent_role_coverage_lines())
    if not agent_souls:
        lines.append("- Agent role contract file was not loaded; fallback guidance was used.")
    lines.extend(
        [
            "",
            "## Recommended Actions",
            "",
            "- Check Run:ai project and queue saturation for the affected workload.",
            "- Review Kubernetes events, pod status, and node conditions.",
            "- Inspect Run:ai control-plane and backend namespace logs for scheduler, "
            "queue, quota, database, or reconciliation errors.",
            "- Check Postgres RCA store health if incident persistence or "
            "similar-incident search looks stale.",
            "- Compare Prometheus GPU, CPU, memory, and scheduling metrics around "
            "the alert window.",
            "- Inspect Loki logs for container errors or startup failures.",
            "",
            "## Troubleshooting Playbook",
            "",
        ]
    )
    if troubleshooting_cases:
        lines.append(troubleshooting_cases)
    else:
        lines.append("- No local troubleshooting cases file was loaded.")
    lines.extend(_similar_incident_lines(request))
    lines.extend(_feedback_hint_lines(request))
    lines.extend(
        [
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


def _similar_incident_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "## Similar Incidents", ""]
    if not request.similar_incidents:
        return [*lines, "- No similar incident memory was provided."]
    for item in request.similar_incidents[:5]:
        feedback = (
            f"{item.positive_feedback} up / {item.negative_feedback} down / "
            f"{item.comment_count} comments"
        )
        lines.append(
            f"- {item.incident_id} ({item.similarity:.3f}, {feedback}): "
            f"{item.analysis_summary or item.title}"
        )
    return lines


def _feedback_hint_lines(request: AlertAnalysisRequest) -> list[str]:
    lines = ["", "## Feedback Learning Hints", ""]
    if not request.feedback_hints:
        return [*lines, "- No operator feedback hints were provided."]
    for hint in request.feedback_hints[:5]:
        lines.append(f"- {hint.sentiment} from {hint.source_id}: {hint.text}")
    return lines


def _chat_answer_from_context(
    request: ChatRequest,
    context: dict[str, object],
    entity: str,
    masker: Masker,
) -> str:
    question = masker.mask_text(request.message.strip())
    incident_content = masker.mask_text((request.incident_content or "").strip())
    alert_content = masker.mask_text((request.alert_content or "").strip())
    active_content = alert_content or incident_content
    title = request.alert_title or request.incident_title or str(entity)
    memory = context.get("rca_memory")
    similar = context.get("similar_incidents")
    missing = _context_list(context, "missing_data")
    warnings = _context_list(context, "warnings")

    lines = [
        "## RCA Chat",
        "",
        f"**Context:** {title}",
        f"**Question:** {question}",
        "",
    ]
    if active_content:
        lines.extend(
            [
                "## Grounded Answer",
                "",
                _focused_chat_response(question, active_content),
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## Grounded Answer",
                "",
                "No specific incident or alert RCA content is attached yet. "
                "Ask from an incident or alert detail page for a more grounded answer.",
                "",
            ]
        )

    memory_lines = _memory_lines(memory or similar)
    if memory_lines:
        lines.extend(["## Related RCA Memory", "", *memory_lines, ""])
    if missing:
        lines.extend(["## Missing Data", "", *[f"- {item}" for item in missing[:8]], ""])
    if warnings:
        lines.extend(["## Warnings", "", *[f"- {item}" for item in warnings[:8]], ""])
    lines.extend(
        [
            "## Next Step",
            "",
            "Use the RCA detail and Agent Evidence Trail to confirm this against Run:AI, "
            "Kubernetes, Prometheus, Loki, and Postgres evidence before taking action.",
        ]
    )
    return "\n".join(lines)


def _focused_chat_response(question: str, content: str) -> str:
    lowered = question.lower()
    excerpted = _compact_text(content, 1800)
    if any(word in lowered for word in ["action", "recommend", "next", "해야", "조치"]):
        return (
            "The recommended path should follow the RCA's manual actions. "
            f"Relevant RCA context:\n\n{excerpted}"
        )
    if any(word in lowered for word in ["evidence", "why", "근거", "왜"]):
        return (
            "The strongest answer should come from the attached evidence and missing-data list. "
            f"Relevant RCA context:\n\n{excerpted}"
        )
    if any(word in lowered for word in ["similar", "previous", "past", "유사", "이전"]):
        return (
            "Compare this incident with the related RCA memory below, "
            "then verify against live evidence. "
            f"Current RCA context:\n\n{excerpted}"
        )
    return f"Based on the attached RCA context:\n\n{excerpted}"


def _memory_lines(memory: object) -> list[str]:
    if not isinstance(memory, list):
        return []
    lines: list[str] = []
    for item in memory[:5]:
        if not isinstance(item, dict):
            continue
        incident_id = item.get("incident_id") or item.get("IncidentID") or "unknown"
        summary = item.get("analysis_summary") or item.get("AnalysisSummary") or item.get("title")
        similarity = item.get("similarity") or item.get("Similarity")
        if summary:
            lines.append(f"- {incident_id} ({similarity or 'memory'}): {summary}")
    return lines


def _context_list(context: dict[str, object], key: str) -> list[str]:
    value = context.get(key)
    if value is None and isinstance(context.get("incident"), dict):
        value = context["incident"].get(key)  # type: ignore[index]
    if value is None and isinstance(context.get("alert"), dict):
        value = context["alert"].get(key)  # type: ignore[index]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _compact_text(value: str, limit: int) -> str:
    cleaned = "\n".join(line.rstrip() for line in value.splitlines() if line.strip())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit].rstrip() + "\n\n[context truncated]"
