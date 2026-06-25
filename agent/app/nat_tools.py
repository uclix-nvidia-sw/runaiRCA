from __future__ import annotations

import json
from typing import Any

from nat.plugin_api import Builder
from nat.plugin_api import FunctionBaseConfig
from nat.plugin_api import FunctionInfo
from nat.plugin_api import register_function

from app.collectors.base import CollectorResult
from app.collectors.base import resolve_target
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import load_settings
from app.schemas import AlertAnalysisRequest


class RunAIContextConfig(FunctionBaseConfig, name="runai_context"):
    """Collect Run:ai project, queue, workload, and scheduler context."""


class KubernetesContextConfig(FunctionBaseConfig, name="kubernetes_context"):
    """Collect Kubernetes pod, event, node, and controller context."""


class PostgresContextConfig(FunctionBaseConfig, name="postgres_context"):
    """Collect Postgres RCA store, pgvector, and transaction health context."""


class PrometheusContextConfig(FunctionBaseConfig, name="prometheus_context"):
    """Collect Prometheus metric context or prepare PromQL evidence queries."""


class LokiContextConfig(FunctionBaseConfig, name="loki_context"):
    """Collect Loki log context or prepare LogQL evidence queries."""


class SynthesizeRunAIRCACfg(FunctionBaseConfig, name="synthesize_runai_rca"):
    """Synthesize component evidence into a KubeRCA-style Run:ai RCA report."""


@register_function(config_type=RunAIContextConfig)
async def runai_context(_config: RunAIContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, RunAICollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=RunAIContextConfig.__doc__ or "")


@register_function(config_type=KubernetesContextConfig)
async def kubernetes_context(_config: KubernetesContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, KubernetesCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=KubernetesContextConfig.__doc__ or "")


@register_function(config_type=PostgresContextConfig)
async def postgres_context(_config: PostgresContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, PostgresCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=PostgresContextConfig.__doc__ or "")


@register_function(config_type=PrometheusContextConfig)
async def prometheus_context(_config: PrometheusContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, PrometheusCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=PrometheusContextConfig.__doc__ or "")


@register_function(config_type=LokiContextConfig)
async def loki_context(_config: LokiContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, LokiCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=LokiContextConfig.__doc__ or "")


@register_function(config_type=SynthesizeRunAIRCACfg)
async def synthesize_runai_rca(_config: SynthesizeRunAIRCACfg, _builder: Builder):
    async def _synthesize(evidence_text: str) -> str:
        return _synthesize_report(evidence_text)

    yield FunctionInfo.from_fn(_synthesize, description=SynthesizeRunAIRCACfg.__doc__ or "")


async def _run_collector(payload: str, collector: Any) -> str:
    request = _parse_payload(payload)
    target = resolve_target(request.alert.labels, request.alert.annotations)
    result = await collector.collect(target)
    return json.dumps(_collector_result_to_dict(result), indent=2, sort_keys=True)


def _parse_payload(payload: str) -> AlertAnalysisRequest:
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError:
        raw = {"alert": {"annotations": {"summary": payload}}}
    if "alert" not in raw:
        raw = {"alert": raw}
    return AlertAnalysisRequest.model_validate(raw)


def _collector_result_to_dict(result: CollectorResult) -> dict[str, Any]:
    return {
        "agent": result.agent,
        "status": result.status,
        "summary": result.summary,
        "confidence": result.confidence,
        "details": result.details,
        "missing_data": result.missing_data,
        "warnings": result.warnings,
        "artifacts": [artifact.model_dump(mode="json") for artifact in result.artifacts],
    }


def _synthesize_report(evidence_text: str) -> str:
    return "\n".join(
        [
            "## Root Cause",
            "",
            "NeMo Agent Toolkit collected component evidence for the Run:ai incident. "
            "Review the per-agent findings below and confirm against the live cluster.",
            "",
            "## Agent Evidence",
            "",
            "```text",
            evidence_text,
            "```",
            "",
            "## Recommended Actions",
            "",
            "- Check Run:ai project and queue saturation for the affected workload.",
            "- Review Kubernetes pod status, events, and node conditions.",
            "- Inspect Postgres RCA store health when incident persistence or similarity search is stale.",
            "- Compare Prometheus GPU, scheduling, CPU, and memory metrics around the alert window.",
            "- Inspect Loki workload logs for scheduling, startup, image, or runtime failures.",
        ]
    )
