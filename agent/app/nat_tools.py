from __future__ import annotations

import json
from typing import Any

from nat.plugin_api import Builder, FunctionBaseConfig, FunctionInfo, register_function

from app.collectors.base import CollectorResult, resolve_target
from app.collectors.change import ChangeCollector
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.collectors.system import SystemCollector
from app.config import load_settings
from app.knowledge import load_troubleshooting_cases
from app.masking import build_masker
from app.prompts import agent_role_coverage_lines, load_agent_souls
from app.schemas import AlertAnalysisRequest


class RunAIContextConfig(FunctionBaseConfig, name="runai_context"):
    """Collect Run:ai API workload, project, queue, quota; no CLI by default."""


class KubernetesContextConfig(FunctionBaseConfig, name="kubernetes_context"):
    """Collect workload and Run:ai control-plane pod/event/node evidence."""


class PostgresContextConfig(FunctionBaseConfig, name="postgres_context"):
    """Collect RCA store, pgvector, feedback, comments, and persistence health context."""


class PrometheusContextConfig(FunctionBaseConfig, name="prometheus_context"):
    """Collect Prometheus GPU, scheduling, pod, restart, CPU, and memory metric evidence."""


class LokiContextConfig(FunctionBaseConfig, name="loki_context"):
    """Collect workload logs plus runai/runai-backend control-plane and backend log evidence."""


class SystemContextConfig(FunctionBaseConfig, name="system_context"):
    """Collect node-level dmesg/journal/syslog and NVIDIA XID evidence."""


class ChangeContextConfig(FunctionBaseConfig, name="change_context"):
    """Collect recent workload, controller, node-condition, and event changes."""


class TroubleshootingCasesConfig(FunctionBaseConfig, name="troubleshooting_cases"):
    """Load known Run:ai troubleshooting cases and operator playbook hints."""


class AnalysisMemoryConfig(FunctionBaseConfig, name="analysis_memory"):
    """Load similar incidents and operator feedback hints from the analysis request."""


class AnalysisAgentConfig(FunctionBaseConfig, name="analysis_agent"):
    """Own final KubeRCA-style RCA analysis, evidence review, confidence, and operator actions."""


class SynthesizeRunAIRCACfg(FunctionBaseConfig, name="synthesize_runai_rca"):
    """Backward-compatible alias for the Analysis Agent RCA report function."""


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


@register_function(config_type=SystemContextConfig)
async def system_context(_config: SystemContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, SystemCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=SystemContextConfig.__doc__ or "")


@register_function(config_type=ChangeContextConfig)
async def change_context(_config: ChangeContextConfig, _builder: Builder):
    async def _collect(input_message: str) -> str:
        return await _run_collector(input_message, ChangeCollector(load_settings()))

    yield FunctionInfo.from_fn(_collect, description=ChangeContextConfig.__doc__ or "")


@register_function(config_type=TroubleshootingCasesConfig)
async def troubleshooting_cases(_config: TroubleshootingCasesConfig, _builder: Builder):
    async def _load(_input_message: str) -> str:
        settings = load_settings()
        cases = load_troubleshooting_cases(settings.troubleshooting_cases_file)
        return cases or "No troubleshooting cases file was loaded."

    yield FunctionInfo.from_fn(_load, description=TroubleshootingCasesConfig.__doc__ or "")


@register_function(config_type=AnalysisMemoryConfig)
async def analysis_memory(_config: AnalysisMemoryConfig, _builder: Builder):
    async def _load(input_message: str) -> str:
        settings = load_settings()
        masker = build_masker(
            settings.masking_regex_list,
            builtin_enabled=settings.builtin_redaction_enabled,
            hash_mode=settings.builtin_redaction_hash_mode,
        )
        request = _parse_payload(input_message)
        payload = {
            "similar_incidents": [
                item.model_dump(mode="json") for item in request.similar_incidents
            ],
            "feedback_hints": [
                item.model_dump(mode="json") for item in request.feedback_hints
            ],
        }
        return json.dumps(masker.mask_object(payload), indent=2, sort_keys=True)

    yield FunctionInfo.from_fn(_load, description=AnalysisMemoryConfig.__doc__ or "")


@register_function(config_type=AnalysisAgentConfig)
async def analysis_agent(_config: AnalysisAgentConfig, _builder: Builder):
    async def _analyze(evidence_text: str) -> str:
        return _synthesize_report(evidence_text)

    yield FunctionInfo.from_fn(_analyze, description=AnalysisAgentConfig.__doc__ or "")


@register_function(config_type=SynthesizeRunAIRCACfg)
async def synthesize_runai_rca(_config: SynthesizeRunAIRCACfg, _builder: Builder):
    async def _synthesize(evidence_text: str) -> str:
        return _synthesize_report(evidence_text)

    yield FunctionInfo.from_fn(_synthesize, description=SynthesizeRunAIRCACfg.__doc__ or "")


async def _run_collector(payload: str, collector: Any) -> str:
    request = _parse_payload(payload)
    target = resolve_target(request.alert.labels, request.alert.annotations)
    result = await collector.collect(target)
    settings = load_settings()
    masker = build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )
    safe_result = masker.mask_object(_collector_result_to_dict(result))
    return json.dumps(safe_result, indent=2, sort_keys=True)


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
    settings = load_settings()
    masker = build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )
    cases = load_troubleshooting_cases(settings.troubleshooting_cases_file)
    agent_souls = load_agent_souls(settings.agent_souls_file)
    role_guidance = (
        "Agent role contracts were loaded."
        if agent_souls
        else "Fallback agent role contracts were used."
    )
    report = "\n".join(
        [
            "## Root Cause",
            "",
            "NeMo Agent Toolkit collected component evidence for the Run:ai incident. "
            "Use the per-agent findings below as the current RCA evidence set.",
            "",
            "## Agent Role Contract",
            "",
            *agent_role_coverage_lines(),
            "",
            "## Analysis Agent Verdict",
            "",
            "The Analysis Agent is responsible for the final RCA judgment, confidence, "
            "impact framing, missing-data callouts, and evidence-backed next actions.",
            "",
            "## Agent Evidence",
            "",
            "```text",
            evidence_text,
            "```",
            "",
            "## Troubleshooting Playbook",
            "",
            cases or "- No local troubleshooting cases file was loaded.",
            "",
            "## Runtime Guidance",
            "",
            role_guidance,
            "",
            "## Recommended Actions",
            "",
            "- Use collected Run:ai project, queue, and workload evidence when present.",
            "- Use collected Kubernetes pod, event, and node evidence when present.",
            "- Use collected Prometheus GPU, scheduling, CPU, and memory metrics when present.",
            "- Restore missing Run:ai, Loki, or Postgres integrations so the agent can "
            "attach those sources on the next analysis run.",
        ]
    )
    return masker.mask_text(report)
