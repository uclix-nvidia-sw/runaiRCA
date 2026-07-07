"""Tests for the Korean-output / honest-no-evidence / graph-remediation additions.

Covers: (1) collectors emit the honest '증거를 찾기 어렵습니다.' marker on no-data
branches, (2) planner focuses namespace-less alerts on node/system level, (3) the
validated TypeDB reasoning functions are wired and degrade gracefully, (4) the
orchestrator waits for ALL collectors and runs Korean LLM synthesis when configured.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import NO_EVIDENCE, AnalysisTarget
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import load_settings
from app.schemas import Alert, AlertAnalysisRequest
from app.services.kg_enrichment import GraphRemediation, graph_remediation
from app.services.orchestrator import AnalysisOrchestrator
from app.services.pipeline import (
    _gpu_model_from,
    _graph_remediation_lines,
    _xid_codes_from_results,
)
from app.services.planner import plan_investigation
from tests.test_orchestrator import make_settings, make_target


def _target(**overrides) -> AnalysisTarget:
    base = dict(
        cluster="", project="", queue="", namespace="", workload_name="",
        workload_type="", runai_workload_id="", node="", pod="",
        severity="warning", alert_name="RunAIAlert",
    )
    base.update(overrides)
    return AnalysisTarget(**base)


# --- honest no-evidence -------------------------------------------------------


@pytest.mark.asyncio
async def test_unconfigured_collectors_report_honest_gap() -> None:
    settings = make_settings()  # everything unconfigured
    for collector in (
        LokiCollector(settings),
        PrometheusCollector(settings),
        PostgresCollector(settings),
        RunAICollector(settings),
    ):
        result = await collector.collect(make_target())
        assert result.summary.startswith(NO_EVIDENCE), (
            f"{result.agent} no-data summary must lead with the honest gap marker"
        )


# --- namespace-less alert -> node/system focus --------------------------------


@pytest.mark.asyncio
async def test_namespace_less_alert_focuses_node_system() -> None:
    settings = make_settings()
    target = _target(alert_name="NodeSomething", node="gpu-node-1")  # no ns/project/queue
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.hypotheses[0]["family"] == "node_kubelet_pressure"
    assert "증거를 찾기 어렵습니다" in plan.narrative
    assert "system agent" in plan.narrative


@pytest.mark.asyncio
async def test_namespaced_alert_is_not_node_forced() -> None:
    settings = make_settings()
    target = _target(alert_name="RunAIWorkloadPending", namespace="team-a", queue="gpu-a")
    plan = await plan_investigation(settings, target, None, {}, [])
    # scheduling signal still leads for a namespaced/queue alert
    assert plan.hypotheses[0]["family"] == "runai_scheduling_quota"


# --- graph remediation (validated reasoning functions) ------------------------


@pytest.mark.asyncio
async def test_graph_remediation_disabled_returns_empty() -> None:
    # load_settings() defaults ENABLE_TYPEDB off -> no query, empty result.
    result = await graph_remediation(load_settings(), family="gpu_hardware_error")
    assert result.is_empty()
    assert result.warnings == []


@pytest.mark.asyncio
async def test_graph_remediation_no_inputs_returns_empty() -> None:
    settings = replace(make_settings(), enable_typedb=True, typedb_address="localhost:1729")
    result = await graph_remediation(settings)  # nothing to look up
    assert result.is_empty()


def test_xid_codes_extracted_from_gpu_evidence() -> None:
    results = [
        SimpleNamespace(
            agent="system",
            summary="NVRM: Xid (PCI:0000:3b:00): 79, pid=1234",
            details={"sources": [{"errors": ["Xid 79 fell off the bus"]}]},
        ),
        SimpleNamespace(agent="postgres", summary="ok", details={}),  # ignored
    ]
    assert _xid_codes_from_results(results) == [79]


def test_gpu_model_derived_from_details() -> None:
    results = [SimpleNamespace(agent="prometheus", summary="", details={"gpu_model": "H100"})]
    assert _gpu_model_from(_target(), results) == "H100"


def test_graph_remediation_lines_render() -> None:
    fixes = GraphRemediation(
        family_fixes=["Reset the GPU / contact support."],
        xid_fixes={79: ["Reset the GPU / contact support."]},
        model_xids={"H100": [79]},
    )
    text = "\n".join(_graph_remediation_lines(fixes))
    assert "Knowledge-graph derived remediation" in text
    assert "NVIDIA Xid 79" in text
    assert "Known Xid codes for H100: 79" in text
    assert _graph_remediation_lines(None) == []
    assert _graph_remediation_lines(GraphRemediation()) == []


# --- synthesis waits for ALL collectors + Korean LLM synthesis ----------------


@pytest.mark.asyncio
async def test_analyze_synthesis_sees_every_collector() -> None:
    # The all-collectors guard: every configured collector's result must be present.
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIWorkloadPending", "namespace": "runai-vision"},
                annotations={"summary": "pending"},
                fingerprint="fp-all",
            )
        )
    )
    assert set(response.capabilities) == {
        "runai", "kubernetes", "postgres", "prometheus", "loki", "system", "change"
    }


@pytest.mark.asyncio
async def test_korean_llm_synthesis_replaces_report(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        language="ko",
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"summary": "노드 디스크 압박이 근본 원인입니다.", '
                                '"detail": "## Root Cause\\n\\n노드 디스크 압박."}'
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NodeDiskPressure", "namespace": "monitoring"},
                annotations={"summary": "Node under disk pressure."},
                fingerprint="fp-ko",
            )
        )
    )

    assert response.analysis_summary == "노드 디스크 압박이 근본 원인입니다."
    assert "노드 디스크 압박" in response.analysis_detail
    assert response.analysis_detail == response.analysis


@pytest.mark.asyncio
async def test_korean_synthesis_falls_back_on_bad_json(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        language="ko",
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True, data={"choices": [{"message": {"content": "not json at all"}}]}
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NodeDiskPressure", "namespace": "monitoring"},
                annotations={"summary": "Node under disk pressure."},
                fingerprint="fp-ko-bad",
            )
        )
    )
    # Bad synthesis -> deterministic English report stands.
    assert "## 2. 원인" in response.analysis_detail
    assert "Agent Role Coverage" not in response.analysis_detail  # static boilerplate removed


@pytest.mark.asyncio
async def test_english_language_keeps_deterministic_report(monkeypatch) -> None:
    # language == "en" (default) never calls Korean synthesis even if LLM configured.
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    seen: list[str] = []

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        # Any LLM call (e.g. planner refinement) fails fast; record for the assert.
        seen.append(str(json_body))
        return SimpleNamespace(ok=False, data=None)

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NodeDiskPressure", "namespace": "monitoring"},
                annotations={"summary": "Node under disk pressure."},
                fingerprint="fp-en",
            )
        )
    )
    assert "## 2. Root Cause" in response.analysis_detail
    assert "Agent Role Coverage" not in response.analysis_detail  # static boilerplate removed
    # The Korean synthesis system prompt is Korean; it must never be sent for en.
    assert not any("한국어" in body for body in seen), "Korean synthesis must not run for en"
