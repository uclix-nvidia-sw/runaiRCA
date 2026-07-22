"""Tests for the Korean-output / honest-no-evidence / graph-remediation additions.

Covers: (1) collectors emit the honest '증거를 찾기 어렵습니다.' marker on no-data
branches, (2) planner focuses namespace-less alerts on node/system level, (3) the
validated TypeDB reasoning functions are wired and degrade gracefully, (4) the
orchestrator waits for ALL collectors and runs Korean LLM synthesis when configured.
"""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import load_settings
from app.knowledge import load_failure_modes
from app.plan import InvestigationPlan
from app.schemas import Alert, AlertAnalysisRequest, SimilarIncidentContext
from app.services.kg_enrichment import GraphRemediation, graph_remediation
from app.services.orchestrator import AnalysisOrchestrator
from app.services.pipeline import (
    _SYNTHESIS_USER_CHARS,
    _complete_synthesis_json,
    _detail_from,
    _gpu_model_from,
    _graph_remediation_lines,
    _korean_report_language_conflict,
    _summary_from,
    _synthesis_evidence_json,
    _synthesize_korean,
    _xid_codes_from_results,
)
from app.services.planner import plan_investigation
from app.services.root_cause_ranking import RankedCause
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


def test_negated_xid_does_not_promote_gpu_hardware() -> None:
    results = [
        CollectorResult(
            agent="system",
            status="ok",
            summary="no Xid 79 observed; GPU healthy",
        )
    ]
    assert _xid_codes_from_results(results, "Xid 31 not observed in alert") == []


def test_gpu_model_derived_from_details() -> None:
    results = [SimpleNamespace(agent="prometheus", summary="", details={"gpu_model": "H100"})]
    assert _gpu_model_from(_target(), results) == "H100"


def test_graph_remediation_lines_render() -> None:
    fixes = GraphRemediation(
        family_fixes=["Reset the GPU / contact support api_key=graph-secret-12345.\n## bad"],
        xid_fixes={79: ["Reset the GPU / contact support password=graph-xid-secret-12345."]},
        model_xids={"H100\n## bad-model": [79]},
    )
    text = "\n".join(_graph_remediation_lines(fixes))
    assert "Knowledge-graph derived remediation" in text
    assert "NVIDIA Xid 79" in text
    assert "Known Xid codes for H100" in text
    assert "79" in text
    assert "graph-secret-12345" not in text
    assert "graph-xid-secret-12345" not in text
    assert "\n## bad" not in text
    assert "[MASKED]" in text
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
                                    '"detail": "## 1. 문제\\n\\n노드 디스크 압박 알림이 발생했습니다.\\n\\n'
                                    '## 2. 원인\\n\\n노드 디스크 압박입니다.\\n\\n'
                                    '## 3. 권장 조치\\n\\n1. `kubectl describe node`로 압박 조건과 이벤트를 확인하세요."}'
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
async def test_korean_synthesis_prompt_redacts_sensitive_evidence(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "SecretAlert", "namespace": "runai"},
            annotations={
                "summary": "token=alert-token-12345",
                "operator_prompt": "api_key=operator-key-12345",
            },
            fingerprint="fp-ko-secret",
        ),
        similar_incidents=[
            {
                "incident_id": "INC-SECRET",
                "similarity": 0.9,
                "analysis_summary": "client_secret=similar-secret-12345",
            }
        ],
    )

    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="DiskPressure=True password=collector-password-12345",
    )
    result.artifacts.append(
        artifact(
            agent="kubernetes",
            source="kubernetes",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            query="kubectl get events -n runai",
            summary="NVRM: Xid 79 token=artifact-token-12345",
            result={"lines": ["GPU has fallen off the bus api_key=artifact-key-12345"]},
        )
    )

    await _synthesize_korean(
        settings,
        request=request,
        results=[result],
        plan=InvestigationPlan(focus="password=plan-secret-12345"),
        root_cause_candidates=[
            RankedCause(
                family="node_kubelet_pressure",
                confidence="high",
                score=6.0,
                rationale=["api_key=rank-key-12345"],
            )
        ],
        kg_context={
            "prior_incidents": [{"analysis_summary": "token=kg-token-12345"}],
            "knowledge": {},
        },
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    joined = "\n".join(captured)
    for secret in [
        "alert-token-12345",
        "operator-key-12345",
        "similar-secret-12345",
        "collector-password-12345",
        "artifact-token-12345",
        "artifact-key-12345",
        "plan-secret-12345",
        "rank-key-12345",
        "kg-token-12345",
    ]:
        assert secret not in joined
    assert "NVRM: Xid 79" in joined
    assert "GPU has fallen off the bus" in joined
    assert "[MASKED]" in joined


@pytest.mark.asyncio
async def test_korean_synthesis_caps_large_artifact_prompt(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko", llm_model_synthesis="m")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = CollectorResult(agent="loki", status="ok", summary="errors")
    result.artifacts.append(
        artifact(
            agent="loki",
            source="loki",
            type="logs",
            status="ok",
            confidence="medium",
            summary="error rows",
            result={"lines": ["x" * 50_000]},
        )
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "RunAITest"}, annotations={})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="loki_errors", confidence="medium", score=1.0, rationale=[])
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert len(captured[0]) <= _SYNTHESIS_USER_CHARS
    assert "x" * 1300 not in captured[0]


@pytest.mark.asyncio
async def test_korean_synthesis_folds_operator_guidance_before_prompt(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIPending", "namespace": "runai"},
                annotations={
                    "summary": "GPU quota pending",
                    "operator_prompt": (
                        "사람 지시: gpu-a quota부터 확인하세요.\n"
                        "## Injected Heading\n"
                        + ("x" * 700)
                    ),
                },
            )
        ),
        results=[
            CollectorResult(
                agent="runai",
                status="ok",
                summary="queue gpu-a has no allocatable quota",
            )
        ],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="queue_quota_exhausted", confidence="high", score=9.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    guidance = payload["operator_guidance"]
    assert "\n" not in guidance
    assert len(guidance) <= 500
    assert "## Injected Heading" in guidance


@pytest.mark.asyncio
async def test_korean_synthesis_skips_unavailable_artifacts(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = CollectorResult(agent="postgres", status="ok", summary="base check complete")
    result.artifacts.extend(
        [
            artifact(
                agent="postgres",
                source="postgres",
                type="drilldown_query",
                status="ok",
                confidence="medium",
                summary="1 row(s)",
                result={"rows": [{"message": "scheduler panic at reclaim/reclaim.go:91"}]},
            ),
            artifact(
                agent="postgres",
                source="postgres",
                type="drilldown_query",
                status="unavailable",
                confidence="low",
                summary="failed query mentioned runtime/panic.go:785",
                result={"error": "runtime/panic.go:785"},
            ),
        ]
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="platform_version_bug", confidence="medium", score=7.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    joined = "\n".join(captured)
    assert "scheduler panic at reclaim/reclaim.go:91" in joined
    assert "runtime/panic.go:785" not in joined
    assert "failed query mentioned" not in joined


@pytest.mark.asyncio
async def test_korean_synthesis_withholds_graph_actions_without_scoped_support(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    class RejectedEligibility:
        def permits(self, _role: str) -> bool:
            return False

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericAlert"})
        ),
        results=[CollectorResult(agent="system", status="ok", summary="current snapshot only")],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="gpu_hardware_error", confidence="medium", score=7.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(
            family_fixes=["Reset the implicated GPU."],
            xid_fixes={79: ["Replace the GPU after hardware validation."]},
        ),
        fallback_detail="fallback",
        evidence_eligibility={"E01": RejectedEligibility()},
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    graph = payload["graph_remediation"]
    assert graph["family_fixes"] == []
    assert graph["xid_fixes"] == {}
    assert "no target/window-scoped supporting observation" in graph["warnings"][0]


@pytest.mark.asyncio
async def test_korean_synthesis_withholds_all_remediation_context_without_scoped_support(
    monkeypatch,
) -> None:
    """Catalog/prior/playbook inputs must not bypass the graph-only gate."""
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    class RejectedEligibility:
        def permits(self, _role: str) -> bool:
            return False

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericAlert"}),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="old",
                    similarity=0.99,
                    analysis_summary="UNSCOPED-PAST-REMEDY",
                )
            ],
        ),
        results=[CollectorResult(agent="system", status="ok", summary="context only")],
        plan=InvestigationPlan(
            matched_alert={"actions": ["UNSCOPED-CATALOG-REMEDY"]},
            case_cards=[{"action": "UNSCOPED-CASE-CARD"}],
        ),
        root_cause_candidates=[
            RankedCause(family="gpu_hardware_error", confidence="medium", score=7.0)
        ],
        kg_context={
            "knowledge": {"gpu_hardware_error": [{"actions": ["UNSCOPED-KB-REMEDY"]}]},
            "prior_incidents": [{"analysis_summary": "UNSCOPED-PRIOR-REMEDY"}],
            "case_cards": [{"action": "UNSCOPED-KG-CASE"}],
        },
        graph_fixes=GraphRemediation(family_fixes=["UNSCOPED-GRAPH-REMEDY"]),
        fallback_detail="fallback",
        troubleshooting_path={"path": ["UNSCOPED-PATH-REMEDY"]},
        evidence_eligibility={"E01": RejectedEligibility()},
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    assert payload["remediation_evidence"]["scoped_support"] is False
    assert payload["matched_alert"] is None
    assert payload["similar_incidents"] == []
    assert "troubleshooting_path" not in payload
    assert payload["knowledge_graph"]["knowledge"] == {}
    assert payload["plan"]["case_cards"] == []
    for forbidden in (
        "UNSCOPED-CATALOG-REMEDY",
        "UNSCOPED-CASE-CARD",
        "UNSCOPED-KB-REMEDY",
        "UNSCOPED-PRIOR-REMEDY",
        "UNSCOPED-KG-CASE",
        "UNSCOPED-GRAPH-REMEDY",
        "UNSCOPED-PAST-REMEDY",
        "UNSCOPED-PATH-REMEDY",
    ):
        assert forbidden not in captured[0]


@pytest.mark.asyncio
async def test_korean_synthesis_sanitizes_unavailable_collector_summary(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericAlert"})
        ),
        results=[
            CollectorResult(
                agent="kubernetes",
                status="unavailable",
                summary="kubectl failed; stale output mentioned DiskPressure and evicted pods",
            )
        ],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    joined = "\n".join(captured)
    assert "DiskPressure" not in joined
    assert "evicted pods" not in joined
    assert NO_EVIDENCE in joined


@pytest.mark.asyncio
async def test_korean_synthesis_exposes_condition_polarity(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="node checked")
    result.artifacts.append(
        artifact(
            agent="kubernetes",
            source="kubernetes",
            type="cluster_api",
            status="ok",
            confidence="high",
            summary="node conditions checked",
            result={
                "conditions": [
                    {"type": "MemoryPressure", "status": "False"},
                    {"type": "DiskPressure", "status": "True"},
                ]
            },
        )
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "NodeCondition"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="node_kubelet_pressure", confidence="medium", score=5.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    context = payload["collector_findings"][0]["context_artifacts"][0]
    checks = context["condition_checks"]
    assert checks == [
        {
            "condition": "MemoryPressure",
            "active": False,
            "source": "kubernetes_condition",
            "status": "False",
        },
        {
            "condition": "DiskPressure",
            "active": True,
            "source": "kubernetes_condition",
            "status": "True",
        },
    ]
    # The canonical checks retain both polarities. The raw prompt projection
    # must not repeat a healthy condition's failure-looking type/reason.
    assert "MemoryPressure" not in context["result"]
    assert "DiskPressure" in context["result"]


@pytest.mark.asyncio
async def test_korean_synthesis_rejects_all_false_conditions_promoted_as_active(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {
            "summary": "네 가지 노드 압박 조건이 동시에 감지되었습니다.",
            "detail": (
                "MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable가 "
                "동시에 감지되어 플랫폼 가용성에 영향을 주었습니다 [E16]."
            ),
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="adhoc_query",
        status="ok",
        confidence="medium",
        summary="특이 신호 없음 (HTTP 200)",
        result={
            "data": {
                "name": "k8s-lb-02",
                "conditions": [
                    {"type": "NetworkUnavailable", "status": "False", "reason": "CalicoIsUp"},
                    {"type": "MemoryPressure", "status": "False"},
                    {"type": "DiskPressure", "status": "False"},
                    {"type": "PIDPressure", "status": "False"},
                    {"truncated": 1},
                ],
            },
            "observation": {"polarity": "unknown", "coverage": "partial"},
        },
    )
    finding.evidence_id = "E16"
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="node checked", artifacts=[finding]
    )

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericNodeAlert"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="node_kubelet_pressure", confidence="medium", score=5.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized is None


@pytest.mark.asyncio
async def test_korean_synthesis_allows_real_incident_negative_memorypressure_claim(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {
            "summary": "단일 노드에 가용 GPU가 부족해 파드가 스케줄링되지 않았습니다.",
            "detail": (
                "이는 노드 압박(MemoryPressure 등)이 아닌 순수 스케줄링 자원 부족"
                "(단편화/과할당) 사례로, 단일 노드에 8 GPU를 배치할 수 없어 발생했습니다."
            ),
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_node_condition",
        status="ok",
        confidence="high",
        summary="MemoryPressure=False",
        result={
            "conditions": [{"type": "MemoryPressure", "status": "False"}],
            "observation": {"polarity": "absent", "coverage": "scoped"},
        },
    )
    finding.evidence_id = "E01"

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "KubePodNotReady"})
        ),
        results=[
            CollectorResult(
                agent="kubernetes", status="ok", summary="node checked", artifacts=[finding]
            )
        ],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="k8s_scheduling_error", confidence="high", score=8.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized is not None
    assert "MemoryPressure 등)이 아닌" in synthesized[1]


@pytest.mark.asyncio
async def test_korean_synthesis_still_rejects_positive_signal_after_negative_signal(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {
            "summary": "노드 상태를 확인했습니다.",
            "detail": "MemoryPressure가 아니지만 DiskPressure가 발생했습니다.",
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericNodeAlert"})
        ),
        results=[CollectorResult(agent="kubernetes", status="ok", summary="node checked")],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="k8s_scheduling_error", confidence="medium", score=5.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized is None


@pytest.mark.asyncio
async def test_korean_synthesis_allows_active_supported_condition(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {
            "summary": "노드에서 DiskPressure가 감지되었습니다.",
            "detail": "DiskPressure=True가 관찰되었습니다 [E01].",
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_node_condition",
        status="ok",
        confidence="high",
        summary="DiskPressure=True",
        result={
            "conditions": [{"type": "DiskPressure", "status": "True"}],
            "observation": {"polarity": "present", "coverage": "scoped"},
        },
    )
    finding.evidence_id = "E01"
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="pressure observed", artifacts=[finding]
    )

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericNodeAlert"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="node_kubelet_pressure", confidence="high", score=8.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized == (
        "노드에서 DiskPressure가 감지되었습니다.",
        "DiskPressure=True가 관찰되었습니다 [E01].",
    )


@pytest.mark.asyncio
async def test_korean_synthesis_drops_preemption_policy_and_rejects_preempt_claim(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {
            "summary": "파드 선점이 발생했습니다.",
            "detail": "Preempt가 실제로 확인되었습니다 [E31].",
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="adhoc_query",
        status="ok",
        confidence="medium",
        summary="특이 신호 없음 (HTTP 200)",
        result={
            "data": {
                "spec": {"preemptionPolicy": "PreemptLowerPriority"},
                "status": {"phase": "Running"},
            },
            "observation": {"polarity": "unknown", "coverage": "partial"},
        },
    )
    finding.evidence_id = "E31"
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="pod checked", artifacts=[finding]
    )

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericPodAlert"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="k8s_scheduling_error", confidence="medium", score=4.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized is None
    assert "PreemptLowerPriority" not in captured[0]


@pytest.mark.asyncio
async def test_korean_synthesis_rejects_private_fact_citation(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {"summary": "일반 요약", "detail": "내부 관측을 인용합니다 [F-143f004a83de2a40]."}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )

    synthesized = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "GenericAlert"})
        ),
        results=[],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert synthesized is None


@pytest.mark.asyncio
async def test_korean_synthesis_does_not_recommend_completed_readonly_checks(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")
    captured: dict[str, str] = {}

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured["system"] = system
        captured["user"] = user
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="node GPU checked")
    result.artifacts.append(
        artifact(
            agent="kubernetes",
            source="kubernetes",
            type="node_gpu_inventory",
            status="ok",
            confidence="medium",
            summary="dgx02 GPU capacity and pod requests were collected",
            result={
                "nodes": [
                    {
                        "name": "dgx02",
                        "capacity": 8,
                        "allocatable": 8,
                        "requested": 8,
                    }
                ],
                "observation": {"polarity": "unknown", "coverage": "partial"},
                "snapshot_role": "current_context",
            },
        )
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "PendingGPUWorkload"})
        ),
        results=[result],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="k8s_scheduling_error", confidence="medium", score=5.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    payload = json.loads(captured["user"].removeprefix("증거(JSON):\n"))
    context = payload["collector_findings"][0]["context_artifacts"][0]
    assert context["status"] == "ok"
    assert "dgx02" in context["result"]
    assert "같은 명령을 다시 실행하라고 하지 마세요" in captured["system"]
    assert "context_artifact라는 이유만으로 완료된 조회" in captured["system"]


@pytest.mark.asyncio
async def test_korean_synthesis_skips_unrelated_similar_incident(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )

    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NCCLTimeout", "namespace": "runai"},
                annotations={
                    "summary": "NCCL WARN socket timeout and ibv_poll_cq failed during allreduce"
                },
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-OLD",
                    similarity=0.98,
                    title="old Run:ai control-plane auth incident",
                    analysis_summary="restart cluster-sync and rotate SAML credentials",
                )
            ],
        ),
        results=[
            CollectorResult(
                agent="loki",
                status="ok",
                summary="NCCL WARN socket timeout and ibv_poll_cq failed during allreduce",
            )
        ],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="network_fabric_error", confidence="high", score=8.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    joined = "\n".join(captured)
    assert "NCCL WARN" in joined
    assert "INC-OLD" not in joined
    assert "cluster-sync" not in joined
    assert "SAML" not in joined


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
    # A configured primary synthesis failure is a failed run, not a successful
    # RCA disguised by the deterministic diagnostic payload.
    assert response.status == "failed"
    assert response.terminal_reason == "synthesis_failed"
    assert response.analysis_quality == "degraded"
    assert response.context["synthesis"]["status"] == "failed"
    assert "invalid JSON" in response.context["synthesis"]["error"]
    assert "## 2. 원인" in response.analysis_detail
    assert "Agent Role Coverage" not in response.analysis_detail  # static boilerplate removed


@pytest.mark.asyncio
async def test_korean_synthesis_rejects_summary_only_json(monkeypatch, caplog) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(*_args, **_kwargs):
        return {"summary": "요약만 반환됨"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "Test"}, annotations={})
        ),
        results=[],
        plan=InvestigationPlan(),
        root_cause_candidates=[],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
    )

    assert result is None
    assert "omitted detail" in caplog.text


@pytest.mark.asyncio
async def test_korean_synthesis_retries_json_missing_detail(monkeypatch, caplog) -> None:
    settings = replace(make_settings(), language="ko")
    replies = [
        '{"summary":"요약만 반환됨"}',
        '{"summary":"정상 요약","detail":"정상 본문"}',
    ]

    async def fake_complete_with_error(*_args, **_kwargs):
        return replies.pop(0), None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result = await _complete_synthesis_json(settings, system="system", user="user")

    assert result == {"summary": "정상 요약", "detail": "정상 본문"}
    assert not replies
    assert "omitted required field(s) detail (attempt 1); retrying" in caplog.text


@pytest.mark.asyncio
async def test_korean_synthesis_does_not_retry_transport_failure(monkeypatch, caplog) -> None:
    settings = replace(make_settings(), language="ko")
    calls = 0

    async def fake_complete_with_error(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return None, "HTTP 504 gateway timeout"

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    diagnostics: list[str] = []
    result = await _complete_synthesis_json(
        settings, system="system", user="user", diagnostics=diagnostics
    )

    assert result is None
    assert calls == 1
    assert "HTTP 504 gateway timeout" in caplog.text
    assert diagnostics and "HTTP 504 gateway timeout" in diagnostics[0]


def test_jwks_discovery_failure_overrides_generic_crashloop_playbook_in_korean() -> None:
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={
                "alertname": "KubePodCrashLooping",
                "namespace": "runai-rca",
                "pod": "runai-rca-runai-mcp-abc",
            },
            annotations={"summary": "runai-mcp CrashLoopBackOff"},
            fingerprint="fp-jwks-discovery",
        )
    )
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=(
                "init jwks verifier: jwks verifier: decode discovery doc: "
                "invalid character '<' looking for beginning of value"
            ),
        )
    ]
    candidates = [RankedCause("workload_startup_error", "medium", 4.0)]

    summary = _summary_from(
        request, results, candidates, failure_modes, language="ko"
    )
    detail = _detail_from(
        request,
        results,
        [],
        failure_modes=failure_modes,
        root_cause_candidates=candidates,
        language="ko",
    )

    assert "OIDC JSON 문서 대신 HTML" in summary
    assert "runaiMcp.oidcIssuerUrl" in detail
    assert "agent.env.runaiTokenUrl=https://<runai-host>/api/v1/token" in detail
    assert "OOM" not in detail
    assert "bad entrypoint" not in detail


def test_oomkilled_overrides_generic_crashloop_actions_in_korean_fallback() -> None:
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={
                "alertname": "KubePodCrashLooping",
                "namespace": "default",
                "pod": "memory-stress",
                "container": "memory-stress",
            },
            annotations={"summary": "memory-stress CrashLoopBackOff"},
            fingerprint="fp-memory-stress-oom",
        )
    )
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=(
                "target container memory-stress lastState terminated reason=OOMKilled "
                "exit code 137; resources limits memory=256Mi; MemoryPressure=False"
            ),
        )
    ]
    candidates = [RankedCause("workload_startup_error", "high", 8.0)]

    summary = _summary_from(
        request, results, candidates, failure_modes, language="ko"
    )
    detail = _detail_from(
        request,
        results,
        [],
        failure_modes=failure_modes,
        root_cause_candidates=candidates,
        language="ko",
    )

    assert "메모리 제한을 초과해 OOMKilled" in summary
    assert "resources.limits.memory" in detail
    assert "작업 메모리 설정을 limit 아래로" in detail
    assert "restart count 증가" in detail
    assert "entrypoint" not in detail.lower()
    assert "secretkeyref" not in detail.lower()
    assert "errimageneverpull" not in detail.lower()


def test_image_pull_deterministic_fallback_keeps_core_report_korean() -> None:
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={
                "alertname": "KubePodNotReady",
                "namespace": "default",
                "pod": "imagepull-abc",
            },
            annotations={
                "summary": "Pod default/imagepull-abc has been non-ready for 15 minutes."
            },
        )
    )
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=(
                "ImagePullBackOff: pull access denied, repository does not exist or may "
                "require authorization"
            ),
        )
    ]
    candidates = [RankedCause("image_pull_error", "high", 8.0)]

    summary = _summary_from(request, results, candidates, failure_modes, language="ko")
    detail = _detail_from(
        request,
        results,
        [],
        failure_modes=failure_modes,
        root_cause_candidates=candidates,
        language="ko",
    )
    core = detail.split("## 부록", 1)[0]

    assert "구분할 수 없습니다" in summary
    assert "대상 Pod가 15분 이상 Ready 상태가 되지 않아" in core
    assert "kubectl describe pod" in core
    assert "ImagePullSecret" in core
    assert "Check that the ImagePullSecret" not in core


def test_image_pull_actions_ignore_family_wide_graph_siblings() -> None:
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={
                "alertname": "KubePodNotReady",
                "namespace": "default",
                "pod": "imagepull-abc",
            },
        )
    )
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary=(
                "ImagePullBackOff: pull access denied, repository does not exist or may "
                "require authorization, insufficient_scope"
            ),
        )
    ]
    graph = GraphRemediation(
        family_fixes=[
            "RATE-LIMIT-SIBLING",
            "TLS-SIBLING",
            "AUTH-SIBLING",
        ]
    )

    detail = _detail_from(
        request,
        results,
        [],
        failure_modes=failure_modes,
        root_cause_candidates=[RankedCause("image_pull_error", "high", 8.0)],
        graph_fixes=graph,
        language="ko",
        self_check_next=(
            "해당 이미지가 레지스트리에 존재하고 현재 ServiceAccount에 pull 권한이 있는지 "
            "영향받은 노드에서 `crictl pull`로 확인하세요."
        ),
    )
    actions = detail.split("## 3. 권장 조치", 1)[1].split("## 부록", 1)[0]
    appendix = detail.split("### Troubleshooting Playbook", 1)[1]

    assert "RATE-LIMIT-SIBLING" not in actions
    assert "TLS-SIBLING" not in actions
    assert "AUTH-SIBLING" not in actions
    assert actions.index("crictl pull") < actions.index("ImagePullSecret")
    assert "ImagePullSecret" in actions
    assert "rate-limit" not in actions
    assert "TLS 인증서" not in actions
    assert "같은 family의 대안 symptom" in appendix
    assert "toomanyrequests" in appendix
    assert "x509" in appendix
    assert "ImagePullSecret을 추가하세요" not in appendix


def test_korean_language_guard_rejects_english_recommended_actions() -> None:
    detail = """## 1. 문제 (Problem)

이미지 pull이 실패했습니다.

## 2. 원인 (Root Cause)

레지스트리 인증을 확인해야 합니다.

## 3. 권장 조치 (Recommended Actions)

1. The registry rejected the pull because the anonymous pull limit was hit.
2. Add the registry CA certificate to every node.

## 부록 (Appendix)
"""

    conflict = _korean_report_language_conflict("이미지 pull 실패", detail)

    assert "English-only" in conflict


@pytest.mark.asyncio
async def test_korean_synthesis_falls_back_when_actions_are_english(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    diagnostics: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        return {
            "summary": "이미지 pull 실패 원인을 분석했습니다.",
            "detail": """## 1. 문제 (Problem)
이미지 pull이 실패했습니다.
## 2. 원인 (Root Cause)
레지스트리 응답을 확인해야 합니다.
## 3. 권장 조치 (Recommended Actions)
1. Retry after the rate-limit window resets.
## 부록 (Appendix)
수집 증거를 기록했습니다.
""",
        }

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    result = await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "ImagePullBackOff"})
        ),
        results=[],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="image_pull_error", confidence="medium", score=5.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="deterministic fallback",
        diagnostics=diagnostics,
    )

    assert result is None
    assert any("language guard" in item for item in diagnostics)


@pytest.mark.asyncio
async def test_korean_synthesis_withholds_family_wide_graph_actions_with_support(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    class SupportedEligibility:
        def permits(self, role: str) -> bool:
            return role == "support"

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "ImagePullBackOff"})
        ),
        results=[],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="image_pull_error", confidence="medium", score=7.0)
        ],
        kg_context={},
        graph_fixes=GraphRemediation(
            family_fixes=["RATE-LIMIT-SIBLING"],
            verified_actions=["TLS-SIBLING"],
            xid_fixes={79: ["XID-SPECIFIC", "GPU 연결 상태를 점검하세요."]},
        ),
        fallback_detail="fallback",
        evidence_eligibility={"E01": SupportedEligibility()},
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    graph_payload = payload["graph_remediation"]
    assert graph_payload["family_fixes"] == []
    assert graph_payload["verified_actions"] == []
    assert graph_payload["xid_fixes"] == {"79": ["GPU 연결 상태를 점검하세요."]}


@pytest.mark.asyncio
async def test_korean_synthesis_prioritizes_matched_symptom_and_labels_family_siblings(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")
    captured: list[str] = []
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured.append(user)
        return {"summary": "요약", "detail": "본문"}

    class SupportedEligibility:
        def permits(self, role: str) -> bool:
            return role == "support"

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "ImagePullBackOff"})
        ),
        results=[
            CollectorResult(
                agent="kubernetes",
                status="ok",
                summary=(
                    "ImagePullBackOff: pull access denied, repository does not exist "
                    "or may require authorization"
                ),
            )
        ],
        plan=InvestigationPlan(),
        root_cause_candidates=[
            RankedCause(family="image_pull_error", confidence="high", score=8.0)
        ],
        kg_context={"knowledge": failure_modes},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
        evidence_eligibility={"E01": SupportedEligibility()},
    )

    payload = json.loads(captured[0].removeprefix("증거(JSON):\n"))
    graph_knowledge = payload["knowledge_graph"]
    selected = graph_knowledge["knowledge"]["image_pull_error"]
    supplemental = graph_knowledge["family_supplemental"]
    assert len(selected) == 1
    assert selected[0]["symptom"] == "이미지 repository 존재 여부 또는 권한 불명확"
    assert selected[0]["evidence_matched"] is True
    assert all(item["evidence_matched"] is False for item in supplemental)
    assert any("pull 요청 제한" in item["symptom"] for item in supplemental)
    assert all("actions" not in item for item in supplemental)
    assert all(item["distinguishing_signals"] for item in supplemental)


@pytest.mark.asyncio
async def test_korean_synthesis_receives_specific_self_check_findings(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    captured: dict[str, str] = {}

    async def fake_complete_synthesis_json(settings, *, system, user):
        captured["system"] = system
        captured["user"] = user
        return {"summary": "요약", "detail": "본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    await _synthesize_korean(
        settings,
        request=AlertAnalysisRequest(
            alert=Alert(status="firing", labels={"alertname": "KubePodCrashLooping"})
        ),
        results=[],
        plan=InvestigationPlan(),
        root_cause_candidates=[],
        kg_context={},
        graph_fixes=GraphRemediation(),
        fallback_detail="fallback",
        self_check_caveat=(
            "JWKS verifier discovery 문서가 JSON이 아니라 HTML이라 파싱에 실패했습니다."
        ),
        self_check_refuted=True,
        self_check_next="OIDC issuer 설정을 확인하세요.",
        reanalysis_note="범용 startup 원인을 반증하고 재분석했습니다.",
    )

    payload = json.loads(captured["user"].removeprefix("증거(JSON):\n"))
    assert payload["self_check"] == {
        "refuted": True,
        "caveat": "JWKS verifier discovery 문서가 JSON이 아니라 HTML이라 파싱에 실패했습니다.",
        "next_check": "OIDC issuer 설정을 확인하세요.",
        "reanalysis_note": "범용 startup 원인을 반증하고 재분석했습니다.",
    }
    assert "구체적인 로그 기반 오류" in captured["system"]


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


def test_synthesis_evidence_json_is_valid_under_heavy_load() -> None:
    # A blunt string slice used to hand the model malformed JSON. The cap must
    # trim at the DATA level (drop lowest-priority collectors from the end) so
    # the evidence is always parseable and the leading reasoning inputs survive.
    heavy = {
        "operator_guidance": "GPU 하드웨어부터 확인하라." * 5,
        "alert": {"name": "KubePodNotReady"},
        "plan": {"narrative": "N" * 400},
        "ranked_root_cause_candidates": [{"family": "gpu_hardware_error"}] * 3,
        "graph_remediation": {"family_fixes": ["fix" * 20] * 5},
        "collector_findings": [
            {"agent": a, "summary": "S" * 300,
             "artifacts": [{"result": "R" * 1200, "summary": "f" * 200} for _ in range(3)]}
            for a in ["runai", "kubernetes", "postgres", "prometheus", "loki", "system", "change"]
        ],
    }
    out = _synthesis_evidence_json(heavy, _SYNTHESIS_USER_CHARS)
    assert len(out) <= _SYNTHESIS_USER_CHARS
    parsed = json.loads(out)  # MUST NOT raise — valid JSON, not a mid-structure cut
    # Human directive + graph-derived fixes are never dropped.
    assert parsed["operator_guidance"].startswith("GPU")
    assert "graph_remediation" in parsed
    # At least the highest-priority collectors survive; drops come from the end.
    assert parsed["collector_findings"]
    assert parsed["collector_findings"][0]["agent"] == "runai"


def test_synthesis_evidence_json_keeps_everything_when_small() -> None:
    small = {"operator_guidance": "x", "collector_findings": [{"agent": "runai", "summary": "ok"}]}
    parsed = json.loads(_synthesis_evidence_json(small, _SYNTHESIS_USER_CHARS))
    assert len(parsed["collector_findings"]) == 1  # nothing dropped under the cap
