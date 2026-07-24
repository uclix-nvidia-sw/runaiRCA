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

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.config import load_settings
from app.knowledge import load_failure_modes
from app.schemas import Alert, AlertAnalysisRequest
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
    candidates = [RankedCause("workload_runtime_error", "high", 8.0)]

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


# --- translation-only synthesis (owner directive 2026-07-22) ------------------


@pytest.mark.asyncio
async def test_korean_synthesis_translates_deterministic_report_verbatim(monkeypatch) -> None:
    # Synthesis is a TRANSLATOR: the prompt must carry exactly the deterministic
    # summary+detail (no evidence JSON, no re-analysis inputs) and return the
    # localized pair.
    settings = replace(make_settings(), language="ko")
    captured = {}

    async def fake_complete_synthesis_json(settings, *, system, user, diagnostics=None):
        captured["system"] = system
        captured["user"] = user
        return {"summary": "한국어 요약", "detail": "# 한국어 본문"}

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    synth = await _synthesize_korean(
        settings,
        summary="Pod default/x is not ready. Likely cause: image pull failure.",
        fallback_detail="# 장애 분석 보고서\n\n- image pull failure evidence",
    )
    assert synth == ("한국어 요약", "# 한국어 본문")
    payload = json.loads(captured["user"])
    assert payload == {
        "summary": "Pod default/x is not ready. Likely cause: image pull failure.",
        "detail": "# 장애 분석 보고서\n\n- image pull failure evidence",
    }
    assert "번역" in captured["system"]
    # The translator prompt must not smuggle re-analysis material back in.
    assert "ranked_root_cause_candidates" not in captured["user"]
    assert "collector_findings" not in captured["user"]


@pytest.mark.asyncio
async def test_korean_synthesis_failure_keeps_deterministic_report(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")

    async def fake_complete_synthesis_json(settings, *, system, user, diagnostics=None):
        return None

    monkeypatch.setattr(
        "app.services.pipeline._complete_synthesis_json", fake_complete_synthesis_json
    )
    diagnostics: list[str] = []
    synth = await _synthesize_korean(
        settings,
        summary="summary",
        fallback_detail="detail",
        diagnostics=diagnostics,
    )
    assert synth is None
    assert diagnostics == ["synthesis returned no valid JSON report"]


# --- closed family universe (graph knowledge cannot mint headline families) ---


def test_catalog_only_knowledge_drops_llm_authored_graph_families(caplog) -> None:
    # 2026-07-22: an old ingest wrote 'workload_startup_image_failure' into
    # TypeDB; consumed as a curated symptom it displaced image_pull_error and
    # forced a harness abstain over 64 ImagePullBackOff warnings.
    from app.services.pipeline import _catalog_only_knowledge

    knowledge = {
        "image_pull_error": [{"symptom": "ImagePullBackOff", "keywords": ["imagepullbackoff"]}],
        "workload_startup_image_failure": [{"symptom": "invented", "keywords": ["imagepull"]}],
    }
    with caplog.at_level("WARNING"):
        kept = _catalog_only_knowledge(knowledge)
    assert set(kept) == {"image_pull_error"}
    assert "workload_startup_image_failure" in caplog.text

    # Catalog-only input passes through untouched; empty graph falls back.
    assert _catalog_only_knowledge({"image_pull_error": []}) == {"image_pull_error": []}
    assert _catalog_only_knowledge(None) == {}
