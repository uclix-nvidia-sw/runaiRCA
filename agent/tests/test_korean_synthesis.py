"""Tests for the Korean-output / honest-no-evidence / graph-remediation additions.

Covers: (1) collectors emit the honest '증거를 찾기 어렵습니다.' marker on no-data
branches, (2) planner focuses namespace-less alerts on node/system level, (3) the
validated TypeDB reasoning functions are wired and degrade gracefully, (4) the
orchestrator waits for ALL collectors and runs Korean LLM synthesis when configured.
"""

from __future__ import annotations

import asyncio
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
    ReportKnowledge,
    _apply_line_translations,
    _detail_from,
    _gpu_model_from,
    _polite_ko,
    _summary_from,
    _translatable_report_lines,
    _translate_report_lines_ko,
    _xid_codes_from_results,
    _xid_diagnostic_guidance_lines,
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


def test_graph_derived_xid_text_is_masked_and_cannot_inject_headings() -> None:
    fixes = GraphRemediation(
        xid_triggers={79: "Reset the GPU / contact support password=graph-secret-12345.\n## bad"},
    )
    text = "\n".join(_xid_diagnostic_guidance_lines(fixes, "en"))
    assert "graph-secret-12345" not in text
    assert "\n## bad" not in text
    assert "[MASKED]" in text
    assert _xid_diagnostic_guidance_lines(None, "en") == []
    assert _xid_diagnostic_guidance_lines(GraphRemediation(), "en") == []


def test_graph_remediation_lines_name_the_xid() -> None:
    """A report must say what XID 79 IS ("GPU has fallen off the bus"), not
    just what to do about it -- the graph carries the catalog's own mnemonic/
    description/severity (kg_enrichment._fill_xid_detail) but nothing rendered
    them yet."""
    fixes = GraphRemediation(
        xid_fixes={79: ["Restart the baremetal host."]},
        xid_triggers={79: "Check for PCIe link errors before reset."},
        xid_mnemonics={79: "ROBUST_CHANNEL_GPU_HAS_FALLEN_OFF_THE_BUS"},
        xid_descriptions={79: "GPU has fallen off the bus"},
        xid_severities={79: "fatal"},
    )
    en_lines = _xid_diagnostic_guidance_lines(fixes, "en")
    assert en_lines and "GPU has fallen off the bus" in en_lines[0]
    assert "fatal" in en_lines[0]


def test_graph_remediation_lines_no_mnemonic_stays_clean() -> None:
    """An XID with fixes/triggers but no catalog entry anywhere -- not in the
    graph, and (code 999999 does not exist) not in the local xid_catalog.yaml
    fallback either -- must not invent a name, and must not leave a dangling
    empty clause (" -- ", "()") behind."""
    fixes = GraphRemediation(
        xid_fixes={999999: ["Run the app under compute-sanitizer."]},
        xid_triggers={999999: "GPU memory page fault."},
    )
    en_lines = _xid_diagnostic_guidance_lines(fixes, "en")
    assert en_lines == ["- Diagnostic guidance (XID 999999): GPU memory page fault."]
    assert " — " not in en_lines[0]
    assert "()" not in en_lines[0]


def test_xid_identity_falls_back_to_local_catalog_without_typedb() -> None:
    """A graph outage must degrade the wording, not delete it: with fixes/
    triggers present (e.g. from a stale ingest) but no detail_for_xid() result
    -- the same shape TypeDB being fully disabled produces -- the identity
    clause must still resolve from the shipped knowledge/xid_catalog.yaml."""
    fixes = GraphRemediation(
        xid_fixes={79: ["Restart the baremetal host."]},
        xid_triggers={79: "Check for PCIe link errors before reset."},
        # xid_mnemonics/xid_descriptions/xid_severities intentionally empty.
    )
    en_lines = _xid_diagnostic_guidance_lines(fixes, "en")
    assert en_lines and "GPU has fallen off the bus" in en_lines[0]
    assert "fatal" in en_lines[0]


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
async def test_korean_llm_synthesis_localizes_english_lines(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        language="ko",
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    sent: list[dict] = []

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        content = json_body["messages"][-1]["content"]
        try:
            pending = json.loads(content)
        except json.JSONDecodeError:
            pending = None
        # A Korean-translation batch is specifically dict[str, str]. Other
        # LLM-gated calls sharing this mock (plan refine's prose, operator-
        # question sharpening's dict[str, list]) are irrelevant here -- reply
        # harmlessly instead of forcing every caller through this shape.
        if not isinstance(pending, dict) or not all(
            isinstance(value, str) for value in pending.values()
        ):
            return SimpleNamespace(
                ok=True, data={"choices": [{"message": {"content": "{}"}}]}
            )
        sent.append(pending)
        # Echo every requested line, keeping backtick spans verbatim.
        translated = {key: f"[번역] {value}" for key, value in pending.items()}
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [
                    {"message": {"content": json.dumps(translated, ensure_ascii=False)}}
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

    assert response.context["synthesis"]["status"] == "completed"
    assert isinstance(response.context["synthesis"]["duration_seconds"], float)
    assert "[번역]" in response.analysis_detail
    assert response.analysis_detail == response.analysis
    # Structure is never sent to the model, so it cannot be rewritten.
    assert "## 2. 원인 (Root Cause)" in response.analysis_detail
    assert sent and all(
        not line.lstrip().startswith("#") for line in sent[0].values()
    )


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
    # Localization is presentation-only: keep the evidence-backed deterministic
    # RCA available, but mark its quality degraded and expose the warning.
    assert response.status == "ok"
    assert response.terminal_reason is None
    assert response.analysis_quality == "degraded"
    assert response.context["synthesis"]["status"] == "failed"
    assert "invalid JSON" in response.context["synthesis"]["error"]
    assert "## 2. 원인" in response.analysis_detail
    assert "Agent Role Coverage" not in response.analysis_detail  # static boilerplate removed




@pytest.mark.asyncio
async def test_korean_synthesis_reasks_only_the_missing_lines(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    detail = "Disk pressure was reported.\nThe kubelet started evicting pods."
    asked: list[dict] = []
    replies = [
        '{"0": "디스크 압박이 보고되었습니다."}',
        '{"1": "kubelet이 Pod를 축출하기 시작했습니다."}',
    ]

    async def fake_complete_with_error(*_args, **kwargs):
        asked.append(json.loads(kwargs["user"]))
        return replies.pop(0), None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert result == "디스크 압박이 보고되었습니다.\nkubelet이 Pod를 축출하기 시작했습니다."
    assert missing == 0
    assert [sorted(payload) for payload in asked] == [["0", "1"], ["1"]]


@pytest.mark.asyncio
async def test_korean_synthesis_keeps_commands_and_structure_out_of_the_prompt(
    monkeypatch,
) -> None:
    settings = replace(make_settings(), language="ko")
    detail = (
        "## 3. 권장 조치\n"
        "\n"
        "1. kubectl describe node dgx02\n"
        "2. Confirm the Secret exists in the SAME namespace with `kubectl get secret`.\n"
        "- 이미 한국어인 줄입니다.\n"
        "- `values.yaml`\n"
        "- https://docs.example/runbook\n"
        "\n"
        "```json\n"
        '{"alertname": "NodeDiskPressure"}\n'
        "```\n"
    )
    pending = _translatable_report_lines(detail)

    # Only the English prose line, and without its list prefix: the command,
    # the Korean line, the inline-code-only line, the bare URL, the heading and
    # the fenced block are all withheld.
    assert list(pending) == ["3"]
    assert pending["3"].startswith("Confirm the Secret")

    asked: list[dict] = []

    async def fake_complete_with_error(*_args, **kwargs):
        asked.append(json.loads(kwargs["user"]))
        return (
            '{"3": "동일한 네임스페이스에 Secret이 있는지 `kubectl get secret`으로 확인하세요."}',
            None,
        )

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert missing == 0
    assert "2. 동일한 네임스페이스에 Secret이 있는지" in result
    assert "1. kubectl describe node dgx02" in result
    assert '{"alertname": "NodeDiskPressure"}' in result
    assert "## 3. 권장 조치" in result


@pytest.mark.asyncio
async def test_korean_synthesis_rejects_a_mangled_command_span(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    detail = "Run `kubectl get secret app-secret` to confirm the Secret exists."

    async def fake_complete_with_error(*_args, **_kwargs):
        return '{"0": "`kubectl get secrets` 를 실행해 Secret 존재를 확인하세요."}', None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    # A mangled command span is rejected, so the line keeps its English text.
    result, missing = await _translate_report_lines_ko(settings, detail)
    assert result == detail
    assert missing == 1


@pytest.mark.asyncio
async def test_korean_report_needs_no_llm_call(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    calls = 0

    async def fake_complete_with_error(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return "{}", None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    detail = "## 1. 문제\n\n노드 디스크 압박 알림이 발생했습니다.\n"
    assert await _translate_report_lines_ko(settings, detail) == (detail, 0)
    assert calls == 0


def test_apply_line_translations_preserves_list_prefixes() -> None:
    detail = "- English bullet line here.\n2. Another English action line."
    assert _apply_line_translations(detail, {"0": "한국어 항목.", "1": "다른 항목."}) == (
        "- 한국어 항목.\n2. 다른 항목."
    )


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
    detail = "Disk pressure was reported on the node."
    result, missing = await _translate_report_lines_ko(settings, detail, diagnostics)

    assert (result, missing) == (detail, 1)
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
                 root_cause_candidates=candidates,
                 knowledge=ReportKnowledge(failure_modes=failure_modes, language="ko"),
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
                 root_cause_candidates=candidates,
                 knowledge=ReportKnowledge(failure_modes=failure_modes, language="ko"),
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
                 root_cause_candidates=candidates,
                 knowledge=ReportKnowledge(failure_modes=failure_modes, language="ko"),
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
                 root_cause_candidates=[RankedCause("image_pull_error", "high", 8.0)],
                 graph_fixes=graph,
                 self_check_next="해당 이미지가 레지스트리에 존재하고 현재 ServiceAccount에 pull 권한이 있는지 "
            "영향받은 노드에서 `crictl pull`로 확인하세요.",
                 knowledge=ReportKnowledge(failure_modes=failure_modes, language="ko"),
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


@pytest.mark.asyncio
async def test_korean_synthesis_prompt_carries_report_text_only(monkeypatch) -> None:
    # Synthesis is a TRANSLATOR: the prompt must carry report lines and nothing
    # that would let the model re-analyze.
    settings = replace(make_settings(), language="ko")
    captured: dict[str, str] = {}

    async def fake_complete_with_error(*_args, **kwargs):
        captured.update(kwargs)
        return '{"0": "이미지 pull 실패 증거입니다."}', None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result, missing = await _translate_report_lines_ko(
        settings, "- image pull failure evidence was collected"
    )

    assert (result, missing) == ("- 이미지 pull 실패 증거입니다.", 0)
    assert json.loads(captured["user"]) == {
        "0": "image pull failure evidence was collected"
    }
    assert "번역" in captured["system"]
    assert "ranked_root_cause_candidates" not in captured["user"]
    assert "collector_findings" not in captured["user"]


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


@pytest.mark.asyncio
async def test_long_report_is_translated_in_batches(monkeypatch) -> None:
    # A long report must not depend on one reply fitting under one completion
    # cap — that is how sections silently went missing.
    lines = [f"Collector {index} reported a scoped observation." for index in range(120)]
    detail = "\n".join(lines)
    batches: list[dict] = []

    async def fake_complete_with_error(*_args, **kwargs):
        pending = json.loads(kwargs["user"])
        batches.append(pending)
        assert kwargs["max_tokens"] < 16384, "batch must not request the full cap"
        return (
            json.dumps({key: f"수집기 관측 {key}." for key in pending}, ensure_ascii=False),
            None,
        )

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    settings = replace(make_settings(), language="ko")
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert missing == 0
    assert len(batches) > 1
    assert len(result.split("\n")) == len(lines)  # line count preserved exactly
    assert "Collector" not in result


@pytest.mark.asyncio
async def test_long_report_translation_batches_run_in_parallel(monkeypatch) -> None:
    lines = [f"Collector {index} reported a scoped observation." for index in range(120)]
    in_flight = 0
    max_in_flight = 0

    async def fake_complete_with_error(*_args, **kwargs):
        nonlocal in_flight, max_in_flight
        pending = json.loads(kwargs["user"])
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0)
        in_flight -= 1
        return json.dumps({key: f"수집기 관측 {key}." for key in pending}), None

    monkeypatch.setattr("app.services.pipeline.complete_with_error", fake_complete_with_error)
    result, missing = await _translate_report_lines_ko(
        replace(make_settings(), language="ko"), "\n".join(lines)
    )

    assert missing == 0
    assert max_in_flight > 1
    assert "Collector" not in result


@pytest.mark.asyncio
async def test_failed_batch_keeps_the_batches_that_worked(monkeypatch) -> None:
    lines = [f"Collector {index} reported a scoped observation." for index in range(120)]
    detail = "\n".join(lines)
    calls = {"n": 0}

    async def fake_complete_with_error(*_args, **kwargs):
        calls["n"] += 1
        pending = json.loads(kwargs["user"])
        if calls["n"] == 1:
            return (
                json.dumps({key: f"수집기 관측 {key}." for key in pending}, ensure_ascii=False),
                None,
            )
        return "not json at all", None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    settings = replace(make_settings(), language="ko")
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert 0 < missing < len(lines)
    assert "수집기 관측" in result  # the good batch survived
    assert "Collector" in result  # the failed batch kept its deterministic text


def test_preserved_spans_cover_api_vocabulary_but_not_plain_english() -> None:
    from app.services.pipeline import _preserved_spans

    source = (
        "Confirm the object exists in the SAME namespace: fix the "
        "secretKeyRef/configMapKeyRef name+key, check nvidia.com/gpu on the node, "
        'and note that secret "app-secret" not found raised '
        "CreateContainerConfigError with `kubectl -n ns get secret` — "
        "cross-namespace and/or aliased references and their IDs never resolve."
    )
    spans = _preserved_spans(source)

    for protected in (
        "`kubectl -n ns get secret`",
        '"app-secret"',
        "secretKeyRef",
        "configMapKeyRef",
        "CreateContainerConfigError",
        "nvidia.com",
    ):
        assert protected in spans, protected
    # Ordinary English — including emphasis, hyphenated words, slashed pairs and
    # short acronym plurals — must stay translatable.
    for free in ("SAME", "cross-namespace", "and/or", "namespace", "IDs"):
        assert free not in spans, free


@pytest.mark.asyncio
async def test_translation_dropping_an_api_term_is_rejected(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    detail = "The alert payload explicitly reported CreateContainerConfigError."

    async def fake_complete_with_error(*_args, **_kwargs):
        # "컨테이너 설정 오류" localizes the API term away — unusable for an operator.
        return '{"0": "알림 페이로드가 컨테이너 설정 오류를 명시적으로 보고했습니다."}', None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert (result, missing) == (detail, 1)


@pytest.mark.asyncio
async def test_translation_keeping_the_object_name_is_accepted(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    detail = 'The kubelet reported secret "app-secret" not found for this Pod.'

    async def fake_complete_with_error(*_args, **_kwargs):
        reply = {"0": 'kubelet이 이 Pod에 대해 secret "app-secret" not found를 보고했습니다.'}
        return json.dumps(reply, ensure_ascii=False), None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    result, missing = await _translate_report_lines_ko(settings, detail)

    assert missing == 0
    assert '"app-secret"' in result


@pytest.mark.asyncio
async def test_translation_runs_after_every_section_is_appended(monkeypatch) -> None:
    """Placement regression: localization must be the LAST thing synthesize does.

    Self-Check, operator questions and general guidance are appended after the
    report body is built. While translation ran before them those sections
    stayed English no matter how well the translator worked — the reported
    "recommended actions came back in English" symptom.
    """
    from app.collectors.base import CollectorResult
    from app.masking import build_masker
    from app.plan import InvestigationPlan
    from app.progress import ProgressReporter
    from app.services import pipeline
    from app.services.kg_enrichment import KGContext
    from app.services.pipeline import PipelineState, synthesize_stage
    from tests.test_orchestrator import make_target

    settings = replace(
        make_settings(),
        language="ko",
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    seen: dict[str, str] = {}

    async def fake_translate(settings, detail, diagnostics=None):
        seen["detail"] = detail
        return detail, 0

    monkeypatch.setattr(
        "app.services.pipeline._translate_report_lines_ko", fake_translate
    )
    state = PipelineState(
        settings=settings,
        request=AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "KubePodNotReady", "namespace": "default"},
                annotations={"summary": "pod not ready"},
                fingerprint="fp-placement",
            )
        ),
        target=make_target(),
        progress=ProgressReporter(settings, run_id=""),
        masker=build_masker(()),
        collectors=[],
        kg_context=KGContext(),
        plan=InvestigationPlan(namespaces=["default"], pod="trainer-0"),
        results=[CollectorResult(agent="kubernetes", status="ok", summary="no evidence")],
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
    )
    state.self_check_next = "Run kubectl describe pod trainer-0 and read the Events tail."
    state.self_check_caveat = (
        "The evidence cannot yet separate a missing Secret from a namespace mismatch."
    )

    await synthesize_stage(state)

    body = seen.get("detail", "")
    assert body, "the translator was never called"
    # Sections appended after the report body must be inside the translated span.
    assert "## Self-Check" in body
    assert state.self_check_caveat in body
    assert state.self_check_next in body
    assert pipeline._general_guidance_heading("ko") in body
    # And they must actually be picked up as translatable prose, not just present.
    batch = set(pipeline._translatable_report_lines(body).values())
    assert any(state.self_check_caveat in line for line in batch)


# _polite_ko: the single choke point that rewrites a rendered Korean line's
# plain-imperative sentence ending (~하라/~해라/~하지 마라/~말라) to polite form.


def test_polite_ko_rewrites_hara_with_trailing_period() -> None:
    assert _polite_ko("GPU 오류 증거를 수집하라.") == "GPU 오류 증거를 수집하세요."


def test_polite_ko_rewrites_hara_with_no_trailing_punctuation() -> None:
    assert _polite_ko("dmesg 로그를 확인하라") == "dmesg 로그를 확인하세요"


def test_polite_ko_rewrites_haji_mara() -> None:
    assert _polite_ko("재시작하지 마라") == "재시작하지 마세요"
    assert _polite_ko("재시작하지 말라.") == "재시작하지 마세요."


def test_polite_ko_rewrites_haera() -> None:
    assert _polite_ko("지금 바로 실행해라") == "지금 바로 실행하세요"


def test_polite_ko_leaves_already_polite_lines_unchanged() -> None:
    for line in ("dmesg 로그를 확인하세요.", "지원 조직에 문의하십시오.", "다시 시작합니다."):
        assert _polite_ko(line) == line


def test_polite_ko_leaves_english_lines_unchanged() -> None:
    line = "Check the node dmesg log to collect evidence."
    assert _polite_ko(line) == line


def test_polite_ko_never_touches_a_code_span() -> None:
    # The code span itself must survive byte-for-byte even though it CONTAINS
    # a string that would otherwise match -- only the true end of the line,
    # outside every backtick span, is a rewrite candidate. A code span earlier
    # in the line neither gets rewritten nor blocks the real tail from being.
    line = "`kubectl get pods -n 하라예제` 명령으로 상태를 확인하라"
    rewritten = _polite_ko(line)
    assert "`kubectl get pods -n 하라예제`" in rewritten
    assert rewritten == "`kubectl get pods -n 하라예제` 명령으로 상태를 확인하세요"


def test_polite_ko_bails_on_unbalanced_backticks() -> None:
    line = "설정을 `nvidia-smi 확인하라"
    assert _polite_ko(line) == line


@pytest.mark.asyncio
async def test_self_check_next_hara_renders_polite_in_recommended_actions() -> None:
    # Integration: a self-check-sourced Korean next_check ending in the plain
    # imperative ("...수집하라.") must render as the polite form in report
    # section 3 -- the live incident this fix was written for.
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "OperatorRequestedAnalysis"},
            fingerprint="polite-ko-fp",
        )
    )
    detail = _detail_from(
        request,
        [],
        [],
        root_cause_candidates=[RankedCause("gpu_hardware_error", "high", 8.0)],
        self_check_next=(
            "해당 노드(dgx01, dgx02 등)의 dmesg 또는 NVIDIA XID 로그를 확인하여 "
            "GPU 오류 증거를 수집하라."
        ),
        knowledge=ReportKnowledge(language="ko"),
    )
    actions = detail.split("## 3. 권장 조치", 1)[1].split("## 부록", 1)[0]
    assert "GPU 오류 증거를 수집하세요." in actions
    assert "수집하라" not in actions
