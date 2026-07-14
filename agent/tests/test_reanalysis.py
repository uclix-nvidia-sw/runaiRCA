"""Tests for the iterative re-analysis loop and the operator-questions section.

Covers: refuted -> bounded re-analysis; not refuted -> none;
re-analysis failure -> clean fallback to the first result; insufficient
evidence -> operator questions section (Korean under ko); no LLM -> behavior
unchanged (no re-analysis, deterministic questions).
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import AnalysisTarget, CollectorResult
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.orchestrator import AnalysisOrchestrator
from app.services.pipeline import _collector_name
from tests.test_orchestrator import make_settings


def llm_settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        enable_investigation_loop=True,
        max_investigation_steps=4,
    )


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "NodeDiskPressure", "namespace": "runai-vision"},
            annotations={"summary": "Node under disk pressure."},
            fingerprint="fp-reanalysis",
        )
    )


def _signatureless_request() -> AlertAnalysisRequest:
    """An alert matching NO curated signature — the true no-signal path.

    The signature-first headline names the family straight from the alert text
    (NodeDiskPressure -> node_kubelet_pressure), so insufficient-evidence tests
    need an alert whose name/summary hit no symptom/known-issue/XID keyword."""
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "MysteriousBlip", "namespace": "runai-vision"},
            annotations={"summary": "Something odd happened."},
            fingerprint="fp-reanalysis-nosig",
        )
    )


def _stub_llm_http(monkeypatch) -> None:
    # Any raw LLM HTTP call (planner refinement, synthesis, sharpening) fails fast.
    async def fake_post_json(*args, **kwargs):
        return SimpleNamespace(ok=False, data=None, error="down", status_code=500)

    monkeypatch.setattr("app.llm.post_json", fake_post_json)


def _install_stubs(
    monkeypatch,
    verdicts: list[dict],
    investigate_calls: list[int],
    refute_calls: list[str],
    fail_second_investigate: bool = False,
) -> None:
    """Stub investigate + refute_top_cause (both lazily imported by the orchestrator).

    First investigate pass yields node-pressure evidence; a second (re-analysis)
    pass replaces it with scheduling-quota evidence so the re-rank flips families.
    """

    async def fake_investigate(settings, target, collectors, plan, kg, max_steps, reporter=None):
        call = len(investigate_calls)
        investigate_calls.append(max_steps)
        if fail_second_investigate and call > 0:
            raise RuntimeError("re-analysis probe exploded")
        if call == 0:
            summaries = {
                "kubernetes": "Node condition DiskPressure=True; kubelet evicting pods",
                "prometheus": "requested gpus exceed allocated gpus",
            }
        else:
            summaries = {
                "kubernetes": "no further node findings",
                "prometheus": "runai reclaimed over-quota gpus; gang pod group preempt",
            }
        results = [
            CollectorResult(
                agent=_collector_name(collector),
                status="ok",
                summary=summaries.get(_collector_name(collector), "nothing notable"),
            )
            for collector in collectors
        ]
        return results, {"hypothesis_ledger": []}

    async def fake_refute(settings, top, results, plan=None):
        refute_calls.append(top.family)
        verdict = verdicts[min(len(refute_calls) - 1, len(verdicts) - 1)]
        return dict(verdict)

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    monkeypatch.setattr("app.services.self_check.refute_top_cause", fake_refute)


def _install_iterative_stubs(
    monkeypatch,
    investigate_calls: list[int],
    refute_calls: list[str],
) -> None:
    async def fake_investigate(settings, target, collectors, plan, kg, max_steps, reporter=None):
        call = len(investigate_calls)
        investigate_calls.append(max_steps)
        summaries_by_call = [
            {
                "kubernetes": "Node condition DiskPressure=True; kubelet evicting pods",
                "prometheus": "requested gpus exceed allocated gpus",
            },
            {
                "kubernetes": "CrashLoopBackOff startup probe failed",
                "prometheus": "runai reclaimed over-quota gpus; gang pod group preempt",
            },
            {
                "kubernetes": "CrashLoopBackOff startup probe failed permission denied",
                "loki": "container ImportError and permission denied during startup",
            },
        ]
        summaries = summaries_by_call[min(call, len(summaries_by_call) - 1)]
        results = [
            CollectorResult(
                agent=_collector_name(collector),
                status="ok",
                summary=summaries.get(_collector_name(collector), "nothing notable"),
            )
            for collector in collectors
        ]
        return results, {"hypothesis_ledger": []}

    verdicts = [
        {
            "confidence": "low",
            "caveat": "Node pressure does not explain the scheduler evidence.",
            "refuted": True,
            "next_check": "Check quota evidence.",
        },
        {
            "confidence": "low",
            "caveat": "Quota does not explain the container crash.",
            "refuted": True,
            "next_check": "Check startup logs.",
        },
        {"confidence": "high", "caveat": "", "refuted": False, "next_check": ""},
    ]

    async def fake_refute(settings, top, results, plan=None):
        refute_calls.append(top.family)
        return dict(verdicts[min(len(refute_calls) - 1, len(verdicts) - 1)])

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    monkeypatch.setattr("app.services.self_check.refute_top_cause", fake_refute)


@pytest.mark.asyncio
async def test_default_cap_allows_multiple_reanalysis_passes_until_resolved(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_iterative_stubs(monkeypatch, investigate_calls, refute_calls)

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    assert investigate_calls == [4, 2, 2]
    assert refute_calls == [
        "node_kubelet_pressure",
        "runai_scheduling_quota",
        "workload_startup_error",
    ]
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "workload_startup_error"
    assert top["confidence"] == "high"
    assert "The initial conclusion (node_kubelet_pressure) was refuted" in response.analysis_detail
    assert (
        "The previous conclusion (runai_scheduling_quota) was refuted"
        in response.analysis_detail
    )
    assert "## Questions for the Operator" not in response.analysis_detail


@pytest.mark.asyncio
async def test_refuted_top_cause_triggers_exactly_one_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "Competing cause fits better.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            },
            {"confidence": "medium", "caveat": "", "refuted": False, "next_check": ""},
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    # Exactly one re-entry: main pass + ONE re-analysis, with the small step budget.
    assert len(investigate_calls) == 2
    assert investigate_calls[1] == 2  # min(2, max_investigation_steps=4)
    assert len(refute_calls) == 2
    assert refute_calls[0] == "node_kubelet_pressure"
    assert refute_calls[1] == "runai_scheduling_quota"
    # The report shows it thought again.
    assert "## Self-Check" in response.analysis_detail
    assert (
        "The initial conclusion (node_kubelet_pressure) was refuted" in response.analysis_detail
    )
    assert "revised conclusion: runai_scheduling_quota" in response.analysis_detail
    # The merged re-analysis evidence drives the final ranking.
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "runai_scheduling_quota"
    # Not refuted anymore -> no operator questions section.
    assert "## Questions for the Operator" not in response.analysis_detail


@pytest.mark.asyncio
async def test_progress_does_not_look_stuck_after_self_check(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "A targeted follow-up is required.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            },
            {"confidence": "medium", "caveat": "", "refuted": False, "next_check": ""},
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )
    events: list[tuple[str, str]] = []
    flushed_at: list[int] = []

    class RecordingProgress:
        def emit(self, phase, message, **_fields):
            events.append((phase, message))

        async def flush(self):
            flushed_at.append(len(events))

    def fake_from_alert(_cls, *_args, **_kwargs):
        return RecordingProgress()

    monkeypatch.setattr(
        pipeline.ProgressReporter,
        "from_alert",
        classmethod(fake_from_alert),
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    await orchestrator.analyze(_request())

    self_check_index = events.index(("self_check", "Self-check complete"))
    follow_up_index = events.index(
        ("investigation", "Running targeted follow-up before synthesis")
    )
    synthesis_index = events.index(("synthesize", "Synthesizing final RCA"))
    synthesis_complete_index = events.index(("synthesize", "Synthesis complete"))
    harness_start_index = events.index(("harness", "Validating synthesized RCA"))
    harness_complete_index = events.index(("harness", "Validation complete"))
    assert (
        self_check_index
        < follow_up_index
        < synthesis_index
        < synthesis_complete_index
        < harness_start_index
        < harness_complete_index
    )
    assert flushed_at == [len(events)]


@pytest.mark.asyncio
async def test_cap_zero_uses_semantic_completion_instead_of_disabling_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "Competing cause fits better.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            }
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    settings = replace(llm_settings(), max_investigation_iterations=0)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_request())

    assert len(investigate_calls) > 1
    assert len(refute_calls) >= 1
    assert "re-analysis pass was performed" in response.analysis_detail
    top = response.context["root_cause_candidates"][0]
    assert top["family"] in {"node_kubelet_pressure", "runai_scheduling_quota"}


@pytest.mark.asyncio
async def test_not_refuted_means_no_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[{"confidence": "high", "caveat": "", "refuted": False, "next_check": ""}],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    assert len(investigate_calls) == 1
    assert len(refute_calls) == 1
    assert "re-analysis pass was performed" not in response.analysis_detail
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "node_kubelet_pressure"


@pytest.mark.asyncio
async def test_reanalysis_failure_falls_back_to_first_result(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "First doubt stands.",
                "refuted": True,
                "next_check": "Check kubelet pressure directly.",
            },
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
        fail_second_investigate=True,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    # Re-analysis was attempted once, blew up, and the first result stands.
    assert len(investigate_calls) == 2
    assert len(refute_calls) == 1  # second refutation never happened
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "node_kubelet_pressure"
    assert "First doubt stands." in response.analysis_detail
    assert "re-analysis pass was performed" not in response.analysis_detail
    # Still refuted -> the honest operator-questions section appears (en settings),
    # leading with the self-check's settling check.
    assert "## Questions for the Operator" in response.analysis_detail
    assert "Check kubelet pressure directly." in response.analysis_detail


@pytest.mark.asyncio
async def test_insufficient_evidence_adds_korean_questions_without_llm() -> None:
    # No LLM, all collectors unconfigured -> insufficient_evidence + Korean questions.
    settings = replace(make_settings(), language="ko")
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_signatureless_request())

    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "insufficient_evidence"
    assert "## 추가 확인 요청" in response.analysis_detail
    section = response.analysis_detail.split("## 추가 확인 요청", 1)[1]
    section = section.split("\n## ", 1)[0]
    questions = [line for line in section.splitlines() if line.startswith("- ")]
    assert 2 <= len(questions) <= 4
    assert any("확인해 주세요" in q for q in questions)


@pytest.mark.asyncio
async def test_llm_sharpened_operator_questions_are_single_line(monkeypatch) -> None:
    async def fake_complete_json(*_args, **_kwargs):
        return {
            "questions": [
                "Check kubelet pressure\n## injected heading\n" + ("detail " * 80),
                "Check scheduler queue token=question-secret-12345",
            ]
        }

    monkeypatch.setattr(pipeline, "complete_json", fake_complete_json)
    settings = replace(llm_settings(), llm_model_synthesis="m")
    questions = await pipeline._operator_questions(
        settings,
        ["loki.query"],
        None,
        AnalysisTarget("", "", "", "", "", "", "", "", "", "warning", "X"),
        "next check\n## bad",
    )

    assert len(questions) == 2
    assert all("\n" not in question for question in questions)
    assert questions[0].endswith("…")
    assert "question-secret-12345" not in "\n".join(questions)
    assert "[MASKED]" in "\n".join(questions)


@pytest.mark.asyncio
async def test_no_llm_keeps_behavior_no_reanalysis(monkeypatch) -> None:
    # LLM off (even with the loop flag on): investigate is never used and no
    # re-analysis note appears — current no-LLM behavior.
    investigate_calls: list[int] = []

    async def fake_investigate(*args, **kwargs):  # pragma: no cover - must not run
        investigate_calls.append(1)
        return []

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    settings = replace(make_settings(), enable_investigation_loop=True)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_signatureless_request())

    assert investigate_calls == []
    assert "재분석" not in response.analysis_detail
    assert "re-analysis pass was performed" not in response.analysis_detail
    # English deterministic questions still appear for the unsettled RCA.
    assert "## Questions for the Operator" in response.analysis_detail
