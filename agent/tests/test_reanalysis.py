"""Tests for the re-analysis-on-refutation pass and the operator-questions section.

Covers: refuted -> exactly one bounded re-analysis; not refuted -> none;
re-analysis failure -> clean fallback to the first result; insufficient
evidence -> operator questions section (Korean under ko); no LLM -> behavior
unchanged (no re-analysis, deterministic questions).
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import CollectorResult
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import AnalysisOrchestrator, _collector_name
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

    async def fake_investigate(settings, target, collectors, plan, kg, max_steps):
        call = len(investigate_calls)
        investigate_calls.append(max_steps)
        if fail_second_investigate and call > 0:
            raise RuntimeError("re-analysis probe exploded")
        if call == 0:
            summaries = {
                "kubernetes": "Node condition DiskPressure=True; kubelet evicting pods",
                "prometheus": "pending pods observed",
            }
        else:
            summaries = {
                "kubernetes": "no further node findings",
                "prometheus": "unschedulable: insufficient gpu quota; pods pending, preempt",
            }
        return [
            CollectorResult(
                agent=_collector_name(collector),
                status="ok",
                summary=summaries.get(_collector_name(collector), "nothing notable"),
            )
            for collector in collectors
        ]

    async def fake_refute(settings, top, results, plan=None):
        refute_calls.append(top.family)
        verdict = verdicts[min(len(refute_calls) - 1, len(verdicts) - 1)]
        return dict(verdict)

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    monkeypatch.setattr("app.services.self_check.refute_top_cause", fake_refute)


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
    assert refute_calls[1] == "scheduling_quota_exhaustion"
    # The report shows it thought again.
    assert "## Self-Check" in response.analysis_detail
    assert (
        "The initial conclusion (node_kubelet_pressure) was refuted" in response.analysis_detail
    )
    assert "revised conclusion: scheduling_quota_exhaustion" in response.analysis_detail
    # The merged re-analysis evidence drives the final ranking.
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "scheduling_quota_exhaustion"
    # Not refuted anymore -> no operator questions section.
    assert "## Questions for the Operator" not in response.analysis_detail


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
    response = await orchestrator.analyze(_request())

    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "insufficient_evidence"
    assert "## 추가 확인 요청" in response.analysis_detail
    section = response.analysis_detail.split("## 추가 확인 요청", 1)[1]
    section = section.split("\n## ", 1)[0]
    questions = [line for line in section.splitlines() if line.startswith("- ")]
    assert 2 <= len(questions) <= 4
    assert any("확인해 주세요" in q for q in questions)


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
    response = await orchestrator.analyze(_request())

    assert investigate_calls == []
    assert "재분석" not in response.analysis_detail
    assert "re-analysis pass was performed" not in response.analysis_detail
    # English deterministic questions still appear for the unsettled RCA.
    assert "## Questions for the Operator" in response.analysis_detail
