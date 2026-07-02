from __future__ import annotations

import asyncio
from dataclasses import replace

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.services.root_cause_ranking import RankedCause
from app.services.self_check import refute_top_cause
from tests.test_orchestrator import make_settings


def _run(coro):
    return asyncio.run(coro)


def _top(family="node_kubelet_pressure", confidence="high"):
    # canonical collector for node_kubelet_pressure is "kubernetes"
    return RankedCause(
        family=family,
        confidence=confidence,
        score=6.0,
        rationale=["kubernetes evidence matched diskpressure"],
        evidence_agents=["kubernetes", "prometheus"],
    )


def test_no_llm_downgrades_when_canonical_evidence_absent():
    settings = make_settings()  # no LLM configured
    results = [
        CollectorResult(agent="kubernetes", status="unavailable", summary="k8s API unreachable"),
        CollectorResult(agent="prometheus", status="ok", summary="node saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "medium"  # downgraded one level
    assert out["caveat"]  # generic caveat present
    # str() renders the caveat so the orchestrator can append it verbatim.
    assert str(out) == out["caveat"]


def test_no_llm_downgrades_when_canonical_reports_no_evidence():
    settings = make_settings()
    results = [
        CollectorResult(agent="kubernetes", status="ok", summary=NO_EVIDENCE),
        CollectorResult(agent="prometheus", status="ok", summary="node saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="medium"), results))
    assert out["confidence"] == "low"


def test_no_llm_keeps_confidence_when_canonical_evidence_present():
    settings = make_settings()
    results = [
        CollectorResult(
            agent="kubernetes", status="ok", summary="Node condition DiskPressure=True; evictions"
        ),
        CollectorResult(agent="prometheus", status="ok", summary="disk saturated"),
    ]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "high"
    assert out["caveat"] == ""
    assert out["refuted"] is False


def test_insufficient_evidence_family_is_left_alone():
    settings = make_settings()
    top = _top(family="insufficient_evidence", confidence="medium")
    out = _run(refute_top_cause(settings, top, []))
    assert out["confidence"] == "medium"
    assert out["caveat"] == ""


def test_korean_caveat_when_language_ko():
    settings = replace(make_settings(), language="ko")
    results = [CollectorResult(agent="kubernetes", status="unavailable", summary="")]
    out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    assert out["confidence"] == "medium"
    assert "자기 점검" in out["caveat"]


def test_never_raises_with_garbage_candidate():
    settings = make_settings()

    class Broken:
        confidence = "high"
        family = "node_kubelet_pressure"

        @property
        def rationale(self):  # pragma: no cover - defensive
            raise RuntimeError("boom")

    out = _run(refute_top_cause(settings, Broken(), []))
    assert out["confidence"] in ("low", "medium", "high")
    assert isinstance(out, dict)


def test_llm_unsupported_downgrades_and_marks_refuted():
    settings = make_settings()
    results = [
        CollectorResult(agent="kubernetes", status="ok", summary="DiskPressure=True"),
    ]

    async def fake_complete_json(*_a, **_k):
        return {"supported": False, "confidence": "low", "caveat": "Competing cause fits better."}

    import app.services.self_check as mod

    orig_configured = mod.llm_configured
    orig_json = mod.complete_json
    mod.llm_configured = lambda _s: True
    mod.complete_json = fake_complete_json
    try:
        out = _run(refute_top_cause(settings, _top(confidence="high"), results))
    finally:
        mod.llm_configured = orig_configured
        mod.complete_json = orig_json
    assert out["refuted"] is True
    assert out["confidence"] == "low"
    assert out["caveat"] == "Competing cause fits better."
