"""Overall analysis deadline: agents get generous per-step time, but one
analysis always finishes within analysis_deadline_seconds (graceful degrade)."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, annotations={}, fingerprint="fp")
    )


def test_deadline_response_is_valid_and_degraded() -> None:
    orch = AnalysisOrchestrator(make_settings())
    resp = orch._deadline_response(_request(), 300)
    assert resp.status == "failed"
    assert resp.terminal_reason == "deadline_exceeded"
    assert resp.analysis_quality == "degraded"
    assert "300" in resp.analysis_summary
    assert any("deadline" in w for w in resp.warnings)


def test_analyze_returns_degraded_when_impl_overruns() -> None:
    # Deadline 1s, impl sleeps far longer -> wait_for stops it, degraded report.
    settings = replace(make_settings(), analysis_deadline_seconds=1)
    orch = AnalysisOrchestrator(settings)

    async def _slow(_request: AlertAnalysisRequest):  # noqa: ANN202
        await asyncio.sleep(30)

    orch._analyze_impl = _slow  # type: ignore[assignment]
    resp = asyncio.run(orch.analyze(_request()))
    assert resp.status == "failed"
    assert resp.terminal_reason == "deadline_exceeded"
    assert resp.analysis_quality == "degraded"
    assert resp.warnings and "deadline" in resp.warnings[0]


def test_deadline_zero_disables_cap() -> None:
    settings = replace(make_settings(), analysis_deadline_seconds=0)
    orch = AnalysisOrchestrator(settings)
    sentinel = object()

    async def _impl(_request: AlertAnalysisRequest):  # noqa: ANN202
        return sentinel

    orch._analyze_impl = _impl  # type: ignore[assignment]
    assert asyncio.run(orch.analyze(_request())) is sentinel  # no wait_for wrapping
