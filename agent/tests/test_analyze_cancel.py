import asyncio

import pytest
from fastapi import HTTPException

from app import main
from app.schemas import Alert, AlertAnalysisRequest


def _req(run_id: str = "") -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, fingerprint="fp"),
        run_id=run_id,
    )


@pytest.mark.asyncio
async def test_cancel_actually_stops_the_running_analysis(monkeypatch):
    started = asyncio.Event()
    inner_cancelled = {"value": False}

    async def slow_analyze(request):
        started.set()
        try:
            await asyncio.sleep(30)  # a long-running analysis
        except asyncio.CancelledError:
            inner_cancelled["value"] = True  # the pipeline actually received the stop
            raise
        raise AssertionError("analysis should have stopped before completing")

    monkeypatch.setattr(main.orchestrator, "analyze", slow_analyze)

    handler = asyncio.create_task(main.analyze(_req(run_id="run-1")))
    await asyncio.wait_for(started.wait(), timeout=2)
    assert "run-1" in main._running_analyses

    assert (await main.cancel_analysis("run-1"))["status"] == "cancelling"

    with pytest.raises(HTTPException) as exc:
        await handler
    assert exc.value.status_code == 499
    assert inner_cancelled["value"] is True
    assert "run-1" not in main._running_analyses  # deregistered on completion


@pytest.mark.asyncio
async def test_cancel_unknown_run_is_a_noop():
    assert (await main.cancel_analysis("does-not-exist"))["status"] == "not_running"


@pytest.mark.asyncio
async def test_analyze_without_run_id_runs_inline(monkeypatch):
    async def quick_analyze(request):
        return "done"

    monkeypatch.setattr(main.orchestrator, "analyze", quick_analyze)
    assert await main.analyze(_req(run_id="")) == "done"
    assert main._running_analyses == {}  # nothing registered without a run_id
