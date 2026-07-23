from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app import llm
from app.services.pipeline import (
    _evidence_deadline_monotonic,
    _finalization_reserve_seconds,
    _record_evidence_budget_stop,
)
from tests.test_orchestrator import make_settings


def test_default_deadline_reserves_finalization_after_shared_evidence_budget() -> None:
    settings = replace(make_settings(), analysis_deadline_seconds=900)
    state = SimpleNamespace(settings=settings, analysis_started_at=100.0)

    assert _finalization_reserve_seconds(900) == 360.0
    assert _evidence_deadline_monotonic(state) == 640.0


def test_optional_budget_stop_is_observability_only() -> None:
    events: list[tuple[str, str, dict[str, str]]] = []
    state = SimpleNamespace(
        investigation_context={"hypothesis_ledger": []},
        extra_warnings=[],
        progress=SimpleNamespace(
            emit=lambda stage, message, **payload: events.append(
                (stage, message, payload)
            )
        ),
    )

    _record_evidence_budget_stop(state, "additional investigation iterations")

    assert state.investigation_context == {"hypothesis_ledger": []}
    assert state.extra_warnings == []
    assert events == [
        (
            "investigation",
            "Evidence budget reached; moving to synthesis",
            {"stopped_phase": "additional investigation iterations"},
        )
    ]


@pytest.mark.asyncio
async def test_llm_transport_timeout_is_capped_by_orchestrator_deadline(monkeypatch) -> None:
    captured: list[float] = []

    async def fake_post_json(*, timeout_seconds, **kwargs):
        captured.append(timeout_seconds)
        return SimpleNamespace(
            ok=True,
            status_code=200,
            error=None,
            data={"choices": [{"message": {"content": "ok"}}]},
        )

    monkeypatch.setattr(llm, "post_json", fake_post_json)
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="model",
        llm_api_key="key",
        llm_request_timeout_seconds=300,
    )
    token = llm.set_analysis_deadline(time.monotonic() + 5)
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_analysis_deadline(token)

    assert text == "ok"
    assert error is None
    assert len(captured) == 1
    assert 0 < captured[0] <= 5
