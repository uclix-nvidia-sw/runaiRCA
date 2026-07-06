from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.progress import ProgressReporter
from tests.test_orchestrator import make_settings


@pytest.mark.asyncio
async def test_progress_reporter_noops_without_backend(monkeypatch) -> None:
    called = False

    async def fake_post_json(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    reporter = ProgressReporter.from_alert(
        make_settings(),
        SimpleNamespace(annotations={"analysis_run_id": "ANL-1"}),
    )

    reporter.emit("planning", "hello")
    await asyncio.sleep(0)

    assert called is False


@pytest.mark.asyncio
async def test_progress_reporter_posts_masked_payload(monkeypatch) -> None:
    calls: list[dict] = []

    async def fake_post_json(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    settings = replace(make_settings(), backend_url="http://backend")
    reporter = ProgressReporter.from_alert(
        settings,
        SimpleNamespace(annotations={"analysis_run_id": "ANL-9"}),
    )

    reporter.emit("planning", "Bearer abcdefghijklmnop", secret="top-secret")
    await asyncio.sleep(0.01)

    assert calls
    assert calls[0]["url"] == "http://backend/api/v1/analysis-runs/ANL-9/progress"
    assert calls[0]["timeout_seconds"] == 3
    assert calls[0]["json_body"]["message"] == "[MASKED]"
    assert calls[0]["json_body"]["secret"] == "[MASKED]"
