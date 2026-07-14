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


@pytest.mark.asyncio
async def test_progress_reporter_serializes_and_flushes_final_updates(monkeypatch) -> None:
    calls: list[str] = []
    first_started = asyncio.Event()
    release_first = asyncio.Event()

    async def fake_post_json(**kwargs):
        message = kwargs["json_body"]["message"]
        calls.append(message)
        if message == "first":
            first_started.set()
            await release_first.wait()

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    settings = replace(make_settings(), backend_url="http://backend")
    reporter = ProgressReporter(settings, "ANL-ordered")

    reporter.emit("synthesize", "first")
    reporter.emit("harness", "second")
    await first_started.wait()

    # The second request cannot overtake the first one at the backend.
    assert calls == ["first"]
    release_first.set()
    await reporter.flush()

    assert calls == ["first", "second"]


@pytest.mark.asyncio
async def test_progress_reporter_only_repeats_ledger_when_it_changes(monkeypatch) -> None:
    calls: list[dict] = []

    async def fake_post_json(**kwargs):
        calls.append(kwargs["json_body"])

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    settings = replace(make_settings(), backend_url="http://backend")
    reporter = ProgressReporter(settings, "ANL-ledger")
    seed = [{"id": "H1", "family": "quota", "status": "open", "confidence": 0.5}]
    changed = [{"id": "H1", "family": "quota", "status": "testing", "confidence": 0.7}]

    reporter.emit("investigation", "first", hypothesis_ledger=seed)
    reporter.emit("investigation", "same", hypothesis_ledger=seed)
    reporter.emit("investigation", "changed", hypothesis_ledger=changed)
    await reporter.flush()

    assert calls[0]["hypothesis_ledger"] == seed
    assert "hypothesis_ledger" not in calls[1]
    assert calls[2]["hypothesis_ledger"] == changed


@pytest.mark.asyncio
async def test_progress_reporter_never_posts_unmasked_payload_if_masker_misbehaves(
    monkeypatch,
) -> None:
    calls: list[dict] = []

    class BadMasker:
        def mask_object(self, value):
            return "not a payload"

        def mask_text(self, text: str) -> str:
            return text

    async def fake_post_json(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    settings = replace(make_settings(), backend_url="http://backend")
    reporter = ProgressReporter(
        settings,
        "ANL-9",
        masker=BadMasker(),
    )

    reporter.emit("planning", "api_key=progress-secret-12345")
    await asyncio.sleep(0.01)

    assert calls == []


@pytest.mark.asyncio
async def test_progress_reporter_rejects_untrusted_run_id(monkeypatch) -> None:
    calls: list[dict] = []

    async def fake_post_json(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("app.progress.post_json", fake_post_json)
    settings = replace(make_settings(), backend_url="http://backend")
    reporter = ProgressReporter.from_alert(
        settings,
        SimpleNamespace(annotations={"analysis_run_id": "ANL-1/../../x?debug=true"}),
    )

    reporter.emit("planning", "hello")
    await asyncio.sleep(0.01)

    assert calls == []
