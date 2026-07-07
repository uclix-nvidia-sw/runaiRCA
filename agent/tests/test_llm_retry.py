from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.http_json import JsonResponse
from app.llm import complete
from tests.test_orchestrator import make_settings


def _settings():
    return replace(
        make_settings(), llm_base_url="https://llm.local", llm_model="m", llm_api_key="k"
    )


@pytest.mark.asyncio
async def test_llm_retries_transient_errors(monkeypatch) -> None:
    statuses = [429, 500, 200]
    sleeps: list[float] = []

    async def fake_post_json(**_kwargs):
        status = statuses.pop(0)
        if status == 200:
            return JsonResponse(
                url="u",
                status_code=200,
                data={"choices": [{"message": {"content": "done"}}]},
            )
        return JsonResponse(url="u", status_code=status, error=f"HTTP {status}")

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    monkeypatch.setattr("app.llm.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("app.llm.random.uniform", lambda *_args: 0)

    assert await complete(_settings(), system="s", user="u") == "done"
    assert len(sleeps) == 2


@pytest.mark.asyncio
async def test_llm_does_not_retry_client_error(monkeypatch) -> None:
    calls = 0

    async def fake_post_json(**_kwargs):
        nonlocal calls
        calls += 1
        return JsonResponse(url="u", status_code=400, error="HTTP 400")

    monkeypatch.setattr("app.llm.post_json", fake_post_json)

    assert await complete(_settings(), system="s", user="u") is None
    assert calls == 1
