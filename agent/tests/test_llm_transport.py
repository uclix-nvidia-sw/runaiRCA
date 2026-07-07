from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app import llm
from tests.test_orchestrator import make_settings


class FakeLangchainClient:
    def __init__(self) -> None:
        self.calls = []
        self.bound = {}

    def bind(self, **kwargs):
        self.bound = kwargs
        return self

    async def ainvoke(self, messages):
        self.calls.append(messages)
        return SimpleNamespace(
            content='{"ok": true}',
            usage_metadata={"input_tokens": 7, "output_tokens": 3, "total_tokens": 10},
        )


def _settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.local/v1",
        llm_model="default-model",
        llm_api_key="secret",
    )


@pytest.mark.asyncio
async def test_complete_json_uses_nat_client_and_records_usage() -> None:
    settings = _settings()
    usage = llm.begin_usage_tracking()
    client = FakeLangchainClient()
    token = llm.set_nat_client(client)
    try:
        data = await llm.complete_json(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    assert data == {"ok": True}
    assert client.calls
    assert client.bound["temperature"] == 0.1
    assert usage["calls"] == 1
    assert usage["prompt_tokens"] == 7
    assert usage["completion_tokens"] == 3
    assert usage["total_tokens"] == 10
    assert usage["by_model"]["default-model"]["calls"] == 1


@pytest.mark.asyncio
async def test_explicit_model_override_uses_http(monkeypatch) -> None:
    settings = _settings()
    client = FakeLangchainClient()
    captured = {}

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        captured["json_body"] = json_body
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": '{"http": true}'}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(client)
    try:
        data = await llm.complete_json(
            settings, system="system", user="user", model="stage-model"
        )
    finally:
        llm.reset_nat_client(token)

    assert data == {"http": True}
    assert captured["json_body"]["model"] == "stage-model"
    assert client.calls == []


@pytest.mark.asyncio
async def test_nat_client_failure_surfaces_and_does_not_use_http(monkeypatch) -> None:
    settings = _settings()

    class BrokenClient:
        async def ainvoke(self, messages):  # litellm "LLM Provider NOT provided" etc.
            raise RuntimeError("LLM Provider NOT provided")

    called = {"http": False}

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        called["http"] = True
        return SimpleNamespace(ok=True, data={"choices": []})

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(BrokenClient())
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    # langchain-only while validating: a NAT client failure surfaces as an error and
    # does NOT silently fall back to httpx (which would mask whether langchain works).
    assert text is None
    assert error
    assert called["http"] is False


@pytest.mark.asyncio
async def test_no_nat_client_uses_http(monkeypatch) -> None:
    settings = _settings()
    captured = {}

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        captured["url"] = url
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": '{"http": true}'}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    data = await llm.complete_json(settings, system="system", user="user")

    assert data == {"http": True}
    assert captured["url"] == "https://llm.local/v1/chat/completions"
