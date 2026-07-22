from __future__ import annotations

import asyncio
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
async def test_nat_client_failure_falls_back_to_http(monkeypatch) -> None:
    # Validation of the langchain client is done (2026-07-08: it returned empty
    # replies and every Korean synthesis fell back to English). Owner decision:
    # an unusable NAT reply now retries once via the direct HTTP path.
    settings = _settings()

    class BrokenClient:
        async def ainvoke(self, messages):  # litellm "LLM Provider NOT provided" etc.
            raise RuntimeError("LLM Provider NOT provided")

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": "직접 경로 응답"}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(BrokenClient())
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    assert text == "직접 경로 응답"
    assert error is None


@pytest.mark.asyncio
async def test_nat_timeout_is_per_call_and_falls_back_to_http(monkeypatch) -> None:
    settings = replace(_settings(), llm_request_timeout_seconds=1)

    class SlowClient:
        async def ainvoke(self, messages):
            await asyncio.sleep(1)
            return SimpleNamespace(content="too late")

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        assert 0 < timeout_seconds <= 0.02
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": "직접 경로 응답"}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    monkeypatch.setattr("app.llm._request_timeout", lambda _settings: 0.01)
    token = llm.set_nat_client(SlowClient())
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    assert text == "직접 경로 응답"
    assert error is None


@pytest.mark.asyncio
async def test_nat_empty_reasoning_reply_falls_back_to_http(monkeypatch, caplog) -> None:
    # The 2026-07-08 incident shape: the model DID reply (usage recorded) but
    # content was empty — a reasoning model spending the whole completion budget
    # on reasoning tokens. Must not surface as a blind "no reply".
    settings = _settings()

    class EmptyReplyClient:
        def bind(self, **kwargs):
            return self

        async def ainvoke(self, messages):
            return SimpleNamespace(
                content="",
                usage_metadata={"input_tokens": 9000, "output_tokens": 4096},
                response_metadata={"finish_reason": "length"},
            )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": '{"summary": "요약"}'}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(EmptyReplyClient())
    try:
        text, error = await llm.complete_with_error(
            settings,
            system="system",
            user="user",
            max_tokens=512,
            purpose="collector_insight",
        )
    finally:
        llm.reset_nat_client(token)

    assert text == '{"summary": "요약"}'
    assert error is None
    assert "purpose=collector_insight" in caplog.text
    assert "requested_max_tokens=512" in caplog.text


@pytest.mark.asyncio
async def test_direct_http_empty_reply_preserves_finish_reason_and_usage(monkeypatch) -> None:
    settings = _settings()

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 9000, "completion_tokens": 512},
            },
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    text, error = await llm.complete_with_error(
        settings,
        system="system",
        user="user",
        max_tokens=16384,
        purpose="korean_synthesis",
    )

    assert text is None
    assert error is not None
    assert "finish_reason=length" in error
    assert "completion_tokens=512" in error


@pytest.mark.asyncio
async def test_nat_and_direct_empty_replies_preserve_both_failures(monkeypatch) -> None:
    settings = _settings()

    class EmptyNatClient:
        def bind(self, **kwargs):
            return self

        async def ainvoke(self, messages):
            return SimpleNamespace(
                content="",
                usage_metadata={"input_tokens": 8000, "output_tokens": 512},
                response_metadata={"finish_reason": "length"},
            )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 8000, "completion_tokens": 1024},
            },
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(EmptyNatClient())
    try:
        text, error = await llm.complete_with_error(
            settings,
            system="system",
            user="user",
            max_tokens=16384,
            purpose="korean_synthesis",
        )
    finally:
        llm.reset_nat_client(token)

    assert text is None
    assert error is not None
    assert "nat:" in error and "completion_tokens=512" in error
    assert "direct_http:" in error and "completion_tokens=1024" in error


@pytest.mark.asyncio
async def test_nat_content_blocks_list_is_joined() -> None:
    settings = _settings()

    class BlockClient:
        def bind(self, **kwargs):
            return self

        async def ainvoke(self, messages):
            return SimpleNamespace(
                content=[
                    {"type": "text", "text": '{"summary":'},
                    {"type": "text", "text": ' "블록 응답"}'},
                ],
                usage_metadata={"input_tokens": 5, "output_tokens": 5},
            )

    token = llm.set_nat_client(BlockClient())
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    assert error is None
    assert text is not None and "블록 응답" in text


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


# 2026-07-21 chat incident: a reasoning model served with a template-injected
# <think> leaked its whole thinking transcript (fake kubectl/tool JSON, a
# fabricated pods=20 quota) into message.content; the raw 51KB trace became the
# operator's chat answer. The transport must strip reasoning in BOTH paths.


def test_strip_reasoning_paired_block() -> None:
    assert llm.strip_reasoning("<think>궁리...</think>답변") == "답변"
    assert llm.strip_reasoning("A<think>r1</think>B<think>r2</think>C") == "ABC"


def test_strip_reasoning_bare_close_keeps_only_final_answer() -> None:
    # Template opened <think> inside the prompt: content has closes but no opens,
    # and everything before the LAST close is reasoning (the incident shape).
    leaked = (
        '[{"tool": "k8s_read", "query": "kubectl get quota -n runai-backend", '
        '"summary": "HTTP 200", "result": "used: pods=18, limited: pods=20"}]\n'
        "Let me check the quota.</think>\n"
        '[{"tool": "promql_query", "query": "up", "summary": "HTTP 200"}]\n'
        "Now I understand.</think>\n최종 답변: thanos receive 파드는 1개입니다."
    )
    assert llm.strip_reasoning(leaked) == "최종 답변: thanos receive 파드는 1개입니다."


def test_strip_reasoning_unclosed_open_yields_empty() -> None:
    assert llm.strip_reasoning("<think>끝나지 않는 궁리") == ""


def test_strip_reasoning_plain_text_untouched() -> None:
    text = "정상 답변 (think 태그 없음)"
    assert llm.strip_reasoning(text) is text


@pytest.mark.asyncio
async def test_http_reply_with_think_leak_returns_only_answer(monkeypatch) -> None:
    settings = _settings()

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [{"message": {"content": "가짜 툴 결과들...</think>진짜 답변"}}],
                "usage": {},
            },
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    text, error = await llm.complete_with_error(settings, system="system", user="user")

    assert text == "진짜 답변"
    assert error is None


@pytest.mark.asyncio
async def test_nat_reasoning_only_reply_falls_back_to_http(monkeypatch) -> None:
    settings = _settings()

    class ReasoningOnlyClient:
        def bind(self, **kwargs):
            return self

        async def ainvoke(self, messages):
            return SimpleNamespace(
                content="<think>reasoning that never produced an answer",
                usage_metadata={"input_tokens": 9000, "output_tokens": 4096},
                response_metadata={"finish_reason": "length"},
            )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(
            ok=True,
            data={"choices": [{"message": {"content": "HTTP 폴백 답변"}}], "usage": {}},
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    token = llm.set_nat_client(ReasoningOnlyClient())
    try:
        text, error = await llm.complete_with_error(settings, system="system", user="user")
    finally:
        llm.reset_nat_client(token)

    assert text == "HTTP 폴백 답변"
    assert error is None
