from __future__ import annotations

import pytest

from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse, ChatRequest
from app.services import chat_agent
from tests.test_orchestrator import make_settings


def _settings():
    from dataclasses import replace

    return replace(
        make_settings(),
        llm_base_url="https://llm.local/v1",
        llm_model="m",
        llm_api_key="k",
        llm_model_chat="m",
    )


def _script(monkeypatch, decisions: list[dict], final: str = "final answer"):
    """Drive complete_json with a scripted decision sequence and complete() final."""
    seq = list(decisions)

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        return seq.pop(0) if seq else {"action": "answer", "answer": final}

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        return final, None

    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)


@pytest.mark.asyncio
async def test_direct_answer_no_tools(monkeypatch) -> None:
    _script(monkeypatch, [{"action": "answer", "answer": "hi there"}])

    async def analyze_fn(_request):  # must NOT be called
        raise AssertionError("analyze should not run for a direct answer")

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="hello"), "ctx", analyze_fn=analyze_fn
    )
    assert text == "hi there"
    assert error is None


@pytest.mark.asyncio
async def test_query_path_runs_readonly_tool(monkeypatch) -> None:
    called = {}

    async def fake_tool(settings, target, args):
        called["args"] = args
        return {"query": "kubectl get pods -n runai", "summary": "2 pods", "result": {"items": []}}

    registry = {"k8s_read": {"description": "d", "call": fake_tool}}
    monkeypatch.setattr(chat_agent, "_flat_tools", lambda settings: registry)
    decision = {
        "action": "query",
        "queries": [{"tool": "k8s_read", "args": {"kind": "pods", "namespace": "runai"}}],
    }
    _script(monkeypatch, [decision], final="There are 2 pods.")

    async def analyze_fn(_request):
        raise AssertionError("analyze should not run")

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="pods in runai?"), "ctx", analyze_fn=analyze_fn
    )
    assert called["args"] == {"kind": "pods", "namespace": "runai"}
    assert text == "There are 2 pods."
    assert error is None


@pytest.mark.asyncio
async def test_analyze_path_triggers_rca_with_target(monkeypatch) -> None:
    seen = {}

    async def analyze_fn(request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        seen["labels"] = dict(request.alert.labels)
        seen["type"] = request.analysis_type
        return AlertAnalysisResponse(
            status="ok",
            analysis="d",
            analysis_summary="root cause: quota",
            analysis_detail="detail",
            analysis_type="chat",
            analysis_quality="high",
        )

    monkeypatch.setattr(chat_agent, "_flat_tools", lambda settings: {})
    _script(
        monkeypatch,
        [{"action": "analyze", "target": {"namespace": "runai", "reason": "investigate"}}],
        final="Analysis says quota.",
    )

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="analyze runai namespace"), "ctx", analyze_fn=analyze_fn
    )
    assert seen["labels"]["namespace"] == "runai"
    assert seen["type"] == "chat"
    assert text == "Analysis says quota."
    assert error is None


@pytest.mark.asyncio
async def test_empty_question_returns_error() -> None:
    async def analyze_fn(_request):
        raise AssertionError

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="   "), "ctx", analyze_fn=analyze_fn
    )
    assert text is None
    assert error == "empty question"
