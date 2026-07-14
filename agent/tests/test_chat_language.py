"""Chat must speak the operator's language and actually use the LLM.

Pins the owner-reported failure mode: LANGUAGE=ko but the chat replied with an
English deterministic context dump, and an LLM failure degraded silently. Now
the scaffold is localized, the LLM answer wins when it works, and an LLM
failure is called out in the answer instead of masquerading as the chatbot's
own choice.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

from app.schemas import ChatRequest
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings


def _orchestrator(**overrides) -> AnalysisOrchestrator:
    return AnalysisOrchestrator(replace(make_settings(), **overrides))


def _llm(**overrides):
    return dict(
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        **overrides,
    )


def test_deterministic_scaffold_is_korean_when_language_ko() -> None:
    orchestrator = _orchestrator(language="ko")  # no LLM configured
    response = asyncio.run(orchestrator.chat(ChatRequest(message="에이전트 상태 알려줘")))
    assert "## RCA 챗" in response.answer
    assert "## 근거 기반 답변" in response.answer
    assert "Grounded Answer" not in response.answer


def test_deterministic_scaffold_stays_english_by_default() -> None:
    orchestrator = _orchestrator(language="en")
    response = asyncio.run(orchestrator.chat(ChatRequest(message="agent status?")))
    assert "## Grounded Answer" in response.answer


def test_context_free_chat_offers_conditional_general_guidance() -> None:
    orchestrator = _orchestrator(language="ko")
    response = asyncio.run(orchestrator.chat(ChatRequest(message="OOMKilled는 어떻게 해결해?")))

    assert "## 일반 점검 가이드" in response.answer
    assert "일반 점검 가이드" in response.answer
    assert "원인이나 해결을 확인한 결론이 아닙니다" in response.answer
    assert "OOMKilled" in response.answer


def test_llm_answer_wins_and_is_returned_verbatim(monkeypatch) -> None:
    async def ok_post_json(*, url, timeout_seconds, json_body, headers):
        assert "반드시 한국어로" in json_body["messages"][0]["content"]
        return SimpleNamespace(
            ok=True,
            status_code=200,
            error=None,
            data={"choices": [{"message": {"content": "네, 지금은 MCP가 비활성입니다."}}]},
        )

    monkeypatch.setattr("app.llm.post_json", ok_post_json)
    orchestrator = _orchestrator(language="ko", **_llm())
    response = asyncio.run(orchestrator.chat(ChatRequest(message="mcp 쓸 수 있나?")))
    assert response.answer == "네, 지금은 MCP가 비활성입니다."


def test_llm_failure_is_surfaced_not_silent(monkeypatch) -> None:
    async def failing_post_json(*, url, timeout_seconds, json_body, headers):
        return SimpleNamespace(ok=False, status_code=502, error="bad gateway", data=None)

    monkeypatch.setattr("app.llm.post_json", failing_post_json)
    orchestrator = _orchestrator(language="ko", **_llm())
    response = asyncio.run(orchestrator.chat(ChatRequest(message="상태?")))
    assert "LLM 채팅 호출이 실패" in response.answer
    assert "502" in response.answer
    assert "## RCA 챗" in response.answer  # scaffold still delivered, localized


def test_chat_context_reports_runai_mcp_and_drilldown_state() -> None:
    orchestrator = _orchestrator(
        language="en", runai_mcp_url="http://localhost:8809/mcp", enable_agent_drilldown=True
    )
    response = asyncio.run(orchestrator.chat(ChatRequest(message="can the agent use mcp?")))
    assert "runai_mcp=True" in response.answer
    assert "agent_drilldown=True" in response.answer
