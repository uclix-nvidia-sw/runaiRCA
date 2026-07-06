from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app import llm
from app.llm import PROMPT_INJECTION_GUARD
from app.schemas import ChatRequest
from app.services import orchestrator as orch_mod
from app.services.orchestrator import AnalysisOrchestrator

_LLM_SETTINGS = SimpleNamespace(
    llm_base_url="http://llm.test/v1",
    llm_model="test-model",
    llm_api_key="key",
    llm_request_timeout_seconds=1,
)


def _capture_post_json(captured: dict):
    async def fake_post_json(*, url, timeout_seconds, json_body, headers):
        captured.update(json_body)
        # Mirror JsonResponse's shape — chat reads status_code/error on failure.
        return SimpleNamespace(ok=False, status_code=503, error="stubbed", data=None)

    return fake_post_json


def test_every_llm_call_carries_the_injection_guard(monkeypatch) -> None:
    # complete() is the funnel for complete_json and every reasoning prompt —
    # evidence text is cluster-writable, so the guard must ride along on all of it.
    captured: dict = {}
    monkeypatch.setattr(llm, "post_json", _capture_post_json(captured))
    asyncio.run(llm.complete(_LLM_SETTINGS, system="base prompt", user="evidence"))
    system = captured["messages"][0]["content"]
    assert system.startswith("base prompt")
    assert PROMPT_INJECTION_GUARD in system


def test_chat_path_carries_the_injection_guard(monkeypatch) -> None:
    # _llm_chat_answer posts directly (bypasses app.llm.complete), so it appends
    # the guard itself — this pins that.
    captured: dict = {}
    monkeypatch.setattr(orch_mod, "post_json", _capture_post_json(captured))
    orchestrator = AnalysisOrchestrator.__new__(AnalysisOrchestrator)
    orchestrator._settings = _LLM_SETTINGS
    asyncio.run(
        orchestrator._llm_chat_answer(ChatRequest(message="why did my job die?"), grounding="ctx")
    )
    assert PROMPT_INJECTION_GUARD in captured["messages"][0]["content"]
