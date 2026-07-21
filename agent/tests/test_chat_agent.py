from __future__ import annotations

import pytest

from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse, ChatRequest
from app.services import chat_agent
from app.services.orchestrator import AnalysisOrchestrator
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
async def test_direct_llm_answer_is_masked_before_return(monkeypatch) -> None:
    _script(
        monkeypatch,
        [{"action": "answer", "answer": "token=direct-secret-12345"}],
    )

    async def analyze_fn(_request):
        raise AssertionError("analyze should not run for a direct answer")

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="repeat the token"), "ctx", analyze_fn=analyze_fn
    )

    assert error is None
    assert "direct-secret-12345" not in text
    assert "[MASKED]" in text


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
async def test_tool_history_is_masked_before_final_llm(monkeypatch) -> None:
    prompts: list[str] = []

    async def fake_tool(settings, target, args):
        return {
            "query": "kubectl get configmap app -n runai",
            "summary": "token=runtime-token-12345",
            "result": {"data": "password=hunter2 api_key=secret-key-12345"},
        }

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        prompts.append(user)
        if len(prompts) == 1:
            return {
                "action": "query",
                "queries": [{"tool": "k8s_read", "args": {"kind": "configmaps"}}],
            }
        return {"action": "wait"}

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        prompts.append(user)
        return "masked answer", None

    monkeypatch.setattr(
        chat_agent,
        "_flat_tools",
        lambda settings: {"k8s_read": {"description": "d", "call": fake_tool}},
    )
    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)

    text, error = await chat_agent.answer_chat(
        _settings(),
        ChatRequest(message="check password=operator-secret-12345"),
        "ctx api_key=context-secret-12345",
        analyze_fn=lambda _request: None,  # type: ignore[arg-type]
    )

    joined = "\n".join(prompts)
    assert text == "masked answer"
    assert error is None
    assert "runtime-token-12345" not in joined
    assert "hunter2" not in joined
    assert "secret-key-12345" not in joined
    assert "operator-secret-12345" not in joined
    assert "context-secret-12345" not in joined
    assert "[MASKED]" in joined


@pytest.mark.asyncio
async def test_query_history_is_masked_at_capture(monkeypatch) -> None:
    history: list[dict] = []

    async def fake_tool(settings, target, args):
        return {
            "query": "kubectl get secret token=query-secret-12345",
            "summary": "api_key=tool-summary-secret-12345",
            "result": {"data": "password=tool-result-secret-12345"},
        }

    tools = {"k8s_read": {"description": "d", "call": fake_tool}}
    decision = {"queries": [{"tool": "k8s_read", "args": {"kind": "secrets"}}]}

    await chat_agent._run_queries(_settings(), tools, None, decision, history)  # type: ignore[arg-type]

    serialized = str(history)
    assert "query-secret-12345" not in serialized
    assert "tool-summary-secret-12345" not in serialized
    assert "tool-result-secret-12345" not in serialized
    assert "[MASKED]" in serialized


@pytest.mark.asyncio
async def test_query_defaults_to_incident_target(monkeypatch) -> None:
    seen_targets: list = []
    systems: list[str] = []

    async def fake_tool(settings, target, args):
        seen_targets.append(target)
        return {"query": "kubectl get pods", "summary": "ok", "result": {}}

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        systems.append(system)
        return {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}]}

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        return "done", None

    monkeypatch.setattr(
        chat_agent, "_flat_tools", lambda settings: {"k8s_read": {"description": "d", "call": fake_tool}}
    )
    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)

    await chat_agent.answer_chat(
        _settings(),
        ChatRequest(
            message="원인이 뭐야",
            incident_id="INC-1",
            context={"target": {"labels": {"namespace": "runai", "pod": "trainer-0"}}},
        ),
        "ctx",
        analyze_fn=lambda _request: None,  # type: ignore[arg-type]
    )

    # A query that omits pod/namespace now defaults to the incident's target,
    # and the LLM is told that default scope.
    assert seen_targets and seen_targets[0].namespace == "runai"
    assert seen_targets[0].pod == "trainer-0"
    assert any("namespace=runai" in s and "pod=trainer-0" in s for s in systems)


@pytest.mark.asyncio
async def test_final_llm_answer_is_masked_before_return(monkeypatch) -> None:
    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        return {"action": "wait"}

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        return "api_key=final-secret-12345", None

    monkeypatch.setattr(chat_agent, "_flat_tools", lambda settings: {})
    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="status?"), "ctx", analyze_fn=lambda _request: None
    )

    assert error is None
    assert "final-secret-12345" not in text
    assert "[MASKED]" in text


@pytest.mark.asyncio
async def test_final_llm_error_is_masked_before_return(monkeypatch) -> None:
    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        return {"action": "wait"}

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        return None, "HTTP 401 api_key=error-secret-12345"

    monkeypatch.setattr(chat_agent, "_flat_tools", lambda settings: {})
    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="status?"), "ctx", analyze_fn=lambda _request: None
    )

    assert text is None
    assert "error-secret-12345" not in error
    assert "[MASKED]" in error


@pytest.mark.asyncio
async def test_failed_tool_result_is_not_sent_to_final_chat_llm(monkeypatch) -> None:
    prompts: list[str] = []

    async def fake_tool(settings, target, args):
        return {
            "query": "kubectl get pods",
            "summary": "query failed; stale output mentioned DiskPressure",
            "error": "query failed; stale output mentioned DiskPressure",
            "result": {"message": "DiskPressure=True; pods evicted"},
        }

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        prompts.append(user)
        return {
            "action": "query",
            "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}],
        }

    async def fake_complete_with_error(settings, *, system, user, model=None, **kw):
        prompts.append(user)
        return "no live evidence", None

    monkeypatch.setattr(
        chat_agent,
        "_flat_tools",
        lambda settings: {"k8s_read": {"description": "d", "call": fake_tool}},
    )
    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)
    monkeypatch.setattr(chat_agent, "complete_with_error", fake_complete_with_error)

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="check pods"), "ctx", analyze_fn=lambda _request: None
    )

    final_prompt = prompts[-1]
    assert text == "no live evidence"
    assert error is None
    assert "DiskPressure" not in final_prompt
    assert "pods evicted" not in final_prompt
    assert "query failed" in final_prompt


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
async def test_analyze_history_is_masked_at_capture() -> None:
    history: list[dict] = []

    async def analyze_fn(_request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        return AlertAnalysisResponse(
            status="ok",
            analysis="d",
            analysis_summary="quota api_key=analysis-summary-secret-12345",
            analysis_detail="detail password=analysis-detail-secret-12345",
            analysis_type="chat",
            analysis_quality="high",
            missing_data=[],
            warnings=[],
            capabilities={},
            context={},
            artifacts=[],
        )

    await chat_agent._run_analysis(
        _settings(),
        analyze_fn,
        {
            "target": {
                "namespace": "runai",
                "reason": "investigate token=analysis-reason-secret-12345",
            }
        },
        history,
    )

    serialized = str(history)
    assert "analysis-summary-secret-12345" not in serialized
    assert "analysis-detail-secret-12345" not in serialized
    assert "analysis-reason-secret-12345" not in serialized
    assert "[MASKED]" in serialized


@pytest.mark.asyncio
async def test_empty_question_returns_error() -> None:
    async def analyze_fn(_request):
        raise AssertionError

    text, error = await chat_agent.answer_chat(
        _settings(), ChatRequest(message="   "), "ctx", analyze_fn=analyze_fn
    )
    assert text is None
    assert error == "empty question"


@pytest.mark.asyncio
async def test_legacy_llm_chat_prompt_redacts_sensitive_inputs(monkeypatch) -> None:
    captured: dict[str, str] = {}

    async def fake_complete_with_error(settings, *, user, **_kwargs):
        captured["user"] = user
        return "ok", None

    monkeypatch.setattr(
        "app.services.orchestrator.complete_with_error", fake_complete_with_error
    )
    orchestrator = AnalysisOrchestrator(_settings())

    text, error = await orchestrator._llm_chat_answer(
        ChatRequest(message="why password=operator-secret-12345"),
        grounding="ctx api_key=context-secret-12345",
    )

    assert text == "ok"
    assert error is None
    assert "operator-secret-12345" not in captured["user"]
    assert "context-secret-12345" not in captured["user"]
    assert "[MASKED]" in captured["user"]


@pytest.mark.asyncio
async def test_cluster_scope_prompt_when_no_context(monkeypatch) -> None:
    """No incident/alert context (backend scope=cluster) → the decision prompt must
    forbid presenting dashboard stats as live cluster inventory."""
    captured: list[str] = []

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        captured.append(system)
        return {"action": "answer", "answer": "ok"}

    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)

    async def analyze_fn(_request):
        raise AssertionError("analyze should not run")

    request = ChatRequest(message="how many nodes?", context={"scope": "cluster"})
    text, error = await chat_agent.answer_chat(_settings(), request, "ctx", analyze_fn=analyze_fn)
    assert error is None and text == "ok"
    assert "NO incident/alert context is selected" in captured[0]
    assert "NOT live cluster inventory" in captured[0]


@pytest.mark.asyncio
async def test_incident_scope_prompt_omits_cluster_rule(monkeypatch) -> None:
    captured: list[str] = []

    async def fake_complete_json(settings, *, system, user, model=None, **kw):
        captured.append(system)
        return {"action": "answer", "answer": "ok"}

    monkeypatch.setattr(chat_agent, "complete_json", fake_complete_json)

    async def analyze_fn(_request):
        raise AssertionError("analyze should not run")

    request = ChatRequest(
        message="what happened?", incident_id="INC-1", context={"scope": "incident"}
    )
    await chat_agent.answer_chat(_settings(), request, "ctx", analyze_fn=analyze_fn)
    assert "NO incident/alert context is selected" not in captured[0]


def test_is_cluster_scope_fallback_without_backend_scope() -> None:
    """Older backends send no scope key — fall back to the id/context presence."""
    assert chat_agent._is_cluster_scope(ChatRequest(message="q")) is True
    assert chat_agent._is_cluster_scope(ChatRequest(message="q", incident_id="INC-1")) is False
    assert (
        chat_agent._is_cluster_scope(ChatRequest(message="q", context={"alert": {"id": "A"}}))
        is False
    )


def test_strip_tool_echo_drops_leading_history_blocks() -> None:
    # 2026-07-21 incident: the model pasted gathered_so_far-format JSON ahead of
    # its real answer after its <think> transcript was stripped by the transport.
    echoed = (
        '[{"tool": "k8s_read", "query": "kubectl get events -n runai-backend", '
        '"summary": "HTTP 200", "result": "{}"}, '
        '{"tool": "promql_query", "query": "up", "summary": "HTTP 200", "result": "{}"}]\n'
        "\n### 답변\nthanos receive 파드는 1개뿐입니다."
    )
    assert chat_agent._strip_tool_echo(echoed) == "### 답변\nthanos receive 파드는 1개뿐입니다."


def test_strip_tool_echo_keeps_inline_and_plain_answers() -> None:
    plain = "파드 수는 `[{\"tool\": ...}]` 형식과 무관합니다."
    assert chat_agent._strip_tool_echo(plain) == plain
    # A list that is NOT tool-history shape stays (e.g. an answer starting with a
    # legitimate JSON list the operator asked for).
    listy = '[{"pod": "a"}, {"pod": "b"}] 두 파드가 실행 중입니다.'
    assert chat_agent._strip_tool_echo(listy) == listy
