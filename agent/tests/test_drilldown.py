from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget, CollectorResult
from app.services import drilldown
from app.services.drilldown import _tool_runai_get, run_drilldowns
from tests.test_orchestrator import make_settings


def drill_settings(**overrides):
    return replace(
        make_settings(),
        enable_agent_drilldown=True,
        drilldown_max_steps=3,
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        **overrides,
    )


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai-vision",
        workload_name="train-1",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="",
        severity="warning",
        alert_name="TestAlert",
    )


def _k8s_result() -> CollectorResult:
    return CollectorResult(
        agent="kubernetes", status="ok", summary="pod train-1-0 Pending; FailedScheduling"
    )


def test_disabled_flag_means_no_llm_calls(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        calls.append(system)
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    settings = replace(drill_settings(), enable_agent_drilldown=False)
    result = _k8s_result()
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    assert calls == []
    assert result.artifacts == []


def test_drilldown_appends_tagged_artifacts_and_stops_on_done(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "query",
                "reason": "check events",
                "queries": [
                    {"tool": "k8s_read", "args": {"kind": "events", "namespace": "runai-vision"}}
                ],
            },
            {"action": "done", "reason": "enough"},
        ]
    )
    seen_args: list[dict] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        return next(decisions)

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        seen_args.append({"kind": kind, "namespace": namespace})
        return {"kind": kind, "status_code": 200, "error": None, "items": []}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert seen_args == [{"kind": "events", "namespace": "runai-vision"}]
    assert [a.type for a in result.artifacts] == ["drilldown_query"]
    assert result.artifacts[0].status == "ok"


def test_loop_is_bounded_by_max_steps_and_queries_per_step(monkeypatch) -> None:
    llm_calls = [0]
    tool_calls = [0]

    async def always_query(settings, *, system, user, temperature=0.1):
        llm_calls[0] += 1
        return {
            "action": "query",
            "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}} for _ in range(9)],
        }

    async def fake_k8s_read(settings, kind, **kwargs):
        tool_calls[0] += 1
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", always_query)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert llm_calls[0] == 3  # drilldown_max_steps
    assert tool_calls[0] == 9  # 3 steps x 3 queries/step cap (9 requested per step)


def test_tool_scoping_is_structural(monkeypatch) -> None:
    # No loki_url / runai_mcp_url in settings -> those agents get NO tools and no
    # loop; kubernetes still drills. An agent can never reach another domain's
    # tools because its registry simply doesn't contain them.
    drilled_agents: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        drilled_agents.append(system.split(" ")[3])  # "You are the {agent} evidence..."
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    results = [
        _k8s_result(),
        CollectorResult(agent="loki", status="ok", summary="logs"),
        CollectorResult(agent="runai", status="ok", summary="workloads"),
        CollectorResult(agent="postgres", status="ok", summary="db"),
    ]
    asyncio.run(run_drilldowns(drill_settings(), results, _target(), None))
    assert drilled_agents == ["kubernetes"]


def test_unavailable_collectors_are_skipped(monkeypatch) -> None:
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        calls[0] += 1
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = CollectorResult(agent="kubernetes", status="unavailable", summary="no token")
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert calls[0] == 0


def test_tool_failure_becomes_observation_not_crash(monkeypatch) -> None:
    decisions = iter(
        [
            {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}]},
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        return next(decisions)

    async def broken_k8s_read(settings, kind, **kwargs):
        raise RuntimeError("apiserver exploded")

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", broken_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert len(result.artifacts) == 1
    assert result.artifacts[0].status == "unavailable"
    assert "apiserver exploded" in (result.artifacts[0].summary or "")


def test_runai_get_tool_refuses_non_api_paths(monkeypatch) -> None:
    mcp_calls = [0]

    async def fake_mcp_call(settings, tool, arguments):
        mcp_calls[0] += 1
        raise AssertionError("must not be reached")

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    outcome = asyncio.run(_tool_runai_get(settings, _target(), {"path": "/auth/token"}))
    assert outcome["error"] and "GET" in outcome["error"]
    assert mcp_calls[0] == 0


def test_runai_get_tool_locks_method_to_get(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        isError = False
        content = []

    async def fake_mcp_call(settings, tool, arguments):
        captured["tool"] = tool
        captured["arguments"] = arguments
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    outcome = asyncio.run(
        _tool_runai_get(
            settings,
            _target(),
            # A hostile/hallucinated request cannot change the verb: method is not
            # an accepted argument and the wrapper hardcodes GET.
            {"path": "/api/v1/workloads", "method": "DELETE", "query": {"name": "x"}},
        )
    )
    assert captured["tool"] == "call_runai_api"
    assert captured["arguments"]["method"] == "GET"
    assert outcome["error"] is None


@pytest.mark.asyncio
async def test_never_raises_even_if_llm_layer_explodes(monkeypatch) -> None:
    async def broken_complete_json(settings, *, system, user, temperature=0.1):
        raise RuntimeError("llm gateway down")

    monkeypatch.setattr(drilldown, "complete_json", broken_complete_json)
    result = _k8s_result()
    await run_drilldowns(drill_settings(), [result], _target(), None)
    assert result.artifacts == []
