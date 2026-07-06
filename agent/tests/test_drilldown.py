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

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
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

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
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

    async def always_query(settings, *, system, user, temperature=0.1, model=None):
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

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
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

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
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

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
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
    async def broken_complete_json(settings, *, system, user, temperature=0.1, model=None):
        raise RuntimeError("llm gateway down")

    monkeypatch.setattr(drilldown, "complete_json", broken_complete_json)
    result = _k8s_result()
    await run_drilldowns(drill_settings(), [result], _target(), None)
    assert result.artifacts == []


def test_salient_markers_scan_only_string_leaves() -> None:
    from app.collectors.base import salient_markers

    data = {
        "error": None,  # a key named error must NOT count as a signal
        "status": {"phase": "Running", "reason": "CrashLoopBackOff"},
        "events": ["Back-off restarting failed container", "NVRM: Xid 79 detected"],
        "count": 3,
    }
    markers = salient_markers(data)
    assert "CrashLoopBackOff" in markers
    assert any("Xid" in m for m in markers)
    assert salient_markers({"status": {"phase": "Running"}, "error": None}) == []


def test_k8s_tool_reports_kubectl_command_title_and_highlights(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_read",
                        "args": {"kind": "pods", "namespace": "runai", "name": "t-0"},
                    }
                ],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        return {
            "kind": "pods",
            "status_code": 200,
            "error": None,
            "data": {"status": {"reason": "OOMKilled"}},
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    settings = replace(drill_settings(), language="ko")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    art = result.artifacts[0]
    assert art.query == "kubectl get pods t-0 -n runai"
    assert art.title == "파드 조회"
    assert art.highlights == ["OOMKilled"]
    assert "주요 신호" in (art.summary or "") and "OOMKilled" in (art.summary or "")


def test_sql_validate_select_is_fail_closed() -> None:
    from app.services.drilldown import _validate_select

    ok, sql = _validate_select("SELECT id, status FROM workloads WHERE name = 'x';")
    assert ok is None and sql.endswith("name = 'x'")
    assert _validate_select("")[0]
    assert _validate_select("DELETE FROM workloads")[0]
    assert _validate_select("SELECT 1; DROP TABLE workloads")[0]
    assert _validate_select("WITH x AS (SELECT 1) INSERT INTO y SELECT * FROM x")[0]
    assert _validate_select("EXPLAIN SELECT 1")[0]  # not SELECT/WITH-leading
    # column names containing forbidden words as substrings are fine
    assert _validate_select("SELECT created_at, updated_at FROM audit")[0] is None


def test_sql_tool_targets_runai_db_and_appends_limit(monkeypatch) -> None:
    captured: dict = {}

    async def fake_run_select(dsn, sql, timeout):
        captured["dsn"] = dsn
        captured["sql"] = sql
        return [{"id": 1}]

    monkeypatch.setattr(drilldown, "_run_select", fake_run_select)
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [{"tool": "sql_select", "args": {"query": "SELECT id FROM workloads"}}],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    settings = drill_settings(runai_db_dsn="postgres://ro@runai-db/runai")
    result = CollectorResult(agent="postgres", status="ok", summary="db health ok")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    assert captured["dsn"] == "postgres://ro@runai-db/runai"
    assert captured["sql"] == "SELECT id FROM workloads LIMIT 50"
    assert result.artifacts[0].query == "SELECT id FROM workloads LIMIT 50"


def test_postgres_agent_has_no_sql_tool_without_any_dsn(monkeypatch) -> None:
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls[0] += 1
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = CollectorResult(agent="postgres", status="ok", summary="db")
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert calls[0] == 0  # make_settings has no postgres_dsn / runai_db_dsn
