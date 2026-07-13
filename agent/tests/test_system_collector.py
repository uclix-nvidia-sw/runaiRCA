from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import system as system_mod
from app.collectors.base import AnalysisTarget
from app.collectors.http_json import JsonResponse
from app.collectors.system import SystemCollector, _base_url_for_node, _lines, system_log_query


def _target(node: str = "gpu-node-1") -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node=node,
        pod="",
        severity="warning",
        alert_name="RunAIAlert",
    )


class _Settings:
    enable_system_agent = True
    system_agent_url = "http://{node}:9095"
    system_agent_token = ""
    system_agent_timeout_seconds = 6
    # llm_configured() reads these; unset -> deterministic path.
    llm_base_url = ""
    llm_model = ""
    llm_api_key = ""


def test_base_url_substitutes_node() -> None:
    assert _base_url_for_node("http://{node}:9095", "n1") == "http://n1:9095"
    assert _base_url_for_node("http://{node}:9095", "n1/../../evil@host") == (
        "http://n1%2F..%2F..%2Fevil%40host:9095"
    )
    # No placeholder -> used as-is (shared endpoint).
    assert _base_url_for_node("http://svc:9095", "n1") == "http://svc:9095"


@pytest.mark.asyncio
async def test_node_internal_ip_encodes_node_path_segment(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Settings(_Settings):
        kubernetes_token_path = "/token"
        kubernetes_ca_path = ""
        kubernetes_api_url = "https://kubernetes.default.svc"
        kubernetes_timeout_seconds = 5

    async def fake_get_json(**kwargs):
        calls.append(kwargs["path"])
        return JsonResponse(url=kwargs["path"], status_code=404, data={})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    monkeypatch.setattr("app.collectors.kubernetes._read_file", lambda _path: "token")

    await system_mod._node_internal_ip(Settings(), "node/../../pods")

    assert calls == ["/api/v1/nodes/node%2F..%2F..%2Fpods"]


def test_lines_tolerates_shapes() -> None:
    assert _lines({"lines": ["a", "b"]}) == ["a", "b"]
    assert _lines({"body": "a\nb"}) == ["a", "b"]
    assert _lines(["x", 1]) == ["x", "1"]
    assert _lines("nope") == []


@pytest.mark.asyncio
async def test_unconfigured_is_unavailable() -> None:
    class Off(_Settings):
        enable_system_agent = False

    result = await SystemCollector(Off()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.url"]


@pytest.mark.asyncio
async def test_no_node_is_unavailable() -> None:
    result = await SystemCollector(_Settings()).collect(_target(node=""))
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.node"]


@pytest.mark.asyncio
async def test_detects_kernel_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = {
        "dmesg": [
            "NVRM: Xid (PCI:0000:65:00): 79, GPU has fallen off the bus.",
            "eth0: link up",
        ],
        "journal": ["systemd: started thing"],
        "syslog": ["kernel: EXT4-fs error (device sda1): bad block"],
    }

    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        source = params["source"]
        return JsonResponse(
            url=f"{base_url}{path}?source={source}",
            status_code=200,
            data={"lines": payloads[source]},
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)

    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    assert result.confidence == "high"
    # XID + "fallen off the bus" + ext4 error surfaced; benign lines dropped.
    detail_sources = {s["source"]: s for s in result.details["sources"]}
    assert detail_sources["dmesg"]["error_count"] == 1
    assert detail_sources["journal"]["error_count"] == 0
    assert detail_sources["syslog"]["error_count"] == 1
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")


@pytest.mark.asyncio
async def test_reachable_but_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=200, data={"lines": ["all good"]})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    assert result.confidence == "medium"
    assert result.missing_data == []


@pytest.mark.asyncio
async def test_historical_incident_scopes_journal_and_ignores_current_tails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(*, params, **kwargs):
        calls.append(params)
        source = params["source"]
        # A current dmesg/syslog error is useful context, but cannot establish
        # a cause for a months-old incident. The time-bounded journal is clean.
        lines = ["NVRM: Xid 79"] if source in {"dmesg", "syslog"} else ["all good"]
        return JsonResponse(url="http://node/logs", status_code=200, data={"lines": lines})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await SystemCollector(_Settings()).collect(target)

    journal_params = next(params for params in calls if params["source"] == "journal")
    assert journal_params == {
        "source": "journal",
        "lines": "500",
        "since": "2026-01-02T02:55:00Z",
        "until": "2026-01-02T03:15:00Z",
    }
    assert all(
        "since" not in params for params in calls if params["source"] in {"dmesg", "syslog"}
    )
    assert result.status == "ok"
    assert result.confidence == "medium"
    assert "journal" in result.summary
    assert result.details["time_range"] == {
        "start": "2026-01-02T02:55:00Z",
        "end": "2026-01-02T03:15:00Z",
    }
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("absent", "scoped")


@pytest.mark.asyncio
async def test_all_sources_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=0, error="ConnectError: refused")

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.query"]
    assert result.warnings


@pytest.mark.asyncio
async def test_system_log_query_is_scoped_bounded_and_body_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(
            url="http://node/logs",
            status_code=200,
            data={"body": "api_key=raw-host-secret", "lines": ["NVRM: Xid 79", "healthy"]},
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    query = await system_log_query(
        _Settings(),
        _target(),
        {"source": "journal", "lookback_seconds": 120, "lines": 2, "grep": "NVRM: Xid"},
    )

    assert calls[0]["params"] == {"source": "journal", "lines": "2", "grep": r"NVRM:\ Xid"}
    assert query["source_group"] == "node_system"
    assert query["independence_group"] == "node_system"
    observation = query["observation"]
    assert observation["observed_entity"] == {"kind": "node", "name": "gpu-node-1"}
    assert observation["window"] == {"lookback_seconds": 120}
    assert observation["polarity"] == "present"
    assert observation["coverage"] == "partial"
    assert set(observation["observation_window"]) == {"start", "end"}
    assert observation["signal_types"] == ["gpu_driver"]
    assert observation["body_included"] is False
    assert "raw-host-secret" not in str(query)
    assert "NVRM: Xid 79" not in str(query)


@pytest.mark.asyncio
async def test_system_log_query_refuses_scope_or_limit_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fake_get_json(**kwargs):
        nonlocal called
        called = True
        return JsonResponse(url="u", status_code=200, data={"lines": []})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    query = await system_log_query(
        _Settings(), _target(), {"source": "journal", "node": "other-node", "lines": 1001}
    )

    assert query["error"] == "node must match the alert node scope"
    assert query["observation"]["coverage"] == "unknown"
    assert called is False


@pytest.mark.asyncio
async def test_system_log_query_refuses_unsafe_grep_and_line_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_json(**kwargs):
        raise AssertionError("invalid arguments must not make a request")

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    too_many = await system_log_query(_Settings(), _target(), {"source": "journal", "lines": 1001})
    unsafe = await system_log_query(
        _Settings(), _target(), {"source": "journal", "grep": "line\nnext"}
    )

    assert too_many["error"] == "lines must be between 1 and 1000"
    assert unsafe["error"] == "grep must not contain control characters"
