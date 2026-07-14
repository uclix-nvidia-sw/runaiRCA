from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP

from app import mcp_client
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.mcp_client import mcp_call, mcp_call_many, mcp_reachability, mcp_tool_json
from tests.test_orchestrator import make_settings, make_target


def _free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
        return port
    except PermissionError as exc:
        pytest.skip(f"local port bind is not permitted in this sandbox: {exc}")
    finally:
        sock.close()


@pytest.mark.asyncio
async def test_mcp_budget_is_shared_across_sequential_calls() -> None:
    async with mcp_client.mcp_budget(0.04):
        await mcp_client._within_mcp_budget(lambda: asyncio.sleep(0.025))
        with pytest.raises(TimeoutError, match="before direct fallback"):
            await mcp_client._within_mcp_budget(lambda: asyncio.sleep(0.025))


@contextlib.asynccontextmanager
async def _serve_mcp(mcp: FastMCP) -> AsyncIterator[str]:
    server = uvicorn.Server(
        uvicorn.Config(
            mcp.streamable_http_app(),
            host=mcp.settings.host,
            port=mcp.settings.port,
            log_level="warning",
        )
    )
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(50):
            if server.started:
                break
            await asyncio.sleep(0.05)
        assert server.started
        yield f"http://{mcp.settings.host}:{mcp.settings.port}/mcp"
    finally:
        server.should_exit = True
        await task


def _fake_datasource_mcp() -> FastMCP:
    mcp = FastMCP(
        "fake-datasource-mcp",
        host="127.0.0.1",
        port=_free_port(),
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    def echo(value: str) -> dict[str, str]:
        return {"value": value}

    @mcp.tool()
    def list_datasources() -> list[dict[str, str]]:
        return [{"type": "prometheus", "uid": "prom"}, {"type": "loki", "uid": "loki"}]

    @mcp.tool()
    def query_prometheus(
        query: str = "",
        expr: str = "",
        datasourceUid: str = "",
        datasource_uid: str = "",
    ) -> dict:
        return {"status": "success", "data": {"result": [{"metric": {}, "value": [1, "1"]}]}}

    @mcp.tool()
    def query_loki_logs(
        datasourceUid: str,
        logql: str,
        limit: int = 20,
        direction: str = "backward",
        queryType: str = "range",
        startRfc3339: str = "",
        endRfc3339: str = "",
    ) -> dict:
        return {"status": "success", "data": {"result": [{"values": [["1", "failed"]]}]}}

    @mcp.tool()
    def pods_get(namespace: str, name: str = "", pod: str = "") -> dict:
        pod_name = name or pod
        return {
            "metadata": {"name": pod_name, "namespace": namespace},
            "spec": {"containers": [{"name": "main", "resources": {}}]},
            "status": {"phase": "Running", "containerStatuses": [{"name": "main"}]},
        }

    @mcp.tool()
    def pods_log(namespace: str, name: str = "", tail: int = 50) -> str:
        return "2026-07-07T00:00:00Z fake log line"

    @mcp.tool()
    def pods_list_in_namespace(namespace: str = "") -> dict:
        return {"items": []}

    @mcp.tool()
    def pods_list(namespace: str = "") -> dict:
        return {"items": []}

    @mcp.tool()
    def events_list(namespace: str = "") -> dict:
        return {"items": []}

    @mcp.tool()
    def resources_list(
        apiVersion: str = "",
        kind: str = "",
        namespace: str = "",
        fieldSelector: str = "",
    ) -> dict:
        return {"items": []}

    @mcp.tool()
    def query(sql: str) -> list[dict]:
        text = sql.lower()
        if "count(*)" in text:
            return [{"active_connections": 1}]
        if "pg_extension" in text:
            return [{"exists": True}]
        if "unnest" in text:
            return [
                {"table_name": "incidents", "exists": True},
                {"table_name": "alerts", "exists": True},
                {"table_name": "incident_embeddings", "exists": True},
                {"table_name": "rca_feedback", "exists": True},
                {"table_name": "analysis_runs", "exists": True},
            ]
        return []

    return mcp


class _Result:
    def __init__(
        self,
        *,
        text: str = "",
        structured: object = None,
        is_error: bool = False,
    ) -> None:
        self.content = [type("Block", (), {"text": text})()] if text else []
        self.structuredContent = structured
        self.isError = is_error


def test_mcp_error_and_fallback_messages_are_masked_and_folded() -> None:
    text = mcp_client.mcp_tool_text(
        _Result(text="line one password=mcp-text-secret-12345\nline two")
    )
    warning = mcp_client.mcp_fallback_warning(
        RuntimeError("gateway failed api_key=mcp-fallback-secret-12345\n## injected")
    )
    error = mcp_client.mcp_error(
        _Result(
            text="tool failed password=mcp-error-secret-12345\n## injected",
            is_error=True,
        )
    )

    joined = f"{text}\n{warning}\n{error}"
    assert "mcp-text-secret-12345" not in joined
    assert "mcp-fallback-secret-12345" not in joined
    assert "mcp-error-secret-12345" not in joined
    assert "line one password=[MASKED]\nline two" in text
    assert "\n## injected" not in joined
    assert "[MASKED]" in joined


def test_mcp_tool_json_masks_structured_and_raw_text() -> None:
    structured = mcp_client.mcp_tool_json(
        _Result(structured={"message": "ok", "api_key": "mcp-structured-secret-12345"})
    )
    text_json = mcp_client.mcp_tool_json(
        _Result(
            text='{"message":"ok","access_token":"mcp-json-secret-12345",'
            '"nested":{"password":"mcp-nested-secret-12345"}}'
        )
    )
    raw = mcp_client.mcp_tool_json(
        _Result(text="not-json token=mcp-raw-secret-12345\n## injected")
    )

    assert structured == {"message": "ok", "api_key": "[MASKED]"}
    assert text_json == {
        "message": "ok",
        "access_token": "[MASKED]",
        "nested": {"password": "[MASKED]"},
    }
    assert "mcp-raw-secret-12345" not in raw["raw"]
    assert "\n## injected" not in raw["raw"]
    assert "[MASKED]" in raw["raw"]


@pytest.mark.asyncio
async def test_k8s_mcp_json_skips_unparseable_table_for_yaml_candidate(monkeypatch) -> None:
    # kubernetes-mcp-server's events_list answers with a human table (not YAML);
    # it "succeeds" at the protocol level but can't be parsed. _k8s_mcp_json must
    # fall through to the yaml-capable resources_list instead of raising and
    # losing the events evidence to the direct-API fallback.
    from app.collectors import kubernetes

    async def fake_mcp_call(url, tool, arguments):
        if tool == "events_list":
            return _Result(
                text="NAMESPACE  LAST SEEN  TYPE     REASON   OBJECT    MESSAGE\n"
                "runai      2m         Warning  BackOff  pod/foo   Back-off restarting"
            )
        if tool == "resources_list":
            return _Result(text="items:\n- kind: Event\n  reason: BackOff\n")
        return _Result(text="")

    monkeypatch.setattr(kubernetes, "mcp_call", fake_mcp_call)
    candidates = [
        ("events_list", {"namespace": "runai"}),
        ("resources_list", {"kind": "Event", "namespace": "runai"}),
    ]
    result = await kubernetes._k8s_mcp_json(make_settings(), candidates)
    assert isinstance(result, dict) and result.get("items"), result


def test_mcp_client_factory_defaults_insecure_and_hardens_via_env(monkeypatch) -> None:
    # Internal self-signed MCP endpoints: default to a custom (verify-off) factory;
    # MCP_TLS_VERIFY=true restores the SDK default (system trust → None).
    monkeypatch.delenv("MCP_TLS_VERIFY", raising=False)
    assert mcp_client._mcp_client_factory() is not None
    monkeypatch.setenv("MCP_TLS_VERIFY", "true")
    assert mcp_client._mcp_client_factory() is None


@pytest.mark.asyncio
async def test_mcp_client_connects_to_real_streamable_http_server() -> None:
    async with _serve_mcp(_fake_datasource_mcp()) as url:
        result = await mcp_call(url, "echo", {"value": "ok"})
        batch = await mcp_call_many(
            url,
            [("echo", {"value": "one"}), ("echo", {"value": "two"})],
        )
        report = await mcp_reachability({"fake": url}, timeout_seconds=2)

    assert mcp_tool_json(result) == {"value": "ok"}
    assert [mcp_tool_json(item) for item in batch] == [
        {"value": "one"},
        {"value": "two"},
    ]
    assert report == {"fake": "ok (11 tools)"}


@pytest.mark.asyncio
async def test_mcp_reachability_checks_services_concurrently_with_deadlines(
    monkeypatch,
) -> None:
    import mcp
    from mcp.client import streamable_http

    started: set[str] = set()

    @contextlib.asynccontextmanager
    async def fake_stream(url, **_kwargs):
        yield url, object(), None

    class FakeSession:
        def __init__(self, read, _write) -> None:
            self.url = read

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def initialize(self) -> None:
            started.add(self.url)
            if self.url == "slow":
                await asyncio.sleep(1)

        async def list_tools(self):
            return type("Tools", (), {"tools": [object()]})()

    monkeypatch.setattr(streamable_http, "streamablehttp_client", fake_stream)
    monkeypatch.setattr(mcp, "ClientSession", FakeSession)

    report = await mcp_reachability(
        {"slow": "slow", "fast": "fast"}, timeout_seconds=0.02
    )

    assert started == {"slow", "fast"}
    assert report["fast"] == "ok (1 tools)"
    assert report["slow"].startswith("unreachable: TimeoutError")


@pytest.mark.asyncio
async def test_startup_mcp_self_check_retries_without_gating_readiness(
    monkeypatch,
) -> None:
    from app import main
    from app.collectors import runai as runai_mod

    calls: list[dict[str, dict[str, str]]] = []

    async def fake_headers(_settings):
        return {"Authorization": "Bearer token"}, []

    async def fake_reachability(_urls, *, headers_by_name, timeout_seconds=10.0):
        calls.append(headers_by_name)
        if len(calls) == 1:
            return {"runai": "unreachable: ConnectError"}
        return {"runai": "ok (16 tools)"}

    monkeypatch.setattr(runai_mod, "_runai_headers", fake_headers)
    monkeypatch.setattr(mcp_client, "mcp_reachability", fake_reachability)
    monkeypatch.setattr(main, "_MCP_SELF_CHECK_RETRY_DELAYS", (0.0, 0.0))
    monkeypatch.setattr(
        main,
        "settings",
        replace(
            main.settings,
            runai_mcp_url="http://runai-mcp:8080/mcp",
            kubernetes_mcp_url="",
            prometheus_mcp_url="",
            loki_mcp_url="",
            postgres_mcp_url="",
        ),
    )

    await main._log_mcp_reachability()

    assert len(calls) == 2
    assert all(
        call["runai"]["Authorization"] == "Bearer token" for call in calls
    )


@pytest.mark.asyncio
async def test_datasource_collectors_attach_to_real_streamable_http_mcp() -> None:
    target = make_target()
    async with _serve_mcp(_fake_datasource_mcp()) as url:
        settings = replace(
            make_settings(),
            prometheus_url="http://direct-prometheus",
            prometheus_mcp_url=url,
            loki_url="http://direct-loki",
            loki_mcp_url=url,
            kubernetes_mcp_url=url,
            postgres_mcp_url=url,
        )
        results = [
            await PrometheusCollector(settings).collect(target),
            await LokiCollector(settings).collect(target),
            await KubernetesCollector(settings).collect(target),
            await PostgresCollector(settings).collect(target),
        ]

    assert all(result.details.get("used_mcp") is True for result in results)
