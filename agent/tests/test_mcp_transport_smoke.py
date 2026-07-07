from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP

from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.mcp_client import mcp_call, mcp_tool_json
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
        query: str = "",
        logql: str = "",
        datasourceUid: str = "",
        datasource_uid: str = "",
        limit: int = 20,
        direction: str = "BACKWARD",
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
    def pods_log(namespace: str, name: str = "", pod: str = "", tailLines: int = 50) -> str:
        return "2026-07-07T00:00:00Z fake log line"

    @mcp.tool()
    def pods_list_in_namespace(namespace: str = "") -> dict:
        return {"items": []}

    @mcp.tool()
    def pods_list(namespace: str = "") -> dict:
        return {"items": []}

    @mcp.tool()
    def events_list(namespace: str = "", fieldSelector: str = "") -> dict:
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
                {"table_name": "rca_comments", "exists": True},
                {"table_name": "analysis_runs", "exists": True},
            ]
        return []

    return mcp


@pytest.mark.asyncio
async def test_mcp_client_connects_to_real_streamable_http_server() -> None:
    async with _serve_mcp(_fake_datasource_mcp()) as url:
        result = await mcp_call(url, "echo", {"value": "ok"})

    assert mcp_tool_json(result) == {"value": "ok"}


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
