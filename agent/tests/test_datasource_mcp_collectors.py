from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors import kubernetes, loki, postgres, prometheus
from app.collectors.http_json import JsonResponse
from tests.test_orchestrator import make_settings, make_target


class _McpResult:
    isError = False

    def __init__(self, structured=None, text: str = "") -> None:
        self.structuredContent = structured
        self.content = [SimpleNamespace(text=text)] if text else []


@pytest.mark.asyncio
async def test_prometheus_collector_uses_mcp_before_direct_http(monkeypatch) -> None:
    calls: list[str] = []
    query_args: list[dict] = []

    async def fake_mcp_call(url, tool, arguments):
        calls.append(tool)
        if tool == "list_datasources":
            return _McpResult([{"type": "prometheus", "uid": "prom"}])
        query_args.append(arguments)
        return _McpResult(
            {"status": "success", "data": {"result": [{"metric": {}, "value": [1, "1"]}]}}
        )

    async def direct_should_not_run(**kwargs):
        raise AssertionError("direct Prometheus HTTP fallback should not run")

    monkeypatch.setattr(prometheus, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(prometheus, "get_json", direct_should_not_run)
    result = await prometheus.PrometheusCollector(
        replace(
            make_settings(),
            prometheus_url="http://prometheus",
            prometheus_mcp_url="http://grafana-mcp/mcp",
        )
    ).collect(
        replace(
            make_target(),
            fired_at="2026-07-10T01:00:00Z",
            resolved_at="2026-07-10T01:10:00Z",
        )
    )

    assert result.details["used_mcp"] is True
    assert "query_prometheus" in calls
    assert query_args
    assert all(args["datasourceUid"] == "prom" for args in query_args)
    assert all(args["queryType"] == "range" for args in query_args)
    assert all(args["startTime"] == "2026-07-10T00:55:00Z" for args in query_args)
    assert all(args["endTime"] == "2026-07-10T01:15:00Z" for args in query_args)
    assert all(args["stepSeconds"] == 60 and "expr" in args for args in query_args)
    assert all("query" not in args and "datasource_uid" not in args for args in query_args)


@pytest.mark.asyncio
async def test_prometheus_collector_falls_back_to_direct_http_on_mcp_failure(
    monkeypatch,
) -> None:
    direct_calls = 0

    async def broken_mcp_call(url, tool, arguments):
        raise RuntimeError("mcp down")

    async def fake_get_json(**kwargs):
        nonlocal direct_calls
        direct_calls += 1
        return JsonResponse(
            url="http://prometheus/api/v1/query",
            status_code=200,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr(prometheus, "mcp_call", broken_mcp_call)
    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    result = await prometheus.PrometheusCollector(
        replace(
            make_settings(),
            prometheus_url="http://prometheus",
            prometheus_mcp_url="http://grafana-mcp/mcp",
        )
    ).collect(make_target())

    assert result.details["used_mcp"] is False
    assert direct_calls > 0
    assert any("MCP unavailable; used direct API fallback" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_loki_collector_uses_only_loki_mcp_tools(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_mcp_call(url, tool, arguments):
        calls.append(tool)
        if tool == "list_datasources":
            return _McpResult([{"type": "loki", "uid": "loki"}])
        return _McpResult(
            {
                "status": "success",
                "data": {"result": [{"values": [["1", "failed scheduling trainer"]]}]},
            }
        )

    async def direct_should_not_run(**kwargs):
        raise AssertionError("direct Loki HTTP fallback should not run")

    monkeypatch.setattr(loki, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(loki, "get_json", direct_should_not_run)
    result = await loki.LokiCollector(
        replace(
            make_settings(),
            loki_url="http://loki",
            loki_mcp_url="http://grafana-mcp/mcp",
        )
    ).collect(make_target())

    assert result.details["used_mcp"] is True
    assert "query_loki_logs" in calls
    assert "query_prometheus" not in calls


@pytest.mark.asyncio
async def test_loki_mcp_parses_grafana_log_entries(monkeypatch) -> None:
    async def fake_mcp_call(url, tool, arguments):
        return _McpResult(
            {
                "data": [
                    {
                        "timestamp": '"1783644593824076217"',
                        "line": "scheduler reconciled workload",
                        "labels": {"namespace": "runai"},
                    }
                ],
                "metadata": {"linesReturned": 20},
            }
        )

    monkeypatch.setattr(loki, "mcp_call", fake_mcp_call)
    result = await loki._mcp_query_loki(
        "http://grafana-mcp/mcp", "smoke", '{namespace="runai"}', 20, "loki"
    )

    assert result["status"] == "success"
    assert result["line_count"] == 20
    assert result["sample_lines"] == ["scheduler reconciled workload"]


@pytest.mark.asyncio
async def test_loki_mcp_queries_the_alert_time_window(monkeypatch) -> None:
    query_args: list[dict] = []

    async def fake_mcp_call(url, tool, arguments):
        if tool == "list_datasources":
            return _McpResult([{"type": "loki", "uid": "loki"}])
        query_args.append(arguments)
        return _McpResult({"status": "success", "data": {"result": []}})

    monkeypatch.setattr(loki, "mcp_call", fake_mcp_call)
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    await loki.LokiCollector(
        replace(make_settings(), loki_mcp_url="http://grafana-mcp/mcp")
    ).collect(target)

    assert query_args
    assert all(args["datasourceUid"] == "loki" for args in query_args)
    assert all(args["direction"] == "backward" for args in query_args)
    assert all(args["queryType"] == "range" for args in query_args)
    assert all(args["startRfc3339"] == "2026-07-10T00:55:00Z" for args in query_args)
    assert all(args["endRfc3339"] == "2026-07-10T01:15:00Z" for args in query_args)
    assert all("logql" in args for args in query_args)
    assert all("query" not in args and "datasource_uid" not in args for args in query_args)
    assert all("startTime" not in args and "endTime" not in args for args in query_args)


@pytest.mark.asyncio
async def test_loki_direct_queries_the_alert_time_window(monkeypatch) -> None:
    direct_args: list[dict] = []

    async def fake_get_json(**kwargs):
        direct_args.append(kwargs["params"])
        return JsonResponse(
            url="http://loki/loki/api/v1/query_range", status_code=200,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr(loki, "get_json", fake_get_json)
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    await loki.LokiCollector(replace(make_settings(), loki_url="http://loki")).collect(target)

    assert direct_args
    assert all(args["start"] == "2026-07-10T00:55:00Z" for args in direct_args)
    assert all(args["end"] == "2026-07-10T01:20:00Z" for args in direct_args)


@pytest.mark.asyncio
async def test_postgres_collector_uses_mcp_before_asyncpg(monkeypatch) -> None:
    async def fake_mcp_call(url, tool, arguments):
        sql = arguments["sql"].lower()
        if "count(*)" in sql:
            return _McpResult([{"active_connections": 1}])
        if "pg_extension" in sql:
            return _McpResult([{"exists": True}])
        if "unnest" in sql:
            return _McpResult(
                [
                    {"table_name": "incidents", "exists": True},
                    {"table_name": "alerts", "exists": True},
                    {"table_name": "incident_embeddings", "exists": True},
                    {"table_name": "rca_feedback", "exists": True},
                    {"table_name": "analysis_runs", "exists": True},
                ]
            )
        if "pg_stat_activity" in sql:
            return _McpResult([])
        return _McpResult([{"ok": 1}])

    monkeypatch.setattr(postgres, "mcp_call", fake_mcp_call)
    result = await postgres.PostgresCollector(
        replace(
            make_settings(),
            postgres_dsn="postgres://direct",
            postgres_mcp_url="http://postgres-mcp/mcp",
        )
    ).collect(make_target())

    assert result.details["connected"] is True
    assert result.artifacts[0].result["used_mcp"] is True


@pytest.mark.asyncio
async def test_kubernetes_collector_uses_mcp_before_service_account_token(
    monkeypatch,
) -> None:
    calls: list[str] = []

    async def fake_mcp_call(url, tool, arguments):
        calls.append(tool)
        if tool == "pods_get":
            return _McpResult(
                {
                    "metadata": {"name": "trainer-0", "namespace": "runai-vision"},
                    "spec": {"containers": [{"name": "main", "resources": {}}]},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{"name": "main", "ready": True}],
                    },
                }
            )
        if tool == "pods_log":
            return _McpResult(
                text=(
                    "2026-07-07T00:00:00Z training started\n"
                    "2026-07-07T00:00:01Z error password=k8s-mcp-log-secret-12345"
                )
            )
        return _McpResult({"items": []})

    def token_should_not_be_read(path: str) -> str:
        raise AssertionError("direct Kubernetes service-account token should not be read")

    monkeypatch.setattr(kubernetes, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(kubernetes, "_read_file", token_should_not_be_read)
    result = await kubernetes.KubernetesCollector(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp")
    ).collect(make_target())

    assert result.details["used_mcp"] is True
    assert "pods_get" in calls
    assert "pods_log" in calls
    rendered = str(result.details["pod_logs"])
    assert "k8s-mcp-log-secret-12345" not in rendered
    assert "[MASKED]" in rendered
