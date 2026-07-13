from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import kubernetes, prometheus
from app.collectors.http_json import JsonResponse
from app.collectors.kubernetes import _collect_pod_logs, _filter_kubernetes_data
from app.collectors.postgres import _collect_postgres_checks
from tests.test_orchestrator import make_settings, make_target


@pytest.mark.asyncio
async def test_prometheus_direct_uses_incident_query_range(monkeypatch) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(
            url="http://prometheus/api/v1/query_range",
            status_code=200,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    await prometheus.PrometheusCollector(
        replace(make_settings(), prometheus_url="http://prometheus")
    ).collect(target)

    assert calls
    assert all(call["path"] == "/api/v1/query_range" for call in calls)
    assert all(call["params"]["start"] == "2026-07-10T00:55:00Z" for call in calls)
    assert all(call["params"]["end"] == "2026-07-10T01:15:00Z" for call in calls)
    assert all(call["params"]["step"] == "60" for call in calls)


@pytest.mark.asyncio
async def test_prometheus_records_zero_and_peak_values_for_evidence(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query_range",
            status_code=200,
            data={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"namespace": "runai-vision", "pod": "trainer-0"},
                            "values": [["100", "0"], ["160", "2.5"], ["220", "0"]],
                        }
                    ]
                },
            },
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    result = await prometheus.PrometheusCollector(
        replace(make_settings(), prometheus_url="http://prometheus")
    ).collect(make_target())

    restarts = next(item for item in result.details["queries"] if item["name"] == "container_restarts")
    summary = restarts["value_summary"]
    assert summary["min"] == 0.0
    assert summary["max"] == 2.5
    assert summary["all_zero"] is False
    assert summary["series"][0]["last"] == 0.0
    assert summary["series"][0]["nonzero_sample_count"] == 1


@pytest.mark.asyncio
async def test_kubernetes_logs_use_incident_since_time_and_previous_restart_log(
    monkeypatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(url="http://kubernetes/log", status_code=200, data={"body": "ok"})

    monkeypatch.setattr(kubernetes, "get_json", fake_get_json)
    logs = await _collect_pod_logs(
        settings=make_settings(),
        target=make_target(),
        containers=["main"],
        headers={"Authorization": "Bearer test"},
        verify=True,
        previous_containers=["main"],
        since_time="2026-07-10T00:55:00Z",
    )

    assert len(logs) == 2
    assert all(call["params"]["sinceTime"] == "2026-07-10T00:55:00Z" for call in calls)
    assert [call["params"].get("previous") for call in calls] == [None, "true"]


def test_kubernetes_events_are_filtered_to_the_incident_window() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    data = {
        "items": [
            {"type": "Warning", "reason": "TooEarly", "eventTime": "2026-07-10T00:54:59Z"},
            {"type": "Warning", "reason": "Inside", "eventTime": "2026-07-10T01:00:00Z"},
            {
                "type": "Warning",
                "reason": "SeriesInside",
                "series": {"lastObservedTime": "2026-07-10T01:14:59Z"},
            },
            {"type": "Warning", "reason": "TooLate", "eventTime": "2026-07-10T01:15:01Z"},
        ]
    }

    filtered = _filter_kubernetes_data("pod_events", data, target)

    assert [item["reason"] for item in filtered["items"]] == ["Inside", "SeriesInside"]


class _HistoryConnection:
    async def fetchval(self, query: str):
        if "pg_extension" in query:
            return True
        if "pg_stat_activity" in query:
            return 1
        return 1

    async def fetch(self, query: str, *args):
        if "information_schema.columns" in query:
            return [
                {
                    "table_schema": "audit",
                    "table_name": "workload_history",
                    "column_name": "created_at",
                    "data_type": "timestamp with time zone",
                },
                {
                    "table_schema": "audit",
                    "table_name": "workload_history",
                    "column_name": "action",
                    "data_type": "text",
                },
            ]
        if 'FROM "audit"."workload_history"' in query:
            assert args == ("2026-07-10T00:55:00Z", "2026-07-10T01:15:00Z")
            if "count(*) AS matching_rows" in query:
                return [
                    {
                        "matching_rows": 1,
                        "first_event_at": "2026-07-10T01:02:00Z",
                        "last_event_at": "2026-07-10T01:02:00Z",
                    }
                ]
            return [{"event_time": "2026-07-10T01:02:00Z", "action": "evicted"}]
        if "information_schema.tables" in query:
            return [{"table_schema": "audit", "table_name": "workload_history"}]
        return []


@pytest.mark.asyncio
async def test_postgres_reads_only_timestamped_audit_history_in_incident_window() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    checks = await _collect_postgres_checks(
        _HistoryConnection(), target, check_rca_tables=False
    )

    history = checks["incident_history"]
    assert history["time_range"] == {
        "start": "2026-07-10T00:55:00Z",
        "end": "2026-07-10T01:15:00Z",
    }
    assert history["tables"] == [
        {
            "schema": "audit",
            "table": "workload_history",
            "timestamp_column": "created_at",
            "context_columns": ["action"],
            "matching_rows": 1,
            "first_event_at": "2026-07-10T01:02:00Z",
            "last_event_at": "2026-07-10T01:02:00Z",
            "rows": [{"event_time": "2026-07-10T01:02:00Z", "action": "evicted"}],
        }
    ]
