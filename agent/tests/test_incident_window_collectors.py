from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import kubernetes, loki, prometheus, runai
from app.collectors.http_json import JsonResponse
from app.collectors.kubernetes import (
    _collect_pod_logs,
    _event_matches_target,
    _filter_kubernetes_data,
    _pod_log_observation,
    _warning_event_observation,
    _warning_event_queries_complete,
)
from app.collectors.postgres import _collect_postgres_checks, _postgres_result
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
async def test_loki_emits_a_scoped_artifact_for_each_incident_query(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://loki/loki/api/v1/query_range",
            status_code=200,
            data={
                "status": "success",
                "data": {"result": [{"values": [["1", "failed scheduling trainer"]]}]},
            },
        )

    monkeypatch.setattr(loki, "get_json", fake_get_json)
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    result = await loki.LokiCollector(
        replace(make_settings(), loki_url="http://loki")
    ).collect(target)

    signals = [artifact for artifact in result.artifacts if artifact.type == "logql_signal"]
    assert signals
    assert all(artifact.result["observation"]["polarity"] == "present" for artifact in signals)
    assert all(
        artifact.result["observation"]["observation_window"]
        == {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
        for artifact in signals
    )


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

    restarts = next(
        item for item in result.details["queries"] if item["name"] == "container_restarts"
    )
    summary = restarts["value_summary"]
    assert summary["min"] == 0.0
    assert summary["max"] == 2.5
    assert summary["all_zero"] is False
    assert summary["zero_sample_count"] == 2
    assert summary["series"][0]["last"] == 0.0
    assert summary["series"][0]["nonzero_sample_count"] == 1


def test_prometheus_query_observation_keeps_zero_as_refuting_evidence() -> None:
    absent = prometheus._prometheus_query_observation(
        {
            "name": "node_memory_pressure",
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 3, "all_zero": True},
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )
    present = prometheus._prometheus_query_observation(
        {
            "name": "node_memory_pressure",
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 3, "all_zero": False},
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert absent["polarity"] == "absent"
    assert absent["coverage"] == "scoped"
    assert present["polarity"] == "present"


def test_prometheus_up_marks_a_mixed_vector_with_any_down_target_present() -> None:
    up_failure = prometheus._prometheus_query_observation(
        {
            "name": "prometheus_up",
            "series_count": 2,
            "value_summary": {
                "numeric_sample_count": 4,
                "zero_sample_count": 1,
                "all_zero": False,
                "min": 0.0,
            },
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )
    healthy = prometheus._prometheus_query_observation(
        {
            "name": "prometheus_up",
            "series_count": 2,
            "value_summary": {
                "numeric_sample_count": 4,
                "zero_sample_count": 0,
                "all_zero": False,
                "min": 1.0,
            },
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert up_failure["polarity"] == "present"
    assert healthy["polarity"] == "absent"


def test_loki_query_observation_only_refutes_with_a_bounded_incident_window() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    absent = loki._loki_query_observation(
        {"name": "error_logs", "line_count": 0, "stream_count": 0}, time_range=time_range
    )
    present = loki._loki_query_observation(
        {"name": "error_logs", "line_count": 2, "stream_count": 1}, time_range=time_range
    )
    live_empty = loki._loki_query_observation(
        {"name": "error_logs", "line_count": 0, "stream_count": 0}, time_range=None
    )

    assert absent["polarity"] == "absent"
    assert absent["coverage"] == "scoped"
    assert present["polarity"] == "present"
    assert live_empty["polarity"] == "unknown"
    assert live_empty["coverage"] == "partial"


def test_runai_query_observation_requires_identity_scoped_coverage() -> None:
    target = make_target()
    present = runai._runai_query_observation(
        {"name": "workloads", "status_code": 200, "data": {"workloads": [{"name": "trainer"}]}},
        target=target,
        used_mcp=True,
    )
    missing = runai._runai_query_observation(
        {"name": "project", "status_code": 404, "error": "HTTP 404", "data": None},
        target=target,
        used_mcp=False,
    )
    broad_nonmatch = runai._runai_query_observation(
        {"name": "projects", "status_code": 200, "data": {"projects": [{"name": "other"}]}},
        target=target,
        used_mcp=True,
    )

    assert (present["polarity"], present["coverage"]) == ("present", "scoped")
    assert (missing["polarity"], missing["coverage"]) == ("absent", "scoped")
    assert (broad_nonmatch["polarity"], broad_nonmatch["coverage"]) == ("unknown", "partial")


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


def test_kubernetes_pod_log_evidence_uses_only_timestamped_incident_lines() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation, entries = _pod_log_observation(
        {
            "container": "main",
            "previous": True,
            "lines": [
                "2026-07-10T00:54:59Z before incident",
                "2026-07-10T01:02:00Z OOMKilled",
                "2026-07-10T01:15:01Z after incident",
            ],
        },
        time_range=time_range,
    )
    unknown, no_entries = _pod_log_observation(
        {"container": "main", "lines": ["untimestamped line"]}, time_range=time_range
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    assert observation["previous"] is True
    assert entries == [{"timestamp": "2026-07-10T01:02:00Z", "line": "OOMKilled"}]
    assert (unknown["polarity"], unknown["coverage"]) == ("unknown", "partial")
    assert no_entries == []


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


def test_namespace_events_require_the_alert_resource_identity() -> None:
    target = replace(
        make_target(), pod="", workload_name="trainer", fired_at="2026-07-10T01:00:00Z"
    )
    matching = {
        "involvedObject": {"kind": "Pod", "name": "trainer-7f8d9"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
        "reason": "FailedScheduling",
    }
    unrelated = {
        "involvedObject": {"kind": "Pod", "name": "other-workload-0"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
        "reason": "FailedScheduling",
    }
    cross_namespace = {
        "metadata": {"namespace": "runai"},
        "involvedObject": {"kind": "Pod", "name": "runai-scheduler-0"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
        "reason": "ReconcileFailed",
        "message": "unable to schedule workload trainer for project vision",
    }
    filtered = _filter_kubernetes_data(
        "namespace_events", {"items": [matching, unrelated]}, target
    )
    control_plane_filtered = _filter_kubernetes_data(
        "runai_control_plane_events:runai", {"items": [cross_namespace, unrelated]}, target
    )

    assert _event_matches_target(matching, target) is True
    assert _event_matches_target(unrelated, target) is False
    assert _event_matches_target(cross_namespace, target) is True
    assert [item["object"] for item in filtered["items"]] == ["trainer-7f8d9"]
    assert [item["object"] for item in control_plane_filtered["items"]] == ["runai-scheduler-0"]


def test_kubernetes_warning_event_observation_is_a_scoped_negative_only_in_window() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}

    absent = _warning_event_observation([], time_range=time_range, status="ok")
    unbounded = _warning_event_observation([], time_range=None, status="ok")

    assert (absent["polarity"], absent["coverage"]) == ("absent", "scoped")
    assert (unbounded["polarity"], unbounded["coverage"]) == ("unknown", "partial")
    unscoped = _warning_event_observation(
        [], time_range=time_range, status="ok", target_scoped=False
    )
    incomplete = _warning_event_observation(
        [], time_range=time_range, status="partial", queries_complete=False
    )
    found_despite_gap = _warning_event_observation(
        [{"reason": "Evicted"}],
        time_range=time_range,
        status="partial",
        queries_complete=False,
    )
    assert (unscoped["polarity"], unscoped["coverage"]) == ("unknown", "partial")
    assert (incomplete["polarity"], incomplete["coverage"]) == ("unknown", "partial")
    assert (found_despite_gap["polarity"], found_despite_gap["coverage"]) == ("present", "scoped")


def test_kubernetes_warning_event_absence_requires_all_event_queries_to_succeed() -> None:
    complete = _warning_event_queries_complete(
        [
            {"name": "pod_events", "error": None},
            {"name": "runai_control_plane_events:runai", "error": None},
        ]
    )
    incomplete = _warning_event_queries_complete(
        [
            {"name": "pod_events", "error": None},
            {"name": "runai_control_plane_events:runai", "error": "HTTP 403"},
        ]
    )

    assert complete is True
    assert incomplete is False


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
                {
                    "table_schema": "audit",
                    "table_name": "workload_history",
                    "column_name": "workload_name",
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
            return [
                {
                    "event_time": "2026-07-10T01:02:00Z",
                    "action": "evicted",
                    "workload_name": "trainer",
                }
            ]
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
            "context_columns": ["action", "workload_name"],
            "matching_rows": 1,
            "first_event_at": "2026-07-10T01:02:00Z",
            "last_event_at": "2026-07-10T01:02:00Z",
            "rows": [
                {
                    "event_time": "2026-07-10T01:02:00Z",
                    "action": "evicted",
                    "workload_name": "trainer",
                }
            ],
            "target_correlation_available": True,
            "target_matching_rows": 1,
            "target_rows": [
                {
                    "event_time": "2026-07-10T01:02:00Z",
                    "action": "evicted",
                    "workload_name": "trainer",
                }
            ],
        }
    ]


@pytest.mark.asyncio
async def test_postgres_history_evidence_requires_target_identity() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    checks = {
        "connected": True,
        "active_connections": 1,
        "long_transactions": [],
        "pgvector_extension": True,
        "rca_tables": {},
        "incident_history": {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "target_correlation_available": True,
                    "target_matching_rows": 0,
                    "target_rows": [],
                },
                {
                    "schema": "audit",
                    "table": "unattributed_history",
                    "target_correlation_available": False,
                    "target_matching_rows": 1,
                    "target_rows": [{"event_time": "2026-07-10T01:02:00Z"}],
                },
            ],
        },
    }
    result = await _postgres_result(
        make_settings(), target, checks=checks, warnings=[], used_mcp=False,
        database_kind="runai_control_plane", check_rca_tables=False,
    )
    observations = {
        artifact.result["observation"]["predicate"]: artifact.result["observation"]
        for artifact in result.artifacts
        if artifact.type == "postgres_incident_history"
    }

    assert observations["postgres_history:audit.workload_history"]["polarity"] == "absent"
    assert observations["postgres_history:audit.unattributed_history"]["polarity"] == "unknown"
