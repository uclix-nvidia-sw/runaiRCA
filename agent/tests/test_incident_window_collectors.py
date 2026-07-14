from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import kubernetes, loki, prometheus, runai
from app.collectors.http_json import JsonResponse
from app.collectors.kubernetes import (
    _collect_pod_logs,
    _event_matches_target,
    _filter_kubernetes_data,
    _kubernetes_list_complete,
    _pod_log_observation,
    _warning_event_observation,
    _warning_event_queries_complete,
)
from app.collectors.postgres import (
    _collect_postgres_checks,
    _history_target_aggregate_query,
    _postgres_result,
)
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
async def test_prometheus_api_error_payload_is_not_treated_as_missing_metrics(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query_range",
            status_code=200,
            data={
                "status": "error",
                "errorType": "bad_data",
                "error": "parse error: unexpected end of input",
            },
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    result = await prometheus.PrometheusCollector(
        replace(make_settings(), prometheus_url="http://prometheus")
    ).collect(target)

    assert result.status == "unavailable"
    assert all(query["error"] for query in result.details["queries"])
    signals = [artifact for artifact in result.artifacts if artifact.type == "promql_signal"]
    assert signals
    assert all(artifact.result["observation"]["polarity"] == "unavailable" for artifact in signals)


@pytest.mark.asyncio
async def test_loki_emits_a_scoped_artifact_for_each_incident_query(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://loki/loki/api/v1/query_range",
            status_code=200,
            data={
                "status": "success",
                "data": {
                    "result": [
                        {"values": [["2026-07-10T01:00:00Z", "failed scheduling trainer"]]}
                    ]
                },
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
    assert summary["any_series_changed_during_window"] is True
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


def test_prometheus_out_of_window_sample_is_not_incident_evidence() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = prometheus._prometheus_query_observation(
        {
            "name": "node_memory_pressure",
            "series_count": 1,
            "value_summary": {
                "numeric_sample_count": 1,
                "all_zero": False,
                "series": [
                    {
                        "first_timestamp": "2026-07-13T09:26:12Z",
                        "last_timestamp": "2026-07-13T09:26:12Z",
                    }
                ],
            },
        },
        time_range=window,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["sample_window_verified"] is False


def test_prometheus_verdict_uses_all_series_not_only_display_samples() -> None:
    summary = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"pod": f"healthy-{index}"},
                "values": [["2026-07-10T01:00:00Z", "1"]],
            }
            for index in range(3)
        ]
        + [
            {
                "metric": {"pod": "scrape-failed"},
                "values": [["2026-07-10T01:00:00Z", "0"]],
            }
        ]
    )
    observation = prometheus._prometheus_query_observation(
        {"name": "prometheus_up", "series_count": 4, "value_summary": summary},
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert len(summary["series"]) == 3
    assert summary["series_count_observed"] == 4
    assert summary["zero_sample_count"] == 1
    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")


def test_prometheus_timestamp_less_historical_sample_is_context_only() -> None:
    summary = prometheus._prometheus_value_summary(
        [{"metric": {"pod": "trainer-0"}, "values": [["", "1"]]}]
    )
    observation = prometheus._prometheus_query_observation(
        {"name": "node_memory_pressure", "series_count": 1, "value_summary": summary},
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["sample_window_verified"] is None


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


def test_restart_counter_requires_change_during_incident_window() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    stale_counter = prometheus._prometheus_query_observation(
        {
            "name": "container_restarts",
            "series_count": 1,
            "value_summary": {
                "numeric_sample_count": 3,
                "all_zero": False,
                "series_with_multiple_samples": 1,
                "any_series_changed_during_window": False,
            },
        },
        time_range=window,
    )
    changed_counter = prometheus._prometheus_query_observation(
        {
            "name": "container_restarts",
            "series_count": 1,
            "value_summary": {
                "numeric_sample_count": 3,
                "all_zero": False,
                "series_with_multiple_samples": 1,
                "any_series_changed_during_window": True,
            },
        },
        time_range=window,
    )
    one_sample = prometheus._prometheus_query_observation(
        {
            "name": "container_restarts",
            "series_count": 1,
            "value_summary": {
                "numeric_sample_count": 1,
                "all_zero": False,
                "series_with_multiple_samples": 0,
            },
        },
        time_range=window,
    )

    assert (stale_counter["polarity"], stale_counter["coverage"]) == ("absent", "scoped")
    assert (changed_counter["polarity"], changed_counter["coverage"]) == ("present", "scoped")
    assert (one_sample["polarity"], one_sample["coverage"]) == ("unknown", "partial")


@pytest.mark.parametrize(
    "name, all_zero",
    [
        ("container_memory", False),
        ("container_cpu", False),
        ("runai_queue_requested_gpus", False),
        ("runai_project_allocated_gpus", True),
    ],
)
def test_thresholdless_usage_metrics_are_context_not_rca_verdicts(
    name: str, all_zero: bool
) -> None:
    observation = prometheus._prometheus_query_observation(
        {
            "name": name,
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 3, "all_zero": all_zero},
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_capacity_gap_absence_requires_both_operands_to_be_observed() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    complete = [
        {
            "name": "runai_queue_requested_gpus",
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 2},
        },
        {
            "name": "runai_queue_allocated_gpus",
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 2},
        },
        {
            "name": "runai_queue_capacity_gap",
            "series_count": 0,
            "value_summary": {"numeric_sample_count": 0},
        },
    ]
    incomplete = [*complete[:1], {**complete[-1]}]

    prometheus._annotate_capacity_gap_coverage(complete)
    prometheus._annotate_capacity_gap_coverage(incomplete)

    no_gap = prometheus._prometheus_query_observation(complete[-1], time_range=window)
    unknown = prometheus._prometheus_query_observation(incomplete[-1], time_range=window)
    positive = prometheus._prometheus_query_observation(
        {
            "name": "runai_queue_capacity_gap",
            "series_count": 1,
            "value_summary": {"numeric_sample_count": 2, "all_zero": False},
        },
        time_range=window,
    )

    assert (no_gap["polarity"], no_gap["coverage"]) == ("absent", "scoped")
    assert (unknown["polarity"], unknown["coverage"]) == ("unknown", "partial")
    assert (positive["polarity"], positive["coverage"]) == ("present", "scoped")


def test_prometheus_unbounded_empty_result_is_not_a_scoped_absence() -> None:
    observation = prometheus._prometheus_query_observation(
        {
            "name": "container_restarts",
            "series_count": 0,
            "value_summary": {"numeric_sample_count": 0},
        },
        time_range=None,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_loki_query_observation_only_refutes_with_a_bounded_incident_window() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    absent = loki._loki_query_observation(
        {"name": "error_logs", "line_count": 0, "stream_count": 0}, time_range=time_range
    )
    present = loki._loki_query_observation(
        {
            "name": "error_logs",
            "line_count": 2,
            "stream_count": 1,
            "sample_entries": [
                {"timestamp": "2026-07-10T01:00:00Z", "line": "incident error"}
            ],
        },
        time_range=time_range,
    )
    timestamp_missing = loki._loki_query_observation(
        {
            "name": "error_logs",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [{"timestamp": "", "line": "unverified error"}],
        },
        time_range=time_range,
    )
    out_of_window = loki._loki_query_observation(
        {
            "name": "error_logs",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {"timestamp": "2026-07-13T09:26:12Z", "line": "current error"}
            ],
        },
        time_range=time_range,
    )
    live_empty = loki._loki_query_observation(
        {"name": "error_logs", "line_count": 0, "stream_count": 0}, time_range=None
    )

    assert absent["polarity"] == "absent"
    assert absent["coverage"] == "scoped"
    assert present["polarity"] == "present"
    assert present["log_window_verified"] is True
    assert (timestamp_missing["polarity"], timestamp_missing["coverage"]) == ("unknown", "partial")
    assert timestamp_missing["log_window_verified"] is None
    assert (out_of_window["polarity"], out_of_window["coverage"]) == ("unknown", "partial")
    assert out_of_window["log_window_verified"] is False
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
    direct_workload_nonmatch = runai._runai_query_observation(
        {"name": "workloads", "status_code": 200, "data": {"workloads": [{"name": "other"}]}},
        target=target,
        used_mcp=False,
    )

    assert (present["polarity"], present["coverage"]) == ("present", "scoped")
    assert (missing["polarity"], missing["coverage"]) == ("absent", "scoped")
    assert (broad_nonmatch["polarity"], broad_nonmatch["coverage"]) == ("unknown", "partial")
    assert (direct_workload_nonmatch["polarity"], direct_workload_nonmatch["coverage"]) == (
        "unknown",
        "partial",
    )


def test_runai_current_resource_state_is_context_for_historical_incident() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
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

    assert (present["polarity"], present["coverage"]) == ("unknown", "partial")
    assert (missing["polarity"], missing["coverage"]) == ("unknown", "partial")
    assert present["observation_window"]["start"] == "2026-07-10T00:55:00Z"


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
            {
                "type": "Warning",
                "reason": "TooEarly",
                "eventTime": "2026-07-10T00:54:59Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {
                "type": "Warning",
                "reason": "Inside",
                "eventTime": "2026-07-10T01:00:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {
                "type": "Warning",
                "reason": "SeriesInside",
                "series": {"lastObservedTime": "2026-07-10T01:14:59Z"},
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {
                "type": "Warning",
                "reason": "TooLate",
                "eventTime": "2026-07-10T01:15:01Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
        ]
    }

    filtered = _filter_kubernetes_data("pod_events", data, target)

    assert [item["reason"] for item in filtered["items"]] == ["Inside", "SeriesInside"]


def test_kubernetes_warning_events_exclude_normal_and_non_pod_targets() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    data = {
        "items": [
            {
                "type": "Normal",
                "reason": "Scheduled",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {
                "type": "Warning",
                "reason": "SameNameJob",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Job", "name": "trainer-0"},
            },
            {
                "type": "Warning",
                "reason": "OOMKilled",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
        ]
    }

    filtered = _filter_kubernetes_data("pod_events", data, target)

    assert [item["reason"] for item in filtered["items"]] == ["OOMKilled"]


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
    paginated = _warning_event_queries_complete(
        [{"name": "pod_events", "error": None, "list_complete": False}]
    )

    assert complete is True
    assert incomplete is False
    assert paginated is False
    assert _kubernetes_list_complete({"items": [], "metadata": {"continue": "next"}}) is False
    assert _kubernetes_list_complete({"items": [], "metadata": {}}) is True


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
            assert args[:2] == ("2026-07-10T00:55:00Z", "2026-07-10T01:15:00Z")
            if "ANY($3::text[])" in query:
                assert args[2:] == (["trainer"],)
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
            "target_first_event_at": "2026-07-10T01:02:00Z",
            "target_last_event_at": "2026-07-10T01:02:00Z",
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
async def test_postgres_history_queries_target_beyond_latest_generic_sample() -> None:
    class TargetOlderThanGenericSample(_HistoryConnection):
        async def fetch(self, query: str, *args):
            if "information_schema.columns" in query:
                return await super().fetch(query, *args)
            if 'FROM "audit"."workload_history"' not in query:
                return await super().fetch(query, *args)
            assert args[:2] == ("2026-07-10T00:55:00Z", "2026-07-10T01:15:00Z")
            targeted = "ANY($3::text[])" in query
            if "count(*) AS matching_rows" in query:
                return [{
                    "matching_rows": 1 if targeted else 11,
                    "first_event_at": "2026-07-10T01:01:00Z",
                    "last_event_at": "2026-07-10T01:14:00Z",
                }]
            return [
                {
                    "event_time": "2026-07-10T01:01:00Z" if targeted else "2026-07-10T01:14:00Z",
                    "action": "targeted" if targeted else "unrelated",
                    "workload_name": "trainer" if targeted else "other-workload",
                }
            ]

    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    checks = await _collect_postgres_checks(
        TargetOlderThanGenericSample(), target, check_rca_tables=False
    )
    table = checks["incident_history"]["tables"][0]

    assert table["matching_rows"] == 11
    assert table["target_matching_rows"] == 1
    assert table["target_rows"] == [{
        "event_time": "2026-07-10T01:01:00Z",
        "action": "targeted",
        "workload_name": "trainer",
    }]


def test_postgres_target_history_query_binds_identity_or_encodes_mcp_value() -> None:
    target = replace(make_target(), workload_name="trainer' OR true --")
    table = {
        "schema": "audit",
        "table": "workload_history",
        "timestamp_column": "created_at",
        "context_columns": ["workload_name"],
    }
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}

    direct = _history_target_aggregate_query(table, target, mcp=False, time_range=time_range)
    mcp = _history_target_aggregate_query(table, target, mcp=True, time_range=time_range)

    assert direct is not None and mcp is not None
    assert "ANY($3::text[])" in direct[0]
    assert direct[1] == [["trainer' or true --"]]
    encoded = "trainer' or true --".encode("utf-8").hex()
    assert f"IN (convert_from(decode('{encoded}', 'hex'), 'UTF8'))" in mcp[0]
    assert mcp[1] == []

    pod_only = _history_target_aggregate_query(
        {**table, "context_columns": ["pod_name"]},
        make_target(),
        mcp=False,
        time_range=time_range,
    )
    assert pod_only is not None
    assert '"pod_name"' in pod_only[0]
    assert pod_only[1] == [["trainer-0"]]

    namespace_only = _history_target_aggregate_query(
        {**table, "context_columns": ["namespace"]},
        make_target(),
        mcp=False,
        time_range=time_range,
    )
    assert namespace_only is None


def test_postgres_workload_history_does_not_fall_back_to_project_or_generic_id() -> None:
    target = make_target()
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    base = {
        "schema": "audit",
        "table": "history",
        "timestamp_column": "created_at",
    }

    project_only = _history_target_aggregate_query(
        {**base, "context_columns": ["project"]}, target, mcp=False, time_range=time_range
    )
    generic_id_only = _history_target_aggregate_query(
        {**base, "context_columns": ["id"]}, target, mcp=False, time_range=time_range
    )
    strong_and_project = _history_target_aggregate_query(
        {**base, "context_columns": ["workload_name", "project"]},
        target,
        mcp=False,
        time_range=time_range,
    )
    project_scoped_target = replace(target, workload_name="", pod="", runai_workload_id="")
    project_scoped = _history_target_aggregate_query(
        {**base, "context_columns": ["project"]},
        project_scoped_target,
        mcp=False,
        time_range=time_range,
    )

    assert project_only is None
    assert generic_id_only is None
    assert strong_and_project is not None
    assert '"workload_name"' in strong_and_project[0]
    assert '"project"' not in strong_and_project[0]
    assert project_scoped is not None
    assert project_scoped[1] == [["vision"]]


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
