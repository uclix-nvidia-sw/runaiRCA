from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import kubernetes, loki, prometheus, runai
from app.collectors.base import CollectorResult, causal_evidence_time_range
from app.collectors.http_json import JsonResponse
from app.collectors.kubernetes import (
    _collect_pod_logs,
    _event_matches_target,
    _event_time_range_complete,
    _filter_kubernetes_data,
    _kubernetes_list_complete,
    _mcp_k8s_response,
    _node_condition_artifacts,
    _pod_log_observation,
    _warning_event_observation,
    _warning_event_queries_complete,
    _warning_events_in_time_range,
    k8s_logs,
)
from app.collectors.postgres import (
    _collect_postgres_checks,
    _history_target_aggregate_query,
    _postgres_history_artifacts,
    _postgres_result,
    _verified_target_aggregate,
)
from app.services import pipeline
from app.services.evidence_blackboard import Blackboard, EvidenceEligibility
from app.services.root_cause_ranking import rank_root_cause_candidates
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


def test_prometheus_range_step_bounds_long_incident_queries() -> None:
    assert prometheus._prometheus_range_step(
        {"start": "2026-01-01T00:00:00Z", "end": "2026-01-11T00:00:00Z"}
    ) == 864


def test_kubernetes_pod_list_prioritizes_failures_and_preserves_omission_count() -> None:
    target = replace(make_target(), workload_name="")
    pods = [
        {
            "metadata": {"name": f"healthy-{index}"},
            "status": {"phase": "Running", "containerStatuses": []},
        }
        for index in range(6)
    ]
    pods.append(
        {
            "metadata": {"name": "runai-scheduler-default-z"},
            "status": {
                "phase": "Failed",
                "reason": "Evicted",
                "conditions": [
                    {"type": "Ready", "status": "True"},
                    {"type": "DisruptionTarget", "status": "True", "reason": "Preemption"},
                ],
                "containerStatuses": [],
            },
        }
    )

    filtered = _filter_kubernetes_data("namespace_pods", {"items": pods}, target)

    assert filtered["items"][0]["name"] == "runai-scheduler-default-z"
    assert filtered["items"][0]["reason"] == "Evicted"
    assert filtered["items"][0]["conditions"][0]["type"] == "DisruptionTarget"
    assert filtered["omitted_pods"] == 2


def test_loki_sample_entries_round_robin_streams() -> None:
    entries = loki._sample_entries(
        [
            {"stream": {"container": "first"}, "values": [["2", "first-2"], ["3", "first-3"]]},
            {"stream": {"container": "second"}, "values": [["1", "second-1"]]},
        ]
    )

    assert [entry["line"] for entry in entries] == ["second-1", "first-2", "first-3"]


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
async def test_prometheus_malformed_success_payload_is_not_a_scoped_absence(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query_range",
            status_code=200,
            data={"status": "success", "data": {}},
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
    assert all(query["error"] == "Prometheus response missing data.result" for query in result.details["queries"])
    signals = [artifact for artifact in result.artifacts if artifact.type == "promql_signal"]
    assert all(artifact.result["observation"]["polarity"] == "unavailable" for artifact in signals)


@pytest.mark.asyncio
async def test_loki_emits_target_evidence_only_for_verified_native_stream_labels(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://loki/loki/api/v1/query_range",
            status_code=200,
            data={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {"namespace": "runai-vision", "pod": "trainer-0"},
                            "values": [["2026-07-10T01:00:00Z", "failed scheduling trainer"]],
                        }
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
    observations = {
        artifact.result["observation"]["predicate"]: artifact.result["observation"] for artifact in signals
    }
    assert (observations["log:error_logs"]["polarity"], observations["log:error_logs"]["coverage"]) == (
        "present",
        "scoped",
    )
    assert observations["log:error_logs"]["target_scope_verified"] is True
    assert observations["log:error_logs"]["observed_entity"] == {
        "kind": "pod",
        "name": "trainer-0",
    }
    assert all(
        (observations[predicate]["polarity"], observations[predicate]["coverage"])
        == ("unknown", "partial")
        for predicate in (
            "log:recent_logs",
            "log:workload_history_logs",
            "log:runai_control_plane_errors",
            "log:runai_control_plane_for_workload",
        )
    )
    assert all(
        artifact.result["observation"]["observation_window"]
        == {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
        for artifact in signals
    )


def test_loki_accepts_exact_flat_mcp_entry_labels_but_rejects_mismatch() -> None:
    target = make_target()
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    base = {
        "name": "error_logs",
        "line_count": 1,
        "stream_count": 1,
        "sample_entries": [
            {"timestamp": "2026-07-10T01:00:00Z", "line": "failed scheduling"}
        ],
    }
    mismatched = loki._loki_query_observation(
        {
            **base,
            "stream_labels": [{"namespace": "other", "pod": "other-pod"}],
            "stream_labels_complete": True,
        },
        target=target,
        time_range=window,
    )
    exact_flat_mcp = loki._loki_query_observation(
        {
            **base,
            # Grafana's flat shape lacks a complete stream list. The exact
            # labels on every positive entry are still direct provenance for
            # those returned observations.
            "stream_labels": [],
            "stream_labels_complete": False,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": "failed scheduling",
                    "labels": {"namespace": "runai-vision", "pod": "trainer-0"},
                }
            ],
        },
        target=target,
        time_range=window,
    )

    assert (mismatched["polarity"], mismatched["coverage"]) == ("unknown", "partial")
    assert mismatched["target_scope_verified"] is False
    assert "observed_entity" not in mismatched
    assert (exact_flat_mcp["polarity"], exact_flat_mcp["coverage"]) == (
        "present",
        "scoped",
    )
    assert exact_flat_mcp["target_scope_verified"] is True
    assert exact_flat_mcp["observed_entity"] == {"kind": "pod", "name": "trainer-0"}


def test_loki_flat_mcp_positive_entries_fail_closed_if_one_lacks_exact_labels() -> None:
    target = make_target()
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = loki._loki_query_observation(
        {
            "name": "error_logs",
            "line_count": 2,
            "stream_count": 0,
            "stream_labels": [],
            "stream_labels_complete": False,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": "error: Traceback (most recent call last)",
                    "labels": {"namespace": "runai-vision", "pod": "trainer-0"},
                },
                {
                    "timestamp": "2026-07-10T01:00:01Z",
                    "line": "failed while starting container",
                    "labels": {"namespace": "runai-vision", "pod": "other-pod"},
                },
            ],
        },
        target=target,
        time_range=window,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["target_scope_verified"] is False


def test_loki_empty_range_requires_verified_log_coverage_for_scoped_absence() -> None:
    target = make_target()
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    query = '{namespace="runai-vision",pod="trainer-0"} |~ "(?i)error"'
    direct = loki._loki_query_observation(
        {
            "name": "error_logs",
            "query": query,
            "transport": "direct",
            "native_response_complete": True,
            "time_range": window,
            "line_count": 0,
            "stream_count": 0,
            "stream_labels": [],
            "stream_labels_complete": True,
            "sample_entries": [],
        },
        target=target,
        time_range=window,
    )
    covered_direct = loki._loki_query_observation(
        {
            "name": "error_logs",
            "query": query,
            "transport": "direct",
            "native_response_complete": True,
            "target_log_coverage_verified": True,
            "time_range": window,
            "line_count": 0,
            "stream_count": 0,
            "stream_labels": [],
            "stream_labels_complete": True,
            "sample_entries": [],
        },
        target=target,
        time_range=window,
    )
    proxied = loki._loki_query_observation(
        {
            "name": "error_logs",
            "query": query,
            "transport": "mcp",
            "time_range": window,
            "line_count": 0,
            "stream_count": 0,
            "stream_labels": [],
            "stream_labels_complete": False,
            "sample_entries": [],
        },
        target=target,
        time_range=window,
    )

    assert (direct["polarity"], direct["coverage"]) == ("unknown", "partial")
    assert direct["target_scope_verified"] is False
    assert (covered_direct["polarity"], covered_direct["coverage"]) == (
        "absent",
        "scoped",
    )
    assert covered_direct["target_scope_verified"] is True
    assert covered_direct["observed_entity"] == {
        "kind": "pod",
        "name": "trainer-0",
    }
    assert (proxied["polarity"], proxied["coverage"]) == ("unknown", "partial")
    assert proxied["target_scope_verified"] is False


def test_loki_recent_target_stream_verifies_empty_error_query_coverage() -> None:
    target = make_target()
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    results = [
        {
            "name": "error_logs",
            "query": '{namespace="runai-vision",pod="trainer-0"} |~ "error"',
            "transport": "direct",
            "native_response_complete": True,
            "time_range": window,
            "line_count": 0,
            "sample_entries": [],
            "stream_labels": [],
            "stream_labels_complete": True,
            "error": None,
        },
        {
            "name": "recent_logs",
            "query": '{namespace="runai-vision",pod="trainer-0"}',
            "transport": "direct",
            "native_response_complete": True,
            "time_range": window,
            "line_count": 1,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": "application started",
                }
            ],
            "stream_labels": [
                {"namespace": "runai-vision", "pod": "trainer-0"}
            ],
            "stream_labels_complete": True,
            "error": None,
        },
    ]

    loki._annotate_loki_target_log_coverage(
        results,
        target=target,
        plan=None,
        time_range=window,
    )
    observation = loki._loki_query_observation(
        results[0], target=target, time_range=window
    )

    assert results[0]["target_log_coverage_verified"] is True
    assert (observation["polarity"], observation["coverage"]) == (
        "absent",
        "scoped",
    )


def test_historical_flat_loki_evidence_survives_blackboard_and_ranking() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    query_window = {
        "start": "2026-07-10T00:55:00Z",
        "end": "2026-07-10T01:15:00Z",
    }
    item = {
        "name": "error_logs",
        "query": '{namespace="runai-vision",pod="trainer-0"} |~ "(?i)error"',
        "line_count": 1,
        "stream_count": 0,
        "stream_labels": [],
        "stream_labels_complete": False,
        "sample_entries": [
            {
                "timestamp": "2026-07-10T01:02:00Z",
                "line": "error: Traceback (most recent call last)",
                "labels": {"namespace": "runai-vision", "pod": "trainer-0"},
            }
        ],
    }
    evidence = loki._loki_query_artifact(
        "loki",
        item,
        target=target,
        plan=None,
        time_range=query_window,
    )
    evidence.evidence_id = "E01"
    result = CollectorResult(
        agent="loki",
        status="ok",
        summary="Loki returned a target-scoped historical failure line.",
        artifacts=[evidence],
    )

    board = Blackboard(run_id="INC-historical-loki")
    board.seed_results(
        [result],
        entity="pod:trainer-0",
        timestamp=target.fired_at,
        observed_window_start="2026-07-10T00:55:00Z",
        observed_window_end="2026-07-10T01:10:00Z",
    )
    fact = board.facts()[0]
    eligibility = EvidenceEligibility.from_fact(
        fact,
        context={
            "run_id": "INC-historical-loki",
            "window_start": "2026-07-10T00:55:00Z",
            "window_end": "2026-07-10T01:10:00Z",
            "entities": ("pod:trainer-0", "namespace:runai-vision"),
        },
    )

    assert eligibility.support is True
    ranked = rank_root_cause_candidates(
        target,
        [result],
        eligible_evidence_ids={"E01"},
    )
    assert ranked[0].family == "workload_runtime_error"


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


@pytest.mark.asyncio
async def test_prometheus_rejects_mismatched_series_labels_as_target_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy's broad vector must not inherit the alert Pod's identity."""

    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query_range",
            status_code=200,
            data={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"namespace": "another-ns", "pod": "another-pod"},
                            "values": [
                                ["2026-07-10T01:02:00Z", "1"],
                                ["2026-07-10T01:03:00Z", "2"],
                            ],
                        }
                    ]
                },
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

    restarts = next(
        artifact
        for artifact in result.artifacts
        if artifact.result.get("observation", {}).get("predicate") == "metric:container_restarts"
    )
    observation = restarts.result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["target_scope_verified"] is False
    assert "observed_entity" not in observation


def test_prometheus_declares_verified_pod_provenance_for_matching_series() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    summary = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"namespace": "runai-vision", "pod": "trainer-0"},
                "values": [
                    ["2026-07-10T01:02:00Z", "1"],
                    ["2026-07-10T01:03:00Z", "2"],
                ],
            }
        ]
    )

    observation = prometheus._prometheus_query_observation(
        {"name": "container_restarts", "series_count": 1, "value_summary": summary},
        target=make_target(),
        time_range=window,
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    assert observation["target_scope_verified"] is True
    assert observation["observed_entity"] == {"kind": "pod", "name": "trainer-0"}


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


def test_prometheus_mixed_window_samples_are_not_incident_evidence() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = prometheus._prometheus_query_observation(
        {
            "name": "node_memory_pressure",
            "series_count": 1,
            "value_summary": {
                "numeric_sample_count": 2,
                "all_zero": False,
                "sample_timestamp_verification_required": True,
                "sample_windows": [
                    {
                        "first_timestamp": "2026-07-10T01:00:00Z",
                        "last_timestamp": "2026-07-13T09:26:12Z",
                    }
                ],
            },
        },
        time_range=window,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["sample_window_verified"] is False


def test_prometheus_unsorted_interior_out_of_window_sample_is_not_evidence() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    summary = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"pod": "trainer-0"},
                "values": [
                    ["2026-07-10T01:00:00Z", "1"],
                    ["2026-07-13T09:26:12Z", "1"],
                    ["2026-07-10T01:01:00Z", "1"],
                ],
            }
        ]
    )
    observation = prometheus._prometheus_query_observation(
        {"name": "node_memory_pressure", "series_count": 1, "value_summary": summary},
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
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


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


def test_global_prometheus_up_stays_telemetry_context_not_target_rca_evidence() -> None:
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

    assert (up_failure["polarity"], up_failure["coverage"]) == ("unknown", "partial")
    assert (healthy["polarity"], healthy["coverage"]) == ("unknown", "partial")


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
            "value_summary": {"numeric_sample_count": 2, "all_zero": False, "min": 4.0},
        },
        time_range=window,
    )

    assert (no_gap["polarity"], no_gap["coverage"]) == ("absent", "scoped")
    assert (unknown["polarity"], unknown["coverage"]) == ("unknown", "partial")
    assert (positive["polarity"], positive["coverage"]) == ("present", "scoped")


def test_prometheus_fixed_templates_require_true_values_and_fixed_labels() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    target = make_target()

    wrong_phase = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"namespace": "runai-vision", "phase": "Running"},
                "values": [["2026-07-10T01:02:00Z", "1"]],
            }
        ]
    )
    non_boolean_pending = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"namespace": "runai-vision", "phase": "Pending"},
                "values": [["2026-07-10T01:02:00Z", "0.5"]],
            }
        ]
    )
    false_gap = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"queue": "gpu-a"},
                "values": [["2026-07-10T01:02:00Z", "0"]],
            }
        ]
    )

    wrong_phase_observation = prometheus._prometheus_query_observation(
        {"name": "namespace_pending_pods", "series_count": 1, "value_summary": wrong_phase},
        target=target,
        time_range=window,
    )
    non_boolean_observation = prometheus._prometheus_query_observation(
        {
            "name": "namespace_pending_pods",
            "series_count": 1,
            "value_summary": non_boolean_pending,
        },
        target=target,
        time_range=window,
    )
    false_gap_observation = prometheus._prometheus_query_observation(
        {"name": "runai_queue_capacity_gap", "series_count": 1, "value_summary": false_gap},
        target=target,
        time_range=window,
    )

    for observation in (
        wrong_phase_observation,
        non_boolean_observation,
        false_gap_observation,
    ):
        assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_capacity_gap_absence_requires_target_scoped_operand_samples() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    wrong_queue_summary = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"queue": "other-queue"},
                "values": [["2026-07-10T01:02:00Z", "4"]],
            }
        ]
    )
    query_results = [
        {
            "name": "runai_queue_requested_gpus",
            "series_count": 1,
            "value_summary": wrong_queue_summary,
        },
        {
            "name": "runai_queue_allocated_gpus",
            "series_count": 1,
            "value_summary": wrong_queue_summary,
        },
        {
            "name": "runai_queue_capacity_gap",
            "series_count": 0,
            "value_summary": {"numeric_sample_count": 0},
        },
    ]

    prometheus._annotate_capacity_gap_coverage(
        query_results, target=make_target(), time_range=window
    )
    observation = prometheus._prometheus_query_observation(
        query_results[-1], target=make_target(), time_range=window
    )

    assert query_results[-1]["capacity_sources_available"] is False
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


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


def test_prometheus_empty_vector_requires_direct_native_transport() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    base = {"name": "container_restarts", "series_count": 0, "value_summary": {}}
    mcp = prometheus._prometheus_query_observation(
        {**base, "transport": "mcp"}, target=make_target(), time_range=window
    )
    direct = prometheus._prometheus_query_observation(
        {**base, "transport": "direct"}, target=make_target(), time_range=window
    )

    assert (mcp["polarity"], mcp["coverage"]) == ("unknown", "partial")
    assert (direct["polarity"], direct["coverage"]) == ("absent", "scoped")


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
    assert present["evidence_window"] == {
        "start": "2026-07-10T01:00:00Z",
        "end": "2026-07-10T01:00:00Z",
    }
    assert (timestamp_missing["polarity"], timestamp_missing["coverage"]) == ("unknown", "partial")
    assert timestamp_missing["log_window_verified"] is None
    assert (out_of_window["polarity"], out_of_window["coverage"]) == ("unknown", "partial")
    assert out_of_window["log_window_verified"] is False
    assert live_empty["polarity"] == "unknown"
    assert live_empty["coverage"] == "partial"


def test_loki_negative_normal_and_recovery_lines_are_not_causal_support() -> None:
    target = make_target()
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    base = {
        "name": "error_logs",
        "line_count": 1,
        "stream_count": 1,
        "stream_labels": [{"namespace": "runai-vision", "pod": "trainer-0"}],
        "stream_labels_complete": True,
    }
    negative_lines = (
        "no OOMKilled was observed; pod is healthy",
        "container crash recovered after retry",
        "OOMKilled=false; workload normal",
    )
    observations = [
        loki._loki_query_observation(
            {
                **base,
                "sample_entries": [
                    {"timestamp": "2026-07-10T01:02:00Z", "line": line}
                ],
            },
            target=target,
            time_range=window,
        )
        for line in negative_lines
    ]
    affirmative = loki._loki_query_observation(
        {
            **base,
            "sample_entries": [
                {"timestamp": "2026-07-10T01:02:00Z", "line": "OOMKilled exit code 137"}
            ],
        },
        target=target,
        time_range=window,
    )
    recent = loki._loki_query_observation(
        {
            **base,
            "name": "recent_logs",
            "sample_entries": [
                {"timestamp": "2026-07-10T01:02:00Z", "line": "normal startup completed"}
            ],
        },
        target=target,
        time_range=window,
    )

    for observation in observations:
        assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
        assert observation["affirmative_line_count"] == 0
    assert (affirmative["polarity"], affirmative["coverage"]) == ("present", "scoped")
    assert affirmative["affirmative_line_count"] == 1
    assert affirmative["observed_entity"] == {"kind": "pod", "name": "trainer-0"}
    assert (recent["polarity"], recent["coverage"]) == ("unknown", "partial")


def test_prometheus_positive_observation_exposes_actual_sample_window() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    summary = prometheus._prometheus_value_summary(
        [
            {
                "metric": {"pod": "trainer-0"},
                "values": [
                    ["2026-07-10T01:11:00Z", "1"],
                    ["2026-07-10T01:12:00Z", "1"],
                ],
            }
        ]
    )

    observation = prometheus._prometheus_query_observation(
        {"name": "node_memory_pressure", "series_count": 1, "value_summary": summary},
        time_range=time_range,
    )

    assert observation["evidence_window"] == {
        "start": "2026-07-10T01:11:00Z",
        "end": "2026-07-10T01:12:00Z",
    }


def test_generic_control_plane_loki_errors_are_context_not_target_support() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    generic = loki._loki_query_observation(
        {
            "name": "runai_control_plane_errors",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {"timestamp": "2026-07-10T01:00:00Z", "line": "scheduler reconcile failed"}
            ],
        },
        time_range=time_range,
    )
    correlated = loki._loki_query_observation(
        {
            "name": "runai_control_plane_for_workload",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {"timestamp": "2026-07-10T01:00:00Z", "line": "trainer scheduler failed"}
            ],
        },
        time_range=time_range,
    )

    assert (generic["polarity"], generic["coverage"]) == ("unknown", "partial")
    assert (correlated["polarity"], correlated["coverage"]) == ("unknown", "partial")


def test_loki_history_accepts_exact_immutable_workload_row_in_incident_window() -> None:
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(make_target(), runai_workload_id=workload_id)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = loki._loki_query_observation(
        {
            "name": "workload_history_logs",
            "query": loki._workload_history_query(target),
            "transport": "direct",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": f"workload {workload_id} failed scheduling",
                    "labels": {"namespace": "runai-vision", "pod": "trainer-old-0"},
                }
            ],
        },
        target=target,
        time_range=time_range,
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    assert observation["target_scope_verified"] is True
    assert observation["observed_entity"] == {
        "kind": "runai_workload_id",
        "name": workload_id,
    }


def test_loki_history_verifies_identity_before_display_truncation() -> None:
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(make_target(), runai_workload_id=workload_id)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    full_line = f"{'x' * 260} workload {workload_id} failed scheduling"
    observation = loki._loki_query_observation(
        {
            "name": "workload_history_logs",
            "query": loki._workload_history_query(target),
            "transport": "direct",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": full_line[:240],
                    "labels": {"namespace": "runai-vision"},
                }
            ],
            "_verification_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": full_line,
                    "labels": {"namespace": "runai-vision"},
                }
            ],
        },
        target=target,
        time_range=time_range,
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")


@pytest.mark.parametrize(
    ("line", "labels"),
    [
        (
            "workload 550e8400-e29b-41d4-a716-446655440001 failed scheduling",
            {"namespace": "runai-vision"},
        ),
        (
            "workload x550e8400-e29b-41d4-a716-446655440000 failed scheduling",
            {"namespace": "runai-vision"},
        ),
        (
            "workload 550e8400-e29b-41d4-a716-446655440000-retry failed scheduling",
            {"namespace": "runai-vision"},
        ),
        ("workload trainer failed scheduling", {"namespace": "runai-vision"}),
        (
            "workload 550e8400-e29b-41d4-a716-446655440000 failed scheduling",
            {"namespace": "other-namespace"},
        ),
    ],
)
def test_loki_history_keeps_wrong_or_partial_workload_rows_as_context(
    line: str,
    labels: dict[str, str],
) -> None:
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(make_target(), runai_workload_id=workload_id)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = loki._loki_query_observation(
        {
            "name": "workload_history_logs",
            "query": loki._workload_history_query(target),
            "transport": "mcp",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": line,
                    "labels": labels,
                }
            ],
        },
        target=target,
        time_range=time_range,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["target_scope_verified"] is False


def test_loki_control_plane_accepts_exact_id_with_returned_namespace_labels() -> None:
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(make_target(), runai_workload_id=workload_id)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    selector = loki._namespace_regex_selector(("runai", "runai-system"))
    observation = loki._loki_query_observation(
        {
            "name": "runai_control_plane_for_workload",
            "query": (
                f"{selector} |~ "
                + loki._logql_string(
                    f"(?i)({loki._bounded_logql_identifier(workload_id)})"
                )
            ),
            "transport": "mcp",
            "line_count": 1,
            "stream_count": 1,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": f"preempted workload {workload_id} due to over quota",
                    "labels": {"namespace": "runai-system", "pod": "scheduler-0"},
                }
            ],
        },
        target=target,
        time_range=time_range,
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    assert observation["target_scope_verified"] is True


def test_loki_control_plane_mcp_without_returned_labels_stays_context() -> None:
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(make_target(), runai_workload_id=workload_id)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = loki._loki_query_observation(
        {
            "name": "runai_control_plane_for_workload",
            "query": '{namespace=~"runai|runai-system"}',
            "transport": "mcp",
            "line_count": 1,
            "stream_count": 0,
            "sample_entries": [
                {
                    "timestamp": "2026-07-10T01:00:00Z",
                    "line": f"workload {workload_id} was preempted",
                }
            ],
        },
        target=target,
        time_range=time_range,
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["target_scope_verified"] is False


@pytest.mark.asyncio
async def test_loki_malformed_success_body_is_unavailable_not_historical_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://loki/loki/api/v1/query_range",
            status_code=200,
            data={"status": "success", "data": {}},
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

    assert result.status == "unavailable"
    assert all(query["error"] == "Loki response missing successful data.result" for query in result.details["queries"])
    signals = [artifact for artifact in result.artifacts if artifact.type == "logql_signal"]
    assert all(artifact.result["observation"]["polarity"] == "unavailable" for artifact in signals)


def test_runai_query_observation_requires_identity_scoped_coverage() -> None:
    target = make_target()
    present = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {"workloads": [{"name": "trainer", "projectName": "vision", "queueName": "gpu-a"}]},
        },
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
    assert (missing["polarity"], missing["coverage"]) == ("unknown", "partial")
    assert (broad_nonmatch["polarity"], broad_nonmatch["coverage"]) == ("unknown", "partial")
    assert (direct_workload_nonmatch["polarity"], direct_workload_nonmatch["coverage"]) == (
        "unknown",
        "partial",
    )


def test_runai_collection_404_cannot_prove_named_resource_absence() -> None:
    target = make_target()
    mcp_project_path_missing = runai._runai_query_observation(
        {"name": "projects", "status_code": 404, "error": "HTTP 404", "data": None},
        target=target,
        used_mcp=True,
    )
    direct_workload_collection_missing = runai._runai_query_observation(
        {"name": "workloads", "status_code": 404, "error": "HTTP 404", "data": None},
        target=target,
        used_mcp=False,
    )
    direct_project_missing = runai._runai_query_observation(
        {"name": "project", "status_code": 404, "error": "HTTP 404", "data": None},
        target=target,
        used_mcp=False,
    )

    assert (mcp_project_path_missing["polarity"], mcp_project_path_missing["coverage"]) == (
        "unavailable",
        "unknown",
    )
    assert (
        direct_workload_collection_missing["polarity"],
        direct_workload_collection_missing["coverage"],
    ) == ("unavailable", "unknown")
    assert (direct_project_missing["polarity"], direct_project_missing["coverage"]) == (
        "unknown",
        "partial",
    )


def test_runai_same_named_workload_requires_non_conflicting_returned_scope() -> None:
    target = make_target()
    wrong_project = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {"workloads": [{"name": "trainer", "project": {"name": "other"}}]},
        },
        target=target,
        used_mcp=False,
    )
    wrong_queue = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {"workloads": [{"name": "trainer", "project": "vision", "queue": "other"}]},
        },
        target=target,
        used_mcp=False,
    )
    matching_scope = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {
                "workloads": [
                    {"name": "trainer", "projectName": "vision", "queueName": "gpu-a"}
                ]
            },
        },
        target=target,
        used_mcp=False,
    )

    assert (wrong_project["polarity"], wrong_project["coverage"]) == ("unknown", "partial")
    assert (wrong_queue["polarity"], wrong_queue["coverage"]) == ("unknown", "partial")
    assert (matching_scope["polarity"], matching_scope["coverage"]) == ("present", "scoped")


def test_runai_identity_does_not_match_nested_context_or_wrong_direct_resource() -> None:
    target = make_target()
    nested = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {"workloads": [{"name": "other", "project": {"name": "trainer"}}]},
        },
        target=target,
        used_mcp=False,
    )
    wrong_project = runai._runai_query_observation(
        {"name": "project", "status_code": 200, "data": {"name": "other-project"}},
        target=target,
        used_mcp=False,
    )
    empty_project = runai._runai_query_observation(
        {"name": "project", "status_code": 200, "data": {}}, target=target, used_mcp=False
    )

    assert (nested["polarity"], nested["coverage"]) == ("unknown", "partial")
    assert (wrong_project["polarity"], wrong_project["coverage"]) == ("unknown", "partial")
    assert (empty_project["polarity"], empty_project["coverage"]) == ("unknown", "partial")
    assert nested["observed_entity"] == {"kind": "workload_name", "name": "trainer"}


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


def test_runai_historical_present_requires_an_in_window_transition() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    current = runai._runai_query_observation(
        {"name": "workloads", "status_code": 200, "data": {"workloads": [{"name": "trainer"}]}},
        target=target,
        used_mcp=True,
    )
    historical = runai._runai_query_observation(
        {
            "name": "workloads",
            "status_code": 200,
            "data": {"workloads": [{"name": "trainer", "statusTransitionTime": "2026-07-10T01:04:00Z"}]},
        },
        target=target,
        used_mcp=True,
    )

    assert (current["polarity"], current["coverage"]) == ("unknown", "partial")
    assert current["current_state_only"] is True
    assert (historical["polarity"], historical["coverage"]) == ("present", "scoped")
    assert historical["evidence_window"] == {
        "start": "2026-07-10T01:04:00Z",
        "end": "2026-07-10T01:04:00Z",
    }


def test_runai_firing_404_is_scoped_only_for_immutable_workload_id() -> None:
    firing = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    resolved = replace(firing, resolved_at="2026-07-10T01:10:00Z")
    workload = replace(firing, runai_workload_id="550e8400-e29b-41d4-a716-446655440000")
    item = {"name": "workload_by_id", "status_code": 404, "error": "HTTP 404", "data": None}

    assert (
        runai._runai_query_observation(item, target=workload, used_mcp=False)["polarity"],
        runai._runai_query_observation(item, target=workload, used_mcp=False)["coverage"],
    ) == ("absent", "scoped")
    resolved_observation = runai._runai_query_observation(item, target=resolved, used_mcp=False)
    assert (resolved_observation["polarity"], resolved_observation["coverage"]) == ("unknown", "partial")
    artifact = runai._runai_query_artifact("runai", item, target=resolved, used_mcp=False)
    assert artifact.status == "partial"
    assert "absent (current state)" in artifact.summary

    for name in ("project", "queue"):
        observation = runai._runai_query_observation(
            {"name": name, "status_code": 404, "error": "HTTP 404", "data": None},
            target=firing,
            used_mcp=False,
        )
        assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


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
    assert all(log["source_verified"] is True for log in logs)
    assert all(
        log["observed_entity"]
        == {"kind": "pod", "name": "trainer-0", "namespace": "runai-vision"}
        for log in logs
    )


@pytest.mark.asyncio
async def test_historical_kubernetes_logs_prefer_timestamped_direct_api(
    monkeypatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(
            url="http://kubernetes/log",
            status_code=200,
            data={"body": "2026-07-10T01:02:00Z failed scheduling"},
        )

    async def mcp_must_not_run(*_args, **_kwargs):
        raise AssertionError("historical logs should use the timestamp-capable API")

    monkeypatch.setattr(kubernetes, "get_json", fake_get_json)
    monkeypatch.setattr(kubernetes, "_read_file", lambda _path: "service-account-token")
    monkeypatch.setattr(kubernetes, "_k8s_mcp_result", mcp_must_not_run)
    result = await k8s_logs(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        "runai-vision",
        "trainer-0",
        container="main",
        since_time="2026-07-10T00:55:00Z",
    )

    assert result["transport"] == "direct"
    assert result["source_verified"] is True
    assert result["time_scope_verified"] is True
    assert calls[0]["params"]["sinceTime"] == "2026-07-10T00:55:00Z"
    assert calls[0]["params"]["timestamps"] == "true"


@pytest.mark.asyncio
async def test_historical_mcp_log_tail_is_context_even_with_pod_identity(
    monkeypatch,
) -> None:
    class Result:
        isError = False
        content: list = []
        structuredContent = {
            "metadata": {"name": "trainer-0", "namespace": "runai-vision"},
            "body": "2026-07-10T01:02:00Z failed scheduling",
        }

    async def fake_mcp_result(*_args, **_kwargs):
        return Result()

    monkeypatch.setattr(kubernetes, "_read_file", lambda _path: "")
    monkeypatch.setattr(kubernetes, "_k8s_mcp_result", fake_mcp_result)
    result = await k8s_logs(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        "runai-vision",
        "trainer-0",
        since_time="2026-07-10T00:55:00Z",
    )
    observation, entries = _pod_log_observation(
        result,
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:10:00Z"},
    )

    assert result["source_verified"] is True
    assert result["time_scope_verified"] is False
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert entries == [{"timestamp": "2026-07-10T01:02:00Z", "line": "failed scheduling"}]


def test_kubernetes_pod_log_evidence_uses_only_timestamped_incident_lines() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation, entries = _pod_log_observation(
        {
            "container": "main",
            "previous": True,
            "source_verified": True,
            "observed_entity": {
                "kind": "pod",
                "name": "trainer-0",
                "namespace": "runai-vision",
            },
            "lines": [
                "2026-07-10T00:54:59Z before incident",
                "2026-07-10T01:10:00Z later OOMKilled",
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
    assert observation["observed_entity"] == {
        "kind": "pod",
        "name": "trainer-0",
        "namespace": "runai-vision",
    }
    assert entries == [
        {"timestamp": "2026-07-10T01:02:00Z", "line": "OOMKilled"},
        {"timestamp": "2026-07-10T01:10:00Z", "line": "later OOMKilled"},
    ]
    assert observation["evidence_window"] == {
        "start": "2026-07-10T01:02:00Z",
        "end": "2026-07-10T01:10:00Z",
    }
    assert (unknown["polarity"], unknown["coverage"]) == ("unknown", "partial")
    assert no_entries == []


def test_unverified_mcp_pod_logs_are_context_not_scoped_evidence() -> None:
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation, entries = _pod_log_observation(
        {
            "container": "main",
            "source_verified": False,
            "lines": ["2026-07-10T01:02:00Z OOMKilled"],
        },
        time_range=time_range,
    )

    # A raw MCP pods_log reply may not identify which Pod emitted this line.
    # Keep the timestamped context for the operator but never attribute it to
    # the alert Pod as a fully scoped causal observation.
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["source_verified"] is False
    assert entries == [{"timestamp": "2026-07-10T01:02:00Z", "line": "OOMKilled"}]


def test_mcp_pod_log_provenance_requires_returned_namespaced_pod() -> None:
    assert kubernetes._mcp_pod_log_observed_entity(
        {"metadata": {"name": "trainer-0", "namespace": "runai-vision"}},
        "runai-vision",
        "trainer-0",
    ) == {"kind": "pod", "name": "trainer-0", "namespace": "runai-vision"}
    assert (
        kubernetes._mcp_pod_log_observed_entity(
            {"metadata": {"name": "other-pod", "namespace": "runai-vision"}},
            "runai-vision",
            "trainer-0",
        )
        is None
    )


def test_pod_log_without_transport_provenance_is_context_only() -> None:
    observation, _ = _pod_log_observation(
        {
            "container": "main",
            "lines": ["2026-07-10T01:02:00Z OOMKilled"],
            # Requested Pod arguments are not returned-resource provenance.
            "pod": "trainer-0",
            "namespace": "runai-vision",
        },
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert observation["source_verified"] is False
    assert "observed_entity" not in observation


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


def test_kubernetes_pod_events_reject_explicitly_cross_namespace_matches() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z", namespace="team-a")
    data = {
        "items": [
            {
                "metadata": {"namespace": "team-b"},
                "type": "Warning",
                "reason": "OOMKilled",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0", "namespace": "team-b"},
            },
            {
                "metadata": {"namespace": "team-a"},
                "type": "Warning",
                "reason": "OOMKilled",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0", "namespace": "team-a"},
            },
        ]
    }

    filtered = _filter_kubernetes_data("pod_events", data, target)

    assert [item["object"] for item in filtered["items"]] == ["trainer-0"]


def test_kubernetes_pod_events_require_alert_uid_when_supplied() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", namespace="team-a", pod_uid="uid-new"
    )
    data = {
        "items": [
            {
                "metadata": {"namespace": "team-a"},
                "type": "Warning",
                "reason": "OldPod",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0", "uid": "uid-old"},
            },
            {
                "metadata": {"namespace": "team-a"},
                "type": "Warning",
                "reason": "NewPod",
                "eventTime": "2026-07-10T01:02:00Z",
                "involvedObject": {"kind": "Pod", "name": "trainer-0", "uid": "uid-new"},
            },
        ]
    }

    filtered = _filter_kubernetes_data("pod_events", data, target)

    assert [item["reason"] for item in filtered["items"]] == ["NewPod"]


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


def test_namespace_events_reject_cross_namespace_target_name() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z", namespace="team-a")
    matching_elsewhere = {
        "metadata": {"namespace": "team-b"},
        "involvedObject": {"kind": "Pod", "name": "trainer-0", "namespace": "team-b"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
    }
    matching_target = {
        "metadata": {"namespace": "team-a"},
        "involvedObject": {"kind": "Pod", "name": "trainer-0", "namespace": "team-a"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
    }

    filtered = _filter_kubernetes_data(
        "namespace_events", {"items": [matching_elsewhere, matching_target]}, target
    )

    assert [item["object"] for item in filtered["items"]] == ["trainer-0"]


def test_workload_events_require_the_expected_controller_or_child_pod_kind() -> None:
    target = replace(make_target(), pod="", workload_name="trainer", workload_type="Deployment")
    config_map = {"involvedObject": {"kind": "ConfigMap", "name": "trainer"}}
    deployment = {"involvedObject": {"kind": "Deployment", "name": "trainer"}}
    child_pod = {"involvedObject": {"kind": "Pod", "name": "trainer-6d8f7"}}

    assert _event_matches_target(config_map, target) is False
    assert _event_matches_target(deployment, target) is True
    assert _event_matches_target(child_pod, target) is True


def test_exact_podgroup_event_supports_pod_target_when_workload_type_is_missing() -> None:
    target = replace(
        make_target(),
        namespace="runai-test-pro3",
        pod="analysistest-01-0-0",
        workload_name="analysistest-01",
        workload_type="",
        fired_at="2026-07-14T01:45:00Z",
        resolved_at="2026-07-14T01:50:00Z",
    )
    event = {
        "metadata": {"namespace": target.namespace},
        "involvedObject": {
            "kind": "PodGroup",
            "name": target.workload_name,
            "namespace": target.namespace,
        },
        "eventTime": "2026-07-14T01:45:18Z",
        "type": "Warning",
        "reason": "Unschedulable",
        # Deliberately does not repeat the Pod/workload name. Identity must
        # come from involvedObject, not from a lucky message substring.
        "message": (
            "Node dgx02 didn't have enough resources: GPUs, requested: 1, "
            "used: 8, capacity: 8"
        ),
    }

    events = _filter_kubernetes_data("workload_events", {"items": [event]}, target)[
        "items"
    ]
    observation = _warning_event_observation(
        events,
        time_range={"start": target.fired_at, "end": target.resolved_at},
        status="ok",
        target=target,
    )

    assert [item["reason"] for item in events] == ["Unschedulable"]
    assert events[0]["target_identity_verified"] is True
    assert events[0]["observed_entity"] == {
        "kind": "pod",
        "name": target.pod,
        "namespace": target.namespace,
    }
    assert (observation["polarity"], observation["coverage"]) == (
        "present",
        "scoped",
    )


def test_workload_event_fallback_rejects_wrong_name_kind_and_namespace() -> None:
    target = replace(
        make_target(),
        namespace="team-a",
        workload_name="trainer",
        workload_type="",
        fired_at="2026-07-10T01:00:00Z",
    )
    base = {
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
        "reason": "Unschedulable",
    }
    events = [
        {
            **base,
            "metadata": {"namespace": "team-a"},
            "involvedObject": {"kind": "PodGroup", "name": "other"},
        },
        {
            **base,
            "metadata": {"namespace": "team-a"},
            "involvedObject": {"kind": "ConfigMap", "name": "trainer"},
        },
        {
            **base,
            "metadata": {"namespace": "team-b"},
            "involvedObject": {"kind": "PodGroup", "name": "trainer"},
        },
    ]

    filtered = _filter_kubernetes_data("workload_events", {"items": events}, target)

    assert filtered["items"] == []


@pytest.mark.asyncio
async def test_base_sweep_queries_exact_workload_events_even_with_a_pod(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        data = (
            {"metadata": {"name": "trainer-0", "namespace": "team-a"}}
            if str(kwargs["path"]).endswith("/pods/trainer-0")
            else {"items": [], "metadata": {}}
        )
        return JsonResponse(url="https://kubernetes.test", status_code=200, data=data)

    monkeypatch.setattr(kubernetes, "get_json", fake_get_json)
    target = replace(
        make_target(),
        namespace="team-a",
        pod="trainer-0",
        workload_name="trainer",
        workload_type="",
        fired_at="2026-07-10T01:00:00Z",
    )

    responses = await kubernetes._collect_kubernetes_responses(
        settings=make_settings(),
        target=target,
        headers={},
        verify=True,
        control_plane_in_scope=False,
    )

    assert [response["name"] for response in responses] == [
        "pod",
        "pod_events",
        "workload_events",
    ]
    selectors = [
        str((call.get("params") or {}).get("fieldSelector") or "")
        for call in calls
        if str(call["path"]).endswith("/events")
    ]
    assert selectors == [
        "involvedObject.name=trainer-0",
        "involvedObject.name=trainer",
    ]


def test_event_project_text_is_not_a_fallback_for_a_concrete_target() -> None:
    target = make_target()
    other_workload = {"message": "project vision failed to schedule workload batch-9"}
    project_only = replace(target, pod="", workload_name="", runai_workload_id="")

    assert _event_matches_target(other_workload, target) is False
    assert _event_matches_target(other_workload, project_only) is True


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


def test_kubernetes_warning_event_observation_exposes_actual_event_span() -> None:
    """A post-resolution Event must not inherit the broad query window as its time."""
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    observation = _warning_event_observation(
        [
            {
                "reason": "Evicted",
                "observedTimestamps": [
                    "2026-07-10T01:11:00Z",
                    "2026-07-10T01:12:00Z",
                ],
            }
        ],
        time_range=time_range,
        status="ok",
    )

    assert observation["evidence_window"] == {
        "start": "2026-07-10T01:11:00Z",
        "end": "2026-07-10T01:12:00Z",
    }


def test_target_container_termination_in_causal_window_is_scoped_and_matchable() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    diagnostics = [
        {
            "name": "main",
            "restartCount": 2,
            "state": {"phase": "waiting", "reason": "CrashLoopBackOff"},
            "lastTerminated": {
                "phase": "terminated",
                "reason": "OOMKilled",
                "exitCode": 137,
                "finishedAt": "2026-07-10T01:04:00Z",
            },
        }
    ]
    lifecycle = kubernetes._container_lifecycle_artifact(
        "kubernetes",
        make_settings(),
        target,
        {
            "name": target.pod,
            "namespace": target.namespace,
            "containerStatuses": [],
        },
        diagnostics,
        time_range=causal_evidence_time_range(target),
    )

    assert lifecycle.type == "kubernetes_container_lifecycle"
    assert lifecycle.result["observation"]["polarity"] == "present"
    assert lifecycle.result["observation"]["coverage"] == "scoped"
    assert lifecycle.result["containers"] == diagnostics
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="target container lifecycle collected",
            confidence="high",
            artifacts=[lifecycle],
        )
    ]
    assert "oomkilled" in pipeline._observed_text(results)

    outside_window = kubernetes._container_lifecycle_artifact(
        "kubernetes",
        make_settings(),
        target,
        {"name": target.pod, "namespace": target.namespace},
        [
            {
                **diagnostics[0],
                "lastTerminated": {
                    **diagnostics[0]["lastTerminated"],
                    "finishedAt": "2026-07-10T01:11:00Z",
                },
            }
        ],
        time_range=causal_evidence_time_range(target),
    )
    assert (
        outside_window.result["observation"]["polarity"],
        outside_window.result["observation"]["coverage"],
    ) == ("unknown", "partial")


def test_runai_crd_health_transition_is_scoped_and_matchable() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    finding = {
        "kind": "Workload",
        "name": "training-1",
        "reason": "Unschedulable",
        "message": "quota exhausted",
        "lastTransitionTime": "2026-07-10T01:04:00Z",
    }
    artifacts = kubernetes._runai_crd_health_artifacts(
        "kubernetes", make_settings(), [finding], time_range=causal_evidence_time_range(target)
    )

    assert len(artifacts) == 1
    observation = artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    assert "unschedulable" in pipeline._observed_text(
        [
            CollectorResult(
                agent="kubernetes", status="ok", summary="", confidence="high", artifacts=artifacts
            )
        ]
    )

    outside = kubernetes._runai_crd_health_artifacts(
        "kubernetes",
        make_settings(),
        [{**finding, "lastTransitionTime": "2026-07-10T01:11:00Z"}],
        time_range=causal_evidence_time_range(target),
    )[0]
    assert (
        outside.result["observation"]["polarity"],
        outside.result["observation"]["coverage"],
    ) == ("unknown", "partial")


def _node_condition_result(target, condition: dict[str, str]) -> CollectorResult:
    responses = [
        {
            "name": "node",
            "status_code": 200,
            "error": None,
            "data": {"name": target.node, "conditions": [condition]},
        }
    ]
    return CollectorResult(
        agent="kubernetes",
        status="ok",
        confidence="high",
        summary="Kubernetes node condition query completed.",
        artifacts=_node_condition_artifacts(
            "kubernetes",
            target,
            responses,
            time_range=causal_evidence_time_range(target),
        ),
    )


def test_true_node_pressure_condition_is_typed_scoped_and_ranked_without_events() -> None:
    target = replace(
        make_target(),
        node="k8s-lb-02",
        fired_at="2026-07-14T01:00:00Z",
        resolved_at="2026-07-14T01:10:00Z",
    )
    result = _node_condition_result(
        target,
        {
            "type": "MemoryPressure",
            "status": "True",
            "lastTransitionTime": "2026-07-13T20:00:00Z",
            "lastHeartbeatTime": "2026-07-14T01:05:00Z",
        },
    )

    assert len(result.artifacts) == 1
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == (
        "present",
        "scoped",
    )
    assert observation["observed_entity"] == {"kind": "node", "name": "k8s-lb-02"}
    assert observation["evidence_window"] == {
        "start": "2026-07-14T01:05:00Z",
        "end": "2026-07-14T01:05:00Z",
    }
    assert result.artifacts[0].result["matched_incident_timestamps"] == {
        "lastHeartbeatTime": "2026-07-14T01:05:00Z"
    }
    result.artifacts[0].evidence_id = "E01"
    board = Blackboard(run_id="INC-node-pressure")
    window = causal_evidence_time_range(target)
    assert window is not None
    board.seed_results(
        [result],
        entity="node:k8s-lb-02",
        timestamp=target.fired_at,
        observed_window_start=window["start"],
        observed_window_end=window["end"],
    )
    eligibility = EvidenceEligibility.from_fact(
        board.facts()[0],
        context={
            "run_id": "INC-node-pressure",
            "window_start": window["start"],
            "window_end": window["end"],
            "entities": ("node:k8s-lb-02",),
        },
    )
    assert eligibility.support is True
    assert (
        rank_root_cause_candidates(
            target,
            [result],
            eligible_evidence_ids={"E01"},
        )[0].family
        == "node_kubelet_pressure"
    )


def test_false_node_pressure_condition_is_scoped_absence_not_rank_support() -> None:
    target = replace(
        make_target(),
        node="k8s-lb-02",
        fired_at="2026-07-14T01:00:00Z",
        resolved_at="2026-07-14T01:10:00Z",
    )
    result = _node_condition_result(
        target,
        {
            "type": "MemoryPressure",
            "status": "False",
            "lastHeartbeatTime": "2026-07-14T01:05:00Z",
        },
    )

    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == (
        "absent",
        "scoped",
    )
    assert rank_root_cause_candidates(target, [result])[0].family == "insufficient_evidence"


def test_historical_node_pressure_snapshot_outside_window_is_context_only() -> None:
    target = replace(
        make_target(),
        node="k8s-lb-02",
        fired_at="2026-07-14T01:00:00Z",
        resolved_at="2026-07-14T01:10:00Z",
    )
    result = _node_condition_result(
        target,
        {
            "type": "MemoryPressure",
            "status": "True",
            "lastTransitionTime": "2026-07-13T20:00:00Z",
            "lastHeartbeatTime": "2026-07-13T22:00:52Z",
        },
    )

    artifact_result = result.artifacts[0].result
    observation = artifact_result["observation"]
    assert (observation["polarity"], observation["coverage"]) == (
        "unknown",
        "partial",
    )
    assert observation["snapshot_role"] == "current_context"
    assert observation["observation_window"] == {}
    assert artifact_result["timestamp_provenance"] == {
        "lastTransitionTime": "2026-07-13T20:00:00Z",
        "lastHeartbeatTime": "2026-07-13T22:00:52Z",
    }
    assert rank_root_cause_candidates(target, [result])[0].family == "insufficient_evidence"


def test_firing_node_pressure_snapshot_is_scoped_even_with_old_condition_timestamp() -> None:
    target = replace(
        make_target(),
        node="k8s-lb-02",
        fired_at="2026-07-14T01:00:00Z",
        resolved_at="",
    )
    result = _node_condition_result(
        target,
        {
            "type": "MemoryPressure",
            "status": "True",
            "lastTransitionTime": "2026-07-13T20:00:00Z",
            "lastHeartbeatTime": "2026-07-13T22:00:52Z",
        },
    )

    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == (
        "present",
        "scoped",
    )
    assert observation["snapshot_role"] == "live_incident"
    assert "evidence_window" not in observation
    assert rank_root_cause_candidates(target, [result])[0].family == "node_kubelet_pressure"


def test_kubernetes_warning_event_projection_excludes_recovery_only_failures() -> None:
    events = [
        {
            "reason": "Scheduled",
            "message": "pod scheduled",
            "observedTimestamps": ["2026-07-10T01:02:00Z"],
        },
        {
            "reason": "PostResolutionFailure",
            "message": "failed only after recovery",
            "observedTimestamps": ["2026-07-10T01:12:00Z"],
        },
        {
            "reason": "Repeating",
            "message": "same event repeated",
            "observedTimestamps": [
                "2026-07-10T01:03:00Z",
                "2026-07-10T01:13:00Z",
            ],
        },
    ]

    projected = _warning_events_in_time_range(
        events,
        {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:10:00Z"},
    )

    assert [event["reason"] for event in projected] == ["Scheduled", "Repeating"]
    assert projected[1]["observedTimestamps"] == ["2026-07-10T01:03:00Z"]
    assert projected[1]["lastTimestamp"] == "2026-07-10T01:03:00Z"


def test_kubernetes_warning_events_with_multiple_pod_uids_are_identity_ambiguous() -> None:
    target = make_target()
    entity = {
        "kind": "pod",
        "name": target.pod,
        "namespace": target.namespace,
    }
    observation = _warning_event_observation(
        [
            {
                "uid": "old-pod-uid",
                "target_identity_verified": True,
                "observed_entity": entity,
                "observedTimestamps": ["2026-07-10T01:02:00Z"],
            },
            {
                "uid": "replacement-pod-uid",
                "target_identity_verified": True,
                "observed_entity": entity,
                "observedTimestamps": ["2026-07-10T01:03:00Z"],
            },
        ],
        time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:10:00Z"},
        status="ok",
        target=target,
    )

    assert observation["target_identity_ambiguous"] is True
    assert observation["target_identity_verified"] is False
    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")


def test_kubernetes_warning_events_require_involved_object_identity_for_support() -> None:
    target = replace(
        make_target(),
        fired_at="2026-07-10T00:55:00Z",
        resolved_at="2026-07-10T01:15:00Z",
    )
    time_range = {"start": target.fired_at, "end": target.resolved_at}
    message_only = {
        "metadata": {"namespace": target.namespace},
        "involvedObject": {"kind": "Pod", "name": "runai-scheduler-0"},
        "eventTime": "2026-07-10T01:02:00Z",
        "type": "Warning",
        "message": f"failed to schedule {target.pod}",
    }
    exact_pod = {
        "metadata": {"namespace": target.namespace},
        "involvedObject": {"kind": "Pod", "name": target.pod},
        "eventTime": "2026-07-10T01:03:00Z",
        "type": "Warning",
    }

    message_summary = _filter_kubernetes_data(
        "namespace_events", {"items": [message_only]}, target
    )["items"]
    exact_summary = _filter_kubernetes_data(
        "namespace_events", {"items": [exact_pod]}, target
    )["items"]

    message_observation = _warning_event_observation(
        message_summary, time_range=time_range, status="ok", target=target
    )
    exact_observation = _warning_event_observation(
        exact_summary, time_range=time_range, status="ok", target=target
    )

    assert (message_observation["polarity"], message_observation["coverage"]) == (
        "present",
        "partial",
    )
    assert "observed_entity" not in message_summary[0]
    assert (exact_observation["polarity"], exact_observation["coverage"]) == (
        "present",
        "scoped",
    )
    assert exact_observation["observed_entity"] == {
        "kind": "pod",
        "name": target.pod,
        "namespace": target.namespace,
    }


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
    workload_incomplete = _warning_event_queries_complete(
        [
            {"name": "pod_events", "error": None},
            {"name": "workload_events", "error": "HTTP 403"},
        ]
    )
    paginated = _warning_event_queries_complete(
        [{"name": "pod_events", "error": None, "list_complete": False}]
    )
    untimed = _warning_event_queries_complete(
        [{"name": "pod_events", "error": None, "event_time_complete": False}]
    )

    assert complete is True
    assert incomplete is False
    assert workload_incomplete is False
    assert paginated is False
    assert untimed is False
    assert _kubernetes_list_complete({"items": [], "metadata": {"continue": "next"}}) is False
    assert _kubernetes_list_complete({"items": [], "metadata": {}}) is True

    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    assert _mcp_k8s_response("pod_events", "events_list", [], target)["list_complete"] is False
    assert _mcp_k8s_response("pod_events", "events_list", {"items": []}, target)["list_complete"] is False
    assert _mcp_k8s_response(
        "pod_events", "events_list", {"items": [], "metadata": {}}, target
    )["list_complete"] is True


def test_kubernetes_zero_event_time_uses_legacy_timestamp_inside_window() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    filtered = _filter_kubernetes_data(
        "pod_events",
        {
            "items": [
                {
                    "type": "Warning",
                    "reason": "OOMKilled",
                    "eventTime": "0001-01-01T00:00:00Z",
                    "lastTimestamp": "2026-07-10T01:02:00Z",
                    "involvedObject": {"kind": "Pod", "name": "trainer-0"},
                }
            ]
        },
        target,
    )

    assert [item["reason"] for item in filtered["items"]] == ["OOMKilled"]
    assert filtered["items"][0]["lastTimestamp"] == "2026-07-10T01:02:00Z"


def test_untimed_target_warning_prevents_historical_event_absence() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    data = {
        "items": [
            {
                "type": "Warning",
                "reason": "OOMKilled",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            }
        ]
    }

    assert _event_time_range_complete("pod_events", data, target) is False


def test_kubernetes_event_uses_all_observation_timestamps_for_incident_window() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")
    filtered = _filter_kubernetes_data(
        "pod_events",
        {
            "items": [
                {
                    "type": "Warning",
                    "reason": "Repeated",
                    "eventTime": "2026-07-10T00:40:00Z",
                    "series": {"lastObservedTime": "2026-07-10T01:02:00Z"},
                    "involvedObject": {"kind": "Pod", "name": "trainer-0"},
                },
                {
                    "type": "Warning",
                    "reason": "Legacy",
                    "firstTimestamp": "2026-07-10T01:03:00Z",
                    "lastTimestamp": "2026-07-10T01:30:00Z",
                    "involvedObject": {"kind": "Pod", "name": "trainer-0"},
                },
            ]
        },
        target,
    )

    assert [item["reason"] for item in filtered["items"]] == ["Repeated", "Legacy"]


def test_malformed_historical_event_payload_prevents_absence() -> None:
    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z")

    assert _event_time_range_complete("pod_events", {"body": "upstream html"}, target) is False


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
            "timestamp_type": "timestamp with time zone",
                "context_columns": ["workload_name", "action"],
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
                "target_aggregate_verified": True,
            "target_first_event_at": "2026-07-10T01:02:00Z",
            "target_last_event_at": "2026-07-10T01:02:00Z",
                "target_rows": [
                {
                    "event_time": "2026-07-10T01:02:00Z",
                    "action": "evicted",
                    "workload_name": "trainer",
                }
                ],
                "target_rows_truncated": False,
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
    assert '"project"' in strong_and_project[0]
    assert strong_and_project[1] == [["trainer"], ["vision"]]
    assert project_scoped is not None
    assert project_scoped[1] == [["vision"]]


def test_postgres_target_history_requires_available_namespace_scope() -> None:
    target = replace(make_target(), namespace="runai-vision", pod="trainer-0")
    table = {
        "schema": "audit",
        "table": "pod_history",
        "timestamp_column": "created_at",
        "context_columns": ["pod_name", "namespace"],
    }
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}

    direct = _history_target_aggregate_query(table, target, mcp=False, time_range=time_range)
    mcp = _history_target_aggregate_query(table, target, mcp=True, time_range=time_range)

    assert direct is not None and mcp is not None
    assert '"pod_name"' in direct[0] and '"namespace"' in direct[0]
    assert direct[1] == [["trainer-0"], ["runai-vision"]]
    assert '"pod_name"' in mcp[0] and '"namespace"' in mcp[0]


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
                        "target_aggregate_verified": True,
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


def test_postgres_history_malformed_target_aggregate_is_not_scoped_absence() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    artifacts = _postgres_history_artifacts(
        target,
        {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "target_correlation_available": True,
                    "target_matching_rows": 0,
                    "target_aggregate_verified": False,
                    "target_rows": [],
                }
            ],
        },
    )

    observation = artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_postgres_history_requires_timestamped_target_rows_for_presence() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    artifacts = _postgres_history_artifacts(
        target,
        {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "context_columns": ["workload_name", "action"],
                    "target_correlation_available": True,
                    "target_matching_rows": 3,
                    "target_aggregate_verified": True,
                    # Aggregate output alone cannot establish an occurrence.
                    "target_rows": [{"event_time": "not-a-time", "workload_name": "trainer"}],
                }
            ],
        },
    )

    observation = artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert "evidence_window" not in observation


def test_postgres_history_malformed_count_cannot_prove_absence() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    artifacts = _postgres_history_artifacts(
        target,
        {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "context_columns": ["workload_name"],
                    "target_correlation_available": True,
                    "target_matching_rows": "not-a-count",
                    "target_aggregate_verified": True,
                    "target_rows": [],
                }
            ],
        },
    )

    observation = artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


@pytest.mark.parametrize("count", [True, False, 1.5])
def test_postgres_target_aggregate_rejects_non_integer_count_shapes(count: object) -> None:
    matches, verified = _verified_target_aggregate(
        {
            "matching_rows": count,
            "first_event_at": "2026-07-10T01:02:00Z",
            "last_event_at": "2026-07-10T01:02:00Z",
        },
        {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
    )

    assert (matches, verified) == (0, False)


@pytest.mark.parametrize("count", [True, False, 1.5])
def test_postgres_history_non_integer_count_cannot_prove_absence_or_presence(count: object) -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    artifacts = _postgres_history_artifacts(
        target,
        {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "context_columns": ["workload_name"],
                    "target_correlation_available": True,
                    "target_matching_rows": count,
                    "target_aggregate_verified": True,
                    "target_rows": [],
                }
            ],
        },
    )

    observation = artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_postgres_history_uses_verified_row_time_and_identity_for_occurrence() -> None:
    target = replace(
        make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    artifacts = _postgres_history_artifacts(
        target,
        {
            "time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"},
            "tables": [
                {
                    "schema": "audit",
                    "table": "workload_history",
                    "context_columns": ["workload_name", "action"],
                    "target_correlation_available": True,
                    "target_matching_rows": 1,
                    "target_aggregate_verified": True,
                    "target_rows": [
                        {
                            "event_time": "2026-07-10T01:02:00Z",
                            "workload_name": "trainer",
                            "action": "evicted",
                        }
                    ],
                }
            ],
        },
    )

    observation = artifacts[0].result["observation"]
    assert observation["evidence_window"] == {
        "start": "2026-07-10T01:02:00Z",
        "end": "2026-07-10T01:02:00Z",
    }
    assert observation["observed_entity"] == {"kind": "workload_name", "name": "trainer"}
