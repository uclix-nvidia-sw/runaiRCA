from __future__ import annotations

from app.collectors.base import AnalysisTarget
from app.collectors.prometheus import (
    _prometheus_mcp_args,
    _prometheus_query_path_and_params,
    _queries_for,
)


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="",
        severity="warning",
        alert_name="TestAlert",
    )


def test_control_plane_promql_has_no_illegal_string_escape():
    # Regression: re.escape("runai-backend") -> "runai\\-backend", and "\\-" is an
    # illegal escape inside a PromQL double-quoted string literal, so Prometheus
    # rejects the whole query with HTTP 400 at the lexer. A namespace with a '-'
    # (the default "runai-backend" has one) must NOT introduce any backslash.
    queries = dict(_queries_for(_target(), None, ("runai", "runai-backend")))
    for name in ("runai_control_plane_restarts", "runai_control_plane_pending"):
        promql = queries[name]
        assert "\\" not in promql, f"{name} has an illegal backslash: {promql!r}"
        assert 'namespace=~"runai|runai-backend"' in promql


def test_pod_metric_queries_require_a_namespace_for_a_unique_identity():
    target = AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="",
        workload_name="",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="same-name-in-another-namespace",
        severity="warning",
        alert_name="TestAlert",
    )

    names = {name for name, _query in _queries_for(target)}

    assert "container_memory" not in names
    assert "container_cpu" not in names
    assert "container_restarts" not in names


def test_range_vector_uses_instant_api_form() -> None:
    window = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}

    path, params = _prometheus_query_path_and_params("metric[5m]", window)
    assert path == "/api/v1/query"
    assert params == {"query": "metric[5m]", "time": window["end"]}

    path, _params = _prometheus_query_path_and_params("(metric[5m])", window)
    assert path == "/api/v1/query"

    path, params = _prometheus_query_path_and_params("rate(metric[5m])", window)
    assert path == "/api/v1/query_range"
    assert params["step"] == "60"

    args = _prometheus_mcp_args("metric[5m]", "prom", window)
    assert args == {
        "datasourceUid": "prom",
        "expr": "metric[5m]",
        "queryType": "instant",
        "time": window["end"],
    }
