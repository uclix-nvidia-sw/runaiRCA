from __future__ import annotations

import pytest

from app.collectors import prometheus
from app.collectors.base import AnalysisTarget
from app.collectors.http_json import JsonResponse
from app.collectors.prometheus import (
    _collect_prometheus_direct,
    _normalize_promql,
    _prometheus_mcp_args,
    _prometheus_query_artifact,
    _prometheus_query_path_and_params,
    _queries_for,
)
from tests.test_orchestrator import make_settings, make_target


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


@pytest.mark.asyncio
async def test_json_escaped_slash_is_normalized_on_both_transports(monkeypatch) -> None:
    query = r'sum(kube_node_status_allocatable{resource="nvidia.com\/gpu"})'
    expected = 'sum(kube_node_status_allocatable{resource="nvidia.com/gpu"})'
    sent: list[dict[str, object]] = []

    async def fake_get_json(**kwargs):
        sent.append(kwargs)
        return JsonResponse(
            url="http://prometheus/api/v1/query",
            status_code=200,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    await _collect_prometheus_direct(make_settings(), [("gpu", query)], [])

    assert sent[0]["params"] == {"query": expected}
    assert _prometheus_mcp_args(query, "prom", None)["expr"] == expected


@pytest.mark.parametrize(
    "query",
    [
        r'{node=~"dgx\.02"}',
        r'{pod=~"web\\d+"}',
        r'"a\\b"',
        r'"a\"b"',
        "sum(metric)",
    ],
)
def test_promql_normalizer_preserves_every_other_escape(query: str) -> None:
    assert _normalize_promql(query) == query


def test_promql_normalizer_leaves_escaped_slash_outside_string_untouched() -> None:
    query = r"sum(metric\/other)"

    assert _normalize_promql(query) == query


@pytest.mark.asyncio
async def test_http_error_detail_is_bounded_in_query_artifact(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query",
            status_code=400,
            data={
                "status": "error",
                "errorType": "bad_data",
                "error": f"parse error: invalid escape {'x' * 300}",
            },
            error="HTTP 400",
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    [item] = await _collect_prometheus_direct(
        make_settings(), [("gpu", "broken")], []
    )
    artifact = _prometheus_query_artifact(
        "prometheus", item, target=make_target(), time_range=None
    )
    error = artifact.result["error"]

    assert error.startswith("HTTP 400: bad_data: parse error: invalid escape")
    assert len(error) == 200


@pytest.mark.asyncio
async def test_successful_query_artifact_has_no_error(monkeypatch) -> None:
    async def fake_get_json(**_kwargs):
        return JsonResponse(
            url="http://prometheus/api/v1/query",
            status_code=200,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr(prometheus, "get_json", fake_get_json)
    [item] = await _collect_prometheus_direct(make_settings(), [("gpu", "up")], [])
    artifact = _prometheus_query_artifact(
        "prometheus", item, target=make_target(), time_range=None
    )

    assert item["error"] is None
    assert artifact.result["error"] is None
