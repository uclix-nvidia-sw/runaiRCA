from __future__ import annotations

from app.collectors.base import AnalysisTarget
from app.collectors.prometheus import _queries_for


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
