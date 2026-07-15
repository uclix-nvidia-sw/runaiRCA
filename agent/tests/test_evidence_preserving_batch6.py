from datetime import UTC, datetime

from app.collectors import grafana_mcp, prometheus
from app.collectors.base import AnalysisTarget


def _target(**values) -> AnalysisTarget:
    base = dict(cluster="", project="vision", queue="gpu-a", namespace="runai", workload_name="", workload_type="", runai_workload_id="", node="", pod="pod", severity="", alert_name="")
    base.update(values)
    return AnalysisTarget(**base)


def test_prometheus_escapes_selector_values_and_accepts_millisecond_epochs() -> None:
    queries = dict(prometheus._queries_for(_target(namespace='run"ai', pod=r"pod\\x", queue='q"x')))
    assert 'namespace="run\\"ai"' in queries["container_memory"]
    assert 'pod="pod\\\\\\\\x"' in queries["container_memory"]
    assert prometheus._parse_prometheus_timestamp("1752118800000") == datetime(2025, 7, 10, 3, 40, tzinfo=UTC)


def test_prometheus_node_followup_uses_an_anchored_escaped_regex() -> None:
    query = dict(prometheus._prom_followup_queries({"pod_statuses": [{"phase": "Pending"}]}, _target(node="gpu.node-1")))["node_memory_headroom"]
    assert "^gpu\\\\.node\\\\-1(:\\\\d+)?$" in query


def test_grafana_name_match_cannot_select_wrong_type() -> None:
    assert grafana_mcp._select_datasource_uid(
        [{"name": "loki-archive", "type": "elasticsearch", "uid": "valid_uid"}], "loki"
    ) == ""
