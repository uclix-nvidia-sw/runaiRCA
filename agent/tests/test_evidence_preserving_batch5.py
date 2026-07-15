import asyncio

from app.collectors import kubernetes, postgres
from app.collectors.base import AnalysisTarget
from tests.test_orchestrator import make_settings


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="vision", queue="gpu-a", namespace="runai", workload_name="trainer",
        workload_type="Deployment", runai_workload_id="", node="", pod="", severity="", alert_name="",
        fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z",
    )


def test_postgres_naive_audit_timestamp_is_verified_as_utc() -> None:
    table = {
        "context_columns": ["workload_name", "namespace", "project", "queue"],
        "target_rows": [{
            "event_time": "2026-07-10T01:04:00",
            "workload_name": "trainer", "namespace": "runai", "project": "vision", "queue": "gpu-a",
        }],
    }
    verified, window, entity = postgres._verified_target_history_rows(
        table, _target(), {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}, 1
    )
    assert verified is True
    assert window == {"start": "2026-07-10T01:04:00Z", "end": "2026-07-10T01:04:00Z"}
    assert entity == {"kind": "workload_name", "name": "trainer"}
    assert postgres._history_rows_assume_utc(table) is True


def test_diagnostic_pod_retains_namespace_context_when_no_workload_match() -> None:
    pod = {"metadata": {"name": "other-12345"}, "status": {"phase": "Pending"}}
    assert kubernetes._diagnostic_pod([pod], "trainer") == pod


def test_node_summary_includes_cordon_and_taints() -> None:
    summary = kubernetes._node_summary({"metadata": {"name": "gpu-1"}, "spec": {
        "unschedulable": True, "taints": [{"key": "maintenance"}]}, "status": {}})
    assert summary["unschedulable"] is True
    assert summary["taints"] == [{"key": "maintenance"}]


def test_crd_scan_keeps_failure_visible(monkeypatch) -> None:
    async def failing(*_args, **_kwargs):
        return {"error": "forbidden", "data": {}}

    monkeypatch.setattr(kubernetes, "k8s_read", failing)
    result = asyncio.run(kubernetes.collect_runai_crd_findings(make_settings(), _target(), []))
    assert result["failed_kinds"]
    assert result["warnings"]
