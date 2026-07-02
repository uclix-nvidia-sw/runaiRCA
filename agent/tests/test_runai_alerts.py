from __future__ import annotations

import asyncio

from app.collectors.base import AnalysisTarget
from app.config import load_settings
from app.knowledge import load_runai_alerts, match_runai_alert
from app.services.planner import plan_investigation

CATALOG = "knowledge/runai_alerts_catalog.yaml"


def test_load_runai_alerts_shape() -> None:
    catalog = load_runai_alerts(CATALOG)
    assert catalog  # non-empty
    matched = match_runai_alert(catalog, "NVIDIA Run:ai Project Controller Reconcile Failure")
    assert matched is not None
    assert matched["family"] == "control_plane_error"
    assert matched["actions"]


def test_match_camelcase_alertname() -> None:
    # Prometheus emits CamelCase alertnames; they must still match the doc's spaced title.
    catalog = load_runai_alerts(CATALOG)
    matched = match_runai_alert(catalog, "RunaiProjectControllerReconcileFailure")
    assert matched is not None
    assert matched["family"] == "control_plane_error"


def test_no_false_match_for_unknown_alert() -> None:
    catalog = load_runai_alerts(CATALOG)
    assert match_runai_alert(catalog, "SomeUnrelatedAlertName") is None


def test_load_runai_alerts_missing_file() -> None:
    assert load_runai_alerts("/nope/does-not-exist.yaml") == {}


def test_planner_uses_matched_builtin_alert() -> None:
    settings = load_settings()  # no LLM configured -> deterministic plan
    target = AnalysisTarget(
        cluster="", project="", queue="", namespace="monitoring", workload_name="",
        workload_type="", runai_workload_id="", node="gpu-1", pod="",
        severity="critical", alert_name="Unknown State Alert for a Node",
    )
    plan = asyncio.run(plan_investigation(settings, target, None, {}, []))
    assert plan.matched_alert is not None
    assert plan.matched_alert["alert"].startswith("Unknown State")
    # The documented family leads the hypotheses.
    assert plan.hypotheses[0]["family"] == "node_kubelet_pressure"
    # A non-Run:ai node alert must NOT pull the control plane into scope.
    assert plan.check_control_plane is False
