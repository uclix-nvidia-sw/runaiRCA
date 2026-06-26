from __future__ import annotations

from app.collectors.base import AnalysisTarget
from app.collectors.kubernetes import _filter_kubernetes_data
from app.collectors.prometheus import _queries_for
from app.nat_tools import (
    AnalysisAgentConfig,
    KubernetesContextConfig,
    LokiContextConfig,
    RunAIContextConfig,
)
from app.prompts import agent_role_coverage_lines, load_agent_souls


def make_target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="vision",
        queue="gpu-a",
        namespace="runai-vision",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="",
        severity="warning",
        alert_name="RunAIWorkloadPending",
    )


def test_agent_role_contracts_cover_each_component_agent() -> None:
    souls = load_agent_souls("prompts/agent_souls.md")

    for section in [
        "## RunAI Agent",
        "## Kubernetes Agent",
        "## Prometheus Agent",
        "## Loki Agent",
        "## Postgres Agent",
        "## Analysis Agent",
    ]:
        assert section in souls

    assert "Running the `runai` CLI by default" in souls
    assert "RUNAI_LOG_NAMESPACES" in souls
    assert "Analysis Dashboard" in souls
    assert "similar incidents and operator feedback hints" in souls


def test_nat_tool_descriptions_expose_agent_boundaries() -> None:
    assert "KubeRCA-style RCA analysis" in (AnalysisAgentConfig.__doc__ or "")
    assert "no CLI by default" in (RunAIContextConfig.__doc__ or "")
    assert "Run:ai control-plane pod/event" in (KubernetesContextConfig.__doc__ or "")
    assert "runai/runai-backend" in (LokiContextConfig.__doc__ or "")


def test_role_coverage_lines_are_operator_visible() -> None:
    text = "\n".join(agent_role_coverage_lines())

    assert "KubeRCA-style RCA verdict" in text
    assert "no CLI by default" in text
    assert "Run:ai control-plane pod health" in text
    assert "runai` and `runai-backend" in text


def test_runai_control_plane_pod_scan_is_not_filtered_by_workload_name() -> None:
    result = _filter_kubernetes_data(
        "runai_control_plane_pods:runai-backend",
        {
            "items": [
                {
                    "metadata": {"name": "runai-backend-0", "namespace": "runai-backend"},
                    "spec": {"nodeName": "node-a"},
                    "status": {"phase": "Running", "containerStatuses": []},
                },
                {
                    "metadata": {"name": "scheduler-0", "namespace": "runai-backend"},
                    "spec": {"nodeName": "node-b"},
                    "status": {"phase": "Pending", "containerStatuses": []},
                },
            ]
        },
        make_target(),
    )

    assert isinstance(result, dict)
    assert result["namespace"] == "runai-backend"
    names = {item["name"] for item in result["items"]}
    assert names == {"runai-backend-0", "scheduler-0"}


def test_prometheus_queries_cover_queue_and_project_gpu_contract() -> None:
    queries = dict(_queries_for(make_target()))

    assert queries["runai_queue_allocated_gpus"] == 'runai_queue_allocated_gpus{queue="gpu-a"}'
    assert queries["runai_queue_requested_gpus"] == 'runai_queue_requested_gpus{queue="gpu-a"}'
    assert (
        queries["runai_project_allocated_gpus"]
        == 'runai_project_allocated_gpus{project="vision"}'
    )
    assert (
        queries["runai_project_requested_gpus"]
        == 'runai_project_requested_gpus{project="vision"}'
    )
