from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import kubernetes
from app.collectors.base import resolve_target
from app.collectors.kubernetes import _collect_resolved_pod_logs, _resolve_workload_pod
from tests.test_orchestrator import make_settings, make_target


@pytest.mark.parametrize(
    ("label", "expected_type"),
    [
        ("deployment", "Deployment"),
        ("statefulset", "StatefulSet"),
        ("daemonset", "DaemonSet"),
        ("replicaset", "ReplicaSet"),
        ("job_name", "Job"),
        ("cronjob", "CronJob"),
    ],
)
def test_resolve_target_infers_controller_type(label: str, expected_type: str) -> None:
    target = resolve_target(
        {
            "namespace": "runai-rca",
            label: "failing-controller",
            "pod": "prometheus-kube-state-metrics-exporter",
        },
        {},
    )

    assert target.workload_name == "failing-controller"
    assert target.workload_type == expected_type
    assert target.pod == ""


@pytest.mark.asyncio
async def test_deployment_resolves_selector_to_most_unhealthy_pod(monkeypatch) -> None:
    calls: list[tuple[str, str, str]] = []

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        calls.append((kind, name, label_selector))
        if kind == "deployments":
            return {
                "data": {"spec": {"selector": {"matchLabels": {"app": "api", "tier": "control"}}}}
            }
        return {
            "data": {
                "items": [
                    {
                        "metadata": {
                            "name": "api-healthy",
                            "creationTimestamp": "2026-07-13T01:00:00Z",
                            "labels": {"app": "api", "tier": "control"},
                        },
                        "status": {"phase": "Running", "containerStatuses": []},
                    },
                    {
                        "metadata": {
                            "name": "api-failed",
                            "creationTimestamp": "2026-07-13T02:00:00Z",
                            "labels": {"app": "api", "tier": "control"},
                        },
                        "status": {"phase": "Failed", "containerStatuses": []},
                    },
                ]
            }
        }

    monkeypatch.setattr(kubernetes, "k8s_read", fake_k8s_read)
    target = replace(
        make_target(),
        namespace="runai-rca",
        workload_name="api",
        workload_type="Deployment",
        pod="",
    )

    resolution = await _resolve_workload_pod(make_settings(), target)

    assert resolution["selected_pod"] == "api-failed"
    assert ("pods", "", "app=api,tier=control") in calls


@pytest.mark.asyncio
async def test_job_without_selector_uses_standard_job_label(monkeypatch) -> None:
    selectors: list[str] = []

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        if kind == "jobs":
            return {"data": {"metadata": {"name": name}, "spec": {}}}
        selectors.append(label_selector)
        return {
            "data": {
                "items": [
                    {
                        "metadata": {"name": "ingest-abc", "labels": {"job-name": "ingest"}},
                        "status": {"phase": "Failed"},
                    }
                ]
            }
        }

    monkeypatch.setattr(kubernetes, "k8s_read", fake_k8s_read)
    target = replace(
        make_target(),
        namespace="runai-rca",
        workload_name="ingest",
        workload_type="Job",
        pod="",
    )

    resolution = await _resolve_workload_pod(make_settings(), target)

    assert selectors == ["batch.kubernetes.io/job-name=ingest"]
    assert resolution["selected_pod"] == "ingest-abc"


@pytest.mark.asyncio
async def test_resolved_controller_pod_logs_are_collected(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_k8s_logs(settings, namespace, pod, container="", tail=0):
        calls.append((pod, container))
        return {"status_code": 200, "error": None, "lines": ["Traceback: boom"]}

    monkeypatch.setattr(kubernetes, "k8s_logs", fake_k8s_logs)
    target = replace(make_target(), namespace="runai-rca", pod="ingest-failed")

    logs = await _collect_resolved_pod_logs(make_settings(), target, ["ingest"])

    assert calls == [("ingest-failed", "ingest")]
    assert logs[0]["lines"] == ["Traceback: boom"]


@pytest.mark.asyncio
async def test_collector_drills_controller_alert_down_to_pod_logs(monkeypatch) -> None:
    async def fake_base_responses(**kwargs):
        return [
            {
                "name": "namespace_pods",
                "path": "MCP pods_list",
                "status_code": 200,
                "error": None,
                "data": {"items": []},
            }
        ]

    async def no_initial_logs(**kwargs):
        return []

    async def fake_resolution(settings, target):
        return {"selected_pod": "api-failed", "selector": "app=api"}

    async def fake_describe(settings, kind, namespace="", name=""):
        return {
            "object": {
                "metadata": {"name": name, "namespace": namespace},
                "spec": {"containers": [{"name": "api"}]},
                "status": {
                    "phase": "Failed",
                    "containerStatuses": [{"name": "api", "restartCount": 0}],
                },
            },
            "events": [{"type": "Warning", "reason": "BackoffLimitExceeded"}],
        }

    async def fake_resolved_logs(settings, target, containers):
        assert target.pod == "api-failed"
        assert containers == ["api"]
        return [
            {
                "container": "api",
                "status_code": 200,
                "error": None,
                "lines": ["Traceback: application failed"],
            }
        ]

    async def no_crds(*args, **kwargs):
        return {"checked": [], "findings": []}

    monkeypatch.setattr(kubernetes, "_collect_kubernetes_responses_via_mcp", fake_base_responses)
    monkeypatch.setattr(kubernetes, "_collect_pod_logs_via_mcp", no_initial_logs)
    monkeypatch.setattr(kubernetes, "_resolve_workload_pod", fake_resolution)
    monkeypatch.setattr(kubernetes, "k8s_describe", fake_describe)
    monkeypatch.setattr(kubernetes, "_collect_resolved_pod_logs", fake_resolved_logs)
    monkeypatch.setattr(kubernetes, "collect_runai_crd_findings", no_crds)

    settings = replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp")
    target = replace(
        make_target(),
        namespace="runai-rca",
        workload_name="api",
        workload_type="Deployment",
        pod="",
    )
    result = await kubernetes.KubernetesCollector(settings).collect(target)

    assert result.details["resolved_pod"] == "api-failed"
    assert result.details["pod_logs"][0]["lines"] == ["Traceback: application failed"]
    assert result.details["pod_statuses"][-1]["phase"] == "Failed"
