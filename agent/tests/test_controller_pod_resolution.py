from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.collectors import kubernetes
from app.collectors.base import resolve_target
from app.collectors.kubernetes import _collect_resolved_pod_logs, _resolve_workload_pod
from tests.test_orchestrator import make_settings, make_target


class _McpResult:
    isError = False

    def __init__(self, structured: object) -> None:
        self.structuredContent = structured
        self.content: list[object] = []


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

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector="", **_kwargs):
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

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector="", **_kwargs):
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

    async def fake_k8s_logs(
        settings, namespace, pod, container="", tail=0, previous=False, since_time=""
    ):
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

    async def fake_describe(settings, kind, namespace="", name="", **_kwargs):
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

    async def fake_resolved_logs(settings, target, containers, **_kwargs):
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event_pod", "expected_count", "expected_verified"),
    [
        ("permission-manager-67466b4f94-rj5d2", 1, True),
        ("other-app-12345-abcde", 0, False),
    ],
)
async def test_workload_firing_warning_uses_resolved_pod_identity_anchor(
    monkeypatch, event_pod, expected_count, expected_verified
) -> None:
    """Deployment alerts verify only Events for their resolved live Pod."""
    namespace = "permission-manager"
    pod_name = "permission-manager-67466b4f94-rj5d2"
    now = datetime.now(UTC).replace(microsecond=0)
    pod = {
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "uid": "permission-manager-pod-uid",
            "labels": {"app": "permission-manager"},
            "ownerReferences": [
                {"kind": "ReplicaSet", "name": "permission-manager-67466b4f94", "uid": "pm-rs-uid"}
            ],
        },
        "spec": {"containers": [{"name": "manager"}]},
        "status": {
            "phase": "Pending",
            "containerStatuses": [
                {
                    "name": "manager",
                    "state": {"waiting": {"reason": "ImagePullBackOff"}},
                }
            ],
        },
    }
    event = {
        "metadata": {"namespace": namespace},
        "involvedObject": {"kind": "Pod", "name": event_pod, "namespace": namespace},
        "type": "Warning",
        "reason": "Failed",
        "message": "Error: ImagePullBackOff",
        "eventTime": now.isoformat().replace("+00:00", "Z"),
    }

    async def fake_mcp_call(_url, tool, arguments):
        kind = str(arguments.get("kind") or "").casefold()
        if tool == "resources_get" and kind in {"deployment", "deployments"}:
            return _McpResult(
                {
                    "metadata": {
                        "name": "permission-manager",
                        "namespace": namespace,
                        "uid": "pm-deploy-uid",
                    },
                    "spec": {"selector": {"matchLabels": {"app": "permission-manager"}}},
                }
            )
        if tool == "resources_get" and kind in {"replicaset", "replicasets"}:
            return _McpResult(
                {
                    "metadata": {
                        "name": "permission-manager-67466b4f94",
                        "namespace": namespace,
                        "uid": "pm-rs-uid",
                        "ownerReferences": [
                            {"kind": "Deployment", "name": "permission-manager", "uid": "pm-deploy-uid"}
                        ],
                    }
                }
            )
        if tool in {"pods_list_in_namespace", "pods_list"} or (
            tool == "resources_list" and kind in {"pod", "pods"}
        ):
            return _McpResult({"items": [pod]})
        if tool in {"pods_get", "resources_get"} and (
            tool == "pods_get" or kind in {"pod", "pods"}
        ):
            return _McpResult(pod)
        if tool in {"events_list", "resources_list"}:
            return _McpResult({"items": [event]})
        return _McpResult({"items": []})

    monkeypatch.setattr(kubernetes, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(kubernetes, "_read_file", lambda _path: "")
    target = replace(
        make_target(),
        namespace=namespace,
        workload_name="permission-manager",
        workload_type="Deployment",
        pod="",
        fired_at=(now - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        resolved_at="",
    )

    result = await kubernetes.KubernetesCollector(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp")
    ).collect(target)

    warning_events = next(a for a in result.artifacts if a.type == "kubernetes_warning_events")
    observation = warning_events.result["observation"]
    assert result.details["resolved_pod"] == pod_name
    assert observation["event_count"] >= expected_count
    assert observation["target_identity_verified"] is expected_verified
    if expected_verified:
        # A bare MCP Event list has no pagination metadata, so it deliberately
        # remains incomplete. Positive, target-verified evidence is still
        # scoped; completeness only gates absence claims.
        assert observation["queries_complete"] is False
        assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")
    else:
        assert observation["event_count"] == 0
