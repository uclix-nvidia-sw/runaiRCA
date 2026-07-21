from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import AnalysisTarget
from app.collectors import kubernetes


def target(*, pod: str = "", workload_type: str = "Deployment") -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="", queue="", namespace="runai", workload_name="api",
        workload_type=workload_type, runai_workload_id="", node="", pod=pod,
        severity="warning", alert_name="alert", fired_at="2026-07-10T01:00:00Z",
    )


def anchor(*, owned: bool = True, pod: str = "api-new") -> AnalysisTarget:
    return replace(target(), pod=pod, pod_uid=f"uid-{pod}", ownership_verified=owned)


def warning_event(pod: str, uid: str, *, verified: bool = True) -> dict[str, object]:
    return {
        "kind": "Pod",
        "observed_entity": {"kind": "workload_name", "name": "api", "namespace": "runai"},
        "target_identity_verified": verified,
        "target_identity_anchor_verified": verified,
        "object": pod,
        "uid": uid,
    }


def test_owned_controller_pod_warning_and_lifecycle_promote() -> None:
    a = anchor()
    observation = kubernetes._warning_event_observation(
        [warning_event(a.pod, a.pod_uid)], time_range={"start": "x", "end": "y"},
        status="ok", target=target(), resolved_pod_anchor=a,
    )
    assert observation["target_identity_verified"] is True
    assert observation["coverage"] == "scoped"
    assert kubernetes._container_lifecycle_target_verified(
        {"name": a.pod, "uid": a.pod_uid, "namespace": "runai"},
        target(), resolved_pod_anchor=a,
    ) is True


def test_selector_match_without_ownership_does_not_promote() -> None:
    a = anchor(owned=False)
    observation = kubernetes._warning_event_observation(
        [warning_event(a.pod, a.pod_uid)], time_range={"start": "x", "end": "y"},
        status="ok", target=target(), resolved_pod_anchor=a,
    )
    assert observation["target_identity_verified"] is False
    assert observation["coverage"] == "partial"
    assert kubernetes._container_lifecycle_target_verified(
        {"name": a.pod, "uid": a.pod_uid, "namespace": "runai"},
        target(), resolved_pod_anchor=a,
    ) is False


def test_pod_target_remains_uid_and_name_scoped() -> None:
    pod_target = target(pod="api-new")
    event = warning_event("api-new", "uid-api-new")
    event["observed_entity"] = {"kind": "pod", "name": "api-new", "namespace": "runai"}
    assert kubernetes._warning_event_observation(
        [event], time_range={"start": "x", "end": "y"}, status="ok", target=pod_target,
    )["coverage"] == "scoped"
    assert kubernetes._container_lifecycle_target_verified(
        {"name": "api-new", "uid": "uid-api-new", "namespace": "runai"}, pod_target,
    ) is True


@pytest.mark.asyncio
async def test_deployment_rollout_only_selects_uid_owned_replica_set_pod(monkeypatch) -> None:
    deployment = {"metadata": {"uid": "deploy-uid"}, "spec": {"selector": {"matchLabels": {"app": "api"}}}}
    replica_sets = {
        "rs-old": {"metadata": {"uid": "rs-old-uid", "ownerReferences": [{"kind": "Deployment", "name": "api", "uid": "other-deploy"}]}},
        "rs-new": {"metadata": {"uid": "rs-new-uid", "ownerReferences": [{"kind": "Deployment", "name": "api", "uid": "deploy-uid"}]}},
    }
    pods = [
        {"metadata": {"name": "api-old", "uid": "pod-old", "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-old", "uid": "rs-old-uid"}]}},
        {"metadata": {"name": "api-new", "uid": "pod-new", "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-new", "uid": "rs-new-uid"}]}},
    ]

    async def fake_read(_settings, resource, *, namespace, name="", label_selector="", full_object=False):
        if resource == "deployments":
            return {"data": deployment}
        if resource == "replicasets":
            return {"data": replica_sets[name]}
        return {"data": {"items": pods}}

    monkeypatch.setattr(kubernetes, "k8s_read", fake_read)
    resolution = await kubernetes._resolve_workload_pod(
        SimpleNamespace(kubernetes_namespaces=()), target()
    )
    assert resolution["selected_pod"] == "api-new"
    assert resolution["ownership_verified"] is True
