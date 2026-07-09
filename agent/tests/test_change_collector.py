from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.collectors import change as change_mod
from app.collectors.base import AnalysisTarget
from app.collectors.change import ChangeCollector
from app.collectors.http_json import JsonResponse


def _target(namespace: str = "runai", node: str = "gpu-node-1") -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="", queue="", namespace=namespace,
        workload_name="trainer", workload_type="", runai_workload_id="",
        node=node, pod="", severity="warning", alert_name="RunAIAlert",
    )


class _Settings:
    kubernetes_api_url = "https://k8s"
    kubernetes_token_path = "/var/run/token"
    kubernetes_ca_path = "/nonexistent-ca"
    kubernetes_timeout_seconds = 6
    kubernetes_list_limit = 50
    kubernetes_namespaces: tuple[str, ...] = ()
    kubernetes_cluster_scope_enabled = True
    # No LLM -> deterministic path, matching the 90-test baseline.
    llm_base_url = ""
    llm_model = ""
    llm_api_key = ""
    language = "en"


def _iso(delta_seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=delta_seconds)).isoformat()


@pytest.mark.asyncio
async def test_no_token_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "")
    result = await ChangeCollector(_Settings()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["change.unconfigured"]
    assert result.summary.startswith("증거를 찾기 어렵습니다.")


@pytest.mark.asyncio
async def test_namespace_out_of_scope_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    class Scoped(_Settings):
        kubernetes_namespaces = ("only-this-ns",)

    result = await ChangeCollector(Scoped()).collect(_target(namespace="runai"))
    assert result.status == "unavailable"
    assert result.missing_data == ["change.unconfigured"]


@pytest.mark.asyncio
async def test_empty_cluster_degrades_to_no_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(**kwargs):
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    result = await ChangeCollector(_Settings()).collect(_target())
    assert result.status == "partial"
    assert result.summary.startswith("증거를 찾기 어렵습니다.")


@pytest.mark.asyncio
async def test_detects_rollout_new_pod_node_and_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, base_url, path, timeout_seconds, params, headers, verify):
        if "/deployments" in path:
            data = {"items": [{
                "metadata": {"name": "trainer", "generation": 5,
                             "creationTimestamp": _iso(-100000)},
                "status": {"observedGeneration": 4, "conditions": []},
            }]}
        elif "/statefulsets" in path or "/daemonsets" in path:
            data = {"items": []}
        elif path.endswith("/pods"):
            data = {"items": [
                {"metadata": {"name": "trainer-new", "creationTimestamp": _iso(-120)}},
                {"metadata": {"name": "trainer-old",
                              "creationTimestamp": _iso(-100000),
                              "deletionTimestamp": _iso(-10)}},
            ]}
        elif "/nodes/" in path:
            data = {"status": {"conditions": [
                {"type": "Ready", "status": "False", "reason": "KubeletNotReady",
                 "lastTransitionTime": _iso(-30)},
            ]}}
        elif path.endswith("/events"):
            data = {"items": [{
                "type": "Warning", "reason": "OOMKilling",
                "message": "Memory cgroup out of memory",
                "lastTimestamp": _iso(-5),
                "involvedObject": {"name": "trainer-new"},
            }]}
        else:
            data = {"items": []}
        return JsonResponse(url=f"{base_url}{path}", status_code=200, data=data)

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    result = await ChangeCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    kinds = {c["kind"] for c in result.details["changes"]}
    assert "Deployment" in kinds  # generation != observedGeneration -> mid-rollout
    assert "PodCreated" in kinds
    assert "PodDeleted" in kinds
    assert "NodeCondition" in kinds
    assert any(k.startswith("Event/") for k in kinds)
    # Sorted most-recent first: the OOM event (-5s) leads.
    assert "OOMKilling" in result.details["changes"][0]["summary"]


@pytest.mark.asyncio
async def test_query_failure_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(**kwargs):
        return JsonResponse(url="u", status_code=0, error="ConnectError: refused")

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    result = await ChangeCollector(_Settings()).collect(_target())
    assert result.status == "partial"
    assert result.warnings  # each failed query recorded a warning


class _ArchSettings(_Settings):
    architecture_file = "knowledge/runai_architecture.yaml"


def _plan(component: str, namespace: str = "runai", node: str = "gpu-node-1"):
    from app.plan import InvestigationPlan

    return InvestigationPlan(namespaces=[namespace], node=node, component=component)


@pytest.mark.asyncio
async def test_dependency_namespaces_scanned_for_upstream_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Alert is ON runai-container-toolkit (ns runai) but the real trigger is an
    # upstream GPU Operator DaemonSet mid-rollout in ns gpu-operator (P2b).
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, base_url, path, timeout_seconds, params, headers, verify):
        if "/namespaces/gpu-operator/daemonsets" in path:
            data = {"items": [{
                "metadata": {"name": "nvidia-driver-daemonset", "namespace": "gpu-operator",
                             "generation": 7, "creationTimestamp": _iso(-100000)},
                "status": {"observedGeneration": 6, "conditions": []},
            }]}
        else:
            data = {"items": []}
        return JsonResponse(url=f"{base_url}{path}", status_code=200, data=data)

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    result = await ChangeCollector(_ArchSettings()).collect(
        _target(), plan=_plan("runai-container-toolkit")
    )
    assert result.status == "ok"
    assert "gpu-operator" in result.details["dependency_namespaces"]
    upstream = [
        c for c in result.details["changes"]
        if c.get("namespace") == "gpu-operator" and c.get("rollout")
    ]
    assert upstream and upstream[0]["name"] == "nvidia-driver-daemonset"


@pytest.mark.asyncio
async def test_helm_release_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, base_url, path, timeout_seconds, params, headers, verify):
        if path.endswith("/secrets"):
            data = {"items": [
                {"metadata": {"name": "sh.helm.release.v1.gpu-operator.v3",
                              "namespace": "gpu-operator",
                              "creationTimestamp": _iso(-60),
                              "labels": {"owner": "helm", "name": "gpu-operator",
                                         "version": "3", "status": "pending-upgrade"}}},
                {"metadata": {"name": "sh.helm.release.v1.gpu-operator.v2",
                              "namespace": "gpu-operator",
                              "creationTimestamp": _iso(-100000),
                              "labels": {"owner": "helm", "name": "gpu-operator",
                                         "version": "2", "status": "superseded"}}},
            ]}
        else:
            data = {"items": []}
        return JsonResponse(url=f"{base_url}{path}", status_code=200, data=data)

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    result = await ChangeCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    helm = [c for c in result.details["changes"] if c.get("kind") == "HelmRelease"]
    # Only the newest in-window revision (v3) is reported, marked as a rollout.
    assert len(helm) == 1
    assert helm[0]["revision"] == 3
    assert helm[0]["rollout"] is True
    assert helm[0]["helm_status"] == "pending-upgrade"
