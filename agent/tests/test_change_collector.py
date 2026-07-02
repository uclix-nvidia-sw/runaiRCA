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
