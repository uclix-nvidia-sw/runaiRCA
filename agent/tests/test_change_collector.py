from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.collectors import change as change_mod
from app.collectors.base import AnalysisTarget
from app.collectors.change import ChangeCollector, change_query
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
    assert result.artifacts[0].result["observation"]["polarity"] == "unavailable"


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
async def test_historical_incident_uses_its_own_change_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **_kwargs):
        if path.endswith("/events"):
            return JsonResponse(
                url="u",
                status_code=200,
                data={
                    "items": [
                        {
                            "type": "Warning",
                            "reason": "DuringIncident",
                            "lastTimestamp": "2026-01-02T03:04:00Z",
                            "involvedObject": {"name": "trainer"},
                        },
                        {
                            "type": "Warning",
                            "reason": "MuchLater",
                            "lastTimestamp": "2026-07-13T09:00:00Z",
                            "involvedObject": {"name": "trainer"},
                        },
                    ]
                },
            )
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await ChangeCollector(_Settings()).collect(target)

    assert result.details["time_range"] == {
        "start": "2026-01-02T02:55:00Z",
        "end": "2026-01-02T03:15:00Z",
    }
    assert [change["reason"] for change in result.details["changes"]] == ["DuringIncident"]
    assert "start=2026-01-02T02:55:00Z" in result.artifacts[0].query
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")


@pytest.mark.asyncio
async def test_historical_incident_excludes_pod_deleted_outside_its_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **_kwargs):
        if path.endswith("/pods"):
            return JsonResponse(
                url="u",
                status_code=200,
                data={
                    "items": [
                        {
                            "metadata": {
                                "name": "trainer-old",
                                "namespace": "runai",
                                "creationTimestamp": "2025-12-01T00:00:00Z",
                                # A stale termination must not become evidence
                                # for the January incident just because the Pod
                                # still has a deletion timestamp in this read.
                                "deletionTimestamp": "2026-01-03T00:00:00Z",
                            }
                        }
                    ]
                },
            )
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await ChangeCollector(_Settings()).collect(target)

    assert result.status == "partial"
    assert result.details["time_range"] == {
        "start": "2026-01-02T02:55:00Z",
        "end": "2026-01-02T03:15:00Z",
    }
    assert result.details.get("changes", []) == []
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("absent", "scoped")


@pytest.mark.asyncio
async def test_change_cache_does_not_reuse_another_workloads_scoped_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **_kwargs):
        if path.endswith("/events"):
            return JsonResponse(
                url="u",
                status_code=200,
                data={
                    "items": [
                        {
                            "type": "Warning",
                            "reason": "BackOff",
                            "lastTimestamp": "2026-01-02T03:04:00Z",
                            "involvedObject": {"kind": "Pod", "name": "trainer-0"},
                        }
                    ]
                },
            )
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    collector = ChangeCollector(_Settings())
    incident = {
        "fired_at": "2026-01-02T03:00:00Z",
        "resolved_at": "2026-01-02T03:10:00Z",
    }
    trainer = await collector.collect(replace(_target(), **incident))
    other = await collector.collect(
        replace(_target(), workload_name="other", pod="other-0", **incident)
    )

    assert trainer.details["changes"][0]["name"] == "trainer-0"
    assert other is not trainer
    assert other.details["changes"] == []
    assert other.details["context_changes"][0]["name"] == "trainer-0"
    observation = other.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


@pytest.mark.asyncio
async def test_historical_unrelated_namespace_change_is_context_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **_kwargs):
        if path.endswith("/events"):
            return JsonResponse(
                url="u",
                status_code=200,
                data={
                    "items": [
                        {
                            "type": "Warning",
                            "reason": "OOMKilled",
                            "lastTimestamp": "2026-01-02T03:04:00Z",
                            "involvedObject": {"kind": "Pod", "name": "other-worker-0"},
                        }
                    ]
                },
            )
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await ChangeCollector(_Settings()).collect(target)

    observation = result.artifacts[0].result["observation"]
    assert result.status == "partial"
    assert result.details["changes"] == []
    assert result.details["context_changes"][0]["name"] == "other-worker-0"
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


@pytest.mark.asyncio
async def test_historical_stale_target_rollout_is_context_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **_kwargs):
        if path.endswith("/deployments"):
            return JsonResponse(
                url="u",
                status_code=200,
                data={
                    "items": [
                        {
                            "metadata": {
                                "name": "trainer",
                                "namespace": "runai",
                                "generation": 5,
                                "creationTimestamp": "2025-12-01T00:00:00Z",
                            },
                            "status": {"observedGeneration": 4, "conditions": []},
                        }
                    ]
                },
            )
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await ChangeCollector(_Settings()).collect(target)

    observation = result.artifacts[0].result["observation"]
    assert result.status == "partial"
    assert result.details["changes"] == []
    assert result.details["context_changes"][0]["relation"] == "stale_or_untimed_context"
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


def test_live_change_window_remains_context_only() -> None:
    observation = change_mod._collector_change_observation(
        changes=[{"kind": "PodCreated"}],
        time_range={"start": "2026-07-13T00:00:00Z", "end": "2026-07-13T01:00:00Z"},
        historical_window=False,
        warnings=[],
    )

    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")


def test_historical_change_requires_individual_occurrence_timestamp() -> None:
    observation = change_mod._collector_change_observation(
        changes=[
            {
                "kind": "Deployment",
                "name": "trainer",
                # A metadata list query may still surface a stale/malformed
                # item. Its broad request range is not evidence that this
                # rollout happened during the incident.
                "timestamp": "not-a-rfc3339-time",
            }
        ],
        time_range={"start": "2026-07-13T00:00:00Z", "end": "2026-07-13T01:00:00Z"},
        historical_window=True,
        warnings=[],
    )

    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert "evidence_window" not in observation


def test_historical_change_uses_change_timestamp_not_query_window() -> None:
    observation = change_mod._collector_change_observation(
        changes=[
            {
                "kind": "PodDeleted",
                "name": "trainer-0",
                "timestamp": "2026-07-13T00:12:00Z",
            }
        ],
        time_range={"start": "2026-07-13T00:00:00Z", "end": "2026-07-13T01:00:00Z"},
        historical_window=True,
        warnings=[],
    )

    assert observation["evidence_window"] == {
        "start": "2026-07-13T00:12:00Z",
        "end": "2026-07-13T00:12:00Z",
    }


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
                              "labels": {"owner": "helm", "name": "trainer",
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


@pytest.mark.asyncio
async def test_change_query_is_bounded_scoped_and_never_returns_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")
    calls: list[dict] = []

    async def fake_get_json(*, path, params, **kwargs):
        calls.append({"path": path, "params": params})
        if path.endswith("/events"):
            data = {"items": [{
                "type": "Warning",
                "reason": "OOMKilling",
                "message": "token=event-body-secret",
                "lastTimestamp": _iso(-5),
                "involvedObject": {"name": "trainer", "kind": "Pod"},
            }]}
        elif path.endswith("/secrets"):
            data = {"items": [{
                "metadata": {
                    "name": "sh.helm.release.v1.trainer.v2",
                    "creationTimestamp": _iso(-10),
                    "labels": {"owner": "helm", "name": "trainer", "version": "2"},
                },
                "data": {"release": "helm-secret-body"},
            }]}
        else:
            data = {"items": []}
        return JsonResponse(url="u", status_code=200, data=data)

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    query = await change_query(
        _Settings(),
        _target(),
        {"kind": "all", "component": "trainer", "lookback_seconds": 120, "limit": 1},
    )

    assert all(
        call["params"] is None or int(call["params"].get("limit", 1)) <= 1 for call in calls
    )
    assert query["source_group"] == "kubernetes_api"
    assert query["independence_group"] == "kubernetes_api"
    observation = query["observation"]
    assert observation["observed_entity"] == {"kind": "component", "name": "trainer"}
    assert observation["window"] == {"lookback_seconds": 120}
    assert observation["polarity"] == "present"
    assert observation["coverage"] == "partial"
    assert set(observation["observation_window"]) == {"start", "end"}
    assert observation["body_included"] is False
    assert len(observation["changes"]) == 1
    assert "event-body-secret" not in str(query)
    assert "helm-secret-body" not in str(query)
    assert "summary" not in observation["changes"][0]


@pytest.mark.asyncio
async def test_change_query_uses_the_historical_incident_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **kwargs):
        if path.endswith("/events"):
            return JsonResponse(url="u", status_code=200, data={"items": [
                {
                    "type": "Warning",
                    "reason": "BackOff",
                    "lastTimestamp": "2026-07-13T21:44:00Z",
                    "involvedObject": {"name": "trainer", "kind": "Pod"},
                },
                {
                    "type": "Warning",
                    "reason": "UnrelatedCurrentEvent",
                    "lastTimestamp": "2026-07-14T09:00:00Z",
                    "involvedObject": {"name": "trainer", "kind": "Pod"},
                },
            ]})
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )
    query = await change_query(_Settings(), target, {"kind": "event", "lookback_seconds": 60})

    observation = query["observation"]
    assert observation["historical_window"] is True
    assert observation["observation_window"] == {
        "start": "2026-07-13T21:38:47Z",
        "end": "2026-07-13T21:50:47Z",
    }
    assert observation["window"] == {"lookback_seconds": 720}
    assert [change["reason"] for change in observation["changes"]] == ["BackOff"]
    assert observation["coverage"] == "scoped"
    assert "start=2026-07-13T21:38:47Z" in query["query"]


@pytest.mark.asyncio
async def test_change_query_keeps_unrelated_namespace_history_as_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(*, path, **kwargs):
        if path.endswith("/events"):
            return JsonResponse(url="u", status_code=200, data={"items": [
                {
                    "type": "Warning",
                    "reason": "BackOff",
                    "lastTimestamp": "2026-07-13T21:44:00Z",
                    "involvedObject": {"name": "unrelated-worker", "kind": "Pod"},
                }
            ]})
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )
    query = await change_query(_Settings(), target, {"kind": "event"})

    observation = query["observation"]
    assert observation["changes"] == []
    assert observation["context_change_count"] == 1
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


@pytest.mark.asyncio
async def test_change_query_marks_paginated_history_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(**kwargs):
        return JsonResponse(
            url="u",
            status_code=200,
            data={"items": [], "metadata": {"continue": "next-page-token"}},
        )

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )
    query = await change_query(_Settings(), target, {"kind": "event"})

    assert query["observation"]["polarity"] == "unknown"
    assert query["observation"]["coverage"] == "partial"
    assert "truncated by Kubernetes pagination" in query["summary"]


@pytest.mark.asyncio
async def test_change_query_refuses_namespace_or_limit_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")
    query = await change_query(
        _Settings(), _target(), {"namespace": "other", "limit": 999}
    )

    assert query["error"] == "namespace must match the alert namespace scope"
    assert query["observation"]["coverage"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["controller", "pod", "node_condition", "event", "helm"])
async def test_change_query_accepts_plan_kinds_with_bounded_lookback(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")

    async def fake_get_json(**kwargs):
        return JsonResponse(url="u", status_code=200, data={"items": []})

    monkeypatch.setattr(change_mod, "get_json", fake_get_json)
    query = await change_query(_Settings(), _target(), {"kind": kind, "lookback_seconds": 86400})

    assert query["error"] is None
    assert query["observation"]["polarity"] == "unknown"
    assert query["observation"]["coverage"] == "partial"


@pytest.mark.asyncio
async def test_change_query_refuses_lookback_outside_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(change_mod, "_read_file", lambda _p: "tok")
    query = await change_query(_Settings(), _target(), {"kind": "event", "lookback_seconds": 59})

    assert query["error"] == "lookback_seconds must be between 60 and 86400"
