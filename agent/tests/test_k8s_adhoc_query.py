"""kubectl-style read-only ad-hoc queries for the investigation loop.

The agent talks to the same API kubectl wraps; what was missing was FREEFORM
querying beyond the collectors' fixed set. These tests pin the safety envelope:
kind allowlist (no secrets), GET/LIST-only path building, and the investigator
wiring that turns LLM 'queries' into evidence artifacts."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from app.collectors import kubernetes as k8s
from app.collectors.base import CollectorResult, artifact
from app.collectors.http_json import JsonResponse
from app.plan import InvestigationPlan
from app.services import investigator
from app.services.evidence_blackboard import normalize_artifact
from tests.test_orchestrator import make_settings, make_target


def test_resolve_read_kind_aliases_and_refusals() -> None:
    assert k8s.resolve_read_kind("pvc") == "persistentvolumeclaims"
    assert k8s.resolve_read_kind("Deploy") == "deployments"
    assert k8s.resolve_read_kind("sc") == "storageclasses"
    assert k8s.resolve_read_kind("pods") == "pods"
    # never readable through this tool
    assert k8s.resolve_read_kind("secrets") is None
    assert k8s.resolve_read_kind("secret") is None
    assert k8s.resolve_read_kind("") is None


def test_k8s_read_builds_get_list_paths(monkeypatch) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(url=kwargs["path"], status_code=200, data={"items": []})

    monkeypatch.setattr(k8s, "get_json", fake_get_json)
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")
    settings = make_settings()

    # namespaced LIST with selector
    out = asyncio.run(
        k8s.k8s_read(settings, "pvc", namespace="team-a", label_selector="app=x")
    )
    assert out["error"] is None
    assert calls[-1]["path"] == "/api/v1/namespaces/team-a/persistentvolumeclaims"
    assert calls[-1]["params"]["labelSelector"] == "app=x"
    # named GET (no list params)
    asyncio.run(k8s.k8s_read(settings, "deployment", namespace="runai", name="scheduler"))
    assert calls[-1]["path"] == "/apis/apps/v1/namespaces/runai/deployments/scheduler"
    assert calls[-1]["params"] is None
    # path segments stay segments even if a hallucinated query includes slash/dot text
    asyncio.run(k8s.k8s_read(settings, "pods", namespace="../runai", name="train/0"))
    assert calls[-1]["path"] == "/api/v1/namespaces/..%2Frunai/pods/train%2F0"
    # cluster-scoped kind ignores the namespace segment
    asyncio.run(k8s.k8s_read(settings, "storageclass"))
    assert calls[-1]["path"] == "/apis/storage.k8s.io/v1/storageclasses"

    # cluster-wide Pod LIST pinned to one assigned node
    out = asyncio.run(
        k8s.k8s_read(settings, "pods", field_selector="spec.nodeName=gpu-node-a")
    )
    assert out["field_selector"] == "spec.nodeName=gpu-node-a"
    assert calls[-1]["path"] == "/api/v1/pods"
    assert calls[-1]["params"]["fieldSelector"] == "spec.nodeName=gpu-node-a"


def test_full_pod_inspection_masks_direct_api_environment_values(monkeypatch) -> None:
    async def fake_get_json(**kwargs):
        return JsonResponse(
            url=kwargs["path"],
            status_code=200,
            data={
                "metadata": {"name": "trainer-0"},
                "spec": {
                    "containers": [
                        {
                            "name": "trainer",
                            "image": "registry/trainer:v1",
                            "env": [{"name": "API_TOKEN", "value": "direct-api-secret"}],
                            "resources": {"limits": {"memory": "8Gi"}},
                        }
                    ]
                },
                "status": {"phase": "Running"},
            },
        )

    monkeypatch.setattr(k8s, "get_json", fake_get_json)
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")
    result = asyncio.run(
        k8s.k8s_read(
            make_settings(), "pods", namespace="runai", name="trainer-0", full_object=True
        )
    )

    assert result["data"]["status"]["phase"] == "Running"
    assert result["data"]["spec"]["containers"][0]["resources"]["limits"]["memory"] == "8Gi"
    assert result["data"]["spec"]["containers"][0]["env"][0]["value"] == "[MASKED]"
    assert "direct-api-secret" not in str(result)


def test_resolve_live_pod_node_encodes_path_segments(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs["path"])
        return JsonResponse(url=kwargs["path"], status_code=404, data={})

    monkeypatch.setattr(k8s, "get_json", fake_get_json)
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")

    asyncio.run(
        k8s.resolve_live_pod_node(
            make_settings(),
            namespace="runai/../../api",
            pod="pod/../../nodes",
        )
    )

    assert calls == [
        "/api/v1/namespaces/runai%2F..%2F..%2Fapi/pods/pod%2F..%2F..%2Fnodes",
        "/api/v1/namespaces/runai%2F..%2F..%2Fapi/pods",
        "/api/v1/namespaces/runai%2F..%2F..%2Fapi/events",
    ]


@pytest.mark.asyncio
async def test_resolve_live_pod_node_uses_mcp_namespace_wide_list_without_direct_token(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_mcp_read(
        _settings,
        _resolved,
        namespace="",
        name="",
        label_selector="",
        full_object=False,
    ):
        calls.append((namespace, name))
        assert full_object is True
        if name:
            return {
                "kind": "pods",
                "namespace": namespace,
                "name": name,
                "status_code": 200,
                "error": None,
                "data": {
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {"nodeName": "gpu-node-7"},
                    "status": {"phase": "Running"},
                },
            }
        return {
            "kind": "pods",
            "namespace": namespace,
            "name": "",
            "status_code": 200,
            "error": None,
            "data": {
                "metadata": {"continue": ""},
                "items": [
                    {
                        "metadata": {"name": "trainer-0", "namespace": namespace},
                        "spec": {"nodeName": "gpu-node-7"},
                        "status": {"phase": "Running"},
                    }
                ],
            },
        }

    def direct_token_should_not_be_read(_path: str) -> str:
        raise AssertionError("MCP node discovery must not require the agent token")

    monkeypatch.setattr(k8s, "_k8s_read_via_mcp", fake_mcp_read)
    monkeypatch.setattr(k8s, "_read_file", direct_token_should_not_be_read)
    settings = replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp")

    resolved = await k8s.resolve_live_pod_node(settings, "team-a", "trainer-0")

    assert resolved == ("trainer-0", "gpu-node-7")
    assert calls == [("team-a", "trainer-0"), ("team-a", "")]


@pytest.mark.asyncio
async def test_resolve_live_pod_node_uses_unambiguous_workload_prefix_for_stale_pod(
    monkeypatch,
) -> None:
    calls: list[str] = []

    async def fake_read(_settings, _kind, namespace="", name="", **_kwargs):
        calls.append(name or "<wide-list>")
        if name:
            return {"status_code": 404, "error": "not found", "data": None}
        return {
            "status_code": 200,
            "error": None,
            "data": {
                "metadata": {"continue": ""},
                "items": [
                    {
                        "metadata": {
                            "name": "slack-test1-worker-new99",
                            "namespace": namespace,
                            "creationTimestamp": "2026-07-14T06:00:00Z",
                        },
                        "spec": {"nodeName": "gpu-node-9"},
                        "status": {
                            "phase": "Failed",
                            "containerStatuses": [],
                        },
                    },
                    {
                        "metadata": {
                            "name": "different-workload-abcde",
                            "namespace": namespace,
                        },
                        "spec": {"nodeName": "gpu-node-other"},
                        "status": {"phase": "Running"},
                    },
                ],
            },
        }

    async def no_events(*_args, **_kwargs):
        raise AssertionError("a live workload match should resolve before historical events")

    monkeypatch.setattr(k8s, "k8s_read", fake_read)
    monkeypatch.setattr(k8s, "_describe_events", no_events)

    resolved = await k8s.resolve_live_pod_node(
        make_settings(),
        "runai-test-pro3",
        "slack-test1-deleted99",
        workload="slack-test1",
    )

    assert resolved == ("slack-test1-worker-new99", "gpu-node-9")
    assert calls == ["slack-test1-deleted99", "<wide-list>"]


@pytest.mark.asyncio
async def test_resolve_live_pod_node_refuses_replacement_from_incomplete_list(
    monkeypatch,
) -> None:
    async def fake_read(_settings, _kind, namespace="", name="", **_kwargs):
        if name:
            return {"status_code": 404, "error": "not found", "data": None}
        return {
            "status_code": 200,
            "error": None,
            "data": {
                "metadata": {"continue": "next-page"},
                "items": [
                    {
                        "metadata": {
                            "name": "trainer-worker-a",
                            "namespace": namespace,
                        },
                        "spec": {"nodeName": "gpu-node-1"},
                        "status": {"phase": "Failed", "containerStatuses": []},
                    }
                ],
            },
        }

    async def no_events(*_args, **_kwargs):
        return []

    monkeypatch.setattr(k8s, "k8s_read", fake_read)
    monkeypatch.setattr(k8s, "_describe_events", no_events)
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "")

    resolved = await k8s.resolve_live_pod_node(
        make_settings(),
        "team-a",
        "trainer-deleted99",
        workload="trainer",
    )

    assert resolved == ("", "")


@pytest.mark.asyncio
async def test_resolve_live_pod_node_paginates_past_50_before_replica_inference(
    monkeypatch,
) -> None:
    calls: list[dict] = []

    def pod(name: str, node: str) -> dict:
        return {
            "metadata": {"name": name, "namespace": "team-a"},
            "spec": {"nodeName": node},
            "status": {"phase": "Failed", "containerStatuses": []},
        }

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        path = kwargs["path"]
        params = kwargs.get("params") or {}
        if path.endswith("/pods/trainer-deleted99"):
            return JsonResponse(
                url=path,
                status_code=404,
                data={},
                error="HTTP 404",
            )
        if path.endswith("/pods") and params.get("continue") == "page-2":
            return JsonResponse(
                url=path,
                status_code=200,
                data={
                    "metadata": {"continue": ""},
                    "items": [pod("trainer-worker-b", "gpu-node-2")],
                },
            )
        if path.endswith("/pods"):
            unrelated = [
                pod(f"unrelated-{index:02d}", "gpu-node-other") for index in range(49)
            ]
            return JsonResponse(
                url=path,
                status_code=200,
                data={
                    "metadata": {"continue": "page-2"},
                    "items": [pod("trainer-worker-a", "gpu-node-1"), *unrelated],
                },
            )
        if path.endswith("/events"):
            return JsonResponse(
                url=path,
                status_code=200,
                data={"metadata": {"continue": ""}, "items": []},
            )
        raise AssertionError(f"unexpected Kubernetes path: {path}")

    monkeypatch.setattr(k8s, "get_json", fake_get_json)
    monkeypatch.setattr(k8s, "_read_file", lambda _path: "token")

    resolved = await k8s.resolve_live_pod_node(
        make_settings(),
        "team-a",
        "trainer-deleted99",
        workload="trainer",
    )

    assert resolved == ("", "")
    assert any((call.get("params") or {}).get("continue") == "page-2" for call in calls)


@pytest.mark.asyncio
async def test_resolve_live_pod_node_does_not_borrow_sibling_node_for_pending_exact_pod(
    monkeypatch,
) -> None:
    pending = {
        "metadata": {"name": "trainer-0", "namespace": "team-a"},
        "spec": {"nodeName": ""},
        "status": {"phase": "Pending"},
    }

    async def fake_read(_settings, _kind, namespace="", name="", **_kwargs):
        if name:
            return {"status_code": 200, "error": None, "data": pending}
        return {
            "status_code": 200,
            "error": None,
            "data": {
                "items": [
                    pending,
                    {
                        "metadata": {"name": "trainer-1", "namespace": namespace},
                        "spec": {"nodeName": "gpu-node-2"},
                        "status": {"phase": "Running"},
                    },
                ]
            },
        }

    monkeypatch.setattr(k8s, "k8s_read", fake_read)

    assert await k8s.resolve_live_pod_node(
        make_settings(), "team-a", "trainer-0", workload="trainer"
    ) == ("trainer-0", "")


def test_kubectl_repr_quotes_multiline_values() -> None:
    rendered = k8s.kubectl_repr("pods", namespace="runai\nbad", name="train/0")
    assert "\n" not in rendered
    assert "'runai\nbad'" not in rendered
    assert "$'runai" not in rendered
    assert "kubectl get pods train/0 -n" in rendered
    assert k8s.kubectl_repr("pods; delete secrets", namespace="runai") == (
        "kubectl get 'pods; delete secrets' -n runai"
    )


def test_k8s_read_refuses_unlisted_kind_without_calling_api(monkeypatch) -> None:
    async def boom(**kwargs):  # pragma: no cover - must not be called
        raise AssertionError("API must not be called for a refused kind")

    monkeypatch.setattr(k8s, "get_json", boom)
    out = asyncio.run(k8s.k8s_read(make_settings(), "secrets", namespace="runai"))
    assert "allowlist" in out["error"]


@pytest.mark.asyncio
async def test_mcp_named_read_rejects_a_different_resource(monkeypatch) -> None:
    async def fake_mcp_json(_settings, _candidates):
        return {"metadata": {"name": "other-pod", "namespace": "team-a"}}

    monkeypatch.setattr(k8s, "_k8s_mcp_json", fake_mcp_json)
    with pytest.raises(RuntimeError, match="did not return the requested resource"):
        await k8s._k8s_read_via_mcp(
            replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
            "pods",
            namespace="team-a",
            name="worker-0",
            full_object=True,
        )


@pytest.mark.asyncio
async def test_mcp_resource_candidates_always_include_api_version(monkeypatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    async def fake_mcp_json(_settings, candidates):
        captured.extend(candidates)
        return {"metadata": {"name": "worker-0", "namespace": "team-a"}}

    monkeypatch.setattr(k8s, "_k8s_mcp_json", fake_mcp_json)
    await k8s._k8s_read_via_mcp(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        "pods",
        namespace="team-a",
        name="worker-0",
        full_object=True,
    )

    resources_get = [args for tool, args in captured if tool == "resources_get"]
    assert resources_get
    assert all(args.get("apiVersion") == "v1" for args in resources_get)


@pytest.mark.asyncio
async def test_base_mcp_node_read_does_not_emit_unversioned_resources_get(monkeypatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    async def fake_mcp_json(_settings, candidates):
        captured.extend(candidates)
        return {"metadata": {"name": "gpu-node"}}

    monkeypatch.setattr(k8s, "_k8s_mcp_json", fake_mcp_json)
    target = replace(make_target(), namespace="", pod="", node="gpu-node")
    await k8s._collect_kubernetes_responses_via_mcp(
        settings=replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        target=target,
        control_plane_in_scope=False,
    )

    resources_get = [args for tool, args in captured if tool == "resources_get"]
    assert resources_get == [{"apiVersion": "v1", "kind": "Node", "name": "gpu-node"}]


@pytest.mark.asyncio
async def test_mcp_yaml_named_read_does_not_fall_back_to_direct_api(monkeypatch) -> None:
    class Result:
        isError = False
        structuredContent = None
        content = [
            type(
                "Text",
                (),
                {
                    "text": (
                        "apiVersion: v1\nkind: Pod\nmetadata:\n"
                        "  name: worker-0\n  namespace: team-a\nspec:\n"
                        "  nodeName: gpu-node-1\n"
                    )
                },
            )()
        ]

    async def fake_mcp_call(_url, tool, _arguments):
        if tool == "resources_get":
            return Result()
        raise RuntimeError("shortcut tool unavailable")

    async def direct_api_must_not_run(**_kwargs):
        raise AssertionError("direct Kubernetes API must not run after an MCP YAML success")

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(k8s, "get_json", direct_api_must_not_run)

    result = await k8s.k8s_read(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        "pods",
        namespace="team-a",
        name="worker-0",
        full_object=True,
    )

    assert result["error"] is None
    assert result["url"].endswith("#read_pods")
    assert result["data"]["metadata"] == {"name": "worker-0", "namespace": "team-a"}
    assert "mcp_fallback" not in result


@pytest.mark.asyncio
async def test_mcp_field_selector_uses_generic_list_and_enforces_assignment(monkeypatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    async def fake_mcp_json(_settings, candidates):
        captured.extend(candidates)
        # Simulate a proxy accepting but ignoring fieldSelector.
        return {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [
                {
                    "metadata": {"name": "on-a", "namespace": "team-a"},
                    "spec": {"nodeName": "gpu-node-a"},
                },
                {
                    "metadata": {"name": "on-b", "namespace": "team-b"},
                    "spec": {"nodeName": "gpu-node-b"},
                },
            ],
        }

    monkeypatch.setattr(k8s, "_k8s_mcp_json", fake_mcp_json)
    result = await k8s._k8s_read_via_mcp(
        replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
        "pods",
        field_selector="spec.nodeName=gpu-node-a",
        full_object=True,
    )

    assert captured
    assert all(tool == "resources_list" for tool, _args in captured)
    assert captured[0][1]["fieldSelector"] == "spec.nodeName=gpu-node-a"
    assert [pod["metadata"]["name"] for pod in result["data"]["items"]] == ["on-a"]


@pytest.mark.asyncio
async def test_gpu_scheduling_snapshot_collects_node_capacity_and_assigned_requests(
    monkeypatch,
) -> None:
    calls: list[dict[str, object]] = []

    async def fake_read(
        _settings,
        kind,
        namespace="",
        name="",
        label_selector="",
        field_selector="",
        *,
        full_object=False,
    ):
        calls.append(
            {
                "kind": kind,
                "namespace": namespace,
                "name": name,
                "field_selector": field_selector,
                "full_object": full_object,
            }
        )
        if kind == "nodes":
            return {
                "url": f"https://kubernetes.default.svc/api/v1/nodes/{name}",
                "status_code": 200,
                "error": None,
                "data": {
                    "metadata": {"name": name},
                    "status": {
                        "capacity": {"nvidia.com/gpu": "8"},
                        "allocatable": {"nvidia.com/gpu": "8"},
                    },
                },
            }
        return {
            "url": "https://kubernetes.default.svc/api/v1/pods",
            "status_code": 200,
            "error": None,
            "data": {
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {},
                "items": [
                    {
                        "metadata": {"namespace": "team-a", "name": "train-a"},
                        "spec": {
                            "nodeName": "gpu-node-a",
                            "containers": [
                                {
                                    "resources": {
                                        "requests": {"nvidia.com/gpu": "2"}
                                    }
                                }
                            ],
                        },
                        "status": {"phase": "Running"},
                    },
                    {
                        "metadata": {"namespace": "team-b", "name": "train-b"},
                        "spec": {
                            "nodeName": "gpu-node-a",
                            "containers": [
                                {
                                    # Extended resources may be limits-only.
                                    "resources": {"limits": {"nvidia.com/gpu": "4"}}
                                }
                            ],
                        },
                        "status": {"phase": "Pending"},
                    },
                    {
                        "metadata": {"namespace": "team-a", "name": "completed"},
                        "spec": {
                            "nodeName": "gpu-node-a",
                            "containers": [
                                {
                                    "resources": {
                                        "requests": {"nvidia.com/gpu": "8"}
                                    }
                                }
                            ],
                        },
                        "status": {"phase": "Succeeded"},
                    },
                    {
                        "metadata": {"namespace": "team-z", "name": "other-node"},
                        "spec": {
                            "nodeName": "gpu-node-z",
                            "containers": [
                                {
                                    "resources": {
                                        "requests": {"nvidia.com/gpu": "8"}
                                    }
                                }
                            ],
                        },
                        "status": {"phase": "Running"},
                    },
                ],
            },
        }

    monkeypatch.setattr(k8s, "k8s_read", fake_read)
    target = replace(make_target(), node="", node_source="")
    plan = InvestigationPlan(
        hypotheses=[
            {
                "family": "k8s_scheduling_error",
                "reason": "FailedScheduling: Insufficient nvidia.com/gpu",
            }
        ]
    )
    snapshots = await k8s._collect_gpu_node_resource_observations(
        make_settings(),
        target,
        plan,
        [
            {
                "reason": "FailedScheduling",
                "message": (
                    "Insufficient nvidia.com/gpu while evaluating capacity "
                    "on node gpu-node-a"
                ),
                "target_identity_verified": True,
            }
        ],
    )

    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot["gpu_capacity"] == 8
    assert snapshot["gpu_allocatable"] == 8
    assert snapshot["gpu_requested"] == 6
    assert snapshot["gpu_estimated_free"] == 2
    assert snapshot["scheduled_non_terminal_pods"] == 2
    assert snapshot["snapshot_role"] == "current_context"
    assert snapshot["observation"] == {
        "kind": "kubernetes_node_gpu_resources",
        "predicate": "kubernetes_node_gpu_resources",
        "polarity": "unknown",
        "coverage": "partial",
        "observation_window": {},
        "snapshot_role": "current_context",
        "observed_entity": {"kind": "node", "name": "gpu-node-a"},
    }
    assert {call["kind"] for call in calls} == {"nodes", "pods"}
    pod_call = next(call for call in calls if call["kind"] == "pods")
    assert pod_call["namespace"] == ""
    assert pod_call["field_selector"] == "spec.nodeName=gpu-node-a"
    assert pod_call["full_object"] is True

    card = k8s._gpu_node_resource_artifact("kubernetes", make_settings(), snapshot)
    assert card.type == "kubernetes_node_gpu_resources"
    assert "kubectl get pods -A --field-selector spec.nodeName=gpu-node-a" in card.query
    assert card.result["observation"]["polarity"] == "unknown"
    fact = normalize_artifact(card, require_typed_observation=True)
    assert fact.polarity == "unknown"
    assert fact.coverage == "partial"
    assert fact.eligibility.support is False
    assert fact.eligibility.refutation is False
    assert fact.eligibility.context is True


@pytest.mark.asyncio
async def test_gpu_snapshot_ignores_preemption_policy_and_generic_node_affinity(
    monkeypatch,
) -> None:
    async def unexpected_read(*_args, **_kwargs):
        raise AssertionError("non-shortage scheduling text must not trigger node reads")

    monkeypatch.setattr(k8s, "k8s_read", unexpected_read)
    plan = InvestigationPlan(
        hypotheses=[
            {
                "family": "k8s_scheduling_error",
                "reason": "preemptionPolicy=PreemptLowerPriority",
            }
        ]
    )
    target = replace(make_target(), node="")
    events = [
        {
            "reason": "FailedScheduling",
            "message": "placement failed on node affinity; preemption is not helpful",
            "target_identity_verified": True,
        }
    ]

    assert await k8s._collect_gpu_node_resource_observations(
        make_settings(), target, plan, events
    ) == []
    assert k8s._gpu_snapshot_candidate_nodes(target, events) == []


def test_gpu_snapshot_extracts_runai_angle_bracket_node() -> None:
    target = replace(make_target(), node="")
    events = [
        {
            "reason": "Unschedulable",
            "message": (
                "Unschedulable: <dgx02>: Node didn't have enough resources: "
                "GPUs, requested: 1, used: 8, capacity: 8"
            ),
            "target_identity_verified": True,
        }
    ]

    assert k8s._gpu_snapshot_candidate_nodes(target, events) == ["dgx02"]
    plan = InvestigationPlan(
        hypotheses=[
            {
                "family": "k8s_scheduling_error",
                "reason": "verify the exact scheduler Warning",
            }
        ]
    )
    assert k8s._gpu_scheduling_snapshot_requested(plan, events) is True


@pytest.mark.asyncio
async def test_mcp_list_read_rejects_empty_success_payload(monkeypatch) -> None:
    class Result:
        isError = False
        content: list = []
        structuredContent: dict = {}

    async def fake_mcp_call(_url, _tool, _arguments):
        return Result()

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    with pytest.raises(RuntimeError, match="Kubernetes object/list payload"):
        await k8s._k8s_mcp_json(
            replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
            [("pods_list", {"namespace": "team-a"})],
        )


def test_k8s_describe_uses_mcp_full_pod_and_filters_its_events(monkeypatch) -> None:
    calls: list[str] = []
    event_selectors: list[str] = []

    class Result:
        isError = False
        content: list = []

        def __init__(self, value: dict) -> None:
            self.structuredContent = value

    async def fake_mcp_call(_url, tool, _arguments):
        calls.append(tool)
        if tool in {"pods_get", "resources_get"}:
            if _arguments.get("kind") == "Event":
                event_selectors.append(str(_arguments.get("fieldSelector") or ""))
            else:
                return Result(
                    {
                        "metadata": {"name": "worker-0", "namespace": "team-a"},
                        "spec": {
                            "containers": [
                                {"name": "main", "env": [{"name": "MODE", "value": "train"}]}
                            ]
                        },
                        "status": {"phase": "Failed"},
                    }
                )
        if tool == "resources_list" and _arguments.get("kind") == "Event":
            event_selectors.append(str(_arguments.get("fieldSelector") or ""))
        return Result(
            {
                "items": [
                    {
                        "type": "Warning",
                        "reason": "OOMKilled",
                        "involvedObject": {"kind": "Pod", "name": "worker-0"},
                        "lastTimestamp": "2026-07-10T01:00:00Z",
                    },
                    {
                        "type": "Warning",
                        "reason": "SameNamePVC",
                        "involvedObject": {
                            "kind": "PersistentVolumeClaim",
                            "name": "worker-0",
                        },
                        "lastTimestamp": "2026-07-10T01:00:00Z",
                    },
                    {
                        "type": "Warning",
                        "reason": "Unrelated",
                        "involvedObject": {"name": "other-pod"},
                        "lastTimestamp": "2026-07-10T01:00:00Z",
                    },
                ]
            }
        )

    def direct_token_should_not_be_read(_path: str) -> str:
        raise AssertionError("direct Kubernetes API fallback should not run")

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(k8s, "_read_file", direct_token_should_not_be_read)
    result = asyncio.run(
        k8s.k8s_describe(
            replace(make_settings(), kubernetes_mcp_url="http://kubernetes-mcp/mcp"),
            "pods",
            namespace="team-a",
            name="worker-0",
            time_range={"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:05:00Z"},
        )
    )

    assert calls[0] == "resources_get"
    assert "events_list" in calls or "resources_list" in calls
    assert event_selectors == ["involvedObject.name=worker-0,involvedObject.kind=Pod"]
    assert result["object"]["spec"]["containers"][0]["env"][0]["value"] == "[MASKED]"
    assert result["observed_entity"] == {
        "kind": "pod",
        "name": "worker-0",
        "namespace": "team-a",
    }
    assert [event["reason"] for event in result["events"]] == ["OOMKilled"]


class KubernetesCollector:  # name derives to "kubernetes" in the loop
    async def collect(self, target, plan=None) -> CollectorResult:
        return CollectorResult(
            agent="kubernetes", status="ok", summary="k8s ok", confidence="medium"
        )


@pytest.mark.asyncio
async def test_investigator_runs_queries_and_attaches_artifacts(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "probe",
                "probes": [{"collector": "kubernetes"}],
                "queries": [
                    {"kind": "pvc", "namespace": "team-a"},
                    # Unsupported pseudo/resource kinds are rejected before
                    # transport; they must not render a noisy failed artifact.
                    {"kind": "secrets"},
                ],
            },
            {"action": "conclude"},
        ]
    )

    async def fake_complete_json(*_a, **_k):
        return next(decisions)

    seen: list[str] = []

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        seen.append(kind)
        if k8s.resolve_read_kind(kind) is None:
            return {"kind": kind, "error": "kind is not in the read-only allowlist"}
        return {"kind": kind, "namespace": namespace, "status_code": 200, "error": None}

    monkeypatch.setattr(investigator, "complete_json", fake_complete_json)
    monkeypatch.setattr(investigator, "k8s_read", fake_k8s_read)
    settings = replace(
        make_settings(), llm_base_url="http://x", llm_model="m", llm_api_key="k"
    )
    results, _context = await investigator.investigate(
        settings, object(), [KubernetesCollector()], InvestigationPlan(), {}, max_steps=4
    )

    assert seen == ["pvc"]
    k8s_result = next(r for r in results if r.agent == "kubernetes")
    adhoc = [a for a in k8s_result.artifacts if a.type == "adhoc_query"]
    assert len(adhoc) == 1
    ok = adhoc[0]
    # The real command, alias resolved to the canonical kind, kubectl-prefixed.
    assert ok.query == "kubectl get persistentvolumeclaims -n team-a"
    assert ok.title  # human card title ("PVC 조회" / "persistentvolumeclaims lookup")


@pytest.mark.asyncio
async def test_investigator_promotes_named_pod_query_to_describe(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "probe",
                "probes": [{"collector": "kubernetes"}],
                "queries": [{"kind": "pods", "namespace": "team-a", "name": "worker-0"}],
            },
            {"action": "conclude"},
        ]
    )

    async def fake_complete_json(*_a, **_k):
        return next(decisions)

    async def fake_describe(_settings, kind, namespace="", name="", **_kwargs):
        assert (kind, namespace, name) == ("pods", "team-a", "worker-0")
        return {
            "kind": "pods",
            "namespace": namespace,
            "name": name,
            "status_code": 200,
            "error": None,
            "object": {"metadata": {"name": name}, "status": {"phase": "Failed"}},
            "events": [{"type": "Warning", "reason": "OOMKilled"}],
        }

    async def generic_read_must_not_run(*_a, **_k):
        raise AssertionError("named pod must use describe rather than compact get")

    monkeypatch.setattr(investigator, "complete_json", fake_complete_json)
    monkeypatch.setattr(investigator, "k8s_describe", fake_describe)
    monkeypatch.setattr(investigator, "k8s_read", generic_read_must_not_run)
    settings = replace(
        make_settings(), llm_base_url="http://x", llm_model="m", llm_api_key="k"
    )
    results, _context = await investigator.investigate(
        settings, object(), [KubernetesCollector()], InvestigationPlan(), {}, max_steps=4
    )

    result = next(item for item in results if item.agent == "kubernetes")
    artifact = next(item for item in result.artifacts if item.type == "adhoc_query")
    assert artifact.title == "Pod YAML + describe"
    assert artifact.query == (
        "kubectl describe pod worker-0 -n team-a; "
        "kubectl get pod worker-0 -n team-a -o yaml"
    )
    assert artifact.result["observation"]["polarity"] == "unknown"
    assert artifact.result["observation"]["coverage"] == "partial"


@pytest.mark.asyncio
async def test_named_pod_adhoc_describe_passes_incident_window(monkeypatch) -> None:
    seen_time_range = None

    async def fake_describe(_settings, kind, *, namespace="", name="", time_range=None):
        nonlocal seen_time_range
        seen_time_range = time_range
        return {"kind": kind, "namespace": namespace, "name": name, "error": None}

    monkeypatch.setattr(investigator, "k8s_describe", fake_describe)
    time_range = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    await investigator._run_adhoc_kubernetes_query(
        make_settings(),
        {"kind": "pods", "namespace": "team-a", "name": "worker-0"},
        time_range=time_range,
    )

    assert seen_time_range == time_range


def test_flowchart_followup_pending_pod_pulls_events_quota_pvc(monkeypatch) -> None:
    # Deterministic flowchart: a Pending pod must trigger follow-up reads of
    # events -> resourcequotas -> persistentvolumeclaims (independent of the LLM).
    reads: list[str] = []

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        reads.append(kind)
        data = {"items": []}
        if kind == "persistentvolumeclaims":
            data = {"items": [{"status": {"phase": "Pending"}}]}  # unbound -> chains to SC
        return {"kind": k8s.resolve_read_kind(kind), "namespace": namespace,
                "status_code": 200, "error": None, "data": data}

    monkeypatch.setattr(k8s, "k8s_read", fake_k8s_read)
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="k8s", confidence="medium",
        details={"pod_statuses": [{"name": "p", "phase": "Pending"}]},
    )
    target = replace(make_target(), namespace="team-a")
    asyncio.run(k8s.k8s_followup(make_settings(), result, target))

    assert "events" in reads and "resourcequotas" in reads
    assert "persistentvolumeclaims" in reads
    # chained: an unbound PVC pulls the storageclass provisioner next
    assert "storageclasses" in reads
    # each read is attached as a followup_query artifact
    artifact = next(a for a in result.artifacts if a.type == "followup_query")
    assert artifact.result["observation"] == {
        "kind": "kubernetes_followup_read",
        "predicate": "kubernetes:events",
        "polarity": "unknown",
        "coverage": "partial",
    }


def test_flowchart_followup_reuses_base_warning_events(monkeypatch) -> None:
    reads: list[str] = []

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        reads.append(kind)
        return {
            "kind": k8s.resolve_read_kind(kind),
            "namespace": namespace,
            "status_code": 200,
            "error": None,
            "data": {"items": []},
        }

    monkeypatch.setattr(k8s, "k8s_read", fake_k8s_read)
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="k8s",
        confidence="medium",
        details={"pod_statuses": [{"name": "p", "phase": "Pending"}]},
        artifacts=[
            artifact(
                agent="kubernetes",
                source="kubernetes",
                type="kubernetes_warning_events",
                status="ok",
                confidence="high",
                query="kubectl get events -n team-a",
                summary="warning events collected",
                result={},
            )
        ],
    )

    asyncio.run(
        k8s.k8s_followup(
            make_settings(), result, replace(make_target(), namespace="team-a"), max_rounds=1
        )
    )

    assert "events" not in reads
    assert {"resourcequotas", "persistentvolumeclaims"} <= set(reads)


def test_flowchart_followup_artifact_query_quotes_namespace(monkeypatch) -> None:
    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        return {
            "kind": k8s.resolve_read_kind(kind),
            "namespace": namespace,
            "status_code": 200,
            "error": None,
            "data": {"items": []},
        }

    monkeypatch.setattr(k8s, "k8s_read", fake_k8s_read)
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="k8s",
        confidence="medium",
        details={"pod_statuses": [{"name": "p", "phase": "Pending"}]},
    )
    target = replace(make_target(), namespace="team-a; delete pods")

    asyncio.run(k8s.k8s_followup(make_settings(), result, target, max_rounds=1))

    assert result.artifacts
    assert result.artifacts[0].query == "kubectl get events -n 'team-a; delete pods'"


def test_flowchart_followup_noop_when_healthy(monkeypatch) -> None:
    async def boom(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("no follow-up expected for a healthy Running pod")

    monkeypatch.setattr(k8s, "k8s_read", boom)
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="ok", confidence="medium",
        details={"pod_statuses": [{"name": "p", "phase": "Running"}], "container_diagnostics": []},
    )
    target = replace(make_target(), namespace="team-a")
    out = asyncio.run(k8s.k8s_followup(make_settings(), result, target))
    assert out == []
