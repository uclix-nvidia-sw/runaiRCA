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
from app.collectors.base import CollectorResult
from app.collectors.http_json import JsonResponse
from app.plan import InvestigationPlan
from app.services import investigator
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
        "/api/v1/namespaces/runai%2F..%2F..%2Fapi/events",
        "/api/v1/namespaces/runai%2F..%2F..%2Fapi/pods",
    ]


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


def test_k8s_describe_uses_mcp_full_pod_and_filters_its_events(monkeypatch) -> None:
    calls: list[str] = []

    class Result:
        isError = False
        content: list = []

        def __init__(self, value: dict) -> None:
            self.structuredContent = value

    async def fake_mcp_call(_url, tool, _arguments):
        calls.append(tool)
        if tool in {"pods_get", "resources_get"}:
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
    assert result["object"]["spec"]["containers"][0]["env"][0]["value"] == "[MASKED]"
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
        "kubectl get pod worker-0 -n team-a -o yaml; "
        "kubectl describe pod worker-0 -n team-a"
    )


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
