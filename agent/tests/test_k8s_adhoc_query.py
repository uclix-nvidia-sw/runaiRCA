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
    # cluster-scoped kind ignores the namespace segment
    asyncio.run(k8s.k8s_read(settings, "storageclass"))
    assert calls[-1]["path"] == "/apis/storage.k8s.io/v1/storageclasses"


def test_k8s_read_refuses_unlisted_kind_without_calling_api(monkeypatch) -> None:
    async def boom(**kwargs):  # pragma: no cover - must not be called
        raise AssertionError("API must not be called for a refused kind")

    monkeypatch.setattr(k8s, "get_json", boom)
    out = asyncio.run(k8s.k8s_read(make_settings(), "secrets", namespace="runai"))
    assert "allowlist" in out["error"]


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
                    {"kind": "secrets"},  # refused by k8s_read, still an observation
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
    results = await investigator.investigate(
        settings, object(), [KubernetesCollector()], InvestigationPlan(), {}, max_steps=4
    )

    assert seen == ["pvc", "secrets"]
    k8s_result = next(r for r in results if r.agent == "kubernetes")
    adhoc = [a for a in k8s_result.artifacts if a.type == "adhoc_query"]
    assert len(adhoc) == 2
    ok = next(a for a in adhoc if a.status == "ok")
    assert "pvc" in (ok.query or "")
    refused = next(a for a in adhoc if a.status == "unavailable")
    assert "allowlist" in refused.summary


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
    assert any(a.type == "followup_query" for a in result.artifacts)


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
