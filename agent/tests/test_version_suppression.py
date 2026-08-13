"""Version-aware precision: known issues already fixed in the cluster's running
Run:ai version are suppressed (no false 'you have this bug')."""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

from app.collectors import runai
from app.collectors.http_json import JsonResponse
from app.collectors.runai import _extract_version
from app.services.pipeline import (
    _known_issue_fixed_in_running,
    _runai_version_from,
    _suppress_fixed_known_issues,
)


def test_extract_version_from_various_payloads() -> None:
    assert _extract_version({"version": "2.23.60"}) == "2.23.60"
    assert _extract_version({"clientVersion": "v2.22.43", "x": 1}) == "2.22.43"
    assert _extract_version({"data": {"controlPlane": {"version": "2.25.1"}}}) == "2.25.1"
    assert _extract_version("Run:ai 2.23.30") == "2.23.30"
    assert _extract_version({"foo": "bar"}) == ""
    assert _extract_version({}) == ""


def test_fixed_in_running_comparison() -> None:
    issue = {"fixed_version": "2.23.60"}
    assert _known_issue_fixed_in_running(issue, "2.23.60") is True   # exactly fixed
    assert _known_issue_fixed_in_running(issue, "2.23.61") is True   # past fixed
    assert _known_issue_fixed_in_running(issue, "2.24.0") is True    # newer minor
    assert _known_issue_fixed_in_running(issue, "2.23.30") is False  # still affected
    assert _known_issue_fixed_in_running(issue, "") is False         # unknown -> keep
    assert _known_issue_fixed_in_running({"fixed_version": ""}, "2.99.9") is False  # no fixed ver


def test_suppress_annotates_but_never_drops_patched_issues() -> None:
    # Dropping conflicts with the question path (a chat question naming an
    # already-fixed issue must still get the knowledge answer, with a version
    # caveat) -- suppression is now annotation, filtered only at the matcher.
    catalog = [
        {"issue": "bug fixed in 2.23.60", "fixed_version": "2.23.60"},
        {"issue": "no fixed version", "fixed_version": ""},
        {"issue": "fixed in 2.23.14", "fixed_version": "2.23.14"},
    ]
    annotated = _suppress_fixed_known_issues(catalog, "2.23.31")
    # every entry survives -- annotation, not a drop
    assert [k["issue"] for k in annotated] == [k["issue"] for k in catalog]
    by_issue = {k["issue"]: k for k in annotated}
    # 2.23.31 >= 2.23.14 (annotated fixed) but < 2.23.60 (not annotated)
    assert by_issue["fixed in 2.23.14"]["_fixed_in_running"] is True
    assert by_issue["fixed in 2.23.14"]["_running_version"] == "2.23.31"
    assert "_fixed_in_running" not in by_issue["bug fixed in 2.23.60"]
    assert "_fixed_in_running" not in by_issue["no fixed version"]

    # unknown running version -> nothing annotated, list is untouched
    unknown = _suppress_fixed_known_issues(catalog, "")
    assert unknown == catalog
    assert all("_fixed_in_running" not in k for k in unknown)


def test_runai_version_from_results() -> None:
    results = [
        SimpleNamespace(agent="kubernetes", details={}),
        SimpleNamespace(agent="runai", details={"runai_version": "2.23.31"}),
    ]
    assert _runai_version_from(results) == "2.23.31"
    assert _runai_version_from([SimpleNamespace(agent="runai", details={})]) == ""


def _k8s_result(*, details=None, artifact_results=()):
    return SimpleNamespace(
        agent="kubernetes",
        details=details or {},
        artifacts=[SimpleNamespace(result=r) for r in artifact_results],
    )


def test_runai_version_from_falls_back_to_the_control_plane_chart_label() -> None:
    # The runai collector's own fetch failed (empty details), but the SAME run's
    # kubernetes collector already listed the control-plane pods.
    k8s = _k8s_result(
        details={
            "runai_control_plane_pods": {
                "runai-backend": [
                    {
                        "metadata": {
                            "labels": {
                                "app.kubernetes.io/version": "2.23.71",
                                "helm.sh/chart": "control-plane-2.23.71",
                            }
                        }
                    }
                ]
            }
        }
    )
    results = [SimpleNamespace(agent="runai", details={}), k8s]
    assert _runai_version_from(results) == "2.23.71"


def test_runai_version_from_scans_artifact_payloads_too() -> None:
    # The alert's own target pod can itself be a control-plane pod (its
    # full-YAML describe artifact carries the label), with no
    # runai_control_plane_pods listing present at all.
    k8s = _k8s_result(
        artifact_results=[
            {"object": {"metadata": {"labels": {"helm.sh/chart": "control-plane-2.23.71"}}}}
        ]
    )
    assert _runai_version_from([k8s]) == "2.23.71"


def test_runai_version_from_ignores_workload_image_tags_and_bare_version_labels() -> None:
    # Only helm.sh/chart: control-plane-X.Y.Z is trusted -- a user workload can
    # carry app.kubernetes.io/version and an image tag with any value at all.
    k8s = _k8s_result(
        artifact_results=[
            {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/version": "9.9.9",
                        "helm.sh/chart": "my-training-job-1.0.0",
                    }
                },
                "spec": {"containers": [{"image": "myrepo/train:3.2.1"}]},
            }
        ]
    )
    assert _runai_version_from([k8s]) == ""


def test_runai_version_from_returns_empty_on_conflicting_chart_versions() -> None:
    # Ambiguity is not evidence -- WARNING, not a guess.
    k8s = _k8s_result(
        artifact_results=[
            {"metadata": {"labels": {"helm.sh/chart": "control-plane-2.23.71"}}},
            {"metadata": {"labels": {"helm.sh/chart": "control-plane-2.24.0"}}},
        ]
    )
    assert _runai_version_from([k8s]) == ""


def test_runai_version_from_prefers_the_runai_collector_when_it_resolved() -> None:
    k8s = _k8s_result(
        artifact_results=[
            {"metadata": {"labels": {"helm.sh/chart": "control-plane-2.20.0"}}}
        ]
    )
    results = [SimpleNamespace(agent="runai", details={"runai_version": "2.23.71"}), k8s]
    assert _runai_version_from(results) == "2.23.71"


def test_extract_version_from_minimal_clusters_response() -> None:
    assert _extract_version(
        [{"uuid": "u1", "name": "c1", "version": "2.23.60", "domain": None}]
    ) == "2.23.60"
    assert _extract_version([{"uuid": "u1", "name": "c1", "version": None}]) == ""
    # Multiple clusters resolve to the first non-empty version in response order.
    assert _extract_version(
        [
            {"uuid": "u1", "name": "c1", "version": None},
            {"uuid": "u2", "name": "c2", "version": "2.24.1"},
        ]
    ) == "2.24.1"


def test_fetch_runai_version_warns_only_on_failures(monkeypatch, caplog) -> None:
    responses = iter(
        [
            JsonResponse(url="https://runai.example/version", status_code=503, error="HTTP 503"),
            JsonResponse(url="https://runai.example/version", status_code=200, data=[]),
            JsonResponse(
                url="https://runai.example/version",
                status_code=200,
                data=[{"version": "2.24.1"}],
            ),
        ]
    )

    async def fake_get_json(**_kwargs):
        return next(responses)

    monkeypatch.setattr(runai, "get_json", fake_get_json)
    monkeypatch.setattr(runai, "mcp_tls_verify", lambda: True)
    # The Run:ai version path is fixed at /api/v1/clusters/minimal.
    settings = SimpleNamespace(
        runai_base_url="https://runai.example",
        runai_timeout_seconds=120,
    )

    with caplog.at_level(logging.WARNING, logger=runai.__name__):
        assert asyncio.run(runai._fetch_runai_version(settings, {})) == ""
        assert asyncio.run(runai._fetch_runai_version(settings, {})) == ""
        assert asyncio.run(runai._fetch_runai_version(settings, {})) == "2.24.1"

    assert [record.getMessage() for record in caplog.records] == [
        "Run:ai version request failed: path=/api/v1/clusters/minimal "
        "status=503 error=HTTP 503",
        "Run:ai version response had no parseable version: "
        "path=/api/v1/clusters/minimal",
    ]


def test_fetch_runai_version_uses_a_short_timeout_not_the_collector_budget(monkeypatch) -> None:
    # A slow best-effort version read must not eat the full collector timeout
    # budget (120s) -- it gets its own short, hardcoded ceiling.
    captured: dict = {}

    async def fake_get_json(**kwargs):
        captured.update(kwargs)
        return JsonResponse(url="https://runai.example/version", status_code=200, data=[])

    monkeypatch.setattr(runai, "get_json", fake_get_json)
    monkeypatch.setattr(runai, "mcp_tls_verify", lambda: True)
    settings = SimpleNamespace(runai_base_url="https://runai.example", runai_timeout_seconds=120)

    asyncio.run(runai._fetch_runai_version(settings, {}))

    assert captured["timeout_seconds"] == runai._RUNAI_VERSION_TIMEOUT_SECONDS
    assert captured["timeout_seconds"] != settings.runai_timeout_seconds


def test_fetch_runai_version_refreshes_once_after_auth_failure(monkeypatch) -> None:
    responses = iter(
        [
            JsonResponse(url="https://runai.example/version", status_code=403, error="HTTP 403"),
            JsonResponse(
                url="https://runai.example/version",
                status_code=200,
                data=[{"version": "2.23.71"}],
            ),
        ]
    )
    seen_headers: list[dict[str, str]] = []

    async def fake_get_json(**kwargs):
        seen_headers.append(kwargs["headers"])
        return next(responses)

    async def fake_headers(_settings, *, prefer_oauth=False):
        assert prefer_oauth is True
        return {"Authorization": "Bearer fresh"}, []

    monkeypatch.setattr(runai, "get_json", fake_get_json)
    monkeypatch.setattr(runai, "_runai_headers", fake_headers)
    monkeypatch.setattr(runai, "mcp_tls_verify", lambda: True)
    settings = SimpleNamespace(
        runai_base_url="https://runai.example",
        runai_token_url="",
        runai_client_id="cid",
        runai_client_secret="secret",
    )

    assert asyncio.run(
        runai._fetch_runai_version(settings, {"Authorization": "Bearer stale"})
    ) == "2.23.71"
    assert seen_headers == [
        {"Authorization": "Bearer stale"},
        {"Authorization": "Bearer fresh"},
    ]
