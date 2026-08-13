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


def test_suppress_filters_only_patched_issues() -> None:
    catalog = [
        {"issue": "bug fixed in 2.23.60", "fixed_version": "2.23.60"},
        {"issue": "no fixed version", "fixed_version": ""},
        {"issue": "fixed in 2.23.14", "fixed_version": "2.23.14"},
    ]
    kept = [k["issue"] for k in _suppress_fixed_known_issues(catalog, "2.23.31")]
    # 2.23.31 >= 2.23.14 (drop) but < 2.23.60 (keep); no-fixed-version always kept
    assert kept == ["bug fixed in 2.23.60", "no fixed version"]
    # unknown running version -> nothing suppressed
    assert len(_suppress_fixed_known_issues(catalog, "")) == 3


def test_runai_version_from_results() -> None:
    results = [
        SimpleNamespace(agent="kubernetes", details={}),
        SimpleNamespace(agent="runai", details={"runai_version": "2.23.31"}),
    ]
    assert _runai_version_from(results) == "2.23.31"
    assert _runai_version_from([SimpleNamespace(agent="runai", details={})]) == ""


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
