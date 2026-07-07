"""Version-aware precision: known issues already fixed in the cluster's running
Run:ai version are suppressed (no false 'you have this bug')."""

from __future__ import annotations

from types import SimpleNamespace

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
