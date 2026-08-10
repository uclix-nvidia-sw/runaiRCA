"""The three catalog drill-down tools (case_lookup, xid_lookup, component_checks):
reachable by every agent, mirror knowledge_lookup's contract, never evidence."""

from __future__ import annotations

import asyncio

import app.services.kg_enrichment as kg_enrichment
from app.collectors.base import AnalysisTarget, CollectorResult
from app.services import drilldown
from tests.test_orchestrator import make_settings


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="trainer-0",
        severity="warning",
        alert_name="KubePodCrashLooping",
    )


class _NullMasker:
    def mask_object(self, value):
        return value

    def mask_text(self, value):
        return value


# --- registry -----------------------------------------------------------


def test_every_domain_agent_can_reach_all_four_knowledge_tools() -> None:
    registry = drilldown._domain_tools(make_settings())
    assert registry, "expected at least one domain registry"
    for agent, tools in registry.items():
        for name in ("knowledge_lookup", "case_lookup", "xid_lookup", "component_checks"):
            assert name in tools, f"{agent} cannot consult {name}"


# --- xid_lookup -----------------------------------------------------------


def test_xid_lookup_happy_path() -> None:
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 79}))
    assert out["result"]["code"] == 79
    assert out["result"]["severity"] == "fatal"
    assert "fallen off the bus" in out["result"]["description"].lower()
    assert out["summary"]


def test_xid_lookup_accepts_numeric_string() -> None:
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": "79"}))
    assert out["result"]["code"] == 79


def test_xid_lookup_rejects_invalid_or_missing_args() -> None:
    settings, target = make_settings(), _target()
    assert "error" in asyncio.run(drilldown._tool_xid_lookup(settings, target, {}))
    bad_xid = {"xid": "not-a-number"}
    assert "error" in asyncio.run(drilldown._tool_xid_lookup(settings, target, bad_xid))
    assert "error" in asyncio.run(drilldown._tool_xid_lookup(settings, target, {"xid": 0}))
    assert "error" in asyncio.run(drilldown._tool_xid_lookup(settings, target, {"xid": 5000}))


def test_xid_lookup_unknown_code() -> None:
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 999}))
    assert out == {"summary": "XID 999 is not in the catalog", "result": {}}


def test_xid_escalation_roots_reverse_walk(tmp_path, monkeypatch) -> None:
    catalog = tmp_path / "xids.yaml"
    catalog.write_text(
        "xids:\n"
        "  - {code: 144, mnemonic: NVLINK, description: d, severity: non-fatal,"
        " gpu_models: [], immediate_action: '', investigatory_action: '', leads_to: [48]}\n"
        "  - {code: 48, mnemonic: DBE, description: d, severity: fatal,"
        " gpu_models: [], immediate_action: '', investigatory_action: '', leads_to: [154]}\n"
        "  - {code: 154, mnemonic: RECOVERY, description: d, severity: fatal,"
        " gpu_models: [], immediate_action: '', investigatory_action: ''}\n"
    )
    monkeypatch.setenv("XID_CATALOG_FILE", str(catalog))
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 154}))
    assert {r["code"] for r in out["result"]["escalation_roots"]} == {48, 144}
    assert out["result"]["escalates_to"] == []

    out48 = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 48}))
    assert out48["result"]["escalates_to"] == [{"code": 154, "mnemonic": "RECOVERY"}]
    assert {r["code"] for r in out48["result"]["escalation_roots"]} == {144}


def test_xid_escalation_roots_cycle_does_not_hang(tmp_path, monkeypatch) -> None:
    catalog = tmp_path / "xids.yaml"
    catalog.write_text(
        "xids:\n"
        "  - {code: 1, mnemonic: A, description: d, severity: non-fatal,"
        " gpu_models: [], immediate_action: '', investigatory_action: '', leads_to: [2]}\n"
        "  - {code: 2, mnemonic: B, description: d, severity: non-fatal,"
        " gpu_models: [], immediate_action: '', investigatory_action: '', leads_to: [1]}\n"
    )
    monkeypatch.setenv("XID_CATALOG_FILE", str(catalog))
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 1}))
    assert {r["code"] for r in out["result"]["escalation_roots"]} == {2}


# --- component_checks -----------------------------------------------------


def test_component_checks_happy_path() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(make_settings(), _target(), {"component": "runai-agent"})
    )
    result = out["result"]
    assert result["component"] == "runai-agent"
    assert result["dependencies"], "runai-agent has curated dependencies"
    assert set(result["dependencies"][0]) == {"name", "failure_effect", "checks"}


def test_component_checks_case_insensitive_match() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(make_settings(), _target(), {"component": "RUNAI-AGENT"})
    )
    assert out["result"]["component"] == "runai-agent"


def test_component_checks_resolves_pod_name_to_component() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(
            make_settings(), _target(), {"component": "runai-agent-6f7d9-xk2lp"}
        )
    )
    assert out["result"]["component"] == "runai-agent"


def test_component_checks_requires_component() -> None:
    out = asyncio.run(drilldown._tool_component_checks(make_settings(), _target(), {}))
    assert out == {"error": "component is required"}


def test_component_checks_unknown_component() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(
            make_settings(), _target(), {"component": "totally-bogus-xyz"}
        )
    )
    assert out["summary"] == "unknown component totally-bogus-xyz"
    assert 0 < len(out["result"]["known_components"]) <= 10


def test_component_checks_unknown_component_substring_match() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(make_settings(), _target(), {"component": "runai-agen"})
    )
    assert "runai-agent" in out["result"]["known_components"]


# --- case_lookup -----------------------------------------------------------


def test_case_lookup_requires_text() -> None:
    out = asyncio.run(drilldown._tool_case_lookup(make_settings(), _target(), {}))
    assert out == {"error": "text is required — pass verbatim error/log lines you observed"}


def test_case_lookup_no_match(monkeypatch) -> None:
    async def empty_cards(settings, text, *, limit=2):
        return [], []

    async def empty_hints(settings, text, *, limit=2):
        return []

    monkeypatch.setattr(kg_enrichment, "external_case_cards", empty_cards)
    monkeypatch.setattr(kg_enrichment, "external_case_hints", empty_hints)
    out = asyncio.run(drilldown._tool_case_lookup(make_settings(), _target(), {"text": "anything"}))
    assert out == {
        "summary": "no external support case matches that text",
        "result": {"cases": [], "investigation_leads": []},
    }


def test_case_lookup_happy_path(monkeypatch) -> None:
    async def fake_cards(settings, text, *, limit=2):
        return (
            [
                {
                    "case_id": "enterprise_support:case-1",
                    "family": "gpu_hardware_error",
                    "mechanism": "ECC double-bit fault on a data-center GPU",
                    "context_class": "external",
                    "matched_error_signatures": ["xid 48"],
                    "successful_actions": ["reseat the GPU"],
                    "failed_actions": ["driver reinstall"],
                    "analysis_summary": "x" * 500,
                    # not in the allowlist -- must not leak through
                    "quality_score": 90,
                }
            ],
            ["some transport warning"],
        )

    expected_hints = [
        {
            "case_id": "enterprise_support:case-1",
            "normalized_action": "Collect nvidia-smi -q",
            "canonical_component_tokens": ["gpu"],
        }
    ]

    async def fake_hints(settings, text, *, limit=2):
        return expected_hints

    monkeypatch.setattr(kg_enrichment, "external_case_cards", fake_cards)
    monkeypatch.setattr(kg_enrichment, "external_case_hints", fake_hints)
    out = asyncio.run(
        drilldown._tool_case_lookup(make_settings(), _target(), {"text": "Xid 48 ECC error"})
    )
    cases = out["result"]["cases"]
    assert len(cases) == 1
    case = cases[0]
    assert case["case_id"] == "enterprise_support:case-1"
    assert case["successful_actions"] == ["reseat the GPU"]
    assert case["failed_actions"] == ["driver reinstall"]
    assert len(case["analysis_summary"]) == 400
    assert "quality_score" not in case
    assert out["result"]["investigation_leads"] == expected_hints
    assert "historical reference" in out["summary"]


def test_case_lookup_error_text_alias_and_typedb_off_by_default() -> None:
    # No monkeypatch: make_settings() ships enable_typedb=False, so this exercises
    # the real kg_enrichment short-circuit (no network) end to end.
    out = asyncio.run(
        drilldown._tool_case_lookup(make_settings(), _target(), {"error_text": "boom"})
    )
    assert out["result"] == {"cases": [], "investigation_leads": []}


# --- artifact suppression (the #1 invariant of this file) ------------------


def _drive_run_query(tool_name: str, call, args: dict) -> tuple[CollectorResult, list[dict]]:
    result = CollectorResult(agent="kubernetes", status="ok", summary="")
    tools = {tool_name: {"description": "d", "call": call}}
    history: list[dict] = []
    asyncio.run(
        drilldown._run_query(
            make_settings(),
            result,
            tools,
            _target(),
            None,
            {"tool": tool_name, "args": args},
            history,
            _NullMasker(),
        )
    )
    return result, history


def test_xid_lookup_answer_never_becomes_evidence() -> None:
    result, history = _drive_run_query("xid_lookup", drilldown._tool_xid_lookup, {"xid": 79})
    assert result.artifacts == [], "xid_lookup answers must not be stored as artifacts"
    assert len(history) == 1
    lookups = result.details.get("knowledge_lookups")
    assert lookups == [{"tool": "xid_lookup", "query": "79", "summary": lookups[0]["summary"]}]
    assert lookups[0]["summary"]


def test_component_checks_answer_never_becomes_evidence() -> None:
    result, history = _drive_run_query(
        "component_checks", drilldown._tool_component_checks, {"component": "runai-agent"}
    )
    assert result.artifacts == [], "component_checks answers must not be stored as artifacts"
    assert len(history) == 1
    lookups = result.details.get("knowledge_lookups")
    assert lookups and lookups[0]["tool"] == "component_checks"
    assert lookups[0]["query"] == "runai-agent"


def test_case_lookup_answer_never_becomes_evidence() -> None:
    # TypeDB off by default (make_settings()) -- exercises the real no-match
    # path, no monkeypatch needed to prove the suppression mechanism.
    result, history = _drive_run_query(
        "case_lookup", drilldown._tool_case_lookup, {"text": "Xid 48 ECC error"}
    )
    assert result.artifacts == [], "case_lookup answers must not be stored as artifacts"
    assert len(history) == 1
    lookups = result.details.get("knowledge_lookups")
    assert lookups and lookups[0]["tool"] == "case_lookup"
    assert lookups[0]["query"] == "Xid 48 ECC error"
