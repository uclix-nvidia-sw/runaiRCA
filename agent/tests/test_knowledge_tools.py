"""The three catalog drill-down tools (case_lookup, xid_lookup, component_checks):
reachable by every agent, mirror knowledge_lookup's contract, never evidence."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace

import app.ontology.typedb_client as typedb_client_module
import app.services.kg_enrichment as kg_enrichment
from app.collectors.base import AnalysisTarget, CollectorResult
from app.ontology.typedb_client import escape_typeql
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


# --- ontology-mode test scaffolding (offline; never touches real TypeDB) ---


def _typedb_settings():
    """TypeDB "on" — paired with a monkeypatched TypeDBClient, never a real socket."""
    return replace(make_settings(), enable_typedb=True, typedb_address="fake:1729")


class _DirectClient:
    """Drop-in TypeDBClient double: wraps a canned `run(query) -> rows` callable.

    Passed directly as the `client` arg to the `_*_via_graph` helpers — the
    same dependency-injection style test_kg_enrichment.py's FakeClient uses
    for `_query_remediation`/`_query_kg`, so no monkeypatching is needed to
    exercise the query-building logic in isolation.
    """

    def __init__(self, run):
        self._run = run

    @contextmanager
    def open_reader(self):
        yield self._run


def _typedb_client_factory(run):
    """A `TypeDBClient(settings)`-shaped constructor, for monkeypatching the
    class itself so a full `_tool_*` call (gate + thread + timeout) is
    exercised end to end."""

    def _construct(settings):
        return _DirectClient(run)

    return _construct


# --- registry -----------------------------------------------------------


def test_every_domain_agent_can_reach_all_four_knowledge_tools() -> None:
    registry = drilldown._domain_tools(make_settings())
    assert registry, "expected at least one domain registry"
    for agent, tools in registry.items():
        for name in ("knowledge_lookup", "case_lookup", "xid_lookup", "component_checks"):
            assert name in tools, f"{agent} cannot consult {name}"


# --- knowledge_lookup -------------------------------------------------------


def test_knowledge_lookup_fallback_source_tag() -> None:
    # TypeDB off (make_settings default): must hit the catalog fallback.
    out = asyncio.run(
        drilldown._tool_knowledge_lookup(make_settings(), _target(), {"hypothesis": "OOMKilled"})
    )
    assert out["source"] == "catalog_fallback"
    assert out["result"]["symptoms"]


def test_knowledge_lookup_graph_mode_surfaces_external_case(monkeypatch) -> None:
    """Proves external cases (symptom name `ext:...`) are now reachable
    through knowledge_lookup, unified with curated/known-issue symptoms."""

    def fake_run(query: str) -> list[dict]:
        if query == kg_enrichment._KNOWLEDGE_QUERY:
            return [
                {
                    "fam": "gpu_hardware_error",
                    "sn": "ext:vendor-case-1",
                    "kw": "ecc double bit",
                    "st": "reseat the gpu",
                },
                {
                    "fam": "workload_runtime_error",
                    "sn": "OOMKilled",
                    "kw": "oomkilled",
                    "st": "raise the memory limit",
                },
            ]
        if query in (
            kg_enrichment._KNOWLEDGE_ACTIONLESS_QUERY,
            kg_enrichment._KNOWLEDGE_AFFECTED_VERSION_QUERY,
            kg_enrichment._KNOWLEDGE_FIXED_VERSION_QUERY,
        ):
            return []
        if query == kg_enrichment._KNOWLEDGE_REASON_QUERY:
            return [{"sn": "OOMKilled", "reason": "container exceeded its memory limit"}]
        return []

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(fake_run))
    out = asyncio.run(
        drilldown._tool_knowledge_lookup(
            _typedb_settings(),
            _target(),
            {"hypothesis": "pod OOMKilled with ecc double bit error"},
        )
    )
    assert out["source"] == "ontology"
    sources = {s["symptom"]: s["source"] for s in out["result"]["symptoms"]}
    assert sources == {"ext:vendor-case-1": "external_case", "OOMKilled": "ontology"}
    assert out["result"]["known_issues"] == []


# --- xid_lookup -----------------------------------------------------------


def test_xid_lookup_happy_path() -> None:
    out = asyncio.run(drilldown._tool_xid_lookup(make_settings(), _target(), {"xid": 79}))
    assert out["source"] == "catalog_fallback"
    assert out["result"]["code"] == 79
    assert out["result"]["severity"] == "fatal"
    assert "fallen off the bus" in out["result"]["description"].lower()
    # `fixes` is the stable key across both modes, composed here from the
    # YAML immediate/investigatory split (both of which remain present too).
    assert out["result"]["fixes"]
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
    assert out == {
        "source": "catalog_fallback",
        "summary": "XID 999 is not in the catalog",
        "result": {},
    }


def test_xid_lookup_graph_mode_reads_ontology(monkeypatch) -> None:
    def fake_run(query: str) -> list[dict]:
        if "detail_for_xid(79)" in query:
            return [{"m": "Xid", "d": "GPU has fallen off the bus", "s": "fatal"}]
        if "fixes_for_xid(79)" in query:
            return [{"x": "Reset the GPU."}]
        if "trigger_for_xid(79)" in query:
            return [{"x": "seen after an ECC failure"}]
        if "applies_to" in query:
            return [{"n": "H100"}]
        return []

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(fake_run))
    out = asyncio.run(drilldown._tool_xid_lookup(_typedb_settings(), _target(), {"xid": 79}))
    assert out["source"] == "ontology"
    result = out["result"]
    assert result["code"] == 79
    assert result["severity"] == "fatal"
    assert result["fixes"] == ["Reset the GPU."]
    assert result["gpu_models"] == ["H100"]
    assert result["escalates_to"] == []
    assert result["escalation_roots"] == []
    # Graph mode has no immediate/investigatory split; `fixes` is the only key.
    assert "immediate_action" not in result
    assert "investigatory_action" not in result


def test_xid_lookup_graph_mode_not_in_catalog(monkeypatch) -> None:
    monkeypatch.setattr(
        typedb_client_module, "TypeDBClient", _typedb_client_factory(lambda query: [])
    )
    out = asyncio.run(drilldown._tool_xid_lookup(_typedb_settings(), _target(), {"xid": 999}))
    assert out == {"source": "ontology", "summary": "XID 999 is not in the catalog", "result": {}}


def test_xid_lookup_graph_failure_falls_back_to_catalog(monkeypatch, caplog) -> None:
    def boom(query: str) -> list[dict]:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(boom))
    with caplog.at_level("WARNING"):
        out = asyncio.run(drilldown._tool_xid_lookup(_typedb_settings(), _target(), {"xid": 79}))
    assert out["source"] == "catalog_fallback"
    assert out["result"]["code"] == 79
    assert "xid_lookup ontology query failed" in caplog.text


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


def test_component_checks_fallback_source_tag() -> None:
    out = asyncio.run(
        drilldown._tool_component_checks(make_settings(), _target(), {"component": "runai-agent"})
    )
    assert out["source"] == "catalog_fallback"


def test_component_checks_graph_mode_reads_ontology(monkeypatch) -> None:
    from app.knowledge import load_architecture

    expected_kind = load_architecture("knowledge/runai_architecture.yaml")["runai-agent"]["kind"]

    def fake_run(query: str) -> list[dict]:
        if 'has name "runai-agent"' not in query:
            return []
        if "has description $v" in query:
            return [{"v": "graph purpose"}]
        if "has failure_effect $v" in query:
            return [{"v": "graph failure effect"}]
        if "has k8s_namespace $v" in query:
            return [{"v": "graph-namespace"}]
        if "has check_command $k" in query:
            return [{"k": "graph check"}]
        if "isa depends_on" in query:
            return []
        return []

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(fake_run))
    out = asyncio.run(
        drilldown._tool_component_checks(
            _typedb_settings(), _target(), {"component": "runai-agent"}
        )
    )
    assert out["source"] == "ontology"
    result = out["result"]
    assert result == {
        "component": "runai-agent",
        "namespace": "graph-namespace",
        "kind": expected_kind,
        "purpose": "graph purpose",
        "failure_effect": "graph failure effect",
        "checks": ["graph check"],
        "depends_on": [],
        "dependencies": [],
    }


def test_component_checks_graph_failure_falls_back_to_catalog(monkeypatch, caplog) -> None:
    def boom(query: str) -> list[dict]:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(boom))
    with caplog.at_level("WARNING"):
        out = asyncio.run(
            drilldown._tool_component_checks(
                _typedb_settings(), _target(), {"component": "runai-agent"}
            )
        )
    assert out["source"] == "catalog_fallback"
    assert out["result"]["component"] == "runai-agent"
    assert "component_checks ontology query failed" in caplog.text


def test_component_checks_unknown_component_never_touches_the_graph(monkeypatch) -> None:
    """Resolution failure stays local-map-based even when TypeDB is enabled —
    there is no canonical name to send to the graph."""

    def explode(query: str) -> list[dict]:
        raise AssertionError("the graph must not be queried for an unresolved component")

    monkeypatch.setattr(typedb_client_module, "TypeDBClient", _typedb_client_factory(explode))
    out = asyncio.run(
        drilldown._tool_component_checks(
            _typedb_settings(), _target(), {"component": "totally-bogus-xyz"}
        )
    )
    assert out["summary"] == "unknown component totally-bogus-xyz"
    # Neither knowledge source was consulted, and the envelope stays
    # source-labelled in every non-error shape.
    assert out["source"] == "unresolved"


def test_component_checks_graph_query_escapes_component_name() -> None:
    """Injection guard: a component name containing a double quote must reach
    TypeQL only through escape_typeql, never interpolated raw."""
    malicious = 'runai-agent" ; insert $x isa node;'
    captured: list[str] = []

    def fake_run(query: str) -> list[dict]:
        captured.append(query)
        return []

    drilldown._component_checks_via_graph(_DirectClient(fake_run), malicious, "")
    joined = "\n".join(captured)
    assert captured, "the graph helper must have issued at least one query"
    assert f'has name "{escape_typeql(malicious)}"' in joined
    assert f'has name "{malicious}"' not in joined


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
