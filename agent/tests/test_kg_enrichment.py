from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace

from app.collectors.base import AnalysisTarget
from app.config import load_settings
from app.services.kg_enrichment import KGContext, _query_kg, _query_remediation, enrich
from app.services.pipeline import _knowledge_base_lines
from app.services.root_cause_ranking import RankedCause


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="", queue="", namespace="", workload_name="",
        workload_type="", runai_workload_id="", node="gpu-1", pod="",
        severity="critical", alert_name="KubeNodeDiskPressure",
    )


def test_root_chain_walks_leads_to_transitively() -> None:
    """Observing XID 154 must surface the true origin 144 (chain 144 -> 48 -> 154),
    not just the one-hop intermediate 48."""
    import re

    # reverse leads_to graph: effect -> [immediate causes]
    causes = {154: [48], 48: [144], 144: []}

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                m = re.search(r"root_xids_for\((\d+)\)", query)
                if m:
                    code = int(m.group(1))
                    return [{"x": c} for c in causes.get(code, [])]
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [154], "")  # type: ignore[arg-type]
    # Transitive ancestors, nearest hop first.
    assert out.root_xids[154] == [48, 144]
    # Fixes fetched for each discovered root too.
    assert 48 in out.xid_fixes and 144 in out.xid_fixes


def test_root_chain_is_cycle_safe() -> None:
    import re

    # pathological cycle 45 -> 74 -> 45; must terminate and not repeat.
    causes = {45: [74], 74: [45]}

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                m = re.search(r"root_xids_for\((\d+)\)", query)
                if m:
                    return [{"x": c} for c in causes.get(int(m.group(1)), [])]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [45], "")  # type: ignore[arg-type]
    assert out.root_xids[45] == [74]  # 45 itself excluded, no infinite loop


def test_root_chain_hop_failure_is_isolated() -> None:
    import re

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                if re.search(r"root_xids_for\(\d+\)", query):
                    raise RuntimeError("leads_to function missing on this TypeDB build")
                return []

            yield run

    # A broken root walk must not wipe the observed XID's own fixes.
    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]
    assert out.xid_fixes[79] == ["reset the GPU"]
    assert 79 not in out.root_xids


def test_enrich_disabled_returns_empty_context() -> None:
    # load_settings() defaults ENABLE_TYPEDB off -> no query, empty context.
    ctx = asyncio.run(enrich(load_settings(), _target()))
    assert ctx.enabled is False
    assert ctx.available is False
    assert ctx.blast_radius_workloads == 0
    assert ctx.prior_incidents == []


def test_query_kg_escapes_typeql_literals() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return []

            yield run

    client = FakeClient()
    target = replace(
        _target(),
        node='gpu-1"; $x isa incident; #\\',
        alert_name='KubeNodeDiskPressure"; delete $x;\\',
    )

    _query_kg(client, target)  # type: ignore[arg-type]

    joined = "\n".join(client.queries)
    assert 'gpu-1\\"; $x isa incident; #\\\\' in joined
    assert 'KubeNodeDiskPressure\\"; delete $x;\\\\' in joined
    assert 'has name "gpu-1"; $x isa incident' not in joined
    assert 'has alert_name "KubeNodeDiskPressure"; delete' not in joined


def test_graph_remediation_escapes_typeql_literals() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return []

            yield run

    client = FakeClient()
    _query_remediation(
        client,  # type: ignore[arg-type]
        'gpu_hardware_error"; delete $x;\\',
        [79],
        'A100"; match $x isa incident;\\',
    )

    joined = "\n".join(client.queries)
    assert 'gpu_hardware_error\\"; delete $x;\\\\' in joined
    assert 'A100\\"; match $x isa incident;\\\\' in joined
    assert 'fixes_for_family("gpu_hardware_error"; delete' not in joined
    assert 'xids_for_gpu_model("A100"; match' not in joined


def test_knowledge_base_section_renders_when_available() -> None:
    kg = KGContext(
        enabled=True,
        available=True,
        blast_radius_workloads=3,
        prior_incidents=[{"incident_id": "inc-1", "analysis_summary": "node disk pressure"}],
    ).as_dict()
    text = "\n".join(_knowledge_base_lines(kg))
    assert "## Knowledge Base (Ontology)" in text
    assert "Blast radius: 3" in text
    assert "inc-1" in text


def test_knowledge_base_prior_summary_is_single_trimmed_line() -> None:
    summary = (
        "root cause line api_key=kg-prior-secret-12345\n## injected heading\n"
        + ("detail " * 100)
    )
    kg = KGContext(
        enabled=True,
        available=True,
        prior_incidents=[
            {"incident_id": "inc-long\n## injected id", "analysis_summary": summary}
        ],
    ).as_dict()

    line = next(line for line in _knowledge_base_lines(kg) if "inc-long" in line)
    assert "\n" not in line
    assert "kg-prior-secret-12345" not in line
    assert "[MASKED]" in line
    assert len(line) < 380
    assert line.endswith("…")


def test_knowledge_base_section_empty_when_disabled() -> None:
    assert _knowledge_base_lines({"enabled": False}) == []
    assert _knowledge_base_lines(None) == []


def test_knowledge_base_section_omitted_when_unavailable() -> None:
    # Optional enrichment: when enabled but unreachable, no operator-facing section
    # is rendered (the reason is carried in the response warnings instead).
    assert _knowledge_base_lines({"enabled": True, "available": False}) == []


_KNOWLEDGE = {
    "node_kubelet_pressure": [
        {
            "symptom": "Node Disk Pressure",
            "keywords": ["diskpressure", "evicted"],
            "actions": ["Cordon or drain the node", "Inspect kubelet disk usage"],
        },
        {
            "symptom": "Node Memory Pressure",
            "keywords": ["memorypressure"],
            "actions": ["Find the memory hog on the node"],
        },
    ]
}


def test_kb_matches_symptom_keyword_for_precise_fix() -> None:
    kg = KGContext(enabled=True, available=True, knowledge=_KNOWLEDGE).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="high", score=7.0)]
    text = "\n".join(
        _knowledge_base_lines(kg, candidates, "node condition DiskPressure=True; pods evicted")
    )
    assert "Matched symptom **Node Disk Pressure**" in text
    assert "Cordon or drain the node" in text
    assert "memory hog" not in text  # the non-matching symptom's action is not shown


def test_kb_actions_are_single_masked_lines() -> None:
    kg = KGContext(
        enabled=True,
        available=True,
        knowledge={
            "node_kubelet_pressure": [
                {
                    "symptom": "Node Disk Pressure\n## injected symptom",
                    "keywords": ["diskpressure"],
                    "actions": [
                        "Cordon the node api_key=kg-action-secret-12345\n## injected action"
                    ],
                }
            ]
        },
    ).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="high", score=7.0)]

    lines = _knowledge_base_lines(kg, candidates, "node condition DiskPressure=True")
    text = "\n".join(lines)

    assert "kg-action-secret-12345" not in text
    assert "[MASKED]" in text
    assert "\n## injected" not in text
    assert any("## injected" in line for line in lines)


def test_kb_says_no_match_when_no_symptom_keyword_matches() -> None:
    # Report fix #5: when no symptom keyword matches the observed evidence, do NOT
    # dump a generic family checklist as if it were a real match — say so plainly.
    kg = KGContext(enabled=True, available=True, knowledge=_KNOWLEDGE).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="medium", score=3.0)]
    text = "\n".join(_knowledge_base_lines(kg, candidates, "some unrelated evidence text"))
    assert "No closely-matching prior knowledge" in text
    assert "Cordon or drain the node" not in text
