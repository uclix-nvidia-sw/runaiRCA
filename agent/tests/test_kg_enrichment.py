from __future__ import annotations

import asyncio

from app.collectors.base import AnalysisTarget
from app.config import load_settings
from app.services.kg_enrichment import KGContext, enrich
from app.services.pipeline import _knowledge_base_lines
from app.services.root_cause_ranking import RankedCause


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="", queue="", namespace="", workload_name="",
        workload_type="", runai_workload_id="", node="gpu-1", pod="",
        severity="critical", alert_name="KubeNodeDiskPressure",
    )


def test_enrich_disabled_returns_empty_context() -> None:
    # load_settings() defaults ENABLE_TYPEDB off -> no query, empty context.
    ctx = asyncio.run(enrich(load_settings(), _target()))
    assert ctx.enabled is False
    assert ctx.available is False
    assert ctx.blast_radius_workloads == 0
    assert ctx.prior_incidents == []


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


def test_kb_says_no_match_when_no_symptom_keyword_matches() -> None:
    # Report fix #5: when no symptom keyword matches the observed evidence, do NOT
    # dump a generic family checklist as if it were a real match — say so plainly.
    kg = KGContext(enabled=True, available=True, knowledge=_KNOWLEDGE).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="medium", score=3.0)]
    text = "\n".join(_knowledge_base_lines(kg, candidates, "some unrelated evidence text"))
    assert "No closely-matching prior knowledge" in text
    assert "Cordon or drain the node" not in text
