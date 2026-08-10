"""The drill-down knowledge tool: reachable by every agent, never evidence."""

import asyncio
import json

from app.collectors.base import AnalysisTarget, CollectorResult
from app.config import load_settings
from app.services import drilldown


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


def test_every_domain_agent_can_reach_the_knowledge_tool():
    registry = drilldown._domain_tools(load_settings())
    assert registry, "expected at least one domain registry"
    for agent, tools in registry.items():
        assert drilldown._KNOWLEDGE_TOOL in tools, f"{agent} cannot consult knowledge"


def test_lookup_returns_curated_knowledge_with_its_source():
    out = asyncio.run(
        drilldown._tool_knowledge_lookup(load_settings(), _target(), {"hypothesis": "OOMKilled"})
    )
    symptoms = out["result"]["symptoms"]
    assert symptoms, "OOMKilled must match curated catalog knowledge"
    assert {s["source"] for s in symptoms} <= {"curated", "learned", "novel"}
    assert all("family" in s for s in symptoms)


def test_lookup_reaches_approved_novel_knowledge():
    """Matcher-only knowledge is exactly what the plan-time catalog cannot carry."""
    from app.knowledge import (
        KnowledgeRegistry,
        _validate_approved_snapshot,
        set_runtime_knowledge_registry,
    )

    registry = KnowledgeRegistry(mode="assist")
    registry._snapshot = _validate_approved_snapshot(
        {
            "revision": "rev-lookup",
            "packages": [
                {
                    "package_id": "KPKG-novel",
                    "state": "active",
                    "compiled": {
                        "failure_modes": [
                            {
                                "family": "novel_fabric_flap_ab12cd34",
                                "symptoms": [
                                    {
                                        "name": "fabric link flaps under sustained load",
                                        "keywords": ["nvlink flap"],
                                        "actions": ["reseat the affected link"],
                                    }
                                ],
                            }
                        ]
                    },
                }
            ],
        }
    )
    set_runtime_knowledge_registry(registry)
    try:
        out = asyncio.run(
            drilldown._tool_knowledge_lookup(
                load_settings(), _target(), {"hypothesis": "saw an nvlink flap on the node"}
            )
        )
    finally:
        set_runtime_knowledge_registry(None)
    novel = [s for s in out["result"]["symptoms"] if s["source"] == "novel"]
    assert novel, f"approved novel knowledge must be reachable, got {out}"
    assert novel[0]["matcher_only"] is True
    assert novel[0]["actions"] == ["reseat the affected link"]


def test_lookup_answer_never_becomes_evidence():
    """Its wording must not reach _observed_text, or the matcher re-reads our own catalog."""
    result = CollectorResult(agent="kubernetes", status="ok", summary="")
    tools = {
        drilldown._KNOWLEDGE_TOOL: {
            "description": "d",
            "call": drilldown._tool_knowledge_lookup,
        }
    }
    history: list[dict] = []

    class _NullMasker:
        def mask_object(self, value):
            return value

        def mask_text(self, value):
            return value

    asyncio.run(
        drilldown._run_query(
            load_settings(),
            result,
            tools,
            _target(),
            None,
            {"tool": drilldown._KNOWLEDGE_TOOL, "args": {"hypothesis": "OOMKilled"}},
            history,
            _NullMasker(),
        )
    )
    assert result.artifacts == [], "knowledge answers must not be stored as artifacts"
    assert history and "OOMKilled" in json.dumps(history), "the agent must still see the answer"
    assert result.details.get("knowledge_lookups"), "the run must keep a receipt of the lookup"
