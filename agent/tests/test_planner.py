from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget
from app.schemas import SimilarIncidentContext
from app.services.planner import plan_investigation
from tests.test_orchestrator import make_settings


def _target(**overrides) -> AnalysisTarget:
    base = dict(
        cluster="",
        project="",
        queue="",
        namespace="",
        workload_name="",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="",
        severity="warning",
        alert_name="RunAIAlert",
    )
    base.update(overrides)
    return AnalysisTarget(**base)


@pytest.mark.asyncio
async def test_control_plane_alert_sets_check_control_plane() -> None:
    settings = make_settings()
    target = _target(alert_name="RunAISchedulerReconcileError", namespace="team-a")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.check_control_plane is True
    for ns in settings.runai_log_namespaces:
        assert ns in plan.namespaces


@pytest.mark.asyncio
async def test_runai_namespace_implicates_control_plane() -> None:
    settings = make_settings()
    target = _target(alert_name="SomeAlert", namespace="runai-backend")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.check_control_plane is True


@pytest.mark.asyncio
async def test_gpu_node_alert_non_runai_ns_no_match_is_breadth_first() -> None:
    settings = make_settings()
    target = _target(
        alert_name="NodeDiskPressure",
        namespace="monitoring",
        node="gpu-node-3",
    )
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.check_control_plane is False
    assert plan.strategy == "breadth_first"
    assert plan.narrative  # must describe HOW to approach
    # control plane namespaces must NOT be swept
    assert "runai" not in " ".join(plan.namespaces)


@pytest.mark.asyncio
async def test_similarity_below_floor_is_excluded() -> None:
    settings = make_settings()
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    similar = [SimilarIncidentContext(incident_id="INC-1", similarity=0.70)]
    plan = await plan_investigation(settings, target, None, {}, similar)

    assert plan.used_similarity is False
    assert plan.strategy == "breadth_first"


@pytest.mark.asyncio
async def test_similarity_at_or_above_floor_is_targeted() -> None:
    settings = make_settings()
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    similar = [SimilarIncidentContext(incident_id="INC-2", similarity=0.85)]
    plan = await plan_investigation(settings, target, None, {}, similar)

    assert plan.used_similarity is True
    assert plan.strategy == "targeted"


@pytest.mark.asyncio
async def test_ontology_prior_incident_is_targeted() -> None:
    settings = make_settings()
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    kg = {"available": True, "prior_incidents": [{"incident_id": "INC-9"}], "knowledge": {}}
    plan = await plan_investigation(settings, target, None, kg, [])

    assert plan.used_ontology is True
    assert plan.strategy == "targeted"


@pytest.mark.asyncio
async def test_hypotheses_ordered_and_present() -> None:
    settings = make_settings()
    target = _target(alert_name="RunAIWorkloadPending", namespace="team-a", queue="gpu-a")
    plan = await plan_investigation(settings, target, None, {}, [])

    families = [h["family"] for h in plan.hypotheses]
    assert "scheduling_quota_exhaustion" in families
    # pending/quota/queue signals should rank scheduling first
    assert families[0] == "scheduling_quota_exhaustion"


@pytest.mark.asyncio
async def test_llm_refinement_kept_on_success(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1):
        return {
            "focus": "refined focus",
            "strategy": "targeted",
            "hypotheses": [{"family": "control_plane_error", "reason": "llm says so"}],
            "narrative": "refined narrative",
        }

    monkeypatch.setattr("app.services.planner.complete_json", fake_complete_json)
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.focus == "refined focus"
    assert plan.strategy == "targeted"
    assert plan.hypotheses[0]["family"] == "control_plane_error"
    # deterministic scope decisions are NOT overridden by the LLM
    assert plan.check_control_plane is False


@pytest.mark.asyncio
async def test_llm_failure_falls_back_to_deterministic(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def boom(settings, *, system, user, temperature=0.1):
        raise RuntimeError("llm down")

    monkeypatch.setattr("app.services.planner.complete_json", boom)
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.strategy == "breadth_first"
    assert plan.focus  # deterministic focus preserved
