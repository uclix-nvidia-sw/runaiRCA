from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget
from app.schemas import Alert, SimilarIncidentContext
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
async def test_unrelated_high_similarity_text_is_not_targeted() -> None:
    settings = make_settings()
    target = _target(alert_name="NCCLTimeout", namespace="runai-research")
    alert = Alert(
        status="firing",
        labels={},
        annotations={
            "summary": "NCCL WARN socket timeout and ibv_poll_cq failed during allreduce"
        },
    )
    similar = [
        SimilarIncidentContext(
            incident_id="INC-OLD",
            similarity=0.98,
            title="old cluster-sync auth incident",
            analysis_summary="restart cluster-sync and rotate SAML metadata",
        )
    ]

    plan = await plan_investigation(settings, target, alert, {}, similar)

    assert plan.used_similarity is False
    assert plan.strategy == "breadth_first"


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
    assert "runai_scheduling_quota" in families
    # pending/quota/queue signals should rank scheduling first
    assert families[0] == "runai_scheduling_quota"


@pytest.mark.asyncio
async def test_platform_namespace_investigates_broadly() -> None:
    # runai / runai-backend = the Run:ai platform itself -> control plane leads and the
    # investigation is broad (k8s + node/system), not workload-scoped.
    settings = make_settings()
    target = _target(alert_name="SomeAlert", namespace="runai-backend")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.hypotheses[0]["family"] == "runai_control_plane_error"
    assert plan.check_control_plane is True
    assert "broadly" in plan.narrative.lower()


@pytest.mark.asyncio
async def test_user_workload_namespace_focuses_scheduler() -> None:
    # runai-test1 = a user workload running INSIDE the platform -> scheduler focus,
    # while still reading the scheduler/control-plane logs.
    settings = make_settings()
    target = _target(alert_name="SomeAlert", namespace="runai-test1")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.hypotheses[0]["family"] == "runai_scheduling_quota"
    assert plan.check_control_plane is True


def test_namespace_scope_classifies() -> None:
    from app.services.planner import _namespace_scope

    settings = make_settings()
    assert _namespace_scope(_target(namespace="runai"), settings) == "platform"
    assert _namespace_scope(_target(namespace="runai-backend"), settings) == "platform"
    assert _namespace_scope(_target(namespace="runai-test1"), settings) == "workload"
    assert _namespace_scope(_target(namespace="team-a", queue="gpu-a"), settings) == "workload"
    assert _namespace_scope(_target(namespace="monitoring"), settings) == "infra"
    assert _namespace_scope(_target(namespace=""), settings) == "infra"


@pytest.mark.asyncio
async def test_llm_refinement_kept_on_success(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return {
            "focus": "refined focus",
            "strategy": "targeted",
            "hypotheses": [{"family": "runai_control_plane_error", "reason": "llm says so"}],
            "narrative": "refined narrative",
        }

    monkeypatch.setattr("app.services.planner.complete_json", fake_complete_json)
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    plan = await plan_investigation(settings, target, None, {}, [])

    assert plan.focus == "refined focus"
    assert plan.strategy == "targeted"
    assert plan.hypotheses[0]["family"] == "runai_control_plane_error"
    # deterministic scope decisions are NOT overridden by the LLM
    assert plan.check_control_plane is False


@pytest.mark.asyncio
async def test_llm_refinement_prompt_redacts_sensitive_inputs(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    prompts: list[str] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        prompts.append(user)
        return None

    monkeypatch.setattr("app.services.planner.complete_json", fake_complete_json)
    target = _target(
        alert_name="RunAIAlert",
        namespace="runai",
        project="password=project-secret-12345",
        workload_name="trainer",
    )
    alert = Alert(
        status="firing",
        labels={},
        annotations={"operator_prompt": "api_key=operator-key-12345"},
    )
    similar = [
        SimilarIncidentContext(
            incident_id="INC-SECRET",
            similarity=0.9,
            title="token=title-token-12345",
            analysis_summary="client_secret=similar-secret-12345",
        )
    ]

    await plan_investigation(settings, target, alert, {}, similar)

    joined = "\n".join(prompts)
    for secret in [
        "project-secret-12345",
        "operator-key-12345",
        "title-token-12345",
        "similar-secret-12345",
    ]:
        assert secret not in joined
    assert "[MASKED]" in joined


@pytest.mark.asyncio
async def test_llm_refinement_output_is_masked_and_single_line(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_complete_json(settings, *, system, user, **_kwargs):
        return {
            "focus": "Check scheduler token=focus-secret-12345\n## injected focus",
            "strategy": "targeted",
            "hypotheses": [
                {
                    "family": "runai_control_plane_error",
                    "reason": "api_key=hypothesis-secret-12345\n## injected reason",
                }
            ],
            "narrative": "Investigate backend password=narrative-secret-12345\n## injected section",
        }

    monkeypatch.setattr("app.services.planner.complete_json", fake_complete_json)

    plan = await plan_investigation(
        settings,
        _target(alert_name="RunAISchedulerError", namespace="runai"),
        None,
        {},
        [],
    )

    serialized = str(plan.as_dict())
    for secret in ["focus-secret-12345", "hypothesis-secret-12345", "narrative-secret-12345"]:
        assert secret not in serialized
    assert "[MASKED]" in serialized
    assert "\n" not in plan.focus
    assert "\n" not in plan.narrative
    assert "\n" not in plan.hypotheses[0]["reason"]


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


@pytest.mark.asyncio
async def test_static_knowledge_alone_is_not_an_ontology_match() -> None:
    # Curated knowledge EXISTS for every family after loading — its mere presence
    # made every plan claim "targeted (matched knowledge-graph facts)". Without an
    # alert-specific fact the plan must stay honest breadth_first.
    settings = make_settings()
    target = _target(alert_name="MysteriousBlip", namespace="monitoring")
    kg = {
        "available": True,
        "prior_incidents": [],
        "knowledge": {
            "node_kubelet_pressure": [
                {"symptom": "Node Disk Pressure", "keywords": ["diskpressure"], "actions": ["x"]}
            ]
        },
    }
    plan = await plan_investigation(settings, target, None, kg, [])
    assert plan.used_ontology is False
    assert plan.strategy == "breadth_first"


@pytest.mark.asyncio
async def test_knowledge_keyword_matching_alert_text_is_targeted() -> None:
    # A knowledge symptom whose keyword appears in the alert's own text IS an
    # alert-specific ontology fact -> targeted.
    settings = make_settings()
    target = _target(alert_name="NodeDiskPressure", namespace="monitoring")
    kg = {
        "available": True,
        "prior_incidents": [],
        "knowledge": {
            "node_kubelet_pressure": [
                {"symptom": "Node Disk Pressure", "keywords": ["diskpressure"], "actions": ["x"]}
            ]
        },
    }
    plan = await plan_investigation(settings, target, None, kg, [])
    assert plan.used_ontology is True
    assert plan.strategy == "targeted"


@pytest.mark.asyncio
async def test_negated_knowledge_keyword_is_not_targeted() -> None:
    settings = make_settings()
    target = _target(alert_name="NoisyAlert", namespace="monitoring")
    alert = Alert(
        status="firing",
        labels={},
        annotations={"summary": "no ImagePullBackOff and no DiskPressure observed"},
    )
    kg = {
        "available": True,
        "prior_incidents": [],
        "knowledge": {
            "image_pull_error": [
                {"symptom": "Image Pull Error", "keywords": ["imagepullbackoff"]}
            ],
            "node_kubelet_pressure": [
                {"symptom": "Node Disk Pressure", "keywords": ["diskpressure"]}
            ],
        },
    }
    plan = await plan_investigation(settings, target, alert, kg, [])
    assert plan.used_ontology is False
    assert plan.strategy == "breadth_first"


@pytest.mark.asyncio
async def test_no_signal_alert_does_not_default_to_node_pressure() -> None:
    # PrometheusMissingRuleEvaluations matches no family keyword. The old tiebreak
    # made node_kubelet_pressure the confident "most likely" leader. It must now be
    # honest: insufficient_evidence, breadth-first, no fabricated family.
    settings = make_settings()
    target = _target(
        alert_name="PrometheusMissingRuleEvaluations",
        namespace="monitoring",
        pod="prometheus-prometheus-kube-prometheus-prometheus-0",
    )
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.hypotheses[0]["family"] == "insufficient_evidence"
    assert "most likely" not in plan.focus
    assert "node kubelet pressure" not in plan.focus


@pytest.mark.asyncio
async def test_memory_alert_is_workload_runtime_not_control_plane() -> None:
    # A container over its own memory limit is workload runtime saturation, not a
    # control-plane error (the catalog family was wrong).
    settings = make_settings()
    target = _target(
        alert_name="RunaiContainerMemoryUsageCritical",
        namespace="runai-backend",
        workload_name="runai-backend-workloads-manager-7b5c45cd7d-89km6",
    )
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.hypotheses[0]["family"] == "workload_runtime_error"


@pytest.mark.asyncio
async def test_llm_can_widen_scope_to_control_plane(monkeypatch) -> None:
    # LLM re-reasons the cause toward the platform → it may turn control-plane
    # reading ON, and the runai control-plane namespaces get added.
    settings = replace(make_settings(), llm_base_url="x", llm_model="m", llm_api_key="k")

    async def fake(settings, *, system, user, temperature=0.1, model=None):
        return {"strategy": "targeted", "check_control_plane": True,
                "hypotheses": [{"family": "runai_control_plane_error", "reason": "platform"}]}

    monkeypatch.setattr("app.services.planner.complete_json", fake)
    # monitoring ns → deterministic check_control_plane is False
    target = _target(alert_name="SomeAlert", namespace="monitoring")
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.check_control_plane is True
    for ns in settings.runai_log_namespaces:
        assert ns in plan.namespaces


@pytest.mark.asyncio
async def test_llm_cannot_narrow_control_plane_below_floor(monkeypatch) -> None:
    # Deterministic router required control-plane (runai-backend ns). The LLM saying
    # false must NOT switch it off — scope only widens, never narrows.
    settings = replace(make_settings(), llm_base_url="x", llm_model="m", llm_api_key="k")

    async def fake(settings, *, system, user, temperature=0.1):
        return {"strategy": "breadth_first", "check_control_plane": False,
                "hypotheses": [{"family": "node_kubelet_pressure", "reason": "x"}]}

    monkeypatch.setattr("app.services.planner.complete_json", fake)
    target = _target(alert_name="SomeAlert", namespace="runai-backend")
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.check_control_plane is True  # deterministic floor held
