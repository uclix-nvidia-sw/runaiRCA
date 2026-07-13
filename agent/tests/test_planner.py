from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget
from app.schemas import Alert, SimilarIncidentContext
from app.services.decision_tree import load_tree
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "expected_family"),
    [
        (
            {"kind": "NodeCondition", "summary": "Node gpu-1 condition Ready=False."},
            "node_kubelet_pressure",
        ),
        (
            {"kind": "PodDeleted", "summary": "Pod trainer-old is terminating."},
            "workload_startup_error",
        ),
    ],
)
async def test_recent_change_leads_before_scheduler(
    change: dict, expected_family: str
) -> None:
    settings = make_settings()
    target = _target(alert_name="SomeAlert", namespace="runai-test1", node="gpu-1")
    plan = await plan_investigation(settings, target, None, {}, [], [change])

    assert plan.hypotheses[0]["family"] == expected_family
    assert plan.hypotheses[0]["family"] != "runai_scheduling_quota"


@pytest.mark.asyncio
async def test_plan_stage_feeds_recent_changes_into_the_planner() -> None:
    # Integration: the parametrized unit test above calls plan_investigation directly,
    # so it does NOT exercise the pipeline wiring. This drives the real plan_stage with
    # a stub "change" collector and asserts the change signal actually reaches the plan.
    from app.collectors.base import CollectorResult
    from app.progress import ProgressReporter
    from app.schemas import Alert, AlertAnalysisRequest
    from app.services import pipeline
    from app.services.kg_enrichment import KGContext

    class _StubChange:
        name = "change"

        async def collect(self, target, plan=None):  # noqa: ANN001
            return CollectorResult(
                agent="change",
                status="ok",
                summary="recent change",
                details={"changes": [{"kind": "NodeCondition", "summary": "Node gpu-1 Ready=False."}]},
            )

    settings = make_settings()
    # No pod -> plan_stage skips the live-pod k8s re-resolution, so this stays offline.
    target = _target(alert_name="SomeAlert", namespace="runai-test1", node="gpu-1")
    state = pipeline.PipelineState(
        settings=settings,
        request=AlertAnalysisRequest(alert=Alert(labels={"alertname": "SomeAlert"}, annotations={})),
        target=target,
        progress=ProgressReporter(settings, run_id=""),
        masker=None,
        collectors=[_StubChange()],
        kg_context=KGContext(),
    )
    await pipeline.plan_stage(state)
    assert state.plan.hypotheses[0]["family"] == "node_kubelet_pressure", state.plan.hypotheses


def test_namespace_scope_classifies() -> None:
    from app.services.planner import _namespace_scope

    settings = make_settings()
    assert _namespace_scope(_target(namespace="runai"), settings) == "platform"
    assert _namespace_scope(_target(namespace="runai-backend"), settings) == "platform"
    assert _namespace_scope(_target(namespace="runai-test1"), settings) == "workload"
    assert _namespace_scope(_target(namespace="team-a", queue="gpu-a"), settings) == "workload"
    assert _namespace_scope(_target(namespace="monitoring"), settings) == "infra"
    assert _namespace_scope(_target(namespace=""), settings) == "infra"


def test_generic_infra_component_is_infra_not_runai_workload() -> None:
    # The reported bug: kube-state-metrics in a runai-* namespace was routed to the
    # Run:ai scheduler. A generic monitoring component is a plain Kubernetes problem.
    from app.services.planner import _implicates_control_plane, _namespace_scope

    settings = make_settings()
    ksm = _target(namespace="runai-rca", pod="prometheus-kube-state-metrics-76f7f4dd55-4lj5q")
    assert _namespace_scope(ksm, settings) == "infra"
    assert _implicates_control_plane(ksm) is False
    # A real Run:ai workload in the same-shaped namespace still routes to workload.
    trainer = _target(namespace="runai-team-a", pod="trainer-0")
    assert _namespace_scope(trainer, settings) == "workload"


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
    # A truly signal-less alert must stay honest: insufficient_evidence,
    # breadth-first, no fabricated family from the declaration-order tiebreak.
    settings = make_settings()
    target = _target(
        alert_name="SomethingCompletelyUnrecognized",
        namespace="acme-team",
        pod="widget-worker-0",
    )
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.hypotheses[0]["family"] == "insufficient_evidence"
    assert "most likely" not in plan.focus
    assert "node kubelet pressure" not in plan.focus


@pytest.mark.asyncio
async def test_typedb_diagnostic_graph_is_injected_as_neutral_collector_directive() -> None:
    settings = make_settings()
    target = _target(
        alert_name="NvidiaXidCriticalError",
        namespace="runai-vision",
        node="gpu-1",
    )
    alert = Alert(
        status="firing",
        labels={"alertname": "NvidiaXidCriticalError"},
        annotations={
            "summary": "NVRM: Xid 79 GPU has fallen off the bus",
            "analysis_run_id": "ANL-42",
        },
    )
    kg = {
        "available": True,
        "prior_incidents": [],
        "knowledge": {},
        "diagnostic_tree": load_tree("knowledge/k8s_troubleshooting_tree.yaml"),
    }

    plan = await plan_investigation(settings, target, alert, kg, [])

    directive = plan.diagnostic_directive
    assert directive["source"] == "typedb"
    assert directive["provisional_family"] == "gpu_hardware_error"
    assert "system" in directive["recommended_collectors"]
    assert directive["checks"]
    assert directive["interpretation"]
    assert "confirm or refute" in directive["instruction"]
    assert [hypothesis["id"] for hypothesis in plan.hypotheses] == [
        f"ANL-42:H{index}" for index in range(1, len(plan.hypotheses) + 1)
    ]
    assert directive["run_id"] == "ANL-42"
    assert directive["probes"]
    assert all(probe["template_id"] == probe["id"] for probe in directive["probes"])
    assert all(
        probe["hypothesis_ids"] == [
            hypothesis["id"]
            for hypothesis in plan.hypotheses
            if hypothesis["family"] == directive["provisional_family"]
        ]
        for probe in directive["probes"]
    )


@pytest.mark.asyncio
async def test_planner_assigns_a_stable_template_id_to_legacy_probe() -> None:
    settings = make_settings()
    target = _target(alert_name="NvidiaXidCriticalError", namespace="runai-vision")
    alert = Alert(annotations={"analysis_run_id": "ANL-42"})
    tree = {
        "root": "scope",
        "nodes": {
            "scope": {
                "id": "scope",
                "question": "Scope the incident.",
                "match": {"always": True},
                "conclusion": {"family": "gpu_hardware_error"},
                "probes": [
                    {
                        "tool": "k8s_read",
                        "arguments_template": {"kind": "events", "namespace": "{{namespace}}"},
                    }
                ],
            }
        },
    }

    first = await plan_investigation(
        settings, target, alert, {"diagnostic_tree": tree}, []
    )
    second = await plan_investigation(
        settings, target, alert, {"diagnostic_tree": tree}, []
    )
    unscoped = await plan_investigation(
        settings, target, Alert(), {"diagnostic_tree": tree}, []
    )

    first_probe = first.diagnostic_directive["probes"][0]
    second_probe = second.diagnostic_directive["probes"][0]
    assert first_probe["template_id"] == second_probe["template_id"]
    assert first_probe["template_id"].startswith("scope-probe-01-")
    assert first_probe["hypothesis_ids"] == [
        hypothesis["id"]
        for hypothesis in first.hypotheses
        if hypothesis["family"] == "gpu_hardware_error"
    ]
    assert "run_id" not in unscoped.diagnostic_directive
    assert "hypothesis_ids" not in unscoped.diagnostic_directive["probes"][0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode, includes_registered",
    [("off", False), ("shadow", False), ("assist", True), ("authoritative", True)],
)
async def test_dynamic_knowledge_can_select_only_registered_tree_probes(
    monkeypatch, mode: str, includes_registered: bool
) -> None:
    from app import knowledge

    class _Registry:
        def __init__(self) -> None:
            self.mode = mode
            self.calls: list[str] = []

        def probe_template_ids_for_family(self, family: str) -> tuple[str, ...]:
            self.calls.append(family)
            # Runtime data is deliberately only identifiers; these attempted
            # arguments are not accepted by the planner.
            return ("registered-probe", "unknown-probe")

    registry = _Registry()
    monkeypatch.setattr(knowledge, "_runtime_knowledge_registry", registry)
    tree = {
        "root": "scope",
        "nodes": {
            "scope": {
                "id": "scope",
                "question": "Scope the incident.",
                "match": {"always": True},
                "conclusion": {"family": "gpu_hardware_error"},
                "probes": [
                    {
                        "id": "path-probe",
                        "tool": "k8s_read",
                        "arguments_template": {"kind": "events", "namespace": "{{namespace}}"},
                    }
                ],
            },
            "registered": {
                "id": "registered",
                "probes": [
                    {
                        "id": "registered-probe",
                        "tool": "k8s_describe",
                        "arguments_template": {
                            "kind": "pods",
                            "name": "{{pod}}",
                            "namespace": "{{namespace}}",
                        },
                    }
                ],
            },
        },
    }

    plan = await plan_investigation(
        make_settings(),
        _target(alert_name="NvidiaXidCriticalError", namespace="runai-vision"),
        Alert(),
        {"diagnostic_tree": tree},
        [],
    )

    probes = plan.diagnostic_directive["probes"]
    assert [probe["template_id"] for probe in probes] == (
        ["path-probe", "registered-probe"] if includes_registered else ["path-probe"]
    )
    assert all(probe["template_id"] != "unknown-probe" for probe in probes)
    assert next(probe for probe in probes if probe["template_id"] == "path-probe")[
        "arguments_template"
    ] == {"kind": "events", "namespace": "{{namespace}}"}
    if includes_registered:
        assert registry.calls == ["gpu_hardware_error"]
        assert next(probe for probe in probes if probe["template_id"] == "registered-probe")[
            "arguments_template"
        ] == {"kind": "pods", "name": "{{pod}}", "namespace": "{{namespace}}"}
    else:
        assert registry.calls == []


@pytest.mark.asyncio
async def test_observability_alert_now_maps_to_its_own_family() -> None:
    # PrometheusMissingRuleEvaluations used to match NO family (the ranked
    # universe stopped at 7 coarse families) and fell to insufficient_evidence;
    # with the unified catalog it names the observability pipeline — and still
    # never the node-pressure tiebreak.
    settings = make_settings()
    target = _target(
        alert_name="PrometheusMissingRuleEvaluations",
        namespace="monitoring",
        pod="prometheus-prometheus-kube-prometheus-prometheus-0",
    )
    plan = await plan_investigation(settings, target, None, {}, [])
    assert plan.hypotheses[0]["family"] == "observability_accuracy"
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
