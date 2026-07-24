"""Tests for the iterative re-analysis loop and the operator-questions section.

Covers: refuted -> bounded re-analysis; not refuted -> none;
re-analysis failure -> clean fallback to the first result; insufficient
evidence -> operator questions section (Korean under ko); no LLM -> behavior
unchanged (no re-analysis, deterministic questions).
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.evidence_blackboard import EvidenceEligibility
from app.services.orchestrator import AnalysisOrchestrator
from app.services.pipeline import _collector_name
from app.services.root_cause_ranking import RankedCause
from app.plan import InvestigationPlan
from tests.test_orchestrator import make_settings


def llm_settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        enable_investigation_loop=True,
        max_investigation_steps=4,
    )


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "NodeDiskPressure", "namespace": "runai-vision"},
            annotations={"summary": "Node under disk pressure."},
            fingerprint="fp-reanalysis",
        )
    )


def _signatureless_request() -> AlertAnalysisRequest:
    """An alert matching NO curated signature — the true no-signal path.

    The signature-first headline names the family straight from the alert text
    (NodeDiskPressure -> node_kubelet_pressure), so insufficient-evidence tests
    need an alert whose name/summary hit no symptom/known-issue/XID keyword."""
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "MysteriousBlip", "namespace": "runai-vision"},
            annotations={"summary": "Something odd happened."},
            fingerprint="fp-reanalysis-nosig",
        )
    )


def _stub_llm_http(monkeypatch) -> None:
    # Any raw LLM HTTP call (planner refinement, synthesis, sharpening) fails fast.
    async def fake_post_json(*args, **kwargs):
        return SimpleNamespace(ok=False, data=None, error="down", status_code=500)

    monkeypatch.setattr("app.llm.post_json", fake_post_json)


def _install_stubs(
    monkeypatch,
    verdicts: list[dict],
    investigate_calls: list[int],
    refute_calls: list[str],
    fail_second_investigate: bool = False,
) -> None:
    """Stub investigate + refute_top_cause (both lazily imported by the orchestrator).

    First investigate pass yields node-pressure evidence; a second (re-analysis)
    pass replaces it with scheduling-quota evidence so the re-rank flips families.
    """

    async def fake_investigate(settings, target, collectors, plan, kg, max_steps, reporter=None):
        call = len(investigate_calls)
        investigate_calls.append(max_steps)
        if fail_second_investigate and call > 0:
            raise RuntimeError("re-analysis probe exploded")
        if call == 0:
            summaries = {
                "kubernetes": "Node condition DiskPressure=True; kubelet evicting pods",
                "prometheus": "requested gpus exceed allocated gpus",
            }
        else:
            summaries = {
                "kubernetes": "no further node findings",
                "prometheus": "runai reclaimed over-quota gpus; gang pod group preempt",
            }
        results = [
            CollectorResult(
                agent=_collector_name(collector),
                status="ok",
                summary=summaries.get(_collector_name(collector), "nothing notable"),
            )
            for collector in collectors
        ]
        return results, {"hypothesis_ledger": []}

    async def fake_refute(settings, top, results, plan=None):
        refute_calls.append(top.family)
        verdict = verdicts[min(len(refute_calls) - 1, len(verdicts) - 1)]
        return dict(verdict)

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    monkeypatch.setattr("app.services.self_check.refute_top_cause", fake_refute)


def _install_iterative_stubs(
    monkeypatch,
    investigate_calls: list[int],
    refute_calls: list[str],
) -> None:
    async def fake_investigate(settings, target, collectors, plan, kg, max_steps, reporter=None):
        call = len(investigate_calls)
        investigate_calls.append(max_steps)
        summaries_by_call = [
            {
                "kubernetes": "Node condition DiskPressure=True; kubelet evicting pods",
                "prometheus": "requested gpus exceed allocated gpus",
            },
            {
                "kubernetes": "CrashLoopBackOff startup probe failed",
                "prometheus": "runai reclaimed over-quota gpus; gang pod group preempt",
            },
            {
                "kubernetes": "CrashLoopBackOff startup probe failed permission denied",
                "loki": "container ImportError and permission denied during startup",
            },
        ]
        summaries = summaries_by_call[min(call, len(summaries_by_call) - 1)]
        results = [
            CollectorResult(
                agent=_collector_name(collector),
                status="ok",
                summary=summaries.get(_collector_name(collector), "nothing notable"),
            )
            for collector in collectors
        ]
        return results, {"hypothesis_ledger": []}

    verdicts = [
        {
            "confidence": "low",
            "caveat": "Node pressure does not explain the scheduler evidence.",
            "refuted": True,
            "next_check": "Check quota evidence.",
        },
        {
            "confidence": "low",
            "caveat": "Quota does not explain the container crash.",
            "refuted": True,
            "next_check": "Check startup logs.",
        },
        {"confidence": "high", "caveat": "", "refuted": False, "next_check": ""},
    ]

    async def fake_refute(settings, top, results, plan=None):
        refute_calls.append(top.family)
        return dict(verdicts[min(len(refute_calls) - 1, len(verdicts) - 1)])

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    monkeypatch.setattr("app.services.self_check.refute_top_cause", fake_refute)


@pytest.mark.asyncio
async def test_default_cap_allows_multiple_reanalysis_passes_until_resolved(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_iterative_stubs(monkeypatch, investigate_calls, refute_calls)

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    assert investigate_calls == [4, 2, 2]
    assert refute_calls == [
        "node_kubelet_pressure",
        "runai_scheduling_quota",
        "workload_startup_error",
    ]
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "workload_startup_error"
    assert top["confidence"] == "high"
    assert "The initial conclusion (node_kubelet_pressure) was refuted" in response.analysis_detail
    assert (
        "The previous conclusion (runai_scheduling_quota) was refuted"
        in response.analysis_detail
    )
    assert "## Questions for the Operator" not in response.analysis_detail


@pytest.mark.asyncio
async def test_refuted_top_cause_triggers_exactly_one_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "Competing cause fits better.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            },
            {"confidence": "medium", "caveat": "", "refuted": False, "next_check": ""},
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    # Exactly one re-entry: main pass + ONE re-analysis, with the small step budget.
    assert len(investigate_calls) == 2
    assert investigate_calls[1] == 2  # min(2, max_investigation_steps=4)
    assert len(refute_calls) == 2
    assert refute_calls[0] == "node_kubelet_pressure"
    assert refute_calls[1] == "runai_scheduling_quota"
    # The report shows it thought again.
    assert "## Self-Check" in response.analysis_detail
    assert (
        "The initial conclusion (node_kubelet_pressure) was refuted" in response.analysis_detail
    )
    assert "revised conclusion: runai_scheduling_quota" in response.analysis_detail
    # The merged re-analysis evidence drives the final ranking.
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "runai_scheduling_quota"
    # Not refuted anymore -> no operator questions section.
    assert "## Questions for the Operator" not in response.analysis_detail


@pytest.mark.asyncio
async def test_completed_followup_is_preserved_when_evidence_budget_expires(
    monkeypatch,
) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "Competing cause fits better.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            },
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )
    budget_checks: list[int] = []

    def budget_exceeded(_state) -> bool:
        budget_checks.append(1)
        # The first check admits the bounded follow-up. The deadline is reached
        # only after that probe has returned, while the optional second
        # self-check is about to start.
        return len(budget_checks) > 1

    monkeypatch.setattr(pipeline, "_evidence_budget_exceeded", budget_exceeded)

    response = await AnalysisOrchestrator(llm_settings()).analyze(_request())

    assert investigate_calls == [4, 2]
    assert refute_calls == ["node_kubelet_pressure"]
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "runai_scheduling_quota"
    assert "re-analysis pass was performed" in response.analysis_detail


@pytest.mark.asyncio
async def test_progress_does_not_look_stuck_after_self_check(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "A targeted follow-up is required.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            },
            {"confidence": "medium", "caveat": "", "refuted": False, "next_check": ""},
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )
    events: list[tuple[str, str]] = []
    flushed_at: list[int] = []

    class RecordingProgress:
        def emit(self, phase, message, **_fields):
            events.append((phase, message))

        async def flush(self):
            flushed_at.append(len(events))

    def fake_from_alert(_cls, *_args, **_kwargs):
        return RecordingProgress()

    monkeypatch.setattr(
        pipeline.ProgressReporter,
        "from_alert",
        classmethod(fake_from_alert),
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    await orchestrator.analyze(_request())

    self_check_index = events.index(("self_check", "Self-check complete"))
    follow_up_index = events.index(
        ("investigation", "Running targeted follow-up before synthesis")
    )
    synthesis_index = events.index(("synthesize", "Synthesizing final RCA"))
    synthesis_complete_index = events.index(("synthesize", "Synthesis complete"))
    harness_start_index = events.index(("harness", "Validating synthesized RCA"))
    harness_complete_index = events.index(("harness", "Validation complete"))
    assert (
        self_check_index
        < follow_up_index
        < synthesis_index
        < synthesis_complete_index
        < harness_start_index
        < harness_complete_index
    )
    assert flushed_at == [len(events)]


@pytest.mark.asyncio
async def test_semantic_completion_does_not_disable_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "Competing cause fits better.",
                "refuted": True,
                "next_check": "Check the scheduler queue directly.",
            }
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    settings = llm_settings()
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_request())

    assert len(investigate_calls) > 1
    assert len(refute_calls) >= 1
    assert "re-analysis pass was performed" in response.analysis_detail
    top = response.context["root_cause_candidates"][0]
    # The sole stub verdict refutes every candidate. The pipeline now fails
    # closed instead of allowing the last refuted family into synthesis.
    assert top["family"] == "insufficient_evidence"


@pytest.mark.asyncio
async def test_not_refuted_means_no_reanalysis(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[{"confidence": "high", "caveat": "", "refuted": False, "next_check": ""}],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    assert len(investigate_calls) == 1
    assert len(refute_calls) == 1
    assert "re-analysis pass was performed" not in response.analysis_detail
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "node_kubelet_pressure"


def test_settled_hypothesis_ignores_unrelated_collector_gap() -> None:
    state = SimpleNamespace(
        root_cause_candidates=[
            SimpleNamespace(family="runai_scheduling_quota", confidence="medium")
        ],
        self_check_refuted=False,
        missing=["loki.query", "change.helm"],
    )

    assert pipeline._needs_more_investigation(state) is False


def test_low_confidence_hypothesis_still_requests_targeted_followup() -> None:
    state = SimpleNamespace(
        root_cause_candidates=[
            SimpleNamespace(family="runai_scheduling_quota", confidence="low")
        ],
        self_check_refuted=False,
        missing=[],
    )

    assert pipeline._needs_more_investigation(state) is True


def test_reanalysis_cannot_reselect_the_self_refuted_family_on_same_mechanism() -> None:
    target = pipeline._ReanalysisTarget(
        "workload_runtime_error",
        "re-analysis after refutation",
        refuted_family="workload_runtime_error",
    )
    candidates = [
        RankedCause("workload_runtime_error", "high", 9.0),
        RankedCause("workload_startup_error", "medium", 3.0),
    ]

    filtered = pipeline._exclude_refuted_reanalysis_candidates(candidates, target)

    assert [candidate.family for candidate in filtered] == ["workload_startup_error"]
    only_refuted = pipeline._exclude_refuted_reanalysis_candidates(candidates[:1], target)
    assert only_refuted[0].family == "insufficient_evidence"


def test_medium_insufficient_evidence_still_requests_targeted_followup() -> None:
    state = SimpleNamespace(
        root_cause_candidates=[
            SimpleNamespace(family="insufficient_evidence", confidence="medium")
        ],
        self_check_refuted=False,
        missing=[],
    )

    assert pipeline._needs_more_investigation(state) is True


def test_probe_history_bookkeeping_does_not_count_as_new_evidence() -> None:
    previous = CollectorResult(
        agent="loki",
        status="ok",
        summary="same bounded log result",
        details={
            "rows": [{"message": "NVRM Xid 79"}],
            "probe_results": [
                {"scope": {"pod": "trainer-0"}, "status": "ok"},
            ],
        },
    )
    repeated = CollectorResult(
        agent="loki",
        status="ok",
        summary="same bounded log result",
        details={
            "rows": [{"message": "NVRM Xid 79"}],
            "probe_results": [
                {"scope": {"pod": "trainer-0"}, "status": "ok"},
                {"scope": {"pod": "trainer-0"}, "status": "ok"},
            ],
        },
    )

    assert pipeline._evidence_signature([previous]) == pipeline._evidence_signature(
        [repeated]
    )


def test_aggregate_evidence_keeps_latest_semantic_round_artifact() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    first = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="cluster_api",
        status="ok",
        confidence="high",
        query="GET /api/v1/namespaces/runai/pods",
        summary="empty sweep",
        result={"items": []},
    )
    repeated = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="cluster_api",
        status="ok",
        confidence="high",
        query="GET /api/v1/namespaces/runai/pods",
        summary="empty sweep from a later round",
        result={"items": []},
    )
    state.results = [
        CollectorResult(
            agent="kubernetes", status="ok", summary="same collector", artifacts=[first, repeated]
        )
    ]

    pipeline._aggregate_evidence(state)
    first_signature = pipeline._evidence_signature(state.results)
    pipeline._aggregate_evidence(state)

    assert state.results[0].artifacts == [repeated]
    assert pipeline._evidence_signature(state.results) == first_signature


def test_aggregate_evidence_keeps_distinct_node_conditions_from_one_query() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    conditions = [
        artifact(
            agent="kubernetes",
            source="kubernetes",
            type="kubernetes_node_condition",
            status="ok",
            confidence="high",
            title=f"node/dgx01 · {condition}",
            query="kubectl get nodes dgx01 -o json",
            summary=f"{condition}=False",
            result={"condition": condition, "status": "False"},
        )
        for condition in ("MemoryPressure", "DiskPressure", "PIDPressure")
    ]
    state.results = [
        CollectorResult(
            agent="kubernetes", status="ok", summary="node healthy", artifacts=conditions
        )
    ]

    pipeline._aggregate_evidence(state)

    assert state.results[0].artifacts == conditions


def test_aggregate_evidence_keeps_same_query_from_distinct_windows() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    cards = [
        artifact(
            agent="prometheus",
            source="prometheus",
            type="promql_signal",
            status="ok",
            confidence="high",
            title="Prometheus · restarts",
            query="increase(kube_pod_container_status_restarts_total[5m])",
            summary=f"restart observation for {start}",
            result={
                "observation": {
                    "kind": "prometheus_query",
                    "predicate": "container_restarts",
                    "polarity": "present",
                    "coverage": "scoped",
                    "observed_entity": {"pod": "trainer-0"},
                    "observation_window": {
                        "start": start,
                        "end": end,
                    },
                }
            },
        )
        for start, end in (
            ("2026-07-22T01:00:00Z", "2026-07-22T01:05:00Z"),
            ("2026-07-22T02:00:00Z", "2026-07-22T02:05:00Z"),
        )
    ]
    state.results = [
        CollectorResult(agent="prometheus", status="ok", summary="two windows", artifacts=cards)
    ]

    pipeline._aggregate_evidence(state)

    assert state.results[0].artifacts == cards


def test_continuation_reanalysis_marks_only_added_artifacts_as_fresh() -> None:
    existing = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_warning_events",
        status="ok",
        confidence="high",
        query="kubectl get events -n default",
        summary="ImagePullBackOff",
        result={"kind": "events", "count": 1},
    )
    added = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="adhoc_query",
        status="ok",
        confidence="medium",
        query="kubectl get resourcequotas -n default",
        summary="quota checked",
        result={"kind": "resourcequotas", "count": 1},
    )
    previous = [
        CollectorResult(
            agent="kubernetes", status="ok", summary="initial", artifacts=[existing]
        )
    ]
    continued = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="continued",
            artifacts=[existing, added],
        )
    ]

    fresh = pipeline._fresh_collector_results(previous, continued)

    assert len(fresh) == 1
    assert fresh[0].artifacts == [added]


def test_reanalysis_note_is_not_appended_twice() -> None:
    note = "The previous conclusion was refuted."
    assert pipeline._append_reanalysis_note(note, note) == note


def test_fresh_scoped_support_can_rehabilitate_a_refuted_family() -> None:
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="warning_events",
        status="ok",
        confidence="high",
        summary="FailedScheduling: pod is Unschedulable",
        result={
            "observation": {
                "predicate": "kubernetes_event:FailedScheduling",
                "polarity": "present",
                "coverage": "scoped",
            }
        },
    )
    finding.evidence_id = "E23"
    fresh = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="scheduler event collected",
            artifacts=[finding],
        )
    ]

    assert pipeline._fresh_results_support_family(
        "k8s_scheduling_error",
        fresh,
        {"E23": EvidenceEligibility(True, True, True)},
    )
    assert not pipeline._fresh_results_support_family(
        "k8s_scheduling_error",
        fresh,
        {"E23": EvidenceEligibility(False, False, True, "wrong entity")},
    )


def test_reanalysis_prefers_newly_eligible_family_over_next_ranked_candidate() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    state.plan = InvestigationPlan(
        hypotheses=[
            {"family": "platform_lifecycle_change", "reason": "original plan first"},
            {"family": "k8s_control_plane_error", "reason": "original plan second"},
        ]
    )
    state.root_cause_candidates = [
        RankedCause("platform_lifecycle_change", "low", 3.0),
        RankedCause("k8s_control_plane_error", "low", 2.5),
    ]
    state.self_check_refuted = True
    finding = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="warning_event",
        status="ok",
        confidence="high",
        summary="ImagePullBackOff for the affected pod",
        result={
            "observation": {
                "predicate": "kubernetes_event:ImagePullBackOff",
                "polarity": "present",
                "coverage": "scoped",
            }
        },
    )
    finding.evidence_id = "E-image-pull"
    state.reanalysis_fresh_support_families = pipeline._fresh_eligible_support_families(
        [CollectorResult(agent="kubernetes", status="ok", summary="", artifacts=[finding])],
        {"E-image-pull": EvidenceEligibility(True, True, True)},
    )

    target = pipeline._next_reanalysis_target(state, {"platform_lifecycle_change"})

    assert target is not None
    assert target.family == "image_pull_error"


def test_reanalysis_ledger_carries_evidence_by_family_across_reused_ids() -> None:
    merged = pipeline._merge_reanalysis_context(
        {
            "hypothesis_ledger": [
                {
                    "id": "H1",
                    "family": "image_pull_error",
                    "evidence_for": ["E-image", "E-image"],
                    "evidence_against": ["E-registry"],
                }
            ]
        },
        {
            "hypothesis_ledger": [
                {"id": "H1", "family": "platform_lifecycle_change"},
                {
                    "id": "H2",
                    "family": "image_pull_error",
                    "evidence_for": ["E-pod"],
                },
            ]
        },
    )

    ledger = merged["hypothesis_ledger"]
    image_pull = next(item for item in ledger if item["family"] == "image_pull_error")
    assert image_pull["evidence_for"] == ["E-image", "E-pod"]
    assert image_pull["evidence_against"] == ["E-registry"]
    assert len({item["id"] for item in ledger}) == len(ledger)


def test_ineligible_fresh_artifact_cannot_change_reanalysis_primary() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    state.root_cause_candidates = [
        RankedCause("platform_lifecycle_change", "low", 3.0),
        RankedCause("k8s_control_plane_error", "low", 2.5),
    ]
    state.self_check_refuted = True
    unknown = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="warning_event",
        status="ok",
        confidence="medium",
        summary="ImagePullBackOff may be present",
        result={
            "observation": {
                "predicate": "kubernetes_event:ImagePullBackOff",
                "polarity": "unknown",
                "coverage": "unknown",
            }
        },
    )
    unknown.evidence_id = "E-unknown"
    state.reanalysis_fresh_support_families = pipeline._fresh_eligible_support_families(
        [CollectorResult(agent="kubernetes", status="ok", summary="", artifacts=[unknown])],
        {"E-unknown": EvidenceEligibility(False, False, True, "observation is unknown")},
    )

    target = pipeline._next_reanalysis_target(state, {"platform_lifecycle_change"})

    assert state.reanalysis_fresh_support_families == ()
    assert target is not None
    assert target.family == "k8s_control_plane_error"


@pytest.mark.asyncio
async def test_reanalysis_stops_when_a_followup_adds_no_evidence(monkeypatch) -> None:
    state = pipeline.new_state(llm_settings(), _request(), collectors=[])
    state.plan = InvestigationPlan(hypotheses=[{"family": "image_pull_error"}])
    state.root_cause_candidates = [RankedCause("image_pull_error", "low", 2.5)]
    calls = 0

    async def same_evidence(_state, *, target):
        nonlocal calls
        calls += 1
        return pipeline._ReanalysisOutcome(
            results=list(_state.results),
            candidates=[RankedCause(target.family, "low", 2.5)],
            ranking_candidate=RankedCause(target.family, "low", 2.5),
            investigation_context={"hypothesis_ledger": []},
            caveat="",
            note="",
            refuted=False,
            next_check="",
            fresh_support_families=(),
        )

    monkeypatch.setattr(pipeline, "_reanalyze_once", same_evidence)

    await pipeline._investigate_until_settled(state)

    assert calls == 1


def test_confidence_diagnostics_keep_ranking_self_check_and_harness_stages_separate() -> None:
    state = pipeline.new_state(make_settings(), _request(), collectors=[])
    state.ranking_candidate_before_self_check = RankedCause(
        "image_pull_error", "high", 6.0
    )
    state.root_cause_candidates = [RankedCause("image_pull_error", "low", 6.0)]
    state.self_check_confidence_before = "high"
    state.self_check_confidence_after = "medium"
    before_harness = RankedCause("image_pull_error", "medium", 6.0)

    diagnostics = pipeline._confidence_diagnostics(
        state,
        harness={"status": "abstained", "overall_score": 68},
        candidate_before_harness=before_harness,
    )

    assert diagnostics["ranking_candidate"]["confidence"] == "high"
    assert diagnostics["pre_harness_candidate"]["confidence"] == "medium"
    assert diagnostics["final_candidate"]["confidence"] == "low"
    assert diagnostics["self_check"]["confidence_after"] == "medium"
    assert diagnostics["harness"]["overall_score"] == 68


@pytest.mark.asyncio
async def test_reanalysis_failure_falls_back_to_first_result(monkeypatch) -> None:
    _stub_llm_http(monkeypatch)
    investigate_calls: list[int] = []
    refute_calls: list[str] = []
    _install_stubs(
        monkeypatch,
        verdicts=[
            {
                "confidence": "low",
                "caveat": "First doubt stands.",
                "refuted": True,
                "next_check": "Check kubelet pressure directly.",
            },
        ],
        investigate_calls=investigate_calls,
        refute_calls=refute_calls,
        fail_second_investigate=True,
    )

    orchestrator = AnalysisOrchestrator(llm_settings())
    response = await orchestrator.analyze(_request())

    # Re-analysis was attempted once and blew up. The already-ranked alternative
    # is self-checked as a bounded fallback; the same stub refutes it too, so the
    # pipeline must abstain rather than restoring the first refuted family.
    assert len(investigate_calls) == 2
    assert len(refute_calls) == 2
    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "insufficient_evidence"
    assert "First doubt stands." in response.analysis_detail
    assert "re-analysis pass was performed" not in response.analysis_detail
    # Still refuted -> the honest operator-questions section appears (en settings),
    # leading with the self-check's settling check.
    assert "## Questions for the Operator" in response.analysis_detail
    assert "Check kubelet pressure directly." in response.analysis_detail


@pytest.mark.asyncio
async def test_insufficient_evidence_adds_korean_questions_without_llm() -> None:
    # No LLM, all collectors unconfigured -> insufficient_evidence + Korean questions.
    settings = replace(make_settings(), language="ko")
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_signatureless_request())

    top = response.context["root_cause_candidates"][0]
    assert top["family"] == "insufficient_evidence"
    assert "## 추가 확인 요청" in response.analysis_detail
    section = response.analysis_detail.split("## 추가 확인 요청", 1)[1]
    section = section.split("\n## ", 1)[0]
    questions = [line for line in section.splitlines() if line.startswith("- ")]
    assert 2 <= len(questions) <= 4
    assert any("확인해 주세요" in q for q in questions)


@pytest.mark.asyncio
async def test_llm_sharpened_operator_questions_are_single_line(monkeypatch) -> None:
    async def fake_complete_json(*_args, **_kwargs):
        return {
            "questions": [
                "Check kubelet pressure\n## injected heading\n" + ("detail " * 80),
                "Check scheduler queue token=question-secret-12345",
            ]
        }

    monkeypatch.setattr(pipeline, "complete_json", fake_complete_json)
    settings = replace(llm_settings(), llm_model_synthesis="m")
    questions = await pipeline._operator_questions(
        settings,
        ["loki.query"],
        None,
        AnalysisTarget("", "", "", "", "", "", "", "", "", "warning", "X"),
        "next check\n## bad",
    )

    assert len(questions) == 2
    assert all("\n" not in question for question in questions)
    assert questions[0].endswith("…")
    assert "question-secret-12345" not in "\n".join(questions)
    assert "[MASKED]" in "\n".join(questions)


@pytest.mark.asyncio
async def test_operator_question_prompt_includes_already_executed_queries(monkeypatch) -> None:
    captured: dict[str, str] = {}

    async def fake_complete_json(*_args, system, user, **_kwargs):
        captured["system"] = system
        captured["user"] = user
        return {"questions": ["Which remaining pod event is missing?", "Which queue state is missing?"]}

    monkeypatch.setattr(pipeline, "complete_json", fake_complete_json)
    await pipeline._operator_questions(
        llm_settings(),
        ["kubernetes.events"],
        None,
        AnalysisTarget("", "", "", "", "", "", "", "", "", "warning", "X"),
        "Check the remaining evidence gap.",
        ["kubectl rollout status deployment/permission-manager -n permission-manager"],
    )

    assert "Do not ask the operator to run checks equivalent" in captured["system"]
    assert "kubectl rollout status deployment/permission-manager -n permission-manager" in captured["user"]


@pytest.mark.asyncio
async def test_no_llm_keeps_behavior_no_reanalysis(monkeypatch) -> None:
    # LLM off (even with the loop flag on): investigate is never used and no
    # re-analysis note appears — current no-LLM behavior.
    investigate_calls: list[int] = []

    async def fake_investigate(*args, **kwargs):  # pragma: no cover - must not run
        investigate_calls.append(1)
        return []

    monkeypatch.setattr("app.services.investigator.investigate", fake_investigate)
    settings = replace(make_settings(), enable_investigation_loop=True)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.analyze(_signatureless_request())

    assert investigate_calls == []
    assert "재분석" not in response.analysis_detail
    assert "re-analysis pass was performed" not in response.analysis_detail
    # English deterministic questions still appear for the unsettled RCA.
    assert "## Questions for the Operator" in response.analysis_detail
