from __future__ import annotations

from app.collectors.base import CollectorResult, artifact
from app.schemas import AlertAnalysisResponse
from app.services.harness import (
    EvidenceLink,
    _trace_item,
    abstain,
    analysis_hash,
    apply_safety_guardrail,
    apply_trace,
    assign_evidence_ids,
    evaluate,
    validate_evidence_links,
)
from app.services.root_cause_ranking import RankedCause


def _response(detail: str = "## Root Cause\n\nA likely cause.") -> AlertAnalysisResponse:
    return AlertAnalysisResponse(
        status="ok",
        thread_ts="",
        analysis=detail,
        analysis_summary="summary",
        analysis_detail=detail,
        analysis_type="firing",
        analysis_quality="medium",
        root_cause_family="gpu_hardware_error",
        missing_data=[],
        warnings=[],
        capabilities={},
        context={},
        artifacts=[],
    )


def _result(agent: str, summary: str = "NVRM Xid 79") -> CollectorResult:
    return CollectorResult(
        agent=agent,
        status="ok",
        summary=summary,
        artifacts=[
            artifact(
                agent=agent,
                source=agent,
                type="logs",
                status="ok",
                confidence="high",
                summary=summary,
            )
        ],
    )


def _scoped_observation(polarity: str = "present") -> dict[str, object]:
    """A synthetic RCA fact must name the resource it observed."""
    return {
        "polarity": polarity,
        "coverage": "scoped",
        "observed_entity": {"kind": "pod", "name": "trainer-0"},
    }


def test_trace_repair_uses_response_local_evidence_ids() -> None:
    results = [_result("loki"), _result("system")]
    for result in results:
        result.artifacts[0].result = {
            "observation": _scoped_observation()
        }
    assign_evidence_ids(results)
    response = _response()
    cause = RankedCause(
        "gpu_hardware_error",
        "high",
        9,
        evidence_agents=["loki", "system"],
    )

    before = evaluate(response, results, [cause])
    assert before.gates["missing_evidence_trace"] is True
    assert before.gates["unsupported_high_confidence"] is False
    assert apply_trace(response, before) is True

    after = evaluate(response, results, [cause])
    assert after.gates["missing_evidence_trace"] is False
    assert "[E01]" in response.analysis_detail
    assert "[E02]" in response.analysis_detail


def test_trace_exposes_structured_evidence_verdicts() -> None:
    results = [_result("kubernetes", "CrashLoopBackOff restart counter increased")]
    results[0].artifacts[0].result = {
        "observation": _scoped_observation()
    }
    assign_evidence_ids(results)
    response = _response()
    cause = RankedCause("workload_startup_error", "medium", 5, evidence_agents=["kubernetes"])

    verdict = evaluate(response, results, [cause])
    assert verdict.trace == [
        {
            "evidence_id": "E01",
            "source": "kubernetes",
            "summary": "CrashLoopBackOff restart counter increased",
            "polarity": "present",
            "coverage": "scoped",
        }
    ]

    assert apply_trace(response, verdict) is True
    assert "observed · scoped" in response.analysis_detail


def test_unrelated_oom_predicate_cannot_ground_scheduling_family() -> None:
    result = _result("kubernetes", "OOMKilled in the workload container")
    result.artifacts[0].type = "kubernetes_pod_log"
    result.artifacts[0].result = {
        "sample_entries": [{"line": "container was OOMKilled"}],
        "observation": {
            **_scoped_observation(),
            "predicate": "kubernetes_pod_log:main",
        },
    }
    assign_evidence_ids([result])

    verdict = evaluate(
        _response("## Root Cause\n\nScheduling failed [E01]."),
        [result],
        [
            RankedCause(
                "k8s_scheduling_error",
                "medium",
                5,
                evidence_agents=["kubernetes"],
            )
        ],
    )

    assert verdict.claims[0]["supporting_evidence"] == []
    assert verdict.gates["missing_evidence_trace"] is True


def test_explicit_unrelated_support_link_is_rejected() -> None:
    result = _result("kubernetes", "OOMKilled in the workload container")
    result.artifacts[0].type = "kubernetes_pod_log"
    result.artifacts[0].result = {
        "sample_entries": [{"line": "container was OOMKilled"}],
        "observation": {
            **_scoped_observation(),
            "predicate": "kubernetes_pod_log:main",
        },
    }
    assign_evidence_ids([result])

    verdict = evaluate(
        _response("## Root Cause\n\nScheduling failed [E01]."),
        [result],
        [
            RankedCause(
                "k8s_scheduling_error",
                "medium",
                5,
                support_evidence_ids=["E01"],
            )
        ],
    )

    assert verdict.claims[0]["supporting_evidence"] == []
    assert verdict.gates["invalid_evidence_links"] is True


def test_trace_does_not_promote_loose_result_fields_to_scoped_evidence() -> None:
    item = _result("loki", "remote body says OOMKilled")
    item.artifacts[0].evidence_id = "E01"
    item.artifacts[0].result = {"polarity": "present", "coverage": "scoped"}

    trace = _trace_item(item.artifacts[0])

    assert (trace["polarity"], trace["coverage"]) == ("unknown", "unknown")


def test_legacy_agent_fallback_excludes_partial_evidence_from_support() -> None:
    scoped = _result("loki", "OOMKilled occurred during the incident")
    scoped.artifacts[0].result = {
        "observation": _scoped_observation()
    }
    partial = _result("prometheus", "current memory usage is high")
    partial.artifacts[0].result = {
        "observation": {"polarity": "present", "coverage": "partial"}
    }
    results = [scoped, partial]
    assign_evidence_ids(results)

    verdict = evaluate(
        _response("## Root Cause\n\nOOMKilled was observed [E01]."),
        results,
        [
            RankedCause(
                "workload_startup_error",
                "medium",
                5,
                evidence_agents=["loki", "prometheus"],
            )
        ],
    )

    assert verdict.claims[0]["supporting_evidence"] == ["E01"]
    assert [item["evidence_id"] for item in verdict.trace] == ["E01"]


def test_high_confidence_needs_two_live_agents_or_signature() -> None:
    results = [_result("loki")]
    assign_evidence_ids(results)
    verdict = evaluate(
        _response(),
        results,
        [RankedCause("gpu_hardware_error", "high", 9, evidence_agents=["loki"])],
    )
    assert verdict.gates["unsupported_high_confidence"] is True


def test_high_confidence_does_not_count_two_kubernetes_api_views_as_independent() -> None:
    results = [_result("kubernetes"), _result("change")]
    assign_evidence_ids(results)

    verdict = evaluate(
        _response(),
        results,
        [
            RankedCause(
                "workload_startup_error",
                "high",
                9,
                evidence_agents=["kubernetes", "change"],
            )
        ],
    )

    assert verdict.gates["unsupported_high_confidence"] is True


def test_high_confidence_query_replicas_do_not_receive_full_calibration_score() -> None:
    """Two E-ids from Loki are trace detail, not independent corroboration."""
    result = _result("loki")
    replica = artifact(
        agent="loki",
        source="loki",
        type="logs",
        status="ok",
        confidence="high",
        summary="NVRM Xid 79",
        result={"observation": _scoped_observation()},
    )
    result.artifacts.extend([replica])
    result.artifacts[0].result = {
        "observation": _scoped_observation()
    }
    assign_evidence_ids([result])

    verdict = evaluate(
        _response(),
        [result],
        [RankedCause("gpu_hardware_error", "high", 9, evidence_agents=["loki"])],
    )

    assert verdict.claims[0]["supporting_evidence"] == ["E01", "E02"]
    assert verdict.gates["unsupported_high_confidence"] is True
    assert verdict.dimensions["uncertainty_calibration"] == 2


def test_dangerous_action_is_repaired_with_a_preceding_guardrail() -> None:
    response = _response("## Recommended Actions\n\n- kubectl delete pod broken-pod")
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is True
    assert apply_safety_guardrail(response) is True
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is False


def test_safety_guardrail_covers_a_long_report() -> None:
    response = _response("x" * 600 + "\n- kubectl delete pod broken-pod")

    assert apply_safety_guardrail(response) is True
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is False


def test_typed_evidence_links_preserve_contradicting_evidence() -> None:
    results = [_result("loki"), _result("system", "NVIDIA XID errors were absent")]
    results[0].artifacts[0].result = {
        "observation": _scoped_observation()
    }
    results[1].artifacts[0].result = {
        "observation": {
            **_scoped_observation("absent"),
            "predicate": "node_log:nvidia_xid_errors",
        }
    }
    assign_evidence_ids(results)
    response = _response("## Root Cause\n\nLikely Xid [E01] despite the counter-signal [E02].")
    verdict = evaluate(
        response,
        results,
        [RankedCause("gpu_hardware_error", "high", 9)],
        evidence_links=[
            EvidenceLink("E01", "support", "Xid is present"),
            {"evidence_id": "E02", "role": "contradict", "explanation": "node appears healthy"},
        ],
    )

    assert verdict.claims[0]["supporting_evidence"] == ["E01"]
    assert verdict.claims[0]["contradicting_evidence"] == ["E02"]
    assert verdict.gates["missing_evidence_trace"] is False
    assert verdict.gates["unresolved_contradiction"] is True
    assert "tool_efficiency" not in verdict.dimensions
    assert verdict.score <= 100


def test_unrelated_positive_fact_cannot_be_linked_as_contradiction() -> None:
    result = _result("kubernetes", "OOMKilled in the workload container")
    result.artifacts[0].result = {
        "sample_entries": [{"line": "container was OOMKilled"}],
        "observation": {
            **_scoped_observation("present"),
            "predicate": "kubernetes_pod_log:main",
        },
    }
    assign_evidence_ids([result])

    verdict = evaluate(
        _response("## Root Cause\n\nScheduling failed despite OOMKilled [E01]."),
        [result],
        [RankedCause("k8s_scheduling_error", "medium", 5)],
        evidence_links=[
            {
                "evidence_id": "E01",
                "role": "contradict",
                "explanation": "an unrelated failure was observed",
            }
        ],
    )

    assert verdict.claims[0]["contradicting_evidence"] == []
    assert verdict.gates["invalid_evidence_links"] is True


def test_invalid_typed_evidence_link_is_a_hard_gate_not_an_exception() -> None:
    results = [_result("loki")]
    assign_evidence_ids(results)
    valid, errors = validate_evidence_links(
        [{"evidence_id": "unknown", "role": "support"}, {"evidence_id": "E01", "role": "made_up"}],
        ["E01"],
    )
    assert valid == []
    assert len(errors) == 2

    verdict = evaluate(
        _response(),
        results,
        [RankedCause("gpu_hardware_error", "medium", 5)],
        evidence_links=[{"evidence_id": "unknown", "role": "support"}],
    )
    assert verdict.gates["invalid_evidence_links"] is True


def test_unavailable_or_unknown_artifacts_cannot_be_linked_as_support() -> None:
    unavailable = _result("loki")
    unavailable.artifacts[0].status = "unavailable"
    unavailable.artifacts[0].summary = "transport failed"
    unknown = _result("system")
    unknown.artifacts[0].status = "pending"
    unknown.artifacts[0].summary = "incomplete collection"
    results = [unavailable, unknown]
    assign_evidence_ids(results)

    verdict = evaluate(
        _response(),
        results,
        [RankedCause("gpu_hardware_error", "medium", 5)],
        evidence_links=[
            {"evidence_id": "E01", "role": "support"},
            {"evidence_id": "E02", "role": "support"},
        ],
    )

    assert verdict.claims[0]["supporting_evidence"] == []
    assert verdict.gates["invalid_evidence_links"] is True


def test_text_only_success_cannot_bypass_typed_observation_link_gate() -> None:
    """Standalone harness use must match Blackboard's context-only fallback."""
    results = [_result("loki", "OOMKilled appeared in an untyped summary")]
    assign_evidence_ids(results)

    verdict = evaluate(
        _response("## Root Cause\n\nOOMKilled [E01]."),
        results,
        [RankedCause("workload_runtime_error", "medium", 5)],
        evidence_links=[{"evidence_id": "E01", "role": "support"}],
    )

    assert verdict.claims[0]["supporting_evidence"] == []
    assert verdict.gates["invalid_evidence_links"] is True


def test_contextual_eligibility_map_missing_an_id_fails_closed() -> None:
    """A blackboard alias miss cannot re-promote a raw scoped-positive card."""
    results = [_result("loki", "unrelated workload OOMKilled")]
    results[0].artifacts[0].result = {"observation": _scoped_observation()}
    assign_evidence_ids(results)

    verdict = evaluate(
        _response("## Root Cause\n\nOOMKilled [E01]."),
        results,
        [RankedCause("workload_runtime_error", "medium", 5)],
        evidence_links=[{"evidence_id": "E01", "role": "support"}],
        # Production passes this map after contextual target/window matching.
        # E01 being absent must mean it is unresolved/ineligible, not allowed.
        evidence_eligibility={"E02": object()},
    )

    assert verdict.claims[0]["supporting_evidence"] == []
    assert verdict.gates["invalid_evidence_links"] is True


def test_analysis_hash_changes_when_the_approved_reasoning_changes() -> None:
    response = _response()
    response.context = {
        "top_root_cause": {"mechanism": "CSI attach timeout"},
        "reasoning_trace_v2": {"hypothesis_id": "H-1", "support": ["E01"]},
    }
    first = analysis_hash(response)

    response.context["reasoning_trace_v2"] = {"hypothesis_id": "H-2", "support": ["E02"]}

    assert analysis_hash(response) != first


def test_abstain_preserves_leading_family_as_a_low_confidence_hypothesis() -> None:
    response = _response()
    candidates = [
        RankedCause(
            "gpu_hardware_error",
            "medium",
            5,
            evidence_agents=["loki"],
            support_evidence_ids=["made-up-id"],
        )
    ]
    verdict = evaluate(response, [], candidates)

    abstain(response, candidates, verdict, historical_reanalysis=True)

    assert response.root_cause_family == "insufficient_evidence"
    assert [candidate.family for candidate in candidates] == [
        "insufficient_evidence",
        "gpu_hardware_error",
    ]
    assert candidates[1].confidence == "low"
    assert candidates[1].support_evidence_ids == []
    assert response.context["provisional_root_cause"]["family"] == "gpu_hardware_error"
    assert "historical re-analysis" in response.analysis_detail
    assert "low-confidence inference" in response.analysis_detail
    assert "rather than guessing" not in response.analysis_detail


def test_abstain_without_a_candidate_does_not_invent_a_family() -> None:
    response = _response()
    candidates = [RankedCause("insufficient_evidence", "low", 0.0)]
    verdict = evaluate(response, [], candidates)

    abstain(response, candidates, verdict, historical_reanalysis=True)

    assert [candidate.family for candidate in candidates] == ["insufficient_evidence"]
    assert "provisional_root_cause" not in response.context
    assert "do not support even a specific working hypothesis" in response.analysis_detail
    assert "before selecting a family" in response.analysis_detail
