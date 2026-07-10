from __future__ import annotations

from app.collectors.base import CollectorResult, artifact
from app.schemas import AlertAnalysisResponse
from app.services.harness import apply_safety_guardrail, apply_trace, assign_evidence_ids, evaluate
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


def test_trace_repair_uses_response_local_evidence_ids() -> None:
    results = [_result("loki"), _result("system")]
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


def test_high_confidence_needs_two_live_agents_or_signature() -> None:
    results = [_result("loki")]
    assign_evidence_ids(results)
    verdict = evaluate(
        _response(),
        results,
        [RankedCause("gpu_hardware_error", "high", 9, evidence_agents=["loki"])],
    )
    assert verdict.gates["unsupported_high_confidence"] is True


def test_dangerous_action_is_repaired_with_a_preceding_guardrail() -> None:
    response = _response("## Recommended Actions\n\n- kubectl delete pod broken-pod")
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is True
    assert apply_safety_guardrail(response) is True
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is False


def test_safety_guardrail_covers_a_long_report() -> None:
    response = _response("x" * 600 + "\n- kubectl delete pod broken-pod")

    assert apply_safety_guardrail(response) is True
    assert evaluate(response, [], []).gates["unsafe_action_without_guardrail"] is False
