from __future__ import annotations

from app.collectors.base import CollectorResult, artifact
from app.schemas import AlertAnalysisResponse
from app.services import pipeline
from app.services.harness import assign_evidence_ids, evaluate
from app.services.root_cause_ranking import RankedCause


def _lifecycle_result(reason: str = "ImagePullBackOff", *, verified: bool = True):
    item = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_container_lifecycle",
        status="ok",
        confidence="high",
        summary="free text ImagePullBackOff",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": verified,
                "observed_entity": {"kind": "pod", "name": "trainer-0"},
            },
            "containers": [
                {
                    "name": "main",
                    "state": {"phase": "waiting", "reason": reason},
                }
            ],
        },
    )
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="ImagePullBackOff", artifacts=[item]
    )
    assign_evidence_ids([result])
    return result


def _warning_result(count: int):
    item = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_warning_events",
        status="ok",
        confidence="high",
        summary="Warning event",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "events": [
                {
                    "type": "Warning",
                    "reason": "ErrImagePull",
                    "count": count,
                    "target_identity_verified": True,
                }
            ],
        },
    )
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="ErrImagePull", artifacts=[item]
    )
    assign_evidence_ids([result])
    return result


def _candidates() -> list[RankedCause]:
    return [
        RankedCause("node_kubelet_pressure", "medium", 8.5),
        RankedCause("image_pull_error", "medium", 4.0),
    ]


def test_imagepullbackoff_lifecycle_state_promotes_image_pull_error_to_high() -> None:
    result = _lifecycle_result()
    typed = pipeline._dispositive_typed_state([result], {"E01"})
    promoted = pipeline._promote_signature_cause(
        _candidates(), [], [], [], typed_state=typed
    )

    assert typed[0] == "image_pull_error"
    assert typed[2] == ["E01"]
    assert promoted[0].family == "image_pull_error"
    assert promoted[0].confidence == "high"
    assert promoted[0].confidence_gate["force_high"] is True
    assert "signature" in promoted[0].evidence_agents
    assert promoted[0].score_breakdown[-1]["kind"] == "typed_container_state"


def test_repeated_typed_warning_event_qualifies_and_low_count_does_not() -> None:
    repeated = _warning_result(3)
    single = _warning_result(1)

    assert pipeline._dispositive_typed_state([repeated], {"E01"})[0] == "image_pull_error"
    assert pipeline._dispositive_typed_state([single], {"E01"}) == ("", "", [])


def test_free_text_and_unverified_artifacts_never_promote() -> None:
    free_text = CollectorResult(
        agent="kubernetes", status="ok", summary="ImagePullBackOff observed", artifacts=[]
    )
    unverified = _lifecycle_result(verified=False)

    assert pipeline._dispositive_typed_state([free_text], set()) == ("", "", [])
    assert pipeline._dispositive_typed_state([unverified], {"E01"}) == ("", "", [])
    assert pipeline._dispositive_typed_state([_lifecycle_result()], {"E99"}) == (
        "",
        "",
        [],
    )


def test_xid_outranks_typed_state() -> None:
    promoted = pipeline._promote_signature_cause(
        _candidates(),
        [79],
        [],
        [],
        typed_state=("image_pull_error", "typed state", ["E01"]),
    )

    assert promoted[0].family == "gpu_hardware_error"
    assert promoted[0].confidence == "high"


def _response(detail: str) -> AlertAnalysisResponse:
    return AlertAnalysisResponse(
        status="ok",
        thread_ts="",
        analysis=detail,
        analysis_summary="summary",
        analysis_detail=detail,
        analysis_type="firing",
        analysis_quality="medium",
        root_cause_family="image_pull_error",
        missing_data=[],
        warnings=[],
        capabilities={},
        context={},
        artifacts=[],
    )


def test_typed_state_high_passes_harness_unsupported_high_gate() -> None:
    result = _lifecycle_result()
    cause = pipeline._promote_signature_cause(
        _candidates(), [], [], [], typed_state=("image_pull_error", "typed state", ["E01"])
    )[0]
    response = _response("## Root Cause\n\nImage pull failed [E01].")

    supported = evaluate(response, [result], [cause])
    assert supported.gates["unsupported_high_confidence"] is False

    result.artifacts.clear()
    unsupported = evaluate(response, [result], [cause])
    assert unsupported.gates["unsupported_high_confidence"] is True
