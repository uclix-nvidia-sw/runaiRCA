from __future__ import annotations

import pytest

from app.collectors.base import CollectorResult, artifact
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.harness import assign_evidence_ids
from app.services.root_cause_ranking import RankedCause


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "KubePodNotReady"})
    )


def _result(reason: str, message: str, *, event: bool = False) -> CollectorResult:
    payload = (
        {
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "events": [
                {
                    "type": "Warning",
                    "reason": reason,
                    "count": 3,
                    "target_identity_verified": True,
                    "message": message,
                }
            ],
        }
        if event
        else {
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "containers": [
                {
                    "name": "main",
                    "state": {"phase": "waiting", "reason": reason, "message": message},
                }
            ],
        }
    )
    item = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_warning_events" if event else "kubernetes_container_lifecycle",
        status="ok",
        confidence="high",
        summary="typed state",
        result=payload,
    )
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="typed state", artifacts=[item]
    )
    assign_evidence_ids([result])
    return result


def _candidate(reason: str, family: str) -> RankedCause:
    return RankedCause(
        family,
        "high",
        9.0,
        mechanism=(
            f"typed container state {reason} on the alert Pod "
            "(machine-reported, not keyword-matched)"
        ),
    )


@pytest.mark.parametrize(
    ("reason", "family", "message", "event", "ko", "en"),
    [
        (
            "CreateContainerConfigError",
            "workload_startup_error",
            'configmap "app-config" not found',
            False,
            "ConfigMap 'app-config'",
            "ConfigMap 'app-config'",
        ),
        (
            "StartError",
            "workload_startup_error",
            'exec: "missing-bin": executable file not found in $PATH',
            False,
            "command/entrypoint가 잘못되었습니다",
            "command/entrypoint is invalid",
        ),
        (
            "OOMKilled",
            "workload_runtime_error",
            "",
            False,
            "OOM kill(exit 137)",
            "OOM-killed it (exit 137)",
        ),
        (
            "Unschedulable",
            "k8s_scheduling_error",
            "0/3 nodes are available: 3 node(s) didn't match Pod's node affinity/selector",
            True,
            "nodeSelector/affinity 불일치",
            "nodeSelector/affinity mismatch",
        ),
        (
            "ErrImagePull",
            "image_pull_error",
            "pull access denied: authentication required",
            True,
            "registry 인증 실패",
            "registry authentication failed",
        ),
    ],
)
def test_typed_headline_includes_specific_cause_in_both_languages(
    reason: str, family: str, message: str, event: bool, ko: str, en: str
) -> None:
    result = _result(reason, message, event=event)
    candidate = _candidate(reason, family)

    korean = pipeline._ranked_root_cause_statement(
        [candidate], _request(), results=[result], eligible_evidence_ids={"E01"}, language="ko"
    )
    english = pipeline._ranked_root_cause_statement(
        [candidate], _request(), results=[result], eligible_evidence_ids={"E01"}
    )

    assert ko in korean
    assert en in english


def test_unknown_typed_reason_never_invents_specific_cause() -> None:
    result = _result("UnrecognizedReason", 'configmap "app-config" not found')
    headline = pipeline._ranked_root_cause_statement(
        [_candidate("UnrecognizedReason", "workload_startup_error")],
        _request(),
        results=[result],
        eligible_evidence_ids={"E01"},
        language="ko",
    )

    assert "app-config" not in headline
    assert "구체적으로는" not in headline


def test_ineligible_probe_message_never_supplies_specific_cause() -> None:
    result = _result("StartError", "")
    probe = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_probe",
        status="ok",
        confidence="high",
        summary="probe",
        result={"message": 'configmap "app-config" not found'},
    )
    result.artifacts.append(probe)
    assign_evidence_ids([result])
    headline = pipeline._ranked_root_cause_statement(
        [_candidate("StartError", "workload_startup_error")],
        _request(),
        results=[result],
        eligible_evidence_ids={"E01"},
        language="ko",
    )

    assert "app-config" not in headline
    assert "구체적으로는" not in headline


def test_response_model_carries_specific_cause_field() -> None:
    """The pipeline assigns response.specific_cause during assembly; a missing
    field on AlertAnalysisResponse raises ValueError on EVERY analysis, and the
    presentation tests above never exercise that path — pin it here."""
    from app.schemas import AlertAnalysisResponse

    assert "specific_cause" in AlertAnalysisResponse.model_fields
    response = AlertAnalysisResponse.model_construct()
    response.specific_cause = "구체적 원인"
    assert response.specific_cause == "구체적 원인"


def test_unschedulable_condition_supplies_specific_cause() -> None:
    """The injected nodeSelector fault: the PodScheduled=False artifact must
    both promote the typed state AND surface the scheduler's mismatch verdict."""
    from dataclasses import replace

    from app.collectors.kubernetes import _pod_scheduling_artifact
    from tests.test_orchestrator import make_settings, make_target

    target = replace(make_target(), pod="scheduling-error", namespace="default")
    pod_object = {
        "metadata": {"name": "scheduling-error", "namespace": "default"},
        "status": {
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": (
                        "0/7 nodes are available: 4 node(s) didn't match Pod's "
                        "node affinity/selector."
                    ),
                }
            ]
        },
    }
    item = _pod_scheduling_artifact("kubernetes", make_settings(), target, pod_object)
    assert item is not None
    result = CollectorResult(agent="kubernetes", status="ok", summary="k8s", artifacts=[item])
    assign_evidence_ids([result])
    eligible = {item.evidence_id}
    family, mechanism, ids = pipeline._dispositive_typed_state([result], eligible)
    assert family == "k8s_scheduling_error"
    assert "Unschedulable" in mechanism
    headline = pipeline._ranked_root_cause_statement(
        [_candidate("Unschedulable", "k8s_scheduling_error")],
        _request(),
        results=[result],
        eligible_evidence_ids=eligible,
        language="ko",
    )
    assert "nodeSelector/affinity 불일치" in headline
