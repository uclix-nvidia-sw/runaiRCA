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


def _signature_result(family: str, *markers: str) -> CollectorResult:
    """An alert_signature card exactly as _alert_signature_evidence_result builds it."""
    item = artifact(
        agent="alert",
        source="alertmanager",
        type="alert_signature",
        status="ok",
        confidence="high",
        summary="Alert payload explicitly reported " + ", ".join(markers) + ".",
        result={
            "matched_signals": list(markers),
            "observation": {
                "predicate": f"alert_signature:{family}",
                "polarity": "present",
                "coverage": "scoped",
                "observed_entity": {"kind": "alert", "name": "fp-1"},
            },
        },
    )
    result = CollectorResult(
        agent="alert", status="ok", summary="alert signature", artifacts=[item]
    )
    assign_evidence_ids([result])
    return result


def _ranked(family: str, mechanism: str) -> RankedCause:
    return RankedCause(family, "high", 9.0, mechanism=mechanism)


def test_warning_event_ranking_still_names_the_missing_object():
    # Ranking settled on the family through a Warning event, so there is no
    # "typed container state ..." mechanism — the headline must still be concrete.
    result = _result(
        "CreateContainerConfigError", 'secret "app-secret" not found', event=True
    )
    eligible = {result.artifacts[0].evidence_id}
    headline = pipeline._ranked_root_cause_statement(
        [_ranked("workload_startup_error", "warning event CreateContainerConfigError")],
        _request(),
        results=[result],
        eligible_evidence_ids=eligible,
        language="ko",
    )
    assert "Secret 'app-secret'" in headline
    assert headline.index("Secret 'app-secret'") < headline.index("분류:")


def test_alert_signature_ranking_names_the_missing_object():
    # The alert payload itself asserted the reason; the object name lives in the
    # annotation text the signature was asserted from.
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubeContainerWaiting"},
            annotations={
                "description": 'CreateContainerConfigError: secret "app-secret" not found'
            },
            fingerprint="fp-1",
        )
    )
    result = _signature_result("workload_startup_error", "CreateContainerConfigError")
    eligible = {result.artifacts[0].evidence_id}
    headline = pipeline._ranked_root_cause_statement(
        [_ranked("workload_startup_error", "alert signature CreateContainerConfigError")],
        request,
        results=[result],
        eligible_evidence_ids=eligible,
        language="ko",
    )
    assert "Secret 'app-secret'" in headline


def test_alert_signature_outside_eligible_evidence_is_not_used():
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubeContainerWaiting"},
            annotations={
                "description": 'CreateContainerConfigError: secret "app-secret" not found'
            },
            fingerprint="fp-1",
        )
    )
    result = _signature_result("workload_startup_error", "CreateContainerConfigError")
    assert (
        pipeline._specific_cause_statement(
            _ranked("workload_startup_error", "alert signature"),
            [result],
            set(),
            language="ko",
            request=request,
        )
        == ""
    )


def test_runbook_text_never_supplies_the_headline():
    # Probe/runbook wording is hypothesis guidance, never incident evidence.
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubeContainerWaiting"},
            annotations={
                "runbook_url": 'https://wiki/secret "app-secret" not found',
                "summary": "container waiting",
            },
            fingerprint="fp-1",
        )
    )
    result = _signature_result("workload_startup_error", "CreateContainerConfigError")
    eligible = {result.artifacts[0].evidence_id}
    detail = pipeline._specific_cause_statement(
        _ranked("workload_startup_error", "alert signature"),
        [result],
        eligible,
        language="ko",
        request=request,
    )
    assert "app-secret" not in detail


def test_specific_cause_leads_and_family_becomes_the_classification():
    result = _result("CreateContainerConfigError", 'secret "app-secret" not found')
    eligible = {result.artifacts[0].evidence_id}
    headline = pipeline._ranked_root_cause_statement(
        [_candidate("CreateContainerConfigError", "workload_startup_error")],
        _request(),
        results=[result],
        eligible_evidence_ids=eligible,
        language="ko",
    )
    assert "가장 가능성 높은 원인은" not in headline
    assert "(분류:" in headline
