"""The alert's OWN text is evidence. An NVRM Xid alert names the fault
("XID 79 ... GPU has fallen off the bus") in its labels/annotations — signature
matching and XID drill-down must see it even when every collector comes back
empty (the exact production case: system agent unreachable, loki failed)."""

from __future__ import annotations

from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import (
    _alert_text,
    _observed_text,
    _promote_xid_cause,
    _xid_codes_from_results,
)
from app.services.root_cause_ranking import RankedCause


def _xid_request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "NVRM Xid Alert", "severity": "warning", "node": "dgx01"},
            annotations={
                "description": "dgx01 - XID 79 (PCI:0000:28:00) - GPU has fallen off the bus."
            },
            fingerprint="fp-xid",
        )
    )


def test_xid_code_extracted_from_alert_text_alone() -> None:
    # No collector evidence at all — the code must still come from the alert.
    assert _xid_codes_from_results([], _alert_text(_xid_request())) == [79]


def test_symptom_matches_from_alert_text_alone() -> None:
    fm = load_failure_modes("knowledge/failure_modes.yaml")
    observed = _observed_text([], _xid_request())
    matches = match_failure_mode_symptoms(fm, observed)
    names = {s.get("symptom") for _, s in matches}
    assert "GPU Fallen Off The Bus" in names
    assert any(f == "gpu_hardware_error" for f, _ in matches)


def test_observed_text_without_request_unchanged() -> None:
    assert _observed_text([]) == ""


def test_xid_promotes_gpu_hardware_over_keyword_noise() -> None:
    # Production complaint: XID alerts kept getting headlined node_kubelet_pressure
    # because the k8s node-conditions text ("DiskPressure ... kubelet") feeds that
    # family's keywords even when every condition is False. An XID is dispositive:
    # gpu_hardware_error must lead the candidates.
    ranked = [
        RankedCause(family="node_kubelet_pressure", confidence="medium", score=3.0),
        RankedCause(family="runai_control_plane_error", confidence="low", score=1.0),
    ]
    promoted = _promote_xid_cause(ranked, [79])
    assert promoted[0].family == "gpu_hardware_error"
    assert promoted[0].confidence == "high"
    assert "79" in promoted[0].rationale[0]
    # keyword families remain as downstream context, in order
    assert [c.family for c in promoted[1:]] == [
        "node_kubelet_pressure",
        "runai_control_plane_error",
    ]
    # no XID -> untouched
    assert _promote_xid_cause(ranked, [])[0].family == "node_kubelet_pressure"


def test_signature_promotion_beats_ranker_and_respects_precedence() -> None:
    from app.services.orchestrator import _promote_signature_cause

    ranked = [RankedCause(family="node_kubelet_pressure", confidence="medium", score=3.0)]
    # known-issue signature beats the ranker
    ki = [{"issue": "Scheduler Reclaim Panic On Large GPU Job", "family": "platform_version_bug"}]
    out = _promote_signature_cause(ranked, [], ki, [])
    assert out[0].family == "platform_version_bug"
    # curated symptom beats the ranker when no known issue matched
    sym = [("gpu_hardware_error", {"symptom": "GPU Fallen Off The Bus"})]
    out = _promote_signature_cause(ranked, [], [], sym)
    assert out[0].family == "gpu_hardware_error"
    # XID outranks both
    out = _promote_signature_cause(ranked, [79], ki, sym)
    assert out[0].family == "gpu_hardware_error" and out[0].confidence == "high"
    # signature agreeing with the ranker keeps the richer ranked entry
    agree = [("node_kubelet_pressure", {"symptom": "Node Disk Pressure"})]
    assert _promote_signature_cause(ranked, [], [], agree)[0] is ranked[0]
    # nothing matched -> ranker stands
    assert _promote_signature_cause(ranked, [], [], [])[0].family == "node_kubelet_pressure"
