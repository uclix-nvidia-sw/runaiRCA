"""The alert's OWN text is evidence. An NVRM Xid alert names the fault
("XID 79 ... GPU has fallen off the bus") in its labels/annotations — signature
matching and XID drill-down must see it even when every collector comes back
empty (the exact production case: system agent unreachable, loki failed)."""

from __future__ import annotations

from app.collectors.base import CollectorResult, artifact
from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.schemas import Alert, AlertAnalysisRequest
from app.services.pipeline import (
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


def test_xid_code_extracted_from_drilldown_artifact() -> None:
    # Drill-down can be the first place a GPU fault appears; it must still feed
    # XID promotion and graph remediation, not just the appendix evidence card.
    result = CollectorResult(agent="system", status="ok", summary="checked dmesg")
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="dmesg returned signals: **Xid 79**",
            result={"lines": ["NVRM: Xid 79 GPU has fallen off the bus"]},
        )
    )
    assert _xid_codes_from_results([result]) == [79]


def test_xid_code_extracted_from_structured_artifact_value() -> None:
    result = CollectorResult(agent="system", status="ok", summary="checked dcgm")
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="dcgm returned a structured fault",
            result={"xid": 79, "status": "faulted"},
        )
    )
    assert _xid_codes_from_results([result]) == [79]


def test_xid_code_ignores_structured_context_only_text() -> None:
    # A current/live snapshot can mention an old Xid in its summary, payload, or
    # details.  Once a collector emits observations, only a present+scoped one
    # may promote the GPU root cause.
    result = CollectorResult(
        agent="system",
        status="ok",
        summary="current dmesg still contains Xid 79",
        details={"last_dmesg_line": "NVRM: Xid 79 GPU has fallen off the bus"},
    )
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="node_logs",
            status="ok",
            confidence="low",
            summary="current log snapshot mentions Xid 79",
            result={
                "lines": ["NVRM: Xid 79 GPU has fallen off the bus"],
                "observation": {"polarity": "unknown", "coverage": "partial"},
            },
        )
    )
    assert _xid_codes_from_results([result]) == []


def test_xid_code_uses_structured_scoped_positive_observation() -> None:
    result = CollectorResult(agent="system", status="ok", summary="checked incident journal")
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="node_logs",
            status="ok",
            confidence="high",
            summary="incident journal contains Xid 79",
            result={
                "lines": ["NVRM: Xid 79 GPU has fallen off the bus"],
                "observation": {"polarity": "present", "coverage": "scoped"},
            },
        )
    )
    assert _xid_codes_from_results([result]) == [79]


def test_unavailable_artifact_xid_is_not_evidence() -> None:
    result = CollectorResult(agent="system", status="ok", summary="dcgm query failed")
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="drilldown_query",
            status="unavailable",
            confidence="low",
            summary="failed query mentioned Xid 79",
            result={"xid": 79, "error": "connection refused"},
        )
    )
    assert _xid_codes_from_results([result]) == []


def test_unavailable_collector_xid_summary_is_not_evidence() -> None:
    result = CollectorResult(
        agent="system",
        status="unavailable",
        summary="system agent failed before evidence; error mentioned Xid 79",
    )
    assert _xid_codes_from_results([result]) == []


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
    from app.services.pipeline import _promote_signature_cause

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
    # signature agreeing with the ranker keeps the ranked family and adds signature support
    agree = [("node_kubelet_pressure", {"symptom": "Node Disk Pressure"})]
    out = _promote_signature_cause(ranked, [], [], agree)
    assert out[0].family == "node_kubelet_pressure"
    assert out[0].score == 7.0
    assert out[0].rationale == ["matched curated symptom: Node Disk Pressure"]
    assert out[0].evidence_agents == ["signature"]
    # nothing matched -> ranker stands
    assert _promote_signature_cause(ranked, [], [], [])[0].family == "node_kubelet_pressure"


def test_lifecycle_symptom_promotion_is_gated_by_active_signal() -> None:
    # A coincidental, unrelated rollout injects "mid-rollout" into observed text and
    # matches the lifecycle symptom. Without the gate it would promote
    # platform_lifecycle_change over a genuine fault. The gate drops lifecycle
    # symptom matches unless the component-chain lifecycle signal is active.
    from app.services.pipeline import _gate_lifecycle_symptoms, _promote_signature_cause

    ranked = [RankedCause(family="node_kubelet_pressure", confidence="high", score=9.0)]
    sym = [("platform_lifecycle_change", {"symptom": "Controller Rollout In Progress"})]

    # inactive (or absent) lifecycle -> lifecycle symptom is dropped, ranker stands
    gated = _gate_lifecycle_symptoms(sym, {"active": False})
    assert gated == []
    assert _promote_signature_cause(ranked, [], [], gated)[0].family == "node_kubelet_pressure"
    assert _gate_lifecycle_symptoms(sym, None) == []

    # a NON-lifecycle symptom is never gated
    other = [("gpu_hardware_error", {"symptom": "GPU Fallen Off The Bus"})]
    assert _gate_lifecycle_symptoms(other, {"active": False}) == other

    # active lifecycle -> lifecycle symptom passes through and can promote
    passed = _gate_lifecycle_symptoms(sym, {"active": True, "components": ["x"]})
    assert passed == sym
    assert (
        _promote_signature_cause(ranked, [], [], passed)[0].family
        == "platform_lifecycle_change"
    )
