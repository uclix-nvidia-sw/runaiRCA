"""The alert's OWN text is evidence. An NVRM Xid alert names the fault
("XID 79 ... GPU has fallen off the bus") in its labels/annotations — signature
matching and XID drill-down must see it even when every collector comes back
empty (the exact production case: system agent unreachable, loki failed)."""

from __future__ import annotations

from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import _alert_text, _observed_text, _xid_codes_from_results


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
