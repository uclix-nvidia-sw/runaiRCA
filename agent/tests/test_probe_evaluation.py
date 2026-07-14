from __future__ import annotations

from app.services.probe_evaluation import evaluate_probe


def _probe() -> dict:
    return {
        "id": "volume-mount",
        "tool": "k8s_describe",
        "support_signal_any": ["FailedMount", "FailedAttachVolume"],
        "refute_signal_any": ["volume mounted successfully"],
    }


def test_probe_evaluator_supports_only_explicit_observed_signal() -> None:
    assessment = evaluate_probe(
        _probe(), {"result": {"events": [{"message": "FailedMount for pvc/data"}]}}
    )

    assert assessment.verdict == "supports"
    assert assessment.support_signals == ("FailedMount",)


def test_probe_evaluator_refutation_wins_and_ignores_query_text() -> None:
    assessment = evaluate_probe(
        _probe(),
        {
            "query": "kubectl describe pod --look-for FailedMount",
            "result": {"events": ["volume mounted successfully", "FailedMount mentioned in old runbook"]},
        },
    )

    assert assessment.verdict == "refutes"
    assert assessment.refute_signals == ("volume mounted successfully",)


def test_probe_evaluator_does_not_turn_negated_or_failed_source_into_support() -> None:
    assert evaluate_probe(
        _probe(), {"result": {"events": ["no FailedMount events for this pod"]}}
    ).verdict == "inconclusive"
    assert evaluate_probe(_probe(), {"error": "Loki unavailable"}).verdict == "unavailable"


def test_scoped_probe_evaluation_rejects_partial_remote_signal() -> None:
    assessment = evaluate_probe(
        _probe(),
        {
            # A remote adapter can describe the condition and supply these
            # convenience fields without proving complete target/window scope.
            "polarity": "present",
            "coverage": "partial",
            "result": {"events": [{"message": "FailedMount for other-pod"}]},
            "observation": {"polarity": "present", "coverage": "partial"},
        },
        require_scoped_observation=True,
    )

    assert assessment.verdict == "inconclusive"
