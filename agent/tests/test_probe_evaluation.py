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


def test_oom_probe_supports_from_last_state_even_while_running() -> None:
    # INC-1785219127694654485: the crash_oomkilled probe reused the startup
    # anchor's vocabulary — no OOM support token, and "Running" as a refuter —
    # so a restarted pod whose lastState records the OOM came back
    # inconclusive despite perfect evidence. The tree now gives that probe its
    # own vocabulary; replay the exact shape here.
    import yaml

    tree = yaml.safe_load(open("knowledge/k8s_troubleshooting_tree.yaml"))
    nodes = tree["nodes"] if isinstance(tree, dict) else tree
    oom_probe = next(
        probe
        for node in nodes
        if isinstance(node, dict) and node.get("id") == "crash_oomkilled"
        for probe in node.get("probes") or []
    )
    outcome = {
        "result": {
            "containers": [
                {
                    "state": {"running": {"startedAt": "2026-07-28T06:00:00Z"}},
                    "lastState": {
                        "terminated": {"reason": "OOMKilled", "exitCode": 137}
                    },
                    "restartCount": 4,
                }
            ]
        }
    }
    assessment = evaluate_probe(oom_probe, outcome)
    assert assessment.verdict == "supports"
    assert assessment.support_signals == ("OOMKilled",)
