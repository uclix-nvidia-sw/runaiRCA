from __future__ import annotations

from app.collectors.base import CollectorResult, artifact
from app.services.pipeline import _lifecycle_signal


def _change(changes: list[dict]) -> CollectorResult:
    return CollectorResult(
        agent="change",
        status="ok",
        summary="recent changes",
        details={"changes": changes},
        artifacts=[
            artifact(
                agent="change",
                source="kubernetes",
                type="change_detection",
                status="ok",
                confidence="high",
                summary="incident-window change",
                result={"observation": {"polarity": "present", "coverage": "scoped"}},
            )
        ],
    )


def test_lifecycle_signal_upstream_only_is_not_target_rollout() -> None:
    # The alert's own component (runai-container-toolkit) is NOT rolling, but an
    # upstream dependency (gpu-operator) is. Signal is active via the chain, but
    # not dispositive (target_rollout False).
    results = [
        _change(
            [
                {"name": "gpu-operator", "kind": "Deployment", "rollout": True,
                 "namespace": "gpu-operator", "summary": "mid-rollout"},
            ]
        )
    ]
    signal = _lifecycle_signal(
        results,
        component="runai-container-toolkit",
        chain=["runai-container-toolkit", "gpu-operator"],
    )
    assert signal.get("active") is True
    assert signal.get("components") == ["gpu-operator"]
    assert signal.get("target_rollout") is False


def test_lifecycle_signal_uncorroborated_lag_is_not_target_rollout() -> None:
    signal = _lifecycle_signal(
        [_change([{"name": "trainer", "kind": "Deployment", "rollout": True,
                   "corroborated": False}])],
        component="trainer",
        chain=["trainer"],
    )
    assert signal.get("active") is True
    assert signal.get("target_rollout") is False


def test_lifecycle_signal_corroborated_rollout_is_target_rollout() -> None:
    signal = _lifecycle_signal(
        [_change([{"name": "trainer", "kind": "Deployment", "rollout": True,
                   "corroborated": True}])],
        component="trainer",
        chain=["trainer"],
    )
    assert signal.get("target_rollout") is True


def test_lifecycle_signal_helm_corroborates_rollout() -> None:
    signal = _lifecycle_signal(
        [_change([
            {"name": "trainer", "kind": "Deployment", "rollout": True,
             "corroborated": False},
            {"name": "trainer", "kind": "HelmRelease", "rollout": True},
        ])],
        component="trainer",
        chain=["trainer"],
    )
    assert signal.get("target_rollout") is True


def test_lifecycle_signal_missing_corroboration_is_legacy_target_rollout() -> None:
    signal = _lifecycle_signal(
        [_change([{"name": "trainer", "kind": "Deployment", "rollout": True}])],
        component="trainer",
        chain=["trainer"],
    )
    assert signal.get("target_rollout") is True


def test_lifecycle_signal_surfaces_helm_note() -> None:
    results = [
        _change(
            [
                {"name": "gpu-operator", "kind": "HelmRelease", "rollout": True,
                 "namespace": "gpu-operator", "revision": 3,
                 "helm_status": "pending-upgrade",
                 "summary": "Helm release gpu-operator revision 3 is pending-upgrade"},
            ]
        )
    ]
    signal = _lifecycle_signal(
        results,
        component="runai-container-toolkit",
        chain=["runai-container-toolkit", "gpu-operator"],
    )
    assert signal.get("active") is True
    assert signal.get("helm")
    assert "pending-upgrade" in signal["helm"][0]


def test_lifecycle_signal_unrelated_rollout_is_inactive() -> None:
    # A rollout of a component NOT in the chain must not trip the signal.
    results = [
        _change(
            [
                {"name": "unrelated-deploy", "kind": "Deployment", "rollout": True,
                 "namespace": "runai", "summary": "mid-rollout"},
            ]
        )
    ]
    signal = _lifecycle_signal(
        results,
        component="runai-container-toolkit",
        chain=["runai-container-toolkit", "gpu-operator"],
    )
    assert signal == {}


def test_lifecycle_signal_no_change_collector_is_empty() -> None:
    assert _lifecycle_signal([], component="x", chain=["x"]) == {}


def test_lifecycle_signal_rejects_partial_live_change_context() -> None:
    result = _change(
        [{"name": "gpu-operator", "kind": "Deployment", "rollout": True}]
    )
    result.artifacts[0].result["observation"] = {
        "polarity": "present",
        "coverage": "partial",
    }

    assert _lifecycle_signal(
        [result], component="gpu-operator", chain=["gpu-operator"]
    ) == {}
