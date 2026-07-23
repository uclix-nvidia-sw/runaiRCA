"""Regression: a Kubernetes container reason is a CLOSED kubelet enum and must be
matched structurally (exact token -> family), never by substring keyword grep.

Reproduces incident INC-...-000002: a Pod stuck in CreateContainerConfigError
(restartCount=0, never started, never terminated) whose two smoking-gun
artifacts each fell through a different keyword gate, forcing insufficient_evidence.
"""

from __future__ import annotations

from dataclasses import replace

from app.collectors.base import artifact
from app.collectors.kubernetes import (
    _container_lifecycle_artifact,
    _target_waiting_fault_reason,
)
from app.services.root_cause_ranking import artifact_supports_family
from tests.test_orchestrator import make_settings, make_target


def _reason_artifact(reason: str, *, summary: str = ""):
    return artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_container_lifecycle",
        status="ok",
        confidence="high",
        summary=summary or f"reason={reason}",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "predicate": "kubernetes_target_container_lifecycle",
                "container_reason": reason.casefold(),
                "observed_entity": {"kind": "pod", "name": "configmap-error"},
            }
        },
    )


def test_structured_reason_supports_only_its_own_family() -> None:
    art = _reason_artifact("CreateContainerConfigError")
    assert artifact_supports_family("workload_startup_error", art)
    # Must NOT leak into a different family by incidental text/keyword.
    assert not artifact_supports_family("image_pull_error", art)
    assert not artifact_supports_family("gpu_hardware_error", art)


def test_structured_reason_survives_negation_landmine() -> None:
    # The kubelet message 'configmap "x" not found' contains "not", which the
    # keyword negation heuristic would have treated as a refutation and dropped.
    art = _reason_artifact(
        "CreateContainerConfigError",
        summary='Error: configmap "nonexistent-config" not found',
    )
    assert artifact_supports_family("workload_startup_error", art)


def test_imagepull_reason_maps_to_image_pull_error() -> None:
    art = _reason_artifact("ImagePullBackOff")
    assert artifact_supports_family("image_pull_error", art)
    assert not artifact_supports_family("workload_startup_error", art)


def test_target_waiting_fault_reason_ignores_benign_states() -> None:
    assert _target_waiting_fault_reason(
        [{"name": "app", "state": {"phase": "waiting", "reason": "CreateContainerConfigError"}}]
    ) == "createcontainerconfigerror"
    # ContainerCreating is a benign transient, not a fault.
    assert _target_waiting_fault_reason(
        [{"name": "app", "state": {"phase": "waiting", "reason": "ContainerCreating"}}]
    ) == ""
    assert _target_waiting_fault_reason([{"name": "app", "state": {"phase": "running"}}]) == ""


def test_stuck_container_config_error_types_present_and_supports() -> None:
    # The full collector path for the INC-000002 shape: still firing, verified
    # target, restartCount=0, no termination -> must be present/scoped support.
    target = replace(
        make_target(),
        namespace="default",
        pod="configmap-error",
        pod_uid="",
        resolved_at="",
        fired_at="2026-07-23T05:31:37Z",
    )
    diagnostics = [
        {
            "name": "app",
            "ready": False,
            "restartCount": 0,
            "started": False,
            "state": {
                "phase": "waiting",
                "reason": "CreateContainerConfigError",
                "message": 'configmap "nonexistent-config" not found',
            },
            "lastTerminated": None,
        }
    ]
    art = _container_lifecycle_artifact(
        "kubernetes",
        make_settings(),
        target,
        {"name": "configmap-error", "namespace": "default"},
        diagnostics,
        time_range={"start": "2026-07-23T05:31:37Z", "end": "2026-07-23T06:09:11Z"},
    )
    observation = art.result["observation"]
    assert observation["polarity"] == "present"
    assert observation["coverage"] == "scoped"
    assert observation["container_reason"] == "createcontainerconfigerror"
    assert artifact_supports_family("workload_startup_error", art)
