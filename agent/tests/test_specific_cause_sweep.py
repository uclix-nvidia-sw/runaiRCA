"""Closed typed reasons always render grounded bilingual detail."""

from __future__ import annotations

import pytest

from app.collectors.base import CollectorResult, artifact
from app.services import pipeline
from app.services.harness import assign_evidence_ids
from app.services.root_cause_ranking import RankedCause


def _result(reason: str, message: str) -> CollectorResult:
    item = artifact(
        agent="kubernetes", source="kubernetes", type="kubernetes_container_lifecycle",
        status="ok", confidence="high", summary="typed state",
        result={
            "observation": {"polarity": "present", "coverage": "scoped", "target_identity_verified": True},
            "containers": [{"name": "main", "state": {"phase": "waiting", "reason": reason, "message": message}}],
        },
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="typed state", artifacts=[item])
    assign_evidence_ids([result])
    return result


def _candidate(reason: str, family: str) -> RankedCause:
    return RankedCause(
        family, "high", 9.0,
        mechanism=f"typed container state {reason} on the alert Pod (machine-reported, not keyword-matched)",
    )


CASES = [
    ("CreateContainerConfigError", "workload_startup_error", 'configmap "app-config" not found', "app-config"),
    ("CreateContainerConfigError", "workload_startup_error", 'secret "app-secret" not found', "app-secret"),
    ("StartError", "workload_startup_error", 'exec: "missing-bin": executable file not found in $PATH', "missing-bin"),
    ("StartError", "workload_startup_error", 'exec /srv/app: no such file or directory', ""),
    ("RunContainerError", "workload_startup_error", 'exec: "serve": executable file not found in $PATH', "serve"),
    ("RunContainerError", "workload_startup_error", 'permission denied while starting /app/serve', ""),
    ("ContainerCannotRun", "workload_startup_error", 'exec: "worker": executable file not found in $PATH', "worker"),
    ("ContainerCannotRun", "workload_startup_error", 'container init: permission denied', ""),
    ("CrashLoopBackOff", "workload_startup_error", 'back-off 5m0s restarting failed container', ""),
    ("CrashLoopBackOff", "workload_startup_error", 'back-off restarting failed container api', ""),
    ("OOMKilled", "workload_runtime_error", 'container exceeded memory limit', ""),
    ("OOMKilled", "workload_runtime_error", 'memory cgroup out of memory', ""),
    ("Unschedulable", "k8s_scheduling_error", "0/5 nodes are available: 5 insufficient nvidia.com/gpu.", "nvidia.com/gpu"),
    ("Unschedulable", "k8s_scheduling_error", "0/3 nodes are available: 3 node(s) had untolerated taint.", ""),
    ("SchedulingGated", "k8s_scheduling_error", "0/2 nodes are available: 2 insufficient cpu.", "cpu"),
    ("SchedulingGated", "k8s_scheduling_error", "0/3 nodes are available: 3 node(s) had untolerated taint.", ""),
    ("ImagePullBackOff", "image_pull_error", 'failed to pull image "registry.example/app:v1": rpc error: code = notfound desc = failed to pull and unpack image "registry.example/app:v1": not found', "registry.example/app:v1"),
    ("ImagePullBackOff", "image_pull_error", 'failed to pull image "registry.example/app:v2": unauthorized: authentication required', "registry.example/app:v2"),
    ("ErrImagePull", "image_pull_error", 'failed to pull image "registry.example/api:v1": manifest unknown', "registry.example/api:v1"),
    ("ErrImagePull", "image_pull_error", 'failed to pull image "registry.example/api:v2": pull access denied', "registry.example/api:v2"),
    ("CreateContainerError", "workload_startup_error", "failed to create containerd task: context deadline exceeded", ""),
    ("CreateContainerError", "workload_startup_error", "failed to create container runtime task", ""),
    ("InvalidImageName", "image_pull_error", 'failed to apply default image tag "repo//app": invalid reference format', "repo//app"),
    ("InvalidImageName", "image_pull_error", 'couldn\'t parse image name "bad@@image": invalid reference format', "bad@@image"),
    ("ErrImageNeverPull", "image_pull_error", 'container image "registry.example/offline:v1" is not present with pull policy of Never', "registry.example/offline:v1"),
    ("ErrImageNeverPull", "image_pull_error", 'image "registry.example/offline:v2" is not present with pull policy of Never', "registry.example/offline:v2"),
]


@pytest.mark.parametrize(("reason", "family", "message", "fragment"), CASES)
def test_every_closed_typed_reason_has_grounded_bilingual_detail(
    reason: str, family: str, message: str, fragment: str
) -> None:
    result = _result(reason, message)
    candidate = _candidate(reason, family)
    ko = pipeline._specific_cause_statement(candidate, [result], {"E01"}, language="ko")
    en = pipeline._specific_cause_statement(candidate, [result], {"E01"}, language="en")
    assert ko and en
    if fragment:
        assert fragment in ko and fragment in en


def test_unknown_typed_reason_has_no_specific_cause() -> None:
    result = _result("UnknownReason", 'secret "app-secret" not found')
    assert not pipeline._specific_cause_statement(
        _candidate("UnknownReason", "workload_startup_error"), [result], {"E01"}, language="ko"
    )


@pytest.mark.parametrize(
    ("reason", "family"),
    sorted({(reason, family) for reason, family, _message, _fragment in CASES}),
)
def test_unknown_message_uses_that_reason_generic_detail(reason: str, family: str) -> None:
    result = _result(reason, "unrecognized kubelet message variant")
    assert pipeline._specific_cause_statement(
        _candidate(reason, family), [result], {"E01"}, language="ko"
    )
