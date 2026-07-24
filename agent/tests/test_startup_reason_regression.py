from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult, artifact
from app.collectors.kubernetes import _container_lifecycle_artifact, _pod_scheduling_artifact
from app.plan import InvestigationPlan
from app.services.evidence_blackboard import Blackboard
from app.services.investigator import _apply_ledger_updates, investigate
from app.services.root_cause_ranking import artifact_supports_family
from tests.test_orchestrator import make_settings, make_target


def _reason_artifact(reason: str, *, phase: str, finished_at: str = ""):
    target = replace(
        make_target(),
        namespace="default",
        pod="configmap-error" if reason == "CreateContainerConfigError" else "command-error",
        fired_at="2026-07-24T04:20:00Z",
        resolved_at="",
    )
    state = {"phase": phase, "reason": reason}
    if finished_at:
        state["finishedAt"] = finished_at
    diagnostics = [
        {
            "name": "app",
            "restartCount": 0,
            "started": False,
            "state": state,
            "lastTerminated": None,
        }
    ]
    return _container_lifecycle_artifact(
        "kubernetes",
        make_settings(),
        target,
        {"name": target.pod, "namespace": target.namespace},
        diagnostics,
        time_range={
            "start": "2026-07-24T04:20:00Z",
            "end": "2026-07-24T04:30:00Z",
        },
    )


@pytest.mark.parametrize(
    ("reason", "phase", "finished_at"),
    [
        ("CreateContainerConfigError", "waiting", ""),
        ("StartError", "terminated", "2026-07-24T04:21:40Z"),
    ],
)
def test_typed_startup_reason_confirms_family_with_evidence(reason, phase, finished_at):
    lifecycle = _reason_artifact(reason, phase=phase, finished_at=finished_at)
    result = CollectorResult(
        agent="kubernetes", status="ok", summary=reason, artifacts=[lifecycle]
    )
    board = Blackboard()
    board.add_result("kubernetes", result, entity="pod:configmap-error")
    evidence_id = board.evidence_id_for(lifecycle)
    ledger = [{"id": "H1", "family": "workload_startup_error", "status": "testing"}]

    assert lifecycle.result["observation"]["polarity"] == "present"
    assert lifecycle.result["observation"]["coverage"] == "scoped"
    assert artifact_supports_family("workload_startup_error", lifecycle)

    _apply_ledger_updates(
        ledger,
        [],
        blackboard=board,
        artifacts=[lifecycle],
        eligible_support_ids={evidence_id},
    )

    assert ledger[0]["evidence_for"] == [evidence_id]


def test_current_oom_termination_confirms_runtime_family_with_evidence():
    target = replace(
        make_target(),
        namespace="default",
        pod="memory-stress",
        pod_uid="oom-pod-uid",
        fired_at="2026-07-24T04:50:00Z",
        resolved_at="",
    )
    lifecycle = _container_lifecycle_artifact(
        "kubernetes",
        make_settings(),
        target,
        {"name": target.pod, "namespace": target.namespace, "uid": target.pod_uid},
        [
            {
                "name": "stress",
                "ready": False,
                "restartCount": 0,
                "started": False,
                "state": {
                    "exitCode": 137,
                    "finishedAt": "2026-07-24T04:56:19Z",
                    "phase": "terminated",
                    "reason": "OOMKilled",
                    "startedAt": "2026-07-24T04:56:18Z",
                },
                "lastTerminated": None,
            }
        ],
        time_range={
            "start": "2026-07-24T04:50:00Z",
            "end": "2026-07-24T05:00:00Z",
        },
    )
    board = Blackboard()
    board.add_result(
        "kubernetes",
        CollectorResult(agent="kubernetes", status="ok", summary="OOMKilled", artifacts=[lifecycle]),
        entity=f"pod:{target.pod}",
    )
    evidence_id = board.evidence_id_for(lifecycle)
    ledger = [{"id": "H1", "family": "workload_runtime_error", "status": "testing"}]

    assert lifecycle.result["observation"]["container_reason"] == "oomkilled"
    assert artifact_supports_family("workload_runtime_error", lifecycle)
    _apply_ledger_updates(
        ledger,
        [],
        blackboard=board,
        artifacts=[lifecycle],
        eligible_support_ids={evidence_id},
    )
    assert ledger[0]["evidence_for"] == [evidence_id]


def test_podscheduled_unschedulable_confirms_scheduling_family_with_evidence():
    target = replace(
        make_target(),
        namespace="default",
        pod="scheduling-error",
        pod_uid="scheduling-pod-uid",
    )
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": target.pod,
            "namespace": target.namespace,
            "uid": target.pod_uid,
        },
        "spec": {
            "containers": [{"name": "nginx", "image": "nginx"}],
            "nodeSelector": {"nonexistent-label": "true"},
        },
        "status": {
            "phase": "Pending",
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": "0/7 nodes matched Pod's node affinity/selector.",
                }
            ],
        },
    }
    scheduling = _pod_scheduling_artifact(
        "kubernetes", make_settings(), target, pod
    )
    assert scheduling is not None
    board = Blackboard()
    board.add_result(
        "kubernetes",
        CollectorResult(
            agent="kubernetes", status="ok", summary="Unschedulable", artifacts=[scheduling]
        ),
        entity=f"pod:{target.pod}",
    )
    evidence_id = board.evidence_id_for(scheduling)
    ledger = [{"id": "H1", "family": "k8s_scheduling_error", "status": "testing"}]

    assert scheduling.result["observation"] == {
        "kind": "kubernetes_pod_scheduling",
        "predicate": "kubernetes_pod_scheduling",
        "polarity": "present",
        "coverage": "scoped",
        "target_identity_verified": True,
        "observed_entity": {
            "kind": "pod",
            "name": target.pod,
            "namespace": target.namespace,
        },
        "scheduling_reason": "unschedulable",
    }
    assert artifact_supports_family("k8s_scheduling_error", scheduling)
    _apply_ledger_updates(
        ledger,
        [],
        blackboard=board,
        artifacts=[scheduling],
        eligible_support_ids={evidence_id},
    )
    assert ledger[0]["evidence_for"] == [evidence_id]


@pytest.mark.asyncio
async def test_final_collector_gather_attaches_typed_support(monkeypatch):
    async def no_llm(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.services.investigator.complete_json", no_llm)
    lifecycle = _reason_artifact("CrashLoopBackOff", phase="waiting")

    class KubernetesCollector:
        async def collect(self, _target, plan=None):
            return CollectorResult(
                agent="kubernetes", status="ok", summary="CrashLoopBackOff", artifacts=[lifecycle]
            )

    results, context = await investigate(
        make_settings(),
        replace(make_target(), namespace="default", pod="command-error"),
        [KubernetesCollector()],
        InvestigationPlan(
            hypotheses=[
                {
                    "id": "H1",
                    "family": "workload_startup_error",
                    "reason": "container startup failure",
                }
            ]
        ),
        None,
        max_steps=1,
        blackboard=Blackboard(),
        deadline_monotonic=None,
    )

    assert results[0].artifacts
    assert context["hypothesis_ledger"][0]["evidence_for"]
