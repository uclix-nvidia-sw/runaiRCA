from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult
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


def test_runai_scheduled_unschedulable_is_not_a_kube_scheduler_fault() -> None:
    """Same reason string, different subsystem.

    A Pod carrying ``schedulerName: runai-scheduler`` was judged by Run:ai, not
    kube-scheduler, so "Unschedulable" is a quota/gang/fraction verdict — not the
    taint/affinity/topology predicate failure k8s_scheduling_error describes.
    """
    from app.services.harness import assign_evidence_ids
    from app.services.pipeline import _dispositive_typed_state
    from app.services.root_cause_ranking import scheduling_reason_family

    target = replace(
        make_target(), namespace="runai-test1", pod="frac-test2-0-0", pod_uid="frac-uid"
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
            "containers": [{"name": "main", "image": "cuda"}],
            "schedulerName": "runai-scheduler",
        },
        "status": {
            "phase": "Pending",
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": "0/2 nodes are available",
                }
            ],
        },
    }
    scheduling = _pod_scheduling_artifact("kubernetes", make_settings(), target, pod)
    assert scheduling is not None

    # The owning scheduler travels INSIDE the observation, where the family
    # typing reads it — not only in the result body beside it.
    assert scheduling.result["observation"]["scheduler"] == "runai-scheduler"

    # The support gate and the dispositive signature must agree on one family.
    assert artifact_supports_family("runai_scheduling_quota", scheduling)
    assert not artifact_supports_family("k8s_scheduling_error", scheduling)

    result = CollectorResult(
        agent="kubernetes", status="ok", summary="Unschedulable", artifacts=[scheduling]
    )
    assign_evidence_ids([result])
    family, rationale, _ids = _dispositive_typed_state(
        [result], {str(scheduling.evidence_id)}
    )
    assert family == "runai_scheduling_quota"
    assert "Unschedulable" in rationale

    # kube-scheduler (and an unnamed scheduler) keep the Kubernetes family.
    assert scheduling_reason_family("Unschedulable", "default-scheduler") == (
        "k8s_scheduling_error"
    )
    assert scheduling_reason_family("Unschedulable") == "k8s_scheduling_error"


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


def _cordon_artifact():
    # RunaiNodeUnschedulableOrNotReady on a manually cordoned node: alert text
    # satisfies the causal gate, node object reports spec.unschedulable=true.
    target = replace(
        make_target(),
        namespace="",
        pod="",
        workload_name="",
        node="k8s-lb-01",
        alert_name="RunaiNodeUnschedulableOrNotReady",
        fired_at="2026-07-28T05:05:00Z",
        resolved_at="",
    )
    from app.collectors.kubernetes import _node_cordon_artifact

    artifacts = _node_cordon_artifact(
        "kubernetes",
        target,
        [{"name": "node", "data": {"name": "k8s-lb-01", "unschedulable": True}}],
        time_range={"start": "2026-07-28T05:05:00Z", "end": "2026-07-28T05:15:00Z"},
    )
    assert len(artifacts) == 1
    return artifacts[0]


def test_cordon_is_lifecycle_change_not_scheduler_fault() -> None:
    # INC-1785215448065944607-000001: a manual cordon fired
    # RunaiNodeUnschedulableOrNotReady and the cordon evidence (present) had no
    # family to support — every hypothesis drifted at 0 evidence and the run
    # ended insufficient_evidence. The typed reason routes it to the
    # administrative-change family and keeps it OUT of k8s_scheduling_error
    # (whose "unschedulable" keyword its summary text would otherwise feed).
    cordon = _cordon_artifact()
    observation = cordon.result["observation"]
    assert observation["polarity"] == "present"
    assert observation["scheduling_reason"] == "NodeNotSchedulable"
    assert artifact_supports_family("platform_lifecycle_change", cordon)
    assert not artifact_supports_family("k8s_scheduling_error", cordon)


def test_cordon_symptom_reaches_the_lifecycle_playbook() -> None:
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    fm = load_failure_modes("knowledge/failure_modes.yaml")
    matches = match_failure_mode_symptoms(
        fm,
        "node/k8s-lb-01 is cordoned (SchedulingDisabled — spec.unschedulable=true)",
    )
    assert any(family == "platform_lifecycle_change" for family, _ in matches)
    symptom = next(s for f, s in matches if f == "platform_lifecycle_change")
    assert "uncordon" in " ".join(symptom.get("actions") or [])


def _crd_artifact(reason: str, message: str = ""):
    from app.collectors.kubernetes import _runai_crd_health_artifacts
    from tests.test_orchestrator import make_settings

    artifacts = _runai_crd_health_artifacts(
        "kubernetes",
        make_settings(),
        [
            {
                "kind": "TrainingWorkload",
                "name": "train-42",
                "namespace": "runai-vision",
                "reason": reason,
                "message": message,
                "lastTransitionTime": "2026-07-28T05:10:00Z",
            }
        ],
        time_range={"start": "2026-07-28T05:05:00Z", "end": "2026-07-28T05:15:00Z"},
    )
    assert len(artifacts) == 1
    return artifacts[0]


def test_bare_runai_crd_phase_is_runai_scheduling_evidence() -> None:
    # Delivery-line audit 2026-07-28: a message-less Run:ai CRD finding either
    # supported NOTHING (Pending) or drifted to kube-scheduler's family via the
    # "unschedulable" keyword (Unschedulable). The phase is the Run:ai
    # scheduler's own verdict, so the typed channel must claim exactly
    # runai_scheduling_quota.
    for phase in ("Pending", "Unschedulable"):
        art = _crd_artifact(phase)
        assert art.result["observation"]["polarity"] == "present"
        assert artifact_supports_family("runai_scheduling_quota", art), phase
        assert not artifact_supports_family("k8s_scheduling_error", art), phase

    # A bare Failed proves the workload failed but not why: honestly ambiguous,
    # so it must stay context-only instead of guessing a family.
    bare_failed = _crd_artifact("Failed")
    from app.knowledge import load_family_catalog

    families = load_family_catalog("knowledge/families.yaml").families
    assert not any(artifact_supports_family(f, bare_failed) for f in families)

    # A real message keeps the keyword path: the text decides the family.
    rich = _crd_artifact("Failed", "failed to reconcile project quota")
    assert artifact_supports_family("runai_control_plane_error", rich)
