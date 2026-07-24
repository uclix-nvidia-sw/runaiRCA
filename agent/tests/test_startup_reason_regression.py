from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult, artifact
from app.collectors.kubernetes import _container_lifecycle_artifact
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
