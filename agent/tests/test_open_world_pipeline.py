from __future__ import annotations

from dataclasses import replace

from app.collectors.base import CollectorResult, artifact
from app.schemas import Alert, AlertAnalysisRequest
from app.services.evidence_blackboard import Blackboard
from app.services.pipeline import (
    _aggregate_evidence,
    _link_probe_assessments_to_ledger,
    _merge_open_world_candidates,
    _refresh_public_reasoning_trace,
    new_state,
)
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings


def test_open_world_ledger_maps_private_facts_to_response_evidence_ids() -> None:
    """Novel candidates must retain only citations the response can expose."""
    request = AlertAnalysisRequest(
        alert=Alert(labels={"alertname": "PodPending", "namespace": "runai"})
    )
    state = new_state(
        replace(make_settings(), open_world_rca_mode="authoritative"), request, collectors=[]
    )
    first = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="event",
        status="ok",
        confidence="high",
        summary="PVC attach repeatedly conflicts on node gpu-01.",
        highlights=["attach conflict"],
    )
    second = artifact(
        agent="loki",
        source="loki",
        type="log",
        status="ok",
        confidence="high",
        summary="CSI controller reports a stale attach operation.",
        highlights=["stale attach"],
    )
    state.results = [
        CollectorResult(
            agent="kubernetes", status="ok", summary=first.summary or "", artifacts=[first]
        ),
        CollectorResult(agent="loki", status="ok", summary=second.summary or "", artifacts=[second]),
    ]
    state.blackboard = Blackboard()
    state.blackboard.seed_results({result.agent: result for result in state.results})
    private_ids = [state.blackboard.evidence_id_for(item) for item in (first, second)]
    state.investigation_context = {
        "hypothesis_ledger": [
            {
                "id": "H-novel",
                "family": "",
                "mechanism": "CSI attach controller races a stale volume operation",
                "status": "supported",
                "evidence_for": [*private_ids, "F-does-not-exist"],
                "evidence_against": [],
            }
        ],
        "reasoning_trace_v2": {"referenced_facts": [{"evidence_id": private_ids[0]}]},
    }

    _aggregate_evidence(state)
    _refresh_public_reasoning_trace(state)
    merged = _merge_open_world_candidates(
        state, [RankedCause("insufficient_evidence", "low", 0.0)]
    )

    novel = next(candidate for candidate in merged if candidate.novelty == "open_world")
    public_ids = {item.evidence_id for item in state.artifacts}
    assert set(novel.support_evidence_ids) == public_ids
    assert all(item.startswith("E") for item in novel.support_evidence_ids)
    assert "F-does-not-exist" not in novel.support_evidence_ids
    assert (
        state.investigation_context["reasoning_trace_v2"]["referenced_facts"][0][
            "evidence_id"
        ]
        in public_ids
    )


def test_probe_verdict_links_real_evidence_without_promoting_hypothesis() -> None:
    request = AlertAnalysisRequest(alert=Alert(labels={"alertname": "PodPending"}))
    state = new_state(make_settings(), request, collectors=[])
    probe_artifact = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="ontology_probe",
        status="ok",
        confidence="medium",
        summary="FailedMount for claim data",
    )
    state.results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="mount failed",
            artifacts=[probe_artifact],
            details={
                "ontology_probe_assessments": [
                    {
                        "hypothesis_family": "k8s_storage_error",
                        "verdict": "supports",
                        "artifact_index": 0,
                    }
                ]
            },
        )
    ]
    state.investigation_context = {
        "hypothesis_ledger": [
            {"id": "H-storage", "family": "k8s_storage_error", "status": "testing"}
        ]
    }

    _aggregate_evidence(state)
    _link_probe_assessments_to_ledger(state)

    hypothesis = state.investigation_context["hypothesis_ledger"][0]
    assert hypothesis["status"] == "testing"
    assert hypothesis["evidence_for"] == [probe_artifact.evidence_id]
