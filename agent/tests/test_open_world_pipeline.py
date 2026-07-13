from __future__ import annotations

import json
from dataclasses import replace

from app.collectors.base import CollectorResult, artifact
from app.schemas import Alert, AlertAnalysisRequest
from app.services.evidence_blackboard import Blackboard
from app.services.pipeline import (
    _aggregate_evidence,
    _link_probe_assessments_to_ledger,
    _merge_open_world_candidates,
    _record_selected_hypothesis_id,
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


def test_probe_verdict_links_only_explicit_hypothesis_without_promoting_it() -> None:
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
                        "hypothesis_ids": ["H-storage"],
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
    state.blackboard = Blackboard()
    state.blackboard.seed_results({"kubernetes": state.results[0]})

    _aggregate_evidence(state)
    _link_probe_assessments_to_ledger(state)

    hypothesis = state.investigation_context["hypothesis_ledger"][0]
    assert hypothesis["status"] == "testing"
    assert "evidence_for" not in hypothesis


def test_probe_verdict_never_falls_back_to_same_family_hypotheses() -> None:
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
                        "hypothesis_ids": ["H-target"],
                        "verdict": "refutes",
                        "artifact_index": 0,
                    }
                ]
            },
        )
    ]
    state.investigation_context = {
        "hypothesis_ledger": [
            {"id": "H-target", "family": "k8s_storage_error", "status": "testing"},
            {"id": "H-same-family", "family": "k8s_storage_error", "status": "testing"},
        ]
    }
    state.blackboard = Blackboard()
    state.blackboard.seed_results({"kubernetes": state.results[0]})

    _aggregate_evidence(state)
    _link_probe_assessments_to_ledger(state)

    target, same_family = state.investigation_context["hypothesis_ledger"]
    assert "evidence_against" not in target
    assert "evidence_against" not in same_family


def test_reasoning_trace_v3_contains_only_public_eligible_evidence_links() -> None:
    request = AlertAnalysisRequest(alert=Alert(labels={"alertname": "PodPending"}))
    state = new_state(make_settings(), request, collectors=[])
    present = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="event",
        status="ok",
        confidence="high",
        summary="FailedMount for claim data",
    )
    unavailable = artifact(
        agent="loki",
        source="loki",
        type="log",
        status="unavailable",
        confidence="low",
        summary="Loki transport failed",
    )
    state.results = [
        CollectorResult(
            agent="kubernetes", status="ok", summary=present.summary or "", artifacts=[present]
        ),
        CollectorResult(
            agent="loki",
            status="unavailable",
            summary=unavailable.summary or "",
            artifacts=[unavailable],
        ),
    ]
    state.blackboard = Blackboard()
    state.blackboard.seed_results({result.agent: result for result in state.results})
    present_fact = state.blackboard.evidence_id_for(present)
    unavailable_fact = state.blackboard.evidence_id_for(unavailable)
    state.investigation_context = {
        "hypothesis_ledger": [
            {
                "id": "H-mount",
                "family": "k8s_storage_error",
                "mechanism": "claim mount fails",
                "status": "testing",
                "evidence_for": [present_fact, unavailable_fact],
            }
        ],
        "reasoning_trace_v2": {"stop_reason": "all_collectors_probed"},
    }

    _aggregate_evidence(state)
    _refresh_public_reasoning_trace(state)

    trace = state.investigation_context["reasoning_trace_v3"]
    assert trace["hypotheses"][0]["evidence_for"] == ["E01"]
    assert trace["hypotheses"][0]["evidence_against"] == []
    assert trace["rejected_evidence_links"] == [
        {
            "hypothesis_id": "H-mount",
            "evidence_id": "E02",
            "role": "support",
            "reason": "source unavailable",
        }
    ]
    assert trace["evidence"][0]["observation_window"] == {"start": "", "end": ""}
    assert trace["evidence"][0]["temporal_relation"] == "unknown"
    assert trace["evidence"][0]["source_group"] == "kubernetes_api"
    assert trace["hypotheses"][0]["supporting_source_groups"] == ["kubernetes_api"]
    assert trace["hypotheses"][0]["contradicting_source_groups"] == []
    assert "F-" not in json.dumps(trace)


def test_reasoning_trace_v3_exposes_precise_observation_timing() -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            labels={"alertname": "PodPending"},
            startsAt="2026-07-13T00:05:00Z",
            endsAt="2026-07-13T00:10:00Z",
        )
    )
    state = new_state(make_settings(), request, collectors=[])
    change = artifact(
        agent="change",
        source="change",
        type="change_detection",
        status="ok",
        confidence="high",
        summary="Deployment rollout started",
        result={
            "observation_window": {
                "start": "2026-07-13T00:00:00Z",
                "end": "2026-07-13T00:01:00Z",
            },
            "source_group": "external_audit",
        },
    )
    state.results = [
        CollectorResult(agent="change", status="ok", summary="rollout", artifacts=[change])
    ]
    state.blackboard = Blackboard()
    state.blackboard.seed_results({"change": state.results[0]})
    private_id = state.blackboard.evidence_id_for(change)
    state.investigation_context = {
        "hypothesis_ledger": [
            {"id": "H1", "status": "testing", "evidence_for": [private_id]}
        ],
        "reasoning_trace_v2": {},
    }

    _aggregate_evidence(state)
    _refresh_public_reasoning_trace(state)

    fact = state.investigation_context["reasoning_trace_v3"]["evidence"][0]
    assert fact["source_group"] == "external_audit"
    assert fact["temporal_relation"] == "precedes_incident"


def test_reasoning_trace_v3_uses_assessment_hypothesis_ids_without_family_inference() -> None:
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
                        "probe_id": "mount-check",
                        "template_id": "mount-check",
                        "execution_id": "run-1:mount-check:0",
                        "executed_at": "2026-07-13T00:01:00Z",
                        "hypothesis_family": "same-family-but-not-a-link",
                        "hypothesis_ids": ["H-exact"],
                        "verdict": "supports",
                        "artifact_index": 0,
                    }
                ]
            },
        )
    ]
    state.blackboard = Blackboard()
    state.blackboard.seed_results({"kubernetes": state.results[0]})
    state.investigation_context = {
        "hypothesis_ledger": [
            {"id": "H-other", "family": "same-family-but-not-a-link", "status": "testing"},
            {"id": "H-exact", "family": "different-family", "status": "testing"},
        ],
        "reasoning_trace_v2": {},
    }

    _aggregate_evidence(state)
    _refresh_public_reasoning_trace(state)

    execution = state.investigation_context["reasoning_trace_v3"]["probe_executions"][0]
    assert execution == {
        "execution_id": "run-1:mount-check:0",
        "template_id": "mount-check",
        "tool": "",
        "verdict": "supports",
        "executed_at": "2026-07-13T00:01:00Z",
        "hypothesis_ids": ["H-exact"],
        "evidence_ids": [],
    }

    state.root_cause_candidates = [
        RankedCause("novel_mount", "medium", 6, hypothesis_id="H-exact", novelty="open_world")
    ]
    _record_selected_hypothesis_id(state)
    assert state.investigation_context["reasoning_trace_v3"]["selected_hypothesis_id"] == "H-exact"

    state.root_cause_candidates = [
        RankedCause(
            "different-family", "medium", 6, hypothesis_id="H-missing", novelty="open_world"
        )
    ]
    _record_selected_hypothesis_id(state)
    assert "selected_hypothesis_id" not in state.investigation_context["reasoning_trace_v3"]
