from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ontology import ingest
from ontology.incident import OntologyIncident


class _Result:
    def resolve(self) -> _Result:
        return self

    def as_concept_rows(self) -> list[Any]:
        return []


class _Tx:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, query: str) -> _Result:
        self.queries.append(query)
        return _Result()


def test_novel_case_projection_keeps_cause_instance_and_contradiction(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        ingest,
        "load_family_catalog",
        lambda _: SimpleNamespace(families={"k8s_storage_error"}),
    )
    tx = _Tx()
    incident = OntologyIncident(
        incident_id="INC-1",
        run_id="ANL-1",
        analysis_hash="hash-1",
        case_id="ANL-1:hash-1",
        approval_state="active",
        user_approved_at="2026-07-10T00:00:00Z",
        root_cause_family="novel_csi_attach_race_a13f9c2d",
        mechanism="CSI attach race",
        mechanism_fingerprint="a13f9c2d",
        case_card={"context": {"cluster": "prod-a"}, "quality_score": 65},
        successful_actions=[{"statement": "restart CSI controller", "outcome": "mitigated"}],
        failed_actions=[{"statement": "restart node", "outcome": "ineffective"}],
        quality_score=90,
        quality_source="operator_review",
        artifacts=[
            {"evidence_id": "E-support", "source": "kubernetes", "summary": "FailedMount"},
            {"evidence_id": "E-contradict", "source": "loki", "summary": "CSI retry succeeded"},
        ],
        harness={
            "diagnosis_state": "supported",
            "status": "passed",
            "overall_score": 90,
            "claims": [
                {
                    "kind": "root_cause",
                    "confidence": "medium",
                    "supporting_evidence": ["E-support"],
                    "contradicting_evidence": ["E-contradict"],
                }
            ],
        },
    )

    ingest._write_run_projection(tx, incident)

    emitted = "\n".join(tx.queries)
    assert 'isa cause_instance, has cause_id "ANL-1:hash-1"' in emitted
    assert 'has subtype "novel_csi_attach_race_a13f9c2d"' in emitted
    assert "insufficient_evidence" not in emitted
    assert "isa case_projection" in emitted
    assert "isa supported_by" in emitted
    assert "isa contradicted_by" in emitted
    assert "has case_card" in emitted
    assert "has quality_score 90" in emitted
    assert 'has outcome "mitigated"' in emitted
    assert 'has outcome "ineffective"' in emitted


def test_fetch_uses_immutable_snapshot_payload_not_mutable_latest_run() -> None:
    assert "FROM rca_case_snapshots cs" in ingest._SELECT_INCIDENTS
    assert "cs.snapshot->>'analysis_summary'" in ingest._SELECT_INCIDENTS
    assert "JOIN analysis_runs ar" not in ingest._SELECT_INCIDENTS
