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


class _PresentResult(_Result):
    def as_concept_rows(self) -> list[Any]:
        return [object()]


class _Tx:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, query: str) -> _Result:
        self.queries.append(query)
        return _Result()


class _TraceTx(_Tx):
    def query(self, query: str) -> _Result:
        self.queries.append(query)
        if "diagnostic_probe_template" in query and "select $p" in query:
            return _PresentResult()
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


def test_fetch_sql_renders_where_without_interpreting_json_braces() -> None:
    with_grace = ingest._SELECT_INCIDENTS.replace("{where}", ingest._RESOLVED_GRACE_WHERE)
    without_grace = ingest._SELECT_INCIDENTS.replace("{where}", "")

    assert "{where}" not in with_grace
    assert "{where}" not in without_grace
    assert "'{}'::jsonb" in with_grace
    assert ingest._RESOLVED_GRACE_WHERE in with_grace


def test_trace_v3_projects_only_explicit_ids_and_metadata(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest,
        "load_family_catalog",
        lambda _: SimpleNamespace(families={"k8s_storage_error"}),
    )
    tx = _TraceTx()
    incident = OntologyIncident(
        incident_id="INC-trace",
        run_id="ANL-trace",
        root_cause_family="k8s_storage_error",
        reasoning_trace_v3={
            "schema_version": 3,
            "hypotheses": [
                {
                    "hypothesis_id": "H-storage",
                    "family": "k8s_storage_error",
                    "mechanism": "CSI attachment stalled",
                    "status": "testing",
                    "confidence": "medium",
                    "evidence_for": ["E-mount"],
                    "evidence_against": [],
                }
            ],
            "evidence": [
                {
                    "evidence_id": "E-mount",
                    "entity": "pod/train-0",
                    "source": "kubernetes_api",
                    "source_group": "kubernetes_api",
                    "predicate": "event.reason",
                    "polarity": "positive",
                    "coverage": "target pod",
                    "quality": "high",
                    "observation_window": {
                        "start": "2026-07-13T00:00:00Z",
                        "end": "2026-07-13T00:01:00Z",
                    },
                }
            ],
            "probe_executions": [
                {
                    "execution_id": "PX-1",
                    "template_id": "storage_failure-probe-01",
                    "tool": "k8s_describe",
                    "verdict": "supports",
                    "executed_at": "2026-07-13T00:01:00Z",
                    "hypothesis_ids": ["H-storage"],
                    "evidence_ids": ["E-mount"],
                }
            ],
            "rejected_evidence_links": [
                {"hypothesis_id": "H-storage", "evidence_id": "E-mount", "reason": "stale"}
            ],
            "stop_reason": "discriminating evidence collected",
        },
    )

    ingest._write_run_projection(tx, incident)

    emitted = "\n".join(tx.queries)
    assert 'has hypothesis_id "ANL-trace:H-storage"' in emitted
    assert 'has evidence_id "ANL-trace:E-mount"' in emitted
    assert 'has probe_execution_id "ANL-trace:PX-1"' in emitted
    assert 'has trace_local_id "H-storage"' in emitted
    assert "isa hypothesis_for" in emitted
    assert "isa probe_execution_tests" in emitted
    assert "isa probe_execution_evidence" in emitted
    assert "has observed_entity" in emitted
    assert "has observed_window_start" in emitted
    assert "probe_arguments" not in emitted


def test_trace_v2_is_not_promoted() -> None:
    assert ingest._trace_v3({"reasoning_trace_v3": {"schema_version": 2}}) == {}


def test_trace_v3_keyset_backfill_is_snapshot_scoped_and_resumable() -> None:
    query = ingest._SELECT_TRACE_V3_PAGE
    assert "FROM rca_case_snapshots cs" in query
    assert "cs.approval_state = 'active'" in query
    assert "(cs.approved_at, cs.case_id) >" in query
    assert "ORDER BY cs.approved_at ASC, cs.case_id ASC" in query
    incident = OntologyIncident(incident_id="INC", run_id="ANL")
    assert ingest._trace_key(incident, "H-1") == "ANL:H-1"
    assert ingest._trace_key(incident, "ANL:H-1") == "ANL:H-1"
