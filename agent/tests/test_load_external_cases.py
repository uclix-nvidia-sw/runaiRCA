from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ontology import ingest
from ontology import load_external_cases as lx


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


def _payload(**overrides: Any) -> dict[str, Any]:
    """Minimal sanitized-shape payload (synthetic ids); override any top-level section."""
    base: dict[str, Any] = {
        "payload_schema_version": "2.0",
        "payload_kind": "historical_incident_candidate",
        "identity": {
            "source_system": "enterprise_support",
            "deduplication_key": "enterprise_support:ab12cd34ef56",
            "source_revision_hash": "sha256:abc123",
            "curation_revision": 1,
        },
        "approval": {"curation_decision": "approved_for_ingestion_with_warnings"},
        "incident": {
            "title": "RoCE multi-node training failed",
            "masked_summary": "RDMA connect failed on the secondary network.",
            "status": "resolved",
            "occurred_at": "2026-03-05T01:46:00",
            "family": "network_fabric_error",
            "family_confidence": "medium",
            "observed_mechanism": "Inter-node reachability failed before QP setup.",
            "confirmed_mechanism": "Switch routing blocked the MacVLAN path.",
        },
        "searchable_context": {
            "error_signatures": [
                "ibv_modify_qp failed with 19 No such device",
                "Destination Host Unreachable",
                "ibv_modify_qp failed with 19 No such device",  # dup → collapsed
            ],
            "retrieval_keywords": ["NCCL RoCE Kubernetes"],
        },
        "evidence_refs": [
            {"evidence_id": "E002", "source_actor": "customer", "evidence_kind": "transcript_quote",
             "masked_summary": "QP transition failure.", "supports": ["F001", "H002"]},
            {"evidence_id": "E018", "source_actor": "customer", "evidence_kind": "statement",
             "masked_summary": "Switch L3 routing corrected.", "supports": ["A004"]},
            {"evidence_id": "E011", "source_actor": "nvidia_support", "evidence_kind": "statement",
             "masked_summary": "Repeated QP transition failures.", "supports": ["A002"]},
        ],
        "historical_actions": [
            {"action_id": "A004", "normalized_action": "Correct switch routing.",
             "outcome": "resolving", "evidence_ids": ["E018"]},
            {"action_id": "A001", "normalized_action": "Attach MacVLAN secondary interface.",
             "outcome": "partially_effective", "evidence_ids": []},
            {"action_id": "A002", "normalized_action": "Constrain RDMA device to one NIC.",
             "outcome": "ineffective", "evidence_ids": ["E011"]},
            {"action_id": "A003", "normalized_action": "Run inter-node ping.",
             "outcome": "diagnostic", "evidence_ids": []},
        ],
        "historical_use": {
            "context_class": "evaluation_only",
            "allowed_uses": ["retrieval_context"],
            "prohibited_uses": ["current_root_cause_proof", "positive_promotion"],
        },
        "ingestion_controls": {
            "ingestion_readiness": "blocked",
            "ingestion_blockers": [{"code": "external_support_case_adapter_missing"}],
        },
    }
    base.update(overrides)
    return base


def test_payload_maps_identity_actions_and_harness() -> None:
    inc = lx._to_incident(_payload(), approved_by="bohyun", approved_at="2026-07-16T00:00:00+09:00")

    assert inc.case_id == "enterprise_support:ab12cd34ef56"
    assert inc.incident_id == inc.run_id == "ext:sc-ab12cd34ef56"
    assert inc.status == "resolved"
    assert inc.root_cause_family == "network_fabric_error"
    assert inc.approval_state == "active"
    assert inc.user_approved_at == "2026-07-16T00:00:00+09:00"
    assert inc.analysis_hash == "sha256:abc123"

    # confirmed_mechanism present → no "unconfirmed:" prefix; fingerprint stable/non-empty.
    assert inc.mechanism == "Switch routing blocked the MacVLAN path."
    assert inc.mechanism_fingerprint and "unconfirmed" not in inc.mechanism

    # outcome vocabulary: resolving→resolved, partially_effective→mitigated (successful);
    # ineffective→ineffective (failed); diagnostic excluded from both graph lists.
    succ = {a["statement"]: a["outcome"] for a in inc.successful_actions}
    assert succ == {
        "Correct switch routing.": "resolved",
        "Attach MacVLAN secondary interface.": "mitigated",
    }
    assert inc.failed_actions == [
        {"statement": "Constrain RDMA device to one NIC.", "outcome": "ineffective"}
    ]

    # supporting_evidence = successful actions' evidence_ids ∪ evidence supporting them.
    assert inc.harness["claims"][0]["supporting_evidence"] == ["E018"]
    assert inc.harness["claims"][0]["confidence"] == "medium"
    assert inc.harness["status"] == "external"
    assert inc.harness["diagnosis_state"] == "resolved"

    # case_card carries the labels; excluded action still preserved in full list.
    card = inc.case_card
    assert card["context_class"] == "evaluation_only"
    assert card["case_origin"] == "enterprise_support"
    assert "positive_promotion" in card["prohibited_uses"]
    assert card["source_revision_hash"] == "sha256:abc123"
    assert card["mechanism_confirmed"] is True
    assert card["context"] == {"incident_status_at_approval": "resolved"}
    assert len(card["historical_actions"]) == 4  # diagnostic retained in the card

    # evidence artifacts carry source_actor and masked summary.
    ev = {a["evidence_id"]: a for a in inc.artifacts}
    assert ev["E002"]["source"] == "customer" and ev["E002"]["type"] == "transcript_quote"
    assert ev["E002"]["confidence"] == "low"


def test_unconfirmed_mechanism_is_prefixed_and_fingerprinted() -> None:
    p = _payload()
    p["incident"] = {**p["incident"], "confirmed_mechanism": None}
    inc = lx._to_incident(p, "op", "t")
    assert inc.mechanism == "unconfirmed: Inter-node reachability failed before QP setup."
    assert inc.mechanism_fingerprint
    assert inc.case_card["mechanism_confirmed"] is False


def test_unresolved_case_has_evidence_but_no_supported_by_or_resolution(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"storage_backend_error"}),
    )
    p = _payload()
    p["incident"] = {**p["incident"], "status": "unresolved", "family": "storage_backend_error"}
    # No successful actions → no supporting evidence, no resolution.
    p["historical_actions"] = [
        {"action_id": "A001", "normalized_action": "Check NFS export.",
         "outcome": "diagnostic", "evidence_ids": []},
    ]
    inc = lx._to_incident(p, "op", "t")
    assert inc.harness["claims"][0]["supporting_evidence"] == []
    assert inc.successful_actions == [] and inc.failed_actions == []

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(p))
    emitted = "\n".join(tx.queries)
    assert "isa evidence" in emitted                     # evidence still projected
    # …but nothing backs the diagnosis: no supported_by / resolution is INSERTED
    # (the run-clear DELETEs mention supported_by, so target the insert form).
    assert "insert $s isa supported_by" not in emitted
    assert "insert $resolution isa resolution" not in emitted


def test_write_case_emits_symptom_edge_and_never_knowledge_edges(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    # Even if a payload lies about promotion eligibility, the loader must never
    # reach the knowledge layer.
    p = _payload()
    p["ingestion_controls"] = {"eligible_for_positive_promotion": True}
    inc = lx._to_incident(p, "op", "t")
    keywords = lx._symptom_keywords(p)

    tx = _Tx()
    lx._write_case(tx, inc, keywords)
    emitted = "\n".join(tx.queries)

    assert 'isa symptom, has name "ext:sc-ab12cd34ef56"' in emitted
    assert 'has keyword "ibv_modify_qp failed with 19 no such device"' in emitted
    assert "isa has_symptom" in emitted
    assert "isa case_projection" in emitted
    # The isolation invariant — no catalog authority, ever.
    assert "isa indicates" not in emitted
    assert "isa resolved_by" not in emitted


def test_symptom_keywords_lowercase_dedup_and_error_signatures_only() -> None:
    kw = lx._symptom_keywords(_payload())
    assert kw == ["ibv_modify_qp failed with 19 no such device", "destination host unreachable"]
    # retrieval_keywords / normalized_symptoms are NOT used.
    assert "nccl roce kubernetes" not in kw


def test_symptom_keywords_empty_when_no_signatures_and_no_curated_tokens() -> None:
    p = _payload()
    p["searchable_context"] = {"error_signatures": [], "retrieval_keywords": ["a", "b"]}
    assert lx._symptom_keywords(p) == []


def test_generic_and_dead_tokens_are_filtered() -> None:
    p = _payload()
    p["searchable_context"] = {
        "error_signatures": [
            "OOMKilled",  # bare generic single word → dropped
            # curator annotation is stripped, leaving the real signal
            "out-of-sequence memory-mapped chunk (reported, raw log unavailable)",
            "wait_event=buffilewrite",  # code-like → kept
        ]
    }
    assert lx._symptom_keywords(p) == [
        "out-of-sequence memory-mapped chunk",
        "wait_event=buffilewrite",
    ]


def test_curated_signature_tokens_flow_into_keywords() -> None:
    # The sanitizer injects curated tokens for zero-signature cases; the loader
    # reads them like error signatures (same cleaning/generic filter applies).
    p = _payload()
    p["searchable_context"] = {
        "error_signatures": [],
        "curated_signature_tokens": ["DCGM_FI_DEV_GPU_UTIL", "RUN-39130", "NFS"],
        "retrieval_keywords": ["above 100 percent"],
    }
    kw = lx._symptom_keywords(p)
    assert "dcgm_fi_dev_gpu_util" in kw and "run-39130" in kw
    assert "nfs" not in kw                # generic single word still filtered
    assert "above 100 percent" not in kw  # retrieval_keywords never used


def test_validate_rejects_bad_version_kind_and_context_class() -> None:
    assert "payload_schema_version" in lx._validate(_payload(payload_schema_version="1.0"))
    assert "payload_kind" in lx._validate(_payload(payload_kind="something_else"))
    assert "context_class" in lx._validate(_payload(historical_use={"context_class": "promotable"}))
    assert "curation_decision" in lx._validate(_payload(approval={"curation_decision": "rejected"}))
    # A blocked ingestion_readiness / blocker list alone does NOT reject.
    assert lx._validate(_payload()) == ""


def test_confidence_bucket_handles_strings_and_numbers() -> None:
    assert lx._confidence_bucket("high") == "high"
    assert lx._confidence_bucket("Medium") == "medium"
    assert lx._confidence_bucket(0.9) == "high"
    assert lx._confidence_bucket(0.6) == "medium"
    assert lx._confidence_bucket(0.2) == "low"
    assert lx._confidence_bucket(None) == "low"
