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


def test_family_candidates_reach_the_case_card() -> None:
    """knowledge_links.family_candidates (curated differential diagnosis: other
    plausible families the curator weighed) must survive into case_card,
    bounded to the closed family catalog -- load_external_cases.py used to
    read none of knowledge_links, so every payload authored it for nothing."""
    p = _payload(knowledge_links={
        "known_issue_matches": [],
        "failure_mode_matches": [],
        "family_candidates": [
            {"family": "network_fabric_error", "confidence": "high"},
            {"family": "platform_lifecycle_change", "confidence": "low"},
            {"family": "not_a_real_family", "confidence": "high"},  # off-catalog: dropped
        ],
    })

    inc = lx._to_incident(p, "op", "t")

    assert inc.case_card["family_candidates"] == [
        {"family": "network_fabric_error", "confidence": "high"},
        {"family": "platform_lifecycle_change", "confidence": "low"},
    ]


def test_family_candidates_default_to_empty_list_without_knowledge_links() -> None:
    inc = lx._to_incident(_payload(), "op", "t")
    assert inc.case_card["family_candidates"] == []


# --- knowledge_links.failure_mode_matches / known_issue_matches (2026-08 audit
# item #2d): a prior pass wired family_candidates and explicitly skipped these
# two because they name free-text catalog entries needing sanitisation. -------


def test_knowledge_links_matches_accepts_only_names_in_the_closed_catalog() -> None:
    valid = frozenset({"NFS Unresponsive / Stale Handle", "CreateContainerError"})
    p = _payload(knowledge_links={
        "failure_mode_matches": [
            {"catalog_entry": "NFS Unresponsive / Stale Handle", "match_type": "exact_mechanism", "confidence": "medium"},
            {"catalog_entry": "Not In The Catalog", "confidence": "high"},  # unknown name: dropped
        ]
    })

    assert lx._knowledge_links_matches(p, "failure_mode_matches", valid) == [
        {"name": "NFS Unresponsive / Stale Handle", "confidence": "medium", "match_type": "exact_mechanism"}
    ]


def test_knowledge_links_matches_accepts_repository_entry_and_issue_aliases() -> None:
    valid = frozenset({"Dashboard Analytics GPU Utilization Mismatch", "Scheduler Reclaim Panic On Large GPU Job"})
    p = _payload(knowledge_links={
        "known_issue_matches": [
            {"repository_entry": "Dashboard Analytics GPU Utilization Mismatch", "confidence": "medium"},
            {"issue": "Scheduler Reclaim Panic On Large GPU Job", "confidence": "high"},
        ]
    })

    names = {m["name"] for m in lx._knowledge_links_matches(p, "known_issue_matches", valid)}
    assert names == {
        "Dashboard Analytics GPU Utilization Mismatch",
        "Scheduler Reclaim Panic On Large GPU Job",
    }


def test_knowledge_links_matches_skips_bare_string_entries() -> None:
    """A curator-prose string ("X — partial match because...") has no separable
    name field safe to validate without parsing free text — skip, don't guess."""
    valid = frozenset({"GPU Allocation Shows Zero On Dashboard"})
    p = _payload(knowledge_links={
        "known_issue_matches": [
            "GPU Allocation Shows Zero On Dashboard; partial because the follow-up chain is unconfirmed",
        ]
    })

    assert lx._knowledge_links_matches(p, "known_issue_matches", valid) == []


def test_knowledge_links_matches_drops_no_match_sentinel_entries() -> None:
    """A dict that asserts NO existing catalog entry (status: none, only a
    proposed candidate_name) must never be treated as a match — it carries
    neither catalog_entry/repository_entry/issue, so the generic name lookup
    already excludes it; this pins that exact real-world shape."""
    valid = frozenset({"Storage Policy All-Blocked Selector Fallback In v2.23.x"})
    p = _payload(knowledge_links={
        "known_issue_matches": [
            {
                "status": "none",
                "candidate_classification": "platform_version_bug",
                "candidate_name": "Storage Policy All-Blocked Selector Fallback In v2.23.x",
                "confidence": "high",
            }
        ]
    })

    assert lx._knowledge_links_matches(p, "known_issue_matches", valid) == []


def test_closed_symptom_and_known_issue_names_load_the_real_catalogs() -> None:
    lx._closed_symptom_names.cache_clear()
    lx._closed_known_issue_names.cache_clear()
    assert "OOMKilled" in lx._closed_symptom_names()
    assert "GPU Allocation Shows Zero On Dashboard" in lx._closed_known_issue_names()


def test_knowledge_links_matches_reach_the_case_card(monkeypatch: Any) -> None:
    monkeypatch.setattr(lx, "_closed_symptom_names", lambda: frozenset({"OOMKilled"}))
    monkeypatch.setattr(
        lx, "_closed_known_issue_names", lambda: frozenset({"GPU Allocation Shows Zero On Dashboard"})
    )
    p = _payload(knowledge_links={
        "failure_mode_matches": [{"catalog_entry": "OOMKilled", "confidence": "high"}],
        "known_issue_matches": [
            {"repository_entry": "GPU Allocation Shows Zero On Dashboard", "confidence": "medium"}
        ],
    })

    inc = lx._to_incident(p, "op", "t")

    assert inc.case_card["failure_mode_matches"] == [
        {"name": "OOMKilled", "confidence": "high"}
    ]
    assert inc.case_card["known_issue_matches"] == [
        {"name": "GPU Allocation Shows Zero On Dashboard", "confidence": "medium"}
    ]


def test_knowledge_links_matches_default_to_empty_list_without_knowledge_links() -> None:
    inc = lx._to_incident(_payload(), "op", "t")
    assert inc.case_card["failure_mode_matches"] == []
    assert inc.case_card["known_issue_matches"] == []


# --- case_card.evidence_refs (bounded projection for hint narration in
# kg_enrichment._external_case_hint_projection) -----------------------------


def test_evidence_refs_reach_the_case_card_bounded() -> None:
    """Only evidence_id/source/kind/summary survive -- never `supports` or
    `source_message_ids` (those name F00x/H00x/M00x ids this payload never
    ships)."""
    inc = lx._to_incident(_payload(), "op", "t")

    assert inc.case_card["evidence_refs"] == [
        {"evidence_id": "E002", "source": "customer", "kind": "transcript_quote",
         "summary": "QP transition failure."},
        {"evidence_id": "E018", "source": "customer", "kind": "statement",
         "summary": "Switch L3 routing corrected."},
        {"evidence_id": "E011", "source": "nvidia_support", "kind": "statement",
         "summary": "Repeated QP transition failures."},
    ]


def test_evidence_refs_collapse_whitespace_in_summary() -> None:
    p = _payload(evidence_refs=[
        {"evidence_id": "E900", "source_actor": "customer", "evidence_kind": "statement",
         "masked_summary": "line one\n   line   two  "},
    ])
    inc = lx._to_incident(p, "op", "t")
    assert inc.case_card["evidence_refs"][0]["summary"] == "line one line two"


def test_evidence_refs_trim_summary_to_240_chars() -> None:
    p = _payload(evidence_refs=[
        {"evidence_id": "E901", "source_actor": "customer", "evidence_kind": "statement",
         "masked_summary": "x" * 300},
    ])
    inc = lx._to_incident(p, "op", "t")
    summary = inc.case_card["evidence_refs"][0]["summary"]
    assert summary == "x" * 240
    assert len(summary) == 240


def test_evidence_refs_entries_without_evidence_id_are_dropped() -> None:
    p = _payload(evidence_refs=[
        {"evidence_id": "E100", "source_actor": "customer", "evidence_kind": "statement",
         "masked_summary": "kept"},
        {"source_actor": "customer", "evidence_kind": "statement", "masked_summary": "no id"},
        {"evidence_id": "", "source_actor": "customer", "evidence_kind": "statement",
         "masked_summary": "blank id"},
    ])
    inc = lx._to_incident(p, "op", "t")
    assert [r["evidence_id"] for r in inc.case_card["evidence_refs"]] == ["E100"]


def test_evidence_refs_default_to_empty_list_without_evidence_refs() -> None:
    inc = lx._to_incident(_payload(evidence_refs=[]), "op", "t")
    assert inc.case_card["evidence_refs"] == []


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


def test_clean_keyword_salvages_masked_placeholder_fragment() -> None:
    # A sanitizer-masked signature can never substring-match real text; the
    # longest literal fragment around the placeholder is the live signal
    # (live-TypeDB finding 2026-08-10: the NFS case's exact kernel line was a
    # dead keyword).
    assert (
        lx._clean_keyword("nfs: server <address> not responding, still trying")
        == "not responding, still trying"
    )
    assert (
        lx._clean_keyword(
            "MountVolume.SetUp failed for volume <volume>: mount failed: exit status 32"
        )
        == "MountVolume.SetUp failed for volume"
    )
    assert (
        lx._clean_keyword("failed to reserve container name")
        == "failed to reserve container name"
    )


def test_write_case_wires_the_trusted_knowledge_chain(monkeypatch: Any) -> None:
    # Owner decision 2026-07-27: vendor-support cases are trusted knowledge.
    # A catalog-family case with support-confirmed actions must land in the
    # SAME family→symptom→action chain as curated knowledge.
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    p = _payload()
    inc = lx._to_incident(p, "op", "t")
    keywords = lx._symptom_keywords(p)

    tx = _Tx()
    lx._write_case(tx, inc, keywords)
    emitted = "\n".join(tx.queries)

    assert 'isa symptom, has name "ext:sc-ab12cd34ef56"' in emitted
    assert 'has keyword "ibv_modify_qp failed with 19 no such device"' in emitted
    assert "isa has_symptom" in emitted
    assert "isa case_projection" in emitted
    assert "insert (symptom: $s, cause: $rc) isa indicates" in emitted
    # Only support-CONFIRMED actions become resolved_by fixes.
    assert 'has statement "Correct switch routing."' in emitted
    assert "insert (symptom: $s, remedy: $a) isa resolved_by" in emitted
    assert 'has statement "Constrain RDMA device to one NIC."; insert (symptom' not in emitted
    # The mechanism rides as the symptom's reason for report narration.
    assert 'has reason "Switch routing blocked the MacVLAN path."' in emitted


def test_unconfirmed_mechanism_case_stays_out_of_the_chain(monkeypatch: Any) -> None:
    # Curator recorded only an OBSERVED mechanism (support never confirmed) —
    # the case stays retrieval+playbook, and previously-written chain edges of
    # a demoted case are deleted.
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    p = _payload()
    p["incident"] = {**p["incident"], "confirmed_mechanism": None}
    inc = lx._to_incident(p, "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(p))
    emitted = "\n".join(tx.queries)
    assert "insert (symptom: $s, cause: $rc) isa indicates" not in emitted
    assert "insert (symptom: $s, remedy: $a) isa resolved_by" not in emitted
    assert "isa indicates(symptom: $s); delete $x;" in emitted  # demote cleanup
    assert "isa has_symptom" in emitted  # retrieval stays


def test_legacy_blanket_positive_promotion_label_does_not_block_the_chain(monkeypatch: Any) -> None:
    # Every shipped payload carries prohibited_uses: positive_promotion as a
    # blanket sanitizer-era label; gating on it would zero the chain and revert
    # the owner's trust decision. The per-case gate is mechanism_confirmed.
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    inc = lx._to_incident(_payload(), "op", "t")  # fixture carries the label
    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(_payload()))
    assert "insert (symptom: $s, cause: $rc) isa indicates" in "\n".join(tx.queries)


def test_chain_keywords_require_specific_signatures(monkeypatch: Any) -> None:
    # A single generic token must not anchor the causal chain; when no keyword
    # survives the specificity gate the case demotes to retrieval-only WITH its
    # full keyword set.
    assert lx._chain_specific("ibv_modify_qp failed with 19 no such device")
    assert lx._chain_specific("runai_pod_gpu_info")
    assert lx._chain_specific("error: column d.daticulocale does not exist")
    assert not lx._chain_specific("oomkilled")
    assert not lx._chain_specific("evicted")

    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    p = _payload()
    # "oomkilled" never even reaches keywords (_is_generic drops bare words);
    # "xid79" survives _is_generic (digit) but is too weak to anchor causality.
    p["searchable_context"] = {
        **(p.get("searchable_context") or {}),
        "error_signatures": ["xid79"],
        "curated_signature_tokens": [],
    }
    inc = lx._to_incident(p, "op", "t")
    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(p))
    emitted = "\n".join(tx.queries)
    assert "insert (symptom: $s, cause: $rc) isa indicates" not in emitted
    assert 'has keyword "xid79"' in emitted  # retrieval keeps the full set


def test_sweep_deletes_only_vanished_case_surfaces() -> None:
    tx = _Tx()
    lx._delete_case_surfaces(tx, "ext:sc-gone000000")
    emitted = "\n".join(tx.queries)
    assert 'has name "ext:sc-gone000000"' in emitted
    assert "isa indicates(symptom: $s); delete $x;" in emitted
    assert "isa has_symptom(symptom: $s); delete $x;" in emitted
    assert 'has runbook_name "ext:sc-gone000000:playbook"' in emitted
    # History stays: no incident/case_snapshot deletion.
    assert "isa incident" not in emitted
    assert "isa case_snapshot" not in emitted


def test_write_case_off_catalog_family_stays_out_of_the_chain(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"weird_external_family"}),
    )
    p = _payload()
    p["incident"] = {**p["incident"], "family": "weird_external_family"}
    inc = lx._to_incident(p, "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(p))
    emitted = "\n".join(tx.queries)
    # Not in the closed catalog -> retrieval only, no knowledge authority
    # (the demote-cleanup DELETE of chain edges is expected and fine).
    assert "insert (symptom: $s, cause: $rc) isa indicates" not in emitted
    assert "insert (symptom: $s, remedy: $a) isa resolved_by" not in emitted


def test_write_case_projects_support_thread_as_diagnostic_playbook(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    inc = lx._to_incident(_payload(), "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(_payload()))
    emitted = "\n".join(tx.queries)

    # The diagnostic step from the support thread becomes a mini-runbook step,
    # scoped by a case-local runbook name so the executable walk never sees it.
    assert 'isa runbook, has name "ext:sc-ab12cd34ef56:playbook"' in emitted
    assert 'has diagnostic_id "ext:sc-ab12cd34ef56:d01"' in emitted
    assert "isa runbook_entry" in emitted
    # Confirmed fixes are resolved_by actions, not playbook steps.
    assert 'has question "Correct switch routing."' not in emitted


# --- playbook step outcome/interpretation + runbook_for case link ----------


def test_playbook_step_carries_outcome_and_resolved_interpretation(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    p = _payload(historical_actions=[
        {"action_id": "A003", "normalized_action": "Run inter-node ping.",
         "outcome": "diagnostic", "evidence_ids": ["E002", "E011"]},
    ])
    inc = lx._to_incident(p, "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(p))
    emitted = "\n".join(tx.queries)

    assert 'has outcome "diagnostic"' in emitted
    assert (
        'has interpretation "QP transition failure. / Repeated QP transition failures."'
        in emitted
    )


def test_playbook_step_interpretation_empty_when_no_evidence_resolves(monkeypatch: Any) -> None:
    # Default fixture's only diagnostic/preventive action (A003) cites no
    # evidence -- current behavior (empty interpretation) must survive the
    # new outcome/interpretation stamping.
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    inc = lx._to_incident(_payload(), "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(_payload()))
    emitted = "\n".join(tx.queries)

    assert 'has interpretation ""' in emitted
    assert 'has outcome "diagnostic"' in emitted


def test_observed_from_evidence_caps_two_summaries_and_400_chars() -> None:
    refs = [
        {"evidence_id": "E1", "summary": "a" * 240},
        {"evidence_id": "E2", "summary": "b" * 240},
        {"evidence_id": "E3", "summary": "c" * 240},
    ]
    observed = lx._observed_from_evidence({"evidence_ids": ["E1", "E2", "E3"]}, refs)
    assert observed == ("a" * 240 + " / " + "b" * 240)[:400]
    assert len(observed) == 400


def test_observed_from_evidence_empty_without_resolvable_evidence() -> None:
    refs = [{"evidence_id": "E1", "summary": "kept"}]
    assert lx._observed_from_evidence({"evidence_ids": []}, refs) == ""
    assert lx._observed_from_evidence({}, refs) == ""
    assert lx._observed_from_evidence({"evidence_ids": ["missing"]}, refs) == ""


def test_runbook_for_insert_binds_entities_only(monkeypatch: Any) -> None:
    """Same static guard as test_probe_template_for_insert_binds_entities_only
    (tests/test_troubleshooting_ontology.py): the relation insert's match must
    NOT assert runbook_for itself, or the insert silently no-ops on a live
    TypeDB even though the loader exits 0."""
    monkeypatch.setattr(
        ingest, "load_family_catalog",
        lambda _: SimpleNamespace(families={"network_fabric_error"}),
    )
    inc = lx._to_incident(_payload(), "op", "t")

    tx = _Tx()
    lx._write_case(tx, inc, lx._symptom_keywords(_payload()))
    inserts = [
        q for q in tx.queries if "insert (runbook: $a, incident: $b) isa runbook_for" in q
    ]
    assert inserts, "loader must attempt the runbook_for insert"
    for query in inserts:
        match_clause = query.split("insert", 1)[0]
        assert "runbook_for" not in match_clause


def test_delete_playbook_deletes_runbook_for_before_runbook() -> None:
    tx = _Tx()
    lx._delete_playbook(tx, "ext:sc-gone000000")
    emitted = "\n".join(tx.queries)
    assert "isa runbook_for(runbook: $r); delete $x;" in emitted
    assert emitted.index("isa runbook_for(runbook: $r); delete $x;") < emitted.index(
        'match $x isa runbook, has name "ext:sc-gone000000:playbook"; delete $x;'
    )


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


def test_symptom_keywords_include_canonical_component_tokens() -> None:
    # A case whose only error signature is a rare log line (the thanos-receive
    # OOM case: "out-of-sequence memory-mapped chunk") is unreachable until
    # that exact line is observed. Component tokens are exact hyphenated names
    # that appear verbatim in pod-name evidence, so they must survive as
    # retrieval keywords; bare generic words are still dropped.
    p = _payload()
    p["searchable_context"]["canonical_component_tokens"] = [
        "runai-backend-thanos-receive",
        "OOMKilled",  # generic single word — must still be dropped
    ]
    keywords = lx._symptom_keywords(p)
    assert "runai-backend-thanos-receive" in keywords
    assert "oomkilled" not in keywords


def test_symptom_keywords_include_trigger_metric_and_issue_reference_tokens() -> None:
    """2026-08 audit item #2c: a case whose only distinguishing signal is a
    metric expression, a curator-named trigger condition, or an external
    bug-tracker id was unretrievable — these three searchable_context lists
    were authored on every payload but never reached the keyword set."""
    p = _payload()
    p["searchable_context"] = {
        "error_signatures": [],
        "trigger_tokens": ["random sub-minute metric outlier", "GPU"],  # bare word dropped
        "metric_signatures": ["DCGM_FI_DEV_GPU_UTIL > 100"],
        "issue_references": ["NVIDIA/dcgm-exporter#418", "RUN-36505"],
        "retrieval_keywords": ["never used"],
    }
    keywords = lx._symptom_keywords(p)
    assert "random sub-minute metric outlier" in keywords
    assert "dcgm_fi_dev_gpu_util > 100" in keywords
    assert "nvidia/dcgm-exporter#418" in keywords
    assert "run-36505" in keywords
    assert "gpu" not in keywords  # bare generic single word still filtered
    assert "never used" not in keywords


def test_symptom_keywords_still_excludes_prose_only_fields() -> None:
    """retrieval_keywords / normalized_symptoms / version_tokens remain
    deliberate exclusions (owner: entry points are the error string and
    canonical identifiers, never prose) — pinned so a future pass does not
    "fix" this the way trigger_tokens/metric_signatures/issue_references
    just were."""
    p = _payload()
    p["searchable_context"] = {
        "error_signatures": [],
        "retrieval_keywords": ["fractional GPU metrics missing"],
        "normalized_symptoms": ["0.5-GPU workload runs but metrics are absent"],
        "version_tokens": ["runai:2.24.58"],
    }
    assert lx._symptom_keywords(p) == []
