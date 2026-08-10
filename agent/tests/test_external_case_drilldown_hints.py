from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import replace

from app.collectors.base import AnalysisTarget, CollectorResult
from app.services import drilldown
from app.services.kg_enrichment import _external_case_hint_projection, _query_external_case_hints
from app.services.root_cause_ranking import rank_root_cause_candidates
from tests.test_orchestrator import make_settings


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="trainer-0",
        severity="warning",
        alert_name="TestAlert",
    )


def _hint_client(recorded: list[str]):
    card = json.dumps(
        {
            "searchable_context": {"canonical_component_tokens": ["containerd", "kubelet"]},
            "historical_actions": [
                {"outcome": "diagnostic", "normalized_action": "Collect kubelet diagnostics"},
                {"outcome": "preventive", "normalized_action": "Compare a healthy node"},
                {"outcome": "resolving", "normalized_action": "Restart containerd"},
                {"outcome": "mitigating", "normalized_action": "Drain the node"},
                {"outcome": "ineffective", "normalized_action": "Reboot the node"},
            ],
        }
    )

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                recorded.append(query)
                if "isa has_symptom" in query:
                    return [
                        {
                            "iid": "ext:case-1",
                            "sum": "containerd failure",
                            "sn": "ext:case-1",
                            "case_id": "enterprise_support:case-1",
                            "family": "workload_runtime_error",
                            "kw": "containerd failed",
                        }
                    ]
                if "has case_card $card" in query:
                    return [{"card": card}]
                return []

            yield run

    return FakeClient()


def test_external_case_hints_extract_only_diagnostic_and_preventive_actions() -> None:
    recorded: list[str] = []
    hints = _query_external_case_hints(  # type: ignore[arg-type]
        _hint_client(recorded), "containerd failed while starting", 2
    )

    assert [hint["normalized_action"] for hint in hints] == [
        "Collect kubelet diagnostics",
        "Compare a healthy node",
    ]
    assert all(hint["case_id"] == "enterprise_support:case-1" for hint in hints)
    assert all(hint["canonical_component_tokens"] == ["containerd", "kubelet"] for hint in hints)
    assert not any(
        forbidden in str(hints).lower()
        for forbidden in ("restart containerd", "drain the node", "reboot the node")
    )
    # Thread order/outcome are always derivable from historical_actions alone.
    assert [hint["order"] for hint in hints] == [1, 2]
    assert [hint["outcome"] for hint in hints] == ["diagnostic", "preventive"]
    # This card (like every payload before evidence_refs) has no evidence_refs
    # key at all -- must degrade to no observations, never KeyError.
    assert all("observed" not in hint for hint in hints)


def _hint_client_with_evidence(recorded: list[str]):
    """Same case as _hint_client, but the CaseCard also carries the bounded
    evidence_refs projection (ontology/load_external_cases.py) and each action
    names the evidence_ids it found -- the shape a freshly reloaded case has."""
    card = json.dumps(
        {
            "searchable_context": {"canonical_component_tokens": ["containerd", "kubelet"]},
            "evidence_refs": [
                {"evidence_id": "E01", "source": "customer", "kind": "statement",
                 "summary": "kubelet logs showed repeated CNI timeouts."},
                {"evidence_id": "E02", "source": "nvidia_support", "kind": "statement",
                 "summary": "A healthy node's containerd socket responded normally."},
                {"evidence_id": "E03", "source": "system", "kind": "raw_command_output",
                 "summary": "never cited by any action -- must not leak into a hint"},
            ],
            "historical_actions": [
                {"outcome": "diagnostic", "normalized_action": "Collect kubelet diagnostics",
                 "evidence_ids": ["E01"]},
                {"outcome": "preventive", "normalized_action": "Compare a healthy node",
                 "evidence_ids": ["E02", "E99"]},  # E99 unresolved -> silently skipped
                {"outcome": "resolving", "normalized_action": "Restart containerd",
                 "evidence_ids": ["E03"]},
            ],
        }
    )

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                recorded.append(query)
                if "isa has_symptom" in query:
                    return [
                        {
                            "iid": "ext:case-1",
                            "sum": "containerd failure",
                            "sn": "ext:case-1",
                            "case_id": "enterprise_support:case-1",
                            "family": "workload_runtime_error",
                            "kw": "containerd failed",
                        }
                    ]
                if "has case_card $card" in query:
                    return [{"card": card}]
                return []

            yield run

    return FakeClient()


def test_external_case_hints_resolve_order_outcome_and_observed_from_evidence_refs() -> None:
    recorded: list[str] = []
    hints = _query_external_case_hints(  # type: ignore[arg-type]
        _hint_client_with_evidence(recorded), "containerd failed while starting", 2
    )

    assert [hint["order"] for hint in hints] == [1, 2]
    assert [hint["outcome"] for hint in hints] == ["diagnostic", "preventive"]
    assert hints[0]["observed"] == ["kubelet logs showed repeated CNI timeouts."]
    assert hints[1]["observed"] == ["A healthy node's containerd socket responded normally."]
    assert not any("never cited" in str(hint) for hint in hints)


def test_external_case_hints_cap_observed_to_two_summaries() -> None:
    card = json.dumps(
        {
            "searchable_context": {"canonical_component_tokens": []},
            "evidence_refs": [
                {"evidence_id": "E01", "summary": "first finding"},
                {"evidence_id": "E02", "summary": "second finding"},
                {"evidence_id": "E03", "summary": "third finding"},
            ],
            "historical_actions": [
                {"outcome": "diagnostic", "normalized_action": "Collect everything",
                 "evidence_ids": ["E01", "E02", "E03"]},
            ],
        }
    )

    def run(query: str) -> list[dict]:
        return [{"card": card}] if "has case_card $card" in query else []

    hints = _external_case_hint_projection(run, "case-x")
    assert hints[0]["observed"] == ["first finding", "second finding"]


def test_external_case_hints_degrade_gracefully_without_evidence_refs_key() -> None:
    """A CaseCard written before evidence_refs existed (old graph data not yet
    reloaded) has no such key at all; an action can still name evidence_ids --
    must resolve to no observations, never KeyError."""
    card = json.dumps(
        {
            "searchable_context": {"canonical_component_tokens": []},
            "historical_actions": [
                {"outcome": "diagnostic", "normalized_action": "Collect kubelet diagnostics",
                 "evidence_ids": ["E01"]},
            ],
        }
    )

    def run(query: str) -> list[dict]:
        return [{"card": card}] if "has case_card $card" in query else []

    hints = _external_case_hint_projection(run, "case-x")
    assert hints[0]["order"] == 1
    assert hints[0]["outcome"] == "diagnostic"
    assert "observed" not in hints[0]


def test_external_case_hints_route_by_component_and_fall_back_to_all_domains() -> None:
    def hint(tokens: list[str]) -> list[dict]:
        return [
            {
                "case_id": "case-1",
                "normalized_action": "Inspect evidence",
                "canonical_component_tokens": tokens,
            }
        ]

    assert drilldown._external_case_hints_for_domain("kubernetes", hint(["containerd"]))
    assert not drilldown._external_case_hints_for_domain("runai", hint(["containerd"]))
    assert drilldown._external_case_hints_for_domain("system", hint(["nfs"]))
    assert drilldown._external_case_hints_for_domain("loki", hint(["logs"]))
    assert drilldown._external_case_hints_for_domain("runai", hint(["scheduler"]))
    assert drilldown._external_case_hints_for_domain("prometheus", hint(["quota"]))
    for domain in drilldown._DOMAIN_FOCUS:
        assert drilldown._external_case_hints_for_domain(domain, hint(["unroutable"]))


def test_external_case_hints_for_domain_forwards_order_outcome_and_observed() -> None:
    """Routing must not silently drop the narrative fields between projection
    (kg_enrichment) and the per-agent prompt (_ontology_guidance) -- this hop
    used to rebuild a bare {case_id, normalized_action} dict."""
    hint = [
        {
            "case_id": "case-1",
            "normalized_action": "Inspect evidence",
            "canonical_component_tokens": ["containerd"],
            "order": 2,
            "outcome": "preventive",
            "observed": ["a healthy node's containerd replied fine"],
        }
    ]
    routed = drilldown._external_case_hints_for_domain("kubernetes", hint)
    assert routed == [
        {
            "case_id": "case-1",
            "normalized_action": "Inspect evidence",
            "order": 2,
            "outcome": "preventive",
            "observed": ["a healthy node's containerd replied fine"],
        }
    ]


def test_external_case_hints_for_domain_omits_narrative_keys_when_absent() -> None:
    """A legacy (pre-evidence_refs) hint has none of order/outcome/observed --
    routing must not fabricate them."""
    hint = [
        {
            "case_id": "case-1",
            "normalized_action": "Inspect evidence",
            "canonical_component_tokens": ["containerd"],
        }
    ]
    routed = drilldown._external_case_hints_for_domain("kubernetes", hint)
    assert routed == [{"case_id": "case-1", "normalized_action": "Inspect evidence"}]


def test_hints_only_reach_guidance_and_do_not_change_ranking() -> None:
    result = CollectorResult(agent="kubernetes", status="ok", summary="pod Pending")
    target = _target()
    before = rank_root_cause_candidates(target, [result])
    hints = [
        {
            "case_id": "enterprise_support:case-1",
            "normalized_action": "Collect kubelet diagnostics",
            "canonical_component_tokens": ["kubelet"],
            "order": 1,
            "outcome": "diagnostic",
            "observed": ["kubelet logs showed repeated CNI timeouts."],
        }
    ]
    settings = replace(make_settings(), enable_agent_drilldown=False)

    asyncio.run(
        drilldown.run_drilldowns(settings, [result], target, None, external_case_hints=hints)
    )

    assert rank_root_cause_candidates(target, [result]) == before
    guidance = drilldown._ontology_guidance(None, external_case_hints=hints)
    lead = guidance["external_case_investigation_leads"][0]
    assert lead["label"].endswith("unverified hypotheses, not evidence")
    assert lead["order"] == 1
    assert lead["outcome"] == "diagnostic"
    assert lead["observed"] == ["kubelet logs showed repeated CNI timeouts."]
    assert "candidate_family" not in guidance


def test_external_hint_path_never_uses_indicates_or_resolved_by_writes() -> None:
    recorded: list[str] = []
    _query_external_case_hints(  # type: ignore[arg-type]
        _hint_client(recorded), "containerd failed while starting", 2
    )

    assert all("insert" not in query.lower() for query in recorded)
    assert all("indicates" not in query.lower() for query in recorded)
    assert all("resolved_by" not in query.lower() for query in recorded)
