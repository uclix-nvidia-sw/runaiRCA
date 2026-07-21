from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import replace

from app.collectors.base import AnalysisTarget, CollectorResult
from app.services import drilldown
from app.services.kg_enrichment import _query_external_case_hints
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


def test_hints_only_reach_guidance_and_do_not_change_ranking() -> None:
    result = CollectorResult(agent="kubernetes", status="ok", summary="pod Pending")
    target = _target()
    before = rank_root_cause_candidates(target, [result])
    hints = [
        {
            "case_id": "enterprise_support:case-1",
            "normalized_action": "Collect kubelet diagnostics",
            "canonical_component_tokens": ["kubelet"],
        }
    ]
    settings = replace(make_settings(), enable_agent_drilldown=False)

    asyncio.run(
        drilldown.run_drilldowns(settings, [result], target, None, external_case_hints=hints)
    )

    assert rank_root_cause_candidates(target, [result]) == before
    guidance = drilldown._ontology_guidance(None, external_case_hints=hints)
    assert guidance["external_case_investigation_leads"][0]["label"].endswith(
        "unverified hypotheses, not evidence"
    )
    assert "candidate_family" not in guidance


def test_external_hint_path_never_uses_indicates_or_resolved_by_writes() -> None:
    recorded: list[str] = []
    _query_external_case_hints(  # type: ignore[arg-type]
        _hint_client(recorded), "containerd failed while starting", 2
    )

    assert all("insert" not in query.lower() for query in recorded)
    assert all("indicates" not in query.lower() for query in recorded)
    assert all("resolved_by" not in query.lower() for query in recorded)
