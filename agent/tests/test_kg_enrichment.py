from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace

from app.collectors.base import AnalysisTarget
from app.config import load_settings
from app.knowledge import match_failure_mode_symptoms
from app.services.kg_enrichment import (
    _EXTERNAL_CASE_QUERY,
    KGContext,
    _aggregate_probe_history,
    _case_card_projection,
    _prior_is_context_compatible,
    _query_candidate_families,
    _query_external_cases,
    _query_kg,
    _query_remediation,
    _rrf_case_priors,
    _safe_case_card,
    _select_case_cards,
    enrich,
)
from app.services.pipeline import (
    ReportKnowledge,
    _causal_chain_line,
    _knowledge_base_lines,
    _playbook_lines,
    _xid_diagnostic_guidance_lines,
)
from app.services.root_cause_ranking import RankedCause


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="", project="", queue="", namespace="", workload_name="",
        workload_type="", runai_workload_id="", node="gpu-1", pod="",
        severity="critical", alert_name="KubeNodeDiskPressure",
    )


def test_root_chain_queries_typeql_recursion() -> None:
    """The ordering pass restores 144 -> 48 -> 154, not numeric order."""
    import re

    causes = {154: [48], 48: [144], 144: []}

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                m = re.search(r"root_xid_chain_for\((\d+)\)", query)
                if m:
                    assert m.group(1) == "154"
                    return [{"x": 48}, {"x": 144}]
                m = re.search(r"root_xids_for\((\d+)\)", query)
                if m:
                    return [{"x": root} for root in causes[int(m.group(1))]]
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [154], "")  # type: ignore[arg-type]
    # Recursion supplies completeness; one-hop lookups supply only order.
    assert out.root_xids[154] == [144, 48]
    assert out.root_xid_status[154] == "ordered"
    # Fixes fetched for each discovered root too.
    assert 48 in out.xid_fixes and 144 in out.xid_fixes
    # A flat root list has no edge structure, so the renderer can only prove a
    # single-hop chain; two-plus ancestors (even a genuine path like this one)
    # render as the plain complete-upstream-set list instead of an arrow chain
    # it cannot verify against an unprovable fan-in (see xid 48/144/145/146).
    assert _causal_chain_line(out, "en") == (
        "- Related GPU errors (XID): 48, 144, 154 — "
        "upstream faults of 154 (complete): 144, 48. Fix the origin first."
    )
    assert _causal_chain_line(out, "ko") == (
        "- 관련 GPU 오류(XID): 48, 144, 154 — "
        "XID 154의 상류 장애(완전): 144, 48. 근본 원인을 먼저 조치하세요."
    )


def test_root_chain_excludes_observed_cycle_member() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "root_xid_chain_for(45)" in query:
                    # A TypeDB cycle includes the observed XID in its result set.
                    return [{"x": 45}, {"x": 74}]
                if "root_xids_for(45)" in query:
                    return [{"x": 74}]
                if "root_xids_for(74)" in query:
                    return [{"x": 45}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [45], "")  # type: ignore[arg-type]
    assert out.root_xids[45] == [74]
    assert out.root_xid_status[45] == "complete-but-unordered"


def test_root_chain_query_failure_is_isolated() -> None:
    import re

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                if re.search(r"root_xid_chain_for\(\d+\)", query):
                    raise RuntimeError("leads_to function missing on this TypeDB build")
                return []

            yield run

    # A broken root walk must not wipe the observed XID's own fixes.
    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]
    assert out.xid_fixes[79] == ["reset the GPU"]
    assert 79 not in out.root_xids
    assert out.root_xid_status[79] == "degraded"
    assert _causal_chain_line(out, "en") == (
        "- Related GPU errors (XID): 79 — see the recommended actions below. "
        "Causal-chain lookup was degraded by a query failure; shown upstream XIDs "
        "may not include the root."
    )
    assert _causal_chain_line(out, "ko") == (
        "- 관련 GPU 오류(XID): 79 — 세부 조치는 아래 권장 조치를 참고. "
        "인과 사슬 조회가 쿼리 실패로 불완전합니다."
    )


def test_root_chain_branch_is_deterministic_and_contains_each_ancestor_once() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "root_xid_chain_for(100)" in query:
                    return [{"x": root} for root in [30, 10, 20]]
                if "root_xids_for(10)" in query:
                    return []
                if "root_xids_for(20)" in query or "root_xids_for(30)" in query:
                    return [{"x": 10}]
                if "root_xids_for(100)" in query:
                    return [{"x": 30}, {"x": 20}]
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [100], "")  # type: ignore[arg-type]
    assert out.root_xids[100] == [10, 20, 30]
    assert out.root_xid_status[100] == "ordered"
    # Three ancestors can't be proven a single chain from a flat list (see
    # test_causal_chain_line_fan_in_is_not_a_fabricated_sequence in
    # test_xid_root_and_timeouts.py), so this renders as the plain upstream
    # list. The exact joined substring proves each ancestor appears once, in
    # order, with no duplicates -- "10" can't false-positive inside "100" here
    # because the match is the full ", "-joined sequence, not a bare number.
    line = _causal_chain_line(out, "en")
    assert "upstream faults of 100 (complete): 10, 20, 30" in line


def test_root_chain_ordering_failure_keeps_the_complete_unordered_set() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "root_xid_chain_for(154)" in query:
                    return [{"x": 48}, {"x": 144}]
                if "root_xids_for" in query:
                    raise RuntimeError("one-hop ordering unavailable")
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [154], "")  # type: ignore[arg-type]
    assert out.root_xids[154] == [48, 144]
    assert out.root_xid_status[154] == "complete-but-unordered"
    assert _causal_chain_line(out, "en") == (
        "- Related GPU errors (XID): 48, 144, 154 — "
        "upstream faults of 154 (complete): 48, 144. Fix the origin first."
    )
    assert _causal_chain_line(out, "ko") == (
        "- 관련 GPU 오류(XID): 48, 144, 154 — "
        "XID 154의 상류 장애(완전): 48, 144. 근본 원인을 먼저 조치하세요."
    )


def test_root_chain_keeps_twenty_recursive_ancestors() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "root_xid_chain_for(1)" in query:
                    return [{"x": root} for root in range(21, 1, -1)]
                if "root_xids_for" in query:
                    return []
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [1], "")  # type: ignore[arg-type]
    assert out.root_xids[1] == list(range(2, 22))
    assert out.root_xid_status[1] == "ordered"


def test_query_remediation_projects_xid_trigger_and_renders_guidance() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "fixes_for_xid(79)" in query:
                    return [{"x": "Reset the GPU."}]
                if "trigger_for_xid(79)" in query:
                    return [{"x": "Check for PCIe link errors before reset."}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]

    assert out.xid_triggers == {79: "Check for PCIe link errors before reset."}
    assert out.as_dict()["xid_triggers"] == {"79": "Check for PCIe link errors before reset."}
    rendered = "\n".join(_xid_diagnostic_guidance_lines(out, "en"))
    assert "Diagnostic guidance (XID 79" in rendered
    assert "Check for PCIe link errors before reset." in rendered
    # This FakeClient never returns a detail_for_xid() row, but XID 79 is a
    # real catalog entry: the local xid_catalog.yaml fallback still names it.
    assert "GPU has fallen off the bus" in rendered
    # English-only graph prose is not leaked into a Korean deterministic report.
    assert _xid_diagnostic_guidance_lines(out, "ko") == []


def test_query_remediation_projects_xid_mnemonic_and_description() -> None:
    """load_xids.py ingests mnemonic/description/severity for all 109 XIDs, but
    no function surfaced them: the graph's name for a GPU fault ("GPU has
    fallen off the bus") was unreachable while its remediation text was not."""

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "detail_for_xid(79)" in query:
                    return [
                        {
                            "m": "ROBUST_CHANNEL_GPU_HAS_FALLEN_OFF_THE_BUS",
                            "d": "GPU has fallen off the bus",
                            "s": "fatal",
                        }
                    ]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]

    assert out.xid_mnemonics == {79: "ROBUST_CHANNEL_GPU_HAS_FALLEN_OFF_THE_BUS"}
    assert out.xid_descriptions == {79: "GPU has fallen off the bus"}
    assert out.xid_severities == {79: "fatal"}
    assert out.as_dict()["xid_mnemonics"] == {"79": "ROBUST_CHANNEL_GPU_HAS_FALLEN_OFF_THE_BUS"}
    assert not out.is_empty()


def test_query_remediation_projects_xid_linkage_note() -> None:
    """xid_catalog.yaml's linkage_note (26 entries) was authored, asserted only
    by a YAML-shape test, and never reached TypeDB or a reader — this pins the
    read side once ingest.py/load_xids.py write it."""

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "detail_for_xid(48)" in query:
                    return [{"m": "ROBUST_CHANNEL_GPU_ECC_DBE", "d": "Double Bit ECC Error", "s": "fatal"}]
                if "linkage_note_for_xid(48)" in query:
                    return [{"x": "CUDA 12.7; GPU driver R565"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [48], "")  # type: ignore[arg-type]

    assert out.xid_linkage_notes == {48: "CUDA 12.7; GPU driver R565"}
    assert out.as_dict()["xid_linkage_notes"] == {"48": "CUDA 12.7; GPU driver R565"}


def test_query_remediation_omits_linkage_note_when_xid_never_escalates() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "detail_for_xid(79)" in query:
                    return [{"m": "ROBUST_CHANNEL_GPU_HAS_FALLEN_OFF_THE_BUS", "d": "GPU has fallen off the bus", "s": "fatal"}]
                return []  # linkage_note_for_xid(79) returns nothing — 79 never escalates.

            yield run

    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]

    assert out.xid_linkage_notes == {}
    assert "xid_linkage_notes" not in out.as_dict() or out.as_dict()["xid_linkage_notes"] == {}


def test_enrich_disabled_returns_empty_context() -> None:
    # load_settings() defaults ENABLE_TYPEDB off -> no query, empty context.
    ctx = asyncio.run(enrich(load_settings(), _target()))
    assert ctx.enabled is False
    assert ctx.available is False
    assert ctx.blast_radius_workloads == 0
    assert ctx.prior_incidents == []


def test_public_context_summarizes_instead_of_embedding_diagnostic_graph() -> None:
    ctx = KGContext(
        enabled=True,
        available=True,
        diagnostic_tree={"root": "root", "nodes": {"root": {}, "leaf": {}}},
    )

    public = ctx.public_dict()

    assert "diagnostic_tree" not in public
    assert public["diagnostic_runbook"] == {"available": True, "steps": 2}


def test_query_kg_escapes_typeql_literals() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return []

            yield run

    client = FakeClient()
    target = replace(
        _target(),
        node='gpu-1"; $x isa incident; #\\',
        alert_name='KubeNodeDiskPressure"; delete $x;\\',
    )

    _query_kg(
        client,
        target,
        [{"incident_id": 'INC-1"; delete $case;\\', "similarity": 0.99}],
    )  # type: ignore[arg-type]

    joined = "\n".join(client.queries)
    assert 'gpu-1\\"; $x isa incident; #\\\\' in joined
    assert 'KubeNodeDiskPressure\\"; delete $x;\\\\' in joined
    assert 'INC-1\\"; delete $case;\\\\' in joined
    assert 'has name "gpu-1"; $x isa incident' not in joined
    assert 'has alert_name "KubeNodeDiskPressure"; delete' not in joined
    assert 'has incident_id "INC-1"; delete' not in joined


def test_query_kg_surfaces_location_history_and_renders_it() -> None:
    # The infra layer's "have we seen trouble HERE before": resolved incidents
    # whose alerts fired at the same node/namespace, any alert name.
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "has node_name" in query:
                    return [{"iid": "INC-node-1", "sum": "GPU fell off the bus."}]
                if "has namespace_name" in query:
                    return [
                        {"iid": "INC-node-1", "sum": "duplicate — must dedupe"},
                        {"iid": "INC-ns-2", "sum": "quota exhausted in namespace."},
                    ]
                return []

            yield run

    target = replace(_target(), namespace="runai-vision")
    data = _query_kg(FakeClient(), target, [])  # type: ignore[arg-type]

    history = data["location_history"]
    assert [item["incident_id"] for item in history] == ["INC-node-1", "INC-ns-2"]
    assert history[0]["where"] == "node gpu-1"
    assert history[1]["where"] == "namespace runai-vision"

    lines = _knowledge_base_lines(
        {"enabled": True, "available": True, "location_history": history}, [], "", ""
    )
    joined = "\n".join(lines)
    assert (
        "- 2 past resolved incident(s) at this alert's location "
        "(different alerts, same node/namespace):"
    ) in lines
    assert "2 past resolved incident(s)" in joined
    assert "INC-node-1 (node gpu-1): GPU fell off the bus." in joined


def test_query_kg_surfaces_workload_topology_and_storage_blast_radius() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "isa exposes" in query:
                    return [{"sn": "runai-backend-workloads"}]
                if "isa uses_storage" in query and 'isa pvc, has name "data-0"' in query:
                    return [
                        {
                            "on": "runai-backend-workloads",
                            "ou": "runai-backend/runai-backend-workloads",
                        },
                        {"on": "other-workload", "ou": "runai-backend/other-workload"},
                    ]
                if "isa uses_storage" in query:
                    return [{"pn": "data-0"}]
                return []

            yield run

    target = replace(
        _target(), namespace="runai-backend", workload_name="runai-backend-workloads"
    )
    data = _query_kg(FakeClient(), target, [])  # type: ignore[arg-type]

    topology = data["workload_topology"]
    assert data["workload_topology_status"] == "complete"
    assert topology["services"] == ["runai-backend-workloads"]
    assert topology["pvcs"] == ["data-0"]
    # The workload itself is excluded from its own storage blast radius.
    assert topology["shared_storage_workloads"] == ["other-workload"]

    lines = _knowledge_base_lines(
        {
            "enabled": True,
            "available": True,
            "workload_topology": topology,
            "workload_topology_status": data["workload_topology_status"],
        },
        [],
        "",
        "",
    )
    joined = "\n".join(lines)
    assert "Workload topology" in joined
    assert lines == [
        "",
        "### Knowledge Base (Ontology)",
        "",
        "- Workload topology (stable identity): Service(s) runai-backend-workloads; "
        "PVC(s) data-0 — PVC shared with 1 other workload(s): other-workload",
    ]
    assert "PVC shared with 1 other workload(s): other-workload" in joined


def test_query_kg_discloses_unsearched_fourth_pvc() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "has name $pn" in query:
                    return [{"pn": f"data-{index}"} for index in range(1, 5)]
                if 'has name "data-4"' in query:
                    raise AssertionError("the fourth PVC must not be searched")
                return []

            yield run

    data = _query_kg(
        FakeClient(), replace(_target(), namespace="runai", workload_name="workload"), []
    )  # type: ignore[arg-type]

    topology = data["workload_topology"]
    assert topology["pvcs"] == ["data-1", "data-2", "data-3", "data-4"]
    assert topology["shared_storage_pvcs"] == ["data-1", "data-2", "data-3"]
    assert topology["shared_storage_truncated"] is True
    assert "shared-storage checked only on PVC(s) data-1, data-2, data-3" in "\n".join(
        _knowledge_base_lines({"enabled": True, "available": True, "workload_topology": topology})
    )


def test_query_kg_uses_namespace_exact_workload_topology() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                if 'has workload_uid "team-a/trainer"' in query and "isa exposes" in query:
                    return [{"sn": "service-a"}]
                if 'has workload_uid "team-a/trainer"' in query and "isa uses_storage" in query:
                    return [{"pn": "pvc-a"}]
                if 'has workload_uid "team-b/trainer"' in query:
                    raise AssertionError("must not query the same name in another namespace")
                return []

            yield run

    client = FakeClient()
    data = _query_kg(
        client, replace(_target(), namespace="team-a", workload_name="trainer"), []
    )  # type: ignore[arg-type]

    assert data["workload_topology"] == {
        "services": ["service-a"],
        "pvcs": ["pvc-a"],
        "shared_storage_workloads": [],
        "shared_storage_pvcs": ["pvc-a"],
        "shared_storage_truncated": False,
    }
    assert any('has workload_uid "team-a/trainer"' in query for query in client.queries)


def test_query_kg_skips_ambiguous_workload_topology_without_namespace() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return []

            yield run

    client = FakeClient()
    data = _query_kg(
        client, replace(_target(), workload_name="trainer"), []
    )  # type: ignore[arg-type]

    assert data["workload_topology"] == {}
    assert data["workload_topology_status"] == "skipped_missing_namespace"
    assert not any("workload_uid" in query for query in client.queries)
    assert _knowledge_base_lines({"enabled": True, "available": True, **data}) == [
        "",
        "### Knowledge Base (Ontology)",
        "",
        "- Workload topology (stable identity): lookup skipped because the alert has no namespace.",
    ]


def test_query_kg_renders_empty_workload_topology_after_lookup() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            yield lambda query: []

    data = _query_kg(
        FakeClient(), replace(_target(), namespace="team-a", workload_name="trainer"), []
    )  # type: ignore[arg-type]

    assert data["workload_topology"] == {}
    assert data["workload_topology_status"] == "complete"
    assert _knowledge_base_lines({"enabled": True, "available": True, **data}) == [
        "",
        "### Knowledge Base (Ontology)",
        "",
        "- Workload topology (stable identity): no Services or PVCs found.",
    ]


def test_location_history_cap_is_rendered_as_at_least() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "has node_name" in query:
                    return [{"iid": f"INC-{index}", "sum": "prior RCA"} for index in range(1, 8)]
                return []

            yield run

    data = _query_kg(FakeClient(), _target(), [])  # type: ignore[arg-type]

    assert len(data["location_history"]) == 6
    assert data["location_history_truncated"] is True
    assert "At least 6 past resolved incident(s)" in "\n".join(
        _knowledge_base_lines({"enabled": True, "available": True, **data})
    )


def test_query_kg_projects_typedb_symptom_metadata() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "not {" in query:
                    return []
                if "has keyword $kw" in query:
                    return [
                        {
                            "fam": "workload_startup_error",
                            "sn": "OOMKilled",
                            "kw": "oomkilled",
                            "st": "Raise the memory limit.",
                        }
                    ]
                if "has reason $reason" in query:
                    return [{"sn": "OOMKilled", "reason": "Memory limit exceeded."}]
                if "has exclusive_actions $exclusive_actions" in query:
                    return [{"sn": "OOMKilled", "exclusive_actions": True}]
                if "has reason_ko $reason_ko" in query:
                    return [{"sn": "OOMKilled", "reason_ko": "메모리 제한을 초과했습니다."}]
                if "has component $component" in query:
                    return [{"sn": "OOMKilled", "component": "cluster-sync"}]
                if "has name_ko $name_ko" in query:
                    return [{"sn": "OOMKilled", "name_ko": "메모리 부족 종료"}]
                if "has statement_ko $statement_ko" in query:
                    return [
                        {"sn": "OOMKilled", "statement_ko": "메모리 제한을 높이세요."},
                        {"sn": "OOMKilled", "statement_ko": "누수를 수정하세요."},
                    ]
                return []

            yield run

    knowledge = _query_kg(FakeClient(), _target())["knowledge"]  # type: ignore[arg-type]

    assert knowledge == {
        "workload_startup_error": [
            {
                "symptom": "OOMKilled",
                "keywords": ["oomkilled"],
                "actions": ["Raise the memory limit."],
                "reason": "Memory limit exceeded.",
                "exclusive_actions": True,
                "requires_lifecycle_signal": False,
                "component": "cluster-sync",
                "symptom_ko": "메모리 부족 종료",
                "reason_ko": "메모리 제한을 초과했습니다.",
                "actions_ko": ["누수를 수정하세요.", "메모리 제한을 높이세요."],
                "affected_version": "",
                "fixed_version": "",
            }
        ]
    }


def test_actionless_confirmed_symptom_reaches_matcher_and_candidate_family() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "not {" in query:
                    return [{
                        "fam": "node_kubelet_pressure",
                        "sn": "confirmed:KubeNodeDiskPressure",
                        "kw": "kubenodediskpressure",
                    }]
                return []

            yield run

    knowledge = _query_kg(FakeClient(), _target())["knowledge"]  # type: ignore[arg-type]
    symptom = knowledge["node_kubelet_pressure"][0]

    assert symptom["actions"] == []
    matches = match_failure_mode_symptoms(knowledge, "KubeNodeDiskPressure")
    assert [(family, item["symptom"], item["actions"]) for family, item in matches] == [
        ("node_kubelet_pressure", "confirmed:KubeNodeDiskPressure", [])
    ]

    class CandidateClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                assert 'causes_for_symptom("confirmed:KubeNodeDiskPressure")' in query
                return [{"x": "node_kubelet_pressure"}]

            yield run

    counts, warnings = _query_candidate_families(
        CandidateClient(), [item["symptom"] for _family, item in matches]  # type: ignore[arg-type]
    )
    assert counts == {"node_kubelet_pressure": 1}
    assert warnings == []


def test_actionless_knowledge_renders_family_prior_without_action_stub() -> None:
    kg = KGContext(
        enabled=True,
        available=True,
        knowledge={
            "node_kubelet_pressure": [
                {
                    "symptom": "confirmed:KubeNodeDiskPressure",
                    "keywords": ["kubenodediskpressure"],
                    "actions": [],
                }
            ]
        },
    ).as_dict()

    text = "\n".join(
        _knowledge_base_lines(kg, None, "KubeNodeDiskPressure")
    )

    assert "Matched symptom **confirmed:KubeNodeDiskPressure**" in text
    assert "no verified action recorded" in text
    assert "known fixes from the knowledge base" not in text
    assert "\n  - " not in text


def test_demoted_external_case_without_indicates_still_matches_nothing() -> None:
    queries: list[str] = []

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                queries.append(query)
                # load_external_cases._delete_chain_edges removed this case's
                # indicates edge, so the actionless read returns no row.
                return []

            yield run

    knowledge = _query_kg(FakeClient(), _target())["knowledge"]  # type: ignore[arg-type]

    assert knowledge == {}
    assert match_failure_mode_symptoms(knowledge, "KubeNodeDiskPressure") == []
    actionless_query = next(query for query in queries if "not {" in query)
    assert "isa indicates" in actionless_query


def test_typedb_failure_mode_symptom_delivery_chain_contract() -> None:
    # When a consumer starts reading a new failure_modes symptom field, add it to the
    # TypeDB loader (load_knowledge.py), the read-back (kg_enrichment.py), and this list.
    contract = {
        "symptom": "OOMKilled",
        "keywords": ["oom", "oomkilled"],
        "actions": ["Inspect memory limit.", "Raise memory limit."],
        "reason": "Memory limit exceeded.",
        "exclusive_actions": True,
        "requires_lifecycle_signal": True,
        "reason_ko": "메모리 제한을 초과했습니다.",
        "actions_ko": ["메모리 제한을 높이세요.", "메모리 제한을 점검하세요."],
        "component": "cluster-sync",
        "symptom_ko": "메모리 부족 종료",
        "affected_version": "<=2.20",
        "fixed_version": "2.21",
    }

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "not {" in query:
                    return []
                if "has keyword $kw" in query:
                    return [
                        {
                            "fam": "workload_startup_error",
                            "sn": contract["symptom"],
                            "kw": keyword,
                            "st": action,
                        }
                        for keyword, action in zip(contract["keywords"], contract["actions"], strict=True)
                    ]
                if "has reason $reason" in query:
                    return [{"sn": contract["symptom"], "reason": contract["reason"]}]
                if "has exclusive_actions $exclusive_actions" in query:
                    return [{"sn": contract["symptom"], "exclusive_actions": True}]
                if "has requires_lifecycle_signal $requires_lifecycle_signal" in query:
                    return [{"sn": contract["symptom"], "requires_lifecycle_signal": True}]
                if "has reason_ko $reason_ko" in query:
                    return [{"sn": contract["symptom"], "reason_ko": contract["reason_ko"]}]
                if "has component $component" in query:
                    return [{"sn": contract["symptom"], "component": contract["component"]}]
                if "has name_ko $name_ko" in query:
                    return [{"sn": contract["symptom"], "name_ko": contract["symptom_ko"]}]
                if "has statement_ko $statement_ko" in query:
                    return [
                        {"sn": contract["symptom"], "statement_ko": action}
                        for action in contract["actions_ko"]
                    ]
                if "has affected_version $affected_version" in query:
                    return [{"sn": contract["symptom"], "affected_version": contract["affected_version"]}]
                if "has fixed_version $fixed_version" in query:
                    return [{"sn": contract["symptom"], "fixed_version": contract["fixed_version"]}]
                return []

            yield run

    symptom = _query_kg(FakeClient(), _target())["knowledge"]["workload_startup_error"][
        0
    ]  # type: ignore[arg-type]

    assert set(symptom) == set(contract)
    assert symptom == contract
    assert isinstance(symptom["keywords"], list)
    assert isinstance(symptom["actions"], list)
    assert isinstance(symptom["actions_ko"], list)
    assert isinstance(symptom["exclusive_actions"], bool)
    assert isinstance(symptom["requires_lifecycle_signal"], bool)
    bool_fields = {"keywords", "actions", "actions_ko", "exclusive_actions", "requires_lifecycle_signal"}
    for field in set(contract) - bool_fields:
        assert isinstance(symptom[field], str)


def test_typedb_symptom_component_preserves_yaml_playbook_checks() -> None:
    typedb_symptom = {
        "symptom": "Cluster Sync Unhealthy",
        "keywords": ["cluster sync unhealthy"],
        "actions": ["Inspect cluster-sync."],
        "component": "cluster-sync",
    }
    components = {
        "cluster-sync": {
            "failure_effect": "Workload status stops syncing.",
            "depends_on": ["runai-backend"],
            "checks": ["kubectl logs -n runai deploy/cluster-sync"],
        },
        "runai-backend": {"depends_on": []},
    }

    typedb_lines = _playbook_lines(
                       None,
                       "cluster sync unhealthy",
                       knowledge=ReportKnowledge(failure_modes={"runai_control_plane_error": [typedb_symptom]}, cases="", components=components),
                   )
    yaml_lines = _playbook_lines(
                     None,
                     "cluster sync unhealthy",
                     knowledge=ReportKnowledge(failure_modes={"runai_control_plane_error": [{**typedb_symptom}]}, cases="", components=components),
                 )

    assert typedb_lines == yaml_lines
    assert "Check order: cluster-sync → runai-backend" in "\n".join(typedb_lines)
    assert "kubectl logs -n runai deploy/cluster-sync" in "\n".join(typedb_lines)


def test_typedb_knowledge_exclusive_actions_suppress_generic_siblings() -> None:
    from app.services.pipeline import _actionable_failure_mode_matches

    matches = _actionable_failure_mode_matches(
        {
            "workload_startup_error": [
                {
                    "symptom": "OOMKilled",
                    "keywords": ["oomkilled"],
                    "actions": ["Raise the memory limit."],
                    "exclusive_actions": True,
                    "reason_ko": "메모리 제한을 초과했습니다.",
                    "actions_ko": ["메모리 제한을 높이세요."],
                },
                {
                    "symptom": "CrashLoopBackOff",
                    "keywords": ["crashloopbackoff"],
                    "actions": ["Inspect logs."],
                },
            ]
        },
        "CrashLoopBackOff after OOMKilled",
        None,
    )

    assert [symptom["symptom"] for _family, symptom in matches] == ["OOMKilled"]


def test_graph_remediation_escapes_typeql_literals() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return []

            yield run

    client = FakeClient()
    _query_remediation(
        client,  # type: ignore[arg-type]
        'gpu_hardware_error"; delete $x;\\',
        [79],
        'A100"; match $x isa incident;\\',
    )

    joined = "\n".join(client.queries)
    # Family alone is no longer an executable remediation lookup. Only the
    # signature-specific XID/model query is sent to TypeDB.
    assert "gpu_hardware_error" not in joined
    assert 'A100\\"; match $x isa incident;\\\\' in joined
    assert 'fixes_for_family("gpu_hardware_error"; delete' not in joined
    assert 'xids_for_gpu_model("A100"; match' not in joined


def test_query_remediation_does_not_flatten_family_actions() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                self.queries.append(query)
                return [{"statement": "SHOULD-NOT-BE-FAMILY-ACTION"}]

            yield run

    client = FakeClient()
    result = _query_remediation(
        client, "image_pull_error", [], ""  # type: ignore[arg-type]
    )

    assert result.is_empty()
    assert client.queries == []


def test_knowledge_base_section_renders_when_available() -> None:
    kg = KGContext(
        enabled=True,
        available=True,
        blast_radius_workloads=3,
        prior_incidents=[{"incident_id": "inc-1", "analysis_summary": "node disk pressure"}],
    ).as_dict()
    text = "\n".join(_knowledge_base_lines(kg))
    assert "## Knowledge Base (Ontology)" in text
    assert "Blast radius: 3" in text
    assert "inc-1" in text


def test_knowledge_base_prior_summary_is_single_trimmed_line() -> None:
    summary = (
        "root cause line api_key=kg-prior-secret-12345\n## injected heading\n"
        + ("detail " * 100)
    )
    kg = KGContext(
        enabled=True,
        available=True,
        prior_incidents=[
            {"incident_id": "inc-long\n## injected id", "analysis_summary": summary}
        ],
    ).as_dict()

    line = next(line for line in _knowledge_base_lines(kg) if "inc-long" in line)
    assert "\n" not in line
    assert "kg-prior-secret-12345" not in line
    assert "[MASKED]" in line
    assert len(line) < 380
    assert line.endswith("…")


def test_knowledge_base_section_empty_when_disabled() -> None:
    assert _knowledge_base_lines({"enabled": False}) == []
    assert _knowledge_base_lines(None) == []


def test_knowledge_base_section_omitted_when_unavailable() -> None:
    # Optional enrichment: when enabled but unreachable, no operator-facing section
    # is rendered (the reason is carried in the response warnings instead).
    assert _knowledge_base_lines({"enabled": True, "available": False}) == []


_KNOWLEDGE = {
    "node_kubelet_pressure": [
        {
            "symptom": "Node Disk Pressure",
            "keywords": ["diskpressure", "evicted"],
            "actions": ["Cordon or drain the node", "Inspect kubelet disk usage"],
        },
        {
            "symptom": "Node Memory Pressure",
            "keywords": ["memorypressure"],
            "actions": ["Find the memory hog on the node"],
        },
    ]
}


def test_kb_matches_symptom_keyword_for_precise_fix() -> None:
    kg = KGContext(enabled=True, available=True, knowledge=_KNOWLEDGE).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="high", score=7.0)]
    text = "\n".join(
        _knowledge_base_lines(kg, candidates, "node condition DiskPressure=True; pods evicted")
    )
    assert "Matched symptom **Node Disk Pressure**" in text
    assert "Cordon or drain the node" in text
    assert "memory hog" not in text  # the non-matching symptom's action is not shown


def test_kb_actions_are_single_masked_lines() -> None:
    kg = KGContext(
        enabled=True,
        available=True,
        knowledge={
            "node_kubelet_pressure": [
                {
                    "symptom": "Node Disk Pressure\n## injected symptom",
                    "keywords": ["diskpressure"],
                    "actions": [
                        "Cordon the node api_key=kg-action-secret-12345\n## injected action"
                    ],
                }
            ]
        },
    ).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="high", score=7.0)]

    lines = _knowledge_base_lines(kg, candidates, "node condition DiskPressure=True")
    text = "\n".join(lines)

    assert "kg-action-secret-12345" not in text
    assert "[MASKED]" in text
    assert "\n## injected" not in text
    assert any("## injected" in line for line in lines)


def test_kb_says_no_match_when_no_symptom_keyword_matches() -> None:
    # Report fix #5: when no symptom keyword matches the observed evidence, do NOT
    # dump a generic family checklist as if it were a real match — say so plainly.
    kg = KGContext(enabled=True, available=True, knowledge=_KNOWLEDGE).as_dict()
    candidates = [RankedCause(family="node_kubelet_pressure", confidence="medium", score=3.0)]
    text = "\n".join(_knowledge_base_lines(kg, candidates, "some unrelated evidence text"))
    assert "No closely-matching prior knowledge" in text
    assert "Cordon or drain the node" not in text


def test_case_cards_include_analog_and_different_family_counterexample() -> None:
    cards = _select_case_cards(
        [
            {"case_id": "C1", "incident_id": "I1", "family": "k8s_storage_error", "analysis_summary": "mount"},
            {"case_id": "C2", "incident_id": "I2", "family": "node_kubelet_pressure", "analysis_summary": "pressure"},
        ]
    )
    assert [card["kind"] for card in cards] == ["analog", "counterexample"]
    assert all(card["historical_prior"] is True for card in cards)


def test_rrf_case_priors_rewards_graph_vector_agreement_without_admitting_raw_memory() -> None:
    prior = [
        {"incident_id": "I-graph", "case_id": "C-graph", "family": "k8s_storage_error"},
        {"incident_id": "I-vector", "case_id": "C-vector", "family": "network_fabric_error"},
    ]
    fused = _rrf_case_priors(
        prior,
        [
            {"incident_id": "I-vector", "similarity": 0.91},
            {"incident_id": "I-unapproved-memory", "similarity": 0.99},
        ],
    )

    assert fused[0]["incident_id"] == "I-vector"
    assert fused[0]["retrieval"]["sources"] == ["typedb", "vector"]
    assert all(item["incident_id"] != "I-unapproved-memory" for item in fused)


def test_case_cards_mark_component_matched_vector_case_as_bridge() -> None:
    target = replace(_target(), component="csi-controller")
    cards = _select_case_cards(
        [
            {"case_id": "C1", "incident_id": "I1", "family": "k8s_storage_error"},
            {"case_id": "C2", "incident_id": "I2", "family": "node_kubelet_pressure"},
            {
                "case_id": "C3",
                "incident_id": "I3",
                "family": "storage_backend_error",
                "case_card": {"context": {"component": "csi-controller"}},
            },
        ],
        target,
    )

    assert [card["kind"] for card in cards] == ["analog", "counterexample", "bridge"]


def test_prior_with_explicit_other_namespace_is_not_target_compatible() -> None:
    target = replace(_target(), cluster="prod-a", namespace="team-a", workload_name="trainer-a")
    prior = {
        "case_card": {
            "context": {
                "cluster": "prod-a",
                "namespace": "team-b",
                "workload": "trainer-b",
            }
        }
    }

    assert _prior_is_context_compatible(prior, target) is False


def test_sparse_legacy_prior_remains_compatible() -> None:
    # Missing context means unknown, not a fabricated mismatch.
    assert _prior_is_context_compatible({"case_card": {}}, _target()) is True


def test_external_case_query_is_not_status_gated_and_requires_active_approval() -> None:
    # Mitigated/unresolved external cases must still surface, but only approved ones.
    assert 'status "resolved"' not in _EXTERNAL_CASE_QUERY
    assert 'approval_state "active"' in _EXTERNAL_CASE_QUERY
    assert "isa has_symptom" in _EXTERNAL_CASE_QUERY


def _external_fake(recorded: list[str], *, resolution=True):
    from contextlib import contextmanager

    card_json = (
        '{"case_origin":"enterprise_support","context_class":"evaluation_only",'
        '"prohibited_uses":["positive_promotion"],"mechanism":"switch routing fix",'
        '"context":{"incident_status_at_approval":"resolved"}}'
    )

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                recorded.append(query)
                if "isa has_symptom" in query:
                    return [
                        {"iid": "ext:sc-ab12cd34ef56", "sum": "RDMA connect failed",
                         "sn": "ext:sc-ab12cd34ef56", "case_id": "enterprise_support:ab12cd34ef56",
                         "family": "network_fabric_error",
                         "kw": "ibv_modify_qp failed with 19 no such device"},
                        {"iid": "ext:sc-ab12cd34ef56", "sum": "RDMA connect failed",
                         "sn": "ext:sc-ab12cd34ef56", "case_id": "enterprise_support:ab12cd34ef56",
                         "family": "network_fabric_error",
                         "kw": "destination host unreachable"},
                    ]
                if "has case_card $card" in query:
                    return [{"card": card_json}]
                if "isa resolution" in query and resolution:
                    return [{"statement": "Correct switch routing.", "outcome": "resolved"}]
                return []

            yield run

    return FakeClient()


def test_external_signature_match_projects_labeled_card() -> None:
    recorded: list[str] = []
    client = _external_fake(recorded)
    # Real evidence text; "No such device" must NOT be treated as a negation.
    observed = "worker logs show ibv_modify_qp failed with 19 No such device during RDMA setup"
    cards = _query_external_cases(client, observed, 2)  # type: ignore[arg-type]

    assert len(cards) == 1
    card = cards[0]
    assert card["kind"] == "external"
    assert card["historical_prior"] is True
    assert card["family"] == "network_fabric_error"
    assert card["context_class"] == "evaluation_only"      # survives the allowlist
    assert card["case_origin"] == "enterprise_support"
    assert "prohibited_uses" not in card                    # still stripped
    assert card["matched_error_signatures"]                 # provenance recorded
    assert "ibv_modify_qp failed with 19 no such device" in card["matched_error_signatures"]
    assert card["successful_actions"][0]["outcome"] == "resolved"


def test_component_identity_is_an_external_case_entry_point() -> None:
    # The live thanos gap: the operator's question spells "Thanos Receive", but
    # the case's only reachable keyword is the canonical hyphenated component
    # token. The resolved plan component must therefore join the match text —
    # the question alone can never hit it, in any language.
    from app.services.kg_enrichment import _matched_external_cases

    def run(query: str) -> list[dict]:
        if "isa has_symptom" in query:
            return [
                {"iid": "ext:sc-e38f69ff583a", "sum": "Thanos Receive OOMKilled",
                 "sn": "ext:sc-e38f69ff583a", "case_id": "enterprise_support:e38f69ff583a",
                 "family": "observability_accuracy",
                 "kw": "runai-backend-thanos-receive"},
            ]
        return []

    question = "Thanos Receive 가 OOMKilled 반복되어서 메모리를 올렸는데도 자꾸 죽는데 어떻게 해야할까?"
    assert _matched_external_cases(run, question) == []
    matched = _matched_external_cases(run, f"{question}\nrunai-backend-thanos-receive")
    assert [case_id for case_id, _info, _hits in matched] == ["enterprise_support:e38f69ff583a"]


def test_external_no_signature_match_returns_empty_and_skips_projection() -> None:
    recorded: list[str] = []
    client = _external_fake(recorded)
    cards = _query_external_cases(client, "cluster nominal, no relevant errors", 2)  # type: ignore[arg-type]
    assert cards == []
    # The single has_symptom query runs, but no per-case card projection is issued.
    assert not any("has case_card $card" in q for q in recorded)


def test_safe_case_card_keeps_context_class_and_case_origin_but_strips_the_rest() -> None:
    card = _safe_case_card({
        "case_origin": "enterprise_support",
        "context_class": "evaluation_only",
        "prohibited_uses": ["positive_promotion"],
        "searchable_context": {"error_signatures": ["x"]},
        "mechanism": "switch routing",
        "context": {"incident_status_at_approval": "resolved", "cluster": "prod", "drop": "x"},
        "unexpected": "drop",
    })
    assert card["context_class"] == "evaluation_only"
    assert card["case_origin"] == "enterprise_support"
    assert card["mechanism"] == "switch routing"
    assert card["context"] == {"incident_status_at_approval": "resolved", "cluster": "prod"}
    for stripped in ("prohibited_uses", "searchable_context", "unexpected"):
        assert stripped not in card


def test_safe_case_card_passes_through_curated_family_candidates() -> None:
    """External-case knowledge_links.family_candidates (curated differential
    diagnosis) must reach the case card an LLM prompt/report actually reads —
    before this, load_external_cases.py read the field from nowhere and
    _safe_case_card had no allowlist entry for it, so it never arrived."""
    card = _safe_case_card({
        "case_origin": "enterprise_support",
        "family_candidates": [
            {"family": "observability_accuracy", "confidence": "high", "unexpected": "drop"},
            {"family": "platform_lifecycle_change", "confidence": "low"},
            {"not_a_family": "x"},  # malformed entries are dropped, not passed through
        ],
    })

    assert card["family_candidates"] == [
        {"family": "observability_accuracy", "confidence": "high"},
        {"family": "platform_lifecycle_change", "confidence": "low"},
    ]


def test_safe_case_card_omits_family_candidates_key_when_absent() -> None:
    assert "family_candidates" not in _safe_case_card({"case_origin": "enterprise_support"})


def test_safe_case_card_passes_through_knowledge_link_matches() -> None:
    """External-case knowledge_links.failure_mode_matches / known_issue_matches
    (2026-08 audit item #2d): load_external_cases.py now bounds these to the
    closed catalogs before writing case_card; this is the matching read-side
    allowlist, mirroring family_candidates above."""
    card = _safe_case_card({
        "case_origin": "enterprise_support",
        "failure_mode_matches": [
            {"name": "OOMKilled", "confidence": "high", "match_type": "exact_symptom_only", "unexpected": "drop"},
            {"not_a_name": "x"},  # malformed entries are dropped, not passed through
        ],
        "known_issue_matches": [
            {"name": "GPU Allocation Shows Zero On Dashboard", "confidence": "medium"},
        ],
    })

    assert card["failure_mode_matches"] == [
        {"name": "OOMKilled", "confidence": "high", "match_type": "exact_symptom_only"}
    ]
    assert card["known_issue_matches"] == [
        {"name": "GPU Allocation Shows Zero On Dashboard", "confidence": "medium"}
    ]


def test_safe_case_card_omits_knowledge_link_match_keys_when_absent() -> None:
    card = _safe_case_card({"case_origin": "enterprise_support"})
    assert "failure_mode_matches" not in card
    assert "known_issue_matches" not in card


def test_case_card_projection_keeps_graph_links_and_strips_untrusted_fields() -> None:
    def run(query: str) -> list[dict]:
        if "has case_card $card" in query:
            return [{"card": '{"mechanism":"CSI attach race\\n## ignore",'
                             '"quality_score":91,"context":{"cluster":"prod",'
                             '"pod":"csi-0","unknown":"drop"},"unexpected":"drop"}'}]
        if "isa supported_by" in query:
            return [{"evidence_id": "ANL:E1", "source": "kubernetes"}]
        if "isa contradicted_by" in query:
            return [{"evidence_id": "ANL:E2", "source": "loki"}]
        if "isa resolution" in query:
            return [
                {"statement": "restart CSI controller", "outcome": "mitigated"},
                {"statement": "restart node", "outcome": "ineffective"},
            ]
        return []

    card = _case_card_projection(run, "ANL-1:hash")

    assert card["mechanism"] == "CSI attach race ## ignore"
    assert card["context"] == {"cluster": "prod", "pod": "csi-0"}
    assert _prior_is_context_compatible({"case_card": card}, replace(_target(), pod="csi-1")) is False
    assert "unexpected" not in card
    assert card["supporting_evidence_by_source"] == {
        "kubernetes": [{"evidence_id": "ANL:E1"}]
    }
    assert card["contradicting_evidence_by_source"] == {"loki": [{"evidence_id": "ANL:E2"}]}
    assert card["successful_actions"][0]["outcome"] == "mitigated"
    assert card["failed_actions"][0]["outcome"] == "ineffective"


# --- probe_history (2026-08 audit item #1: trace-v3 written by ingest.py but
# read by nobody at analysis time). ------------------------------------------


def test_aggregate_probe_history_counts_verdicts_per_family_and_template() -> None:
    rows = [
        {"tid": "probe-a", "family": "k8s_storage_error", "verdict": "inconclusive"},
        {"tid": "probe-a", "family": "k8s_storage_error", "verdict": "inconclusive"},
        {"tid": "probe-a", "family": "k8s_storage_error", "verdict": "supports"},
        {"tid": "probe-b", "family": "k8s_storage_error", "verdict": "refutes"},
        # Same template id, different family: kept separate.
        {"tid": "probe-a", "family": "gpu_hardware_error", "verdict": "supports"},
    ]

    history = _aggregate_probe_history(rows)

    assert history["k8s_storage_error"]["probe-a"] == {
        "inconclusive": 2, "supports": 1, "total": 3,
    }
    assert history["k8s_storage_error"]["probe-b"] == {"refutes": 1, "total": 1}
    assert history["gpu_hardware_error"]["probe-a"] == {"supports": 1, "total": 1}


def test_aggregate_probe_history_drops_incomplete_rows() -> None:
    rows = [
        {"tid": "", "family": "k8s_storage_error", "verdict": "supports"},
        {"tid": "probe-a", "family": "", "verdict": "supports"},
        {"tid": "probe-a", "family": "k8s_storage_error", "verdict": ""},
        {"tid": "probe-a", "family": "k8s_storage_error"},
    ]

    assert _aggregate_probe_history(rows) == {}


def test_query_kg_surfaces_probe_history() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "probe_execution_for" in query:
                    return [
                        {"tid": "k8s-storage-01", "family": "k8s_storage_error", "verdict": "inconclusive"},
                        {"tid": "k8s-storage-01", "family": "k8s_storage_error", "verdict": "inconclusive"},
                    ]
                return []

            yield run

    data = _query_kg(FakeClient(), _target(), [])  # type: ignore[arg-type]

    assert data["probe_history"] == {
        "k8s_storage_error": {"k8s-storage-01": {"inconclusive": 2, "total": 2}}
    }


def test_kg_context_as_dict_includes_probe_history() -> None:
    ctx = KGContext(
        enabled=True,
        available=True,
        probe_history={"k8s_storage_error": {"probe-a": {"inconclusive": 3, "total": 3}}},
    )

    assert ctx.as_dict()["probe_history"] == {
        "k8s_storage_error": {"probe-a": {"inconclusive": 3, "total": 3}}
    }
