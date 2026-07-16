from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace

from app.collectors.base import AnalysisTarget
from app.config import load_settings
from app.services.kg_enrichment import (
    _EXTERNAL_CASE_QUERY,
    KGContext,
    _case_card_projection,
    _prior_is_context_compatible,
    _query_external_cases,
    _query_kg,
    _query_remediation,
    _rrf_case_priors,
    _safe_case_card,
    _select_case_cards,
    enrich,
)
from app.services.pipeline import (
    _graph_remediation_lines,
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


def test_root_chain_walks_leads_to_transitively() -> None:
    """Observing XID 154 must surface the true origin 144 (chain 144 -> 48 -> 154),
    not just the one-hop intermediate 48."""
    import re

    # reverse leads_to graph: effect -> [immediate causes]
    causes = {154: [48], 48: [144], 144: []}

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                m = re.search(r"root_xids_for\((\d+)\)", query)
                if m:
                    code = int(m.group(1))
                    return [{"x": c} for c in causes.get(code, [])]
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [154], "")  # type: ignore[arg-type]
    # Transitive ancestors, nearest hop first.
    assert out.root_xids[154] == [48, 144]
    # Fixes fetched for each discovered root too.
    assert 48 in out.xid_fixes and 144 in out.xid_fixes


def test_root_chain_is_cycle_safe() -> None:
    import re

    # pathological cycle 45 -> 74 -> 45; must terminate and not repeat.
    causes = {45: [74], 74: [45]}

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                m = re.search(r"root_xids_for\((\d+)\)", query)
                if m:
                    return [{"x": c} for c in causes.get(int(m.group(1)), [])]
                return []

            yield run

    out = _query_remediation(FakeClient(), "", [45], "")  # type: ignore[arg-type]
    assert out.root_xids[45] == [74]  # 45 itself excluded, no infinite loop


def test_root_chain_hop_failure_is_isolated() -> None:
    import re

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
                if "fixes_for_xid" in query:
                    return [{"x": "reset the GPU"}]
                if re.search(r"root_xids_for\(\d+\)", query):
                    raise RuntimeError("leads_to function missing on this TypeDB build")
                return []

            yield run

    # A broken root walk must not wipe the observed XID's own fixes.
    out = _query_remediation(FakeClient(), "", [79], "")  # type: ignore[arg-type]
    assert out.xid_fixes[79] == ["reset the GPU"]
    assert 79 not in out.root_xids


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
    assert "Diagnostic guidance (XID 79): Check for PCIe link errors before reset." in "\n".join(
        _graph_remediation_lines(out)
    )
    assert _xid_diagnostic_guidance_lines(out, "ko") == [
        "- 진단 안내 (XID 79): Check for PCIe link errors before reset."
    ]


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


def test_query_kg_projects_typedb_symptom_metadata() -> None:
    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
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
                "component": "cluster-sync",
                "symptom_ko": "메모리 부족 종료",
                "reason_ko": "메모리 제한을 초과했습니다.",
                "actions_ko": ["누수를 수정하세요.", "메모리 제한을 높이세요."],
            }
        ]
    }


def test_typedb_failure_mode_symptom_delivery_chain_contract() -> None:
    # When a consumer starts reading a new failure_modes symptom field, add it to the
    # TypeDB loader (load_knowledge.py), the read-back (kg_enrichment.py), and this list.
    contract = {
        "symptom": "OOMKilled",
        "keywords": ["oom", "oomkilled"],
        "actions": ["Inspect memory limit.", "Raise memory limit."],
        "reason": "Memory limit exceeded.",
        "exclusive_actions": True,
        "reason_ko": "메모리 제한을 초과했습니다.",
        "actions_ko": ["메모리 제한을 높이세요.", "메모리 제한을 점검하세요."],
        "component": "cluster-sync",
        "symptom_ko": "메모리 부족 종료",
    }

    class FakeClient:
        @contextmanager
        def open_reader(self):
            def run(query: str) -> list[dict]:
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
    for field in set(contract) - {"keywords", "actions", "actions_ko", "exclusive_actions"}:
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
        {"runai_control_plane_error": [typedb_symptom]},
        "",
        components=components,
    )
    yaml_lines = _playbook_lines(
        None,
        "cluster sync unhealthy",
        {"runai_control_plane_error": [{**typedb_symptom}]},
        "",
        components=components,
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
    assert 'gpu_hardware_error\\"; delete $x;\\\\' in joined
    assert 'A100\\"; match $x isa incident;\\\\' in joined
    assert 'fixes_for_family("gpu_hardware_error"; delete' not in joined
    assert 'xids_for_gpu_model("A100"; match' not in joined


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
