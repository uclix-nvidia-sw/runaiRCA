from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.decision_tree import walk_tree
from app.services.kg_enrichment import _query_diagnostic_tree
from ontology.load_troubleshooting import BUNDLED_RUNBOOK_ID, _document, _load, _probe_templates

TREE = Path("knowledge/k8s_troubleshooting_tree.yaml")


class _Answer:
    def resolve(self):
        return self

    def as_concept_rows(self):
        return []


class _Tx:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, text: str) -> _Answer:
        self.queries.append(text)
        return _Answer()


def test_loader_projects_every_yaml_step_transition_and_action() -> None:
    raw = _document(TREE)
    assert raw is not None
    expected_edges = sum(len(node.get("branches") or []) for node in raw["nodes"])
    expected_actions = sum(
        len((node.get("conclusion") or {}).get("next_steps") or []) for node in raw["nodes"]
    )
    tx = _Tx()

    nodes, edges, actions = _load(tx, raw)

    assert (nodes, edges, actions) == (len(raw["nodes"]), expected_edges, expected_actions)
    joined = "\n".join(tx.queries)
    assert "isa diagnostic_step" in joined
    assert "isa diagnostic_transition" in joined
    assert "isa diagnostic_outcome" in joined
    assert "isa diagnostic_recommendation" in joined


def test_loader_projects_authored_alternatives() -> None:
    """The YAML's authored differential diagnosis (``alternatives``: competing
    family + reason + discriminator) must reach TypeDB. Before this, the loader
    silently dropped every one of them, so the primary (TypeDB) path surfaced
    NO competing hypotheses while the degraded YAML-fallback path did."""
    raw = _document(TREE)
    assert raw is not None
    authored = [
        node
        for node in raw["nodes"]
        if isinstance(node.get("alternatives"), list) and node["alternatives"]
    ]
    assert len(authored) > 40  # 55 nodes carry authored alternatives as of writing

    tx = _Tx()
    _load(tx, raw)
    joined = "\n".join(tx.queries)
    assert "isa diagnostic_alternative" in joined

    sample = next(node for node in raw["nodes"] if node["id"] == "scheduling_capacity")
    first = sample["alternatives"][0]
    assert first["family"] == "runai_scheduling_quota"
    match_line = next(
        q
        for q in tx.queries
        if 'has diagnostic_id "scheduling_capacity"' in q and "diagnostic_alternative" in q
    )
    assert f'has reason "{first["reason"]}"' in match_line
    assert f'has discriminator "{first["discriminator"]}"' in match_line


def test_domain_runbooks_cover_every_step_and_name_the_real_coverage() -> None:
    # Browsing the ontology used to show ONE runbook ("k8s only") even though
    # the tree covers Run:ai scheduling, the GPU stack, NCCL and more. Every
    # step must land in exactly one domain view, and the non-k8s domains must
    # actually be populated.
    from ontology.load_troubleshooting import RUNBOOK_NAME, step_domain

    raw = _document(TREE)
    assert raw is not None
    domains = {str(node["id"]): step_domain(str(node["id"])) for node in raw["nodes"]}
    populated = set(domains.values())
    for expected in ("runai_scheduling", "runai_control_plane", "gpu_stack", "distributed_training", "storage", "networking", "node_health"):
        assert expected in populated, f"domain {expected} has no steps"

    tx = _Tx()
    _load(tx, raw)
    joined = "\n".join(tx.queries)
    for domain in populated:
        assert f"{RUNBOOK_NAME}:domain:{domain}" in joined
    # Domain views must not add entry points or touch probe IDs.
    assert joined.count("isa runbook_entry;") == 1


def test_schema_models_executable_runbook_relations() -> None:
    schema = Path("ontology/schema.tql").read_text(encoding="utf-8")
    for label in (
        "entity diagnostic_step",
        "relation runbook_contains",
        "relation runbook_entry",
        "relation diagnostic_transition",
        "relation diagnostic_outcome",
        "relation diagnostic_recommendation",
        "entity diagnostic_probe_template",
        "relation probe_template_for",
    ):
        assert label in schema
    assert "probe_arguments" not in schema


def test_probe_templates_have_stable_ids_and_keep_legacy_json_projection() -> None:
    raw = _document(TREE)
    assert raw is not None
    probes = [probe for node in raw["nodes"] for probe in node.get("probes") or []]
    ids = [probe.get("id") for probe in probes]
    assert raw["runbook_id"] == BUNDLED_RUNBOOK_ID
    assert all(isinstance(probe_id, str) and probe_id for probe_id in ids)
    assert len(ids) == len(set(ids))
    for node in raw["nodes"]:
        for probe in node.get("probes") or []:
            assert probe["id"].startswith(f"{BUNDLED_RUNBOOK_ID}:{node['id']}:p")

    tx = _Tx()
    _load(tx, raw)
    queries = "\n".join(tx.queries)
    assert "isa diagnostic_probe_template" in queries
    assert "isa probe_template_for" in queries
    legacy = next(query for query in tx.queries if "has probe_template" in query)
    encoded = legacy.split('has probe_template "', 1)[1].rsplit('";', 1)[0]
    assert json.loads(encoded.replace('\\"', '"'))["id"]


def test_probe_template_for_insert_binds_entities_only() -> None:
    """The relation insert's match must NOT assert probe_template_for itself.

    The loader only reaches the insert after that exact pattern matched zero
    rows, so a match clause containing the relation makes the insert a silent
    no-op — exit 0, permanently empty relation (live-TypeDB finding
    2026-08-10; substring assertions alone cannot catch it)."""
    tx = _Tx()
    _load(tx, _document(TREE))
    inserts = [
        query
        for query in tx.queries
        if "insert (step: $s, template: $p) isa probe_template_for" in query
    ]
    assert inserts, "loader must attempt the probe_template_for insert"
    for query in inserts:
        match_clause = query.split("insert", 1)[0]
        assert "probe_template_for" not in match_clause


def test_bundled_probe_id_must_include_runbook_and_step_scope() -> None:
    with pytest.raises(ValueError, match="bundled diagnostic probe id"):
        _probe_templates(
            [{"id": "scheduling_capacity-probe-01", "tool": "k8s_read"}],
            "scheduling_capacity",
            runbook_id=BUNDLED_RUNBOOK_ID,
            enforce_scoped=True,
        )


def test_typedb_projection_reconstructs_executable_tree() -> None:
    def run(query: str) -> list[dict]:
        if "diagnostic_steps_for_runbook" in query:
            return [
                {
                    "id": "root",
                    "q": "Which layer failed?",
                    "v": "Read the first event",
                    "i": "Classify the layer",
                    "a": "Do not restart",
                    "m": '{"always":true}',
                },
                {
                    "id": "leaf",
                    "q": "Is the node pressured?",
                    "v": "Read node conditions",
                    "i": "Pressure is node-wide",
                    "a": "Do not blame the pod",
                    "m": '{"any":["diskpressure"]}',
                },
            ]
        if "entry_steps_for_runbook" in query:
            return [{"id": "root"}]
        if "diagnostic_transitions_for_runbook" in query:
            return [
                {
                    "pid": "root",
                    "nid": "leaf",
                    "m": '{"any":["diskpressure"]}',
                    "priority": 0,
                }
            ]
        if "diagnostic_outcomes_for_runbook" in query:
            return [
                {
                    "id": "leaf",
                    "family": "node_kubelet_pressure",
                    "sum": "Node disk pressure",
                    "conf": "high",
                }
            ]
        if "diagnostic_actions_for_runbook" in query:
            return [{"id": "leaf", "st": "Cordon the node", "seq": 0}]
        if "diagnostic_disconfirmations_for_runbook" in query:
            return [{"id": "leaf", "d": "DiskPressure is False"}]
        if "diagnostic_alternatives_for_runbook" in query:
            return [
                {
                    "id": "root",
                    "family": "runai_scheduling_quota",
                    "reason": "Run:ai policy can produce an indistinguishable Pending workload.",
                    "disc": "Check whether runai-scheduler-default emitted the first event.",
                    "seq": 0,
                }
            ]
        if "has principle" in query:
            return [{"p": "Preserve evidence"}]
        if "has source_url" in query:
            return [{"s": "https://kubernetes.io/docs/"}]
        return []

    tree = _query_diagnostic_tree(run)
    walked = walk_tree(tree, "Node condition DiskPressure=True")

    assert walked["path"] == ["root", "leaf"]
    assert walked["conclusion"]["family"] == "node_kubelet_pressure"
    assert walked["conclusion"]["next_steps"] == ["Cordon the node"]
    assert walked["conclusion"]["disconfirm"] == ["DiskPressure is False"]
    # The graph-projected alternative must reach the SAME step["alternatives"]
    # shape planner._diagnostic_directive turns into competing_hypotheses —
    # previously always empty on the TypeDB path (see load_troubleshooting.py).
    assert walked["steps"][0]["alternatives"] == [
        {
            "family": "runai_scheduling_quota",
            "reason": "Run:ai policy can produce an indistinguishable Pending workload.",
            "discriminator": "Check whether runai-scheduler-default emitted the first event.",
        }
    ]
