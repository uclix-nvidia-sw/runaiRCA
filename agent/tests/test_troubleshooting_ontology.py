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
