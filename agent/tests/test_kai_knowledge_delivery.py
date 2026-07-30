"""The KAI knowledge must survive every hop to a consumer, not just exist.

Authoring a fact in YAML is the easy half; the recurring failure in this repo is
a fact that never reaches the layer that needed it. These tests walk each hop:
YAML -> TypeDB loader writes -> planner identity -> drill-down thinking material.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.knowledge import (
    component_check_lines,
    load_architecture,
    load_failure_modes,
    match_failure_mode_symptoms,
)
from ontology.load_architecture import _ensure_component
from ontology.load_knowledge import _ensure_symptom

_BIND_SYMPTOM = "Bind Failed After Scheduling Decision"


class _FakeTx:
    """Records every TypeQL string; reads answer 'nothing exists yet'."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, query: str) -> Any:
        self.queries.append(query)
        return self

    def resolve(self) -> Any:
        return self

    def as_concept_rows(self) -> list[Any]:
        return []


@pytest.fixture(scope="module")
def modes() -> dict[str, list[dict]]:
    return load_failure_modes("knowledge/failure_modes.yaml")


@pytest.fixture(scope="module")
def architecture() -> dict[str, dict]:
    return load_architecture("knowledge/runai_architecture.yaml")


def _symptom(modes: dict[str, list[dict]], name: str) -> dict:
    for symptoms in modes.values():
        for symptom in symptoms:
            if str(symptom.get("symptom") or symptom.get("name")) == name:
                return symptom
    raise AssertionError(f"symptom not in the catalogue: {name}")


def test_loader_writes_every_field_the_new_entries_carry(modes) -> None:
    """No loader change was needed — this proves it rather than assuming it."""
    symptom = _symptom(modes, "Consolidation Reallocated Running Workloads")
    tx = _FakeTx()

    _ensure_symptom(
        tx,
        "Consolidation Reallocated Running Workloads",
        [str(k) for k in symptom["keywords"]],
        str(symptom.get("reason") or ""),
        str(symptom.get("reason_ko") or ""),
        symptom.get("exclusive_actions") is True,
        [str(a) for a in symptom.get("actions_ko") or []],
        str(symptom.get("component") or ""),
        str(symptom.get("name_ko") or ""),
    )
    written = "\n".join(tx.queries)

    assert "isa symptom" in written
    # The upstream misspelling has to survive verbatim into the graph.
    assert 'has keyword "sucesfully consolidated for job"' in written
    assert "has reason " in written and "has reason_ko " in written
    assert 'has component "runai-scheduler-default"' in written
    assert "has name_ko " in written
    # actions_ko land as statement_ko on the symptom.
    assert "has statement_ko " in written


def test_bind_symptom_loads_its_exclusive_flag(modes) -> None:
    symptom = _symptom(modes, _BIND_SYMPTOM)
    tx = _FakeTx()

    _ensure_symptom(
        tx,
        _BIND_SYMPTOM,
        [str(k) for k in symptom["keywords"]],
        exclusive_actions=symptom.get("exclusive_actions") is True,
    )

    assert "has exclusive_actions true" in "\n".join(tx.queries)


def test_reservation_check_loads_as_a_component_check(architecture) -> None:
    """The reservation Pod's location is architecture data, not action prose."""
    binder = architecture["binder"]
    tx = _FakeTx()

    _ensure_component(tx, {"component": "binder", **binder})
    written = "\n".join(tx.queries)

    assert "isa control_plane_component" in written
    assert "gpu-reservation" in written
    assert "has check_command" in written
    # Stale checks are cleared first, so a removed YAML line cannot linger.
    assert "delete has $old of $c" in written


def test_reservation_check_reaches_the_report_playbook(architecture) -> None:
    lines = " ".join(component_check_lines(architecture, "binder"))

    assert "gpu-reservation" in lines


def test_reservation_check_reaches_the_drilldown_thinking_material() -> None:
    """The investigating agent, not only the finished report, must see the check."""
    from app.collectors.base import AnalysisTarget, CollectorResult
    from app.services.drilldown import _implicated_architecture
    from tests.test_orchestrator import make_settings

    target = AnalysisTarget(
        cluster="",
        project="test1",
        queue="",
        namespace="runai-test1",
        workload_name="binder",
        workload_type="Deployment",
        runai_workload_id="",
        node="dgx02",
        pod="binder-7d9f",
        severity="warning",
        alert_name="KubePodNotReady",
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="binder degraded")

    lines = _implicated_architecture(make_settings(), result, target)
    joined = "\n".join(lines)

    # Both halves: which dependency to check next AND how to interrogate it.
    assert "binder check order:" in joined
    assert "gpu-reservation" in joined


def test_bind_failure_signature_and_component_agree(modes, architecture) -> None:
    """The symptom's component must exist in the catalogue it points at."""
    matches = match_failure_mode_symptoms(
        modes, "failed to bind pod runai-test1/trainer-0 to node dgx01".lower()
    )
    _family, symptom = matches[0]
    component = str(symptom.get("component") or "")

    assert component == "binder"
    assert component in architecture, "symptom points at a component with no topology entry"
    assert architecture[component].get("depends_on"), "no dependency chain to walk"
