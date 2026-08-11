from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from app.collectors import kubernetes, runai, runai_mcp
from app.collectors.base import (
    CollectorResult,
    artifact,
    classify_scope_less_quantity_alert,
    resolve_target,
)
from app.config import load_settings
from app.plan import InvestigationPlan
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.kg_enrichment import KGContext
from tests.test_orchestrator import make_settings

FIXTURES = Path(__file__).parent / "fixtures" / "runai_mcp"


def _payload(name: str) -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def _request() -> AlertAnalysisRequest:
    # Verbatim shape of live alert ALR-1782967135070104135-000003: the value
    # metadata lives in ANNOTATIONS and carries BOTH __value_string__ and the
    # flat refId-to-number __values__ form. A replay that drops either key
    # would not catch a classifier that chokes on the real payload.
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "Ready GPUs"},
            annotations={
                "__value_string__": (
                    "[ var='A' labels={} value=8 ], [ var='C' labels={} value=1 ]"
                ),
                "__values__": '{"A":8,"C":1}',
            },
        )
    )


def _state(*, enabled: bool = True) -> pipeline.PipelineState:
    settings = replace(
        make_settings(),
        enable_quantity_scope_derivation=enabled,
        runai_mcp_url="http://runai-mcp/mcp",
        analysis_deadline_seconds=0,
    )
    state = pipeline.new_state(settings, _request(), collectors=[])
    state.kg_context = KGContext()
    state.plan = InvestigationPlan()
    return state


def test_quantity_scope_setting_defaults_off_and_reads_env(monkeypatch) -> None:
    monkeypatch.delenv("ENABLE_QUANTITY_SCOPE_DERIVATION", raising=False)
    assert load_settings().enable_quantity_scope_derivation is False
    monkeypatch.setenv("ENABLE_QUANTITY_SCOPE_DERIVATION", "true")
    assert load_settings().enable_quantity_scope_derivation is True


def test_scope_less_quantity_classifier_accepts_live_grafana_shape() -> None:
    request = _request()
    target = resolve_target(request.alert.labels, request.alert.annotations)

    assert (
        classify_scope_less_quantity_alert(request.alert.labels, request.alert.annotations, target)
        == "gpu"
    )


def test_scope_less_quantity_classifier_accepts_empty_label_json_values() -> None:
    labels = {
        "alertname": "Ready GPU",
        "__values__": json.dumps(
            {"A": {"Labels": {}, "Value": 8}, "C": {"labels": {}, "value": 1}}
        ),
    }
    assert classify_scope_less_quantity_alert(labels, {}, resolve_target(labels, {})) == "gpu"


def test_scope_less_quantity_classifier_accepts_flat_refid_json_values() -> None:
    """The live incident's __values__ is the FLAT refId-to-number form.

    Grafana emits '{"A":8,"C":1}' (no Labels/Value wrapper); the classifier
    originally only counted numbers under a literal Value/value key, so the
    real alert — which carries this annotation alongside __value_string__ —
    classified as "" and the whole derivation was a dead guard."""
    labels = {"alertname": "Ready GPUs", "__values__": '{"A":8,"C":1}'}
    assert classify_scope_less_quantity_alert(labels, {}, resolve_target(labels, {})) == "gpu"


@pytest.mark.parametrize(
    ("labels", "annotations"),
    [
        ({"alertname": "Ready GPUs", "node": "dgx02", "__value_string__": "value=8"}, {}),
        ({"alertname": "Ready GPUs", "pod": "trainer-0", "__value_string__": "value=8"}, {}),
        (
            {
                "alertname": "Ready GPUs",
                "namespace": "team-a",
                "__value_string__": "value=8",
            },
            {},
        ),
        ({"alertname": "Ready GPUs", "__value_string__": "value=not-a-number"}, {}),
        (
            {
                "alertname": "Ready GPUs",
                "__value_string__": "labels={node=dgx02} value=8",
            },
            {},
        ),
        ({"alertname": "Ready GPUs", "__value_string__": "value=NaN"}, {}),
        ({"alertname": "Ready GPUs", "__value_string__": "value=Infinity"}, {}),
        ({"alertname": "Ready GPUs", "__values__": "not-json"}, {}),
        (
            {
                "alertname": "Ready GPUs",
                "__values__": '{"A":{"Labels":{"node":"dgx02"},"Value":8}}',
            },
            {},
        ),
        ({"alertname": "Ready GPUs", "__values__": '{"A":{"Value":true}}'}, {}),
        ({"alertname": "Ready CPUs", "__value_string__": "labels={} value=8"}, {}),
        (
            {"alertname": "Ready GPUs"},
            {"summary": "8 GPUs appear in prose but no Grafana value exists"},
        ),
    ],
    ids=[
        "node",
        "pod",
        "namespace",
        "nonnumeric",
        "embedded-label",
        "nan",
        "infinity",
        "malformed-json",
        "json-label",
        "boolean-json-value",
        "non-gpu",
        "prose-number",
    ],
)
def test_scope_less_quantity_classifier_rejects_unsupported_shapes(
    labels: dict[str, str], annotations: dict[str, str]
) -> None:
    assert (
        classify_scope_less_quantity_alert(labels, annotations, resolve_target(labels, annotations))
        == ""
    )


@pytest.mark.asyncio
async def test_fixture_reconciliation_nominates_dgx02(monkeypatch) -> None:
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")

    async def inputs(*_args):
        return inventory, health, False

    async def no_fallback(*_args):
        raise AssertionError("health nomination must not call Kubernetes")

    monkeypatch.setattr(runai_mcp, "fetch_quantity_scope_inputs", inputs)
    monkeypatch.setattr(kubernetes, "resolve_unique_gpu_deficit_node", no_fallback)

    result = await pipeline._quantity_scope_round(_state())

    assert result is not None
    assert result[0] == "dgx02"
    assert result[-1] == 8


@pytest.mark.asyncio
async def test_authenticated_helper_calls_only_the_two_scope_tools_in_order(
    monkeypatch,
) -> None:
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")
    calls: list[tuple[str, dict, dict]] = []

    async def headers(*_args, **_kwargs):
        return {"Authorization": "Bearer token"}, []

    async def cluster_id(*_args):
        return "cluster-id"

    class Result:
        isError = False

        def __init__(self, payload):
            self.payload = payload

    async def mcp_call(_url, tool, arguments, *, headers):
        calls.append((tool, arguments, headers))
        return Result(inventory if tool == "get_cluster_physical_inventory" else health)

    monkeypatch.setattr(runai, "_runai_headers", headers)
    monkeypatch.setattr(runai_mcp, "resolve_runai_cluster_id", cluster_id)
    monkeypatch.setattr(runai_mcp, "mcp_call", mcp_call)
    monkeypatch.setattr(runai_mcp, "_tool_json", lambda result: result.payload)

    result = await runai_mcp.fetch_quantity_scope_inputs(
        replace(make_settings(), runai_mcp_url="http://runai-mcp/mcp"),
        resolve_target({}, {}),
    )

    assert result == (inventory, health, False)
    assert calls == [
        (
            "get_cluster_physical_inventory",
            {"clusterId": "cluster-id"},
            {"Authorization": "Bearer token"},
        ),
        (
            "get_cluster_infrastructure_health",
            {"clusterId": "cluster-id"},
            {"Authorization": "Bearer token"},
        ),
    ]


def _deficit_zero(inventory: dict, _health: dict) -> None:
    inventory["totals"]["gpusAllocatable"] = 16


def _allocatable_above_total(inventory: dict, _health: dict) -> None:
    inventory["totals"]["gpusAllocatable"] = 17


def _two_gpu_nodes(_inventory: dict, health: dict) -> None:
    other = copy.deepcopy(health["unhealthyNodes"][0])
    other["name"] = "dgx03"
    other["gpus"]["count"] = 1
    health["unhealthyNodes"].append(other)


def _zero_gpu_node(_inventory: dict, health: dict) -> None:
    health["unhealthyNodes"][0]["gpus"]["count"] = 0


def _count_mismatch(_inventory: dict, health: dict) -> None:
    health["unhealthyNodes"][0]["gpus"]["count"] = 7


def _missing_field(_inventory: dict, health: dict) -> None:
    del health["unhealthyNodes"][0]["gpus"]


def _malformed_type(inventory: dict, _health: dict) -> None:
    inventory["totals"]["gpusTotal"] = "16"


def _malformed_health_type(_inventory: dict, health: dict) -> None:
    health["unhealthyNodes"][0]["gpus"]["count"] = "8"


def _missing_inventory_field(inventory: dict, _health: dict) -> None:
    del inventory["totals"]["gpusAllocatable"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate",
    [
        _deficit_zero,
        _allocatable_above_total,
        _two_gpu_nodes,
        _zero_gpu_node,
        _count_mismatch,
        _missing_field,
        _malformed_type,
        _malformed_health_type,
        _missing_inventory_field,
    ],
)
async def test_fixture_mutations_fail_closed(monkeypatch, mutate) -> None:  # noqa: ANN001
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")
    mutate(inventory, health)

    async def inputs(*_args):
        return inventory, health, False

    async def no_fallback(*_args):
        raise AssertionError("only an empty/failed health call permits fallback")

    monkeypatch.setattr(runai_mcp, "fetch_quantity_scope_inputs", inputs)
    monkeypatch.setattr(kubernetes, "resolve_unique_gpu_deficit_node", no_fallback)

    assert await pipeline._quantity_scope_round(_state()) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("health_failed", [False, True])
async def test_empty_or_failed_health_uses_matching_kubernetes_fallback(
    monkeypatch, health_failed: bool
) -> None:
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")
    health["unhealthyNodes"] = []

    async def inputs(*_args):
        return inventory, None if health_failed else health, health_failed

    async def fallback(*_args):
        return "dgx02", Decimal(8)

    monkeypatch.setattr(runai_mcp, "fetch_quantity_scope_inputs", inputs)
    monkeypatch.setattr(kubernetes, "resolve_unique_gpu_deficit_node", fallback)

    result = await pipeline._quantity_scope_round(_state())
    assert result is not None and result[0] == "dgx02"


@pytest.mark.asyncio
async def test_kubernetes_fallback_must_match_inventory_deficit(monkeypatch) -> None:
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")
    health["unhealthyNodes"] = []

    async def inputs(*_args):
        return inventory, health, False

    async def fallback(*_args):
        return "dgx02", Decimal(7)

    monkeypatch.setattr(runai_mcp, "fetch_quantity_scope_inputs", inputs)
    monkeypatch.setattr(kubernetes, "resolve_unique_gpu_deficit_node", fallback)

    assert await pipeline._quantity_scope_round(_state()) is None


@pytest.mark.asyncio
async def test_kubernetes_fallback_requires_one_complete_positive_deficit(monkeypatch) -> None:
    nodes = {
        "metadata": {"continue": ""},
        "items": [
            {"metadata": {"name": "cpu01"}, "status": {}},
            {
                "metadata": {"name": "dgx01"},
                "status": {
                    "capacity": {"nvidia.com/gpu": "8"},
                    "allocatable": {"nvidia.com/gpu": "8"},
                },
            },
            {
                "metadata": {"name": "dgx02"},
                "status": {
                    "capacity": {"nvidia.com/gpu": "8"},
                    "allocatable": {"nvidia.com/gpu": "0"},
                },
            },
        ],
    }

    async def read(*_args, **_kwargs):
        return {"status_code": 200, "error": None, "data": nodes}

    monkeypatch.setattr(kubernetes, "k8s_read", read)
    assert await kubernetes.resolve_unique_gpu_deficit_node(make_settings()) == (
        "dgx02",
        Decimal(8),
    )


@pytest.mark.asyncio
async def test_flag_off_short_circuits_before_classifier(monkeypatch) -> None:
    state = _state(enabled=False)
    original_target = state.target
    state.plan = None

    def forbidden(*_args):
        raise AssertionError("classifier called while rollout flag was off")

    async def plan(*_args):
        return InvestigationPlan()

    monkeypatch.setattr(pipeline, "classify_scope_less_quantity_alert", forbidden)
    monkeypatch.setattr(pipeline, "plan_investigation", plan)

    await pipeline.plan_stage(state)

    assert state.target == original_target
    assert state.plan is not None and state.plan.as_dict() == InvestigationPlan().as_dict()
    assert state.extra_warnings == []
    assert state.scope_derivation is None


@pytest.mark.asyncio
async def test_timeout_leaves_response_relevant_state_unchanged(monkeypatch) -> None:
    state = _state()

    async def blocked(*_args):
        await asyncio.sleep(60)

    monkeypatch.setattr(pipeline, "_quantity_scope_round", blocked)
    monkeypatch.setattr(pipeline, "_QUANTITY_SCOPE_DERIVATION_TIMEOUT_SECONDS", 0.001)
    before = (
        state.target,
        state.plan.as_dict(),
        list(state.warnings),
        list(state.extra_warnings),
        list(state.artifacts),
        state.scope_derivation,
    )

    await pipeline._derive_quantity_alert_scope(state)

    assert (
        state.target,
        state.plan.as_dict(),
        state.warnings,
        state.extra_warnings,
        state.artifacts,
        state.scope_derivation,
    ) == before


@pytest.mark.asyncio
async def test_ready_gpus_replay_promotes_only_effective_scope_and_provenance(
    monkeypatch,
) -> None:
    inventory = _payload("cluster_physical_inventory.json")
    health = _payload("cluster_infrastructure_health.json")

    async def inputs(*_args):
        return inventory, health, False

    async def plan(*_args):
        return InvestigationPlan()

    class VerifiedNodeCollector:
        name = "fixture"

        async def collect(self, target, _plan):  # noqa: ANN001
            return CollectorResult(
                agent=self.name,
                status="ok",
                summary=f"{target.node} is NotReady",
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="kubernetes",
                        type="node_condition",
                        status="ok",
                        confidence="high",
                        summary=f"{target.node} is NotReady",
                        result={
                            "observation": {
                                "predicate": "node_ready",
                                "polarity": "present",
                                "coverage": "scoped",
                                "target_identity_verified": True,
                                "observed_entity": {
                                    "kind": "node",
                                    "name": target.node,
                                },
                            }
                        },
                    )
                ],
            )

    monkeypatch.setattr(runai_mcp, "fetch_quantity_scope_inputs", inputs)
    monkeypatch.setattr(pipeline, "plan_investigation", plan)
    state = _state()
    state.plan = None
    state.collectors = [VerifiedNodeCollector()]

    await pipeline.plan_stage(state)

    assert state.plan is not None and state.plan.node == "dgx02"
    assert state.target.node == "dgx02"
    assert state.target.node_source == "derived_from_inventory_deficit"
    assert state.declared_target is not None and state.declared_target.node == ""
    assert state.scope_derivation is not None
    assert state.scope_derivation["evidence_role"] == "scope_seed_not_causal_evidence"
    assert "target_identity_verified" not in state.scope_derivation

    pipeline._apply_effective_target(state)
    assert state.target.node_source == "derived_from_inventory_deficit"

    await pipeline.evidence_stage(state)
    await pipeline.rank_stage(state)
    await pipeline.self_check_stage(state)
    await pipeline.synthesize_stage(state)

    assert state.response is not None
    assert state.response.context["scope_derivation"] == state.scope_derivation
    assert "derived from a unique physical-versus-allocatable GPU deficit" in state.detail
    assert "the alert did not declare a node" in state.detail
    assert all(artifact.type != "scope_derivation" for artifact in state.response.artifacts)
    verified = next(
        artifact for artifact in state.response.artifacts if artifact.type == "node_condition"
    )
    assert verified.evidence_id in pipeline._eligible_support_ids_for_output(state)


def test_report_omits_derived_scope_without_receipt() -> None:
    detail = pipeline._detail_from(
        _request(),
        [],
        [],
        knowledge=pipeline.ReportKnowledge(language="en"),
        effective_target=replace(resolve_target(_request().alert.labels, {}), node="dgx02"),
    )
    assert "Investigation scope candidate" not in detail
