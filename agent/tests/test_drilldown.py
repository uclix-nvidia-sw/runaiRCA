from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import AnalysisTarget, CollectorResult
from app.llm import begin_usage_tracking
from app.plan import InvestigationPlan
from app.schemas import AlertAnalysisArtifact
from app.services import drilldown
from app.services.drilldown import (
    _tool_k8s_describe,
    _tool_k8s_logs,
    _tool_logql,
    _tool_promql,
    _tool_runai_cluster_infrastructure_health,
    _tool_runai_cluster_metrics,
    _tool_runai_cluster_physical_inventory,
    _tool_runai_department_resources,
    _tool_runai_project_resources,
    _tool_runai_workload_effective_policy,
    _tool_runai_workload_status,
    _tool_runai_workload_summary,
    run_drilldowns,
)
from app.services.evidence_blackboard import Blackboard
from app.services.root_cause_ranking import _artifact_is_evidence
from tests.test_orchestrator import make_settings


def drill_settings(**overrides):
    return replace(
        make_settings(),
        enable_agent_drilldown=True,
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        **overrides,
    )


def test_kubernetes_read_rejects_non_resource_kind_before_execution() -> None:
    assert not drilldown._valid_domain_query(
        {"tool": "k8s_read", "args": {"kind": "promql"}}
    )
    assert not drilldown._valid_domain_query(
        {"tool": "k8s_read", "args": {"kind": "deployment_history"}}
    )
    assert drilldown._valid_domain_query(
        {"tool": "k8s_read", "args": {"kind": "deployments"}}
    )


def test_kubernetes_prompt_refuses_configuration_as_observed_preemption() -> None:
    prompt = drilldown._system_prompt("kubernetes", {})

    assert "spec.preemptionPolicy=PreemptLowerPriority does NOT prove" in prompt
    assert "require an active condition or target-scoped Warning Event" in prompt


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai-vision",
        workload_name="train-1",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="",
        severity="warning",
        alert_name="TestAlert",
    )


def _k8s_result() -> CollectorResult:
    return CollectorResult(
        agent="kubernetes", status="ok", summary="pod train-1-0 Pending; FailedScheduling"
    )


def test_disabled_flag_means_no_llm_calls(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls.append(system)
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    settings = replace(drill_settings(), enable_agent_drilldown=False)
    result = _k8s_result()
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    assert calls == []
    assert result.artifacts == []


def test_drilldown_blackboard_records_the_incident_window() -> None:
    target = replace(
        _target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    board = Blackboard()
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="pod train-1-0 Pending; FailedScheduling",
        artifacts=[
            AlertAnalysisArtifact(
                agent="kubernetes",
                source="kubernetes",
                type="k8s_read",
                status="ok",
                confidence="high",
                summary="Pod train-1-0 remained Pending during the incident.",
                    result={
                        "observation": {
                            "polarity": "present",
                            "coverage": "scoped",
                            "observed_entity": {"kind": "workload_name", "name": "train-1"},
                        }
                    },
            )
        ],
    )

    drilldown._record_blackboard(board, result, target)

    fact = board.facts()[0]
    assert fact.observation_window == ("2026-07-10T00:55:00Z", "2026-07-10T01:10:00Z")
    assert fact.eligibility.from_fact(
        fact,
        context={
            "window_start": "2026-07-10T00:55:00Z",
            "window_end": "2026-07-10T01:10:00Z",
        },
    ).support


@pytest.mark.asyncio
async def test_metric_and_log_drilldowns_preserve_mcp_errors_and_incident_window(
    monkeypatch,
) -> None:
    target = replace(
        _target(), fired_at="2026-07-10T01:00:00Z", resolved_at="2026-07-10T01:10:00Z"
    )
    seen_prom_window: dict[str, str] | None = None
    seen_loki_window: dict[str, str] | None = None

    async def fake_prom_mcp(settings, name, query, *, time_range=None):
        nonlocal seen_prom_window
        seen_prom_window = time_range
        return {"error": "Prometheus MCP response missing data.result"}

    async def fake_loki_mcp(settings, name, query, *, time_range=None):
        nonlocal seen_loki_window
        seen_loki_window = time_range
        return {"error": "Loki MCP response missing a recognized log result"}

    monkeypatch.setattr(drilldown, "prom_mcp_query", fake_prom_mcp)
    monkeypatch.setattr(drilldown, "loki_mcp_query", fake_loki_mcp)
    settings = drill_settings(
        prometheus_mcp_url="http://prom-mcp",
        loki_mcp_url="http://loki-mcp",
    )

    prom = await _tool_promql(settings, target, {"query": "up"})
    logs = await _tool_logql(settings, target, {"query": '{namespace="runai-vision"}'})

    expected = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    assert seen_prom_window == expected
    assert seen_loki_window == expected
    assert prom["error"] == "Prometheus MCP response missing data.result"
    assert logs["error"] == "Loki MCP response missing a recognized log result"


@pytest.mark.asyncio
async def test_metric_and_log_queries_reject_overlong_input() -> None:
    settings = drill_settings()
    target = _target()

    prom = await _tool_promql(settings, target, {"query": "a" * 601})
    logs = await _tool_logql(settings, target, {"query": "a" * 601})

    # "invalid" routes _query_failure_feedback to the invalid_request repair
    # category, so the loop tells the model to correct the query, not retry it.
    assert prom["error"] == "invalid query: exceeds 600 characters; shorten it"
    assert logs["error"] == "invalid query: exceeds 600 characters; shorten it"


@pytest.mark.asyncio
async def test_kubernetes_log_and_describe_drilldowns_use_incident_scope(monkeypatch) -> None:
    target = replace(
        _target(),
        pod="trainer-0",
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    log_call: dict[str, object] = {}
    describe_call: dict[str, object] = {}

    async def fake_logs(settings, namespace, pod, **kwargs):
        log_call.update({"namespace": namespace, "pod": pod, **kwargs})
        return {"error": None, "lines": ["2026-07-10T01:01:00Z prior failure"]}

    async def fake_describe(settings, kind, **kwargs):
        describe_call.update({"kind": kind, **kwargs})
        return {"error": None, "events": []}

    monkeypatch.setattr(drilldown, "k8s_logs", fake_logs)
    monkeypatch.setattr(drilldown, "k8s_describe", fake_describe)

    logs = await _tool_k8s_logs(
        drill_settings(), target, {"pod": "trainer-0", "previous": True}
    )
    await _tool_k8s_describe(
        drill_settings(), target, {"kind": "pods", "name": "trainer-0"}
    )

    expected = {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}
    assert log_call["previous"] is True
    assert log_call["since_time"] == expected["start"]
    assert "--previous" in logs["query"]
    assert describe_call["time_range"] == expected


def test_drilldown_appends_tagged_artifacts_and_stops_on_done(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "query",
                "reason": "check events",
                "queries": [
                    {"tool": "k8s_read", "args": {"kind": "events", "namespace": "runai-vision"}}
                ],
            },
            {"action": "done", "reason": "enough"},
        ]
    )
    seen_args: list[dict] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        seen_args.append({"kind": kind, "namespace": namespace})
        return {"kind": kind, "status_code": 200, "error": None, "items": []}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert seen_args == [{"kind": "events", "namespace": "runai-vision"}]
    assert [a.type for a in result.artifacts] == ["drilldown_query"]
    assert result.artifacts[0].status == "ok"


@pytest.mark.asyncio
async def test_partial_drilldown_result_cannot_be_promoted_by_failure_keywords() -> None:
    async def partial_tool(settings, target, args):
        return {
            "summary": "FailedMount appeared in a current event tail",
            "polarity": "present",
            "coverage": "partial",
            "result": {"events": [{"reason": "FailedMount"}]},
        }

    result = _k8s_result()
    await drilldown._run_query(
        drill_settings(),
        result,
        {"partial_tool": {"call": partial_tool}},
        _target(),
        None,
        {"tool": "partial_tool", "args": {}},
        [],
        drilldown._drilldown_masker(drill_settings()),
    )

    artifact = result.artifacts[0]
    assert artifact.result["observation"] == {
        "kind": "drilldown_query",
        "predicate": "partial_tool",
        "polarity": "present",
        "coverage": "partial",
    }
    assert not _artifact_is_evidence(artifact)


@pytest.mark.asyncio
async def test_raw_tool_response_observation_cannot_claim_scoped_support() -> None:
    """A successful API body is not allowed to author our evidence verdict."""

    async def raw_api_tool(settings, target, args):
        return {
            "summary": "HTTP 200",
            # An adapter that merely mirrors these fields from an HTTP/LLM
            # response has not proven them either.
            "polarity": "present",
            "coverage": "scoped",
            "result": {
                # This is remote response data, not an adapter-produced result.
                "observation": {
                    "polarity": "present",
                    "coverage": "scoped",
                    "observed_entity": {"kind": "pod", "name": "other-pod"},
                    "observation_window": {
                        "start": "2026-07-01T00:00:00Z",
                        "end": "2026-07-01T00:01:00Z",
                    },
                }
            },
        }

    result = _k8s_result()
    await drilldown._run_query(
        drill_settings(),
        result,
        {"raw_api_tool": {"call": raw_api_tool}},
        _target(),
        None,
        {"tool": "raw_api_tool", "args": {}},
        [],
        drilldown._drilldown_masker(drill_settings()),
    )

    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert not _artifact_is_evidence(result.artifacts[0])


@pytest.mark.asyncio
async def test_malformed_query_hidden_but_real_error_stays_visible() -> None:
    from app.collectors.base import NO_EVIDENCE

    async def bad_query_tool(settings, target, args):
        # The agent wrote a query the backend rejected — not a finding.
        return {
            "error": "loki API returned status code 400: parse error: unexpected IDENTIFIER",
            "status_code": 400,
        }

    async def forbidden_tool(settings, target, args):
        # A real failure (auth) must stay visible.
        return {"error": "HTTP 403 forbidden", "status_code": 403}

    bad = _k8s_result()
    await drilldown._run_query(
        drill_settings(), bad, {"bad_query_tool": {"call": bad_query_tool}},
        _target(), None, {"tool": "bad_query_tool", "args": {}}, [],
        drilldown._drilldown_masker(drill_settings()),
    )
    assert bad.artifacts[0].summary.startswith(NO_EVIDENCE)

    real = _k8s_result()
    await drilldown._run_query(
        drill_settings(), real, {"forbidden_tool": {"call": forbidden_tool}},
        _target(), None, {"tool": "forbidden_tool", "args": {}}, [],
        drilldown._drilldown_masker(drill_settings()),
    )
    assert not real.artifacts[0].summary.startswith(NO_EVIDENCE)


@pytest.mark.asyncio
async def test_change_timeline_keeps_only_adapter_verified_scoped_observation(monkeypatch) -> None:
    observation = {
        "kind": "change_query",
        "predicate": "change:event",
        "polarity": "present",
        "coverage": "scoped",
        "observed_entity": {"kind": "workload", "name": "train-1"},
        "observation_window": {
            "start": "2026-07-10T00:55:00Z",
            "end": "2026-07-10T01:15:00Z",
        },
    }

    async def fake_change_query(settings, target, args):
        return {
            "query": "bounded timeline",
            "summary": "one correlated change",
            "error": None,
            "observation": observation,
            "result": {"changes": [{"name": "train-1"}]},
        }

    monkeypatch.setattr(drilldown, "change_query", fake_change_query)
    result = _k8s_result()
    await drilldown._run_query(
        drill_settings(),
        result,
        {"k8s_change_timeline": {"call": drilldown._tool_k8s_change_timeline}},
        _target(),
        None,
        {"tool": "k8s_change_timeline", "args": {"source": "event"}},
        [],
        drilldown._drilldown_masker(drill_settings()),
    )

    assert result.artifacts[0].result["observation"] == observation
    assert _artifact_is_evidence(result.artifacts[0])


def test_drilldown_prompts_redact_sensitive_evidence(monkeypatch) -> None:
    prompts: list[str] = []
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, user, **_kwargs):
        prompts.append(user)
        return next(decisions)

    async def fake_k8s_read(settings, kind, **kwargs):
        return {
            "kind": kind,
            "query": "kubectl get pods",
            "summary": "api_key=tool-key-12345",
            "result": {"data": "password=tool-password-12345"},
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="DiskPressure=True token=summary-token-12345",
    )
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    joined = "\n".join(prompts)
    for secret in ["summary-token-12345", "tool-key-12345", "tool-password-12345"]:
        assert secret not in joined
    assert "[MASKED]" in joined
    artifact_text = str(result.artifacts[0].__dict__)
    assert "tool-key-12345" not in artifact_text
    assert "tool-password-12345" not in artifact_text
    assert "[MASKED]" in artifact_text


def test_drilldown_prompt_includes_prior_artifact_result() -> None:
    result = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai collector returned workload metadata.",
        artifacts=[
            AlertAnalysisArtifact(
                agent="runai",
                source="runai",
                type="workload",
                status="ok",
                summary="metadata rows",
                result={
                    "component": "pod-group-controller",
                    "condition": "stale gang phase",
                },
            )
        ],
    )

    prompt = drilldown._user_prompt(result, _target(), None, [], [])

    assert "pod-group-controller" in prompt
    assert "stale gang phase" in prompt


def test_drilldown_receives_source_scoped_ontology_guidance(monkeypatch) -> None:
    prompts: list[str] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        prompts.append(user)
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    plan = InvestigationPlan(
        diagnostic_directive={
            "source": "typedb",
            "path": ["incident_scope", "pod_pending", "scheduling_capacity"],
            "questions": ["Why is the pod Pending?"],
            "checks": ["Compare requested and allocatable GPU capacity."],
            "interpretation": ["Capacity is relevant only after eligibility filters pass."],
            "avoid": ["Do not change requests before reading the FailedScheduling predicate."],
            "disconfirm": ["A matching node has allocatable GPU capacity."],
            "provisional_family": "k8s_scheduling_error",
            "competing_hypotheses": [{"id": "pending_volume_binding"}],
            "recommended_collectors": ["prometheus"],
        }
    )

    asyncio.run(run_drilldowns(drill_settings(), [_k8s_result()], _target(), plan))

    payload = json.loads(prompts[0])
    guidance = payload["ontology_guidance"]
    assert guidance["source"] == "typedb"
    assert guidance["collector"] == "kubernetes"
    assert guidance["primary"] is False
    assert guidance["candidate_family"] == "k8s_scheduling_error"
    assert guidance["checks"] == ["Compare requested and allocatable GPU capacity."]
    assert guidance["interpretation"] == [
        "Capacity is relevant only after eligibility filters pass."
    ]
    assert guidance["avoid"] == [
        "Do not change requests before reading the FailedScheduling predicate."
    ]
    assert guidance["disconfirm"] == ["A matching node has allocatable GPU capacity."]


def test_drilldown_runs_resolved_ontology_probe_before_llm_query(monkeypatch) -> None:
    seen_args: list[dict] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        seen_args.append({"kind": kind, "namespace": namespace, "name": name})
        return {"kind": kind, "status_code": 200, "error": None, "items": []}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "tool": "k8s_read",
                    "arguments_template": {"kind": "events", "namespace": "{{namespace}}"},
                }
            ]
        }
    )
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), plan))

    assert seen_args == [{"kind": "events", "namespace": "runai-vision", "name": ""}]
    assert [item.type for item in result.artifacts] == ["ontology_probe"]


def test_ontology_probe_keeps_untyped_remote_signal_inconclusive(monkeypatch) -> None:
    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_read(settings, kind, **_kwargs):
        return {
            "kind": kind,
            "status_code": 200,
            "error": None,
            "items": [{"reason": "FailedMount"}],
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "id": "mount-check",
                    "tool": "k8s_read",
                    "arguments_template": {"kind": "events", "namespace": "{{namespace}}"},
                    "support_signal_any": ["FailedMount"],
                    "refute_signal_any": ["mounted successfully"],
                }
            ]
        }
    )
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), plan))

    assessment = result.details["ontology_probe_assessments"][0]
    assert assessment | {"executed_at": ""} == {
        "probe_id": "mount-check",
        "tool": "k8s_read",
        "verdict": "inconclusive",
        "support_signals": [],
        "refute_signals": [],
        "template_id": "mount-check",
        "attempt_index": 1,
        "artifact_index": 0,
        "executed_at": "",
    }
    assert assessment["executed_at"].endswith("Z")
    assert "execution_id" not in assessment
    assert "hypothesis_ids" not in assessment


def test_ontology_probe_accepts_adapter_verified_scoped_observation(monkeypatch) -> None:
    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_change_query(settings, target, args):
        observation = {
            "kind": "change_query",
            "predicate": "change:event",
            "polarity": "present",
            "coverage": "scoped",
            "observed_entity": {"kind": "namespace", "name": "runai-vision"},
            "observation_window": {
                "start": "2026-07-10T00:55:00Z",
                "end": "2026-07-10T01:15:00Z",
            },
        }
        return {
            "summary": "one correlated FailedMount event",
            "error": None,
            "observation": observation,
            "result": {"events": [{"reason": "FailedMount"}]},
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "change_query", fake_change_query)
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "id": "mount-change-check",
                    "tool": "k8s_change_timeline",
                    "arguments_template": {"source": "event"},
                    "support_signal_any": ["FailedMount"],
                }
            ]
        }
    )
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), plan))

    assessment = result.details["ontology_probe_assessments"][0]
    assert assessment["verdict"] == "supports"
    assert assessment["support_signals"] == ["FailedMount"]


def test_ontology_probe_execution_uses_exact_template_hypotheses_and_run(monkeypatch) -> None:
    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_read(settings, kind, **_kwargs):
        return {
            "kind": kind,
            "status_code": 200,
            "error": None,
            "items": [{"reason": "FailedMount"}],
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    plan = InvestigationPlan(
        diagnostic_directive={
            "run_id": "ANL-42",
            "probes": [
                {
                    "template_id": "storage-mount-v1",
                    "tool": "k8s_read",
                    "arguments_template": {"kind": "events", "namespace": "{{namespace}}"},
                    "support_signal_any": ["FailedMount"],
                    "hypothesis_ids": ["ANL-42:H2", "ANL-42:H7"],
                }
            ],
        }
    )
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), plan))

    assessment = result.details["ontology_probe_assessments"][0]
    assert assessment["template_id"] == "storage-mount-v1"
    assert assessment["hypothesis_ids"] == ["ANL-42:H2", "ANL-42:H7"]
    assert assessment["attempt_index"] == 1
    assert assessment["execution_id"] == "ANL-42:storage-mount-v1:1"
    assert "evidence_ids" not in assessment


def test_ontology_probe_with_unresolved_placeholder_is_not_broadened(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_read(settings, kind, **_kwargs):
        calls.append(kind)
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "tool": "k8s_read",
                    "arguments_template": {"kind": "pods", "name": "{{pod}}"},
                }
            ]
        }
    )

    asyncio.run(run_drilldowns(drill_settings(), [_k8s_result()], _target(), plan))

    assert calls == []


def test_ontology_probe_resolves_explicit_resource_identifiers(monkeypatch) -> None:
    seen_args: list[dict] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_describe(settings, kind, *, namespace="", name="", time_range=None):
        seen_args.append({"kind": kind, "namespace": namespace, "name": name})
        return {"kind": kind, "status_code": 200, "error": None, "events": []}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_describe", fake_k8s_describe)
    target = replace(
        _target(),
        service="training-api",
        component="controller",
        storage_claim="dataset-cache",
        volume="pvc-48f2",
    )
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "tool": "k8s_describe",
                    "arguments_template": {
                        "kind": "persistentvolumeclaims",
                        "name": "{{storage_claim}}",
                        "namespace": "{{namespace}}",
                    },
                }
            ]
        }
    )

    asyncio.run(run_drilldowns(drill_settings(), [_k8s_result()], target, plan))

    assert seen_args == [
        {"kind": "persistentvolumeclaims", "namespace": "runai-vision", "name": "dataset-cache"}
    ]


def test_ontology_probe_rejects_unsafe_target_value_instead_of_widening(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_complete_json(settings, *, user, **_kwargs):
        return {"action": "done"}

    async def fake_k8s_describe(settings, kind, **_kwargs):
        calls.append(kind)
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_describe", fake_k8s_describe)
    target = replace(_target(), storage_claim="claim\nall-pvcs")
    plan = InvestigationPlan(
        diagnostic_directive={
            "probes": [
                {
                    "tool": "k8s_describe",
                    "arguments_template": {
                        "kind": "persistentvolumeclaims",
                        "name": "{{storage_claim}}",
                    },
                }
            ]
        }
    )

    asyncio.run(run_drilldowns(drill_settings(), [_k8s_result()], target, plan))

    assert calls == []


def test_drilldown_prompt_orders_stable_prefix_and_keeps_latest_history() -> None:
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="pod pending " + ("x" * 1100),
    )
    history = [
        {
            "tool": "k8s_read",
            "args": "{}",
            "outcome": (
                ("OLDEST-HISTORY " if idx == 12 else "LATEST-HISTORY " if idx == 19 else "")
                + ("x" * 1400)
            ),
        }
        for idx in range(20)
    ]

    prompt = drilldown._user_prompt(result, _target(), None, history, [])

    assert len(prompt) <= 6000
    assert prompt.find('"target"') < prompt.find('"my_summary"')
    assert "LATEST-HISTORY" in prompt
    assert "OLDEST-HISTORY" not in prompt


def test_drilldown_prompt_skips_unavailable_artifact_result() -> None:
    result = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai collector returned workload metadata.",
        artifacts=[
            AlertAnalysisArtifact(
                agent="runai",
                source="runai",
                type="workload",
                status="unavailable",
                summary="failed query mentioned pod-group-controller",
                result={"error": "pod-group-controller stale gang phase"},
            )
        ],
    )

    prompt = drilldown._user_prompt(result, _target(), None, [], [])

    assert "pod-group-controller" not in prompt
    assert "stale gang phase" not in prompt


def test_unavailable_base_summary_is_only_operational_feedback() -> None:
    result = CollectorResult(
        agent="loki",
        status="unavailable",
        summary="HTTP 400; stale response mentioned DiskPressure and evicted pods",
    )

    prompt = drilldown._user_prompt(result, _target(), None, [], [])

    assert "DiskPressure" not in prompt
    assert "evicted pods" not in prompt
    assert '"error_category": "invalid_request"' in prompt
    assert "query syntax or arguments are invalid" in prompt


def test_drilldown_runs_all_new_allowed_queries(monkeypatch) -> None:
    llm_calls = [0]
    tool_calls = [0]

    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_read",
                        "args": {"kind": "pods", "label_selector": f"app={idx}"},
                    }
                    for idx in range(9)
                ],
            },
            {"action": "done"},
        ]
    )

    async def always_query(settings, *, system, user, temperature=0.1, model=None):
        llm_calls[0] += 1
        return next(decisions)

    async def fake_k8s_read(settings, kind, **kwargs):
        tool_calls[0] += 1
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", always_query)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert llm_calls[0] == 2
    assert tool_calls[0] == 9


def test_drilldown_stops_at_configured_reasoning_round_cap(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_read",
                        "args": {"kind": "events", "label_selector": f"n={idx}"},
                    }
                ],
            }
            for idx in range(7)
        ]
        + [{"action": "done"}]
    )
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls[0] += 1
        return next(decisions)

    async def fake_k8s_read(settings, kind, **kwargs):
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    settings = replace(drill_settings(), max_investigation_steps=3)
    asyncio.run(run_drilldowns(settings, [result], _target(), None))

    assert calls[0] == 3
    assert len(result.artifacts) == 3


def test_unlimited_drilldown_stops_when_a_query_repeats(monkeypatch) -> None:
    decisions = iter(
        [
            {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "events"}}]},
            {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "events"}}]},
        ]
    )
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls[0] += 1
        return next(decisions)

    async def fake_k8s_read(settings, kind, **kwargs):
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert calls[0] == 2
    assert len(result.artifacts) == 1
    assert any("no new allowed read-only query" in warning for warning in result.warnings)


def test_drilldown_runs_independent_query_batch_concurrently(monkeypatch) -> None:
    started: list[str] = []
    both_started = asyncio.Event()

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return {
            "action": "query",
            "queries": [
                {"tool": "k8s_read", "args": {"kind": "pods"}},
                {"tool": "k8s_read", "args": {"kind": "events"}},
            ],
        }

    async def fake_k8s_read(settings, kind, **kwargs):
        started.append(kind)
        if len(started) == 2:
            both_started.set()
        await asyncio.wait_for(both_started.wait(), timeout=0.1)
        return {"kind": kind, "status_code": 200, "error": None}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert set(started) == {"pods", "events"}
    assert len(result.artifacts) == 2
    assert all(artifact.status == "ok" for artifact in result.artifacts)


def test_drilldown_does_not_stop_for_high_usage(monkeypatch) -> None:
    usage = begin_usage_tracking()
    usage["total_tokens"] = 10

    calls = [0]

    async def should_call_llm(*args, **kwargs):
        calls[0] += 1
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", should_call_llm)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert result.artifacts == []
    assert calls == [1]


def test_tool_scoping_is_structural(monkeypatch) -> None:
    # No loki_url / runai_mcp_url in settings -> those agents get NO tools and no
    # loop; kubernetes still drills. An agent can never reach another domain's
    # tools because its registry simply doesn't contain them.
    drilled_agents: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        drilled_agents.append(system.split(" ")[3])  # "You are the {agent} evidence..."
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    results = [
        _k8s_result(),
        CollectorResult(agent="loki", status="ok", summary="logs"),
        CollectorResult(agent="runai", status="ok", summary="workloads"),
        CollectorResult(agent="postgres", status="ok", summary="db"),
    ]
    asyncio.run(run_drilldowns(drill_settings(), results, _target(), None))
    assert drilled_agents == ["kubernetes"]


def test_system_and_change_agents_adapt_with_their_own_safe_tools(monkeypatch) -> None:
    rounds: dict[str, int] = {}

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        agent = system.split(" ")[3]
        rounds[agent] = rounds.get(agent, 0) + 1
        if rounds[agent] > 1:
            return {"action": "done"}
        if agent == "system":
            return {
                "action": "query",
                "queries": [
                    {"tool": "system_log_query", "args": {"source": "journal"}}
                ],
            }
        return {
            "action": "query",
            "queries": [{"tool": "change_query", "args": {"source": "event"}}],
        }

    async def fake_system_log_query(settings, target, args):
        observation = {
            "kind": "system_log_query",
            "predicate": "node_system:gpu_driver",
            "polarity": "present",
            "coverage": "scoped",
            "observed_entity": {"kind": "node", "name": "gpu-1"},
        }
        return {
            "query": "system logs source=journal node=gpu-1",
            "summary": "one GPU driver signal",
            "error": None,
            "observation": observation,
            "result": observation,
        }

    async def fake_change_query(settings, target, args):
        observation = {
            "kind": "change_query",
            "predicate": "change:event",
            "polarity": "present",
            "coverage": "scoped",
            "observed_entity": {"kind": "namespace", "name": "runai-vision"},
        }
        return {
            "query": "bounded change timeline source=event",
            "summary": "one target-scoped event change",
            "error": None,
            "observation": observation,
            "result": observation,
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "system_log_query", fake_system_log_query)
    monkeypatch.setattr(drilldown, "change_query", fake_change_query)
    results = [
        CollectorResult(agent="system", status="unavailable", summary="base host read failed"),
        CollectorResult(agent="change", status="ok", summary="base change sweep was empty"),
    ]
    target = replace(_target(), node="gpu-1")

    asyncio.run(run_drilldowns(drill_settings(), results, target, None))

    assert rounds == {"system": 2, "change": 2}
    assert [artifact.status for artifact in results[0].artifacts] == ["ok"]
    assert [artifact.status for artifact in results[1].artifacts] == ["ok"]
    assert results[0].artifacts[0].result["observation"]["coverage"] == "scoped"
    assert results[1].artifacts[0].result["observation"]["coverage"] == "scoped"


def test_cross_domain_drilldown_query_is_visible_in_warnings(monkeypatch) -> None:
    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return {
            "action": "query",
            "queries": [{"tool": "runai_get", "args": {"path": "/api/v1/workloads"}}],
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert result.artifacts == []
    assert any("no new allowed read-only query" in warning for warning in result.warnings)


def test_unavailable_collector_gets_a_bounded_recovery_round(monkeypatch) -> None:
    prompts: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        prompts.append(user)
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = CollectorResult(
        agent="kubernetes",
        status="unavailable",
        summary="base Kubernetes read failed",
        missing_data=["kubernetes.query"],
        warnings=["HTTP 403: forbidden by RBAC"],
    )
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert len(prompts) == 1
    assert '"status": "unavailable"' in prompts[0]
    assert '"error_category": "authorization"' in prompts[0]
    assert "not incident evidence" in prompts[0]


def test_rejected_query_gets_one_correction_round(monkeypatch) -> None:
    prompts: list[str] = []
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "kubectl_logs",
                        "args": {"pod": "train-1-0", "namespace": "runai-vision"},
                    }
                ],
            },
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_logs",
                        "args": {"pod": "train-1-0", "namespace": "runai-vision"},
                    }
                ],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        prompts.append(user)
        return next(decisions)

    async def fake_logs(settings, namespace, pod, **kwargs):
        return {"error": None, "lines": ["healthy startup"]}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_logs", fake_logs)
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert len(prompts) == 3
    assert '"status": "rejected"' in prompts[1]
    assert "kubectl_logs" in prompts[1]
    assert "k8s_logs" in prompts[1]
    assert len(result.artifacts) == 1
    assert result.artifacts[0].status == "ok"


def test_failed_log_query_exposes_safe_repair_detail_then_accepts_new_query(monkeypatch) -> None:
    prompts: list[str] = []
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_logs",
                        "args": {
                            "pod": "train-1-0",
                            "namespace": "runai-vision",
                            "container": "wrong",
                        },
                    }
                ],
            },
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_describe",
                        "args": {
                            "kind": "pods",
                            "name": "train-1-0",
                            "namespace": "runai-vision",
                        },
                    }
                ],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        prompts.append(user)
        return next(decisions)

    async def fake_logs(settings, namespace, pod, **kwargs):
        return {"error": "HTTP 400: container wrong is not valid for pod", "lines": []}

    async def fake_describe(settings, kind, **kwargs):
        return {"error": None, "events": [], "object": {"kind": "Pod"}}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_logs", fake_logs)
    monkeypatch.setattr(drilldown, "k8s_describe", fake_describe)
    result = _k8s_result()

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert len(prompts) == 3
    second_prompt = json.loads(prompts[1])
    failure = json.loads(second_prompt["drilldown_so_far"][0]["outcome"])
    assert failure["error_category"] == "container_selection"
    assert failure["diagnostic"] == "HTTP 400: container selection is missing or invalid"
    assert "container wrong" not in prompts[1]
    assert [artifact.status for artifact in result.artifacts] == ["unavailable", "ok"]


def test_tool_failure_becomes_observation_not_crash(monkeypatch) -> None:
    decisions = iter(
        [
            {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}]},
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    async def broken_k8s_read(settings, kind, **kwargs):
        raise RuntimeError("apiserver exploded")

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", broken_k8s_read)
    result = _k8s_result()
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert len(result.artifacts) == 1
    assert result.artifacts[0].status == "unavailable"
    assert "apiserver exploded" in (result.artifacts[0].summary or "")


def test_failed_tool_result_is_not_replayed_as_next_prompt_evidence(monkeypatch) -> None:
    prompts: list[str] = []
    decisions = iter(
        [
            {"action": "query", "queries": [{"tool": "k8s_read", "args": {"kind": "pods"}}]},
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        prompts.append(user)
        return next(decisions)

    async def exploding_tool(call, settings, target, args):
        return {
            "query": "kubectl get pods",
            "summary": "query failed; stale output mentioned DiskPressure",
            "error": "query failed; stale output mentioned DiskPressure",
            "result": {"message": "DiskPressure=True; pods evicted"},
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "_call_tool_safely", exploding_tool)
    result = CollectorResult(agent="kubernetes", status="ok", summary="base evidence")

    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))

    assert len(prompts) == 2
    assert "DiskPressure" not in prompts[1]
    assert "pods evicted" not in prompts[1]
    assert "query failed" in prompts[1]
    assert result.artifacts[0].status == "unavailable"
    assert not result.artifacts[0].highlights


def test_official_runai_tools_are_target_bound(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        isError = False
        content = []

    async def fake_mcp_call(settings, tool, arguments):
        captured["tool"] = tool
        captured["arguments"] = arguments
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")
    workload_id = "550e8400-e29b-41d4-a716-446655440000"
    target = replace(_target(), project="vision", runai_workload_id=workload_id)
    outcome = asyncio.run(
        _tool_runai_workload_status(
            settings,
            target,
            {"workloadId": "attacker-selected", "method": "DELETE"},
        )
    )
    assert captured["tool"] == "get_workload_status"
    assert captured["arguments"] == {"workloadId": workload_id}
    assert outcome["error"] is None


def test_official_runai_tools_require_alert_identity(monkeypatch) -> None:
    async def fake_mcp_call(settings, tool, arguments):
        raise AssertionError("must not be reached")

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")
    assert "no immutable" in asyncio.run(
        _tool_runai_workload_status(settings, _target(), {})
    )["error"]
    assert "not a UUID" in asyncio.run(
        _tool_runai_workload_status(
            settings, replace(_target(), runai_workload_id="workload-42"), {}
        )
    )["error"]
    assert "no Run:ai project" in asyncio.run(
        _tool_runai_project_resources(settings, _target(), {})
    )["error"]


def test_official_runai_summary_uses_alert_project(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        isError = False
        content = []

    async def fake_mcp_call(settings, tool, arguments):
        captured["tool"] = tool
        captured["arguments"] = arguments
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    outcome = asyncio.run(
        _tool_runai_workload_summary(
            drill_settings(runai_mcp_url="http://localhost:8080/mcp"),
            replace(_target(), project="vision"),
            {"projectName": "attacker-selected"},
        )
    )
    assert captured == {
        "tool": "get_workloads_summary",
        "arguments": {"orgType": "project", "orgName": "vision"},
    }
    assert outcome["error"] is None


def test_official_runai_registry_exposes_target_bound_read_tools() -> None:
    tools = drilldown._domain_tools(
        drill_settings(runai_mcp_url="http://localhost:8080/mcp")
    )["runai"]
    assert {
        "runai_workload_summary",
        "runai_workload_status",
        "runai_workload_history",
        "runai_workload_pods",
        "runai_workload_spec",
        "runai_workload_metrics",
        "runai_project_resources",
        "runai_project_metrics",
        "runai_workload_effective_policy",
        "runai_department_resources",
        "runai_cluster_physical_inventory",
        "runai_cluster_infrastructure_health",
        "runai_cluster_metrics",
        "runai_node_pools",
        "runai_node_pods",
    } <= set(tools)


def test_runai_cluster_physical_inventory_returns_success_and_error_artifacts(monkeypatch) -> None:
    class _Result:
        isError = False
        content = []

    calls = iter([_Result(), RuntimeError("physical inventory unavailable")])

    async def fake_mcp_call(settings, tool, arguments):
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        assert tool == "get_cluster_physical_inventory"
        assert arguments == {"clusterId": "cluster-id"}
        return outcome

    async def fake_cluster_id(settings, target):
        return "cluster-id"

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    monkeypatch.setattr(drilldown, "_resolve_runai_cluster_id", fake_cluster_id)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    success = asyncio.run(_tool_runai_cluster_physical_inventory(settings, _target(), {}))
    assert success["error"] is None
    failed = asyncio.run(_tool_runai_cluster_physical_inventory(settings, _target(), {}))
    assert "physical inventory unavailable" in failed["error"]

    async def missing_cluster_id(settings, target):
        raise RuntimeError("could not resolve Run:ai cluster ID")

    monkeypatch.setattr(drilldown, "_resolve_runai_cluster_id", missing_cluster_id)
    unresolved = asyncio.run(_tool_runai_cluster_physical_inventory(settings, _target(), {}))
    assert "could not resolve Run:ai cluster ID" in unresolved["error"]


def test_runai_cluster_infrastructure_health_returns_success_and_error_artifacts(
    monkeypatch,
) -> None:
    class _Result:
        isError = False
        content = []

    calls = iter([_Result(), RuntimeError("infrastructure health unavailable")])

    async def fake_mcp_call(settings, tool, arguments):
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        assert tool == "get_cluster_infrastructure_health"
        assert arguments == {"clusterId": "cluster-id"}
        return outcome

    async def fake_cluster_id(settings, target):
        return "cluster-id"

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    monkeypatch.setattr(drilldown, "_resolve_runai_cluster_id", fake_cluster_id)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    success = asyncio.run(
        _tool_runai_cluster_infrastructure_health(settings, _target(), {})
    )
    assert success["error"] is None
    failed = asyncio.run(_tool_runai_cluster_infrastructure_health(settings, _target(), {}))
    assert "infrastructure health unavailable" in failed["error"]


def test_runai_cluster_metrics_uses_incident_window_and_returns_error_artifact(monkeypatch) -> None:
    class _Result:
        isError = False
        content = []

    calls = iter([_Result(), RuntimeError("cluster metrics unavailable")])
    captured: list[dict] = []

    async def fake_mcp_call(settings, tool, arguments):
        captured.append({"tool": tool, "arguments": arguments})
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def fake_cluster_id(settings, target):
        return "cluster-id"

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    monkeypatch.setattr(drilldown, "_resolve_runai_cluster_id", fake_cluster_id)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")
    target = replace(
        _target(), fired_at="2025-01-01T00:00:00Z", resolved_at="2025-01-01T00:10:00Z"
    )

    assert asyncio.run(_tool_runai_cluster_metrics(settings, target, {}))["error"] is None
    failed = asyncio.run(_tool_runai_cluster_metrics(settings, target, {}))
    assert captured == [
        {
            "tool": "get_cluster_metrics",
            "arguments": {
                "clusterId": "cluster-id",
                "start": "2024-12-31T23:55:00Z",
                "end": "2025-01-01T00:15:00Z",
            },
        },
        {
            "tool": "get_cluster_metrics",
            "arguments": {
                "clusterId": "cluster-id",
                "start": "2024-12-31T23:55:00Z",
                "end": "2025-01-01T00:15:00Z",
            },
        },
    ]
    assert "cluster metrics unavailable" in failed["error"]


def test_runai_department_resources_scopes_when_labeled_and_returns_error_artifact(
    monkeypatch,
) -> None:
    class _Result:
        isError = False
        content = []

    calls = iter([_Result(), _Result(), RuntimeError("department resources unavailable")])
    captured: list[dict] = []

    async def fake_mcp_call(settings, tool, arguments):
        captured.append({"tool": tool, "arguments": arguments})
        outcome = next(calls)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    assert asyncio.run(
        _tool_runai_department_resources(settings, replace(_target(), department="research"), {})
    )["error"] is None
    assert asyncio.run(_tool_runai_department_resources(settings, _target(), {}))["error"] is None
    failed = asyncio.run(_tool_runai_department_resources(settings, _target(), {}))
    assert captured == [
        {"tool": "list_department_resources", "arguments": {"departmentName": "research"}},
        {"tool": "list_department_resources", "arguments": {}},
        {"tool": "list_department_resources", "arguments": {}},
    ]
    assert "department resources unavailable" in failed["error"]


def test_runai_workload_effective_policy_requires_project_kind_and_returns_success(
    monkeypatch,
) -> None:
    class _Result:
        isError = False
        content = []

    captured: dict = {}

    async def fake_mcp_call(settings, tool, arguments):
        captured["tool"] = tool
        captured["arguments"] = arguments
        return _Result()

    async def fake_project_id(settings, target):
        return "project-id"

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    monkeypatch.setattr(drilldown, "_resolve_runai_project_id", fake_project_id)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    assert asyncio.run(
        _tool_runai_workload_effective_policy(
            settings, replace(_target(), project="vision", workload_type="training"), {}
        )
    )["error"] is None
    failed = asyncio.run(_tool_runai_workload_effective_policy(settings, _target(), {}))
    assert captured == {
        "tool": "get_workload_effective_policy",
        "arguments": {"projectId": "project-id", "kind": "Training"},
    }
    assert "no Run:ai project" in failed["error"]

    invalid_kind = asyncio.run(
        _tool_runai_workload_effective_policy(
            settings, replace(_target(), project="vision", workload_type="batch"), {}
        )
    )
    assert "unusable" in invalid_kind["error"]

    async def missing_project_id(settings, target):
        raise RuntimeError("could not resolve Run:ai project ID")

    monkeypatch.setattr(drilldown, "_resolve_runai_project_id", missing_project_id)
    unresolved = asyncio.run(
        _tool_runai_workload_effective_policy(
            settings, replace(_target(), project="vision", workload_type="Inference"), {}
        )
    )
    assert "could not resolve Run:ai project ID" in unresolved["error"]


def test_runai_cluster_id_discovery_matches_name_uses_single_cluster_and_errors(
    monkeypatch,
) -> None:
    drilldown._RUNAI_CLUSTER_ID_CACHE.clear()
    responses = iter(
        [
            {"clusters": [{"name": "uclick-runai", "uuid": "named-cluster-id"}]},
            [{"name": "only-cluster", "id": "single-cluster-id"}],
            {"clusters": [{"name": "one", "uuid": "one-id"}, {"name": "two", "uuid": "two-id"}]},
        ]
    )
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(ok=True, data=next(responses))

    monkeypatch.setattr(drilldown, "get_json", fake_get_json)
    settings = drill_settings(
        runai_base_url="https://runai.example", runai_bearer_token="test-token"
    )

    named = replace(_target(), cluster="uclick-runai")
    assert asyncio.run(drilldown._resolve_runai_cluster_id(settings, named)) == "named-cluster-id"
    assert asyncio.run(drilldown._resolve_runai_cluster_id(settings, named)) == "named-cluster-id"
    assert asyncio.run(
        drilldown._resolve_runai_cluster_id(settings, replace(_target(), cluster="alert-name"))
    ) == "single-cluster-id"
    with pytest.raises(RuntimeError, match="could not resolve Run:ai cluster ID"):
        asyncio.run(
            drilldown._resolve_runai_cluster_id(settings, replace(_target(), cluster="missing"))
        )
    assert [call["path"] for call in calls] == [
        "/api/v1/clusters",
        "/api/v1/clusters",
        "/api/v1/clusters",
    ]


def test_runai_project_id_discovery_caches_name_matches_and_errors(monkeypatch) -> None:
    drilldown._RUNAI_PROJECT_ID_CACHE.clear()
    responses = iter(
        [
            {"projects": [{"name": "vision", "id": "vision-id"}]},
            [{"name": "other", "id": "other-id"}],
        ]
    )
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(ok=True, data=next(responses))

    monkeypatch.setattr(drilldown, "get_json", fake_get_json)
    settings = drill_settings(
        runai_base_url="https://runai.example", runai_bearer_token="test-token"
    )
    target = replace(_target(), project="vision")

    assert asyncio.run(drilldown._resolve_runai_project_id(settings, target)) == "vision-id"
    assert asyncio.run(drilldown._resolve_runai_project_id(settings, target)) == "vision-id"
    with pytest.raises(RuntimeError, match="could not resolve Run:ai project ID"):
        asyncio.run(
            drilldown._resolve_runai_project_id(settings, replace(_target(), project="missing"))
        )
    assert [call["path"] for call in calls] == [
        "/api/v1/org-unit/projects",
        "/api/v1/org-unit/projects",
    ]


def test_change_tool_does_not_advertise_secret_backed_helm_scan_by_default() -> None:
    description = drilldown._domain_tools(drill_settings())["kubernetes"][
        "k8s_change_timeline"
    ]["description"]
    assert "|helm" not in description

    enabled = replace(drill_settings(), enable_helm_change_detection=True)
    enabled_description = drilldown._domain_tools(enabled)["kubernetes"][
        "k8s_change_timeline"
    ]["description"]
    assert "|helm" in enabled_description


def test_official_runai_tool_masks_text_result_and_error(monkeypatch) -> None:
    class _Result:
        def __init__(self, text: str, *, is_error: bool = False) -> None:
            self.isError = is_error
            self.content = [type("Block", (), {"text": text})()]

    calls = iter(
        [
            _Result('{"api_key":"summary-secret-12345"}'),
            _Result("tool failed password=summary-error-secret-12345\n## injected", is_error=True),
        ]
    )

    async def fake_mcp_call(settings, tool, arguments):
        return next(calls)

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    ok = asyncio.run(_tool_runai_workload_summary(settings, _target(), {}))
    failed = asyncio.run(_tool_runai_workload_summary(settings, _target(), {}))

    rendered = str([ok, failed])
    assert "summary-secret-12345" not in rendered
    assert "summary-error-secret-12345" not in rendered
    assert "\n## injected" not in rendered
    assert "[MASKED]" in rendered


def test_official_runai_tool_masks_text_json_result(monkeypatch) -> None:
    class _Result:
        isError = False
        content = [
            type(
                "Block",
                (),
                {
                    "text": '{"access_token":"get-secret-12345",'
                    '"nested":{"password":"nested-get-secret-12345"}}'
                },
            )()
        ]

    async def fake_mcp_call(settings, tool, arguments):
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8080/mcp")

    outcome = asyncio.run(_tool_runai_workload_summary(settings, _target(), {}))

    assert outcome["result"] == {
        "access_token": "[MASKED]",
        "nested": {"password": "[MASKED]"},
    }


@pytest.mark.asyncio
async def test_never_raises_even_if_llm_layer_explodes(monkeypatch) -> None:
    async def broken_complete_json(settings, *, system, user, temperature=0.1, model=None):
        raise RuntimeError("llm gateway down password=drilldown-llm-secret-12345")

    monkeypatch.setattr(drilldown, "complete_json", broken_complete_json)
    result = _k8s_result()
    await run_drilldowns(drill_settings(), [result], _target(), None)
    assert result.artifacts == []
    assert any("llm gateway down" in warning for warning in result.warnings)
    assert "drilldown-llm-secret-12345" not in " ".join(result.warnings)


def test_salient_markers_scan_only_string_leaves() -> None:
    from app.collectors.base import salient_markers

    data = {
        "error": None,  # a key named error must NOT count as a signal
        "status": {"phase": "Running", "reason": "CrashLoopBackOff"},
        "events": ["Back-off restarting failed container", "NVRM: Xid 79 detected"],
        "count": 3,
    }
    markers = salient_markers(data)
    assert "CrashLoopBackOff" in markers
    assert any("Xid" in m for m in markers)
    assert salient_markers({"status": {"phase": "Running"}, "error": None}) == []


def test_salient_markers_ignore_negated_signals() -> None:
    from app.collectors.base import salient_markers

    assert salient_markers({"status": "no ImagePullBackOff; registry is fine"}) == []
    assert salient_markers({"status": "CrashLoopBackOff not observed; pod running"}) == []
    assert salient_markers({"status": "ImagePullBackOff observed on trainer"}) == [
        "ImagePullBackOff"
    ]


def test_salient_markers_require_active_structured_conditions() -> None:
    from app.collectors.base import condition_observations, salient_markers

    healthy = {
        "conditions": [
            {"type": "DiskPressure", "status": "False", "reason": "KubeletHasNoDiskPressure"},
            {"type": "MemoryPressure", "status": "False"},
            {"type": "PIDPressure", "status": "False"},
            {"type": "NetworkUnavailable", "status": "False"},
        ]
    }
    assert salient_markers(healthy) == []
    assert {item["condition"] for item in condition_observations(healthy)} == {
        "DiskPressure",
        "MemoryPressure",
        "PIDPressure",
        "NetworkUnavailable",
    }
    assert all(item["active"] is False for item in condition_observations(healthy))

    failing = {"type": "MemoryPressure", "status": "True"}
    assert salient_markers(failing) == ["MemoryPressure"]
    assert condition_observations(failing)[0]["active"] is True


def test_condition_observations_do_not_turn_unknown_into_refutation() -> None:
    from app.collectors.base import condition_observations

    kubernetes_unknown = {"type": "MemoryPressure", "status": "Unknown"}
    prometheus_unknown = {
        "metric": {"condition": "MemoryPressure", "status": "unknown"},
        "value": [1720000000, "1"],
    }
    false_zero = {
        "metric": {"condition": "MemoryPressure", "status": "false"},
        "value": [1720000000, "0"],
    }

    assert condition_observations(kubernetes_unknown) == []
    assert condition_observations(prometheus_unknown) == []
    assert condition_observations(false_zero) == []


def test_node_conditions_ignore_compact_response_truncation_sentinel() -> None:
    from app.collectors.kubernetes import _node_conditions

    node = {
        "conditions": [
            {"type": "NetworkUnavailable", "status": "False"},
            {"type": "MemoryPressure", "status": "False"},
            {"type": "DiskPressure", "status": "False"},
            {"type": "PIDPressure", "status": "False"},
            {"truncated": 1},
        ]
    }

    assert _node_conditions([{"name": "node", "data": node}]) == [
        {"node_conditions_healthy": True, "checked": 4}
    ]


def test_kubernetes_markers_ignore_pod_spec_keyword_values() -> None:
    from app.collectors.base import kubernetes_salient_markers, salient_markers

    pod = {
        "spec": {"preemptionPolicy": "PreemptLowerPriority"},
        "metadata": {"annotations": {"example": "OOMKilled documentation"}},
        "status": {
            "containerStatuses": [
                {"state": {"running": {}}, "lastState": {"terminated": {"reason": "OOMKilled"}}}
            ]
        },
    }

    assert kubernetes_salient_markers(pod) == ["OOMKilled"]
    assert salient_markers("PreemptLowerPriority") == []


def test_kubernetes_markers_apply_condition_polarity_before_reason_keywords() -> None:
    from app.collectors.base import condition_observations, kubernetes_salient_markers

    refuted = {
        "status": {
            "conditions": [
                # Deliberately inconsistent reason text proves that status is
                # authoritative and keyword presence alone cannot pass.
                {"type": "PodScheduled", "status": "True", "reason": "Unschedulable"},
                {
                    "type": "DisruptionTarget",
                    "status": "False",
                    "reason": "PreemptionByScheduler",
                },
                {"type": "MemoryPressure", "status": "False"},
            ]
        }
    }
    active = {
        "status": {
            "conditions": [
                {"type": "PodScheduled", "status": "False", "reason": "Unschedulable"},
                {
                    "type": "DisruptionTarget",
                    "status": "True",
                    "reason": "PreemptionByScheduler",
                },
                {"type": "MemoryPressure", "status": "True"},
            ]
        }
    }

    assert kubernetes_salient_markers(refuted) == []
    assert kubernetes_salient_markers(active) == [
        "Unschedulable",
        "PreemptionByScheduler",
        "MemoryPressure",
    ]
    assert [
        (item["condition"], item["active"])
        for item in condition_observations(active)
    ] == [
        ("PodScheduled", True),
        ("DisruptionTarget", True),
        ("MemoryPressure", True),
    ]
    assert [
        (item["condition"], item["active"])
        for item in condition_observations(refuted)
    ] == [
        ("PodScheduled", False),
        ("DisruptionTarget", False),
        ("MemoryPressure", False),
    ]


def test_kubernetes_markers_require_warning_event_and_observed_object() -> None:
    from app.collectors.base import kubernetes_salient_markers

    events = {
        "items": [
            {
                "type": "Normal",
                "reason": "Preempting",
                "message": "pod was Preempted",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {
                "type": "Normal",
                "reason": "Preempted",
                "message": "pod was selected as a scheduler victim",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
            {"type": "Warning", "reason": "Unschedulable"},
            {
                "type": "Warning",
                "reason": "FailedScheduling",
                "message": "pod is Unschedulable",
                "involvedObject": {"kind": "Pod", "name": "trainer-0"},
            },
        ]
    }

    assert kubernetes_salient_markers(events) == [
        "Preempted",
        "FailedScheduling",
        "Unschedulable",
    ]


def test_salient_markers_require_positive_prometheus_condition_sample() -> None:
    from app.collectors.base import condition_observations, salient_markers

    inactive = {
        "metric": {"condition": "DiskPressure", "status": "true", "node": "gpu-1"},
        "value": [1720000000, "0"],
    }
    active = {
        "metric": {"condition": "DiskPressure", "status": "true", "node": "gpu-1"},
        "value": [1720000000, "1"],
    }
    false_series = {
        "metric": {"condition": "DiskPressure", "status": "false", "node": "gpu-1"},
        "value": [1720000000, "1"],
    }
    assert salient_markers(inactive) == []
    assert salient_markers(false_series) == []
    assert salient_markers(active) == ["DiskPressure"]
    assert condition_observations(inactive)[0]["active"] is False
    assert condition_observations(active)[0]["active"] is True


def test_drilldown_caps_reasoning_rounds_but_batches_queries(monkeypatch) -> None:
    decision_calls = 0
    query_calls: list[str] = []

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        nonlocal decision_calls
        decision_calls += 1
        return {
            "action": "query",
            "queries": [
                {
                    "tool": "k8s_read",
                    "args": {
                        "kind": "events",
                        "namespace": "runai-vision",
                        "label_selector": f"round={decision_calls},query={index}",
                    },
                }
                for index in range(5)
            ],
        }

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        query_calls.append(label_selector)
        return {"kind": kind, "status_code": 200, "error": None, "items": []}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    settings = replace(drill_settings(), max_investigation_steps=3)
    asyncio.run(run_drilldowns(settings, [_k8s_result()], _target(), None))

    assert decision_calls == 3
    assert len(query_calls) == 15


def test_named_pod_read_is_promoted_to_describe_and_reports_highlights(monkeypatch) -> None:
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [
                    {
                        "tool": "k8s_read",
                        "args": {"kind": "pods", "namespace": "runai", "name": "t-0"},
                    }
                ],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    async def fake_k8s_describe(
        settings, kind, *, namespace="", name="", time_range=None
    ):
        assert (kind, namespace, name) == ("pods", "runai", "t-0")
        return {
            "kind": "pods",
            "namespace": namespace,
            "name": name,
            "status_code": 200,
            "error": None,
            "object": {
                "status": {
                    "containerStatuses": [
                        {"state": {"terminated": {"reason": "OOMKilled"}}}
                    ]
                }
            },
            "events": [],
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_describe", fake_k8s_describe)
    result = _k8s_result()
    settings = replace(drill_settings(), language="ko")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    art = result.artifacts[0]
    assert art.query == (
        "kubectl get pod t-0 -n runai -o yaml; "
        "kubectl describe pod t-0 -n runai"
    )
    assert art.title == "Pod YAML + 상세 점검"
    assert art.highlights == ["OOMKilled"]
    assert "주요 신호" in (art.summary or "") and "OOMKilled" in (art.summary or "")


def test_sql_validate_select_is_fail_closed() -> None:
    from app.services.drilldown import _validate_select

    ok, sql = _validate_select("SELECT id, status FROM workloads WHERE name = 'x';")
    assert ok is None and sql.endswith("name = 'x'")
    assert _validate_select("")[0]
    assert _validate_select("DELETE FROM workloads")[0]
    assert _validate_select("SELECT * INTO scratch_copy FROM workloads")[0]
    assert _validate_select("SELECT pg_sleep(60)")[0]
    assert _validate_select("SELECT pg_terminate_backend(pid) FROM pg_stat_activity")[0]
    assert _validate_select("SELECT lo_export(123, '/tmp/x')")[0]
    assert _validate_select("SELECT nextval('workloads_id_seq')")[0]
    assert _validate_select("SELECT pg_advisory_lock(42)")[0]
    assert _validate_select("SELECT pg_notify('chan', 'msg')")[0]
    assert _validate_select("SELECT pg_read_file('/etc/passwd')")[0]
    assert _validate_select("SELECT * FROM dblink('host=other', 'SELECT 1') AS t(x int)")[0]
    assert _validate_select("SELECT * FROM pg_ls_waldir()")[0]
    assert _validate_select("SELECT 1; DROP TABLE workloads")[0]
    assert _validate_select("WITH x AS (SELECT 1) INSERT INTO y SELECT * FROM x")[0]
    assert _validate_select("EXPLAIN SELECT 1")[0]  # not SELECT/WITH-leading
    # column names containing forbidden words as substrings are fine
    assert _validate_select("SELECT created_at, updated_at FROM audit")[0] is None


def test_sql_validate_select_ignores_literals_but_rejects_comments() -> None:
    from app.services.drilldown import _validate_select

    ok, sql = _validate_select(
        "SELECT id FROM audit WHERE message = 'delete;   still text' "
        "AND raw = $$DROP TABLE workloads;$$;"
    )
    assert ok is None
    assert "'delete;   still text'" in sql
    assert "$$DROP TABLE workloads;$$" in sql
    assert _validate_select("SELECT id FROM workloads -- hide the rest")[0]
    assert _validate_select("SELECT id FROM workloads /* hide the rest */")[0]


def test_sql_validate_select_rejects_quoted_dangerous_functions() -> None:
    from app.services.drilldown import _validate_select

    assert _validate_select('SELECT "pg_sleep"(60)')[0]
    assert _validate_select("SELECT pg_catalog.\"pg_read_file\"('/etc/passwd')")[0]


def test_sql_tool_targets_runai_db_and_appends_limit(monkeypatch) -> None:
    captured: dict = {}

    async def fake_run_select(dsn, sql, timeout):
        captured["dsn"] = dsn
        captured["sql"] = sql
        return [{"id": 1}]

    monkeypatch.setattr(drilldown, "_run_select", fake_run_select)
    decisions = iter(
        [
            {
                "action": "query",
                "queries": [{"tool": "sql_select", "args": {"query": "SELECT id FROM workloads"}}],
            },
            {"action": "done"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return next(decisions)

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    settings = drill_settings(runai_db_dsn="postgres://ro@runai-db/runai")
    result = CollectorResult(agent="postgres", status="ok", summary="db health ok")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    assert captured["dsn"] == "postgres://ro@runai-db/runai"
    assert captured["sql"] == "SELECT id FROM workloads LIMIT 50"
    assert result.artifacts[0].query == "SELECT id FROM workloads LIMIT 50"


def test_sql_tool_only_trusts_trailing_limit(monkeypatch) -> None:
    captured: dict = {}

    async def fake_run_select(dsn, sql, timeout):
        captured["sql"] = sql
        return [{"id": 1}]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        return {
            "action": "query",
            "queries": [
                {
                    "tool": "sql_select",
                    "args": {"query": "SELECT id FROM workloads WHERE note = 'limit 1'"},
                }
            ],
        }

    monkeypatch.setattr(drilldown, "_run_select", fake_run_select)
    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    settings = drill_settings(runai_db_dsn="postgres://ro@runai-db/runai")
    result = CollectorResult(agent="postgres", status="ok", summary="db health ok")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    assert captured["sql"] == "SELECT id FROM workloads WHERE note = 'limit 1' LIMIT 50"


def test_postgres_agent_has_no_sql_tool_without_any_dsn(monkeypatch) -> None:
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls[0] += 1
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = CollectorResult(agent="postgres", status="ok", summary="db")
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert calls[0] == 0  # make_settings has no postgres_dsn / runai_db_dsn


def test_signals_are_bolded_in_evidence_text() -> None:
    # Emphasis lives in the text (markdown **), so it survives report/export/JSON
    # instead of relying on a frontend-only red highlight (option A).
    from app.collectors.base import signals_line

    assert signals_line(["NetworkUnavailable", "DiskPressure"], "ko") == (
        "주요 신호: **NetworkUnavailable**, **DiskPressure**"
    )
    assert signals_line(["OOMKilled"], "en") == "signals: **OOMKilled**"
    assert signals_line([], "ko") == ""


@pytest.mark.asyncio
async def test_drilldowns_cancel_at_shared_evidence_deadline(monkeypatch) -> None:
    started = asyncio.Event()

    async def never_finishes(settings, **kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(drilldown, "complete_json", never_finishes)
    result = _k8s_result()

    await run_drilldowns(
        drill_settings(),
        [result],
        _target(),
        None,
        # Leave enough time for a busy CI event loop to schedule _drill_one
        # before asserting that the shared deadline cancels it.
        deadline_monotonic=time.monotonic() + 0.2,
    )

    assert started.is_set()
    assert not any("evidence budget" in warning for warning in result.warnings)
