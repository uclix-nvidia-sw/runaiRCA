from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget, CollectorResult
from app.llm import begin_usage_tracking
from app.plan import InvestigationPlan
from app.schemas import AlertAnalysisArtifact
from app.services import drilldown
from app.services.drilldown import _tool_runai_get, run_drilldowns
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


def test_ontology_probe_records_structured_support_verdict(monkeypatch) -> None:
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
        "verdict": "supports",
        "support_signals": ["FailedMount"],
        "refute_signals": [],
        "template_id": "mount-check",
        "attempt_index": 1,
        "artifact_index": 0,
        "executed_at": "",
    }
    assert assessment["executed_at"].endswith("Z")
    assert "execution_id" not in assessment
    assert "hypothesis_ids" not in assessment


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

    async def fake_k8s_describe(settings, kind, *, namespace="", name=""):
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


def test_unavailable_collectors_are_skipped(monkeypatch) -> None:
    calls = [0]

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls[0] += 1
        return {"action": "done"}

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    result = CollectorResult(agent="kubernetes", status="unavailable", summary="no token")
    asyncio.run(run_drilldowns(drill_settings(), [result], _target(), None))
    assert calls[0] == 0


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


def test_runai_get_tool_refuses_non_api_paths(monkeypatch) -> None:
    mcp_calls = [0]

    async def fake_mcp_call(settings, tool, arguments):
        mcp_calls[0] += 1
        raise AssertionError("must not be reached")

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    outcome = asyncio.run(_tool_runai_get(settings, _target(), {"path": "/auth/token"}))
    assert outcome["error"] and "GET" in outcome["error"]
    assert mcp_calls[0] == 0


def test_runai_get_tool_refuses_path_traversal_and_inline_query(monkeypatch) -> None:
    mcp_calls = [0]

    async def fake_mcp_call(settings, tool, arguments):
        mcp_calls[0] += 1
        raise AssertionError("must not be reached")

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    for path in (
        "/api/../auth/token",
        "/api/%2e%2e/auth/token",
        "/api/v1/./workloads",
        "/api/v1/workloads?x=y",
        "/api/v1/workloads%0a/api/v1/projects",
        "/api/v1/workloads%2Fsecret",
        "/api/%252e%252e/auth/token",
        "/api/%252Fsecret",
        "/api/v1/%255csecret",
        "/api/v1/workloads%250aGET",
    ):
        outcome = asyncio.run(_tool_runai_get(settings, _target(), {"path": path}))
        assert outcome["error"] and "GET" in outcome["error"]
    assert mcp_calls[0] == 0


def test_runai_get_tool_locks_method_to_get(monkeypatch) -> None:
    captured: dict = {}

    class _Result:
        isError = False
        content = []

    async def fake_mcp_call(settings, tool, arguments):
        captured["tool"] = tool
        captured["arguments"] = arguments
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    outcome = asyncio.run(
        _tool_runai_get(
            settings,
            _target(),
            # A hostile/hallucinated request cannot change the verb: method is not
            # an accepted argument and the wrapper hardcodes GET.
            {"path": "/api/v1/workloads", "method": "DELETE", "query": {"name": "x"}},
        )
    )
    assert captured["tool"] == "call_runai_api"
    assert captured["arguments"]["method"] == "GET"
    assert outcome["error"] is None


def test_runai_get_tool_urlencodes_display_query(monkeypatch) -> None:
    class _Result:
        isError = False
        content = []

    async def fake_mcp_call(settings, tool, arguments):
        return _Result()

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")
    outcome = asyncio.run(
        _tool_runai_get(
            settings,
            _target(),
            {
                "path": "/api/v1/workloads",
                "query": {
                    "name": "trainer&includeSecrets=true",
                    "newline": "ok\nGET /api/delete",
                },
            },
        )
    )
    assert "includeSecrets=true" not in outcome["query"]
    assert "\n" not in outcome["query"]
    assert "trainer%26includeSecrets%3Dtrue" in outcome["query"]


def test_runai_search_tool_masks_text_result_and_error(monkeypatch) -> None:
    class _Result:
        def __init__(self, text: str, *, is_error: bool = False) -> None:
            self.isError = is_error
            self.content = [type("Block", (), {"text": text})()]

    calls = iter(
        [
            _Result("GET /api/v1/workloads api_key=search-secret-12345\n## injected"),
            _Result("tool failed password=search-error-secret-12345\n## injected", is_error=True),
        ]
    )

    async def fake_mcp_call(settings, tool, arguments):
        return next(calls)

    monkeypatch.setattr(drilldown, "_mcp_call", fake_mcp_call)
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")

    ok = asyncio.run(drilldown._tool_runai_search(settings, _target(), {"query": "workloads"}))
    failed = asyncio.run(drilldown._tool_runai_search(settings, _target(), {"query": "workloads"}))

    rendered = str([ok, failed])
    assert "search-secret-12345" not in rendered
    assert "search-error-secret-12345" not in rendered
    assert "\n## injected" not in rendered
    assert "[MASKED]" in rendered


def test_runai_get_tool_masks_text_json_result(monkeypatch) -> None:
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
    settings = drill_settings(runai_mcp_url="http://localhost:8809/mcp")

    outcome = asyncio.run(_tool_runai_get(settings, _target(), {"path": "/api/v1/workloads"}))

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


def test_k8s_tool_reports_kubectl_command_title_and_highlights(monkeypatch) -> None:
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

    async def fake_k8s_read(settings, kind, *, namespace="", name="", label_selector=""):
        return {
            "kind": "pods",
            "status_code": 200,
            "error": None,
            "data": {"status": {"reason": "OOMKilled"}},
        }

    monkeypatch.setattr(drilldown, "complete_json", fake_complete_json)
    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    result = _k8s_result()
    settings = replace(drill_settings(), language="ko")
    asyncio.run(run_drilldowns(settings, [result], _target(), None))
    art = result.artifacts[0]
    assert art.query == "kubectl get pods t-0 -n runai"
    assert art.title == "파드 조회"
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
    assert any("shared evidence budget exhausted" in warning for warning in result.warnings)
