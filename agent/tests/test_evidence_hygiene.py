"""Evidence-hygiene checks: stale-pod re-resolution stems, a healthy Postgres
healthcheck demoted to non-evidence, and Korean playbook translation splicing."""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import NO_EVIDENCE, CollectorResult, artifact
from app.collectors.kubernetes import best_matching_pod, pod_name_stem
from app.collectors.postgres import _postgres_result
from app.plan import InvestigationPlan
from app.schemas import Alert, AlertAnalysisRequest, SimilarIncidentContext
from app.services import pipeline
from app.services.evidence_blackboard import Blackboard
from app.services.kg_enrichment import GraphRemediation
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings, make_target

# --- stale-pod re-resolution ---------------------------------------------------


def test_pod_name_stem_strips_controller_suffix() -> None:
    assert pod_name_stem("runai-container-toolkit-vttmr") == "runai-container-toolkit-"
    assert pod_name_stem("web-7f6b9c-abcde") == "web-7f6b9c-"
    # StatefulSet ordinals are STABLE names; a stem would match sibling replicas
    # on other nodes, so none is produced.
    assert pod_name_stem("trainer-0") == ""
    assert pod_name_stem("standalone") == ""


def _pod(name: str, node: str, created: str, *, restarts: int = 0, phase: str = "Running") -> dict:
    return {
        "metadata": {"name": name, "creationTimestamp": created},
        "spec": {"nodeName": node},
        "status": {
            "phase": phase,
            "containerStatuses": [{"name": "main", "restartCount": restarts}],
        },
    }


def test_best_matching_pod_prefers_the_unhealthy_replacement() -> None:
    # DaemonSet: healthy siblings run on EVERY node — the newest of them must
    # never win over the crashlooping replacement, or node evidence is read
    # from the wrong node.
    items = [
        _pod("runai-container-toolkit-crash", "dgx01", "2026-07-06T00:00:00Z", restarts=7),
        _pod("runai-container-toolkit-fresh", "dgx05", "2026-07-07T00:00:00Z"),
        _pod("unrelated-abc12", "dgx03", "2026-07-08T00:00:00Z", restarts=9),
    ]
    match = best_matching_pod(items, [pod_name_stem("runai-container-toolkit-vttmr")])
    assert match is not None
    assert match["spec"]["nodeName"] == "dgx01"


def test_best_matching_pod_all_healthy_needs_unambiguous_match() -> None:
    stem = [pod_name_stem("runai-container-toolkit-vttmr")]
    many_healthy = [
        _pod("runai-container-toolkit-aaa11", "dgx01", "2026-07-01T00:00:00Z"),
        _pod("runai-container-toolkit-bbb22", "dgx02", "2026-07-02T00:00:00Z"),
    ]
    assert best_matching_pod(many_healthy, stem) is None  # guessing = wrong-node evidence
    assert best_matching_pod(many_healthy[:1], stem) is not None  # unambiguous is safe
    assert best_matching_pod(many_healthy, [""]) is None


def test_workload_prefix_node_resolution_rejects_multi_node_replicas() -> None:
    from app.collectors.kubernetes import _best_live_target_pod

    replicas = [
        _pod("trainer-worker-a1b2c", "dgx01", "2026-07-01T00:00:00Z"),
        _pod("trainer-worker-d3e4f", "dgx02", "2026-07-02T00:00:00Z"),
    ]

    assert _best_live_target_pod(replicas, ["trainer-deleted-z9y8x"], "trainer") is None
    assert _best_live_target_pod(replicas[:1], ["trainer-deleted-z9y8x"], "train") is None


# --- healthy Postgres healthcheck is not evidence -------------------------------


def test_insufficient_evidence_gets_a_separate_general_guidance_section() -> None:
    detail = pipeline._detail_from(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "GenericAlert"},
                annotations={"summary": "OOMKilled was reported by an operator"},
            )
        ),
        [],
        [],
        failure_modes={
            "workload_startup_error": [
                {
                    "symptom": "OOMKilled",
                    "keywords": ["oomkilled"],
                    "actions": ["GENERAL-GUIDANCE raise the memory limit after validation."],
                }
            ]
        },
        root_cause_candidates=[
            RankedCause(family="insufficient_evidence", confidence="low", score=0.0)
        ],
        eligible_support_ids=set(),
    )

    actions = detail.split("## 3. Recommended Actions", 1)[1].split("## 4. Appendix", 1)[0]
    guidance = detail.split("## General Troubleshooting Guidance", 1)[1].split(
        "## 4. Appendix", 1
    )[0]
    assert "GENERAL-GUIDANCE" not in actions
    assert "not a diagnosis" in guidance
    assert "GENERAL-GUIDANCE" in guidance


@pytest.mark.asyncio
async def test_healthy_postgres_check_is_not_evidence() -> None:
    checks = {
        "connected": True,
        "active_connections": 2,
        "long_transactions": [],
        "pgvector_extension": True,
        "rca_tables": {"incidents": True},
    }
    result = await _postgres_result(
        make_settings(),
        make_target(),
        checks=checks,
        warnings=[],
        used_mcp=False,
        database_kind="runai_control_plane",
        check_rca_tables=False,
    )
    assert result.status == "ok"
    assert result.summary.startswith(NO_EVIDENCE), (
        "a passing healthcheck must carry the no-evidence marker so it never "
        "ranks alongside real findings"
    )
    assert result.confidence == "low"
    assert result.artifacts[0].confidence == "low"


@pytest.mark.asyncio
async def test_unhealthy_postgres_check_stays_evidence() -> None:
    checks = {
        "connected": True,
        "active_connections": 9,
        "long_transactions": [{"pid": 1, "xact_age": "00:11:00"}],
        "pgvector_extension": True,
        "rca_tables": {},
    }
    result = await _postgres_result(
        make_settings(),  # LLM unconfigured -> deterministic summary kept
        make_target(),
        checks=checks,
        warnings=[],
        used_mcp=False,
        database_kind="runai_control_plane",
        check_rca_tables=False,
    )
    assert result.status == "partial"
    assert not result.summary.startswith(NO_EVIDENCE)
    assert result.confidence == "medium"


# --- Korean playbook translation -------------------------------------------------


@pytest.mark.asyncio
async def test_translate_playbook_ko_splices_only_the_playbook(monkeypatch) -> None:
    detail = (
        "## 4. Appendix\n"
        "\n### Troubleshooting Playbook\n\n"
        "- **GPU Allocation Shows Zero On Dashboard** (known issue)\n"
        "  - Delete the offending pod.\n"
        "\n### Similar Incidents\n\n- No similar past incident found."
    )

    async def fake_complete(settings, *, system, user, **kwargs):
        assert "GPU Allocation" in user
        assert kwargs["model"] == "super"
        return (
            "- **대시보드 GPU 할당 0 표시** (알려진 이슈)\n"
            "  - 문제 파드를 삭제하세요. api_key=translation-secret-12345"
        )

    monkeypatch.setattr(pipeline, "complete", fake_complete)
    translated = await pipeline._translate_playbook_ko(
        replace(make_settings(), llm_model_insight="super"), detail
    )
    assert "대시보드 GPU 할당 0 표시" in translated
    assert "Delete the offending pod" not in translated
    assert "### Similar Incidents" in translated  # neighbouring sections untouched
    assert "- No similar past incident found." in translated
    assert "translation-secret-12345" not in translated
    assert "[MASKED]" in translated


@pytest.mark.asyncio
async def test_translate_playbook_ko_keeps_detail_without_marker() -> None:
    detail = "## 2. 원인\n\n- 근거"
    assert await pipeline._translate_playbook_ko(make_settings(), detail) == detail


@pytest.mark.asyncio
async def test_sharpen_operator_questions_uses_insight_model(monkeypatch) -> None:
    models: list[str | None] = []

    async def fake_complete_json(settings, *, model=None, **_kwargs):
        models.append(model)
        return {"questions": ["Which queue was saturated?", "Which pod stayed pending?"]}

    monkeypatch.setattr(pipeline, "complete_json", fake_complete_json)

    questions = await pipeline._sharpen_operator_questions(
        replace(make_settings(), llm_model_insight="super"),
        ["queue?", "pod?"],
        ["prometheus.metrics"],
        None,
    )

    assert questions == ["Which queue was saturated?", "Which pod stayed pending?"]
    assert models == ["super"]


# --- drill-down observability -----------------------------------------------------


def test_report_evidence_prefers_drilldown_artifact_result_over_generic_summary() -> None:
    result = CollectorResult(agent="postgres", status="ok", summary="db drilldown ok")
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            query="SELECT message FROM scheduler_logs LIMIT 1",
            summary="1 row(s)",
            result={"rows": [{"message": "reclaim/reclaim.go:91 runtime/panic.go:785"}]},
        )
    )
    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="platform_version_bug", confidence="medium", score=7.0)
        ],
    )

    evidence = detail.split("### Evidence", 1)[1].split("###", 1)[0]
    assert "runtime/panic.go:785" in evidence
    assert "1 row(s)" not in evidence


def test_root_cause_supporting_evidence_uses_drilldown_after_no_evidence_base() -> None:
    result = CollectorResult(agent="postgres", status="ok", summary=NO_EVIDENCE)
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="1 row(s)",
            result={
                "rows": [{"message": "scheduler panic at reclaim/reclaim.go:91"}],
                "observation": {"polarity": "present", "coverage": "scoped"},
            },
        )
    )
    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="platform_version_bug", confidence="medium", score=7.0)
        ],
    )

    root_cause = detail.split("## 2. Root Cause", 1)[1].split("## 3.", 1)[0]
    assert "scheduler panic at reclaim/reclaim.go:91" in root_cause


def test_context_only_artifact_stays_out_of_root_cause_evidence() -> None:
    result = CollectorResult(agent="prometheus", status="ok", summary="metrics queried")
    result.artifacts.append(
        artifact(
            agent="prometheus",
            source="prometheus",
            type="promql_signal",
            status="ok",
            confidence="low",
            summary="container memory was observed",
            result={
                "observation": {"polarity": "unknown", "coverage": "partial"},
            },
        )
    )

    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "MemoryAlert"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="node_kubelet_pressure", confidence="medium", score=7.0)
        ],
    )

    root_cause = detail.split("## 2. Root Cause", 1)[1].split("## 3.", 1)[0]
    evidence = detail.split("### Evidence", 1)[1].split("###", 1)[0]
    assert "container memory was observed" not in root_cause
    assert "container memory was observed" in evidence


def test_contextual_eligibility_blocks_scoped_artifact_from_root_cause() -> None:
    """A scoped result for another entity/window is appendix context, not proof."""
    result = CollectorResult(agent="loki", status="ok", summary="logs queried")
    finding = artifact(
        agent="loki",
        source="loki",
        type="logql_signal",
        status="ok",
        confidence="high",
        summary="OOMKilled occurred on unrelated-pod",
        result={"observation": {"polarity": "present", "coverage": "scoped"}},
    )
    finding.evidence_id = "E01"
    result.artifacts.append(finding)

    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "MemoryAlert"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="workload_runtime_error", confidence="medium", score=7.0)
        ],
        # The blackboard rejected E01 because it belongs to a different target
        # or incident window.  It may remain visible in the appendix only.
        eligible_support_ids=set(),
    )

    root_cause = detail.split("## 2. Root Cause", 1)[1].split("## 3.", 1)[0]
    appendix = detail.split("### Evidence", 1)[1].split("###", 1)[0]
    assert "OOMKilled occurred on unrelated-pod" not in root_cause
    assert "OOMKilled occurred on unrelated-pod" in appendix


def test_context_only_artifact_cannot_emit_graph_remediation_actions() -> None:
    """Historical graph fixes need a current scoped observation before actioning."""
    result = CollectorResult(agent="system", status="ok", summary="live node snapshot")
    result.artifacts.append(
        artifact(
            agent="system",
            source="system",
            type="node_logs",
            status="ok",
            confidence="medium",
            summary="old Xid 79 appears in an unbounded current log snapshot",
            result={
                "lines": ["NVRM: Xid 79"],
                "observation": {"polarity": "unknown", "coverage": "partial"},
            },
        )
    )
    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "GenericAlert"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="gpu_hardware_error", confidence="medium", score=7.0)
        ],
        graph_fixes=GraphRemediation(
            family_fixes=["Reset the implicated GPU."],
            xid_fixes={79: ["Replace the GPU after hardware validation."]},
            root_xids={79: [48]},
        ),
        # The blackboard rejected every artifact as context/out-of-scope.
        eligible_support_ids=set(),
    )

    root_cause = detail.split("## 2. Root Cause", 1)[1].split("## 3.", 1)[0]
    actions = detail.split("## 3. Recommended Actions", 1)[1].split("## 4.", 1)[0]
    assert "Fix the root XID first" not in root_cause
    assert "Reset the implicated GPU" not in actions
    assert "Replace the GPU" not in actions


def test_context_only_artifacts_cannot_emit_catalog_or_historical_actions() -> None:
    """Every cause-specific action path needs current scoped support, not just graph fixes."""
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "NodeDiskPressure"},
            annotations={"summary": "DiskPressure was named by a stale dashboard card"},
        ),
        similar_incidents=[
            SimilarIncidentContext(
                incident_id="old-pressure",
                similarity=0.99,
                analysis_summary="HISTORICAL-REMEDY drain the old node",
            )
        ],
    )
    plan = InvestigationPlan(
        matched_alert={
            "family": "node_kubelet_pressure",
            "actions": ["CATALOG-REMEDY cordon the node"],
        },
        component="component-a",
    )
    modes = {
        "node_kubelet_pressure": [
            {
                "symptom": "Node Disk Pressure",
                "keywords": ["diskpressure"],
                "actions": ["PLAYBOOK-REMEDY inspect and drain the node"],
            }
        ]
    }
    detail = pipeline._detail_from(
        request,
        [CollectorResult(agent="kubernetes", status="ok", summary="current snapshot")],
        [],
        failure_modes=modes,
        root_cause_candidates=[
            RankedCause(family="node_kubelet_pressure", confidence="medium", score=7.0)
        ],
        kg_context={"enabled": True, "available": True, "knowledge": modes},
        plan=plan,
        graph_fixes=GraphRemediation(family_fixes=["GRAPH-REMEDY reset the node"]),
        components={"component-a": {"checks": ["COMPONENT-REMEDY restart it"]}},
        # A typed artifact existed but was another target/window, so this is an
        # explicit production-style no-support verdict rather than a legacy call.
        eligible_support_ids=set(),
    )

    actions = detail.split("## 3. Recommended Actions", 1)[1].split("## 4.", 1)[0]
    assert "Not enough evidence for concrete actions" in actions
    for forbidden in (
        "CATALOG-REMEDY",
        "COMPONENT-REMEDY",
        "PLAYBOOK-REMEDY",
        "GRAPH-REMEDY",
        "HISTORICAL-REMEDY",
    ):
        assert forbidden not in actions
    assert "Knowledge-base remediation is withheld" in detail
    assert "Specific playbook remediation is withheld" in detail


def test_synthesis_input_separates_support_contradiction_and_context() -> None:
    result = CollectorResult(agent="prometheus", status="ok", summary="all metrics queried")
    for name, polarity, coverage in (
        ("capacity gap", "present", "scoped"),
        ("restart unchanged", "absent", "scoped"),
        ("memory snapshot", "unknown", "partial"),
    ):
        result.artifacts.append(
            artifact(
                agent="prometheus",
                source="prometheus",
                type="promql_signal",
                status="ok",
                confidence="medium",
                summary=name,
                result={"observation": {"polarity": polarity, "coverage": coverage}},
            )
        )

    finding = pipeline._synthesis_collector_findings([result])[0]

    assert finding["collection_summary"] == "all metrics queried"
    assert [item["summary"] for item in finding["supporting_artifacts"]] == ["capacity gap"]
    assert [item["summary"] for item in finding["contradicting_artifacts"]] == [
        "restart unchanged"
    ]
    assert [item["summary"] for item in finding["context_artifacts"]] == ["memory snapshot"]
    assert finding["context_artifacts"][0]["evidence_role"] == "context"


def test_synthesis_input_uses_contextual_eligibility_over_raw_scoped_role() -> None:
    result = CollectorResult(agent="loki", status="ok", summary="logs queried")
    finding = artifact(
        agent="loki",
        source="loki",
        type="logql_signal",
        status="ok",
        confidence="high",
        summary="unrelated workload OOMKilled",
        result={"observation": {"polarity": "present", "coverage": "scoped"}},
    )
    finding.evidence_id = "E01"
    result.artifacts.append(finding)

    projected = pipeline._synthesis_collector_findings(
        [result], evidence_eligibility={"E01": object()}
    )[0]

    assert projected["supporting_artifacts"] == []
    assert projected["contradicting_artifacts"] == []
    assert [item["summary"] for item in projected["context_artifacts"]] == [
        "unrelated workload OOMKilled"
    ]


def test_unavailable_drilldown_artifact_is_appendix_context_not_supporting_evidence() -> None:
    result = CollectorResult(agent="postgres", status="ok", summary=NO_EVIDENCE)
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="unavailable",
            confidence="low",
            summary="postgres drilldown failed: connection refused",
        )
    )
    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="platform_version_bug", confidence="medium", score=7.0)
        ],
    )

    root_cause = detail.split("## 2. Root Cause", 1)[1].split("## 3.", 1)[0]
    evidence = detail.split("### Evidence", 1)[1].split("###", 1)[0]
    assert "connection refused" not in root_cause
    assert "connection refused" in evidence


def test_appendix_prefers_successful_artifact_over_later_failed_artifact() -> None:
    result = CollectorResult(agent="postgres", status="ok", summary=NO_EVIDENCE)
    result.artifacts.extend(
        [
            artifact(
                agent="postgres",
                source="postgres",
                type="drilldown_query",
                status="ok",
                confidence="medium",
                summary="1 row(s)",
                result={"rows": [{"message": "scheduler panic at reclaim/reclaim.go:91"}]},
            ),
            artifact(
                agent="postgres",
                source="postgres",
                type="drilldown_query",
                status="unavailable",
                confidence="low",
                summary="later postgres drilldown failed: connection refused",
            ),
        ]
    )
    detail = pipeline._detail_from(
        AlertAnalysisRequest(alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})),
        [result],
        [],
        root_cause_candidates=[
            RankedCause(family="platform_version_bug", confidence="medium", score=7.0)
        ],
    )

    evidence = detail.split("### Evidence", 1)[1].split("###", 1)[0]
    assert "scheduler panic at reclaim/reclaim.go:91" in evidence
    assert "connection refused" not in evidence


@pytest.mark.asyncio
async def test_drilldown_llm_failure_is_visible_in_warnings(monkeypatch) -> None:
    """A dead LLM must not masquerade as a satisfied drill-down agent."""
    from dataclasses import replace

    from app.collectors.base import CollectorResult
    from app.services import drilldown

    async def no_decision(*args, **kwargs):
        return None  # transport/parse failure

    async def why(*args, **kwargs):
        # The follow-up diagnostic call surfaces the actual reason (e.g. the
        # litellm-provider config error) rather than a bare "failed".
        return None, "HTTP 400 provider not found"

    monkeypatch.setattr(drilldown, "complete_json", no_decision)
    monkeypatch.setattr(drilldown, "complete_with_error", why)
    settings = replace(
        make_settings(),
        enable_agent_drilldown=True,
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="pod Pending")
    await drilldown.run_drilldowns(settings, [result], make_target(), None)
    # The failure is visible AND diagnosable (the reason is surfaced, not just "failed").
    assert any("LLM decision call failed" in w for w in result.warnings)
    assert any("provider not found" in w for w in result.warnings)


# --- wrong-node protection (Codex review) -----------------------------------------


def test_best_matching_pod_multiple_unhealthy_nodes_is_ambiguous() -> None:
    # A DaemonSet broken on SEVERAL nodes: per-pod attribution is impossible
    # from stems alone — guessing would read kernel logs from the wrong node.
    stem = [pod_name_stem("runai-container-toolkit-vttmr")]
    spread = [
        _pod("runai-container-toolkit-aa111", "dgx01", "2026-07-06T00:00:00Z", restarts=3),
        _pod("runai-container-toolkit-bb222", "dgx07", "2026-07-07T00:00:00Z", restarts=5),
    ]
    assert best_matching_pod(spread, stem) is None

    # Successive incarnations on the SAME node stay resolvable (newest wins).
    same_node = [
        _pod("runai-container-toolkit-aa111", "dgx01", "2026-07-06T00:00:00Z", restarts=3),
        _pod("runai-container-toolkit-bb222", "dgx01", "2026-07-07T00:00:00Z", restarts=5),
    ]
    match = best_matching_pod(same_node, stem)
    assert match is not None
    assert match["metadata"]["name"] == "runai-container-toolkit-bb222"


def test_node_from_pod_events_reads_kubelet_host_and_scheduled_message() -> None:
    from app.collectors.kubernetes import node_from_pod_events

    kubelet = [{"source": {"host": "dgx01"}, "message": "Back-off restarting container"}]
    assert node_from_pod_events(kubelet) == "dgx01"
    scheduled = [
        {
            "source": {"component": "default-scheduler"},
            "message": "Successfully assigned runai/runai-container-toolkit-vttmr to dgx02",
        }
    ]
    assert node_from_pod_events(scheduled) == "dgx02"
    assert node_from_pod_events([{"message": "Pulled image"}]) == ""


# --- LLM JSON parsing hardening ----------------------------------------------------


def test_parse_json_object_survives_prose_fences_and_trailing_junk() -> None:
    from app.llm import parse_json_object

    assert parse_json_object('물론입니다! {"summary": "ok", "detail": "본문"} 도움이 되길!') == {
        "summary": "ok",
        "detail": "본문",
    }
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('{"nested": {"b": "brace } in string"}}') == {
        "nested": {"b": "brace } in string"}
    }
    assert parse_json_object('{"decision": {"query": "up"},}') is None
    assert parse_json_object('{"decision": {"query": "up"},} {"later": true}') == {
        "later": True
    }
    assert parse_json_object("no json here") is None
    assert parse_json_object("{truncated: ") is None
    assert parse_json_object("") is None


@pytest.mark.asyncio
async def test_synthesis_retries_once_on_malformed_json(monkeypatch) -> None:
    replies = iter(["not json at all", '{"summary": "요약", "detail": "본문"}'])
    calls = {"n": 0}

    async def fake_complete(settings, **kwargs):
        calls["n"] += 1
        return next(replies)

    monkeypatch.setattr(pipeline, "complete", fake_complete)
    parsed = await pipeline._complete_synthesis_json(
        make_settings(), system="s", user="u"
    )
    assert parsed == {"summary": "요약", "detail": "본문"}
    assert calls["n"] == 2


# --- MCP label-selector fidelity ----------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_k8s_list_candidates_all_carry_label_selector(monkeypatch) -> None:
    """No MCP candidate may 'succeed' by silently dropping the requested selector."""
    from dataclasses import replace

    from app.collectors import kubernetes as k8s

    seen: list[list[tuple[str, dict]]] = []

    async def fake_mcp_json(settings, candidates):
        seen.append(candidates)
        return {"items": []}

    monkeypatch.setattr(k8s, "_k8s_mcp_json", fake_mcp_json)
    settings = replace(make_settings(), kubernetes_mcp_url="http://mcp:8080/mcp")
    item = await k8s.k8s_read(settings, "pods", namespace="runai", label_selector="app=toolkit")
    assert item["error"] is None
    assert seen, "MCP path must be attempted when the URL is configured"
    for tool, args in seen[0]:
        assert args.get("labelSelector") == "app=toolkit", (
            f"candidate {tool} would drop the label selector"
        )


def test_apply_label_selector_filters_equality_only() -> None:
    from app.collectors.kubernetes import _apply_label_selector, kubectl_repr

    data = {
        "items": [
            {"metadata": {"name": "a", "labels": {"app": "toolkit", "tier": "node"}}},
            {"metadata": {"name": "b", "labels": {"app": "other"}}},
            {"metadata": {"name": "c"}},
        ]
    }
    filtered = _apply_label_selector(data, "app=toolkit,tier=node")
    assert [i["metadata"]["name"] for i in filtered["items"]] == ["a"]
    # set-based selectors pass through untouched
    assert _apply_label_selector(data, "app in (toolkit,other)") is data
    assert _apply_label_selector(data, "app!=other") is data
    assert _apply_label_selector(data, "=toolkit") is data
    assert kubectl_repr("pods; delete secrets", namespace="runai") == (
        "kubectl get 'pods; delete secrets' -n runai"
    )


# --- architecture knowledge reaches the drill-down loop -----------------------------


def test_implicated_architecture_slices_topology_for_the_incident(monkeypatch) -> None:
    from app.collectors.base import CollectorResult
    from app.services import drilldown

    components = {
        "runai-container-toolkit": {
            "component": "runai-container-toolkit",
            "failure_effect": "GPU containers cannot start on that node.",
            "depends_on": ["runai-agent"],
        },
        "runai-agent": {
            "component": "runai-agent",
            "failure_effect": "UI changes never reach the cluster.",
            "depends_on": [],
        },
        "unrelated-svc": {
            "component": "unrelated-svc",
            "failure_effect": "Something else.",
            "depends_on": [],
        },
    }
    monkeypatch.setattr(
        "app.knowledge.load_architecture", lambda path: components
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="pod crashloops")
    lines = drilldown._implicated_architecture(
        make_settings(),
        result,
        make_target().__class__(
            **{**make_target().__dict__, "pod": "runai-container-toolkit-vttmr"}
        ),
    )
    joined = " ".join(lines)
    assert "runai-container-toolkit" in joined
    assert "runai-agent" in joined  # dependency chain rides along
    assert "unrelated-svc" not in joined
    # pure user-workload incident implicates nothing
    empty = drilldown._implicated_architecture(make_settings(), result, make_target())
    assert empty == []


def test_implicated_architecture_ranks_the_alert_subject_first(monkeypatch) -> None:
    """A broad evidence sweep must not crowd the alert's subject component out."""
    from app.collectors.base import CollectorResult
    from app.services import drilldown

    # YAML order puts three incidental components FIRST; the alert's pod names
    # the fourth. The old first-3-in-file-order cap dropped the subject.
    components = {
        name: {"component": name, "failure_effect": f"{name} broken.", "depends_on": []}
        for name in ["runai-agent", "cluster-sync", "assets-sync", "runai-backend-workloads"]
    }
    monkeypatch.setattr("app.knowledge.load_architecture", lambda path: components)
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="control-plane sweep: runai-agent ok, cluster-sync ok, assets-sync ok",
    )
    target = make_target().__class__(
        **{**make_target().__dict__, "pod": "runai-backend-workloads-7f6b9-abcde"}
    )
    lines = drilldown._implicated_architecture(make_settings(), result, target)
    assert any(line.startswith("runai-backend-workloads:") for line in lines), (
        "the alert's subject component must survive the relevance cap"
    )


def test_target_match_survives_incidental_longer_evidence_match(monkeypatch) -> None:
    """An evidence-only mention must not subsume the alert's target component."""
    from app.collectors.base import CollectorResult
    from app.services import drilldown

    components = {
        name: {"component": name, "failure_effect": f"{name} broken.", "depends_on": []}
        for name in ["runai-backend", "runai-backend-workloads"]
    }
    monkeypatch.setattr("app.knowledge.load_architecture", lambda path: components)
    # Target pod names runai-backend; the LONGER name appears only in evidence.
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="sweep also listed runai-backend-workloads as Running",
    )
    target = make_target().__class__(
        **{**make_target().__dict__, "pod": "runai-backend-7f6b9-abcde"}
    )
    lines = drilldown._implicated_architecture(make_settings(), result, target)
    assert any(line.startswith("runai-backend:") for line in lines), (
        "the target-matched component must not be subsumed by an evidence mention"
    )
    # Both matching the SAME identifier still dedupes to the specific one.
    target2 = make_target().__class__(
        **{**make_target().__dict__, "pod": "runai-backend-workloads-7f6b9-abcde"}
    )
    lines2 = drilldown._implicated_architecture(make_settings(), result, target2)
    assert any(line.startswith("runai-backend-workloads:") for line in lines2)
    assert not any(line.startswith("runai-backend:") for line in lines2)


def test_implicated_architecture_ignores_healthy_evidence_mentions(monkeypatch) -> None:
    """Healthy component names in a broad sweep are context, not suspects."""
    from app.collectors.base import CollectorResult
    from app.schemas import AlertAnalysisArtifact
    from app.services import drilldown

    components = {
        name: {"component": name, "failure_effect": f"{name} broken.", "depends_on": []}
        for name in ["runai-agent", "cluster-sync", "assets-sync"]
    }
    monkeypatch.setattr("app.knowledge.load_architecture", lambda path: components)
    target = make_target()

    healthy = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary=(
            "control-plane sweep: runai-agent ok, cluster-sync running, "
            "healthy components: assets-sync"
        ),
    )
    assert drilldown._implicated_architecture(make_settings(), healthy, target) == []

    healthy_artifact = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai sweep returned rows.",
        artifacts=[
            AlertAnalysisArtifact(
                agent="runai",
                source="runai",
                type="component",
                status="ok",
                summary="metadata rows",
                result={"component": "runai-agent", "status": "healthy"},
            )
        ],
    )
    assert drilldown._implicated_architecture(make_settings(), healthy_artifact, target) == []

    failing_artifact = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai sweep returned rows.",
        artifacts=[
            AlertAnalysisArtifact(
                agent="runai",
                source="runai",
                type="component",
                status="ok",
                summary="metadata rows",
                result={"component": "cluster-sync", "status": "disconnected"},
            )
        ],
    )
    artifact_lines = drilldown._implicated_architecture(
        make_settings(), failing_artifact, target
    )
    assert any(line.startswith("cluster-sync:") for line in artifact_lines)

    unavailable_artifact = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai sweep returned rows.",
        artifacts=[
            AlertAnalysisArtifact(
                agent="runai",
                source="runai",
                type="component",
                status="unavailable",
                summary="failed query mentioned cluster-sync disconnected",
                result={"error": "cluster-sync disconnected"},
            )
        ],
    )
    assert drilldown._implicated_architecture(make_settings(), unavailable_artifact, target) == []

    failing = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="runai-agent is not healthy; cluster-sync disconnected",
    )
    lines = drilldown._implicated_architecture(make_settings(), failing, target)
    assert any(line.startswith("runai-agent:") for line in lines)
    assert any(line.startswith("cluster-sync:") for line in lines)


def test_implicated_architecture_ignores_refuted_component_mentions(monkeypatch) -> None:
    """Refuted component mentions must not steer the drill-down prompt."""
    from app.collectors.base import CollectorResult
    from app.services import drilldown

    components = {
        name: {"component": name, "failure_effect": f"{name} broken.", "depends_on": []}
        for name in ["runai-agent", "cluster-sync"]
    }
    monkeypatch.setattr("app.knowledge.load_architecture", lambda path: components)
    target = make_target()

    for summary in [
        "runai-agent has no errors; cluster-sync has no restarts",
        "no issues in runai-agent or cluster-sync after rollout",
        "runai-agent not implicated; cluster-sync healthy",
        "runai-agent errors were ruled out; cluster-sync ok",
        "checked runai-agent logs and found no matching errors",
    ]:
        result = CollectorResult(agent="kubernetes", status="ok", summary=summary)
        assert drilldown._implicated_architecture(make_settings(), result, target) == []

    mixed = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="runai-agent has no errors but cluster-sync disconnected",
    )
    lines = drilldown._implicated_architecture(make_settings(), mixed, target)
    assert any(line.startswith("cluster-sync:") for line in lines)
    assert not any(line.startswith("runai-agent:") for line in lines)


def test_implicated_architecture_ignores_doc_and_question_mentions(monkeypatch) -> None:
    """Docs/templates/questions are not live evidence for platform topology."""
    from app.collectors.base import CollectorResult
    from app.services import drilldown

    components = {
        name: {"component": name, "failure_effect": f"{name} broken.", "depends_on": []}
        for name in ["runai-agent", "cluster-sync"]
    }
    monkeypatch.setattr("app.knowledge.load_architecture", lambda path: components)
    target = make_target()

    for summary in [
        "docs example: runai-agent disconnected",
        "runbook example says cluster-sync disconnected",
        "question: could this be runai-agent unavailable?",
        "template includes cluster-sync error",
    ]:
        result = CollectorResult(agent="kubernetes", status="ok", summary=summary)
        assert drilldown._implicated_architecture(make_settings(), result, target) == []

    live = CollectorResult(agent="kubernetes", status="ok", summary="cluster-sync disconnected")
    lines = drilldown._implicated_architecture(make_settings(), live, target)
    assert any(line.startswith("cluster-sync:") for line in lines)


# --- followups must query the LIVE pod, not the alert's stale name -------------------


@pytest.mark.asyncio
async def test_evidence_stage_scopes_followup_target_to_the_plan(monkeypatch) -> None:
    from app.plan import InvestigationPlan
    from app.progress import ProgressReporter
    from app.schemas import Alert, AlertAnalysisRequest

    seen: dict[str, str] = {}

    async def fake_k8s_followup(settings, k8s_result, target, **kwargs):
        seen["k8s"] = target.pod
        return []

    async def fake_prom_followup(settings, prom_result, k8s_result, target, **kwargs):
        seen["prom"] = target.pod
        return []

    monkeypatch.setattr("app.collectors.kubernetes.k8s_followup", fake_k8s_followup)
    monkeypatch.setattr("app.collectors.prometheus.prometheus_followup", fake_prom_followup)
    stale_target = make_target().__class__(
        **{**make_target().__dict__, "pod": "toolkit-dead1"}
    )
    state = pipeline.PipelineState(
        settings=make_settings(),  # no LLM -> one-shot gather; no drill-down
        request=AlertAnalysisRequest(alert=Alert(labels={}, annotations={})),
        target=stale_target,
        progress=ProgressReporter(make_settings(), run_id=""),
        masker=None,
        collectors=[],
        plan=InvestigationPlan(pod="toolkit-live2", namespaces=[stale_target.namespace]),
    )
    await pipeline.evidence_stage(state)
    assert seen == {"k8s": "toolkit-live2", "prom": "toolkit-live2"}, (
        "follow-ups must query the plan's re-resolved live pod"
    )
    assert (state.target.pod, state.target.node) == ("toolkit-live2", stale_target.node)


@pytest.mark.asyncio
async def test_re_resolved_live_target_drives_blackboard_eligibility(monkeypatch) -> None:
    """A live replacement is collection scope and validation scope, not just a query hint."""
    from app.progress import ProgressReporter

    seen: dict[str, str] = {}

    class KubernetesCollector:
        async def collect(self, target, plan):  # noqa: ANN001
            seen.update(pod=target.pod, node=target.node)
            return CollectorResult(
                agent="kubernetes",
                status="ok",
                summary="FailedScheduling on the resolved live Pod",
                artifacts=[
                    artifact(
                        agent="kubernetes",
                        source="kubernetes",
                        type="kubernetes_warning_events",
                        status="ok",
                        confidence="high",
                        summary="FailedScheduling on trainer-live2",
                        result={
                            "events": [
                                {
                                    "type": "Warning",
                                    "reason": "FailedScheduling",
                                    "message": "0/2 nodes are available",
                                }
                            ],
                            "observation": {
                                "predicate": "kubernetes_warning_events",
                                "polarity": "present",
                                "coverage": "scoped",
                                "observed_entity": {
                                    "kind": "pod",
                                    "name": target.pod,
                                    "namespace": target.namespace,
                                },
                            },
                        },
                    )
                ],
            )

    async def no_followup(*_args, **_kwargs):
        return []

    monkeypatch.setattr("app.collectors.kubernetes.k8s_followup", no_followup)
    monkeypatch.setattr("app.collectors.prometheus.prometheus_followup", no_followup)
    fired_at = "2026-07-14T01:00:00Z"
    stale_target = replace(
        make_target(),
        pod="trainer-dead1",
        node="",
        fired_at=fired_at,
    )
    state = pipeline.PipelineState(
        settings=make_settings(),
        request=AlertAnalysisRequest(
            incident_id="INC-live-target",
            alert=Alert(
                status="firing",
                labels={},
                annotations={},
                startsAt=fired_at,
            ),
        ),
        target=stale_target,
        progress=ProgressReporter(make_settings(), run_id="INC-live-target"),
        masker=None,
        collectors=[KubernetesCollector()],
        plan=InvestigationPlan(
            pod="trainer-live2",
            node="gpu-node-live",
            workload="trainer",
            namespaces=[stale_target.namespace],
        ),
    )

    await pipeline.evidence_stage(state)

    assert seen == {"pod": "trainer-live2", "node": "gpu-node-live"}
    assert (state.target.pod, state.target.node) == ("trainer-live2", "gpu-node-live")
    eligibility = pipeline._public_evidence_eligibility(state)
    assert eligibility["E01"].support is True
    assert "pod:trainer-live2" in pipeline._evidence_context(state)["entities"]
    assert "pod:trainer-dead1" not in pipeline._evidence_context(state)["entities"]


@pytest.mark.parametrize(
    ("labels", "annotations"),
    [
        ({"condition": "OOMKilled", "status": "False"}, {}),
        ({"status": "False", "condition": "OOMKilled"}, {}),
        ({}, {"condition": "FailedScheduling", "value": "0"}),
        ({}, {"value": "inactive", "reason": "ImagePullBackOff"}),
    ],
)
def test_false_alert_condition_is_not_positive_signature(labels, annotations) -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "ConditionProbe", **labels},
            annotations=annotations,
            fingerprint="fp-false-condition",
        )
    )

    assert pipeline._alert_signature_evidence_result(request, make_target()) is None


@pytest.mark.parametrize(
    "summary",
    [
        "Check whether this pod is OOMKilled before changing limits.",
        "Possible ImagePullBackOff; inspect registry credentials.",
        "Runbook: grep for FailedScheduling in pod events.",
        "Expected observation: Unschedulable if the queue is exhausted.",
    ],
)
def test_conditional_alert_guidance_is_not_positive_signature(summary) -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "GenericAlert"},
            annotations={"summary": summary},
            fingerprint="fp-conditional",
        )
    )

    assert pipeline._alert_signature_evidence_result(request, make_target()) is None


def test_asserted_alert_signature_uses_alert_identity_not_live_target() -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "ContainerFailure"},
            annotations={"summary": "Container terminated with OOMKilled"},
            fingerprint="fp-stale-alert",
        )
    )
    live_target = replace(make_target(), pod="replacement-pod", node="replacement-node")

    result = pipeline._alert_signature_evidence_result(request, live_target)

    assert result is not None
    observation = result.artifacts[0].result["observation"]
    assert observation["observed_entity"] == {
        "kind": "alert",
        "name": "fp-stale-alert",
    }


@pytest.mark.asyncio
async def test_alert_only_xid_is_auditable_harness_support(monkeypatch) -> None:
    """A dispositive alert signature gets a real E-link instead of a rationale bypass."""
    from app.services.kg_enrichment import KGContext

    async def no_followup(*_args, **_kwargs):
        return []

    monkeypatch.setattr("app.collectors.kubernetes.k8s_followup", no_followup)
    monkeypatch.setattr("app.collectors.prometheus.prometheus_followup", no_followup)
    settings = replace(make_settings(), enable_rca_output_harness=True)
    request = AlertAnalysisRequest(
        incident_id="INC-xid-alert",
        alert=Alert(
            status="firing",
            labels={
                "alertname": "NVRMXidCritical",
                "namespace": "runai-vision",
                "node": "gpu-node-1",
            },
            annotations={"summary": "NVRM: Xid 79 detected by the GPU driver"},
            startsAt="2026-07-14T01:00:00Z",
        ),
    )
    state = pipeline.new_state(settings, request, collectors=[])
    state.kg_context = KGContext()
    state.plan = InvestigationPlan(
        namespaces=[state.target.namespace],
        node=state.target.node,
        hypotheses=[{"family": "gpu_hardware_error", "reason": "alert XID"}],
    )

    await pipeline.evidence_stage(state)
    await pipeline.rank_stage(state)
    await pipeline.self_check_stage(state)
    await pipeline.synthesize_stage(state)
    await pipeline.harness_stage(state)

    assert state.response is not None
    assert state.response.root_cause_family == "gpu_hardware_error"
    xid_cards = [card for card in state.response.artifacts if card.agent == "alert"]
    assert len(xid_cards) == 1
    assert xid_cards[0].result["observation"]["predicate"] == "alert_signature:nvidia_xid"
    assert xid_cards[0].result["observation"]["observed_entity"] == {
        "kind": "alert",
        "name": "NVRMXidCritical",
    }
    assert "alert:NVRMXidCritical" in pipeline._evidence_context(state)["entities"]
    claim = state.response.context["harness"]["claims"][0]
    assert claim["supporting_evidence"] == [xid_cards[0].evidence_id]
    assert state.response.context["harness"]["status"] == "pass"


@pytest.mark.asyncio
async def test_resolved_incident_keeps_alert_pod_for_followups(monkeypatch) -> None:
    """A current replacement must not erase any historical target identity."""
    from app.plan import InvestigationPlan
    from app.progress import ProgressReporter

    seen: dict[str, tuple[str, str, str, str]] = {}

    async def fake_k8s_followup(settings, k8s_result, target, **kwargs):
        seen["k8s"] = (
            target.namespace,
            target.pod,
            target.node,
            target.workload_name,
        )
        return []

    async def fake_prom_followup(settings, prom_result, k8s_result, target, **kwargs):
        seen["prom"] = (
            target.namespace,
            target.pod,
            target.node,
            target.workload_name,
        )
        return []

    monkeypatch.setattr("app.collectors.kubernetes.k8s_followup", fake_k8s_followup)
    monkeypatch.setattr("app.collectors.prometheus.prometheus_followup", fake_prom_followup)
    alert_target = replace(
        make_target(),
        namespace="historical-ns",
        pod="toolkit-dead1",
        node="historical-node",
        workload_name="historical-workload",
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    state = pipeline.PipelineState(
        settings=make_settings(),
        request=AlertAnalysisRequest(
            alert=Alert(
                # A stored/manual historical run can retain a stale firing
                # status while endsAt is the authoritative resolved boundary.
                status="firing",
                labels={},
                annotations={},
                startsAt=alert_target.fired_at,
                endsAt=alert_target.resolved_at,
            )
        ),
        target=alert_target,
        progress=ProgressReporter(make_settings(), run_id=""),
        masker=None,
        collectors=[],
        # Simulates the replacement Pod selected by a live plan lookup.
        plan=InvestigationPlan(
            pod="toolkit-live2",
            node="current-node",
            workload="current-workload",
            namespaces=["current-ns", "runai"],
        ),
    )

    await pipeline.evidence_stage(state)

    expected = (
        "historical-ns",
        "toolkit-dead1",
        "historical-node",
        "historical-workload",
    )
    assert seen == {"k8s": expected, "prom": expected}
    assert state.plan.namespaces == ["historical-ns", "current-ns", "runai"]
    assert (
        state.target.namespace,
        state.target.pod,
        state.target.node,
        state.target.workload_name,
    ) == expected
    assert state.declared_target == alert_target


@pytest.mark.asyncio
async def test_resolved_incident_uses_only_single_concrete_occurrence_pod(monkeypatch) -> None:
    """Grouped Pod names are history; never replace them with a live planner guess."""
    from app.plan import InvestigationPlan
    from app.progress import ProgressReporter

    seen: list[str] = []

    async def fake_k8s_followup(settings, k8s_result, target, **kwargs):
        seen.append(target.pod)
        return []

    async def fake_prom_followup(*args, **kwargs):
        return []

    monkeypatch.setattr("app.collectors.kubernetes.k8s_followup", fake_k8s_followup)
    monkeypatch.setattr("app.collectors.prometheus.prometheus_followup", fake_prom_followup)
    target = replace(
        make_target(),
        pod="",
        workload_name="trainer",
        fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    request = AlertAnalysisRequest(
        alert=Alert(status="resolved", labels={}, annotations={}),
        occurrence_pods=["trainer-dead-a"],
    )
    state = pipeline.PipelineState(
        settings=make_settings(),
        request=request,
        target=target,
        progress=ProgressReporter(make_settings(), run_id=""),
        masker=None,
        collectors=[],
        plan=InvestigationPlan(pod="trainer-live-now", namespaces=[target.namespace]),
    )

    await pipeline.evidence_stage(state)

    assert seen == ["trainer-dead-a"]
    assert state.plan.pod == "trainer-dead-a"

    # More than one occurrence is a set of affected Pods. Picking one would
    # silently discard the others and can attach evidence to the wrong node.
    state.request.occurrence_pods = ["trainer-dead-a", "trainer-dead-b"]
    state.plan.pod = "trainer-live-now"
    seen.clear()
    await pipeline.evidence_stage(state)
    assert seen == [""]
    assert state.plan.pod == ""


def test_blackboard_aliases_do_not_merge_same_summary_from_different_pods() -> None:
    fired = "2026-07-13T10:00:00Z"
    resolved = "2026-07-13T10:05:00Z"
    target = replace(make_target(), fired_at=fired, resolved_at=resolved)
    observed_window = {"start": fired, "end": resolved}

    def pod_artifact(pod: str):
        return artifact(
            agent="kubernetes",
            source="kubernetes",
            type="pod_condition",
            status="ok",
            confidence="high",
            # Deliberately identical: the observed resource must keep these
            # facts separate, not a display-summary coincidence.
            summary="Pod reported a condition during the incident.",
            highlights=["condition observed"],
            result={
                "observation": {
                    "polarity": "present",
                    "coverage": "scoped",
                    "observed_entity": f"pod:{pod}",
                    "observation_window": observed_window,
                }
            },
        )

    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="pod conditions collected",
        artifacts=[pod_artifact("unrelated-0"), pod_artifact(target.pod)],
    )
    board = Blackboard(run_id="INC-current")
    board.add_result(
        "kubernetes",
        result,
        entity=f"pod:{target.pod}",
        timestamp=fired,
        observed_window_start=fired,
        observed_window_end=resolved,
    )
    state = pipeline.PipelineState(
        settings=make_settings(),
        request=AlertAnalysisRequest(
            alert=Alert(labels={}, annotations={}), incident_id="INC-current"
        ),
        target=target,
        progress=pipeline.ProgressReporter(make_settings(), run_id=""),
        masker=None,
        collectors=[],
        results=[result],
        blackboard=board,
    )
    pipeline._aggregate_evidence(state)

    aliases = pipeline._blackboard_artifact_evidence_ids(state)
    facts_by_entity = {fact.entity: fact.fact_id for fact in board.facts()}
    assert aliases[facts_by_entity["pod:unrelated-0"]] == "E01"
    assert aliases[facts_by_entity[f"pod:{target.pod}"]] == "E02"

    eligibility = pipeline._public_evidence_eligibility(state)
    assert eligibility["E01"].support is False
    assert eligibility["E02"].support is True


def test_causal_evidence_context_keeps_prelude_and_opens_firing_alert() -> None:
    """Causal eligibility includes the trigger prelude, not recovery epilogue.

    Historical collectors retain a bounded fifteen-minute firing query, while
    causal eligibility admits target-scoped evidence observed while the alert
    is still firing. Resolved alerts still exclude the recovery epilogue.
    """
    from app.progress import ProgressReporter

    target = replace(make_target(), fired_at="2026-07-10T01:00:00Z", resolved_at="")
    state = pipeline.PipelineState(
        settings=make_settings(),
        request=AlertAnalysisRequest(alert=Alert(labels={}, annotations={}), incident_id="INC-now"),
        target=target,
        progress=ProgressReporter(make_settings(), run_id=""),
        masker=None,
        collectors=[],
    )
    assert pipeline._evidence_context(state)["window_start"] == "2026-07-10T00:55:00Z"
    assert pipeline._evidence_context(state)["window_end"] != "2026-07-10T01:15:00Z"

    state.target = replace(target, resolved_at="2026-07-10T01:10:00Z")
    assert pipeline._evidence_context(state)["window_end"] == "2026-07-10T01:10:00Z"
