"""Evidence-hygiene checks: stale-pod re-resolution stems, a healthy Postgres
healthcheck demoted to non-evidence, and Korean playbook translation splicing."""

from __future__ import annotations

import pytest

from app.collectors.base import NO_EVIDENCE
from app.collectors.kubernetes import best_matching_pod, pod_name_stem
from app.collectors.postgres import _postgres_result
from app.services import pipeline
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


# --- healthy Postgres healthcheck is not evidence -------------------------------


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
        return "- **대시보드 GPU 할당 0 표시** (알려진 이슈)\n  - 문제 파드를 삭제하세요."

    monkeypatch.setattr(pipeline, "complete", fake_complete)
    translated = await pipeline._translate_playbook_ko(make_settings(), detail)
    assert "대시보드 GPU 할당 0 표시" in translated
    assert "Delete the offending pod" not in translated
    assert "### Similar Incidents" in translated  # neighbouring sections untouched
    assert "- No similar past incident found." in translated


@pytest.mark.asyncio
async def test_translate_playbook_ko_keeps_detail_without_marker() -> None:
    detail = "## 2. 원인\n\n- 근거"
    assert await pipeline._translate_playbook_ko(make_settings(), detail) == detail


# --- drill-down observability -----------------------------------------------------


@pytest.mark.asyncio
async def test_drilldown_llm_failure_is_visible_in_warnings(monkeypatch) -> None:
    """A dead LLM must not masquerade as a satisfied drill-down agent."""
    from dataclasses import replace

    from app.collectors.base import CollectorResult
    from app.services import drilldown

    async def no_decision(*args, **kwargs):
        return None  # transport/parse failure

    monkeypatch.setattr(drilldown, "complete_json", no_decision)
    settings = replace(
        make_settings(),
        enable_agent_drilldown=True,
        drilldown_max_steps=3,
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    result = CollectorResult(agent="kubernetes", status="ok", summary="pod Pending")
    await drilldown.run_drilldowns(settings, [result], make_target(), None)
    assert any("LLM decision call failed" in w for w in result.warnings)


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
    from app.collectors.kubernetes import _apply_label_selector

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
