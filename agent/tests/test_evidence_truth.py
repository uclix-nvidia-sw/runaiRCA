"""Evidence-truth regressions from the 2026-07-08 KubePodNotReady incident:

An alert on a long-gone runai-container-toolkit pod produced a confident
"runai_control_plane_error (high, 8.0)" headline from ZERO error evidence —
the ranker matched the LogQL probe strings and the healthy control-plane pod
NAME listing; the k8s MCP sweep was silently demoted to the direct API by the
dead pod's 404; and the GPU Operator knowledge stayed unreachable because no
error string existed to signature-match. These tests pin the fixes.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.collectors.base import CollectorResult, artifact
from app.collectors.kubernetes import (
    _collect_kubernetes_responses_via_mcp,
    _k8s_yaml_payload,
    _target_pod_missing,
    k8s_read,
)
from app.knowledge import component_action_lines, component_for_target, load_architecture
from app.services import pipeline
from app.services.planner import plan_investigation
from app.services.root_cause_ranking import rank_root_cause_candidates
from app.schemas import Alert, AlertAnalysisRequest
from tests.test_orchestrator import make_settings, make_target

COMPONENTS = load_architecture("knowledge/runai_architecture.yaml")


def _toolkit_target():
    return replace(
        make_target(),
        namespace="runai",
        project="",
        queue="",
        workload_name="runai-container-toolkit-vttmr",
        pod="runai-container-toolkit-vttmr",
        alert_name="KubePodNotReady",
    )


# --- ranker self-poisoning ----------------------------------------------------


def _empty_run_results() -> list[CollectorResult]:
    """The 2026-07-08 incident's evidence, faithfully: every collector reachable,
    nothing found — but the k8s details carry the healthy control-plane pod
    LISTING and the loki details carry the probe query strings."""
    k8s_details = {
        "queries": [
            {
                "name": "pod",
                "path": "/api/v1/namespaces/runai/pods/runai-container-toolkit-vttmr",
                "url": "https://k8s/api/v1/namespaces/runai/pods/runai-container-toolkit-vttmr",
                "status_code": 404,
                "error": "pods \"runai-container-toolkit-vttmr\" not found",
                "data": None,
            },
            {
                "name": "runai_control_plane_events:runai-backend",
                "path": "/api/v1/namespaces/runai-backend/events",
                "url": "https://k8s/api/v1/namespaces/runai-backend/events",
                "status_code": 200,
                "error": None,
                "data": {"items": []},
            },
        ],
        "runai_control_plane_pods": [
            "runai-backend-7f9c",
            "runai-cluster-sync-abc",
            "runai-scheduler-default-xyz",
        ],
        "pod_statuses": [],
        "warning_events": [],
    }
    loki_details = {
        "queries": [
            {
                "name": "workload_errors",
                "query": (
                    '{namespace="runai"} |~ "(?i)(reconcile error|failed to reconcile|'
                    'cluster-sync|authorization)"'
                ),
                "status_code": 200,
                "line_count": 0,
                "error": None,
            },
            {
                "name": "control_plane",
                "query": '{namespace="runai-backend"} |~ "(?i)(error|panic)"',
                "status_code": 200,
                "line_count": 0,
                "error": None,
            },
        ],
    }
    return [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            confidence="high",
            summary="Kubernetes API queries completed for the resolved alert target.",
            details=k8s_details,
            artifacts=[
                artifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="cluster_api",
                    status="ok",
                    confidence="high",
                    query="/api/v1/namespaces/runai/pods/runai-container-toolkit-vttmr",
                    summary="Kubernetes API queries completed for the resolved alert target.",
                    result=k8s_details,
                )
            ],
        ),
        CollectorResult(
            agent="loki",
            status="partial",
            confidence="medium",
            summary="증거를 찾기 어렵습니다. Loki is reachable, but no lines matched.",
            details=loki_details,
            artifacts=[
                artifact(
                    agent="loki",
                    source="loki",
                    type="logql",
                    status="partial",
                    confidence="medium",
                    query='{namespace="runai-backend"} |~ "(?i)(error|panic|authorization)"',
                    summary="0 matching log line(s)",
                    result=loki_details,
                )
            ],
        ),
    ]


def test_ranker_ignores_probe_text_and_healthy_pod_listings() -> None:
    # Pre-fix this exact evidence scored runai_control_plane_error 8.0/high.
    candidates = rank_root_cause_candidates(_toolkit_target(), _empty_run_results())
    assert candidates
    top = candidates[0]
    assert top.family == "insufficient_evidence", top.as_dict()


def test_observed_text_excludes_probe_query_values() -> None:
    request = AlertAnalysisRequest(
        alert=Alert(
            labels={
                "alertname": "KubePodNotReady",
                "namespace": "runai",
                "pod": "runai-container-toolkit-vttmr",
            },
            annotations={},
        )
    )
    observed = pipeline._observed_text(_empty_run_results(), request)
    # The probe strings must not become matchable "evidence".
    assert "cluster-sync" not in observed
    assert "authorization" not in observed
    assert "runai-backend" not in observed


# --- k8s MCP sweep: per-query errors are observations ---------------------------


class _McpResult:
    def __init__(self, structured=None, text: str = "", is_error: bool = False) -> None:
        self.structuredContent = structured
        self.content = [SimpleNamespace(text=text)] if text else []
        self.isError = is_error


@pytest.mark.asyncio
async def test_mcp_sweep_survives_a_dead_pod_404(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    calls: list[str] = []

    async def fake_mcp_call(url, tool, arguments):
        calls.append(tool)
        if tool == "pods_get" or (tool == "resources_get" and arguments.get("kind") == "Pod"):
            return _McpResult(text='pods "x" not found', is_error=True)
        return _McpResult({"items": []})

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    settings = replace(make_settings(), kubernetes_mcp_url="http://mcp:9903/mcp")
    responses = await _collect_kubernetes_responses_via_mcp(
        settings=settings, target=_toolkit_target(), control_plane_in_scope=True
    )
    by_name = {r["name"]: r for r in responses}
    assert "not found" in str(by_name["pod"]["error"])  # observation, not a raise
    # The rest of the sweep still rode MCP.
    assert by_name["pod_events"]["error"] is None
    assert by_name["runai_control_plane_pods:runai"]["error"] is None


@pytest.mark.asyncio
async def test_mcp_sweep_raises_only_when_everything_fails(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    async def broken_mcp_call(url, tool, arguments):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(k8s, "mcp_call", broken_mcp_call)
    settings = replace(make_settings(), kubernetes_mcp_url="http://mcp:9903/mcp")
    with pytest.raises(RuntimeError):
        await _collect_kubernetes_responses_via_mcp(
            settings=settings, target=_toolkit_target(), control_plane_in_scope=True
        )


def test_k8s_yaml_payload_parses_yaml_and_rejects_tables() -> None:
    # kubernetes-mcp-server speaks YAML (the 2026-07-08 run demoted EVERY query
    # to the direct API with "MCP result was not JSON").
    pod = _k8s_yaml_payload("metadata:\n  name: x\nspec:\n  nodeName: dgx01\n")
    assert isinstance(pod, dict) and pod["spec"]["nodeName"] == "dgx01"
    with pytest.raises(RuntimeError):
        _k8s_yaml_payload("NAME   READY   STATUS\nfoo    1/1     Running")


# The 0.1.42 run's exact corruption: masking TEXT before parsing swallowed the
# newline after "secret:" and produced "secret: [MASKED] 420" — invalid YAML
# ("expected <block end>, but found '<scalar>' ... [MASKED] 420"). Parsing must
# happen on the RAW text; masking applies to the parsed object.
_POD_YAML_WITH_SECRET_VOLUME = (
    "metadata:\n"
    "  name: runai-backend-xyz\n"
    "  annotations:\n"
    "    example.io/auth: Bearer abcdefghijklmnop123456\n"
    "spec:\n"
    "  volumes:\n"
    "  - name: runai-ca\n"
    "    secret:\n"
    "      defaultMode: 420\n"
    "      secretName: runai-ca-cert\n"
    "status:\n"
    "  phase: Running\n"
)


def test_k8s_yaml_payload_survives_secret_shaped_fields_and_masks_values() -> None:
    parsed = _k8s_yaml_payload(_POD_YAML_WITH_SECRET_VOLUME)
    # Structure is intact (text-masking corrupted it into a parse error before).
    assert parsed["spec"]["volumes"][0]["name"] == "runai-ca"
    assert parsed["status"]["phase"] == "Running"
    # Secrets are still masked — on the parsed object, not the serialized text.
    assert "abcdefghijklmnop" not in str(parsed)


@pytest.mark.asyncio
async def test_k8s_read_uses_mcp_yaml_reply_without_fallback(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    async def fake_mcp_call(url, tool, arguments):
        return _McpResult(
            text=(
                "metadata:\n  name: runai-container-toolkit-vttmr\n"
                "spec:\n  nodeName: dgx01\nstatus:\n  phase: Running\n"
            )
        )

    async def direct_should_not_run(**kwargs):
        raise AssertionError("direct API fallback should not run for a YAML MCP reply")

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    monkeypatch.setattr(k8s, "get_json", direct_should_not_run)
    settings = replace(make_settings(), kubernetes_mcp_url="http://mcp:9903/mcp")
    result = await k8s_read(settings, "pods", namespace="runai", name="runai-container-toolkit-vttmr")
    assert result["error"] is None
    assert "#read_pods" in result["url"]
    assert result["data"]["spec"]["nodeName"] == "dgx01"


@pytest.mark.asyncio
async def test_grafana_datasource_uid_rejects_ids_and_names(monkeypatch) -> None:
    # Passing a numeric row id / display name as datasourceUid made grafana-mcp
    # fail every query with 400 "id is invalid" -> whole collector fell back.
    from app.collectors import prometheus as prom

    async def fake_call(url, tool, args_list):
        return [{"type": "prometheus", "name": "Prometheus (default)", "id": 1}]

    monkeypatch.setattr(prom, "_call_mcp_json", fake_call)
    assert await prom._grafana_datasource_uid("http://mcp", "prometheus") == ""

    async def fake_call_uid(url, tool, args_list):
        return [{"type": "prometheus", "name": "Prometheus", "uid": "prom-main_1"}]

    monkeypatch.setattr(prom, "_call_mcp_json", fake_call_uid)
    assert await prom._grafana_datasource_uid("http://mcp", "prometheus") == "prom-main_1"


@pytest.mark.asyncio
async def test_k8s_read_not_found_is_an_answer_not_a_fallback(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    async def fake_mcp_call(url, tool, arguments):
        return _McpResult(text='pods "gone" not found', is_error=True)

    monkeypatch.setattr(k8s, "mcp_call", fake_mcp_call)
    settings = replace(make_settings(), kubernetes_mcp_url="http://mcp:9903/mcp")
    result = await k8s_read(settings, "pods", namespace="runai", name="gone")
    assert result["status_code"] == 404
    assert "#read_pods" in result["url"]  # answered over MCP, no direct retry


# --- honest stale-target reporting ----------------------------------------------


def test_target_pod_missing_detection() -> None:
    target = _toolkit_target()
    gone_direct = [{"name": "pod", "status_code": 404, "error": "not found", "data": None}]
    gone_mcp = [{"name": "pod", "status_code": None, "error": 'pods "x" not found', "data": None}]
    rbac = [{"name": "pod", "status_code": 403, "error": "forbidden", "data": None}]
    assert _target_pod_missing(target, gone_direct) is True
    assert _target_pod_missing(target, gone_mcp) is True
    assert _target_pod_missing(target, rbac) is False
    assert _target_pod_missing(replace(target, pod=""), gone_direct) is False


@pytest.mark.asyncio
async def test_drilldown_summary_never_carries_the_mcp_fallback_note(monkeypatch) -> None:
    # The fallback note used to be prefixed into the artifact SUMMARY, which the
    # ranker/signature matchers read — "no route to host" toward OUR MCP service
    # scored as cluster-network evidence. It now travels under "mcp_fallback"
    # (a non-matchable key) and is surfaced via collector warnings.
    from app.services import drilldown

    async def fake_k8s_read(settings, kind, namespace="", name="", label_selector=""):
        return {
            "kind": "pods",
            "status_code": 200,
            "error": None,
            "data": {"items": []},
            "mcp_fallback": "MCP unavailable; used direct API fallback: no route to host",
        }

    monkeypatch.setattr(drilldown, "k8s_read", fake_k8s_read)
    outcome = await drilldown._tool_k8s_read(make_settings(), make_target(), {"kind": "pods"})
    assert "no route to host" not in str(outcome.get("summary"))
    assert "no route to host" in str(outcome.get("mcp_fallback"))


# --- unified family universe -----------------------------------------------------


def test_ranker_can_nominate_ontology_families_directly() -> None:
    # The ranked universe used to stop at 7 coarse families; GPU/fabric/storage/
    # runtime/observability/auth knowledge existed in the ontology but could
    # never appear as a ranked category without a signature promotion.
    results = [
        CollectorResult(
            agent="system",
            status="ok",
            confidence="high",
            summary=(
                "Node dgx01: 3 kernel/hardware error line(s) found in dmesg: "
                "NVRM: Xid (PCI:0000:3b:00): 79, GPU has fallen off the bus"
            ),
            details={},
        ),
        CollectorResult(
            agent="loki",
            status="ok",
            confidence="medium",
            summary="matched log line: XidCriticalError reported by device plugin",
            details={},
        ),
    ]
    candidates = rank_root_cause_candidates(_toolkit_target(), results)
    assert candidates[0].family == "gpu_hardware_error", [c.as_dict() for c in candidates]


def test_ranker_ignores_own_transport_errors() -> None:
    # "no route to host" toward OUR MCP service is a probe failure, not
    # cluster-network evidence.
    results = [
        CollectorResult(
            agent="kubernetes",
            status="ok",
            confidence="high",
            summary="Kubernetes API queries completed for the resolved alert target.",
            details={
                "queries": [
                    {
                        "name": "pod",
                        "error": "MCP fallback: no route to host; coredns lookup failed",
                        "data": None,
                    }
                ],
                "mcp_fallback": "MCP unavailable; used direct API fallback: no route to host",
            },
        ),
    ]
    candidates = rank_root_cause_candidates(_toolkit_target(), results)
    assert candidates[0].family == "insufficient_evidence", [c.as_dict() for c in candidates]


# --- Run:ai CRD reads (kubectl parity) --------------------------------------------


def test_runai_crd_kinds_are_readable_aliases() -> None:
    from app.collectors.kubernetes import resolve_read_kind

    assert resolve_read_kind("project") == "projects"
    assert resolve_read_kind("queues") == "queues"
    assert resolve_read_kind("podgroup") == "podgroups"
    assert resolve_read_kind("trainingworkload") == "trainingworkloads"
    assert resolve_read_kind("runaiconfig") == "runaiconfigs"


@pytest.mark.asyncio
async def test_k8s_read_discovers_runai_crd_group_version(monkeypatch, tmp_path) -> None:
    from app.collectors import kubernetes as k8s

    token = tmp_path / "token"
    token.write_text("t")
    calls: list[str] = []

    async def fake_get_json(*, base_url, path, timeout_seconds, params=None, headers=None, verify=True):
        calls.append(path)
        if path == "/apis/run.ai":
            return SimpleNamespace(
                ok=True,
                url=path,
                status_code=200,
                error=None,
                data={"preferredVersion": {"groupVersion": "run.ai/v2"}},
            )
        return SimpleNamespace(
            ok=True,
            url=path,
            status_code=200,
            error=None,
            data={"kind": "Project", "metadata": {"name": "test-pro"}},
        )

    monkeypatch.setattr(k8s, "get_json", fake_get_json)
    monkeypatch.setattr(k8s, "_API_GROUP_PREFIX_CACHE", {})
    settings = replace(
        make_settings(), kubernetes_mcp_url="", kubernetes_token_path=str(token)
    )
    result = await k8s.k8s_read(settings, "project", name="test-pro")
    assert result["error"] is None
    assert "/apis/run.ai" in calls[0]
    # Cluster-scoped CRD: no /namespaces/ segment, discovered version used.
    assert calls[1] == "/apis/run.ai/v2/projects/test-pro"


def test_mcp_api_kind_candidates_prefer_discovered_version(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    monkeypatch.setattr(
        k8s, "_API_GROUP_PREFIX_CACHE", {"scheduling.run.ai": "/apis/scheduling.run.ai/v2"}
    )
    pairs = k8s._k8s_mcp_api_kinds("podgroups")
    assert pairs[0] == ("scheduling.run.ai/v2", "PodGroup")
    assert all(kind == "PodGroup" for _, kind in pairs)


@pytest.mark.asyncio
async def test_runai_mcp_projects_falls_back_to_org_unit_path() -> None:
    from app.collectors.runai_mcp import _call_api

    class FakeSession:
        def __init__(self) -> None:
            self.paths: list[str] = []

        async def call_tool(self, tool, args):
            self.paths.append(args["path"])
            if args["path"] == "/api/v1/projects":
                return _McpResult(text="404 page not found", is_error=True)
            return _McpResult({"projects": [{"name": "test-pro"}]})

    session = FakeSession()
    item = await _call_api(
        session, "projects", "GET", ["/api/v1/projects", "/api/v1/org-unit/projects"], None
    )
    assert session.paths == ["/api/v1/projects", "/api/v1/org-unit/projects"]
    assert item["error"] is None
    assert "/api/v1/org-unit/projects" in item["query"]


# --- component identity entry point ---------------------------------------------


def test_component_for_target_matches_pod_names() -> None:
    toolkit = component_for_target(COMPONENTS, "runai-container-toolkit-vttmr")
    assert toolkit is not None and toolkit["component"] == "runai-container-toolkit"
    assert toolkit["family"] == "gpu_hardware_error"

    sync = component_for_target(COMPONENTS, "runai-cluster-sync-8b6d9", "")
    assert sync is not None and sync["component"] == "cluster-sync"

    # Longest name wins over a shorter prefix component.
    workloads = component_for_target(COMPONENTS, "runai-backend-workloads-7f9c4b")
    assert workloads is not None and workloads["component"] == "runai-backend-workloads"

    assert component_for_target(COMPONENTS, "totally-unrelated-pod-abc12") is None


def test_component_action_lines_walk_into_gpu_operator_stack() -> None:
    lines = component_action_lines(COMPONENTS, "runai-container-toolkit")
    text = " ".join(lines)
    assert "nvidia-container-toolkit-daemonset" in text  # depends_on chain surfaced
    assert "gpu-operator" in text  # the owner's "look at the GPU Operator" rule


@pytest.mark.asyncio
async def test_planner_leads_with_the_component_family() -> None:
    plan = await plan_investigation(
        make_settings(), _toolkit_target(), None, kg_context=None, similar_incidents=None
    )
    assert plan.component == "runai-container-toolkit"
    assert plan.hypotheses[0]["family"] == "gpu_hardware_error"
    assert "runai-container-toolkit" in plan.hypotheses[0]["reason"]


@pytest.mark.asyncio
async def test_component_identity_outranks_the_alert_catalog_family() -> None:
    # "Run:ai DaemonSet Rollout Stuck" is a documented catalog alert carrying
    # family runai_control_plane_error — but when the stuck daemonset IS the
    # container toolkit, WHO the alert is about is the more specific signal and
    # must keep the lead (the catalog definition stays on the plan for actions).
    target = replace(
        _toolkit_target(),
        alert_name="RunaiDaemonSetRolloutStuck",
    )
    plan = await plan_investigation(
        make_settings(), target, None, kg_context=None, similar_incidents=None
    )
    assert plan.matched_alert is not None  # the catalog entry was recognised
    assert plan.component == "runai-container-toolkit"
    assert plan.hypotheses[0]["family"] == "gpu_hardware_error"
    families = [h["family"] for h in plan.hypotheses]
    assert "runai_control_plane_error" in families  # catalog family still ranked


def test_numbered_actions_lead_with_component_checks() -> None:
    from app.plan import InvestigationPlan

    plan = InvestigationPlan(component="runai-container-toolkit")
    request = AlertAnalysisRequest(
        alert=Alert(labels={"alertname": "KubePodNotReady"}, annotations={})
    )
    numbered = pipeline._numbered_actions(
        plan,
        None,
        [],
        "",
        {},
        [],
        request,
        [],
        components=COMPONENTS,
    )
    assert numbered, "component checks should produce actions"
    assert "gpu-operator" in " ".join(numbered)
