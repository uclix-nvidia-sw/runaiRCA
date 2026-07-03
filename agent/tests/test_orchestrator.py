from __future__ import annotations

import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.collectors.base import AnalysisTarget, resolve_target
from app.collectors.loki import LokiCollector, _loki_headers
from app.collectors.runai import RunAICollector, _runai_headers
from app.config import Settings
from app.masking import build_masker
from app.schemas import (
    Alert,
    AlertAnalysisRequest,
    ChatRequest,
    FeedbackHintContext,
    SimilarIncidentContext,
)
from app.services.orchestrator import AnalysisOrchestrator, NemoWorkflowRunner, _extract_nat_result


def make_settings() -> Settings:
    return Settings(
        port=8000,
        log_level="info",
        language="en",
        kubernetes_api_url="https://kubernetes.default.svc",
        kubernetes_token_path="/var/run/secrets/kubernetes.io/serviceaccount/token",
        kubernetes_ca_path="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        kubernetes_timeout_seconds=1,
        kubernetes_list_limit=10,
        kubernetes_namespaces=(),
        kubernetes_cluster_scope_enabled=True,
        runai_base_url="",
        runai_bearer_token="",
        runai_client_id="",
        runai_client_secret="",
        runai_token_url="",
        runai_workloads_path="/api/v1/workloads",
        runai_projects_path="/api/v1/projects",
        runai_queues_path="/api/v1/queues",
        runai_version_path="/api/v1/version",
        runai_timeout_seconds=1,
        prometheus_url="",
        prometheus_timeout_seconds=1,
        prometheus_mcp_url="",
        loki_url="",
        loki_bearer_token="",
        loki_basic_username="",
        loki_basic_password="",
        loki_tenant_id="",
        loki_timeout_seconds=1,
        loki_query_limit=10,
        loki_mcp_url="",
        runai_log_namespaces=("runai", "runai-backend"),
        postgres_dsn="",
        postgres_timeout_seconds=1,
        troubleshooting_cases_file="knowledge/troubleshooting_cases.md",
        failure_modes_file="knowledge/failure_modes.yaml",
        runai_alerts_file="knowledge/runai_alerts_catalog.yaml",
        runai_known_issues_file="knowledge/runai_known_issues.yaml",
        enable_system_agent=False,
        system_agent_url="",
        system_agent_token="",
        system_agent_timeout_seconds=6,
        enable_pod_exec=False,
        pod_exec_timeout_seconds=10,
        agent_souls_file="prompts/agent_souls.md",
        masking_regex_list=(),
        builtin_redaction_enabled=True,
        builtin_redaction_hash_mode=False,
        llm_base_url="",
        llm_model="",
        llm_api_key="",
        llm_request_timeout_seconds=120,
        nat_config_file="configs/runai_rca_workflow.yml",
        enable_nat_runtime=False,
        nat_timeout_seconds=1,
        typedb_address="",
        typedb_database="runai_rca",
        typedb_username="admin",
        typedb_password="password",
        typedb_tls_enabled=False,
        typedb_timeout_seconds=1,
        enable_typedb=False,
        enable_investigation_loop=False,
        max_investigation_steps=4,
        max_reanalysis_steps=2,
        analysis_deadline_seconds=300,
    )


def make_target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="vision",
        queue="gpu-a",
        namespace="runai-vision",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="trainer-0",
        severity="warning",
        alert_name="RunAIWorkloadPending",
    )


def test_resolve_target_derives_project_from_runai_namespace() -> None:
    target = resolve_target(
        {"namespace": "runai-vision", "pod": "trainer-0"},
        {},
    )

    assert target.project == "vision"
    assert target.namespace == "runai-vision"


def test_loki_headers_prefer_bearer_and_include_tenant() -> None:
    settings = replace(
        make_settings(),
        loki_bearer_token="loki-token",
        loki_basic_username="basic-user",
        loki_basic_password="basic-password",
        loki_tenant_id="tenant-a",
    )

    headers, warnings = _loki_headers(settings)

    assert headers["Authorization"] == "Bearer loki-token"
    assert headers["X-Scope-OrgID"] == "tenant-a"
    assert warnings == []


def test_loki_headers_support_basic_auth() -> None:
    settings = replace(
        make_settings(),
        loki_basic_username="basic-user",
        loki_basic_password="basic-password",
    )

    headers, warnings = _loki_headers(settings)

    assert headers["Authorization"].startswith("Basic ")
    assert warnings == []


@pytest.mark.asyncio
async def test_loki_401_marks_auth_missing(monkeypatch) -> None:
    async def fake_get_json(**kwargs) -> SimpleNamespace:
        return SimpleNamespace(
            url=f"{kwargs['base_url']}{kwargs['path']}",
            status_code=401,
            error="HTTP 401",
            data={"body": "unauthorized"},
        )

    monkeypatch.setattr("app.collectors.loki.get_json", fake_get_json)
    collector = LokiCollector(replace(make_settings(), loki_url="http://loki.example"))

    result = await collector.collect(make_target())

    assert result.status == "unavailable"
    assert "loki.auth" in result.missing_data
    assert any("HTTP 401" in warning for warning in result.warnings)
    assert any("Evicted" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_loki_401_from_gateway_points_to_direct_read_service(monkeypatch) -> None:
    async def fake_get_json(**kwargs) -> SimpleNamespace:
        return SimpleNamespace(
            url=f"{kwargs['base_url']}{kwargs['path']}",
            status_code=401,
            error="HTTP 401",
            data={"body": "unauthorized"},
        )

    monkeypatch.setattr("app.collectors.loki.get_json", fake_get_json)
    collector = LokiCollector(replace(make_settings(), loki_url="http://loki-gateway.monitoring.svc"))

    result = await collector.collect(make_target())

    assert "loki.auth" in result.missing_data
    assert any("gateway Basic Auth" in warning for warning in result.warnings)
    assert any("direct loki-read service" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_runai_headers_warn_when_auth_header_is_missing() -> None:
    headers, warnings = await _runai_headers(
        replace(make_settings(), runai_base_url="https://runai.example")
    )

    assert "Authorization" not in headers
    assert any("no Authorization header" in warning for warning in warnings)


@pytest.mark.asyncio
async def test_runai_token_uses_json_client_credentials(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        captured["url"] = url
        captured["json_body"] = json_body
        return SimpleNamespace(ok=True, error=None, data={"accessToken": "tok-123"})

    monkeypatch.setattr("app.collectors.runai.post_json", fake_post_json)
    settings = replace(
        make_settings(),
        runai_base_url="https://runai.example",
        runai_token_url="https://runai.example/api/v1/token",
        runai_client_id="cid",
        runai_client_secret="secret",
    )
    headers, warnings = await _runai_headers(settings)

    assert headers["Authorization"] == "Bearer tok-123"
    assert captured["json_body"] == {
        "grantType": "client_credentials",
        "clientId": "cid",
        "clientSecret": "secret",
    }
    assert warnings == []


@pytest.mark.asyncio
async def test_runai_token_falls_back_to_form_candidate_url(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        calls.append(("json", url))
        return SimpleNamespace(ok=False, error="HTTP 404", data={"body": "not found"})

    async def fake_post_form_json(*, url, timeout_seconds, data, headers=None, verify=True):
        calls.append(("form", url))
        if url.endswith("/auth/realms/runai/protocol/openid-connect/token"):
            return SimpleNamespace(ok=True, error=None, data={"access_token": "form-token"})
        return SimpleNamespace(ok=False, error="HTTP 404", data={"body": "not found"})

    monkeypatch.setattr("app.collectors.runai.post_json", fake_post_json)
    monkeypatch.setattr("app.collectors.runai.post_form_json", fake_post_form_json)
    settings = replace(
        make_settings(),
        runai_base_url="https://runai.example",
        runai_token_url="https://runai.example/wrong-token-url",
        runai_client_id="cid",
        runai_client_secret="secret",
    )

    headers, warnings = await _runai_headers(settings)

    assert headers["Authorization"] == "Bearer form-token"
    assert warnings == []
    assert (
        "form",
        "https://runai.example/auth/realms/runai/protocol/openid-connect/token",
    ) in calls


@pytest.mark.asyncio
async def test_runai_collector_skips_queries_without_auth(monkeypatch) -> None:
    async def fake_get_json(**kwargs) -> SimpleNamespace:
        raise AssertionError("Run:ai API should not be queried without Authorization")

    monkeypatch.setattr("app.collectors.runai.get_json", fake_get_json)
    collector = RunAICollector(replace(make_settings(), runai_base_url="https://runai.example"))

    result = await collector.collect(make_target())

    assert result.status == "unavailable"
    assert "runai.auth" in result.missing_data
    assert result.details["queries"] == []


@pytest.mark.asyncio
async def test_analyze_returns_unified_artifacts() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={
                    "alertname": "RunAIWorkloadPending",
                    "severity": "warning",
                    "namespace": "runai-vision",
                    "project": "vision",
                    "queue": "gpu-a",
                    "workload": "trainer",
                },
                annotations={"summary": "Workload has been pending for too long."},
                fingerprint="fp-1",
            )
        )
    )

    assert response.status == "ok"
    assert response.analysis_summary
    assert "analysis completed" not in response.analysis_summary
    assert response.context["agent_souls_applied"] is True
    assert "Agent Role Coverage" not in response.analysis_detail  # static boilerplate removed
    assert "requires operator review" not in response.analysis_detail
    assert "Inspect Loki logs" not in response.analysis_detail
    assert {artifact.agent for artifact in response.artifacts} == {
        "runai",
        "kubernetes",
        "postgres",
        "prometheus",
        "loki",
        "system",
        "change",
    }
    assert response.capabilities["runai"] in {"partial", "ok"}
    # Self-check must never leave a dangling empty section: if the header is
    # present, a non-empty caveat body must follow it.
    detail = response.analysis_detail
    if "## Self-Check" in detail:
        body = detail.split("## Self-Check", 1)[1]
        assert body.strip(), "empty ## Self-Check section appended"
    # The report must read as a document: Problem -> Root Cause -> Recommended
    # Actions -> Appendix, in that order (Word-export skeleton).
    order = [
        detail.find("# Incident Analysis Report"),
        detail.find("## 1. Problem"),
        detail.find("## 2. Root Cause"),
        detail.find("## 3. Recommended Actions"),
        detail.find("## 4. Appendix"),
    ]
    assert all(idx >= 0 for idx in order), f"missing report section: {order}"
    assert order == sorted(order), f"report sections out of order: {order}"


@pytest.mark.asyncio
async def test_analyze_includes_similar_incidents_and_feedback_hints() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIWorkloadPending", "namespace": "runai-vision"},
                annotations={"summary": "Pending workload is waiting for GPU quota."},
                fingerprint="fp-memory",
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-000001",
                    title="Prior queue saturation",
                    similarity=0.91,
                    analysis_summary="Queue gpu-a was saturated.",
                    positive_feedback=2,
                    comment_count=1,
                )
            ],
            feedback_hints=[
                FeedbackHintContext(
                    source_id="INC-000001",
                    sentiment="comment",
                    weight=0.91,
                    text="Operators confirmed quota saturation was the real cause.",
                )
            ],
        )
    )

    assert response.context["similar_incidents"][0]["incident_id"] == "INC-000001"
    assert response.context["feedback_hints"][0]["source_id"] == "INC-000001"
    assert "## Similar Incidents" in response.analysis_detail
    assert "Operators confirmed quota saturation" in response.analysis_detail


@pytest.mark.asyncio
async def test_analyze_includes_investigation_plan_section() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NodeDiskPressure", "namespace": "monitoring"},
                annotations={"summary": "Node under disk pressure."},
                fingerprint="fp-plan",
            )
        )
    )

    assert "## Investigation Plan" in response.analysis_detail
    plan = response.context["plan"]
    # non-runai namespace, no keywords, no match -> control plane out of scope
    assert plan["check_control_plane"] is False
    assert plan["strategy"] == "breadth_first"


@pytest.mark.asyncio
async def test_analyze_excludes_low_similarity_incidents() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "NodeDiskPressure", "namespace": "monitoring"},
                annotations={"summary": "Node under disk pressure."},
                fingerprint="fp-lowsim",
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-LOW",
                    title="Weak match",
                    similarity=0.70,
                    analysis_summary="Not really related.",
                )
            ],
        )
    )

    assert "No similar past incident found." in response.analysis_detail
    assert "INC-LOW" not in response.analysis_detail


@pytest.mark.asyncio
async def test_analyze_weaves_similar_incident_fix_into_actions() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIWorkloadPending", "namespace": "runai-vision"},
                annotations={"summary": "Pending workload waiting for GPU quota."},
                fingerprint="fp-weave",
            ),
            similar_incidents=[
                SimilarIncidentContext(
                    incident_id="INC-HIGH",
                    title="Prior quota saturation",
                    similarity=0.88,
                    analysis_summary="Raised queue gpu-a quota to clear the backlog.",
                )
            ],
        )
    )

    recommended = response.analysis_detail.split("## 3. Recommended Actions", 1)[1]
    actions_block = recommended.split("##", 1)[0]
    assert "INC-HIGH" in actions_block
    assert "Raised queue gpu-a quota" in actions_block


@pytest.mark.asyncio
async def test_analyze_lists_grouped_pods() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "KubePodCrashLooping", "namespace": "monitoring"},
                annotations={"summary": "Loki read pod is crash looping."},
                fingerprint="fp-flap",
            ),
            occurrence_count=4,
            occurrence_pods=[
                "loki-read-7d9f8c6b5-x2k4p",
                "loki-read-7d9f8c6b5-a1b2c",
            ],
        )
    )

    assert "## Affected Pods" in response.analysis_detail
    assert "loki-read-7d9f8c6b5-x2k4p" in response.analysis_detail
    assert "grouped from 4 occurrence" in response.analysis_detail
    assert response.context["occurrence_count"] == 4
    assert "loki-read-7d9f8c6b5-a1b2c" in response.context["occurrence_pods"]


@pytest.mark.asyncio
async def test_analyze_isolates_collector_exceptions() -> None:
    class ExplodingCollector:
        async def collect(self, target, plan=None):
            raise RuntimeError("collector boom")

    orchestrator = AnalysisOrchestrator(make_settings())
    orchestrator._collectors = [ExplodingCollector()]

    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAICollectorCrash", "namespace": "runai"},
                annotations={"summary": "Collector crashed during RCA."},
                fingerprint="fp-collector-crash",
            )
        )
    )

    assert response.status == "ok"
    assert response.analysis_quality == "low"
    assert response.capabilities["exploding"] == "unavailable"
    assert "exploding.collector_exception" in response.missing_data
    assert any("collector boom" in warning for warning in response.warnings)
    assert "**exploding**:" in response.analysis_detail


@pytest.mark.asyncio
async def test_analyze_falls_back_when_nat_runtime_raises(monkeypatch) -> None:
    settings = replace(make_settings(), enable_nat_runtime=True)
    orchestrator = AnalysisOrchestrator(settings)

    async def broken_nat_run(payload):
        raise RuntimeError("nat executable missing")

    monkeypatch.setattr(orchestrator._nat, "run", broken_nat_run)

    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAINatFailure", "namespace": "runai"},
                annotations={"summary": "NAT failed but fallback should continue."},
                fingerprint="fp-nat-failure",
            )
        )
    )

    assert response.status == "ok"
    assert "NAT failed but fallback should continue" in response.analysis_detail
    assert any("nemo failed unexpectedly" in warning for warning in response.warnings)


@pytest.mark.asyncio
async def test_chat_without_detail_reports_runtime_state() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.chat(
        ChatRequest(
            message="야 알람 왔잖아",
            page="evidence_dashboard",
            context={
                "dashboard_state": {
                    "alert_count": 1,
                    "firing_alert_count": 1,
                    "analysis_run_count": 1,
                    "analysis_statuses": {"failed": 1},
                    "latest_alert": {
                        "alert_id": "ALR-000001",
                        "status": "firing",
                        "severity": "warning",
                        "title": "RunAIWorkloadPending",
                    },
                    "latest_run": {
                        "run_id": "ANL-000001",
                        "status": "failed",
                        "target_type": "alert",
                        "target_id": "ALR-000001",
                        "capabilities": {"agent": "timeout"},
                        "warnings": ["agent request timed out"],
                        "missing_data": ["agent.response"],
                    },
                },
                "agent_runtime": {
                    "agent_request_timeout_seconds": 180,
                    "chat_mode": "deterministic_context",
                    "database": {
                        "postgres": True,
                        "pgvector_status": "enabled",
                        "similarity_search": "pgvector_cosine",
                    },
                },
            },
        )
    )

    assert "## Current Agent State" in response.answer
    assert "ALR-000001" in response.answer
    assert "ANL-000001 is failed" in response.answer
    assert "timeout" in response.answer
    assert "No specific incident or alert RCA content is attached yet" not in response.answer


@pytest.mark.anyio
async def test_chat_uses_llm_when_configured(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example.com/v1",
        llm_model="rca-router",
        llm_api_key="secret",
    )
    captured: dict[str, object] = {}

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        captured["url"] = url
        captured["json_body"] = json_body
        return SimpleNamespace(
            ok=True,
            data={
                "choices": [
                    {"message": {"content": "Live LLM reply about the pending workload."}}
                ]
            },
        )

    monkeypatch.setattr("app.services.orchestrator.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.chat(
        ChatRequest(message="왜 워크로드가 멈췄어?", page="operations")
    )

    assert response.answer == "Live LLM reply about the pending workload."
    assert captured["url"] == "https://llm.example.com/v1/chat/completions"
    assert captured["json_body"]["model"] == "rca-router"


@pytest.mark.anyio
async def test_chat_falls_back_when_llm_unavailable(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example.com/v1",
        llm_model="rca-router",
        llm_api_key="secret",
    )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        return SimpleNamespace(ok=False, data=None)

    monkeypatch.setattr("app.services.orchestrator.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.chat(ChatRequest(message="status?", page="operations"))

    assert "## RCA Chat" in response.answer


@pytest.mark.anyio
async def test_chat_falls_back_when_llm_call_raises(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example.com/v1",
        llm_model="rca-router",
        llm_api_key="secret",
    )

    async def fake_post_json(*, url, timeout_seconds, json_body, headers=None, verify=True):
        raise RuntimeError("LLM transport exploded")

    monkeypatch.setattr("app.services.orchestrator.post_json", fake_post_json)
    orchestrator = AnalysisOrchestrator(settings)
    response = await orchestrator.chat(ChatRequest(message="status?", page="operations"))

    assert response.status == "ok"
    assert "## RCA Chat" in response.answer
    assert "## Warnings" in response.answer
    assert "llm failed unexpectedly" in response.answer
    assert "LLM transport exploded" in response.answer


def test_extract_nat_result_strips_console_wrapper() -> None:
    output = (
        "\x1b[32mWorkflow Result:\n## Root Cause\n\nBody\n"
        "--------------------------------------------------\x1b[39m"
    )

    assert _extract_nat_result(output) == "## Root Cause\n\nBody"


def test_nat_runner_can_materialize_remote_mcp_urls(tmp_path: Path) -> None:
    config = tmp_path / "workflow.yml"
    config.write_text(
        """
function_groups:
  prometheus_mcp:
    server:
      url: http://localhost:9901/mcp
  loki_mcp:
    server:
      url: http://localhost:9902/mcp
""".strip(),
        encoding="utf-8",
    )
    settings = replace(
        make_settings(),
        nat_config_file=str(config),
        prometheus_mcp_url="https://prometheus-mcp.example.com/mcp",
        loki_mcp_url="https://loki-mcp.example.com/mcp",
    )

    rendered = Path(NemoWorkflowRunner(settings)._materialize_config_file()).read_text(
        encoding="utf-8"
    )

    assert "https://prometheus-mcp.example.com/mcp" in rendered
    assert "https://loki-mcp.example.com/mcp" in rendered
    assert "localhost:9901" not in rendered
    assert "localhost:9902" not in rendered


def test_nat_runner_materializes_litellm_placeholders(tmp_path: Path) -> None:
    config = tmp_path / "workflow_litellm.yml"
    config.write_text(
        """
llms:
  litellm_llm:
    _type: litellm
    model_name: __RUNAI_RCA_LLM_MODEL__
    base_url: __RUNAI_RCA_LLM_BASE_URL__
    api_key: __RUNAI_RCA_LLM_API_KEY__
    request_timeout: __RUNAI_RCA_LLM_REQUEST_TIMEOUT_SECONDS__
""".strip(),
        encoding="utf-8",
    )
    settings = replace(
        make_settings(),
        nat_config_file=str(config),
        llm_base_url="https://litellm.example.com/v1",
        llm_model="auto-router",
        llm_api_key="test-secret",
        llm_request_timeout_seconds=45,
    )

    rendered_path = Path(NemoWorkflowRunner(settings)._materialize_config_file())
    rendered = rendered_path.read_text(encoding="utf-8")

    assert "https://litellm.example.com/v1" in rendered
    assert "auto-router" in rendered
    assert "test-secret" in rendered
    assert "request_timeout: 45" in rendered
    assert "__RUNAI_RCA_LLM" not in rendered
    assert stat.S_IMODE(rendered_path.stat().st_mode) == 0o600

    NemoWorkflowRunner(settings)._cleanup_materialized_config(str(rendered_path))

    assert not rendered_path.exists()


def test_nat_runner_skips_partial_litellm_materialization(tmp_path: Path) -> None:
    config = tmp_path / "workflow_litellm.yml"
    config.write_text(
        """
llms:
  litellm_llm:
    _type: litellm
    model_name: __RUNAI_RCA_LLM_MODEL__
    base_url: __RUNAI_RCA_LLM_BASE_URL__
    api_key: __RUNAI_RCA_LLM_API_KEY__
    request_timeout: __RUNAI_RCA_LLM_REQUEST_TIMEOUT_SECONDS__
""".strip(),
        encoding="utf-8",
    )
    settings = replace(
        make_settings(),
        nat_config_file=str(config),
        llm_api_key="test-secret",
        llm_request_timeout_seconds=45,
    )

    assert NemoWorkflowRunner(settings)._materialize_config_file() == str(config)


def test_masker_redacts_sensitive_object_values() -> None:
    masker = build_masker((r"internal-user-[0-9]+",))
    secret_blob = (
        "c2Vuc2l0aXZlLXNlY3JldC12YWx1ZS1mb3ItcmVkYWN0aW9uLXRlc3QtcGF5bG9hZA=="
    )
    payload = {
        "password": "plain-secret",
        "token_path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "message": (
            "Authorization: Bearer abcdefghijklmnop "
            "postgresql://user:dbpassword@postgres/runai "
            "owner=internal-user-42 "
            f"blob={secret_blob}"
        ),
        "env": [{"name": "RUNAI_TOKEN", "value": "runtime-secret"}],
    }

    masked = masker.mask_object(payload)

    assert masked["password"] == "[MASKED]"
    assert masked["token_path"] == "/var/run/secrets/kubernetes.io/serviceaccount/token"
    assert "abcdefghijklmnop" not in masked["message"]
    assert "dbpassword" not in masked["message"]
    assert "internal-user-42" not in masked["message"]
    assert secret_blob not in masked["message"]
    assert masked["env"][0]["value"] == "[MASKED]"


@pytest.mark.asyncio
async def test_analyze_masks_sensitive_alert_text() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAISecretLeak", "namespace": "runai"},
                annotations={
                    "summary": (
                        "Failure included Authorization: Bearer abcdefghijklmnop "
                        "and password=do-not-show"
                    )
                },
                fingerprint="fp-secret",
            )
        )
    )

    serialized = response.model_dump_json()
    assert "abcdefghijklmnop" not in serialized
    assert "do-not-show" not in serialized
    assert "[MASKED]" in serialized


@pytest.mark.asyncio
async def test_chat_agent_answers_from_attached_rca_memory() -> None:
    orchestrator = AnalysisOrchestrator(make_settings())
    response = await orchestrator.chat(
        ChatRequest(
            message="이전 유사 RCA랑 비교해서 왜 GPU가 pending인지 알려줘",
            page="incident_detail",
            incident_id="INC-000001",
            incident_title="Queue blocked while waiting for GPUs",
            incident_content=(
                "Root Cause: Run:AI queue gpu-a has no available GPU quota. "
                "Recommended Actions: increase queue quota or move workload."
            ),
            context={
                "rca_memory": [
                    {
                        "incident_id": "INC-000000",
                        "similarity": 0.92,
                        "analysis_summary": "Prior gpu-a quota saturation blocked trainer.",
                    }
                ],
                "missing_data": ["prometheus.workload_metrics"],
            },
        )
    )

    assert response.status == "ok"
    assert "Related RCA Memory" in response.answer
    assert "INC-000000" in response.answer
    assert "gpu-a has no available GPU quota" in response.answer


def test_pod_describe_line_carries_limits_restarts_oomkilled() -> None:
    # "phase Running" alone tells the operator nothing on a memory-limit alert:
    # the describe-grade line must carry the limit, restarts, and last OOMKilled.
    from app.services.orchestrator import _pod_describe_line

    pod = {
        "name": "workloads-manager-x",
        "phase": "Running",
        "resources": {
            "workloads-manager": {
                "limits": {"memory": "10Gi", "cpu": "2"},
                "requests": {"memory": "8Gi"},
            }
        },
        "containerStatuses": [
            {
                "name": "workloads-manager",
                "restartCount": 3,
                "state": {"running": {"startedAt": "2026-07-03T00:00:00Z"}},
                "lastState": {
                    "terminated": {
                        "reason": "OOMKilled",
                        "exitCode": 137,
                        "finishedAt": "2026-07-02T23:59:00Z",
                    }
                },
            }
        ],
    }
    line = _pod_describe_line(pod)
    assert "mem limit 10Gi (request 8Gi)" in line
    assert "3 restart(s)" in line
    assert "last OOMKilled (exit 137)" in line
    # and the OOMKilled token feeds signature matching downstream
    assert "oomkilled" in line.lower()
    # a bare healthy pod stays a simple phase line
    assert _pod_describe_line({"name": "p", "phase": "Running"}) == (
        "- Kubernetes pod p is in phase Running."
    )


@pytest.mark.asyncio
async def test_loki_correlates_control_plane_logs_to_dying_workload(monkeypatch) -> None:
    # When a workload alert implicates the control plane, Loki must also query the
    # runai/runai-backend namespaces for lines that NAME this workload — that's where
    # "scheduler evicted/preempted workload X" lives, beyond the error-pattern query.
    from types import SimpleNamespace

    seen_queries: list[str] = []

    async def fake_get_json(**kwargs) -> SimpleNamespace:
        seen_queries.append(kwargs["params"]["query"])
        return SimpleNamespace(
            url="http://loki/x", status_code=200, error=None,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr("app.collectors.loki.get_json", fake_get_json)
    collector = LokiCollector(replace(make_settings(), loki_url="http://loki.example"))
    plan = SimpleNamespace(
        namespaces=["runai-vision"], pod="", workload="trainer", check_control_plane=True
    )
    await collector.collect(make_target(), plan)

    joined = "\n".join(seen_queries)
    # the control-plane namespaces are queried for the workload identifier
    assert any("trainer" in q and "runai" in q for q in seen_queries), joined
    # and the generic control-plane-error sweep still runs
    assert any("reconcile" in q for q in seen_queries), joined


def test_correlation_term_skips_too_short_identifiers() -> None:
    from app.collectors.base import AnalysisTarget
    from app.collectors.loki import _control_plane_correlation_term

    def tgt(**k):
        base = dict(cluster="", project="", queue="", namespace="", workload_name="",
                    workload_type="", runai_workload_id="", node="", pod="",
                    severity="warning", alert_name="A")
        base.update(k)
        return AnalysisTarget(**base)

    assert _control_plane_correlation_term(tgt(workload_name="trainer")) == "trainer"
    # regex metachars are escaped so the identifier can't break the LogQL query
    assert _control_plane_correlation_term(tgt(workload_name="job.v2")) == r"job\.v2"
    # too short → skipped (would match unrelated lines)
    assert _control_plane_correlation_term(tgt(workload_name="a", project="x")) == ""


def test_prometheus_widens_to_control_plane_health_when_implicated() -> None:
    # When a workload alert implicates the control plane, Prometheus must also probe
    # whether the scheduler/backend pods are crashlooping / stuck Pending — that's a
    # common real cause of a dead workload.
    from types import SimpleNamespace

    from app.collectors.prometheus import _queries_for

    plan = SimpleNamespace(namespaces=["runai-vision"], pod="trainer-0", check_control_plane=True)
    names = dict(_queries_for(make_target(), plan, ("runai", "runai-backend")))
    assert "runai_control_plane_restarts" in names
    assert "runai_control_plane_pending" in names
    q = names["runai_control_plane_restarts"]
    assert "namespace=~" in q and "runai" in q and "backend" in q

    # Not implicated → no control-plane widening (empty namespaces).
    names2 = dict(_queries_for(make_target(), plan, ()))
    assert not any(k.startswith("runai_control_plane_") for k in names2)


@pytest.mark.asyncio
async def test_loki_skips_empty_selector_no_400(monkeypatch) -> None:
    # Loki rejects `{}`; when the target has no namespace/pod/workload the collector
    # must NOT issue an empty-selector query, and must say why.
    from types import SimpleNamespace

    issued: list[str] = []

    async def fake_get_json(**kwargs) -> SimpleNamespace:
        issued.append(kwargs["params"]["query"])
        return SimpleNamespace(
            url="http://loki/x", status_code=200, error=None,
            data={"status": "success", "data": {"result": []}},
        )

    monkeypatch.setattr("app.collectors.loki.get_json", fake_get_json)
    collector = LokiCollector(replace(make_settings(), loki_url="http://loki.example"))
    bare = AnalysisTarget(
        cluster="", project="", queue="", namespace="", workload_name="",
        workload_type="", runai_workload_id="", node="", pod="",
        severity="critical", alert_name="X",
    )
    # no plan → control_plane defaults in-scope, but the {} target queries must be skipped
    result = await collector.collect(bare, SimpleNamespace(
        namespaces=[], pod="", workload="", check_control_plane=False))
    assert all(q != "{}" and not q.startswith("{} ") for q in issued), issued
    assert any("empty {} selector" in w for w in result.warnings)


def test_adhoc_query_repr_shows_selector_and_only_set_params() -> None:
    from app.services.investigator import _adhoc_query_repr

    assert _adhoc_query_repr(
        {"kind": "pods", "namespace": "runai", "name": "", "label_selector": "app=x"}
    ) == "get pods -n runai -l app=x"
    # two reads differing only by selector must render differently
    a = _adhoc_query_repr({"kind": "pods", "namespace": "runai", "label_selector": "a=1"})
    b = _adhoc_query_repr({"kind": "pods", "namespace": "runai", "label_selector": "b=2"})
    assert a != b
    # cluster-scoped read with just a name
    assert _adhoc_query_repr({"kind": "nodes", "name": "dgx01"}) == "get nodes dgx01"
