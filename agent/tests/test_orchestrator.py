from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

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
        runai_timeout_seconds=1,
        prometheus_url="",
        prometheus_timeout_seconds=1,
        prometheus_mcp_url="",
        loki_url="",
        loki_timeout_seconds=1,
        loki_query_limit=10,
        loki_mcp_url="",
        runai_log_namespaces=("runai", "runai-backend"),
        postgres_dsn="",
        postgres_timeout_seconds=1,
        troubleshooting_cases_file="knowledge/troubleshooting_cases.md",
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
    )


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
    assert response.context["agent_souls_applied"] is True
    assert "## Agent Role Coverage" in response.analysis_detail
    assert {artifact.agent for artifact in response.artifacts} == {
        "runai",
        "kubernetes",
        "postgres",
        "prometheus",
        "loki",
    }
    assert response.capabilities["runai"] in {"partial", "ok"}


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
