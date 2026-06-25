from __future__ import annotations

import pytest

from app.config import Settings
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import AnalysisOrchestrator, _extract_nat_result


def make_settings() -> Settings:
    return Settings(
        port=8000,
        log_level="info",
        language="en",
        runai_base_url="",
        runai_client_id="",
        runai_client_secret="",
        runai_timeout_seconds=1,
        prometheus_url="",
        prometheus_timeout_seconds=1,
        loki_url="",
        loki_timeout_seconds=1,
        postgres_dsn="",
        postgres_timeout_seconds=1,
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
    assert {artifact.agent for artifact in response.artifacts} == {
        "runai",
        "kubernetes",
        "postgres",
        "prometheus",
        "loki",
    }
    assert response.capabilities["runai"] in {"partial", "ok"}


def test_extract_nat_result_strips_console_wrapper() -> None:
    output = "\x1b[32mWorkflow Result:\n## Root Cause\n\nBody\n--------------------------------------------------\x1b[39m"

    assert _extract_nat_result(output) == "## Root Cause\n\nBody"
