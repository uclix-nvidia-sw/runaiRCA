from __future__ import annotations

from dataclasses import replace

import pytest

from app.config import load_settings
from app.schemas import Alert, AlertAnalysisArtifact, AlertAnalysisRequest, AlertAnalysisResponse
from app.services.orchestrator import AnalysisOrchestrator
from app.services.response_budget import (
    analysis_response_bytes,
    enforce_analysis_response_budget,
)
from tests.test_orchestrator import make_settings


def _response(blob: str = "") -> AlertAnalysisResponse:
    detail = (
        "## Root Cause\n\nJWKS discovery returned HTML.\n\n## Recommended Actions\n\nFix routing."
    )
    return AlertAnalysisResponse(
        status="ok",
        thread_ts="",
        analysis=detail,
        analysis_summary="JWKS discovery routing is incorrect.",
        analysis_detail=detail,
        analysis_type="firing",
        analysis_quality="high",
        root_cause_family="workload_startup_error",
        missing_data=[],
        warnings=[],
        capabilities={"kubernetes": "ok", "loki": "ok"},
        context={
            "target": {"namespace": "runai-rca", "pod": "runai-mcp-0"},
            "top_root_cause": {"family": "workload_startup_error"},
            "investigation": {"raw": blob},
            "reasoning_trace_v3": {"raw": blob},
        },
        artifacts=[
            AlertAnalysisArtifact(
                agent="kubernetes",
                source="pod-log",
                type="log",
                status="ok",
                confidence="high",
                summary="Discovery parsing failed because HTML was returned.",
                result={"lines": [blob]},
            )
        ],
    )


def test_small_analysis_response_is_unchanged() -> None:
    response = _response("one log line")
    before = response.model_dump_json()

    assert not enforce_analysis_response_budget(response, 1 << 20, language="ko")
    assert response.model_dump_json() == before


def test_oversized_response_preserves_report_and_fits_budget() -> None:
    response = _response("로그" * 200_000)
    summary = response.analysis_summary
    detail = response.analysis_detail
    budget = 64 << 10

    assert enforce_analysis_response_budget(response, budget, language="ko")

    assert analysis_response_bytes(response) <= budget
    assert response.analysis_summary == summary
    assert response.analysis_detail == detail
    assert response.analysis == ""
    assert "축약되었습니다" in "\n".join(response.warnings)
    metadata = response.context["response_budget"]
    assert metadata["original_bytes"] > budget
    assert metadata["final_bytes"] == analysis_response_bytes(response) <= budget
    assert metadata["truncated_artifact_results"] >= 1
    assert "investigation" in metadata["omitted_context_keys"]
    assert response.artifacts
    assert response.artifacts[0].summary.startswith("Discovery parsing failed")


def test_pathological_report_body_is_bounded_as_last_resort() -> None:
    response = _response("")
    response.analysis_detail = "원인과 조치 " * 50_000
    response.analysis = response.analysis_detail
    budget = 64 << 10

    assert enforce_analysis_response_budget(response, budget, language="ko")

    assert analysis_response_bytes(response) <= budget
    assert response.analysis_detail.endswith("...")


@pytest.mark.asyncio
async def test_orchestrator_applies_budget_at_public_response_boundary() -> None:
    budget = 64 << 10
    orchestrator = AnalysisOrchestrator(
        replace(
            make_settings(),
            analysis_deadline_seconds=0,
            analysis_response_max_bytes=budget,
            language="ko",
        )
    )

    async def oversized(_request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        return _response("로그" * 200_000)

    orchestrator._analyze_impl = oversized  # type: ignore[assignment]
    result = await orchestrator.analyze(
        AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIMCPDown"},
                annotations={},
                fingerprint="response-budget",
            )
        )
    )

    assert analysis_response_bytes(result) <= budget
    assert result.context["response_budget"]["applied"] is True
    assert "llm_usage" in result.context


def test_analysis_response_budget_loads_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("ANALYSIS_RESPONSE_MAX_BYTES", "987654")

    assert load_settings().analysis_response_max_bytes == 987654
