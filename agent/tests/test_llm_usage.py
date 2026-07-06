from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.http_json import JsonResponse
from app.llm import complete
from app.schemas import Alert, AlertAnalysisRequest, AlertAnalysisResponse
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings


@pytest.mark.asyncio
async def test_llm_usage_is_injected_by_analyze(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.local",
        llm_model="m",
        llm_api_key="k",
        analysis_deadline_seconds=0,
    )

    async def fake_post_json(**_kwargs):
        return JsonResponse(
            url="u",
            status_code=200,
            data={
                "choices": [{"message": {"content": "done"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8},
            },
        )

    async def fake_impl(request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        await complete(settings, system="s", user="u")
        return AlertAnalysisResponse(
            status="ok",
            thread_ts=request.thread_ts,
            analysis="a",
            analysis_summary="s",
            analysis_detail="d",
            analysis_type="firing",
            analysis_quality="high",
            missing_data=[],
            warnings=[],
            capabilities={},
            context={},
            artifacts=[],
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    orch = AnalysisOrchestrator(settings)
    orch._analyze_impl = fake_impl  # type: ignore[assignment]

    response = await orch.analyze(
        AlertAnalysisRequest(alert=Alert(labels={"alertname": "x"}, annotations={}))
    )

    assert response.context["llm_usage"] == {
        "calls": 1,
        "prompt_tokens": 3,
        "completion_tokens": 5,
        "total_tokens": 8,
    }
