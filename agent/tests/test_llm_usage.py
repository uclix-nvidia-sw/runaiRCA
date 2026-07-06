from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.http_json import JsonResponse
from app.llm import begin_usage_tracking, complete, llm_configured
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
        "calls_without_usage": 0,
        "failed_calls": 0,
        "prompt_tokens": 3,
        "completion_tokens": 5,
        "total_tokens": 8,
        "by_model": {
            "m": {
                "calls": 1,
                "calls_without_usage": 0,
                "failed_calls": 0,
                "prompt_tokens": 3,
                "completion_tokens": 5,
                "total_tokens": 8,
            },
        },
    }


@pytest.mark.asyncio
async def test_llm_usage_counts_missing_usage(monkeypatch) -> None:
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
            data={"choices": [{"message": {"content": "done"}}]},
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

    assert response.context["llm_usage"]["calls"] == 1
    assert response.context["llm_usage"]["calls_without_usage"] == 1
    assert response.context["llm_usage"]["by_model"]["m"]["calls_without_usage"] == 1


@pytest.mark.asyncio
async def test_llm_usage_counts_exhausted_retry(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.local",
        llm_model="m",
        llm_api_key="k",
        analysis_deadline_seconds=0,
    )

    async def fake_post_json(**_kwargs):
        return JsonResponse(url="u", status_code=500, error="HTTP 500")

    async def fake_sleep(_seconds: float) -> None:
        return None

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
    monkeypatch.setattr("app.llm.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("app.llm.random.uniform", lambda *_args: 0)
    orch = AnalysisOrchestrator(settings)
    orch._analyze_impl = fake_impl  # type: ignore[assignment]

    response = await orch.analyze(
        AlertAnalysisRequest(alert=Alert(labels={"alertname": "x"}, annotations={}))
    )

    assert response.context["llm_usage"]["calls"] == 0
    assert response.context["llm_usage"]["failed_calls"] == 1
    assert response.context["llm_usage"]["by_model"]["m"]["failed_calls"] == 1


@pytest.mark.asyncio
async def test_complete_uses_stage_model_override(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.local",
        llm_model="default-model",
        llm_api_key="k",
    )
    seen: dict[str, str] = {}

    async def fake_post_json(**kwargs):
        seen["model"] = kwargs["json_body"]["model"]
        return JsonResponse(
            url="u",
            status_code=200,
            data={
                "choices": [{"message": {"content": "done"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
            },
        )

    monkeypatch.setattr("app.llm.post_json", fake_post_json)
    usage = begin_usage_tracking()

    assert await complete(settings, system="s", user="u", model="planner-model") == "done"
    assert seen["model"] == "planner-model"
    assert usage["by_model"]["planner-model"]["total_tokens"] == 3


def test_llm_configured_accepts_stage_model_without_default_model() -> None:
    settings = replace(make_settings(), llm_base_url="https://llm.local", llm_model="", llm_api_key="k")

    assert llm_configured(settings, "planner-model")
    assert not llm_configured(settings)
