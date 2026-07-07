from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from app.progress import ProgressReporter
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings

CONFIG = Path(__file__).parents[1] / "configs" / "runai_rca_engine.yml"


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "RunAIWorkloadPending", "namespace": "runai"},
            annotations={"summary": "smoke"},
            fingerprint="fp-nat-engine",
        )
    )


@pytest.mark.asyncio
async def test_engine_yaml_builds_and_analyzes_end_to_end(monkeypatch) -> None:
    events = []

    class Recorder:
        def emit(self, phase: str, message: str, **data) -> None:
            events.append((phase, message))

    def fake_from_alert(cls, settings, alert, masker=None):
        return Recorder()

    monkeypatch.setattr(ProgressReporter, "from_alert", classmethod(fake_from_alert))
    settings = replace(
        make_settings(),
        enable_nat_runtime=True,
        nat_config_file=str(CONFIG),
    )
    response = await AnalysisOrchestrator(settings).analyze(_request())

    assert response.status == "ok"
    assert response.analysis_summary
    assert response.analysis_detail
    assert set(response.capabilities) == set(settings.collectors)
    assert response.context["nemo_runtime"] == "enabled"
    assert response.context["plan"]
    assert response.context["root_cause_candidates"]
    assert not any("nemo failed" in warning for warning in response.warnings)
    for stage in ("enrich", "plan", "evidence", "rank", "self_check", "synthesize"):
        assert (stage, "stage started") in events
        assert (stage, "stage finished") in events
    assert set(response.context["llm_usage"]) == {
        "calls",
        "calls_without_usage",
        "failed_calls",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "by_model",
        "cost_usd",
    }


@pytest.mark.asyncio
async def test_engine_failure_falls_back_to_direct_pipeline() -> None:
    settings = replace(
        make_settings(),
        enable_nat_runtime=True,
        nat_config_file="/nonexistent.yml",
    )
    response = await AnalysisOrchestrator(settings).analyze(_request())

    assert response.status == "ok"
    assert any("nemo failed unexpectedly" in warning for warning in response.warnings)
    assert response.context["nemo_runtime"] == "fallback"
