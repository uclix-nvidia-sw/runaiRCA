from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nat.data_models.evaluator import EvalInput, EvalInputItem

from app.nat_engine import RcaFamilyEvaluatorConfig, rca_family_evaluator
from app.progress import ProgressReporter
from app.schemas import Alert, AlertAnalysisRequest, AlertAnalysisResponse
from app.services.orchestrator import AnalysisOrchestrator
from tests.test_orchestrator import make_settings

CONFIG = Path(__file__).parents[1] / "configs" / "runai_rca_engine.yml"
NAT_DATASET = Path(__file__).parents[1] / "eval" / "nat_dataset.jsonl"
VALID_FAMILIES = {
    # families.yaml plus signature-only families from failure_modes.yaml and
    # runai_known_issues.yaml.
    "gpu_hardware_error",
    "node_kubelet_pressure",
    "runai_scheduling_quota",
    "k8s_scheduling_error",
    "runai_control_plane_error",
    "k8s_control_plane_error",
    "workload_startup_error",
    "image_pull_error",
    "insufficient_evidence",
    "platform_version_bug",
    "observability_accuracy",
    "expected_known_behavior",
}


def _request() -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "RunAIWorkloadPending", "namespace": "runai"},
            annotations={"summary": "smoke"},
            fingerprint="fp-nat-engine",
        )
    )


def _eval_item(
    item_id: str,
    expected: str,
    candidates: list[dict[str, object]],
    *,
    as_json: bool = False,
) -> EvalInputItem:
    output = {"context": {"root_cause_candidates": candidates}}
    return EvalInputItem(
        id=item_id,
        input_obj={},
        expected_output_obj={"expected_family": expected},
        output_obj=json.dumps(output) if as_json else output,
        full_dataset_entry={},
    )


@pytest.mark.asyncio
async def test_rca_family_evaluator_scores_ranked_family_matches() -> None:
    async with rca_family_evaluator(RcaFamilyEvaluatorConfig(), None) as info:
        output = await info.evaluate_fn(
            EvalInput(
                eval_input_items=[
                    _eval_item(
                        "exact",
                        "gpu_hardware_error",
                        [{"family": "gpu_hardware_error", "confidence": "high"}],
                    ),
                    _eval_item(
                        "partial",
                        "image_pull_error",
                        [
                            {"family": "k8s_scheduling_error", "confidence": "medium"},
                            {"family": "image_pull_error", "confidence": "medium"},
                        ],
                        as_json=True,
                    ),
                    _eval_item(
                        "miss",
                        "runai_scheduling_quota",
                        [{"family": "k8s_scheduling_error", "confidence": "medium"}],
                    ),
                    _eval_item(
                        "false-assertion",
                        "insufficient_evidence",
                        [{"family": "gpu_hardware_error", "confidence": "high"}],
                        as_json=True,
                    ),
                ]
            )
        )

    by_id = {item.id: item for item in output.eval_output_items}
    assert by_id["exact"].score == 1.0
    assert by_id["partial"].score == 0.5
    assert by_id["miss"].score == 0.0
    assert by_id["false-assertion"].score == 0.0
    assert by_id["false-assertion"].reasoning["false_assertion"] is True


def test_nat_dataset_schema_and_families() -> None:
    for line in NAT_DATASET.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        expected = item.get("answer", {}).get("expected_family")
        assert item.get("id")
        assert item.get("question", {}).get("alert")
        assert expected in VALID_FAMILIES


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
async def test_multiple_nat_engines_keep_their_own_settings() -> None:
    a = AnalysisOrchestrator(
        replace(
            make_settings(),
            enable_nat_runtime=True,
            nat_config_file=str(CONFIG),
            collectors=("kubernetes",),
        )
    )
    b = AnalysisOrchestrator(
        replace(
            make_settings(),
            enable_nat_runtime=True,
            nat_config_file=str(CONFIG),
            collectors=("prometheus", "loki"),
        )
    )
    try:
        await a.start_engine()
        await b.start_engine()

        a_response = await a.analyze(_request())
        b_response = await b.analyze(_request())
    finally:
        await a.close_engine()
        await b.close_engine()

    assert sorted(a_response.capabilities) == ["kubernetes"]
    assert sorted(b_response.capabilities) == ["loki", "prometheus"]


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


@pytest.mark.asyncio
async def test_incomplete_engine_response_falls_back_to_direct_pipeline() -> None:
    settings = replace(make_settings(), enable_nat_runtime=True)
    orchestrator = AnalysisOrchestrator(settings)

    async def shallow_run(_request):
        return AlertAnalysisResponse(
            status="ok",
            thread_ts="",
            analysis="",
            analysis_summary="",
            analysis_detail="",
            analysis_type="firing",
            analysis_quality="low",
            missing_data=[],
            warnings=[],
            capabilities={},
            context={},
            artifacts=[],
        )

    orchestrator._engine = SimpleNamespace(run=shallow_run)

    response = await orchestrator.analyze(_request())

    assert response.status == "ok"
    assert response.analysis_summary
    assert response.analysis_detail
    assert response.context["nemo_runtime"] == "fallback"
    assert any("incomplete RCA response" in warning for warning in response.warnings)


@pytest.mark.asyncio
async def test_invalid_engine_candidate_falls_back_to_direct_pipeline() -> None:
    settings = replace(make_settings(), enable_nat_runtime=True)
    orchestrator = AnalysisOrchestrator(settings)

    async def shallow_run(_request):
        return AlertAnalysisResponse(
            status="ok",
            thread_ts="",
            analysis="looks complete",
            analysis_summary="looks complete",
            analysis_detail="looks complete",
            analysis_type="firing",
            analysis_quality="medium",
            missing_data=[],
            warnings=[],
            capabilities={},
            context={"root_cause_candidates": [{}]},
            artifacts=[],
        )

    orchestrator._engine = SimpleNamespace(run=shallow_run)

    response = await orchestrator.analyze(_request())

    assert response.status == "ok"
    assert response.context["nemo_runtime"] == "fallback"
    assert any("invalid top root-cause candidate" in warning for warning in response.warnings)


@pytest.mark.asyncio
async def test_mismatched_engine_top_root_cause_falls_back_to_direct_pipeline() -> None:
    settings = replace(make_settings(), enable_nat_runtime=True)
    orchestrator = AnalysisOrchestrator(settings)

    async def shallow_run(_request):
        return AlertAnalysisResponse(
            status="ok",
            thread_ts="",
            analysis="looks complete",
            analysis_summary="looks complete",
            analysis_detail="looks complete",
            analysis_type="firing",
            analysis_quality="medium",
            missing_data=[],
            warnings=[],
            capabilities={},
            context={
                "root_cause_candidates": [
                    {"family": "runai_scheduling_quota", "confidence": "medium"}
                ],
                "top_root_cause": {"family": "image_pull_error", "confidence": "medium"},
            },
            artifacts=[],
        )

    orchestrator._engine = SimpleNamespace(run=shallow_run)

    response = await orchestrator.analyze(_request())

    assert response.status == "ok"
    assert response.context["nemo_runtime"] == "fallback"
    assert any("top_root_cause does not match" in warning for warning in response.warnings)


@pytest.mark.asyncio
async def test_engine_health_surfaces_failure_and_logs_once(caplog) -> None:
    settings = replace(
        make_settings(),
        enable_nat_runtime=True,
        nat_config_file="/nonexistent.yml",
    )
    orch = AnalysisOrchestrator(settings)
    assert orch.engine_health()["state"] == "unknown"

    with caplog.at_level("ERROR", logger="app.services.orchestrator"):
        await orch.analyze(_request())
        await orch.analyze(_request())

    health = orch.engine_health()
    assert health["state"] == "failed"
    assert health["consecutive_failures"] == 2  # both runs failed
    assert health["last_error"]
    # Edge-triggered: two consecutive failures log the FAILING line exactly once,
    # so kubelet-frequency retries never spam the log.
    failing = [r for r in caplog.records if "nemo engine FAILING" in r.getMessage()]
    assert len(failing) == 1


@pytest.mark.asyncio
async def test_engine_health_masks_failure_payloads(caplog) -> None:
    settings = replace(make_settings(), enable_nat_runtime=True)
    orch = AnalysisOrchestrator(settings)

    async def broken_run(_request):
        raise RuntimeError("startup failed password=nemo-health-secret-12345")

    orch._engine = SimpleNamespace(run=broken_run)

    with caplog.at_level("ERROR", logger="app.services.orchestrator"):
        await orch.analyze(_request())

    health = orch.engine_health()
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert health["state"] == "failed"
    assert "nemo-health-secret-12345" not in str(health)
    assert "nemo-health-secret-12345" not in log_text
    assert "[MASKED]" in health["last_error"]
    assert "[MASKED]" in log_text


def test_engine_health_disabled_when_runtime_off() -> None:
    settings = replace(make_settings(), enable_nat_runtime=False)
    assert AnalysisOrchestrator(settings).engine_health()["state"] == "disabled"
