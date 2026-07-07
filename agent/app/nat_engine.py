from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
from contextvars import ContextVar
from typing import Any

from nat.builder.evaluator import EvaluatorInfo
from nat.builder.framework_enum import LLMFrameworkEnum
from nat.data_models.component_ref import FunctionRef, LLMRef
from nat.data_models.evaluator import EvalInput, EvaluatorBaseConfig
from nat.data_models.intermediate_step import IntermediateStepType
from nat.plugin_api import (
    Builder,
    FunctionBaseConfig,
    FunctionInfo,
    register_evaluator,
    register_function,
)
from nat.plugins.eval.data_models.evaluator_io import EvalOutput, EvalOutputItem
from nat.runtime.loader import load_workflow

from app import llm as app_llm
from app.config import Settings, load_settings
from app.progress import ProgressReporter
from app.schemas import AlertAnalysisRequest, AlertAnalysisResponse
from app.services import pipeline

_settings_holder: Settings | None = None
_settings_var: ContextVar[Settings | None] = ContextVar("runai_rca_settings", default=None)
_STAGES = {"enrich", "plan", "evidence", "rank", "self_check", "synthesize"}


class RcaStageConfig(FunctionBaseConfig, name="rca_stage"):
    """One Run:ai RCA pipeline stage exposed as a NAT function."""

    stage: str


@register_function(config_type=RcaStageConfig)
async def rca_stage(config: RcaStageConfig, _builder: Builder):
    stage = getattr(pipeline, f"{config.stage}_stage", None)
    if stage is None:
        raise ValueError(f"unknown RCA pipeline stage: {config.stage}")

    async def _run(state: object) -> object:
        return await stage(state)

    _run.__annotations__ = {
        "state": object,
        "return": object,
    }
    yield FunctionInfo.from_fn(_run, description=f"Run:ai RCA {config.stage} stage.")


class RcaFamilyEvaluatorConfig(EvaluatorBaseConfig, name="rca_family"):
    """Score whether the workflow's top root-cause family matches the labeled family."""

    top_k: int = 3
    partial_credit: float = 0.5


@register_evaluator(config_type=RcaFamilyEvaluatorConfig)
async def rca_family_evaluator(config: RcaFamilyEvaluatorConfig, _builder: Builder):
    async def _evaluate(eval_input: EvalInput) -> EvalOutput:
        items = []
        top_k = max(1, int(config.top_k))
        for item in eval_input.eval_input_items:
            response = _response_dict(item.output_obj)
            candidates = _root_cause_candidates(response)
            got = [str(c.get("family") or "") for c in candidates[:top_k] if c.get("family")]
            expected = _expected_family(item.expected_output_obj)
            if got and got[0] == expected:
                score = 1.0
            elif expected and expected in got:
                score = float(config.partial_credit)
            else:
                score = 0.0
            items.append(
                EvalOutputItem(
                    id=item.id,
                    score=score,
                    reasoning={
                        "expected": expected,
                        "got": got,
                        "false_assertion": _false_assertion(expected, candidates),
                    },
                )
            )
        average = sum(float(item.score) for item in items) / len(items) if items else 0.0
        return EvalOutput(average_score=average, eval_output_items=items)

    yield EvaluatorInfo(
        config=config,
        evaluate_fn=_evaluate,
        description=RcaFamilyEvaluatorConfig.__doc__ or "",
    )


class RunaiRcaPipelineConfig(FunctionBaseConfig, name="runai_rca_pipeline"):
    """Run the full Run:ai RCA pipeline as an in-process NAT controller."""

    enrich: FunctionRef
    plan: FunctionRef
    evidence: FunctionRef
    rank: FunctionRef
    self_check: FunctionRef
    synthesize: FunctionRef
    llm: LLMRef = "local_llm"


@register_function(config_type=RunaiRcaPipelineConfig)
async def runai_rca_pipeline(config: RunaiRcaPipelineConfig, builder: Builder):
    funcs = {
        "enrich": await builder.get_function(config.enrich),
        "plan": await builder.get_function(config.plan),
        "evidence": await builder.get_function(config.evidence),
        "rank": await builder.get_function(config.rank),
        "self_check": await builder.get_function(config.self_check),
        "synthesize": await builder.get_function(config.synthesize),
    }

    async def _run(request: object) -> object:
        settings = _settings_var.get() or _settings_holder or load_settings()
        cli_input = isinstance(request, str)
        state = pipeline.new_state(settings, _request_from(request), runtime_label="enabled")
        client = None
        if app_llm.llm_configured(settings, settings.llm_model):
            client = await builder.get_llm(config.llm, wrapper_type=LLMFrameworkEnum.LANGCHAIN)
        token = app_llm.set_nat_client(client) if client is not None else None
        try:
            response = await pipeline.run_pipeline(
                state,
                stages={name: fn.ainvoke for name, fn in funcs.items()},
            )
            return response.model_dump_json() if cli_input else response
        finally:
            if token is not None:
                app_llm.reset_nat_client(token)

    _run.__annotations__ = {
        "request": object,
        "return": object,
    }
    yield FunctionInfo.from_fn(_run, description=RunaiRcaPipelineConfig.__doc__ or "")


def _request_from(value: object) -> AlertAnalysisRequest:
    if isinstance(value, AlertAnalysisRequest):
        return value
    if isinstance(value, str):
        try:
            raw = json.loads(value)
        except json.JSONDecodeError:
            raw = {"alert": {"annotations": {"summary": value}}}
    else:
        raw = value
    if isinstance(raw, dict) and "alert" not in raw:
        raw = {"alert": raw}
    return AlertAnalysisRequest.model_validate(raw)


def _response_dict(value: object) -> dict[str, Any]:
    if isinstance(value, AlertAnalysisResponse):
        return value.model_dump()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def _expected_family(value: object) -> str:
    expected = _response_dict(value)
    return str(expected.get("expected_family") or "").strip()


def _root_cause_candidates(response: dict[str, Any]) -> list[dict[str, Any]]:
    context = response.get("context")
    if not isinstance(context, dict):
        return []
    candidates = context.get("root_cause_candidates")
    if not isinstance(candidates, list):
        return []
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _false_assertion(expected: str, candidates: list[dict[str, Any]]) -> bool:
    if expected != "insufficient_evidence" or not candidates:
        return False
    top = candidates[0]
    return (
        top.get("family") != "insufficient_evidence"
        and str(top.get("confidence") or "") == "high"
    )


class NatEngine:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        self._stack: AsyncExitStack | None = None
        self._sm = None

    async def start(self) -> None:
        if self._sm is not None:
            return
        async with self._lock:
            if self._sm is not None:
                return
            global _settings_holder
            _settings_holder = self._settings
            stack = AsyncExitStack()
            self._sm = await stack.enter_async_context(
                load_workflow(self._settings.nat_config_file, max_concurrency=-1)
            )
            self._stack = stack

    async def run(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        await self.start()
        assert self._sm is not None
        reporter = ProgressReporter.from_alert(
            self._settings, request.alert, pipeline._build_settings_masker(self._settings)
        )
        nat_usage: dict[str, dict[str, int]] = {}
        settings_token = _settings_var.set(self._settings)
        try:
            async with self._sm.run(request) as runner:
                subscription = runner.context.intermediate_step_manager.subscribe(
                    lambda step: _bridge_step(step, reporter, nat_usage)
                )
                try:
                    result = await runner.result(AlertAnalysisResponse)
                finally:
                    subscription.unsubscribe()
        finally:
            _settings_var.reset(settings_token)
        if isinstance(result, AlertAnalysisResponse):
            response = result
        else:
            response = AlertAnalysisResponse.model_validate(result)
        if nat_usage:
            response.context["llm_usage_nat"] = nat_usage
        return response

    async def aclose(self) -> None:
        async with self._lock:
            if self._stack is not None:
                await self._stack.aclose()
            self._stack = None
            self._sm = None


def _bridge_step(
    step: object, reporter: ProgressReporter, usage: dict[str, dict[str, int]]
) -> None:
    payload = getattr(step, "payload", None)
    if payload is None:
        return
    name = str(getattr(payload, "name", "") or "")
    event_type = getattr(payload, "event_type", None)
    if event_type == IntermediateStepType.FUNCTION_START and name in _STAGES:
        reporter.emit(name, "stage started")
    elif event_type == IntermediateStepType.FUNCTION_END and name in _STAGES:
        reporter.emit(name, "stage finished")
    elif event_type == IntermediateStepType.LLM_END:
        ancestry = getattr(step, "function_ancestry", None)
        stage = str(getattr(ancestry, "function_name", "") or "workflow")
        if stage not in _STAGES:
            stage = str(getattr(ancestry, "parent_name", "") or "workflow")
        info = getattr(payload, "usage_info", None)
        tokens = getattr(info, "token_usage", None)
        if tokens is None:
            return
        bucket = usage.setdefault(
            stage,
            {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )
        bucket["calls"] += int(getattr(info, "num_llm_calls", 0) or 1)
        bucket["prompt_tokens"] += int(getattr(tokens, "prompt_tokens", 0) or 0)
        bucket["completion_tokens"] += int(getattr(tokens, "completion_tokens", 0) or 0)
        bucket["total_tokens"] += int(getattr(tokens, "total_tokens", 0) or 0)
