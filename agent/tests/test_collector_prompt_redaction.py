from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import change, kubernetes, loki, system
from app.collectors.base import NO_EVIDENCE
from app.llm import begin_usage_tracking
from tests.test_orchestrator import make_settings


def _settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )


@pytest.mark.asyncio
async def test_collector_insight_is_cached_within_usage_scope(monkeypatch) -> None:
    calls = 0

    async def fake_complete(_settings, *, user, **_kwargs):
        nonlocal calls
        calls += 1
        return f"insight {calls}"

    monkeypatch.setattr(loki, "complete", fake_complete)
    begin_usage_tracking()
    settings = _settings()

    first = await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}])
    second = await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}])

    assert first == "insight 1"
    assert second == "insight 1"
    assert calls == 1

    begin_usage_tracking()
    await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}])
    assert calls == 2


@pytest.mark.asyncio
async def test_no_evidence_collectors_skip_insight_llm(monkeypatch) -> None:
    async def should_not_call(*_args, **_kwargs):
        raise AssertionError("no-evidence summaries should not call the LLM")

    monkeypatch.setattr(loki, "complete", should_not_call)
    monkeypatch.setattr(kubernetes, "complete", should_not_call)
    settings = _settings()

    assert (
        await loki._llm_insight(
            settings, "Prometheus metrics", f"{NO_EVIDENCE} no matching series.", []
        )
        is None
    )
    assert (
        await kubernetes._senior_insight(
            settings,
            summary=f"{NO_EVIDENCE} Kubernetes query failed.",
            container_diagnostics=[],
            warning_events=[],
            logs=[],
            exec_probes=[],
        )
        == ""
    )


@pytest.mark.asyncio
async def test_insight_calls_use_stage_model_override(monkeypatch) -> None:
    models: list[str | None] = []

    async def fake_complete(_settings, *, model=None, **_kwargs):
        models.append(model)
        return "ok"

    for module in (change, kubernetes, loki):
        monkeypatch.setattr(module, "complete", fake_complete)

    settings = replace(_settings(), llm_model_insight="super")
    begin_usage_tracking()
    await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}])
    await kubernetes._senior_insight(
        settings,
        summary="summary",
        container_diagnostics=[],
        warning_events=[{"message": "FailedScheduling"}],
        logs=[],
        exec_probes=[],
    )
    await change._senior_insight(settings, [{"summary": "deployment changed"}])

    assert models == ["super", "super", "super"]

    models.clear()
    await loki._llm_insight(
        replace(settings, llm_model_insight=""), "source", "summary", [{"line": "new evidence"}]
    )
    assert models == [None]


@pytest.mark.asyncio
async def test_collector_insights_use_configured_token_budget(monkeypatch) -> None:
    budgets: list[int | None] = []

    async def fake_complete(_settings, *, max_tokens=None, **_kwargs):
        budgets.append(max_tokens)
        return "ok"

    for module in (change, kubernetes, loki, system):
        monkeypatch.setattr(module, "complete", fake_complete)

    settings = replace(_settings(), llm_insight_max_tokens=640)
    begin_usage_tracking()
    await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}])
    await kubernetes._senior_insight(
        settings,
        summary="summary",
        container_diagnostics=[],
        warning_events=[{"message": "FailedScheduling"}],
        logs=[],
        exec_probes=[],
    )
    await system._llm_insight(settings, "node-a", ["NVRM Xid 79"])
    await change._senior_insight(settings, [{"summary": "deployment changed"}])

    assert budgets == [640, 640, 640, 640]


@pytest.mark.asyncio
async def test_collector_llm_prompts_redact_sensitive_inputs(monkeypatch) -> None:
    prompts: list[str] = []

    async def fake_complete(_settings, *, user, **_kwargs):
        prompts.append(user)
        return "ok"

    for module in (change, kubernetes, loki, system):
        monkeypatch.setattr(module, "complete", fake_complete)

    settings = _settings()
    await loki._llm_insight(
        settings,
        "Loki token=source-token-12345",
        "summary password=summary-password-12345",
        [{"line": "api_key=loki-key-12345"}],
    )
    await kubernetes._senior_insight(
        settings,
        summary="api_key=k8s-summary-key-12345",
        container_diagnostics=[],
        warning_events=[{"message": "token=k8s-event-token-12345"}],
        logs=[{"lines": ["error password=k8s-log-password-12345"]}],
        exec_probes=[{"output": "client_secret=k8s-exec-secret-12345"}],
    )
    await system._llm_insight(
        settings,
        "node-password=system-node-secret-12345",
        ["NVRM error api_key=system-key-12345"],
    )
    await change._senior_insight(
        settings,
        [{"summary": "deployment changed token=change-token-12345"}],
    )

    joined = "\n".join(prompts)
    for secret in [
        "source-token-12345",
        "summary-password-12345",
        "loki-key-12345",
        "k8s-summary-key-12345",
        "k8s-event-token-12345",
        "k8s-log-password-12345",
        "k8s-exec-secret-12345",
        "system-node-secret-12345",
        "system-key-12345",
        "change-token-12345",
    ]:
        assert secret not in joined
    assert "[MASKED]" in joined


@pytest.mark.asyncio
async def test_collector_llm_outputs_are_redacted(monkeypatch) -> None:
    async def fake_complete(_settings, *, user, **_kwargs):
        return "api_key=collector-output-secret-12345"

    for module in (change, kubernetes, loki, system):
        monkeypatch.setattr(module, "complete", fake_complete)

    settings = _settings()
    outputs = [
        await loki._llm_insight(settings, "source", "summary", [{"line": "evidence"}]),
        await kubernetes._senior_insight(
            settings,
            summary="summary",
            container_diagnostics=[],
            warning_events=[],
            logs=[],
            exec_probes=[],
        ),
        await system._llm_insight(settings, "node-a", ["NVRM Xid 79"]),
        await change._senior_insight(settings, [{"summary": "deployment changed"}]),
    ]

    joined = "\n".join(output or "" for output in outputs)
    assert "collector-output-secret-12345" not in joined
    assert "[MASKED]" in joined
