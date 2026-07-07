from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import change, kubernetes, loki, system
from tests.test_orchestrator import make_settings


def _settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )


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
