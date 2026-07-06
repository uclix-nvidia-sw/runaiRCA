from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult
from app.plan import InvestigationPlan
from app.services.investigator import investigate
from tests.test_orchestrator import make_settings, make_target


class RunaiCollector:
    def __init__(self) -> None:
        self.calls = 0

    async def collect(self, target, plan=None) -> CollectorResult:
        self.calls += 1
        return CollectorResult(agent="runai", status="ok", summary="runai ok")


class KubernetesCollector:
    def __init__(self) -> None:
        self.calls = 0

    async def collect(self, target, plan=None) -> CollectorResult:
        self.calls += 1
        return CollectorResult(agent="kubernetes", status="ok", summary="kubernetes ok")


class LokiCollector:
    def __init__(self) -> None:
        self.calls = 0

    async def collect(self, target, plan=None) -> CollectorResult:
        self.calls += 1
        return CollectorResult(agent="loki", status="ok", summary="loki ok")


def _collectors() -> list[object]:
    return [RunaiCollector(), KubernetesCollector(), LokiCollector()]


@pytest.mark.asyncio
async def test_no_llm_falls_back_to_full_gather() -> None:
    # No LLM configured -> complete_json returns None -> loop bails, full gather runs.
    collectors = _collectors()
    results = await investigate(
        make_settings(), make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}
    assert all(c.calls == 1 for c in collectors)


@pytest.mark.asyncio
async def test_returns_all_collectors_even_when_llm_probes_subset(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    calls = {"n": 0}

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls["n"] += 1
        # Probe only loki, then conclude — the other two must still be run at the end.
        if calls["n"] == 1:
            return {"action": "probe", "reason": "logs", "probes": [{"collector": "loki"}]}
        return {"action": "conclude", "reason": "enough"}

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    collectors = _collectors()
    results = await investigate(
        settings, make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}
    assert all(c.calls == 1 for c in collectors)


@pytest.mark.asyncio
async def test_loop_is_bounded_by_max_steps(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    calls = {"n": 0}

    async def never_conclude(settings, *, system, user, temperature=0.1):
        calls["n"] += 1
        # Always re-probe the same collector so only "conclude" or max_steps can stop it.
        return {"action": "probe", "reason": "again", "probes": [{"collector": "runai"}]}

    monkeypatch.setattr("app.services.investigator.complete_json", never_conclude)
    results = await investigate(
        settings, make_target(), _collectors(), InvestigationPlan(), {}, max_steps=2
    )

    assert calls["n"] <= 2  # bounded
    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}


@pytest.mark.asyncio
async def test_collector_exception_does_not_raise(monkeypatch) -> None:
    class RunaiCollectorBoom:
        async def collect(self, target, plan=None):
            raise RuntimeError("boom")

    # class name -> "runai_collector_boom"; only the mapped names matter here.
    collectors = [RunaiCollectorBoom(), LokiCollector()]
    results = await investigate(
        make_settings(), make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    by_status = {r.status for r in results}
    assert by_status == {"unavailable", "ok"}
    assert len(results) == 2
