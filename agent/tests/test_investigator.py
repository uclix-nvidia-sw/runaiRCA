from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult
from app.llm import begin_usage_tracking
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
    results, context = await investigate(
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
    results, context = await investigate(
        settings, make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}
    assert all(c.calls == 1 for c in collectors)


@pytest.mark.asyncio
async def test_hypothesis_ledger_updates_and_confident_stop(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    calls = {"n": 0}
    plan = InvestigationPlan(
        hypotheses=[
            {"family": "runai_scheduling_quota", "reason": "queue saturated"},
            {"family": "workload_startup_error", "reason": "pod may be crashing"},
        ]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        calls["n"] += 1
        if "final skeptical reflection" in system:
            return {"hypothesis_updates": [], "new_hypotheses": []}
        return {
            "action": "probe",
            "reason": "quota evidence is strongest",
            "selected_hypothesis": "H1",
            "probes": [{"collector": "runai"}],
            "hypothesis_updates": [
                {
                    "id": "H1",
                    "confidence": 0.9,
                    "evidence_for": ["queue saturated"],
                    "status": "supported",
                }
            ],
        }

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    results, context = await investigate(
        settings, make_target(), _collectors(), plan, {}, max_steps=4
    )

    ledger = context["hypothesis_ledger"]
    assert ledger[0]["id"] == "H1"
    assert ledger[0]["confidence"] == 0.9
    assert ledger[0]["status"] == "supported"
    assert "queue saturated" in ledger[0]["evidence_for"]
    assert calls["n"] == 2  # one decision, one reflection; confident stop avoids extra loop steps
    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}


@pytest.mark.asyncio
async def test_reflection_can_add_missing_hypothesis(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    plan = InvestigationPlan(
        hypotheses=[{"family": "runai_scheduling_quota", "reason": "queue saturated"}]
    )

    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        if "final skeptical reflection" in system:
            return {
                "hypothesis_updates": [],
                "new_hypotheses": [
                    {
                        "family": "image_pull_error",
                        "statement": "registry failure could explain pending pods",
                        "confidence": 0.45,
                    }
                ],
            }
        return {"action": "conclude", "reason": "enough", "hypothesis_updates": []}

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    _, context = await investigate(settings, make_target(), _collectors(), plan, {}, max_steps=4)

    families = [item["family"] for item in context["hypothesis_ledger"]]
    assert "image_pull_error" in families


@pytest.mark.asyncio
async def test_loop_is_bounded_by_max_steps(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    calls = {"n": 0}

    async def never_conclude(settings, *, system, user, temperature=0.1, model=None):
        calls["n"] += 1
        # Always re-probe the same collector so only "conclude" or max_steps can stop it.
        return {"action": "probe", "reason": "again", "probes": [{"collector": "runai"}]}

    monkeypatch.setattr("app.services.investigator.complete_json", never_conclude)
    results, context = await investigate(
        settings, make_target(), _collectors(), InvestigationPlan(), {}, max_steps=2
    )

    assert calls["n"] <= 3  # max_steps decisions + one final reflection
    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}


@pytest.mark.asyncio
async def test_token_budget_stops_investigation_loop(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
        analysis_token_budget=10,
    )
    usage = begin_usage_tracking()
    usage["total_tokens"] = 10

    async def should_not_call_llm(*args, **kwargs):
        raise AssertionError("budget should stop the loop before another LLM call")

    monkeypatch.setattr("app.services.investigator.complete_json", should_not_call_llm)
    collectors = _collectors()
    results, context = await investigate(
        settings, make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    assert {r.agent for r in results} == {"runai", "kubernetes", "loki"}
    assert any("token budget" in warning for result in results for warning in result.warnings)


@pytest.mark.asyncio
async def test_collector_exception_does_not_raise(monkeypatch) -> None:
    class RunaiCollectorBoom:
        async def collect(self, target, plan=None):
            raise RuntimeError("boom")

    # class name -> "runai_collector_boom"; only the mapped names matter here.
    collectors = [RunaiCollectorBoom(), LokiCollector()]
    results, context = await investigate(
        make_settings(), make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    by_status = {r.status for r in results}
    assert by_status == {"unavailable", "ok"}
    assert len(results) == 2
