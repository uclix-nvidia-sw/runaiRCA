from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import CollectorResult
from app.plan import InvestigationPlan
from app.services.evidence_blackboard import Blackboard
from app.services.investigator import _build_user_prompt, _evidence_summary, investigate
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
        self.last_plan = None

    async def collect(self, target, plan=None) -> CollectorResult:
        self.calls += 1
        self.last_plan = plan
        return CollectorResult(agent="kubernetes", status="ok", summary="kubernetes ok")


class LokiCollector:
    def __init__(self) -> None:
        self.calls = 0

    async def collect(self, target, plan=None) -> CollectorResult:
        self.calls += 1
        return CollectorResult(agent="loki", status="ok", summary="loki ok")


def _collectors() -> list[object]:
    return [RunaiCollector(), KubernetesCollector(), LokiCollector()]


def test_unavailable_evidence_summary_does_not_expose_stale_signal_text() -> None:
    summaries = _evidence_summary(
        {
            "kubernetes": CollectorResult(
                agent="kubernetes",
                status="unavailable",
                summary="kubectl failed; stale output mentioned DiskPressure and evicted pods",
                missing_data=["kubernetes.api"],
                warnings=["api unreachable"],
            )
        }
    )

    assert summaries == [
        {
            "collector": "kubernetes",
            "status": "unavailable",
            "confidence": "low",
            "summary": "collector unavailable; no evidence collected",
            "missing_data": ["kubernetes.api"],
            "warnings": ["api unreachable"],
        }
    ]


def test_failed_adhoc_result_is_not_replayed_as_prompt_evidence() -> None:
    prompt = _build_user_prompt(
        InvestigationPlan(),
        {},
        {},
        {"kubernetes": object()},
        [],
        adhoc=[
            {
                "kind": "pods",
                "namespace": "runai",
                "error": "query failed; stale output mentioned DiskPressure",
                "data": {"message": "DiskPressure=True; pods evicted"},
            }
        ],
    )

    assert "DiskPressure" not in prompt
    assert "pods evicted" not in prompt
    assert "query failed" in prompt


def test_investigation_prompt_orders_stable_prefix_and_keeps_latest_evidence() -> None:
    evidence: dict[str, CollectorResult] = {}
    by_name: dict[str, object] = {}
    for idx in range(30):
        name = f"collector-{idx:02d}"
        by_name[name] = object()
        marker = "OLDEST-SIGNAL " if idx == 0 else "LATEST-SIGNAL " if idx == 29 else ""
        evidence[name] = CollectorResult(
            agent=name,
            status="ok",
            summary=marker + ("x" * 390),
            confidence="medium",
        )

    prompt = _build_user_prompt(InvestigationPlan(), {}, evidence, by_name, [], adhoc=[])

    assert len(prompt) <= 8000
    assert prompt.find('"plan"') < prompt.find('"evidence_so_far"')
    assert "LATEST-SIGNAL" in prompt
    assert "OLDEST-SIGNAL" not in prompt


def test_investigator_prompt_receives_ontology_diagnostic_directive() -> None:
    plan = InvestigationPlan(
        diagnostic_directive={
            "source": "typedb",
            "questions": ["Did the node report an XID before the timeout?"],
            "checks": ["Compare dmesg and per-rank timestamps"],
            "disconfirm": ["The XID is outside the incident window"],
            "provisional_family": "gpu_hardware_error",
        }
    )

    prompt = _build_user_prompt(plan, {}, {}, {"system": object()}, [], adhoc=[])

    assert '"source": "typedb"' in prompt
    assert "per-rank timestamps" in prompt
    assert "outside the incident window" in prompt


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
async def test_each_collector_receives_an_ontology_scoped_role() -> None:
    collector = KubernetesCollector()
    plan = InvestigationPlan(
        diagnostic_directive={
            "checks": ["Read pod events"],
            "recommended_collectors": ["kubernetes"],
        }
    )

    await investigate(make_settings(), make_target(), [collector], plan, {}, max_steps=1)

    directive = collector.last_plan.diagnostic_directive
    assert directive["collector"] == "kubernetes"
    assert directive["primary"] is True
    assert "disconfirming evidence" in directive["collector_instruction"]


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
async def test_investigation_prompts_redact_sensitive_inputs(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )
    prompts: list[str] = []

    class SecretCollector:
        async def collect(self, target, plan=None):
            return CollectorResult(
                agent="runai",
                status="ok",
                summary="quota check token=collector-token-12345",
            )

    async def fake_complete_json(settings, *, system, user, **_kwargs):
        prompts.append(user)
        if len(prompts) == 1:
            return {"action": "probe", "probes": [{"collector": "runai"}]}
        if "final skeptical reflection" in system:
            return {"hypothesis_updates": [], "new_hypotheses": []}
        return {"action": "conclude", "hypothesis_updates": []}

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    plan = InvestigationPlan(
        hypotheses=[{"family": "runai_scheduling_quota", "reason": "password=plan-secret-12345"}]
    )
    kg = {
        "blast_radius_workloads": 1,
        "prior_incidents": [{"analysis_summary": "api_key=kg-key-12345"}],
    }

    await investigate(settings, make_target(), [SecretCollector()], plan, kg, max_steps=3)

    joined = "\n".join(prompts)
    for secret in ["plan-secret-12345", "kg-key-12345", "collector-token-12345"]:
        assert secret not in joined
    assert "[MASKED]" in joined


@pytest.mark.asyncio
async def test_investigation_context_masks_llm_decision_outputs(monkeypatch) -> None:
    settings = replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )

    async def fake_complete_json(settings, *, system, user, **_kwargs):
        if "final skeptical reflection" in system:
            return {
                "hypothesis_updates": [
                    {"id": "H1", "evidence_for": ["token=reflect-secret-12345"]}
                ],
                "new_hypotheses": [
                    {
                        "family": "image_pull_error",
                        "statement": "api_key=newhyp-secret-12345",
                    }
                ],
            }
        return {
            "action": "conclude",
            "reason": "api_key=reason-secret-12345",
            "hypothesis_updates": [
                {"id": "H1", "evidence_for": ["password=ledger-secret-12345"]}
            ],
        }

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    plan = InvestigationPlan(hypotheses=[{"family": "runai_scheduling_quota", "reason": "quota"}])

    _, context = await investigate(settings, make_target(), _collectors(), plan, {}, max_steps=2)

    serialized = str(context)
    for secret in [
        "reason-secret-12345",
        "ledger-secret-12345",
        "reflect-secret-12345",
        "newhyp-secret-12345",
    ]:
        assert secret not in serialized
    assert "[MASKED]" in serialized


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
async def test_reflection_receives_query_safe_shared_observations(monkeypatch) -> None:
    settings = replace(
        make_settings(), llm_base_url="https://llm.example/v1", llm_model="m", llm_api_key="k"
    )
    reflection_prompt = ""
    calls = 0

    async def fake_complete_json(settings, *, system, user, **_kwargs):
        nonlocal calls, reflection_prompt
        if "final skeptical reflection" in system:
            reflection_prompt = user
            return {"hypothesis_updates": [], "new_hypotheses": []}
        calls += 1
        if calls == 1:
            return {"action": "probe", "probes": [{"collector": "runai"}]}
        return {"action": "conclude"}

    monkeypatch.setattr("app.services.investigator.complete_json", fake_complete_json)
    await investigate(
        settings, make_target(), _collectors(), InvestigationPlan(), {}, max_steps=3, blackboard=Blackboard()
    )

    assert '"shared_observations"' in reflection_prompt
    assert "F-" in reflection_prompt


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
async def test_collector_exception_does_not_raise(monkeypatch) -> None:
    class RunaiCollectorBoom:
        async def collect(self, target, plan=None):
            raise RuntimeError("api_key=collector-boom-secret-12345")

    # class name -> "runai_collector_boom"; only the mapped names matter here.
    collectors = [RunaiCollectorBoom(), LokiCollector()]
    results, context = await investigate(
        make_settings(), make_target(), collectors, InvestigationPlan(), {}, max_steps=4
    )

    by_status = {r.status for r in results}
    assert by_status == {"unavailable", "ok"}
    assert len(results) == 2
    serialized = str(results)
    assert "collector-boom-secret-12345" not in serialized
    assert "RuntimeError" in serialized
