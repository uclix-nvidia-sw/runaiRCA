import asyncio
from dataclasses import replace

from app.services import knowledge_refine
from tests.test_orchestrator import make_settings


def llm_settings():
    return replace(
        make_settings(),
        llm_base_url="https://llm.example/v1",
        llm_model="m",
        llm_api_key="k",
    )


def test_without_llm_returns_trimmed_originals() -> None:
    actions, refined = asyncio.run(
        knowledge_refine.refine_actions(
            make_settings(), family="f", mechanism="m", actions=[" a ", "", "b"]
        )
    )
    assert actions == ["a", "b"]
    assert refined is False


def test_refines_instance_identifiers_and_reports_change(monkeypatch) -> None:
    async def fake_complete_json(settings, *, system, user, temperature=0.1, model=None):
        assert "nonexistent-secret" in user
        assert '"namespace": "default"' in user
        return {"actions": ["<namespace>에서 누락된 <secret-name> Secret을 생성하거나 참조를 수정하라"]}

    monkeypatch.setattr(knowledge_refine, "complete_json", fake_complete_json)
    actions, refined = asyncio.run(
        knowledge_refine.refine_actions(
            llm_settings(),
            family="workload_startup_error",
            mechanism="missing secret reference",
            actions=["kubectl get secret nonexistent-secret -n default 를 실행하여 확인하라"],
            context={"namespace": "default", "pod": "secret-error"},
        )
    )
    assert refined is True
    assert actions == ["<namespace>에서 누락된 <secret-name> Secret을 생성하거나 참조를 수정하라"]


def test_shape_mismatch_falls_back_to_originals(monkeypatch) -> None:
    async def fake_complete_json(*_args, **_kwargs):
        return {"actions": ["one", "two"]}

    monkeypatch.setattr(knowledge_refine, "complete_json", fake_complete_json)
    actions, refined = asyncio.run(
        knowledge_refine.refine_actions(
            llm_settings(), family="f", mechanism="m", actions=["only one"]
        )
    )
    assert actions == ["only one"]
    assert refined is False


def test_unparseable_response_falls_back(monkeypatch) -> None:
    async def fake_complete_json(*_args, **_kwargs):
        return None

    monkeypatch.setattr(knowledge_refine, "complete_json", fake_complete_json)
    actions, refined = asyncio.run(
        knowledge_refine.refine_actions(
            llm_settings(), family="f", mechanism="m", actions=["keep me"]
        )
    )
    assert actions == ["keep me"]
    assert refined is False
