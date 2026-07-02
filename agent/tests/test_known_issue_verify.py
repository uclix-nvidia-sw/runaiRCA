"""Adversarial verification of keyword-matched known issues: an LLM refutes ones
the evidence doesn't support; conservative and LLM-gated (no LLM -> no-op)."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from app.services import self_check
from tests.test_orchestrator import make_settings

_ISSUES = [{"issue": "A", "reason": "x"}, {"issue": "B", "reason": "y"}]


def _llm_settings():
    return replace(make_settings(), llm_base_url="http://x", llm_model="m", llm_api_key="k")


def test_no_llm_is_noop() -> None:
    # Without an LLM the keyword match stands — nothing suppressed.
    assert asyncio.run(self_check.verify_known_issues(make_settings(), _ISSUES, [])) == set()


def test_empty_issues_is_noop() -> None:
    assert asyncio.run(self_check.verify_known_issues(_llm_settings(), [], [])) == set()


def test_refutes_only_named_valid_candidates(monkeypatch) -> None:
    async def _fake(*_a, **_k):
        return {"refuted": ["B", "ghost"]}  # 'ghost' is not a candidate -> ignored

    monkeypatch.setattr(self_check, "complete_json", _fake)
    out = asyncio.run(self_check.verify_known_issues(_llm_settings(), _ISSUES, []))
    assert out == {"B"}


def test_malformed_verdict_is_safe(monkeypatch) -> None:
    async def _fake(*_a, **_k):
        return {"refuted": "not-a-list"}

    monkeypatch.setattr(self_check, "complete_json", _fake)
    assert asyncio.run(self_check.verify_known_issues(_llm_settings(), _ISSUES, [])) == set()


def test_verify_matches_generic_symptom_and_xid(monkeypatch) -> None:
    # The verification is generic: failure-mode symptoms and GPU XIDs are verified
    # the same way as known issues.
    async def _fake(*_a, **_k):
        return {"refuted": ["OOMKilled", "XID 45"]}

    monkeypatch.setattr(self_check, "complete_json", _fake)
    candidates = [
        {"name": "OOMKilled", "detail": "workload_startup — raise the memory limit"},
        {"name": "XID 45", "detail": "reset the GPU"},
        {"name": "ImagePullBackOff", "detail": "check the registry"},  # kept
    ]
    out = asyncio.run(self_check.verify_matches(_llm_settings(), candidates, [], subject="match"))
    assert out == {"OOMKilled", "XID 45"}
