from __future__ import annotations

import asyncio
from dataclasses import replace

from app.services.critic import apply_safe_patches, critique_claims, parse_critic_result
from app.services import pipeline
from tests.test_orchestrator import make_settings


def test_critic_finds_missing_support_and_returns_monotonic_patch() -> None:
    result = critique_claims(
        [{"claim_id": "C1", "kind": "root_cause", "confidence": "high", "supporting_evidence": []}],
        available_evidence_ids=["E01"],
    )

    assert result.status == "issues"
    assert {issue.code for issue in result.issues} == {"missing_support"}
    assert result.patches[0].op == "downgrade_confidence"
    assert (
        apply_safe_patches([{"claim_id": "C1", "confidence": "high"}], result)[0]["confidence"]
        == "medium"
    )


def test_critic_marks_contradicted_high_confidence_claim_and_has_noop() -> None:
    result = critique_claims(
        [
            {
                "claim_id": "C1",
                "kind": "root_cause",
                "confidence": "high",
                "supporting_evidence": ["E01"],
                "contradicting_evidence": ["E02"],
            }
        ],
        available_evidence_ids=["E01", "E02"],
    )
    assert any(issue.code == "unresolved_contradiction" for issue in result.issues)
    assert (
        apply_safe_patches([{"claim_id": "C1", "confidence": "high"}], result)[0]["confidence"]
        == "medium"
    )

    assert critique_claims(
        [
            {
                "claim_id": "C2",
                "kind": "observation",
                "confidence": "low",
                "supporting_evidence": ["E01"],
            }
        ],
        available_evidence_ids=["E01"],
    ).is_noop


def test_untrusted_critic_output_cannot_upgrade_or_invent_claims() -> None:
    result = parse_critic_result(
        {
            "issues": [{"claim_id": "C1", "code": "weak", "evidence_ids": ["E01", "missing"]}],
            "patches": [
                {"claim_id": "C1", "op": "downgrade_confidence", "value": "high"},
                {"claim_id": "unknown", "op": "mark_inferred", "value": "inferred"},
                {"claim_id": "C1", "op": "replace_report", "value": "hallucinated"},
            ],
        },
        claim_ids=["C1"],
        available_evidence_ids=["E01"],
    )

    assert result.issues[0].evidence_ids == ("E01",)
    assert result.is_noop is False
    assert result.patches == ()
    assert (
        apply_safe_patches([{"claim_id": "C1", "confidence": "medium"}], result)[0]["confidence"]
        == "medium"
    )


def test_semantic_critic_uses_default_model_when_no_override(monkeypatch) -> None:
    settings = replace(
        make_settings(), llm_base_url="https://llm.example/v1", llm_model="default-model", llm_api_key="key"
    )
    seen: list[str] = []

    async def fake_complete_json(settings, *, model=None, **_kwargs):
        seen.append(str(model))
        return {"issues": [], "patches": []}

    monkeypatch.setattr(pipeline, "complete_json", fake_complete_json)

    result = asyncio.run(
        pipeline._semantic_critic(settings, [{"claim_id": "C01"}], available_evidence_ids=["E01"])
    )

    assert result.is_noop
    assert seen == ["default-model"]
