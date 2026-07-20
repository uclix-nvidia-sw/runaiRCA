"""Regression for the Korean-synthesis semantic guard.

An enumerated, inconclusive, or probe-command mention of a node/scheduler signal
is a thing to inspect, not an asserted claim. Treating it as a positive claim
discarded correct Korean synthesis and forced the English deterministic
fallback even with LANGUAGE=ko and a live LLM (observed 2026-07-20).
"""

from app.services.pipeline import (
    _synthesis_fragment_asserts_signal,
    _synthesis_signal_mentions,
)


def _first_mention(fragment: str, term: str) -> tuple[int, int]:
    mentions = _synthesis_signal_mentions(fragment, (term,))
    assert mentions, f"term {term!r} not found in fragment"
    return mentions[0]


# --- Non-assertive contexts that must NOT be flagged (real rejected fragments) ---


def test_enumeration_condition_is_not_asserted() -> None:
    fragment = (
        "- **추론(Inference)**: 알림은 GPU 노드 Ready 조건 불충분을 가리키나, "
        "노드 컨디션(MemoryPressure/DiskPressure/PIDPressure/NetworkUnavailable), "
        "kubelet 로그, DCGM/GPU 드라이버 에러를 확인해야 합니다."
    )
    start, end = _first_mention(fragment, "networkunavailable")
    assert _synthesis_fragment_asserts_signal(fragment, start, end) is False


def test_inconclusive_enumeration_is_not_asserted() -> None:
    fragment = (
        "`k8s_troubleshooting:node_not_ready:p01` 프로브 실행 결과 `inconclusive` — "
        "노드 조건(Ready, MemoryPressure, DiskPressure, PIDPressure) 전환 증거 미확보 [E100]"
    )
    start, end = _first_mention(fragment, "memorypressure")
    assert _synthesis_fragment_asserts_signal(fragment, start, end) is False


def test_probe_command_enumeration_is_not_asserted() -> None:
    fragment = (
        "`kubectl logs -n runai deploy/runai-scheduler-default --tail=200`로 "
        "스케줄러 결정 로그(quota/gang/preempt/reclaim) 검토."
    )
    start, end = _first_mention(fragment, "preempt")
    assert _synthesis_fragment_asserts_signal(fragment, start, end) is False


# --- Genuine assertions must STILL be flagged (guard not gutted) ---


def test_direct_cause_claim_is_still_asserted() -> None:
    fragment = "근본 원인은 NetworkUnavailable 입니다."
    start, end = _first_mention(fragment, "networkunavailable")
    assert _synthesis_fragment_asserts_signal(fragment, start, end) is True


def test_confirmed_cause_claim_is_still_asserted() -> None:
    fragment = "MemoryPressure 가 원인으로 확인되었습니다."
    start, end = _first_mention(fragment, "memorypressure")
    assert _synthesis_fragment_asserts_signal(fragment, start, end) is True
