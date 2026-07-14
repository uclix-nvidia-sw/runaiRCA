"""Clearly-labelled, non-diagnostic guidance for context-free requests.

This is deliberately separate from RCA remediation. It can reuse curated
catalogue actions, but never presents a keyword match as evidence that the
symptom or its cause is present in the current environment.
"""

from __future__ import annotations

from typing import Any

from app.knowledge import match_failure_mode_symptoms, match_runai_known_issues
from app.masking import Masker, build_masker

_BASE_LINES = {
    "en": [
        "- This is general troubleshooting guidance, not a diagnosis or confirmation that "
        "the problem is occurring now.",
        "- First identify the affected workload/pod/node, namespace, and time window; then "
        "check Kubernetes events and pod status, relevant Run:ai queue/project state, and "
        "logs or metrics from that same window.",
        "- Treat the conditional steps below as checks to validate before making a change.",
    ],
    "ko": [
        "- 현재 인시던트의 live evidence가 없으므로, 아래 내용은 일반 점검 가이드이며 "
        "원인이나 해결을 확인한 결론이 아닙니다.",
        "- 먼저 영향받은 워크로드/파드/노드, namespace, 발생 시각을 정한 뒤 같은 시간대의 "
        "Kubernetes 이벤트·파드 상태, Run:ai queue/project 상태, 로그·메트릭을 확인하세요.",
        "- 아래의 조건부 조치는 실제 신호를 확인한 뒤에만 적용하세요.",
    ],
}


def general_guidance_lines(
    query: str,
    failure_modes: dict[str, list[dict[str, Any]]],
    known_issues: list[dict[str, Any]],
    *,
    language: str = "en",
    masker: Masker | None = None,
) -> list[str]:
    """Return optional next checks for a question without live evidence.

    Exact catalogue signature matches can narrow a generic guide, but they are
    always worded as conditional checks. Fuzzy matching is intentionally excluded:
    a context-free request should not gain a specific recommendation from loose
    text similarity.
    """
    active_masker = masker or build_masker(())
    lines = list(_BASE_LINES.get(language, _BASE_LINES["en"]))
    text = active_masker.mask_text(query or "")

    for issue in match_runai_known_issues(known_issues, text)[:2]:
        name = _safe(issue.get("issue"), active_masker, 180)
        lines.append(
            f"- 질문의 문구가 알려진 이슈 **{name}**와 정확히 일치하는 경우에만 "
            "다음을 확인하세요:"
            if language == "ko"
            else f"- Only if the question's wording matches the known issue **{name}**, check:"
        )
        lines.extend(
            f"  - {_safe(action, active_masker, 360)}" for action in issue.get("actions", [])[:3]
        )

    for _family, symptom in match_failure_mode_symptoms(failure_modes, text)[:2]:
        name = _safe(symptom.get("symptom"), active_masker, 180)
        actions = symptom.get("actions") or []
        if not actions:
            continue
        lines.append(
            f"- 실제로 **{name}** 신호가 관찰된 경우에만 다음 조치를 검토하세요:"
            if language == "ko"
            else f"- Only if **{name}** is actually observed, consider:"
        )
        lines.extend(f"  - {_safe(action, active_masker, 360)}" for action in actions[:3])

    return lines


def _safe(value: object, masker: Masker, limit: int) -> str:
    text = " ".join(masker.mask_text(str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
