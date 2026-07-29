"""Clearly-labelled, non-diagnostic guidance for context-free requests.

This is deliberately separate from RCA remediation. It can reuse curated
catalogue actions, but never presents a keyword match as evidence that the
symptom or its cause is present in the current environment.
"""

from __future__ import annotations

from typing import Any

from app.knowledge import (
    component_action_lines,
    component_for_text,
    family_label,
    localized_failure_mode_actions,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)
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
    component: str = "",
    component_source: str = "",
    components: dict[str, dict[str, Any]] | None = None,
    matched_alert: dict[str, Any] | None = None,
    families: list[str] | None = None,
    case_cards: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Return optional next checks for a question without live evidence.

    Exact catalogue signature matches can narrow a generic guide, but they are
    always worded as conditional checks. Fuzzy matching is intentionally excluded:
    a context-free request should not gain a specific recommendation from loose
    text similarity.

    ``component`` and ``matched_alert`` come from the investigation plan and are
    the two retrieval paths that need no evidence at all: the component is the
    alert target's own identity (pod name -> architecture component) and the
    matched alert is a catalog entry resolved from the alert name. Without them
    an evidence-free run silently drops ontology the same run already retrieved.

    ``families`` are the planner's hypothesis families. The curated keywords are
    written to match EVIDENCE text (event and log strings such as "preempted by
    higher priority"), so a human question misses them in every language --
    "runai scheduling error" matches nothing at all. The planner LLM already read
    the operator's question, in whatever language it was asked, and named a
    family from the closed catalog; that name is the language-independent bridge
    into the ontology, and it costs no extra call. Unknown names simply find no
    symptoms, so a hallucinated family cannot invent guidance.

    ``case_cards`` are this run's retrieval-matched historical priors; only the
    ``kind == "external"`` ones (vendor-support cases) render here, as clearly
    labelled history. Without them, the one prior that answers "I already raised
    memory and it still dies" (Thanos Receive OOMKilled, stabilized by a CPU
    increase with memory unchanged) stayed invisible to the operator: it went
    only to LLM prompt surfaces, never the deterministic report.
    """
    active_masker = masker or build_masker(())
    lines = list(_BASE_LINES.get(language, _BASE_LINES["en"]))
    text = active_masker.mask_text(query or "")
    if not component:
        entry = component_for_text(components or {}, query)
        component = entry["component"] if entry else ""

    # Precision order mirrors the playbook: identity beats any keyword match.
    # The component is a fact about the target, so its checks are stated plainly
    # -- naming what to inspect is not a claim about what went wrong.
    if component:
        checks = component_action_lines(components or {}, component)
        if checks:
            name = _safe(component, active_masker, 120)
            lines.append(
                (
                    f"- 이 요청은 **{name}** 컴포넌트에 대한 것으로 해석되었습니다. "
                    "확인된 대상이 아니라 해석이며, 원인 확정 전 다음을 확인할 수 있습니다:"
                    if language == "ko"
                    else f"- This request was interpreted as being about the **{name}** component — "
                    "an interpretation, not a confirmed target. These can be checked:"
                )
                if component_source == "llm"
                else (
                    f"- 알림 대상이 **{name}** 컴포넌트입니다. "
                    "원인 확정 전이라도 다음을 확인할 수 있습니다:"
                    if language == "ko"
                    else f"- The alert target is the **{name}** component. Even before a cause "
                    "is confirmed, these can be checked:"
                )
            )
            lines.extend(f"  - {_safe(check, active_masker, 360)}" for check in checks[:4])

    alert_actions = [str(a) for a in (matched_alert or {}).get("actions", [])][:3]
    if alert_actions:
        alert_name = _safe(
            (matched_alert or {}).get("alert") or (matched_alert or {}).get("name"),
            active_masker,
            160,
        )
        lines.append(
            f"- 이 알림(**{alert_name}**)에 대한 문서화된 대응 절차입니다. "
            "현재 원인으로 확인된 내용은 아닙니다:"
            if language == "ko"
            else f"- Documented response steps for this alert (**{alert_name}**) — "
            "not a confirmed cause for the current run:"
        )
        lines.extend(f"  - {_safe(action, active_masker, 360)}" for action in alert_actions)

    lines.extend(_external_case_lines(case_cards or [], language, active_masker))

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

    symptom_matches = match_failure_mode_symptoms(failure_modes, text)[:2]
    for _family, symptom in symptom_matches:
        name = _safe(symptom.get("symptom"), active_masker, 180)
        actions = localized_failure_mode_actions(symptom, language)
        if not actions:
            continue
        lines.append(
            f"- 실제로 **{name}** 신호가 관찰된 경우에만 다음 조치를 검토하세요:"
            if language == "ko"
            else f"- Only if **{name}** is actually observed, consider:"
        )
        lines.extend(f"  - {_safe(action, active_masker, 360)}" for action in actions[:3])

    # Only as a fallback: an exact signature hit is a stronger reason to show a
    # symptom than the planner's reading of the question.
    if not symptom_matches:
        lines.extend(
            _family_candidate_lines(families or [], failure_modes, language, active_masker)
        )

    return lines


def _external_case_lines(
    case_cards: list[dict[str, Any]], language: str, masker: Masker
) -> list[str]:
    """Signature-matched vendor-support cases, as labelled history only.

    External cards are retrieval-matched against this run's own observed text
    and component identity, so they are target-specific — but their allowed use
    is historical context (``prohibited_uses: current_root_cause_proof``), so
    every line states outcome as what happened THEN, never as this run's cause.
    What was tried and did NOT work is included on purpose: it is exactly what
    stops an operator from repeating an already-failed fix.
    """
    lines: list[str] = []
    external = [c for c in case_cards if c.get("kind") == "external"]
    for card in external[:2]:
        summary = _safe(card.get("analysis_summary"), masker, 400)
        if not summary:
            continue
        ref = _safe(card.get("case_id") or card.get("incident_id"), masker, 100)
        status = _safe(card.get("context_class"), masker, 40)
        suffix = f", {status}" if status else ""
        lines.append(
            f"- 이 대상과 시그니처가 일치하는 외부 지원 사례가 있습니다 "
            f"(**{ref}**{suffix}). 현재 원인으로 확인된 것이 아닌 과거 기록입니다:"
            if language == "ko"
            else f"- An external support case matches this target's signature "
            f"(**{ref}**{suffix}). Historical record — not a confirmed cause for this run:"
        )
        lines.append(f"  - {'당시 경과' if language == 'ko' else 'What happened'}: {summary}")
        for action in list(card.get("successful_actions") or [])[:2]:
            statement = _safe(action.get("statement"), masker, 300)
            outcome = _safe(action.get("outcome"), masker, 20)
            if statement:
                label = "당시 효과 있었던 조치" if language == "ko" else "Action that helped then"
                lines.append(f"  - {label} ({outcome}): {statement}")
        for action in list(card.get("failed_actions") or [])[:2]:
            statement = _safe(action.get("statement"), masker, 300)
            if statement:
                label = "당시 효과 없었던 조치" if language == "ko" else "Action that did NOT help then"
                lines.append(f"  - {label}: {statement}")
    return lines


def _family_candidate_lines(
    families: list[str],
    failure_modes: dict[str, list[dict[str, Any]]],
    language: str,
    masker: Masker,
) -> list[str]:
    """Representative symptoms of the families the planner nominated.

    Presented as what to look for, never as what happened: no evidence was
    collected, and the family came from reading the request, not the cluster.
    """
    lines: list[str] = []
    for family in families[:2]:
        symptoms = [
            s
            for s in (failure_modes.get(family) or [])
            if localized_failure_mode_actions(s, language)
        ]
        if not symptoms:
            continue
        label = _safe(family_label(family), masker, 160)
        lines.append(
            f"- 이번 요청은 **{label}** 계열로 해석되었습니다. 확인된 원인이 아니라 "
            "이 계열에서 흔한 증상이며, 각 항목을 실제로 관찰했는지 먼저 확인하세요:"
            if language == "ko"
            else f"- This request was interpreted as **{label}**. These are the common "
            "symptoms of that family — not a confirmed cause; check whether any is "
            "actually present:"
        )
        for symptom in symptoms[:3]:
            name = _safe(symptom.get("symptom"), masker, 180)
            action = _safe(localized_failure_mode_actions(symptom, language)[0], masker, 300)
            lines.append(f"  - **{name}**: {action}")
    return lines


def _safe(value: object, masker: Masker, limit: int) -> str:
    text = " ".join(masker.mask_text(str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
