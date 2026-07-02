"""Adversarial self-check + calibrated confidence for the top ranked cause.

After ranking, a skeptical senior SRE tries to *refute* the top candidate using
ONLY the gathered evidence: what would we expect to see if this cause were true,
is it actually present, does a competing cause fit better, and what single check
would settle it. If the evidence doesn't support the cause, confidence is
downgraded and a short caveat is attached.

LLM-gated: with no LLM configured the deterministic fallback fires — if the top
family's canonical collector reported no usable evidence (unavailable / NO_EVIDENCE),
confidence drops one level with a generic caveat. Otherwise confidence is kept.

Never raises into analyze(): any failure returns a safe default that preserves
the ranked confidence with no caveat.

Return value is a `dict` (confidence/caveat/refuted/next_check) so callers can inspect it;
its str() is the caveat text so the orchestrator can append it to the report
verbatim.
"""

from __future__ import annotations

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.config import Settings
from app.llm import complete_json, llm_configured
from app.services.root_cause_ranking import _FAMILY_RULES, RankedCause

_CONF_ORDER = ("low", "medium", "high")


class _Result(dict):
    """dict with a str() that yields the caveat, for verbatim report append."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.get("caveat") or "")


def _default(
    confidence: str, caveat: str = "", refuted: bool = False, next_check: str = ""
) -> _Result:
    return _Result(
        confidence=confidence, caveat=caveat, refuted=refuted, next_check=next_check
    )


def _downgrade(confidence: str) -> str:
    try:
        return _CONF_ORDER[max(0, _CONF_ORDER.index(confidence) - 1)]
    except ValueError:
        return "low"


def _canonical_has_evidence(family: str, results: list[CollectorResult]) -> bool:
    """True when the family's canonical collector returned usable evidence."""
    rule = _FAMILY_RULES.get(family)
    if not rule:
        return True  # unknown family (e.g. insufficient_evidence) — nothing to refute
    canonical = rule[0]
    for r in results:
        if r.agent != canonical:
            continue
        if r.status == "unavailable":
            return False
        summary = (r.summary or "").strip()
        return bool(summary) and summary != NO_EVIDENCE
    return False  # canonical collector did not even run


async def refute_top_cause(
    settings: Settings,
    top_candidate: RankedCause,
    results: list[CollectorResult],
    plan: object = None,
) -> dict:
    """Try to refute the top cause; return {confidence, caveat, refuted}."""
    try:
        confidence = getattr(top_candidate, "confidence", "low")
        family = getattr(top_candidate, "family", "")
        # Nothing to refute when there is no positive claim.
        if not family or family == "insufficient_evidence":
            return _default(confidence)

        has_evidence = _canonical_has_evidence(family, results)

        if not llm_configured(settings):
            # ponytail: deterministic gate — the only signal we have without an LLM
            # is whether the canonical source actually backed the claim.
            if not has_evidence:
                return _default(
                    _downgrade(confidence),
                    _caveat_missing_evidence(family, settings),
                    refuted=False,
                    next_check=_next_check_missing_evidence(family, settings),
                )
            return _default(confidence)

        verdict = await _llm_refute(settings, top_candidate, results, has_evidence)
        if not verdict:
            # LLM failed/empty: fall back to the deterministic gate.
            if not has_evidence:
                return _default(
                    _downgrade(confidence),
                    _caveat_missing_evidence(family, settings),
                    next_check=_next_check_missing_evidence(family, settings),
                )
            return _default(confidence)

        supported = bool(verdict.get("supported", True))
        caveat = str(verdict.get("caveat") or "").strip()
        next_check = str(verdict.get("next_check") or "").strip()
        new_conf = confidence if supported else _downgrade(confidence)
        # Also honour an explicit weaker confidence from the model, never a stronger one.
        model_conf = str(verdict.get("confidence") or "").strip().lower()
        if model_conf in _CONF_ORDER:
            if _CONF_ORDER.index(model_conf) < _CONF_ORDER.index(new_conf):
                new_conf = model_conf
        return _default(new_conf, caveat, refuted=not supported, next_check=next_check)
    except Exception:  # noqa: BLE001 - self-check is best-effort; never break analyze()
        return _default(getattr(top_candidate, "confidence", "low"))


def _caveat_missing_evidence(family: str, settings: Settings) -> str:
    canonical = _FAMILY_RULES.get(family, ("the canonical source",))[0]
    if getattr(settings, "language", "en") == "ko":
        return (
            f"자기 점검: 이 원인의 핵심 근거 수집기({canonical})에서 증거를 확인하지 못해 "
            "신뢰도를 한 단계 낮췄습니다. 결론 전에 해당 소스를 직접 확인하세요."
        )
    return (
        f"Self-check: the canonical evidence source ({canonical}) for this cause returned "
        "no usable evidence, so confidence was lowered one level. Verify that source directly "
        "before acting."
    )


def _next_check_missing_evidence(family: str, settings: Settings) -> str:
    """The single settling check for the deterministic missing-evidence gate."""
    canonical = _FAMILY_RULES.get(family, ("the canonical source",))[0]
    if getattr(settings, "language", "en") == "ko":
        return f"핵심 근거 수집기({canonical})에서 이 원인의 증거를 직접 확인해 주세요."
    return f"Check the canonical evidence source ({canonical}) directly for this cause."


async def _llm_refute(
    settings: Settings,
    top: RankedCause,
    results: list[CollectorResult],
    has_evidence: bool,
) -> dict | None:
    ko = getattr(settings, "language", "en") == "ko"
    evidence = "\n".join(
        f"- {r.agent} [{r.status}]: {(r.summary or '').strip() or NO_EVIDENCE}" for r in results
    )
    caveat_lang = "Korean" if ko else "English"
    system = (
        "You are a skeptical senior SRE reviewing a proposed root cause for a Run:ai "
        "GPU-platform alert. Your job is to TRY TO REFUTE it using ONLY the gathered "
        "evidence below. Ask: what evidence would we expect if this cause were true, is "
        "it actually present, does a competing cause fit the evidence better, and what "
        "single check would settle it. Do not invent evidence. Be conservative: if the "
        "evidence does not clearly support the cause, mark it unsupported.\n"
        f"Write the caveat and next_check in {caveat_lang}. Respond with a JSON object: "
        '{"supported": bool, "confidence": "low|medium|high", "caveat": str, '
        '"next_check": str}. '
        "The caveat is one or two sentences naming the strongest doubt and the single "
        "check that would settle it; next_check is that single settling check phrased "
        "as one concrete instruction to the operator."
    )
    user = (
        f"Proposed root cause family: {top.family}\n"
        f"Ranked confidence: {top.confidence}\n"
        f"Canonical source has usable evidence: {has_evidence}\n"
        f"Rationale: {'; '.join(top.rationale) or '(none)'}\n\n"
        f"Gathered evidence:\n{evidence}"
    )
    return await complete_json(settings, system=system, user=user, temperature=0.1)


async def verify_known_issues(
    settings: Settings,
    issues: list[dict],
    results: list[CollectorResult],
) -> set[str]:
    """Names of keyword-matched known issues the evidence does NOT actually support.

    Signature keyword hits can be superficial, so a skeptical LLM pass checks each
    matched known issue against the evidence and flags the ones that don't really
    fit — those get suppressed by the caller. LLM-gated and conservative: with no
    LLM configured, or on any failure/uncertainty, returns an empty set so the
    keyword match stands by default. Never raises into analyze().
    """
    try:
        names = {str(i.get("issue") or "").strip() for i in issues}
        names.discard("")
        if not names or not llm_configured(settings):
            return set()
        verdict = await _llm_verify_known_issues(settings, issues, results)
        refuted = (verdict or {}).get("refuted")
        if not isinstance(refuted, list):
            return set()
        # Only honour names that were actually candidates (guard against hallucinated names).
        return {str(n).strip() for n in refuted if str(n).strip() in names}
    except Exception:  # noqa: BLE001 - best-effort; never break analyze()
        return set()


async def _llm_verify_known_issues(
    settings: Settings,
    issues: list[dict],
    results: list[CollectorResult],
) -> dict | None:
    evidence = "\n".join(
        f"- {r.agent} [{r.status}]: {(r.summary or '').strip() or NO_EVIDENCE}" for r in results
    )
    candidates = "\n".join(
        f"- {str(i.get('issue') or '').strip()}: "
        f"{' '.join(str(i.get('reason') or '').split())}"
        for i in issues
    )
    system = (
        "You are a skeptical senior SRE. Each candidate below is a KNOWN Run:ai issue "
        "that matched this alert's evidence by keyword. Keyword matches can be "
        "superficial, so decide which candidates the gathered evidence does NOT "
        "actually support. Use ONLY the evidence; do not invent any. Be conservative: "
        "refute a candidate only when the evidence clearly does not fit — when unsure, "
        'keep it. Respond with a JSON object: {"refuted": [exact issue names that are '
        'NOT supported by the evidence]}.'
    )
    user = f"Candidate known issues:\n{candidates}\n\nGathered evidence:\n{evidence}"
    return await complete_json(settings, system=system, user=user, temperature=0.1)
