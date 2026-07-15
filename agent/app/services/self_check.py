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

import json
from collections.abc import Mapping

from app.collectors.base import NO_EVIDENCE, CollectorResult, condition_observations
from app.config import Settings
from app.llm import complete_json, llm_configured
from app.masking import build_masker
from app.services.root_cause_ranking import (
    _FAMILY_RULES,
    RankedCause,
    artifact_supports_family,
)

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


def _canonical_has_evidence(
    family: str,
    results: list[CollectorResult],
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> bool:
    """True only when the canonical collector has scoped positive evidence.

    The ranker already rejects context-only observations. The deterministic
    self-check must use the same bar: otherwise a broad collector summary (or
    a raw usage metric) can preserve confidence after the ranker correctly
    refused to treat it as proof.
    """
    rule = _FAMILY_RULES.get(family)
    if not rule:
        return True  # unknown family (e.g. insufficient_evidence) — nothing to refute
    canonical = rule[0]
    for r in results:
        if r.agent != canonical:
            continue
        if r.status == "unavailable":
            return False
        return any(
            _artifact_has_evidence(
                family,
                art,
                evidence_eligibility=evidence_eligibility,
            )
            for art in getattr(r, "artifacts", []) or []
        )
    return False  # canonical collector did not even run


def _artifact_has_evidence(
    family: str,
    art: object,
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> bool:
    """Accept only an explicit scoped positive collector verdict.

    Keyword-bearing summaries are deliberately excluded: a condition's name,
    an HTTP success line, or a current snapshot is not a verified occurrence in
    the incident window.
    """
    # Pipeline callers have already normalized target, topology, run identity,
    # and incident window on the blackboard.  A raw artifact's local
    # ``present/scoped`` declaration is not enough here: otherwise an
    # observation from another Pod or a recovery-time query can preserve the
    # top RCA's confidence after ranking correctly excluded it.  Direct/unit
    # callers without a board retain the narrow artifact-local fallback.
    if evidence_eligibility is not None:
        evidence_id = str(getattr(art, "evidence_id", "") or "")
        eligibility = evidence_eligibility.get(evidence_id)
        permits = getattr(eligibility, "permits", None)
        return bool(
            callable(permits)
            and permits("support")
            and artifact_supports_family(family, art)
        )

    result = getattr(art, "result", None)
    if not isinstance(result, Mapping):
        return False
    observation = result.get("observation")
    if not isinstance(observation, Mapping):
        return False
    return bool(
        str(observation.get("polarity") or "").strip().lower() == "present"
        and str(observation.get("coverage") or "").strip().lower() == "scoped"
        and artifact_supports_family(family, art)
    )


async def refute_top_cause(
    settings: Settings,
    top_candidate: RankedCause,
    results: list[CollectorResult],
    plan: object = None,
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> dict:
    """Try to refute the top cause; return {confidence, caveat, refuted}."""
    try:
        confidence = getattr(top_candidate, "confidence", "low")
        family = getattr(top_candidate, "family", "")
        # Nothing to refute when there is no positive claim.
        if not family or family == "insufficient_evidence":
            return _default(confidence)

        has_evidence = _canonical_has_evidence(
            family, results, evidence_eligibility=evidence_eligibility
        ) or _has_signature_evidence(
            top_candidate,
            results,
            evidence_eligibility=evidence_eligibility,
        )

        if not llm_configured(settings, settings.llm_model_self_check):
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

        verdict = await _llm_refute(settings, top_candidate, results, has_evidence, plan)
        if not verdict:
            # LLM failed/empty: fall back to the deterministic gate.
            if not has_evidence:
                return _default(
                    _downgrade(confidence),
                    _caveat_missing_evidence(family, settings),
                    next_check=_next_check_missing_evidence(family, settings),
                )
            return _default(confidence)

        # The model may use context to explain/refute a hypothesis, but it must
        # never turn that context into support.  ``has_evidence`` is computed
        # deterministically from a scoped positive canonical observation (or a
        # direct alert signature), so it is the upper bound on the verdict.
        supported = bool(verdict.get("supported", True)) and has_evidence
        masker = _self_check_masker(settings)
        caveat = _one_line(masker.mask_text(str(verdict.get("caveat") or "")), limit=360)
        next_check = _one_line(
            masker.mask_text(str(verdict.get("next_check") or "")), limit=240
        )
        if not has_evidence:
            caveat = caveat or _caveat_missing_evidence(family, settings)
            next_check = next_check or _next_check_missing_evidence(family, settings)
        new_conf = confidence if supported else _downgrade(confidence)
        # Also honour an explicit weaker confidence from the model, never a stronger one.
        model_conf = str(verdict.get("confidence") or "").strip().lower()
        if model_conf in _CONF_ORDER:
            if _CONF_ORDER.index(model_conf) < _CONF_ORDER.index(new_conf):
                new_conf = model_conf
        return _default(new_conf, caveat, refuted=not supported, next_check=next_check)
    except Exception:  # noqa: BLE001 - self-check is best-effort; never break analyze()
        return _default(getattr(top_candidate, "confidence", "low"))


def _one_line(value: object, *, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


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


def _has_signature_evidence(
    top_candidate: RankedCause,
    results: list[CollectorResult],
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> bool:
    """Accept a signature bypass only when it resolves to auditable evidence.

    Standalone legacy callers have no blackboard/ID map, so retain their narrow
    rationale fallback.  Production pipeline callers always provide the map;
    there a signature must be a typed, scoped artifact whose predicate supports
    the selected family (for example the alert's NVIDIA XID card).
    """
    if evidence_eligibility is not None:
        return any(
            _artifact_has_evidence(
                top_candidate.family,
                art,
                evidence_eligibility=evidence_eligibility,
            )
            for result in results
            for art in (getattr(result, "artifacts", []) or [])
        )
    agents = {str(a).lower() for a in getattr(top_candidate, "evidence_agents", [])}
    rationale = " ".join(getattr(top_candidate, "rationale", [])).lower()
    return ("signature" in agents or "alert" in agents) and (
        "matched known-issue signature" in rationale
        or "matched curated symptom" in rationale
        or "nvidia xid" in rationale
    )


def _compact_evidence_value(value: object, *, limit: int = 1200) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(value)
    text = " ".join(text.split())
    return text[:limit]


def _evidence_digest(results: list[CollectorResult], masker) -> str:
    lines: list[str] = []
    for r in results:
        summary = (r.summary or "").strip() or NO_EVIDENCE
        lines.append(f"- {r.agent} [{r.status}]: {masker.mask_text(summary)}")
        selected = [
            art for art in (getattr(r, "artifacts", []) or []) if art.status in ("ok", "partial")
        ]
        selected = [
            art
            for _index, art in sorted(
                sorted(
                    enumerate(selected),
                    key=lambda item: (bool(item[1].highlights), item[1].status == "ok", item[0]),
                    reverse=True,
                )[:6]
            )
        ]
        for art in selected:
            parts = [
                str(art.title or art.type or "artifact").strip(),
                f"status={art.status}",
            ]
            if art.query:
                parts.append(f"query={_compact_evidence_value(art.query, limit=400)}")
            if art.summary:
                parts.append(f"summary={_compact_evidence_value(art.summary, limit=600)}")
            if art.highlights:
                parts.append(f"highlights={', '.join(map(str, art.highlights[:6]))}")
            if art.result is not None:
                checks = condition_observations(art.result)
                if checks:
                    parts.append(f"condition_checks={_compact_evidence_value(checks)}")
                parts.append(f"result={_compact_evidence_value(art.result)}")
            lines.append(f"  artifact: {masker.mask_text(' | '.join(parts))}")
    return "\n".join(lines)


async def _llm_refute(
    settings: Settings,
    top: RankedCause,
    results: list[CollectorResult],
    has_evidence: bool,
    plan: object = None,
) -> dict | None:
    ko = getattr(settings, "language", "en") == "ko"
    masker = _self_check_masker(settings)
    evidence = _evidence_digest(results, masker)
    caveat_lang = "Korean" if ko else "English"
    system = (
        "You are a skeptical senior SRE reviewing a proposed root cause for a Run:ai "
        "GPU-platform alert. Your job is to TRY TO REFUTE it using ONLY the gathered "
        "evidence below. Ask: what evidence would we expect if this cause were true, is "
        "it actually present, does a competing cause fit the evidence better, and what "
        "single check would settle it. Do not invent evidence. Be conservative: if the "
        "evidence does not clearly support the cause, mark it unsupported. A condition "
        "name alone is metadata: only condition_checks active=true supports it, while "
        "active=false is contradicting evidence. A collector summary and an artifact "
        "whose observation is unknown/partial are context only: they can refute or "
        "suggest a next check, but can never support the proposed cause. The \"Specific "
        "or canonical evidence present\" flag is authoritative; when false, you MUST "
        "return supported=false.\n"
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
        f"Specific or canonical evidence present: {has_evidence}\n"
        f"Rationale: {masker.mask_text('; '.join(top.rationale) or '(none)')}\n\n"
        f"Hypothesis ledger: {masker.mask_text(_hypothesis_ledger_hint(plan))}\n\n"
        f"Gathered evidence:\n{evidence}"
    )
    return await complete_json(
        settings,
        system=system,
        user=user,
        temperature=0.1,
        model=settings.llm_model_self_check,
    )


def _hypothesis_ledger_hint(plan: object) -> str:
    if not isinstance(plan, dict):
        return "(none)"
    ledger = plan.get("hypothesis_ledger")
    if not ledger:
        return "(none)"
    return str(ledger)[:2000]


async def verify_matches(
    settings: Settings,
    candidates: list[dict],
    results: list[CollectorResult],
    *,
    subject: str = "candidate finding",
    declared_alert: str = "",
) -> set[str]:
    """Names of signature/keyword-matched candidates the evidence does NOT support.

    A skeptical LLM pass over matches (known issues, failure-mode symptoms, GPU XIDs):
    keyword/signature hits can be superficial, so it flags the ones the gathered
    evidence doesn't actually back — the caller suppresses those. LLM-gated and
    conservative: with no LLM configured, or on any failure/uncertainty, returns an
    empty set so the match stands by default. Never raises into analyze().

    Each candidate is {"name": str, "detail": str}; returned names are a subset of the
    candidate names (hallucinated names are dropped).
    """
    try:
        names = {str(c.get("name") or "").strip() for c in candidates}
        names.discard("")
        if not names or not llm_configured(settings, settings.llm_model_self_check):
            return set()
        verdict = await _llm_verify_matches(
            settings,
            candidates,
            results,
            subject,
            declared_alert=declared_alert,
        )
        refuted = (verdict or {}).get("refuted")
        if not isinstance(refuted, list):
            return set()
        return {str(n).strip() for n in refuted if str(n).strip() in names}
    except Exception:  # noqa: BLE001 - best-effort; never break analyze()
        return set()


async def verify_known_issues(
    settings: Settings,
    issues: list[dict],
    results: list[CollectorResult],
    *,
    declared_alert: str = "",
) -> set[str]:
    """Suppress keyword-matched known issues the evidence doesn't support (see verify_matches)."""
    candidates = [
        {"name": str(i.get("issue") or "").strip(), "detail": str(i.get("reason") or "")}
        for i in issues
    ]
    return await verify_matches(
        settings,
        candidates,
        results,
        subject="known Run:ai issue",
        declared_alert=declared_alert,
    )


async def _llm_verify_matches(
    settings: Settings,
    candidates: list[dict],
    results: list[CollectorResult],
    subject: str,
    *,
    declared_alert: str = "",
) -> dict | None:
    masker = _self_check_masker(settings)
    evidence = _evidence_digest(results, masker)
    cand = "\n".join(
        f"- {str(c.get('name') or '').strip()}: "
        f"{masker.mask_text(' '.join(str(c.get('detail') or '').split()))}"
        for c in candidates
    )
    system = (
        f"You are a skeptical senior SRE. Each {subject} below matched this alert's "
        "evidence by keyword or signature. Matches can be superficial, so decide which "
        "the gathered evidence does NOT actually support. Use ONLY the evidence; do not "
        "invent any. Be conservative: refute a match only when the evidence clearly does "
        "not fit — when unsure, keep it. The declared alert payload is a source "
        "observation, not a collector result: an explicit positive signature there may "
        "support a match even when collectors no longer retain the event, but false, "
        'normal, recovered, or negated values do not. Respond with a JSON object: {"refuted": [exact '
        'names that are NOT supported by the evidence]}.'
    )
    safe_alert = masker.mask_text(" ".join(str(declared_alert or "").split()))
    user = (
        f"Candidates:\n{cand}\n\nDeclared alert payload:\n"
        f"{safe_alert or '(not supplied)'}\n\nGathered collector evidence:\n{evidence}"
    )
    return await complete_json(
        settings,
        system=system,
        user=user,
        temperature=0.1,
        model=settings.llm_model_self_check,
    )


def _self_check_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )
