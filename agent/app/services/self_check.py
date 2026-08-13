"""Adversarial self-check + calibrated confidence for the top ranked cause.

After ranking, a skeptical senior SRE tries to *refute* the top candidate using
ONLY the gathered evidence: what would we expect to see if this cause were true,
is it actually present, does a competing cause fit better, and what single check
would settle it. If the evidence doesn't support the cause, confidence is
downgraded and a short caveat is attached.

LLM-gated: with no LLM configured the deterministic fallback fires. A scoped
absence that directly contradicts the family always refutes the candidate.
For a caller that passes a real evidence_eligibility map, missing eligible
evidence (no eligible collector supplied a family-relevant scoped positive
fact) only refutes when the family was promoted by a DISPOSITIVE signature
(NVIDIA XID / a typed, machine-reported Kubernetes state -- see
_is_signature_promoted): that is a specific, verified claim, and no evidence
means there was never anything behind it. Every other family with no eligible
evidence -- ranker-derived, or promoted only by a curated known-issue/symptom
keyword hit against the alert's own prose -- is merely unconfirmed, not
refuted, so confidence only drops one level. The LLM path applies the same
conditional; a model's own supported=false can still refute when eligible
evidence DOES exist but the model finds it unconvincing. A standalone/legacy
caller (evidence_eligibility=None) skips this conditional entirely and keeps
the original unconditional gate, since it has no rigorous eligibility
computation to reason about.

Never raises into analyze(): any failure returns a safe default that preserves
the ranked confidence with no caveat.

Return value is a `dict` (confidence/caveat/refuted/next_check) so callers can inspect it;
its str() is the caveat text so the orchestrator can append it to the report
verbatim.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping

from app.collectors.base import NO_EVIDENCE, CollectorResult, condition_observations
from app.config import Settings
from app.llm import complete_json, llm_configured
from app.masking import build_masker
from app.services.evidence_projection import observed_payload
from app.services.root_cause_ranking import (
    _FAMILY_RULES,
    RankedCause,
    artifact_contradicts_family,
    artifact_supports_family,
)

_log = logging.getLogger(__name__)

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


_DISPOSITIVE_SIGNATURE_KINDS = frozenset({"nvidia_xid", "typed_container_state"})


def _is_signature_promoted(top: RankedCause) -> bool:
    """True when the headline is a DISPOSITIVE signature, not a keyword hint.

    ``harness._signature_support`` treats every signature-promotion call site
    in pipeline.py alike (checking ``"signature" in top.evidence_agents`` OR a
    rationale substring). We instead read the structured ``score_breakdown``
    ``kind`` -- pipeline.py stamps one of four: ``nvidia_xid``,
    ``typed_container_state``, ``known_issue``, ``curated_symptom`` -- and only
    treat the first two as "signature-promoted" for this refutation gate.

    That split is deliberate, not an oversight: NVIDIA XID and a typed,
    machine-reported Kubernetes reason are verified structured facts, so no
    eligible evidence behind them is genuinely anomalous ("there was never
    anything behind it"). known_issue/curated_symptom are keyword hits against
    the alert's own free-form prose -- inherently a heuristic hint, not a
    verified fact -- so with no eligible evidence they are simply unconfirmed,
    same as a ranker-derived family. Proven empirically: treating those two
    kinds as refutable-on-missing-evidence broke ~14 curated-symptom/known-
    issue scenarios in tests/test_troubleshooting_scenarios.py (e.g.
    admission-webhook x509 -> k8s_control_plane_error), which never simulate
    real collector evidence and rely on exactly this leniency.
    """
    return any(
        isinstance(entry, Mapping)
        and str(entry.get("stage") or "").strip().lower() == "signature"
        and str(entry.get("kind") or "").strip().lower() in _DISPOSITIVE_SIGNATURE_KINDS
        for entry in getattr(top, "score_breakdown", None) or []
    )


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


def _deterministic_gate(
    confidence: str,
    family: str,
    settings: Settings,
    *,
    has_evidence: bool,
    has_contradiction: bool,
    missing_evidence_refutes: bool,
) -> _Result:
    """Shared body of the no-LLM gate and the LLM-returned-nothing fallback.

    Factored out so the two callers cannot re-diverge the way the
    LLM-verdict-present path once diverged from them: a scoped contradiction
    always refutes; missing eligible evidence only refutes a signature-
    promoted family (``missing_evidence_refutes``), otherwise it just
    downgrades confidence one level (unconfirmed, not refuted).
    """
    if not has_evidence or has_contradiction:
        return _default(
            _downgrade(confidence),
            (
                _caveat_contradiction(family, settings)
                if has_contradiction
                else _caveat_missing_evidence(family, settings)
            ),
            refuted=has_contradiction or missing_evidence_refutes,
            next_check=_next_check_missing_evidence(family, settings),
        )
    return _default(confidence)


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

        has_evidence = _has_family_evidence(
            family, results, evidence_eligibility=evidence_eligibility
        ) or _has_signature_evidence(
            top_candidate,
            results,
            evidence_eligibility=evidence_eligibility,
        )
        has_contradiction = _has_family_contradiction(
            family, results, evidence_eligibility=evidence_eligibility
        )
        # OWNER DECISION: "no eligible evidence" refutes a family only when it
        # was promoted by a DISPOSITIVE signature (NVIDIA XID / typed
        # Kubernetes-reported state -- see _is_signature_promoted) -- a
        # specific claim with nothing behind it. A ranker-derived family
        # (including a curated known-issue/symptom keyword hint) with no
        # eligible evidence is merely unconfirmed, so it is only downgraded
        # one level, never refuted on that basis alone.
        #
        # Scoped to callers that pass a real evidence_eligibility map: a
        # standalone/legacy caller (map is None) has no rigorous eligibility
        # computation behind has_evidence/has_contradiction at all (see
        # _artifact_has_evidence's narrow local fallback), so this conditional
        # does not apply there -- it keeps the original unconditional gate.
        eligibility_aware = evidence_eligibility is not None
        missing_evidence_refutes = (
            eligibility_aware
            and not has_evidence
            and _is_signature_promoted(top_candidate)
        )

        if not llm_configured(settings, settings.llm_model_self_check):
            return _deterministic_gate(
                confidence,
                family,
                settings,
                has_evidence=has_evidence,
                has_contradiction=has_contradiction,
                missing_evidence_refutes=missing_evidence_refutes,
            )

        verdict = await _llm_refute(
            settings,
            top_candidate,
            results,
            has_evidence,
            has_contradiction,
            plan,
            evidence_eligibility=evidence_eligibility,
        )
        if not verdict:
            # LLM failed/empty: fall back to the deterministic gate above.
            _log.warning("self-check LLM returned no verdict; using deterministic gate")
            return _deterministic_gate(
                confidence,
                family,
                settings,
                has_evidence=has_evidence,
                has_contradiction=has_contradiction,
                missing_evidence_refutes=missing_evidence_refutes,
            )

        # The model may use context to explain/refute a hypothesis, but it must
        # never turn that context into support on its own. A direct
        # contradiction always refutes. For an eligibility-aware caller,
        # missing evidence with no contradiction refutes only a signature-
        # promoted family (missing_evidence_refutes above); a ranker-derived
        # family instead gets the same one-level downgrade as the
        # deterministic gate, regardless of the model's own "supported"
        # opinion, so all three paths agree on the unconfirmed-not-refuted
        # contract. A standalone/legacy caller (no eligibility map) keeps the
        # original formula below, where has_evidence is an unconditional
        # upper bound on the model's verdict.
        if (
            eligibility_aware
            and not has_contradiction
            and not has_evidence
            and not missing_evidence_refutes
        ):
            supported = True
            new_conf = _downgrade(confidence)
        else:
            supported = (
                bool(verdict.get("supported", True))
                and has_evidence
                and not has_contradiction
            )
            new_conf = confidence if supported else _downgrade(confidence)
        masker = _self_check_masker(settings)
        caveat = _one_line(masker.mask_text(str(verdict.get("caveat") or "")), limit=360)
        next_check = _one_line(
            masker.mask_text(str(verdict.get("next_check") or "")), limit=240
        )
        if not has_evidence:
            caveat = caveat or _caveat_missing_evidence(family, settings)
            next_check = next_check or _next_check_missing_evidence(family, settings)
        # Also honour an explicit weaker confidence from the model, never a stronger one.
        model_conf = str(verdict.get("confidence") or "").strip().lower()
        if model_conf in _CONF_ORDER:
            if _CONF_ORDER.index(model_conf) < _CONF_ORDER.index(new_conf):
                new_conf = model_conf
        # `refuted` must come from the deterministic layer, never the model's bare
        # opinion: the model can cite a coexisting observation (e.g. an unrelated
        # pod's OOM next to a dispositive GPU XID alert signature) to argue against
        # the cause in prose without that observation being a falsifier --
        # artifact_contradicts_family() in root_cause_ranking.py documents the same
        # rule for the ranker. `supported=False` still drives the confidence
        # downgrade above. The two refuting conditions are exactly the deterministic
        # gate's, so all three paths agree: a scoped contradiction, or the OWNER
        # DECISION above (a signature-promoted claim with nothing eligible behind
        # it). The ontology-probe "refutes" verdict is a separate, evidence-grounded
        # refutation channel handled in pipeline.py.
        return _default(
            new_conf,
            caveat,
            refuted=has_contradiction or missing_evidence_refutes,
            next_check=next_check,
        )
    except Exception:  # noqa: BLE001 - self-check is best-effort; never break analyze()
        _log.warning("self-check failed; keeping ranked confidence unchanged", exc_info=True)
        return _default(getattr(top_candidate, "confidence", "low"))


def _one_line(value: object, *, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _caveat_missing_evidence(family: str, settings: Settings) -> str:
    """Caveat for the "no eligible evidence" gate.

    The live gate (``_has_family_evidence``) accepts eligible support from ANY
    collector, not only the family's canonical one, so this must not claim the
    canonical source specifically was consulted and came up empty — it may
    never have run at all. Name it only as where to look next.
    """
    canonical = _FAMILY_RULES.get(family, ("the canonical source",))[0]
    if getattr(settings, "language", "en") == "ko":
        return (
            "자기 점검: 이 원인을 뒷받침하는 증거를 수집기에서 확인하지 못해 신뢰도를 "
            f"한 단계 낮췄습니다. 결론 전에 핵심 근거 수집기({canonical})를 직접 확인하세요."
        )
    return (
        "Self-check: no collector returned usable scoped evidence for this cause, so "
        f"confidence was lowered one level. Verify the canonical source ({canonical}) "
        "directly before acting."
    )


def _next_check_missing_evidence(family: str, settings: Settings) -> str:
    """The single settling check for the deterministic missing-evidence gate."""
    canonical = _FAMILY_RULES.get(family, ("the canonical source",))[0]
    if getattr(settings, "language", "en") == "ko":
        return f"핵심 근거 수집기({canonical})에서 이 원인의 증거를 직접 확인해 주세요."
    return f"Check the canonical evidence source ({canonical}) directly for this cause."


def _caveat_contradiction(family: str, settings: Settings) -> str:
    if getattr(settings, "language", "en") == "ko":
        return (
            f"자기 점검: `{family}`을(를) 직접 반박하는 대상·시간창 범위의 증거가 있어 "
            "현재 결론을 유지할 수 없습니다. 반박 증거와 지지 증거의 범위를 다시 확인하세요."
        )
    return (
        f"Self-check: target- and incident-window-scoped evidence directly contradicts "
        f"{family}; the current conclusion cannot be retained without resolving that conflict."
    )


def _has_family_evidence(
    family: str,
    results: list[CollectorResult],
    *,
    evidence_eligibility: Mapping[str, object] | None,
) -> bool:
    """Accept any eligible family-specific support, not only the canonical agent."""
    return any(
        _artifact_has_evidence(
            family,
            art,
            evidence_eligibility=evidence_eligibility,
        )
        for result in results
        for art in (getattr(result, "artifacts", []) or [])
    )


def _has_family_contradiction(
    family: str,
    results: list[CollectorResult],
    *,
    evidence_eligibility: Mapping[str, object] | None,
) -> bool:
    for result in results:
        for art in getattr(result, "artifacts", []) or []:
            if evidence_eligibility is not None:
                evidence_id = str(getattr(art, "evidence_id", "") or "")
                eligibility = evidence_eligibility.get(evidence_id)
                permits = getattr(eligibility, "permits", None)
                if not callable(permits) or not permits("contradict"):
                    continue
            if artifact_contradicts_family(family, art):
                return True
    return False


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


def _evidence_digest(
    results: list[CollectorResult],
    masker,
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> str:
    headlines: list[str] = []
    artifact_lines: list[str] = []
    for r in results:
        summary = (r.summary or "").strip() or NO_EVIDENCE
        headlines.append(f"- {r.agent} [{r.status}]: {masker.mask_text(summary)}")
        selected = [
            art for art in (getattr(r, "artifacts", []) or []) if art.status in ("ok", "partial")
        ]
        selected = [
            art for _index, art in sorted(
                ([(len(selected) - 1, selected[-1])] if selected else []) + sorted(
                    enumerate(selected[:-1]),
                    key=lambda item: (bool(item[1].highlights), item[1].status == "ok", item[0]),
                    reverse=True,
                )[:5]
            )
        ]
        for art in selected:
            evidence_role = "context"
            if evidence_eligibility is not None:
                evidence_id = str(getattr(art, "evidence_id", "") or "")
                eligibility = evidence_eligibility.get(evidence_id)
                permits = getattr(eligibility, "permits", None)
                if callable(permits) and permits("support"):
                    evidence_role = "support"
                elif callable(permits) and permits("contradict"):
                    evidence_role = "contradict"
            parts = [
                str(art.title or art.type or "artifact").strip(),
                f"status={art.status}",
                f"evidence_role={evidence_role}",
            ]
            if art.summary:
                parts.append(f"summary={_compact_evidence_value(art.summary, limit=600)}")
            if art.highlights:
                parts.append(f"highlights={', '.join(map(str, art.highlights[:6]))}")
            if art.result is not None:
                checks = condition_observations(art.result)
                if checks:
                    parts.append(f"condition_checks={_compact_evidence_value(checks)}")
                parts.append(
                    f"result={_compact_evidence_value(observed_payload(art.result))}"
                )
            artifact_lines.append(f"  artifact: {masker.mask_text(' | '.join(parts))}")
    lines = list(headlines)
    size = len("\n".join(lines))
    for line in artifact_lines:
        extra = len(line) + (1 if lines else 0)
        if size + extra > 24_000:
            break
        lines.append(line)
        size += extra
    return "\n".join(lines)


async def _llm_refute(
    settings: Settings,
    top: RankedCause,
    results: list[CollectorResult],
    has_evidence: bool,
    has_contradiction: bool,
    plan: object = None,
    *,
    evidence_eligibility: Mapping[str, object] | None = None,
) -> dict | None:
    ko = getattr(settings, "language", "en") == "ko"
    masker = _self_check_masker(settings)
    evidence = _evidence_digest(
        results, masker, evidence_eligibility=evidence_eligibility
    )
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
        "return supported=false. Distinguish OOM scope using positive evidence: the "
        "target container's lastState.terminated.reason=OOMKilled is direct evidence "
        "of a container OOM. When that container has a memory limit and node-level "
        "pressure is absent or contradicted, treat the cgroup limit as the primary "
        "mechanism and CrashLoopBackOff as its consequence. A missing dmesg/journal "
        "record is a coverage gap, not positive evidence of node-level OOM; only "
        "separate incident-scoped kernel OOM, eviction, or active MemoryPressure "
        "evidence establishes that competing scope.\n"
        f"Write the caveat and next_check in {caveat_lang}. Respond with a JSON object: "
        '{"supported": bool, "confidence": "low|medium|high", "caveat": str, '
        '"next_check": str}. '
        "The caveat is one or two sentences naming the strongest doubt and the single "
        "check that would settle it; next_check is that single settling check phrased "
        "as one concrete instruction to the operator."
        + (
            " Write Korean in polite form (~하세요/~합니다), never the plain "
            "imperative (~하라/~해라)."
            if ko
            else ""
        )
    )
    user = (
        f"Proposed root cause family: {top.family}\n"
        f"Ranked confidence: {top.confidence}\n"
        f"Specific or canonical evidence present: {has_evidence}\n"
        f"Direct scoped contradiction present: {has_contradiction}\n"
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
        "normal, recovered, or negated values do not. Respond with a JSON object: "
        '{"refuted": [exact '
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
