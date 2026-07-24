"""Final, evidence-first guard for an RCA response.

The pipeline already gathers, ranks, and refutes evidence. This module makes
that work auditable at the response boundary: a conclusion must point at
collected artifacts, high confidence must have enough independent live support,
and risky change commands must not lead the operator guidance.

It deliberately has a useful deterministic mode. LLM review can enrich the
scores later, but a failed model call must never remove the safety gates.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.knowledge import _keyword_hits
from app.schemas import AlertAnalysisResponse
from app.services.root_cause_ranking import (
    FAMILIES,
    RankedCause,
    _artifact_family_semantics,
    artifact_contradicts_family,
    artifact_supports_family,
)

_USABLE = {"ok", "partial"}
_DANGEROUS_ACTION = re.compile(
    r"\b(kubectl\s+(?:delete|drain|cordon|uncordon)|helm\s+(?:rollback|uninstall)|"
    r"rm\s+-rf|delete\s+(?:pod|pvc|volume|namespace)|restart\s+(?:all|every))\b",
    re.IGNORECASE,
)
_GUARDRAIL = re.compile(
    r"\b(confirm|approval|approve|verify|backup|impact|maintenance window)\b|"
    r"(확인|승인|백업|영향|점검|유지보수)",
    re.IGNORECASE,
)
_WEIGHTS = {
    "evidence_grounding": 25,
    "diagnostic_reasoning": 20,
    "investigation_plan": 20,
    "uncertainty_calibration": 15,
    # This used to include a permanently-perfect ``tool_efficiency`` score.
    # A score that is not measured is noise, so retain a 100-point rubric by
    # assigning its weight to the operator-facing quality we can actually see.
    "operational_usefulness": 15,
    "safety": 5,
}
_EVIDENCE_LINK_ROLES = frozenset({"support", "contradict", "context"})


@dataclass(frozen=True)
class HarnessVerdict:
    diagnosis_state: str
    score: int
    dimensions: dict[str, int]
    gates: dict[str, bool]
    claims: list[dict[str, Any]]
    trace: list[dict[str, str]]

    @property
    def failed_gates(self) -> list[str]:
        return [name for name, failed in self.gates.items() if failed]


@dataclass(frozen=True)
class EvidenceLink:
    """A typed connection between a claim and response-local evidence.

    ``fact_id`` is deliberately an evidence ID rather than an opaque object.
    That makes the contract useful before the EvidenceFact blackboard lands,
    while still allowing the future blackboard to use its stable fact ID here.
    """

    fact_id: str
    role: str
    explanation: str = ""

    @property
    def evidence_id(self) -> str:
        return self.fact_id


def validate_evidence_links(
    links: Iterable[EvidenceLink | Mapping[str, Any]] | None,
    evidence_ids: Iterable[str],
    *,
    eligibility_by_id: Mapping[str, object] | None = None,
) -> tuple[list[EvidenceLink], list[str]]:
    """Normalize supplied evidence links without allowing bad links to pass.

    The harness must be fail-closed but not crash a response because an LLM
    returned malformed JSON.  Invalid links are returned as messages so the
    caller can make them visible as a hard gate.
    """
    known = {str(item).strip() for item in evidence_ids if str(item).strip()}
    valid: list[EvidenceLink] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(links or []):
        if isinstance(raw, EvidenceLink):
            link = raw
        elif isinstance(raw, Mapping):
            link = EvidenceLink(
                fact_id=str(raw.get("fact_id") or raw.get("evidence_id") or "").strip(),
                role=str(raw.get("role") or "").strip().lower(),
                explanation=str(raw.get("explanation") or "").strip(),
            )
        else:
            errors.append(f"link[{index}] is not an object")
            continue
        if not link.fact_id:
            errors.append(f"link[{index}] has no evidence ID")
            continue
        if link.role not in _EVIDENCE_LINK_ROLES:
            errors.append(f"link[{index}] has invalid role {link.role!r}")
            continue
        if link.fact_id not in known:
            errors.append(f"link[{index}] references unknown evidence {link.fact_id!r}")
            continue
        eligibility = (eligibility_by_id or {}).get(link.fact_id)
        permits = getattr(eligibility, "permits", None)
        if not callable(permits):
            # A pipeline-provided map is the context-aware target/window/run
            # gate.  An ID missing from it is not a legacy success fallback:
            # it was not resolved to an eligible blackboard fact, so cannot
            # become support merely because a caller cited it explicitly.
            errors.append(
                f"link[{index}] has no eligibility verdict for {link.fact_id!r}"
            )
            continue
        if not permits(link.role):
            reason = str(getattr(eligibility, "reason", "") or "ineligible observation")
            errors.append(
                f"link[{index}] cannot use {link.fact_id!r} as {link.role}: {reason}"
            )
            continue
        key = (link.fact_id, link.role)
        if key not in seen:
            valid.append(link)
            seen.add(key)
    return valid, errors


def assign_evidence_ids(results: list[CollectorResult]) -> list[object]:
    """Give every returned artifact a stable, response-local evidence ID."""
    artifacts: list[object] = []
    number = 0
    for result in results:
        for item in result.artifacts:
            number += 1
            item.evidence_id = f"E{number:02d}"
            artifacts.append(item)
    return artifacts


def _promoted_issue_keywords(
    top: RankedCause | None, known_issues: list[dict] | None
) -> tuple[str, ...] | None:
    if top is None or known_issues is None:
        return None
    for rationale in getattr(top, "rationale", []) or []:
        match = re.fullmatch(r"matched known-issue signature:\s*(.+)", str(rationale))
        if not match:
            continue
        issue_name = match.group(1)
        for entry in known_issues:
            if not isinstance(entry, Mapping) or entry.get("issue") != issue_name:
                continue
            keywords = entry.get("keywords")
            if not isinstance(keywords, (list, tuple)):
                return None
            return tuple(str(keyword).lower() for keyword in keywords)
        return None
    return None


def _grounds_promoted_issue(artifact: object, issue_keywords: tuple[str, ...] | None) -> bool:
    if not issue_keywords:
        return False
    _agent, _predicate, text = _artifact_family_semantics(artifact)
    return bool(_keyword_hits(text, list(issue_keywords))[0])


def _grounds_promoted_symptom(candidate: RankedCause | None, artifact: object) -> bool:
    if candidate is None:
        return False
    evidence_id = str(getattr(artifact, "evidence_id", "") or "")
    if evidence_id not in set(getattr(candidate, "support_evidence_ids", []) or []):
        return False
    for item in getattr(candidate, "score_breakdown", []) or []:
        if item.get("kind") != "curated_symptom":
            continue
        keywords = [str(keyword) for keyword in item.get("matched_keywords") or []]
        _agent, _predicate, text = _artifact_family_semantics(artifact)
        if keywords and any(keyword.casefold() in text for keyword in keywords):
            return True
    return False


def _supports_candidate_family(
    candidate: RankedCause | None,
    family: str,
    artifact: object,
    issue_keywords: tuple[str, ...] | None,
) -> bool:
    return bool(
        artifact_supports_family(family, artifact)
        or _grounds_promoted_issue(artifact, issue_keywords)
        or _grounds_promoted_symptom(candidate, artifact)
    )


def evaluate(
    response: AlertAnalysisResponse,
    results: list[CollectorResult],
    candidates: list[RankedCause],
    *,
    next_check: str = "",
    evidence_links: Iterable[EvidenceLink | Mapping[str, Any]] | None = None,
    evidence_eligibility: Mapping[str, object] | None = None,
    known_issues: list[dict] | None = None,
    generic_state_alert: bool = False,
) -> HarnessVerdict:
    top = candidates[0] if candidates else None
    usable = _usable_artifacts(results)
    by_agent: dict[str, list[object]] = {}
    for item in usable:
        by_agent.setdefault(str(getattr(item, "agent", "")), []).append(item)

    family = str(getattr(top, "family", "") or "")
    issue_keywords = _promoted_issue_keywords(top, known_issues)
    agents = set(getattr(top, "evidence_agents", []) or []) if top else set()
    agent_supporting = [item for agent in agents for item in by_agent.get(agent, [])]
    if _signature_support(top):
        # Signature promotion is logical provenance, not a physical collector.
        # XID and curated signatures can arrive from Alertmanager, Loki,
        # Kubernetes, or the system agent.  Claim semantics below are the
        # authoritative boundary, so consider every family-relevant card here.
        agent_supporting.extend(
            item for item in usable if _supports_candidate_family(top, family, item, issue_keywords)
        )
    agent_supporting = _unique_artifacts(agent_supporting)
    all_artifacts = [item for result in results for item in result.artifacts]
    all_ids = [
        str(getattr(item, "evidence_id", ""))
        for item in all_artifacts
        if getattr(item, "evidence_id", "")
    ]
    by_id = {str(getattr(item, "evidence_id", "")): item for item in all_artifacts}
    # ``None`` means this standalone harness caller has no blackboard context,
    # so derive typed artifact eligibility locally.  An explicitly supplied
    # (including empty) map is authoritative and must remain fail-closed for
    # evidence IDs it does not contain.
    eligibility_by_id = (
        dict(_artifact_eligibility(all_artifacts))
        if evidence_eligibility is None
        else dict(evidence_eligibility)
    )
    supplied_links = _supplied_evidence_links(response, top, evidence_links)
    links, link_errors = validate_evidence_links(
        supplied_links, all_ids, eligibility_by_id=eligibility_by_id
    )
    if family in FAMILIES:
        semantically_valid: list[EvidenceLink] = []
        for link in links:
            artifact = by_id.get(link.fact_id)
            if artifact is not None:
                if link.role == "support" and not _supports_candidate_family(
                    top, family, artifact, issue_keywords
                ):
                    link_errors.append(
                        f"link to {link.fact_id!r} does not support root-cause family {family!r}"
                    )
                    continue
                if link.role == "contradict" and not artifact_contradicts_family(
                    family, artifact
                ):
                    link_errors.append(
                        f"link to {link.fact_id!r} does not contradict root-cause family {family!r}"
                    )
                    continue
            semantically_valid.append(link)
        links = semantically_valid
    elif str(getattr(top, "novelty", "")) != "open_world":
        semantically_valid = []
        for link in links:
            artifact = by_id.get(link.fact_id)
            if artifact is not None and link.role == "support" and not _grounds_promoted_issue(
                artifact, issue_keywords
            ):
                link_errors.append(
                    f"link to {link.fact_id!r} does not ground promoted known-issue family {family!r}"
                )
                continue
            semantically_valid.append(link)
        links = semantically_valid
    # Legacy callers derive support from the ranker's evidence agents.  New
    # callers provide explicit support/contradiction links and get exact claim
    # grounding instead of an agent-name approximation.
    if supplied_links is None:
        # An agent may return useful context alongside a scoped positive
        # observation. The legacy agent-name fallback must not turn every one
        # of those artifacts into root-cause support.
        supporting = [
            item
            for item in agent_supporting
            if (
                (eligibility := eligibility_by_id.get(str(getattr(item, "evidence_id", ""))))
                is not None
                and callable(getattr(eligibility, "permits", None))
                and eligibility.permits("support")
                and (
                    _supports_candidate_family(top, family, item, issue_keywords)
                )
            )
        ]
        claim_links = [
            EvidenceLink(str(getattr(item, "evidence_id", "")), "support")
            for item in supporting
            if getattr(item, "evidence_id", "")
        ]
    else:
        supporting = [
            by_id[link.fact_id]
            for link in links
            if link.role == "support" and link.fact_id in by_id
        ]
        claim_links = links
    supporting = _unique_artifacts(supporting)
    support_ids = [link.fact_id for link in claim_links if link.role == "support"]
    contradiction_ids = [link.fact_id for link in claim_links if link.role == "contradict"]
    traced_ids = [*support_ids, *contradiction_ids]
    support_source_groups = {_independence_key(item) for item in supporting}
    signature = _signature_support(top) and bool(supporting)
    confidence = str(getattr(top, "confidence", "low") or "low")
    insufficient = not family or family == "insufficient_evidence"

    gates = {
        "unsupported_high_confidence": bool(
            not insufficient
            and confidence == "high"
            and len(support_source_groups) < 2
            and not signature
        ),
        "missing_evidence_trace": bool(
            not insufficient
            and (
                not support_ids
                or not all(
                    f"[{evidence_id}]" in response.analysis_detail
                    for evidence_id in traced_ids
                )
            )
        ),
        "invalid_evidence_links": bool(link_errors),
        # A direct scoped contradiction is unresolved regardless of whether an
        # earlier stage labelled the candidate medium or high.  Restricting this
        # gate to high let contradicted medium conclusions retain remediation
        # authority.
        "unresolved_contradiction": bool(not insufficient and contradiction_ids),
        # Generic state alerts (non-ready / waiting / replicas-mismatch class)
        # describe a symptom shared by many causes. Naming a specific family
        # without a single target-verified supporting observation is a guess
        # (2026-07-24 audit: 4/10 KubePodNotReady runs concluded families with
        # zero target-scoped artifacts).
        "generic_alert_without_target_evidence": bool(
            not insufficient
            and generic_state_alert
            and not any(_target_verified_artifact(item) for item in supporting)
        ),
        "unsafe_action_without_guardrail": _unsafe_action_without_guardrail(
            response.analysis_detail
        ),
    }
    diagnosis_state = "unresolved" if insufficient else (
        "provisional" if confidence == "low" else "supported"
    )
    claim = {
        "claim_id": "C01",
        "kind": "root_cause",
        "statement": family or "insufficient_evidence",
        "family": family or "insufficient_evidence",
        "confidence": confidence,
        "supporting_evidence": support_ids,
        "contradicting_evidence": contradiction_ids,
        "evidence_links": [
            {"evidence_id": link.fact_id, "role": link.role, "explanation": link.explanation}
            for link in claim_links
        ],
        "evidence_link_errors": link_errors,
    }
    trace = [
        _trace_item(item)
        for item in _unique_artifacts(
            [
                item
                for item in all_artifacts
                if str(getattr(item, "evidence_id", "")) in set(traced_ids)
            ]
            if supplied_links is not None
            else supporting
        )
        if getattr(item, "evidence_id", "")
    ]
    dimensions = _dimension_scores(
        response,
        candidates,
        support_ids,
        support_source_groups,
        next_check=next_check,
        unsafe=gates["unsafe_action_without_guardrail"],
    )
    score = round(sum(dimensions[name] / 5 * weight for name, weight in _WEIGHTS.items()))
    return HarnessVerdict(diagnosis_state, score, dimensions, gates, [claim], trace)


def apply_trace(response: AlertAnalysisResponse, verdict: HarnessVerdict) -> bool:
    """Append a compact trace once; returns whether the report changed."""
    if not verdict.trace or "## Evidence Trace" in response.analysis_detail:
        return False
    lines = ["## Evidence Trace", ""]
    for item in verdict.trace:
        summary = item["summary"] or "Collected evidence"
        lines.append(
            f"- [{item['evidence_id']}] {item['source']} · "
            f"{_trace_verdict_label(item)}: {summary}"
        )
    response.analysis_detail = response.analysis_detail.rstrip() + "\n\n" + "\n".join(lines)
    response.analysis = response.analysis_detail
    return True


def _target_verified_artifact(item: object) -> bool:
    payload = getattr(item, "result", None)
    if not isinstance(payload, dict):
        return False
    observation = payload.get("observation")
    return (
        isinstance(observation, dict)
        and observation.get("target_identity_verified") is True
    )


def _trace_item(item: object) -> dict[str, str]:
    """Render the normalized truth state alongside every cited artifact.

    The final report previously carried only a prose summary. That made a
    scoped absence (useful contradiction) visually indistinguishable from a
    positive observation, and hid partial/current-context observations. Reuse
    the same normalizer that the evidence-link gate trusts so the display never
    invents a stronger verdict than the RCA engine accepted.
    """
    polarity, coverage = "unknown", "partial"
    try:
        from app.services.evidence_blackboard import normalize_artifact

        # Match the evidence-link boundary: a result body that merely happens
        # to contain a success summary or loose polarity fields is context,
        # not a scoped verdict in the operator-visible trace.
        fact = normalize_artifact(item, require_typed_observation=True)
        polarity = str(fact.polarity)
        coverage = str(fact.coverage)
    except Exception:  # noqa: BLE001 - trace rendering must not block the RCA.
        pass
    return {
        "evidence_id": str(getattr(item, "evidence_id", "")),
        "source": str(getattr(item, "source", "")),
        "summary": _single_line(getattr(item, "summary", ""), 220),
        "polarity": polarity,
        "coverage": coverage,
    }


def _trace_verdict_label(item: Mapping[str, str]) -> str:
    polarity = item.get("polarity", "unknown")
    coverage = item.get("coverage", "partial")
    if polarity == "present" and coverage == "scoped":
        return "observed · scoped"
    if polarity == "absent" and coverage == "scoped":
        return "not observed · scoped"
    if polarity == "unavailable":
        return "source unavailable"
    return "context only · partial"


def apply_safety_guardrail(response: AlertAnalysisResponse) -> bool:
    if not _unsafe_action_without_guardrail(response.analysis_detail):
        return False
    guard = (
        "## Safety Gate\n\n"
        "Before any destructive or disruptive change, first collect the read-only evidence above, "
        "confirm impact and rollback/backup requirements, and obtain operator approval.\n\n"
    )
    response.analysis_detail = guard + response.analysis_detail
    response.analysis = response.analysis_detail
    return True


def apply_confidence_downgrade(candidates: list[RankedCause]) -> bool:
    if not candidates or candidates[0].confidence != "high":
        return False
    candidates[0].confidence = "medium"
    return True


def abstain(
    response: AlertAnalysisResponse,
    candidates: list[RankedCause],
    verdict: HarnessVerdict,
    *,
    historical_reanalysis: bool = False,
    language: str = "en",
    next_check: str = "",
) -> None:
    """Return an unresolved RCA without discarding a useful working hypothesis.

    A hard-gate failure means that a family cannot be presented as confirmed.
    It does not mean that all inference is worthless, especially when a past
    incident no longer has complete telemetry.  Preserve the previous leader
    as an explicitly low-confidence hypothesis behind ``insufficient_evidence``
    so operators and Top-N evaluation can still inspect it without mistaking it
    for verified evidence or remediation authority.
    """
    ko = language == "ko"
    previous_top = next(
        (candidate for candidate in candidates if candidate.family != "insufficient_evidence"),
        None,
    )
    provisional: RankedCause | None = None
    if previous_top is not None:
        claim = verdict.claims[0] if verdict.claims else {}
        provisional = replace(
            previous_top,
            confidence="low",
            support_evidence_ids=list(claim.get("supporting_evidence") or []),
            contradiction_evidence_ids=list(claim.get("contradicting_evidence") or []),
        )

    candidates[:] = [
        RankedCause("insufficient_evidence", "low", 0.0),
        *([provisional] if provisional is not None else []),
    ]
    response.root_cause_family = "insufficient_evidence"
    response.analysis_quality = "degraded"
    if provisional is not None:
        response.context["provisional_root_cause"] = provisional.as_dict()
        if ko:
            response.analysis_summary = (
                f"근본 원인은 미확정입니다. `{provisional.family}`이(가) 낮은 확신도의 "
                "잠정 가설로 남아 있습니다."
            )
            historical_note = (
                "과거 인시던트 재분석이라 텔레메트리 일부 누락은 예상됩니다. "
                if historical_reanalysis
                else ""
            )
            hypothesis_note = (
                f"{historical_note}가장 유력한 family `{provisional.family}`은(는) 남은 신호로부터의 "
                "낮은 확신도 추론으로 유지됩니다. 검증된 원인이나 원인별 조치의 근거가 아닙니다."
            )
            verification_check = (
                "- 파괴적 조치를 취하기 전에 읽기 전용 쿼리로 유력 가설을 검증하세요.\n"
            )
        else:
            response.analysis_summary = (
                f"Root cause is unconfirmed; {provisional.family} remains a low-confidence "
                "working hypothesis."
            )
            historical_note = (
                "Because this is a historical re-analysis, incomplete telemetry is expected. "
                if historical_reanalysis
                else ""
            )
            hypothesis_note = (
                f"{historical_note}The leading family `{provisional.family}` is retained as a "
                "low-confidence inference from the remaining signals. It is not a verified cause "
                "or justification for cause-specific remediation."
            )
            verification_check = (
                "- Verify the leading hypothesis with a read-only query before any disruptive action.\n"
            )
    else:
        response.context.pop("provisional_root_cause", None)
        if ko:
            response.analysis_summary = "수집된 증거로는 근본 원인이 확정되지 않았습니다."
            hypothesis_note = "현재 신호로는 특정 잠정 가설조차 세울 수 없습니다."
            verification_check = (
                "- family를 선택하기 전에 대상·인시던트 시간창으로 스코프된 신호를 "
                "최소 1개 이상 수집하세요.\n"
            )
        else:
            response.analysis_summary = "Root cause is not confirmed by the collected evidence."
            hypothesis_note = (
                "The available signals do not support even a specific working hypothesis yet."
            )
            verification_check = (
                "- Collect at least one target- and incident-window-scoped signal "
                "before selecting a family.\n"
            )
    if ko:
        specific_check = f"- Self-check 다음 확인: {next_check}\n" if next_check else ""
        response.analysis_detail = (
            "## 평가\n\n"
            "수집된 증거로는 근본 원인 family를 확정할 수 없습니다. "
            + hypothesis_note
            + "\n\n"
            "## 필요한 다음 점검\n\n"
            "- 대상 워크로드와 인시던트 시간창에 대해 사용 불가였거나 비어 있던 증거 소스를 "
            "다시 수집하세요.\n"
            + specific_check
            + verification_check
            + "\n"
            "## Harness 판정\n\n"
            + "\n".join(f"- {name}" for name in verdict.failed_gates)
        )
    else:
        specific_check = f"- Self-check next check: {next_check}\n" if next_check else ""
        response.analysis_detail = (
            "## Assessment\n\n"
            "The collected evidence does not support confirming a root-cause family. "
            + hypothesis_note
            + "\n\n"
            "## Required Next Checks\n\n"
            "- Re-run the unavailable or empty evidence source for the affected workload "
            "and incident window.\n"
            + specific_check
            + verification_check
            + "\n"
            "## Harness Findings\n\n"
            + "\n".join(f"- {name}" for name in verdict.failed_gates)
        )
    response.analysis = response.analysis_detail


def payload(verdict: HarnessVerdict, *, status: str, repairs: int) -> dict[str, Any]:
    return {
        "rubric_version": "2",
        "status": status,
        "diagnosis_state": verdict.diagnosis_state,
        "overall_score": verdict.score,
        "dimension_scores": verdict.dimensions,
        "hard_gates": verdict.gates,
        "violations": verdict.failed_gates,
        "repair_attempts": repairs,
        "claims": verdict.claims,
        "evidence_trace": verdict.trace,
    }


def analysis_hash(response: AlertAnalysisResponse) -> str:
    """Hash the complete approved RCA claim, not just rendered prose.

    Snapshot identity must change when the selected mechanism, causal trace, or
    evidence links change even if an editor happens to produce the same Korean
    summary/detail.  The v1 fields remain inside the canonical payload so old
    review semantics are preserved for newly generated hashes.
    """
    context = response.context if isinstance(response.context, dict) else {}
    payload = {
        "schema_version": 2,
        "summary": response.analysis_summary,
        "detail": response.analysis_detail,
        "root_cause_family": response.root_cause_family,
        "top_root_cause": context.get("top_root_cause"),
        "reasoning_trace_v2": context.get("reasoning_trace_v2"),
        "reasoning_trace_v3": context.get("reasoning_trace_v3"),
        "evidence_links": context.get("evidence_links"),
    }
    value = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _supplied_evidence_links(
    response: AlertAnalysisResponse,
    top: RankedCause | None,
    explicit: Iterable[EvidenceLink | Mapping[str, Any]] | None,
) -> Iterable[EvidenceLink | Mapping[str, Any]] | None:
    """Find a v2 claim link set while preserving the v1 evaluate contract."""
    if explicit is not None:
        return explicit
    if top is not None:
        links = getattr(top, "evidence_links", None)
        if links is not None:
            return links
        support = getattr(top, "support_evidence_ids", None)
        contradict = getattr(top, "contradiction_evidence_ids", None)
        if contradict is None:
            contradict = getattr(top, "contradicting_evidence_ids", None)
        # RankedCause now always exposes empty v2 lists for compatibility.  An
        # empty pair means "no explicit links supplied", so retain the legacy
        # agent-derived trace rather than treating it as an invalid empty claim.
        if support or contradict:
            return [
                *({"evidence_id": item, "role": "support"} for item in (support or [])),
                *({"evidence_id": item, "role": "contradict"} for item in (contradict or [])),
            ]
    context_links = (
        response.context.get("evidence_links")
        if isinstance(response.context, dict)
        else None
    )
    return context_links if context_links is not None else None


def _usable_artifacts(results: list[CollectorResult]) -> list[object]:
    out: list[object] = []
    for result in results:
        for item in result.artifacts:
            summary = str(getattr(item, "summary", "") or "").strip()
            if getattr(item, "status", "") in _USABLE and summary and summary != NO_EVIDENCE:
                out.append(item)
    return out


def _artifact_eligibility(artifacts: Iterable[object]) -> dict[str, object]:
    """Evaluate links from typed observation semantics, not status prose.

    ``evaluate`` is also used by callers outside the PipelineState path, where
    no precomputed Blackboard eligibility map is available.  Those callers
    must not regain the legacy ``ok + summary => scoped support`` inference:
    only a collector-declared observation may ground an evidence link.
    """
    from app.services.evidence_blackboard import normalize_artifact

    eligible: dict[str, object] = {}
    for item in artifacts:
        evidence_id = str(getattr(item, "evidence_id", "") or "")
        if not evidence_id:
            continue
        try:
            eligible[evidence_id] = normalize_artifact(
                item, require_typed_observation=True
            ).eligibility
        except Exception:  # noqa: BLE001 - malformed evidence must not become proof
            continue
    return eligible


def _signature_support(top: RankedCause | None) -> bool:
    if top is None:
        return False
    rationale = " ".join(top.rationale).lower()
    return "signature" in {str(agent).lower() for agent in top.evidence_agents} or any(
        marker in rationale for marker in ("nvidia xid", "matched known-issue signature", "matched curated symptom")
    )


def _unique_artifacts(items: list[object]) -> list[object]:
    seen: set[str] = set()
    unique: list[object] = []
    for item in items:
        key = str(getattr(item, "evidence_id", ""))
        if key and key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _independence_key(item: object) -> str:
    """Use the telemetry plane, even for legacy artifacts outside a blackboard."""
    try:
        from app.services.evidence_blackboard import normalize_artifact

        return str(normalize_artifact(item).independence_group)
    except Exception:  # noqa: BLE001 - malformed artifacts are not independent proof
        return str(
            getattr(item, "independence_group", "")
            or getattr(item, "source", "")
            or getattr(item, "agent", "")
        )


def _unsafe_action_without_guardrail(detail: str) -> bool:
    for match in _DANGEROUS_ACTION.finditer(detail or ""):
        # A synthesized report can place Recommended Actions far below its
        # safety section. Any explicit earlier guardrail still governs that
        # action; limiting this to a short character window caused repeated
        # repair attempts on otherwise-safe long reports.
        preceding = (detail or "")[: match.start()]
        if not _GUARDRAIL.search(preceding):
            return True
    return False


def _dimension_scores(
    response: AlertAnalysisResponse,
    candidates: list[RankedCause],
    support_ids: list[str],
    support_source_groups: set[str],
    *,
    next_check: str,
    unsafe: bool,
) -> dict[str, int]:
    top = candidates[0] if candidates else None
    confidence = str(getattr(top, "confidence", "low") or "low")
    detail = response.analysis_detail.lower()
    return {
        "evidence_grounding": 5 if support_ids else 0,
        "diagnostic_reasoning": 4 if len(candidates) > 1 else 2,
        "investigation_plan": 5 if next_check else (3 if "check" in detail or "확인" in detail else 1),
        # Repeating an observation from the same collector is useful trace
        # detail, but it does not corroborate a high-confidence conclusion.
        # This rubric must agree with the high-confidence gate above instead
        # of awarding a perfect calibration score for two Loki/Kubernetes
        # query replicas.
        "uncertainty_calibration": 5 if confidence != "high" or len(support_source_groups) >= 2 else 2,
        "operational_usefulness": 4 if "action" in detail or "조치" in detail else 2,
        "safety": 0 if unsafe else 5,
    }


def _single_line(value: object, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]
