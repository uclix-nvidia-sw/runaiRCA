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
import re
from dataclasses import dataclass
from typing import Any

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.schemas import AlertAnalysisResponse
from app.services.root_cause_ranking import RankedCause

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
    "operational_usefulness": 10,
    "tool_efficiency": 5,
    "safety": 5,
}


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


def evaluate(
    response: AlertAnalysisResponse,
    results: list[CollectorResult],
    candidates: list[RankedCause],
    *,
    next_check: str = "",
) -> HarnessVerdict:
    top = candidates[0] if candidates else None
    usable = _usable_artifacts(results)
    by_agent: dict[str, list[object]] = {}
    for item in usable:
        by_agent.setdefault(str(getattr(item, "agent", "")), []).append(item)

    family = str(getattr(top, "family", "") or "")
    agents = set(getattr(top, "evidence_agents", []) or []) if top else set()
    supporting = [item for agent in agents for item in by_agent.get(agent, [])]
    supporting = _unique_artifacts(supporting)
    support_ids = [str(getattr(item, "evidence_id", "")) for item in supporting if getattr(item, "evidence_id", "")]
    signature = _signature_support(top)
    confidence = str(getattr(top, "confidence", "low") or "low")
    insufficient = not family or family == "insufficient_evidence"

    gates = {
        "unsupported_high_confidence": bool(
            not insufficient and confidence == "high" and len({getattr(item, "agent", "") for item in supporting}) < 2 and not signature
        ),
        "missing_evidence_trace": bool(
            not insufficient
            and (not support_ids or not all(f"[{evidence_id}]" in response.analysis_detail for evidence_id in support_ids))
        ),
        "unsafe_action_without_guardrail": _unsafe_action_without_guardrail(response.analysis_detail),
    }
    diagnosis_state = "unresolved" if insufficient else ("provisional" if confidence == "low" else "supported")
    claim = {
        "claim_id": "C01",
        "kind": "root_cause",
        "statement": family or "insufficient_evidence",
        "family": family or "insufficient_evidence",
        "confidence": confidence,
        "supporting_evidence": support_ids,
        "contradicting_evidence": [],
    }
    trace = [
        {
            "evidence_id": str(getattr(item, "evidence_id", "")),
            "source": str(getattr(item, "source", "")),
            "summary": _single_line(getattr(item, "summary", ""), 220),
        }
        for item in supporting
        if getattr(item, "evidence_id", "")
    ]
    dimensions = _dimension_scores(
        response,
        candidates,
        support_ids,
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
        lines.append(f"- [{item['evidence_id']}] {item['source']}: {summary}")
    response.analysis_detail = response.analysis_detail.rstrip() + "\n\n" + "\n".join(lines)
    response.analysis = response.analysis_detail
    return True


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


def abstain(response: AlertAnalysisResponse, candidates: list[RankedCause], verdict: HarnessVerdict) -> None:
    """Return an honest unresolved RCA when a hard gate cannot be repaired."""
    candidates[:] = [RankedCause("insufficient_evidence", "low", 0.0)]
    response.root_cause_family = "insufficient_evidence"
    response.analysis_quality = "degraded"
    response.analysis_summary = "Root cause is not confirmed by the collected evidence."
    response.analysis_detail = (
        "## Assessment\n\n"
        "The collected evidence does not support a safe, high-confidence root-cause conclusion. "
        "The agent is withholding a root-cause family rather than guessing.\n\n"
        "## Required Next Checks\n\n"
        "- Re-run the unavailable or empty evidence source for the affected workload and incident window.\n"
        "- Verify the leading hypothesis with a read-only query before any disruptive action.\n\n"
        "## Harness Findings\n\n"
        + "\n".join(f"- {name}" for name in verdict.failed_gates)
    )
    response.analysis = response.analysis_detail


def payload(verdict: HarnessVerdict, *, status: str, repairs: int) -> dict[str, Any]:
    return {
        "rubric_version": "1",
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
    value = "\n".join(
        (response.analysis_summary, response.analysis_detail, response.root_cause_family)
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _usable_artifacts(results: list[CollectorResult]) -> list[object]:
    out: list[object] = []
    for result in results:
        for item in result.artifacts:
            summary = str(getattr(item, "summary", "") or "").strip()
            if getattr(item, "status", "") in _USABLE and summary and summary != NO_EVIDENCE:
                out.append(item)
    return out


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
        "uncertainty_calibration": 5 if confidence != "high" or len(support_ids) >= 2 else 2,
        "operational_usefulness": 4 if "action" in detail or "조치" in detail else 2,
        "tool_efficiency": 5,
        "safety": 0 if unsafe else 5,
    }


def _single_line(value: object, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]
