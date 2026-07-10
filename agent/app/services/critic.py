"""Safe structured review for evidence-grounded RCA claims.

This module deliberately does not let a critic rewrite operator-facing prose.
An LLM critic can be useful for identifying a weak causal leap, but its output
is untrusted input.  We accept only a small, monotonic patch vocabulary and
fall back to a no-op whenever the output is malformed or unsafe.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_CONFIDENCE = {"low", "medium", "high"}
_PATCH_TYPES = frozenset({"downgrade_confidence", "mark_inferred"})


@dataclass(frozen=True)
class CriticIssue:
    claim_id: str
    code: str
    severity: str
    message: str
    evidence_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class CriticPatch:
    claim_id: str
    op: str
    value: str
    reason: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "claim_id": self.claim_id,
            "op": self.op,
            "value": self.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CriticResult:
    issues: tuple[CriticIssue, ...] = ()
    patches: tuple[CriticPatch, ...] = ()
    status: str = "noop"

    @property
    def is_noop(self) -> bool:
        return self.status == "noop"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "issues": [issue.as_dict() for issue in self.issues],
            "patches": [patch.as_dict() for patch in self.patches],
        }


def critique_claims(
    claims: Iterable[Mapping[str, Any]],
    *,
    available_evidence_ids: Iterable[str],
) -> CriticResult:
    """Return deterministic semantic-grounding issues and conservative patches.

    This is intentionally useful without a model call.  A later LLM critic may
    add issues, but it cannot bypass the same evidence-link validation or make
    a confidence claim stronger.
    """
    available = {str(value) for value in available_evidence_ids}
    issues: list[CriticIssue] = []
    patches: list[CriticPatch] = []
    for index, claim in enumerate(claims):
        claim_id = str(claim.get("claim_id") or f"claim-{index + 1}")
        confidence = str(claim.get("confidence") or "low").lower()
        support = _id_list(claim.get("supporting_evidence") or claim.get("support_evidence_ids"))
        contradict = _id_list(
            claim.get("contradicting_evidence") or claim.get("contradiction_evidence_ids")
        )
        unknown = tuple(sorted({*support, *contradict} - available))
        if unknown:
            issues.append(
                CriticIssue(
                    claim_id,
                    "unknown_evidence",
                    "error",
                    "Claim references evidence not in the investigation.",
                    unknown,
                )
            )
        if str(claim.get("kind") or "") in {"root_cause", "causal_edge"} and not support:
            issues.append(
                CriticIssue(
                    claim_id,
                    "missing_support",
                    "error",
                    "Material claim has no supporting evidence.",
                )
            )
            if confidence == "high":
                patches.append(
                    CriticPatch(
                        claim_id, "downgrade_confidence", "medium", "No supporting evidence."
                    )
                )
        if confidence == "high" and contradict:
            issues.append(
                CriticIssue(
                    claim_id,
                    "unresolved_contradiction",
                    "warning",
                    "High-confidence claim has contradicting evidence.",
                    tuple(contradict),
                )
            )
            patches.append(
                CriticPatch(
                    claim_id, "downgrade_confidence", "medium", "Contradicting evidence remains."
                )
            )
        if str(claim.get("inference") or "").lower() == "observed" and not support:
            issues.append(
                CriticIssue(
                    claim_id, "ungrounded_observation", "warning", "Observed claim lacks evidence."
                )
            )
            patches.append(
                CriticPatch(
                    claim_id, "mark_inferred", "inferred", "No direct observation evidence."
                )
            )
    return CriticResult(
        tuple(issues), tuple(_dedupe_patches(patches)), "issues" if issues else "noop"
    )


def parse_critic_result(
    raw: object,
    *,
    claim_ids: Iterable[str],
    available_evidence_ids: Iterable[str],
) -> CriticResult:
    """Safely accept an optional LLM critic response.

    Invalid output returns a no-op result.  A critic can only downgrade
    confidence or mark a claim as inferred; it cannot inject prose, evidence,
    actions, or a stronger conclusion.
    """
    if not isinstance(raw, Mapping):
        return CriticResult()
    known_claims = {str(value) for value in claim_ids}
    known_evidence = {str(value) for value in available_evidence_ids}
    patches: list[CriticPatch] = []
    issues: list[CriticIssue] = []
    for item in raw.get("issues", []):
        if not isinstance(item, Mapping):
            continue
        claim_id = str(item.get("claim_id") or "")
        evidence_ids = tuple(
            str(value) for value in item.get("evidence_ids", []) if str(value) in known_evidence
        )
        if claim_id in known_claims:
            issues.append(
                CriticIssue(
                    claim_id=claim_id,
                    code=str(item.get("code") or "critic_issue")[:80],
                    severity=str(item.get("severity") or "warning")[:16],
                    message=str(item.get("message") or "Critic flagged this claim.")[:500],
                    evidence_ids=evidence_ids,
                )
            )
    for item in raw.get("patches", []):
        if not isinstance(item, Mapping):
            continue
        claim_id = str(item.get("claim_id") or "")
        op = str(item.get("op") or "")
        value = str(item.get("value") or "").lower()
        if claim_id not in known_claims or op not in _PATCH_TYPES:
            continue
        if op == "downgrade_confidence" and value not in {"low", "medium"}:
            continue
        if op == "mark_inferred" and value != "inferred":
            continue
        patches.append(CriticPatch(claim_id, op, value, str(item.get("reason") or "")[:500]))
    patches = _dedupe_patches(patches)
    return CriticResult(tuple(issues), tuple(patches), "issues" if issues or patches else "noop")


def apply_safe_patches(
    claims: Iterable[Mapping[str, Any]], result: CriticResult
) -> list[dict[str, Any]]:
    """Apply the critic's whitelist-only patches to copied claim dictionaries."""
    patch_by_claim: dict[str, list[CriticPatch]] = {}
    for patch in result.patches:
        patch_by_claim.setdefault(patch.claim_id, []).append(patch)
    updated: list[dict[str, Any]] = []
    for index, raw_claim in enumerate(claims):
        claim = dict(raw_claim)
        claim_id = str(claim.get("claim_id") or f"claim-{index + 1}")
        for patch in patch_by_claim.get(claim_id, []):
            if patch.op == "downgrade_confidence":
                current = str(claim.get("confidence") or "low").lower()
                if _confidence_rank(patch.value) < _confidence_rank(current):
                    claim["confidence"] = patch.value
            elif patch.op == "mark_inferred":
                claim["inference"] = "inferred"
        updated.append(claim)
    return updated


def _id_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item) for item in value if str(item)]


def _dedupe_patches(patches: Iterable[CriticPatch]) -> list[CriticPatch]:
    seen: set[tuple[str, str, str]] = set()
    output: list[CriticPatch] = []
    for patch in patches:
        key = (patch.claim_id, patch.op, patch.value)
        if key not in seen:
            seen.add(key)
            output.append(patch)
    return output


def _confidence_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(value.lower(), 0)
