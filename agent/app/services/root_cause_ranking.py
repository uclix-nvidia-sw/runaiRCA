"""Deterministic root-cause *candidate* ranking.

Ranks the 5 root-cause families for the CURRENT incident from the evidence the
collectors already gathered. This is NOT incident similarity — pgvector /
`similarIncidentsLocked` in the Go backend owns "which past incidents are
similar". Here we answer "which failure family does this incident's evidence
point to, and how confidently", and cite the agents that back each candidate.

Encodes rules R1-R6 from agent/knowledge/troubleshooting_cases.md. Keyword
heuristics over collector text, not a model.

ponytail: substring keyword scan over each collector's summary/artifacts/details,
scoped per family to the agents that own that signal. Upgrade to structured
detail parsing (or an LLM judge) only if the eval hit-rate stalls.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from app.collectors.base import AnalysisTarget, CollectorResult
from app.knowledge import load_family_catalog

_FAMILY_CATALOG = load_family_catalog(os.getenv("FAMILIES_FILE", "knowledge/families.yaml"))
FAMILIES = _FAMILY_CATALOG.families
INSUFFICIENT = "insufficient_evidence"
_FAMILY_RULES = _FAMILY_CATALOG.rules

_FLOOR = 2.0          # min top score below which we fall back to insufficient_evidence
_HIGH = 5.0           # score needed (with >=2 corroborating agents) for high confidence
_MED = 2.5
_CONF_ORDER = ("low", "medium", "high")


@dataclass
class RankedCause:
    family: str
    confidence: str
    score: float
    rationale: list[str] = field(default_factory=list)
    evidence_agents: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "confidence": self.confidence,
            "score": round(self.score, 2),
            "rationale": self.rationale,
            "evidence_agents": self.evidence_agents,
        }


@dataclass
class _Score:
    points: float = 0.0
    rationale: list[str] = field(default_factory=list)
    agents: set[str] = field(default_factory=set)
    force_high: bool = False


def rank_root_cause_candidates(
    target: AnalysisTarget,
    results: list[CollectorResult],
    occurrence_count: int = 0,
    top_n: int = 3,
    kg_blast_radius: int = 0,
    priors: dict[str, float] | None = None,
) -> list[RankedCause]:
    top_n = max(1, top_n)
    text_by_agent = {r.agent: _result_text(r) for r in results}
    status_by_agent = {r.agent: r.status for r in results}
    blast, blast_agents = _kg_blast_radius(results)
    # Blast radius now comes from synthesis-time KG enrichment, not a collector.
    if kg_blast_radius > blast:
        blast = kg_blast_radius
        blast_agents = blast_agents | {"knowledge-graph"}

    scores = {fam: _Score() for fam in FAMILIES}
    for fam, (canonical, agents, keywords) in _FAMILY_RULES.items():
        s = scores[fam]
        for agent in agents:
            text = text_by_agent.get(agent, "")
            if not text:
                continue
            hits = sorted({kw for kw in keywords if kw in text})
            if not hits:
                continue
            weight = 2.0 if agent == canonical else 1.0
            # cap per-agent contribution so one verbose log can't dominate
            s.points += weight * min(len(hits), 3)
            s.agents.add(agent)
            s.rationale.append(f"{agent} evidence matched {', '.join(hits[:3])}")

    _apply_bonuses(scores, blast, blast_agents, occurrence_count)

    # Optional feedback-derived priors nudge a family that already has a signal
    # (multiplier on its score). Priors never create a candidate from nothing.
    if priors:
        for fam, s in scores.items():
            factor = priors.get(fam)
            if factor is not None and s.points > 0:
                s.points *= factor
                s.rationale.append(f"feedback prior adjusted score x{factor:.2f}")

    ranked = [
        RankedCause(
            family=fam,
            score=s.points,
            rationale=s.rationale,
            evidence_agents=sorted(s.agents),
            confidence=_confidence(fam, s, status_by_agent),
        )
        for fam, s in scores.items()
        if s.points > 0
    ]
    ranked.sort(key=lambda c: c.score, reverse=True)

    # R6 evidence gate: no family clears the floor / has no corroboration.
    if not ranked or ranked[0].score < _FLOOR or not ranked[0].evidence_agents:
        gate = _insufficient(results, status_by_agent)
        return [gate, *ranked][:top_n]
    return ranked[:top_n]


def _apply_bonuses(
    scores: dict[str, _Score],
    blast: int,
    blast_agents: set[str],
    occurrence_count: int,
) -> None:
    node = scores["node_kubelet_pressure"]
    startup = scores["workload_startup_error"]
    quota = scores["runai_scheduling_quota"]
    control = scores["runai_control_plane_error"]

    # R1: node pressure with blast radius across >=2 workloads on the node.
    if node.points > 0 and blast >= 2:
        node.points += 3.0
        node.agents.update(blast_agents)
        node.force_high = True
        node.rationale.append(f"blast radius: {blast} workloads affected on the same node")
    # R4: startup failure is more likely when the control plane is quiet.
    if startup.points > 0 and control.points == 0:
        startup.points += 1.0
        startup.rationale.append("control-plane logs quiet — points to a workload-local fault")
    # quota signal is stronger when a queue/project is actually in play (already
    # in the matched text); nudge so a lone keyword doesn't tie a real one.
    if quota.points > 0 and any(a in quota.agents for a in ("prometheus", "runai")):
        quota.points += 0.5
    # flapping favours cycling failure modes (node eviction / crashloop).
    if occurrence_count > 1:
        for s in (node, startup):
            if s.points > 0:
                s.points += 0.5
                s.rationale.append("alert is flapping (grouped occurrences) — cycling workload")


def _confidence(fam: str, s: _Score, status_by_agent: dict[str, str]) -> str:
    if s.force_high or (s.points >= _HIGH and len(s.agents) >= 2):
        level = 2  # high
    elif s.points >= _MED or s.agents:
        level = 1  # medium
    else:
        level = 0  # low
    # missing-data penalty: canonical source unavailable -> downgrade one level.
    canonical = _FAMILY_RULES[fam][0]
    if status_by_agent.get(canonical) == "unavailable":
        level = max(0, level - 1)
    return _CONF_ORDER[level]


def _insufficient(
    results: list[CollectorResult], status_by_agent: dict[str, str]
) -> RankedCause:
    unavailable = sorted(a for a, st in status_by_agent.items() if st == "unavailable")
    ok = sorted(a for a, st in status_by_agent.items() if st == "ok")
    rationale = [
        "No failure family cleared the evidence floor from a corroborating source; "
        "naming a root cause would be a guess (R6).",
    ]
    if unavailable:
        rationale.append(f"Evidence gaps: {', '.join(unavailable)} unavailable.")
    confidence = "medium" if len(ok) >= 2 else "low"
    return RankedCause(
        family=INSUFFICIENT,
        confidence=confidence,
        score=0.0,
        rationale=rationale,
        evidence_agents=ok,
    )


def _result_text(result: CollectorResult) -> str:
    parts = [result.summary or ""]
    for art in result.artifacts:
        if art.summary:
            parts.append(art.summary)
        if art.result is not None:
            parts.append(_stringify(art.result))
    if result.details:
        parts.append(_stringify(result.details))
    return " ".join(parts).lower()


def _stringify(value: object) -> str:
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def _kg_blast_radius(results: list[CollectorResult]) -> tuple[int, set[str]]:
    best = 0
    agents: set[str] = set()
    for r in results:
        raw = r.details.get("blast_radius_workloads") or r.details.get("kg_blast_radius")
        if raw is None:
            continue
        try:
            blast = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if blast > best:
            best = blast
            agents = {r.agent}
        elif blast == best and blast > 0:
            agents.add(r.agent)
    return best, agents
