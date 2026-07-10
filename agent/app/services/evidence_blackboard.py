"""Typed, query-safe evidence shared by open-world RCA workers.

Collectors are allowed to return rich artifacts (including the query that was
used to obtain them).  A blackboard intentionally retains only the observed
finding and stable provenance needed for reasoning.  This prevents a probe
string from later being mistaken for evidence by a ranker or an LLM.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from app.collectors.base import NO_EVIDENCE, CollectorResult
from app.collectors.base import artifact as make_artifact
from app.masking import Masker, build_masker
from app.schemas import AlertAnalysisArtifact

Polarity = Literal["present", "absent", "unknown", "unavailable"]
Coverage = Literal["scoped", "partial", "unknown"]
EvidenceRole = Literal["support", "contradict", "context"]
HypothesisStatus = Literal["untested", "testing", "supported", "refuted", "provisional"]

_POLARITIES = frozenset({"present", "absent", "unknown", "unavailable"})
_COVERAGE = frozenset({"scoped", "partial", "unknown"})
_ROLES = frozenset({"support", "contradict", "context"})
_HYPOTHESIS_STATUSES = frozenset({"untested", "testing", "supported", "refuted", "provisional"})
_QUERY_KEYS = frozenset(
    {
        "query",
        "queries",
        "url",
        "path",
        "command",
        "arguments",
        "args",
        "request",
        "request_body",
        "sql",
        "logql",
        "promql",
    }
)

# Independence is about the underlying telemetry plane, not the agent that
# happened to read it. Two Kubernetes agents are therefore one source.
_SOURCE_GROUPS = {
    "k8s": "kubernetes_api",
    "kubernetes": "kubernetes_api",
    "kubernetes_api": "kubernetes_api",
    "loki": "loki",
    "prometheus": "prometheus",
    "system": "node_system",
    "node": "node_system",
    "runai": "runai_api",
    "runai_api": "runai_api",
    "postgres": "postgres",
    "postgresql": "postgres",
    "change": "change_control",
}


def source_independence_group(source: str) -> str:
    """Return the stable underlying-source group for corroboration checks."""
    normalized = _normalise_token(source)
    return _SOURCE_GROUPS.get(normalized, normalized or "unknown")


@dataclass(frozen=True, slots=True)
class EvidenceFact:
    """One normalized observation; never carries collector query text."""

    fact_id: str
    artifact_id: str
    timestamp: str
    entity: str
    source: str
    independence_group: str
    predicate: str
    value: str
    quality: str
    polarity: Polarity
    coverage: Coverage
    summary: str = ""
    highlights: tuple[str, ...] = ()
    observed_window_start: str = ""
    observed_window_end: str = ""
    unit: str = ""
    provenance: tuple[tuple[str, str], ...] = ()

    @property
    def evidence_id(self) -> str:
        """Compatibility name used in operator-facing evidence citations."""
        return self.fact_id

    @property
    def is_reliable_absence(self) -> bool:
        return self.polarity == "absent" and self.coverage == "scoped"

    def prompt_dict(self, *, masker: Masker | None = None) -> dict[str, Any]:
        """Return a compact prompt projection with no query or raw result data."""
        active_masker = masker or build_masker(())
        return {
            "evidence_id": self.fact_id,
            "timestamp": active_masker.mask_text(self.timestamp),
            "observed_window": {
                "start": active_masker.mask_text(self.observed_window_start),
                "end": active_masker.mask_text(self.observed_window_end),
            },
            "entity": active_masker.mask_text(self.entity),
            "source": self.source,
            "independence_group": self.independence_group,
            "predicate": self.predicate,
            "value": active_masker.mask_text(self.value),
            "unit": self.unit,
            "quality": self.quality,
            "polarity": self.polarity,
            "coverage": self.coverage,
            "summary": active_masker.mask_text(self.summary),
            "highlights": [active_masker.mask_text(item) for item in self.highlights],
        }


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    fact_id: str
    role: EvidenceRole
    explanation: str = ""

    def __post_init__(self) -> None:
        if self.role not in _ROLES:
            raise ValueError(f"invalid evidence role: {self.role}")


@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id: str
    mechanism: str
    family: str | None = None
    expected_observations: tuple[str, ...] = ()
    falsifiers: tuple[str, ...] = ()
    evidence_links: tuple[EvidenceLink, ...] = ()
    status: HypothesisStatus = "untested"
    next_discriminating_probe: str = ""

    def __post_init__(self) -> None:
        if self.status not in _HYPOTHESIS_STATUSES:
            raise ValueError(f"invalid hypothesis status: {self.status}")

    @property
    def support_evidence_ids(self) -> tuple[str, ...]:
        return tuple(link.fact_id for link in self.evidence_links if link.role == "support")

    @property
    def contradiction_evidence_ids(self) -> tuple[str, ...]:
        return tuple(link.fact_id for link in self.evidence_links if link.role == "contradict")


@dataclass(frozen=True, slots=True)
class DiagnosticProbe:
    probe_id: str
    agent: str
    tool: str
    arguments_template: Mapping[str, Any] = field(default_factory=dict)
    incident_time_window_start: str = ""
    incident_time_window_end: str = ""
    expected_result_shape: str = ""
    supports_when: tuple[str, ...] = ()
    refutes_when: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()


class EvidenceBlackboard:
    """Deduplicated facts and safe, relevant projections for reasoning agents."""

    def __init__(self, facts: Iterable[EvidenceFact] = ()) -> None:
        self._facts: dict[str, EvidenceFact] = {}
        for fact in facts:
            self.add(fact)

    def add(self, fact: EvidenceFact) -> bool:
        """Add a fact once. Returns ``True`` only when it was new."""
        if fact.fact_id in self._facts:
            return False
        self._facts[fact.fact_id] = fact
        return True

    def get(self, fact_id: str) -> EvidenceFact | None:
        return self._facts.get(fact_id)

    def facts(self) -> tuple[EvidenceFact, ...]:
        return tuple(self._facts[fact_id] for fact_id in sorted(self._facts))

    def independence_groups(self, fact_ids: Iterable[str]) -> frozenset[str]:
        """Return groups contributing observed support, excluding unknown gaps."""
        return frozenset(
            fact.independence_group
            for fact_id in fact_ids
            if (fact := self._facts.get(fact_id)) is not None and fact.polarity == "present"
        )

    def has_independent_support(self, fact_ids: Iterable[str], *, minimum: int = 2) -> bool:
        return len(self.independence_groups(fact_ids)) >= minimum

    def relevant_prompt_projection(
        self,
        *,
        entity_hints: Iterable[str] = (),
        fact_ids: Iterable[str] | None = None,
        limit: int = 12,
        masker: Masker | None = None,
    ) -> list[dict[str, Any]]:
        """Prioritize matching entities without leaking raw artifacts or queries."""
        wanted_ids = set(fact_ids) if fact_ids is not None else None
        hints = tuple(_normalise_token(hint) for hint in entity_hints if _normalise_token(hint))
        candidates = [
            fact
            for fact in self._facts.values()
            if wanted_ids is None or fact.fact_id in wanted_ids
        ]
        candidates.sort(key=lambda fact: (-_relevance(fact, hints), fact.fact_id))
        return [fact.prompt_dict(masker=masker) for fact in candidates[: max(0, limit)]]


class Blackboard(EvidenceBlackboard):
    """Integration-facing blackboard API for collectors and reasoning agents.

    ``EvidenceBlackboard`` is deliberately small for pure fact operations;
    this subclass is the convenient boundary for the existing collector
    protocol.  It never stores an artifact's query or raw result.
    """

    def add_result(
        self,
        agent: str,
        result: CollectorResult,
        *,
        entity: str = "",
        timestamp: str = "",
        observed_window_start: str = "",
        observed_window_end: str = "",
    ) -> tuple[EvidenceFact, ...]:
        """Normalize every artifact in a collector result and add new facts."""
        artifacts = result.artifacts or [
            make_artifact(
                agent=agent,
                source=agent,
                type="collector_result",
                status=result.status,
                confidence=result.confidence,
                summary=result.summary,
                # Details may contain raw probe text; normalize_artifact uses
                # them only to recognize an explicit empty success and never
                # carries them into the fact or prompt projection.
                result=result.details,
            )
        ]
        added: list[EvidenceFact] = []
        for item in artifacts:
            raw = _artifact_mapping(item)
            raw = {**raw, "agent": agent or _clean_text(raw.get("agent"))}
            fact = normalize_artifact(
                raw,
                entity=entity,
                timestamp=timestamp,
                observed_window_start=observed_window_start,
                observed_window_end=observed_window_end,
            )
            if self.add(fact):
                added.append(fact)
        return tuple(added)

    def seed_results(
        self,
        results: Mapping[str, CollectorResult] | Iterable[CollectorResult],
        *,
        entity: str = "",
        timestamp: str = "",
        observed_window_start: str = "",
        observed_window_end: str = "",
    ) -> tuple[EvidenceFact, ...]:
        """Seed a blackboard from the legacy collector-result mapping."""
        pairs = results.items() if isinstance(results, Mapping) else (
            (item.agent, item) for item in results
        )
        added: list[EvidenceFact] = []
        for agent, result in pairs:
            added.extend(
                self.add_result(
                    agent,
                    result,
                    entity=entity,
                    timestamp=timestamp,
                    observed_window_start=observed_window_start,
                    observed_window_end=observed_window_end,
                )
            )
        return tuple(added)

    def prompt_view(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Alias used by LLM callers for the safe relevance projection."""
        return self.relevant_prompt_projection(**kwargs)

    def facts_for_agents(self, *, agent: str | None = None) -> tuple[EvidenceFact, ...]:
        """Return query-free facts, optionally limited to one producing agent."""
        facts = self.facts()
        if not agent:
            return facts
        return tuple(
            fact
            for fact in facts
            if dict(fact.provenance).get("agent") == agent
        )

    def evidence_id_for(
        self,
        artifact: AlertAnalysisArtifact | Mapping[str, Any],
        **kwargs: Any,
    ) -> str:
        """Calculate the stable ID before adding the fact to the blackboard."""
        return normalize_artifact(artifact, **kwargs).fact_id


def normalize_artifact(
    artifact: AlertAnalysisArtifact | Mapping[str, Any],
    *,
    entity: str = "",
    timestamp: str = "",
    observed_window_start: str = "",
    observed_window_end: str = "",
    artifact_id: str = "",
    predicate: str = "observation",
    polarity: Polarity | None = None,
    coverage: Coverage | None = None,
    masker: Masker | None = None,
) -> EvidenceFact:
    """Turn a collector artifact into a stable fact without retaining its query.

    Callers may explicitly set polarity/coverage when a tool has richer result
    semantics. The inferred fallback only calls a clean successful no-evidence
    response ``absent``; an unavailable source is never absence.
    """
    raw = _artifact_mapping(artifact)
    source = _clean_text(raw.get("source")) or "unknown"
    status = _normalise_token(_clean_text(raw.get("status")))
    summary = _clean_text(raw.get("summary"))
    highlights = tuple(
        text for item in _as_list(raw.get("highlights")) if (text := _clean_text(item))
    )
    result = raw.get("result")
    resolved_polarity = polarity or _infer_polarity(status, summary, highlights, result)
    if resolved_polarity not in _POLARITIES:
        raise ValueError(f"invalid polarity: {resolved_polarity}")
    resolved_coverage = coverage or _infer_coverage(status, resolved_polarity)
    if resolved_coverage not in _COVERAGE:
        raise ValueError(f"invalid coverage: {resolved_coverage}")
    # Missing tool coverage must never masquerade as a verified negative.
    if resolved_polarity == "absent" and resolved_coverage != "scoped":
        resolved_polarity = "unknown"

    active_masker = masker or build_masker(())
    safe_summary = active_masker.mask_text(summary)
    safe_highlights = tuple(active_masker.mask_text(item) for item in highlights)
    safe_entity = active_masker.mask_text(entity)
    safe_value = _finding_value(safe_summary, safe_highlights, resolved_polarity)
    safe_provenance = (
        ("agent", _clean_text(raw.get("agent"))),
        ("type", _clean_text(raw.get("type"))),
    )
    stable_fields = {
        "artifact_id": artifact_id or _artifact_identity(raw),
        "timestamp": timestamp,
        "window": [observed_window_start, observed_window_end],
        "entity": safe_entity,
        "source": source,
        "predicate": predicate,
        "value": safe_value,
        "polarity": resolved_polarity,
        "coverage": resolved_coverage,
        "summary": safe_summary,
        "highlights": safe_highlights,
        "provenance": safe_provenance,
    }
    fact_id = stable_fact_id(stable_fields)
    return EvidenceFact(
        fact_id=fact_id,
        artifact_id=str(stable_fields["artifact_id"]),
        timestamp=timestamp,
        entity=safe_entity,
        source=source,
        independence_group=source_independence_group(source),
        predicate=predicate,
        value=safe_value,
        quality=_clean_text(raw.get("confidence")) or "low",
        polarity=resolved_polarity,
        coverage=resolved_coverage,
        summary=safe_summary,
        highlights=safe_highlights,
        observed_window_start=observed_window_start,
        observed_window_end=observed_window_end,
        provenance=tuple((key, value) for key, value in safe_provenance if value),
    )


def stable_fact_id(fields: Mapping[str, Any]) -> str:
    """Deterministic ID for a query-free canonical observation payload."""
    encoded = json.dumps(
        fields, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return f"F-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"


def _artifact_mapping(artifact: AlertAnalysisArtifact | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(artifact, AlertAnalysisArtifact):
        return artifact.model_dump()
    return artifact


def _infer_polarity(
    status: str, summary: str, highlights: tuple[str, ...], result: Any
) -> Polarity:
    if status in {"unavailable", "error", "failed", "timeout"}:
        return "unavailable"
    if status not in {"ok", "partial", "success"}:
        return "unknown"
    if summary.startswith(NO_EVIDENCE) or _completed_empty_result(result):
        return "absent"
    if highlights or summary:
        return "present"
    return "unknown"


def _infer_coverage(status: str, polarity: Polarity) -> Coverage:
    if polarity == "unavailable":
        return "unknown"
    if status in {"ok", "success"}:
        return "scoped"
    if status == "partial":
        return "partial"
    return "unknown"


def _completed_empty_result(value: Any, *, parent_key: str = "") -> bool:
    """Recognise an explicitly empty successful result while ignoring query fields."""
    if _normalise_token(parent_key) in _QUERY_KEYS:
        return False
    if isinstance(value, Mapping):
        if not value:
            return False
        meaningful = [
            child
            for key, child in value.items()
            if _normalise_token(str(key)) not in _QUERY_KEYS
        ]
        if not meaningful:
            return False
        return all(
            _completed_empty_result(child, parent_key=str(key)) for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return value == [] or bool(value) and all(_completed_empty_result(item) for item in value)
    if isinstance(value, int) and parent_key in {"line_count", "count", "matches"}:
        return value == 0
    return False


def _finding_value(summary: str, highlights: tuple[str, ...], polarity: Polarity) -> str:
    if highlights:
        return "; ".join(highlights)
    if polarity == "absent":
        return "no matching observation"
    if polarity == "unavailable":
        return "source unavailable"
    return summary


def _artifact_identity(raw: Mapping[str, Any]) -> str:
    # Both the collector and the response-local citation layer may attach an
    # ``evidence_id`` to the same artifact at different times.  It is a
    # presentation alias, not part of the observation, so including it here
    # would create a different F-id after ``assign_evidence_ids`` runs.
    # Query is likewise intentionally excluded: it is a retrieval instruction,
    # not evidence.
    identity = {
        key: raw.get(key)
        for key in ("agent", "source", "type", "status", "summary", "highlights")
    }
    return stable_fact_id(identity)


def _relevance(fact: EvidenceFact, hints: tuple[str, ...]) -> int:
    haystack = _normalise_token(" ".join((fact.entity, fact.predicate, fact.value, fact.summary)))
    return sum(1 for hint in hints if hint and hint in haystack)


def _normalise_token(value: str) -> str:
    return re.sub(r"[^a-z0-9_./:-]+", "", value.strip().lower().replace(" ", "_"))


def _clean_text(value: object) -> str:
    return " ".join(str(value or "").split())


def _as_list(value: object) -> list[object]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return []
