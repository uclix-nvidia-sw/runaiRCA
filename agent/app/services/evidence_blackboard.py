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
from datetime import datetime
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
    # The current change collector reads Kubernetes rollout state. It is not an
    # independent audit plane unless a future collector explicitly identifies
    # an external GitOps/audit source group.
    "change": "kubernetes_api",
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
    run_id: str = ""
    topology: tuple[str, ...] = ()

    @property
    def evidence_id(self) -> str:
        """Compatibility name used in operator-facing evidence citations."""
        return self.fact_id

    @property
    def is_reliable_absence(self) -> bool:
        return self.polarity == "absent" and self.coverage == "scoped"

    @property
    def source_group(self) -> str:
        """Public v3 name for the telemetry-independence grouping."""
        return self.independence_group

    @property
    def observation_window(self) -> tuple[str, str]:
        """The incident window in which this observation was evaluated."""
        return (self.observed_window_start, self.observed_window_end)

    @property
    def eligibility(self) -> EvidenceEligibility:
        return EvidenceEligibility.from_fact(self)

    def prompt_dict(self, *, masker: Masker | None = None) -> dict[str, Any]:
        """Return a compact prompt projection with no query or raw result data."""
        active_masker = masker or build_masker(())
        observed_window = {
            "start": active_masker.mask_text(self.observed_window_start),
            "end": active_masker.mask_text(self.observed_window_end),
        }
        return {
            "evidence_id": self.fact_id,
            "timestamp": active_masker.mask_text(self.timestamp),
            # Keep v2's observed_window while offering the clearer v3 name.
            "observed_window": observed_window,
            "observation_window": observed_window,
            "entity": active_masker.mask_text(self.entity),
            "source": self.source,
            "independence_group": self.independence_group,
            "source_group": self.source_group,
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
class EvidenceEligibility:
    """Whether one observation may ground a typed reasoning link.

    Availability gaps and unknown observations are useful operational context,
    but are never proof.  An explicitly empty, fully scoped observation is
    useful only to refute a hypothesis; it cannot be promoted into support.
    """

    support: bool
    refutation: bool
    context: bool
    reason: str = ""

    @classmethod
    def from_fact(
        cls, fact: EvidenceFact, *, context: Mapping[str, Any] | None = None
    ) -> EvidenceEligibility:
        base = cls.from_fields(fact.polarity, fact.coverage)
        if not context:
            return base
        expected_run = _clean_text(context.get("run_id"))
        if expected_run and fact.run_id and expected_run != fact.run_id:
            return cls(False, False, False, "evidence belongs to a different run")
        if not _window_compatible(
            fact.observed_window_start,
            fact.observed_window_end,
            _clean_text(context.get("window_start")),
            _clean_text(context.get("window_end")),
        ):
            return cls(False, False, False, "evidence is outside the incident window")
        expected_entities = _context_tokens(context.get("entities"))
        if expected_entities and fact.entity and not _tokens_overlap(
            _context_tokens((fact.entity,)), expected_entities
        ):
            return cls(False, False, False, "evidence targets a different entity")
        expected_topology = _context_tokens(context.get("topology"))
        if expected_topology and fact.topology and not _tokens_overlap(
            _context_tokens(fact.topology), expected_topology
        ):
            return cls(False, False, False, "evidence conflicts with target topology")
        return base

    @classmethod
    def from_fields(cls, polarity: str, coverage: str) -> EvidenceEligibility:
        if polarity == "present":
            return cls(True, True, True)
        if polarity == "absent" and coverage == "scoped":
            return cls(False, True, True, "scoped absence may only refute")
        if polarity == "absent":
            return cls(False, False, True, "absence is not fully scoped")
        if polarity == "unavailable":
            return cls(False, False, True, "source unavailable")
        return cls(False, False, True, "observation is unknown")

    def permits(self, role: EvidenceRole | str) -> bool:
        if role == "support":
            return self.support
        if role == "contradict":
            return self.refutation
        return self.context


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
        details = result.details if isinstance(result.details, Mapping) else {}
        source_group = _clean_text(details.get("source_group"))
        run_id = _clean_text(details.get("run_id") or details.get("incident_run_id"))
        topology = details.get("topology") or details.get("target_topology")
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
                source_group=source_group,
                run_id=run_id,
                topology=topology,
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
    source_group: str = "",
    run_id: str = "",
    topology: object = (),
    masker: Masker | None = None,
) -> EvidenceFact:
    """Turn a collector artifact into a stable fact without retaining its query.

    Callers may explicitly set polarity/coverage when a tool has richer result
    semantics. The inferred fallback only calls a clean successful no-evidence
    response ``absent``; an unavailable source is never absence.
    """
    raw = _artifact_mapping(artifact)
    result = raw.get("result")
    result_metadata = result if isinstance(result, Mapping) else {}
    observation = result_metadata.get("observation")
    observation_metadata = observation if isinstance(observation, Mapping) else {}

    def metadata(key: str) -> object:
        return raw.get(key) or result_metadata.get(key) or observation_metadata.get(key)

    # A collector-provided observation window is more precise than the broad
    # incident window supplied by the pipeline.  Preserve it for causal/timing
    # review rather than overwriting it with the alert's lifetime.
    raw_window = metadata("observation_window") or metadata("observed_window")
    if isinstance(raw_window, Mapping):
        observed_window_start = _clean_text(raw_window.get("start")) or observed_window_start
        observed_window_end = _clean_text(raw_window.get("end")) or observed_window_end
    observed_window_start = _clean_text(metadata("observed_window_start")) or observed_window_start
    observed_window_end = _clean_text(metadata("observed_window_end")) or observed_window_end
    source = _clean_text(raw.get("source")) or "unknown"
    status = _normalise_token(_clean_text(raw.get("status")))
    summary = _clean_text(raw.get("summary"))
    highlights = tuple(
        text for item in _as_list(raw.get("highlights")) if (text := _clean_text(item))
    )
    # Prefer an explicit collector verdict over text heuristics. Structured
    # probes already know whether a condition was present, absent, or merely
    # unavailable; reducing that to an "error" keyword would make every agent
    # reinforce the same false positive during synthesis.
    metadata_polarity = _normalise_token(_clean_text(metadata("polarity")))
    resolved_polarity = (
        polarity
        or (metadata_polarity if metadata_polarity in _POLARITIES else None)
        or _infer_polarity(status, summary, highlights, result)
    )
    if resolved_polarity not in _POLARITIES:
        raise ValueError(f"invalid polarity: {resolved_polarity}")
    metadata_coverage = _normalise_token(_clean_text(metadata("coverage")))
    resolved_coverage = (
        coverage
        or (metadata_coverage if metadata_coverage in _COVERAGE else None)
        or _infer_coverage(status, resolved_polarity)
    )
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
    # Legacy artifacts did not name their predicate. Use structured probe
    # metadata when available, then the artifact type as a bounded fallback.
    # Explicit callers retain ownership of a more specific predicate.
    resolved_predicate = predicate
    if predicate == "observation":
        resolved_predicate = (
            _clean_text(metadata("predicate"))
            or _clean_text(metadata("kind"))
            or _clean_text(raw.get("type"))
            or predicate
        )
    resolved_predicate = _normalise_token(resolved_predicate) or "observation"
    safe_provenance = (
        ("agent", _clean_text(raw.get("agent"))),
        ("type", _clean_text(raw.get("type"))),
    )
    resolved_run_id = _clean_text(run_id or metadata("run_id") or metadata("incident_run_id"))
    resolved_topology = _context_tokens(
        topology or metadata("topology") or metadata("target_topology")
    )
    stable_fields = {
        "artifact_id": artifact_id or _artifact_identity(raw),
        "timestamp": timestamp,
        "window": [observed_window_start, observed_window_end],
        "entity": safe_entity,
        "source": source,
        "predicate": resolved_predicate,
        "value": safe_value,
        "polarity": resolved_polarity,
        "coverage": resolved_coverage,
        "run_id": resolved_run_id,
        "topology": resolved_topology,
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
        independence_group=source_independence_group(
            _clean_text(source_group or metadata("source_group")) or source
        ),
        predicate=resolved_predicate,
        value=safe_value,
        quality=_clean_text(raw.get("confidence")) or "low",
        polarity=resolved_polarity,
        coverage=resolved_coverage,
        summary=safe_summary,
        highlights=safe_highlights,
        observed_window_start=observed_window_start,
        observed_window_end=observed_window_end,
        provenance=tuple((key, value) for key, value in safe_provenance if value),
        run_id=resolved_run_id,
        topology=resolved_topology,
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


def _context_tokens(value: object) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        values = (f"{key}:{item}" for key, item in value.items() if _clean_text(item))
    elif isinstance(value, str):
        values = (value,)
    elif isinstance(value, Iterable):
        values = (str(item) for item in value)
    else:
        values = ()
    return tuple(token for item in values if (token := _normalise_token(_clean_text(item))))


def _tokens_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    return bool(set(left) & set(right))


def _window_compatible(
    observed_start: str, observed_end: str, incident_start: str, incident_end: str
) -> bool:
    """Reject only explicit non-overlap; missing context remains compatible."""
    if not (observed_start and observed_end and incident_start and incident_end):
        return True
    try:
        start = _parse_time(observed_start)
        end = _parse_time(observed_end)
        incident_from = _parse_time(incident_start)
        incident_to = _parse_time(incident_end)
    except ValueError:
        return True
    return start <= incident_to and end >= incident_from


def temporal_relation_to_incident(
    observed_start: str, observed_end: str, incident_start: str, incident_end: str
) -> str:
    """Classify timing without pretending a post-incident observation is a cause.

    The result is descriptive, not an eligibility gate: a log captured after
    an alert can still corroborate a condition, but reviewers can no longer
    mistake it for evidence observed before the symptom.
    """
    if not (observed_start and observed_end and incident_start and incident_end):
        return "unknown"
    try:
        start = _parse_time(observed_start)
        end = _parse_time(observed_end)
        incident_from = _parse_time(incident_start)
        incident_to = _parse_time(incident_end)
    except ValueError:
        return "unknown"
    if end < incident_from:
        return "precedes_incident"
    if start > incident_to:
        return "follows_incident"
    if start >= incident_from and end <= incident_to:
        return "during_incident"
    return "overlaps_incident"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
