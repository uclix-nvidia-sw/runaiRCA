from __future__ import annotations

import json

from app.collectors.base import NO_EVIDENCE, CollectorResult, artifact
from app.services.evidence_blackboard import (
    Blackboard,
    EvidenceBlackboard,
    normalize_artifact,
    source_independence_group,
    temporal_relation_to_incident,
)


def _artifact(*, source: str = "loki", status: str = "ok", **kwargs):
    return artifact(
        agent=kwargs.pop("agent", source),
        source=source,
        type=kwargs.pop("type", "logs"),
        status=status,
        confidence=kwargs.pop("confidence", "high"),
        summary=kwargs.pop("summary", "Observed FailedMount on pod trainer-0."),
        query=kwargs.pop("query", '{namespace="runai"} |= "FailedMount"'),
        result=kwargs.pop("result", {"lines": ["FailedMount"]}),
        highlights=kwargs.pop("highlights", ["FailedMount"]),
        **kwargs,
    )


def test_normalized_fact_id_is_deterministic_and_query_independent() -> None:
    first = normalize_artifact(_artifact(query="secret-query-a"), entity="pod/trainer-0")
    second = normalize_artifact(_artifact(query="secret-query-b"), entity="pod/trainer-0")

    assert first.fact_id == second.fact_id
    assert first.fact_id.startswith("F-")
    assert "secret-query" not in json.dumps(first.prompt_dict())


def test_unavailable_is_not_absence_and_empty_success_is_scoped_absence() -> None:
    unavailable = normalize_artifact(
        _artifact(status="unavailable", summary="Loki transport failed", highlights=[], result=None)
    )
    empty = normalize_artifact(
        _artifact(
            summary=f"{NO_EVIDENCE} Loki returned no matching lines.",
            highlights=[],
            result={"line_count": 0, "query": "do-not-leak"},
        )
    )
    partial = normalize_artifact(
        _artifact(
            status="partial",
            summary=f"{NO_EVIDENCE} Partial result.",
            highlights=[],
            result={"line_count": 0},
        )
    )

    assert unavailable.polarity == "unavailable"
    assert unavailable.coverage == "unknown"
    assert empty.polarity == "absent"
    assert empty.is_reliable_absence
    assert partial.polarity == "unknown"
    assert not partial.is_reliable_absence


def test_structured_probe_metadata_wins_over_keyword_inference() -> None:
    # The summary deliberately contains a tempting failure keyword. The probe
    # verified the target condition was false, so it must become refuting
    # evidence rather than support for a keyword-matched root cause.
    fact = normalize_artifact(
        _artifact(
            source="kubernetes",
            type="node_condition",
            summary="MemoryPressure keyword appeared in an unrelated event.",
            result={
                "observation": {
                    "kind": "node_condition",
                    "polarity": "absent",
                    "coverage": "scoped",
                }
            },
        )
    )

    assert fact.predicate == "node_condition"
    assert fact.polarity == "absent"
    assert fact.coverage == "scoped"
    assert not fact.eligibility.support
    assert fact.eligibility.refutation


def test_independence_counts_underlying_source_not_agent() -> None:
    first = normalize_artifact(
        _artifact(source="kubernetes", agent="kubernetes", summary="Pod Evicted")
    )
    second = normalize_artifact(
        _artifact(source="k8s", agent="change", summary="Pod Evicted again")
    )
    third = normalize_artifact(
        _artifact(source="loki", agent="loki", summary="Eviction in kubelet log")
    )
    board = EvidenceBlackboard([first, second, third])

    assert board.independence_groups([first.fact_id, second.fact_id]) == {"kubernetes_api"}
    assert not board.has_independent_support([first.fact_id, second.fact_id])
    assert board.has_independent_support([first.fact_id, third.fact_id])


def test_blackboard_deduplicates_stable_fact_ids() -> None:
    fact = normalize_artifact(_artifact(), entity="pod/trainer-0")
    duplicate = normalize_artifact(_artifact(), entity="pod/trainer-0")
    board = EvidenceBlackboard()

    assert board.add(fact)
    assert not board.add(duplicate)
    assert [item.fact_id for item in board.facts()] == [fact.fact_id]


def test_prompt_projection_is_relevant_and_never_exposes_query_or_raw_result() -> None:
    target = normalize_artifact(
        _artifact(
            summary="Pod trainer-0 has FailedMount.",
            query='kubectl get secret --token=should-not-appear',
            result={"query": "also-not-appear", "lines": ["FailedMount"]},
        ),
        entity="pod/trainer-0",
    )
    unrelated = normalize_artifact(
        _artifact(summary="Node dgx01 has DiskPressure."), entity="node/dgx01"
    )
    board = EvidenceBlackboard([unrelated, target])

    projection = board.relevant_prompt_projection(entity_hints=["trainer-0"], limit=1)
    encoded = json.dumps(projection)

    assert projection[0]["evidence_id"] == target.fact_id
    assert "should-not-appear" not in encoded
    assert "also-not-appear" not in encoded
    assert "result" not in projection[0]
    assert "query" not in projection[0]


def test_integration_blackboard_seeds_collector_results_and_exposes_safe_api() -> None:
    item = _artifact(agent="kubernetes", source="kubernetes", summary="Pod trainer-0 is Evicted.")
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="Pod trainer-0 is Evicted.",
        confidence="high",
        artifacts=[item],
    )
    board = Blackboard()

    added = board.seed_results({"kubernetes": result}, entity="pod/trainer-0")

    assert len(added) == 1
    assert board.evidence_id_for(item, entity="pod/trainer-0") == added[0].fact_id
    assert board.facts_for_agents(agent="kubernetes") == added
    assert board.prompt_view(entity_hints=["trainer-0"])[0]["evidence_id"] == added[0].fact_id


def test_response_local_evidence_alias_does_not_change_fact_identity() -> None:
    item = _artifact(agent="kubernetes", source="kubernetes", summary="Pod trainer-0 is Evicted.")
    board = Blackboard()
    original = board.add_result("kubernetes", CollectorResult(
        agent="kubernetes", status="ok", summary="Pod trainer-0 is Evicted.", artifacts=[item]
    ))[0]

    item.evidence_id = "E01"

    assert board.evidence_id_for(item) == original.fact_id


def test_eligibility_rejects_unknown_support_and_limits_scoped_absence_to_refutation() -> None:
    unknown = normalize_artifact(_artifact(status="pending", summary="incomplete", highlights=[]))
    absent = normalize_artifact(
        _artifact(summary=f"{NO_EVIDENCE} no matching lines", highlights=[], result={"count": 0})
    )

    assert not unknown.eligibility.permits("support")
    assert not unknown.eligibility.permits("contradict")
    assert not absent.eligibility.permits("support")
    assert absent.eligibility.permits("contradict")


def test_change_source_is_kubernetes_unless_collector_overrides_group() -> None:
    item = _artifact(source="change", agent="change", summary="deployment revision observed")
    board = Blackboard()
    overridden = board.add_result(
        "change",
        CollectorResult(
            agent="change",
            status="ok",
            summary=item.summary or "",
            artifacts=[item],
            details={"source_group": "external_audit"},
        ),
    )

    assert source_independence_group("change") == "kubernetes_api"
    assert overridden[0].source_group == "external_audit"


def test_eligibility_rejects_explicit_wrong_run_window_entity_or_topology() -> None:
    fact = normalize_artifact(
        {
            "agent": "kubernetes",
            "source": "kubernetes",
            "type": "event",
            "status": "ok",
            "summary": "FailedMount",
            "run_id": "run-a",
            "topology": ["cluster:one", "node:gpu-01"],
        },
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert not fact.eligibility.from_fact(fact, context={"run_id": "run-b"}).support
    assert not fact.eligibility.from_fact(
        fact,
        context={"window_start": "2026-07-13T01:00:00Z", "window_end": "2026-07-13T02:00:00Z"},
    ).support
    assert not fact.eligibility.from_fact(fact, context={"entities": ["pod:other"]}).support
    assert not fact.eligibility.from_fact(fact, context={"topology": ["cluster:two"]}).support


def test_precise_artifact_window_wins_and_is_classified_for_causal_review() -> None:
    fact = normalize_artifact(
        {
            "agent": "change",
            "source": "change",
            "type": "rollout",
            "status": "ok",
            "summary": "Deployment revision changed",
            # Drilldown artifacts retain a tool's observation as their result.
            "result": {
                "observation_window": {
                    "start": "2026-07-13T00:00:00Z",
                    "end": "2026-07-13T00:01:00Z",
                },
                "source_group": "external_audit",
            },
        },
        observed_window_start="2026-07-13T00:05:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert fact.observation_window == ("2026-07-13T00:00:00Z", "2026-07-13T00:01:00Z")
    assert fact.source_group == "external_audit"
    assert temporal_relation_to_incident(
        *fact.observation_window, "2026-07-13T00:05:00Z", "2026-07-13T00:10:00Z"
    ) == "precedes_incident"
