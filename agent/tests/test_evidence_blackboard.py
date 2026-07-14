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


def test_independence_excludes_positive_partial_coverage() -> None:
    scoped = normalize_artifact(
        _artifact(source="kubernetes", agent="kubernetes", summary="Pod was Evicted")
    )
    partial = normalize_artifact(
        _artifact(
            source="prometheus",
            agent="prometheus",
            summary="Memory usage was high in an incomplete sample window",
            status="partial",
            result={
                "observation": {
                    "kind": "metric",
                    "polarity": "present",
                    "coverage": "partial",
                }
            },
        )
    )
    board = EvidenceBlackboard([scoped, partial])

    assert board.independence_groups([scoped.fact_id, partial.fact_id]) == {"kubernetes_api"}
    assert not board.has_independent_support([scoped.fact_id, partial.fact_id])


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


def test_blackboard_keeps_untyped_summary_as_context_only() -> None:
    """A successful text-only legacy artifact cannot support an RCA hypothesis."""
    item = _artifact(
        agent="kubernetes",
        source="kubernetes",
        summary="Pod trainer-0 is Evicted.",
        result={"events": [{"reason": "Evicted"}]},
    )
    board = Blackboard()

    [fact] = board.add_result(
        "kubernetes",
        CollectorResult(agent="kubernetes", status="ok", summary=item.summary or "", artifacts=[item]),
        entity="pod:trainer-0",
    )

    assert (fact.polarity, fact.coverage) == ("unknown", "unknown")
    assert not fact.eligibility.support
    assert fact.eligibility.context


def test_blackboard_requires_a_nested_observation_envelope() -> None:
    """Loose result keys cannot impersonate a collector typed verdict."""
    item = _artifact(
        source="kubernetes",
        result={"polarity": "present", "coverage": "scoped"},
    )
    board = Blackboard()

    [fact] = board.add_result(
        "kubernetes",
        CollectorResult(agent="kubernetes", status="ok", summary=item.summary or "", artifacts=[item]),
        entity="pod:trainer-0",
    )

    assert (fact.polarity, fact.coverage) == ("unknown", "unknown")
    assert not fact.eligibility.support


def test_malformed_declared_scope_is_not_relabelled_as_alert_target() -> None:
    """An incomplete collector scope must not inherit a valid incident scope."""
    item = _artifact(
        source="kubernetes",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "observed_entity": {"kind": "Pod"},
                "observation_window": {
                    "start": "",
                    "end": "2026-07-13T00:10:00Z",
                },
            }
        },
    )
    board = Blackboard(run_id="run-a")

    [fact] = board.add_result(
        "kubernetes",
        CollectorResult(agent="kubernetes", status="ok", summary=item.summary or "", artifacts=[item]),
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert fact.entity == ""
    assert fact.observation_window == ("", "")
    assert (fact.polarity, fact.coverage) == ("unknown", "partial")
    eligibility = fact.eligibility.from_fact(
        fact,
        context={
            "run_id": "run-a",
            "window_start": "2026-07-13T00:00:00Z",
            "window_end": "2026-07-13T00:10:00Z",
            "entities": ["pod:trainer-0"],
        },
    )
    assert not eligibility.support


def test_typed_scoped_artifact_without_observed_entity_cannot_inherit_alert_target() -> None:
    """Pipeline target context must not turn a broad result into Pod evidence."""
    item = _artifact(
        source="kubernetes",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "observation_window": {
                    "start": "2026-07-13T00:00:00Z",
                    "end": "2026-07-13T00:10:00Z",
                },
            }
        },
    )
    board = Blackboard(run_id="run-a")

    [fact] = board.add_result(
        "kubernetes",
        CollectorResult(agent="kubernetes", status="ok", summary=item.summary or "", artifacts=[item]),
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert fact.entity == ""
    assert (fact.polarity, fact.coverage) == ("unknown", "partial")
    assert not fact.eligibility.from_fact(
        fact,
        context={
            "run_id": "run-a",
            "window_start": "2026-07-13T00:00:00Z",
            "window_end": "2026-07-13T00:10:00Z",
            "entities": ["pod:trainer-0"],
        },
    ).support


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


def test_eligibility_keeps_partially_covered_positive_as_context_only() -> None:
    partial = normalize_artifact(
        _artifact(
            summary="node log tail contains OOM",
            result={
                "observation": {
                    "kind": "system_log_query",
                    "predicate": "system_log_query",
                    "polarity": "present",
                    "coverage": "partial",
                }
            },
        )
    )

    assert not partial.eligibility.permits("support")
    assert not partial.eligibility.permits("contradict")
    assert partial.eligibility.permits("context")


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


def test_run_context_fails_closed_when_fact_identity_is_missing() -> None:
    fact = normalize_artifact(
        _artifact(
            source="kubernetes",
            result={"observation": {"polarity": "present", "coverage": "scoped"}},
        ),
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    missing_run = fact.eligibility.from_fact(fact, context={"run_id": "run-a"})
    assert not missing_run.support
    assert missing_run.context
    assert "run identity is missing" in missing_run.reason


def test_blackboard_stamps_its_run_but_preserves_declared_cross_run_identity() -> None:
    board = Blackboard(run_id="run-a")
    result = CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="Pod trainer-0 was Evicted",
        artifacts=[
            _artifact(
                source="kubernetes",
                result={"observation": {"polarity": "present", "coverage": "scoped"}},
            ),
            _artifact(
                source="kubernetes",
                result={
                    "run_id": "run-b",
                    "observation": {"polarity": "present", "coverage": "scoped"},
                },
            ),
        ],
    )

    current, stale = board.add_result(
        "kubernetes",
        result,
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert current.run_id == "run-a"
    assert board.evidence_id_for(
        result.artifacts[0],
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    ) == current.fact_id
    assert stale.run_id == "run-b"
    assert not stale.eligibility.from_fact(stale, context={"run_id": "run-a"}).support


def test_eligibility_requires_an_observation_window_for_historical_support() -> None:
    fact = normalize_artifact(
        _artifact(source="kubernetes", summary="Pod was Evicted"), entity="pod:trainer-0"
    )

    eligibility = fact.eligibility.from_fact(
        fact,
        context={
            "window_start": "2026-07-13T00:00:00Z",
            "window_end": "2026-07-13T00:10:00Z",
        },
    )

    assert not eligibility.support
    assert eligibility.context
    assert "window is missing" in eligibility.reason


def test_collector_observed_entity_overrides_seed_target_identity() -> None:
    board = Blackboard()
    facts = board.add_result(
        "kubernetes",
        CollectorResult(
            agent="kubernetes",
            status="ok",
            summary="other-worker-0 was OOMKilled",
            artifacts=[
                _artifact(
                    source="kubernetes",
                    summary="other-worker-0 was OOMKilled",
                    result={
                        "observation": {
                            "polarity": "present",
                            "coverage": "scoped",
                            "observed_entity": {"kind": "Pod", "name": "other-worker-0"},
                        }
                    },
                )
            ],
        ),
        entity="pod:trainer-0",
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
    )

    assert facts[0].entity == "pod:other-worker-0"
    assert not facts[0].eligibility.from_fact(
        facts[0],
        context={
            "window_start": "2026-07-13T00:00:00Z",
            "window_end": "2026-07-13T00:10:00Z",
            "entities": ["pod:trainer-0"],
        },
    ).support


def test_namespaced_observed_entity_rejects_same_named_pod_in_another_namespace() -> None:
    fact = normalize_artifact(
        _artifact(
            source="kubernetes",
            summary="trainer-0 was OOMKilled",
            result={
                "observation": {
                    "polarity": "present",
                    "coverage": "scoped",
                    "observed_entity": {
                        "kind": "pod",
                        "name": "trainer-0",
                        "namespace": "other-team",
                    },
                }
            },
        ),
        observed_window_start="2026-07-13T00:00:00Z",
        observed_window_end="2026-07-13T00:10:00Z",
        require_typed_observation=True,
    )

    eligibility = fact.eligibility.from_fact(
        fact,
        context={
            "window_start": "2026-07-13T00:00:00Z",
            "window_end": "2026-07-13T00:10:00Z",
            "entities": ["pod:trainer-0", "namespace:target-team"],
        },
    )

    assert fact.entity_scope == ("namespace:other-team",)
    assert not eligibility.support
    assert "entity scope" in eligibility.reason


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


def test_evidence_occurrence_window_blocks_post_resolution_recovery_signal() -> None:
    """A query can overlap an incident even when its only signal is recovery-time."""
    fact = normalize_artifact(
        _artifact(
            source="loki",
            result={
                "observation": {
                    "polarity": "present",
                    "coverage": "scoped",
                    # The range deliberately includes a post-resolution
                    # epilogue for collection completeness.
                    "observation_window": {
                        "start": "2026-07-13T00:55:00Z",
                        "end": "2026-07-13T01:15:00Z",
                    },
                    # But this error was observed only after resolution.
                    "evidence_window": {
                        "start": "2026-07-13T01:11:00Z",
                        "end": "2026-07-13T01:12:00Z",
                    },
                }
            },
        ),
        entity="pod:trainer-0",
    )

    eligibility = fact.eligibility.from_fact(
        fact,
        context={
            "window_start": "2026-07-13T01:00:00Z",
            "window_end": "2026-07-13T01:10:00Z",
        },
    )

    assert fact.observation_window == ("2026-07-13T01:11:00Z", "2026-07-13T01:12:00Z")
    assert not eligibility.support
    assert "outside the incident window" in eligibility.reason


def test_timezone_less_windows_are_context_not_comparison_errors() -> None:
    assert temporal_relation_to_incident(
        "2026-07-13T00:00:00",
        "2026-07-13T00:01:00",
        "2026-07-13T00:00:00Z",
        "2026-07-13T00:10:00Z",
    ) == "unknown"
