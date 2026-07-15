import re

from app.collectors import kubernetes, loki, postgres, runai
from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.masking import MASK_TOKEN, build_masker
from app.services import pipeline, self_check


def _target(**values) -> AnalysisTarget:
    base = dict(
        cluster="", project="vision", queue="gpu-a", namespace="runai",
        workload_name="trainer", workload_type="", runai_workload_id="", node="", pod="",
        severity="", alert_name="", fired_at="2026-07-10T01:00:00Z",
        resolved_at="2026-07-10T01:10:00Z",
    )
    base.update(values)
    return AnalysisTarget(**base)


def test_loki_gpu_fetch_tokens_are_failure_shaped_and_affirmed() -> None:
    assert loki._LOKI_FAILURE_TOKEN_RE.search("NVRM: Xid 79")
    assert loki._LOKI_FAILURE_TOKEN_RE.search("CUDA out of memory")
    fetch = re.compile(loki._LOKI_ERROR_FETCH_PATTERN)
    assert not fetch.search("using cuda:0")
    assert not fetch.search("NCCL INFO Bootstrap")


def test_postgres_history_keeps_causal_row_when_sample_has_epilogue() -> None:
    table = {
        "context_columns": ["workload_name"],
        "target_rows": [
            {"event_time": "2026-07-10T01:12:00Z", "workload_name": "trainer"},
            {"event_time": "2026-07-10T00:59:00Z", "workload_name": "trainer"},
        ],
    }
    verified, window, _ = postgres._verified_target_history_rows(
        table, _target(), {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}, 2
    )
    assert verified is True
    assert window == {"start": "2026-07-10T00:59:00Z", "end": "2026-07-10T00:59:00Z"}


def test_postgres_naive_timestamp_type_disclosure_includes_absence() -> None:
    artifacts = postgres._postgres_history_artifacts(
        _target(),
        {"time_range": {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"}, "tables": [{
            "schema": "audit", "table": "events", "timestamp_type": "timestamp without time zone",
            "target_correlation_available": True, "target_aggregate_verified": True,
            "target_matching_rows": 0, "target_rows": [],
        }]},
    )
    assert artifacts[0].result["observation"]["naive_timestamps_assumed_utc"] is True


def test_runai_precomputed_full_payload_window_survives_compaction() -> None:
    target = _target()
    full = {"workloads": [
        {"name": f"other-{index}"} for index in range(5)
    ] + [{"name": "trainer", "statusTransitionTime": "2026-07-10T01:04:00Z"}]}
    observation = runai._runai_query_observation(
        {"name": "workloads", "identity_matched": True, "data": {"workloads": full["workloads"][:5]},
         "evidence_window": runai._runai_evidence_window(full, "workloads", target, {"start": "2026-07-10T00:55:00Z", "end": "2026-07-10T01:15:00Z"})},
        target=target, used_mcp=False,
    )
    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")


def test_empty_mcp_payload_remains_valid_and_requests_direct_equivalent() -> None:
    item = runai._validated_runai_query_results([
        {"name": "workloads", "transport": "mcp", "status_code": 200, "data": {"total": 0}}
    ])[0]
    assert item.get("error") is None
    assert item["explicitly_empty"] is True


def test_event_sort_uses_nonzero_newest_timestamp() -> None:
    event = {"eventTime": "0001-01-01T00:00:00Z", "series": {"lastObservedTime": "2026-07-10T01:04:00Z"}}
    assert kubernetes._event_sort_timestamp(event) == (True, "2026-07-10T01:04:00+00:00")


def test_masking_keeps_token_prose_but_masks_password() -> None:
    masker = build_masker(())
    assert masker.mask_text("failed to get token: connection refused") == "failed to get token: connection refused"
    assert masker.mask_text("password: monkey") == f"password: {MASK_TOKEN}"


def test_loki_samples_newest_per_stream_then_orders_chronologically() -> None:
    entries = loki._sample_entries(
        [{"stream": {"pod": "a"}, "values": [["1", "old"], ["3", "new"]]},
         {"stream": {"pod": "b"}, "values": [["2", "middle"]]}],
        limit=2,
    )
    assert [entry["line"] for entry in entries] == ["middle", "new"]


def test_newest_artifact_has_a_guaranteed_synthesis_and_digest_slot() -> None:
    result = CollectorResult(agent="loki", status="ok", summary="headline")
    for index in range(6):
        result.artifacts.append(artifact(
            agent="loki", source="loki", type="logs", status="ok", confidence="high",
            summary=f"old-{index}", highlights=["signal"],
            result={"observation": {"polarity": "unknown", "coverage": "partial"}},
        ))
    result.artifacts.append(artifact(
        agent="loki", source="loki", type="logs", status="partial", confidence="low",
        summary="newest", result={"observation": {"polarity": "unknown", "coverage": "partial"}},
    ))
    findings = pipeline._synthesis_collector_findings([result])[0]
    assert "newest" in [item["summary"] for item in findings["context_artifacts"]]
    assert "newest" in self_check._evidence_digest([result], build_masker(()))
