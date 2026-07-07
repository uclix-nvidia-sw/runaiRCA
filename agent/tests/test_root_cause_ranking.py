from __future__ import annotations

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.services.root_cause_ranking import rank_root_cause_candidates


def _target(**overrides: str) -> AnalysisTarget:
    base = dict(
        cluster="prod",
        project="research",
        queue="research-default",
        namespace="runai-research",
        workload_name="trainer",
        workload_type="Training",
        runai_workload_id="wl-1",
        node="gpu-node-17",
        pod="trainer-abc-x1",
        severity="critical",
        alert_name="KubeNodeDiskPressure",
    )
    base.update(overrides)
    return AnalysisTarget(**base)


def _r(
    agent: str,
    status: str = "ok",
    summary: str = "",
    details=None,
    artifacts=None,
) -> CollectorResult:
    return CollectorResult(
        agent=agent,
        status=status,
        summary=summary,
        details=details or {},
        artifacts=artifacts or [],
    )


def test_r1_node_pressure_wins_with_blast_radius() -> None:
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_r2_quota_exhaustion_wins() -> None:
    results = [
        _r("kubernetes", summary="pod Pending FailedScheduling: insufficient nvidia.com/gpu"),
        _r("prometheus", summary="queue GPUs saturated; quota fully consumed"),
        _r("loki", summary="logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "runai_scheduling_quota"


def test_r4_startup_failure_when_control_plane_quiet() -> None:
    # a pure container-startup crash (no image-pull signal) ranks workload_startup_error
    results = [
        _r("kubernetes", summary="pod CrashLoopBackOff; back-off restarting failed container"),
        _r("loki", summary="workload log: oomkilled at startup, exit 137"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "workload_startup_error"


def test_image_pull_ranks_separately_from_startup() -> None:
    # the split: an image-pull failure is image_pull_error, not workload_startup_error
    results = [
        _r("kubernetes", summary="container waiting ImagePullBackOff; ErrImagePull"),
        _r("loki", summary="pull access denied from registry, manifest for tag not found"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "image_pull_error"


def test_r3_control_plane_error_wins_on_backend_reconcile_error() -> None:
    results = [
        _r(
            "loki",
            summary="runai-backend reconcile error: admission webhook denied; authorization failed",
        ),
        _r("kubernetes", summary="workload events sparse"),
    ]
    ranked = rank_root_cause_candidates(_target(alert_name="RunAIWorkloadPending"), results)
    assert ranked[0].family == "runai_control_plane_error"


def test_scheduler_pod_name_does_not_elevate_control_plane() -> None:
    # Regression: a node-exporter-style alert whose Loki stream labels merely
    # mention the runai-scheduler pod name must NOT rank as a control-plane error.
    # Previously the bare "scheduler" keyword matched the pod label and won.
    results = [
        _r("kubernetes", summary="pod prometheus-node-exporter Running; NodeNotReady briefly"),
        _r("loki", summary='logs from pod="runai-scheduler-0" nominal; no errors'),
    ]
    ranked = rank_root_cause_candidates(_target(alert_name="NodeExporterDown"), results)
    assert ranked[0].family != "runai_control_plane_error"


def test_normal_or_negated_keyword_mentions_do_not_rank_as_causes() -> None:
    results = [
        _r(
            "kubernetes",
            summary=(
                "kubelet healthy; no DiskPressure; no CrashLoopBackOff; "
                "no ImagePullBackOff; no FailedScheduling"
            ),
        ),
        _r(
            "loki",
            summary="registry connectivity ok; no pull access denied; no reconcile errors",
        ),
    ]
    ranked = rank_root_cause_candidates(_target(alert_name="NoisyHealthCheck"), results, top_n=5)
    assert [candidate.family for candidate in ranked] == ["insufficient_evidence"]


def test_r6_insufficient_evidence_when_nothing_corroborates() -> None:
    results = [
        _r("kubernetes", status="unavailable", summary="kubernetes API not configured"),
        _r("prometheus", status="unavailable", summary="prometheus url not set"),
        _r("loki", status="unavailable", summary="loki url not set"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "insufficient_evidence"


def test_unavailable_collector_summary_does_not_rank_as_evidence() -> None:
    results = [
        _r(
            "kubernetes",
            status="unavailable",
            summary="kubectl unavailable; stale note mentioned DiskPressure and evicted pods",
        ),
        _r("loki", summary="workload logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "insufficient_evidence"


def test_unavailable_artifact_result_does_not_rank_as_evidence() -> None:
    results = [
        _r(
            "kubernetes",
            summary="pod events unavailable",
            artifacts=[
                artifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="events",
                    status="unavailable",
                    confidence="low",
                    summary="query failed",
                    result={"message": "DiskPressure=True; pods evicted"},
                )
            ],
        ),
        _r("loki", summary="workload logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "insufficient_evidence"


def test_result_json_keys_do_not_rank_as_evidence() -> None:
    results = [
        _r(
            "kubernetes",
            summary="structured payload had no failure values",
            details={
                "DiskPressure": None,
                "CrashLoopBackOff": False,
                "FailedScheduling": [],
                "quota": {"hard": None},
            },
        ),
        _r("loki", summary="logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(alert_name="StructuredPayload"), results)
    assert ranked[0].family == "insufficient_evidence"


def test_empty_metric_query_metadata_does_not_rank_as_evidence() -> None:
    results = [
        _r(
            "prometheus",
            status="partial",
            summary=(
                f"{NO_EVIDENCE} Prometheus is reachable, but the workload metric queries "
                "returned no series."
            ),
            details={
                "queries": [
                    {
                        "name": "queue_quota_saturation",
                        "query": "sum(runai_queue_gpu_quota) by (queue)",
                        "metric": "runai_queue_gpu_quota",
                        "expr": "runai_queue_gpu_quota > 0",
                        "samples": [],
                    }
                ]
            },
        )
    ]

    ranked = rank_root_cause_candidates(_target(alert_name="SparseMetrics"), results)
    assert ranked[0].family == "insufficient_evidence"


def test_unavailable_blast_radius_does_not_upgrade_node_pressure() -> None:
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", status="unavailable", summary="kg offline", details={"kg_blast_radius": 3}),
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "medium"
