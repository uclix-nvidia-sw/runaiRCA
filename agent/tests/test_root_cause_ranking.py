from __future__ import annotations

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.services.root_cause_ranking import (
    RankedCause,
    _result_text,
    merge_open_world_candidates,
    novel_family_slug,
    rank_root_cause_candidates,
)


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


def test_novel_family_slug_keeps_distinct_unicode_mechanisms() -> None:
    first, first_fingerprint = novel_family_slug("CSI attach race on gpu-03")
    korean, korean_fingerprint = novel_family_slug("CSI 연결 경합으로 볼륨 마운트 실패")

    assert first.startswith("novel_csi_attach_race")
    assert korean.startswith("novel_csi_")
    assert first_fingerprint != korean_fingerprint
    assert first != korean


def test_open_world_candidate_requires_known_independence_provenance() -> None:
    known = [RankedCause("insufficient_evidence", "low", 0.0)]
    ledger = [
        {
            "id": "H-new",
            "mechanism": "CSI controller races a stale attach operation",
            "status": "supported",
            "support_evidence_ids": ["E01", "E02"],
        }
    ]

    unprovenanced = merge_open_world_candidates(known, ledger, enabled=True)
    verified = merge_open_world_candidates(
        known,
        ledger,
        fact_groups={"E01": "kubernetes_api", "E02": "loki"},
        enabled=True,
    )

    assert unprovenanced == known
    assert any(candidate.novelty == "open_world" for candidate in verified)


def test_r1_node_pressure_wins_with_blast_radius() -> None:
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_r1_soft_tokens_only_do_not_force_high_without_node_condition() -> None:
    # P3: during a GPU-Operator rollout the device-plugin DaemonSet restarts and
    # kubelet is mentioned in logs, so node_kubelet_pressure scores on SOFT tokens.
    # The KG reports a blast radius (the co-located operator DaemonSets). With NO
    # actual node condition reported, the blast must NOT force node pressure HIGH —
    # this is the single-owner/subsystem multi-node rollout case that neither
    # component-identity nor a lifecycle signal caught.
    results = [
        _r(
            "kubernetes",
            summary=(
                "kubelet restarted nvidia-device-plugin; device plugin re-registered "
                "on gpu-node-17 (node reports Ready)"
            ),
        ),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 4}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    by_family = {c.family: c for c in ranked}
    if "node_kubelet_pressure" in by_family:
        node = by_family["node_kubelet_pressure"]
        assert node.confidence != "high"
        assert not any("blast radius" in r for r in node.rationale)


def test_r1_prometheus_node_condition_still_force_highs() -> None:
    # The hard node-condition signal may come from prometheus (not just kubernetes).
    results = [
        _r("prometheus", summary="kube_node_status_condition MemoryPressure=true on gpu-node-17"),
        _r("kubernetes", summary="kubelet evicting pods on gpu-node-17"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_healthy_node_object_in_queries_does_not_score_node_pressure() -> None:
    # A HEALTHY node object still literally carries the failure vocabulary — the
    # condition TYPES "DiskPressure"/"MemoryPressure" (status False) and the message
    # "kubelet has no disk pressure". The kubernetes collector embeds that raw object
    # under details["queries"] (and mirrors it into its artifact result). The base
    # keyword scan used to score node_kubelet_pressure on a perfectly healthy node
    # from that text alone — the recurring "왜 다 False인데 아직도 그게 있다고 하냐" misfire.
    # The raw queries duplicate must be excluded from the ranking text.
    healthy_node = {
        "name": "k8s-lb-01",
        "conditions": [
            {"type": "MemoryPressure", "status": "False", "reason": "KubeletHasSufficientMemory",
             "message": "kubelet has sufficient memory available"},
            {"type": "DiskPressure", "status": "False", "reason": "KubeletHasNoDiskPressure",
             "message": "kubelet has no disk pressure"},
            {"type": "PIDPressure", "status": "False", "reason": "KubeletHasSufficientPID",
             "message": "kubelet has sufficient PID available"},
            {"type": "Ready", "status": "True", "reason": "KubeletReady",
             "message": "kubelet is posting ready status"},
        ],
    }
    details = {
        "namespace": "runai",
        "workload_name": "runai-container-toolkit",
        "node": "k8s-lb-01",
        # The collector's structured signal collapses a healthy node to a marker.
        "node_conditions": [{"node_conditions_healthy": True, "checked": 4}],
        "warning_events": [],
        "queries": [
            {"name": "node", "path": "/api/v1/nodes/k8s-lb-01", "status_code": 200, "data": healthy_node}
        ],
    }
    k8s = _r(
        "kubernetes",
        summary="Node k8s-lb-01 checked; conditions nominal.",
        details=details,
        artifacts=[
            artifact(
                agent="kubernetes", source="kubernetes", type="cluster_api", status="ok",
                confidence="high", summary="Node k8s-lb-01 checked",
                query="/api/v1/nodes/k8s-lb-01", result=details,
            )
        ],
    )
    ranked = rank_root_cause_candidates(
        _target(workload_name="runai-container-toolkit", node="k8s-lb-01",
                alert_name="RunaiDaemonSetUnavailableOnNodes"),
        [k8s],
    )
    families = {c.family for c in ranked}
    assert "node_kubelet_pressure" not in families


def test_structured_partial_artifacts_do_not_feed_keyword_ranker() -> None:
    partial = artifact(
        agent="system",
        source="system",
        type="system_log",
        status="ok",
        confidence="medium",
        summary="OOMKilled seen in a finite node log tail",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "partial",
            },
            "lines": ["OOMKilled"],
        },
    )
    result = _r(
        "system",
        summary="OOMKilled in a current log tail",
        details={"errors": ["OOMKilled"]},
        artifacts=[partial],
    )

    assert _result_text(result) == ""


def test_structured_scoped_artifact_remains_available_to_keyword_ranker() -> None:
    scoped = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="warning_event",
        status="ok",
        confidence="high",
        summary="Evicted workload in incident window",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
            },
            "events": [{"reason": "Evicted"}],
        },
    )

    assert "evicted" in _result_text(_r("kubernetes", artifacts=[scoped]))


def test_real_node_pressure_still_scores_after_queries_drop() -> None:
    # Guard the fix above from over-correcting: when a condition is genuinely
    # abnormal (DiskPressure=True), it surfaces in the structured node_conditions
    # (not just the raw queries), so node_kubelet_pressure must still score.
    details = {
        "namespace": "runai",
        "node": "dgx01",
        "node_conditions": [
            {"type": "DiskPressure", "status": "True", "reason": "KubeletHasDiskPressure",
             "message": "kubelet has disk pressure"}
        ],
        "warning_events": [
            {"reason": "EvictionThresholdMet", "type": "Warning",
             "message": "Attempting to reclaim ephemeral-storage"}
        ],
        "queries": [{"name": "node", "path": "/api/v1/nodes/dgx01", "status_code": 200, "data": {}}],
    }
    k8s = _r(
        "kubernetes",
        summary="Node dgx01 reports DiskPressure=True.",
        details=details,
        artifacts=[
            artifact(
                agent="kubernetes",
                source="kubernetes",
                type="cluster_api",
                status="ok",
                confidence="low",
                summary="current node snapshot",
                result={"observation": {"polarity": "unknown", "coverage": "partial"}},
            ),
            artifact(
                agent="kubernetes",
                source="kubernetes",
                type="kubernetes_warning_events",
                status="ok",
                confidence="high",
                summary="EvictionThresholdMet in incident window",
                result={"observation": {"polarity": "present", "coverage": "scoped"}},
            ),
        ],
    )
    ranked = rank_root_cause_candidates(
        _target(node="dgx01", alert_name="KubeNodeDiskPressure"), [k8s]
    )
    assert any(c.family == "node_kubelet_pressure" for c in ranked)


def test_facets_annotate_family_locus_and_nature() -> None:
    # P4: every candidate carries its intrinsic (subsystem/Locus, nature) facets.
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    top = ranked[0]
    assert top.family == "node_kubelet_pressure"
    assert top.subsystem == "node"
    assert top.nature == "saturation"
    # Facets are exposed in the serialized form too.
    d = top.as_dict()
    assert d["subsystem"] == "node" and d["nature"] == "saturation"


def test_lifecycle_candidate_carries_trigger_facet() -> None:
    # P4: the Trigger facet names the proximate change on the lifecycle candidate.
    results = [
        _r("kubernetes", summary="Node gpu-node-17 MemoryPressure noted once"),
        _r("loki", summary="logs nominal"),
        _change_result(
            [
                {"name": "runai-container-toolkit", "kind": "DaemonSet", "rollout": True,
                 "namespace": "runai", "summary": "mid-rollout"},
            ]
        ),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=["runai-container-toolkit", "gpu-operator"],
        lifecycle={
            "active": True,
            "components": ["runai-container-toolkit"],
            "target_rollout": True,
            "helm": ["gpu-operator rev 3 (pending-upgrade)"],
        },
    )
    top = ranked[0]
    assert top.family == "platform_lifecycle_change"
    assert top.subsystem == "platform-lifecycle"
    assert top.nature == "lifecycle_change"
    assert "runai-container-toolkit" in top.trigger
    assert "pending-upgrade" in top.trigger
    # A non-lifecycle candidate must NOT claim the rollout as its trigger.
    others = [c for c in ranked if c.family != "platform_lifecycle_change"]
    assert all(c.trigger == "" for c in others)


def test_trigger_facet_survives_signature_promotion() -> None:
    # Regression for the P4 reviewer finding: _promote_signature_cause rebuilds the
    # top candidate (via _with_signature_support, or a fresh lead RankedCause for a
    # different family). subsystem/nature re-derive from the family in __post_init__,
    # but Trigger is ranker-computed and has no such fallback — so it must be carried
    # through both promotion paths or it is silently dropped from the report/as_dict.
    from app.services.pipeline import _promote_signature_cause

    results = [
        _r("kubernetes", summary="Node gpu-node-17 MemoryPressure noted once"),
        _change_result(
            [
                {"name": "runai-container-toolkit", "kind": "DaemonSet", "rollout": True,
                 "namespace": "runai", "summary": "mid-rollout"},
            ]
        ),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        lifecycle={
            "active": True,
            "components": ["runai-container-toolkit"],
            "target_rollout": True,
            "helm": ["gpu-operator rev 3 (pending-upgrade)"],
        },
    )
    lifecycle_cause = next(c for c in ranked if c.family == "platform_lifecycle_change")
    assert lifecycle_cause.trigger  # ranker set it

    symptom = ("platform_lifecycle_change", {"symptom": "Controller Rollout In Progress"})

    # Path A: lifecycle family is already the ranker's top → _with_signature_support.
    top_first = [lifecycle_cause, *[c for c in ranked if c.family != "platform_lifecycle_change"]]
    promoted_a = _promote_signature_cause(top_first, [], [], [symptom])
    assert promoted_a[0].family == "platform_lifecycle_change"
    assert promoted_a[0].trigger == lifecycle_cause.trigger
    assert promoted_a[0].as_dict()["trigger"] == lifecycle_cause.trigger

    # Path B: a different family leads → fresh lead RankedCause for the lifecycle family.
    other = next(c for c in ranked if c.family != "platform_lifecycle_change")
    top_other = [other, *[c for c in ranked if c.family != other.family]]
    promoted_b = _promote_signature_cause(top_other, [], [], [symptom])
    assert promoted_b[0].family == "platform_lifecycle_change"
    assert promoted_b[0].trigger == lifecycle_cause.trigger


def test_r1_healthy_node_object_in_details_does_not_force_high() -> None:
    # Regression for the P3 reviewer finding: the kubernetes collector embeds the
    # RAW node object in details["queries"], and a HEALTHY node still literally
    # carries type "DiskPressure"/"MemoryPressure" + "kubelet has no disk pressure"
    # text. A naive substring guard sees those and wrongly re-enables the blast
    # force-high. With soft tokens only and the collector's abnormal-filtered
    # node_conditions marked healthy, node pressure must NOT be forced HIGH.
    healthy_node = {
        "node_conditions": [{"node_conditions_healthy": True, "checked": 4}],
        "queries": [
            {
                "name": "node",
                "data": {
                    "conditions": [
                        {"type": "DiskPressure", "status": "False",
                         "reason": "KubeletHasNoDiskPressure",
                         "message": "kubelet has no disk pressure"},
                        {"type": "MemoryPressure", "status": "False",
                         "reason": "KubeletHasSufficientMemory",
                         "message": "kubelet has sufficient memory available"},
                        {"type": "Ready", "status": "True",
                         "reason": "KubeletReady", "message": "kubelet is posting ready status"},
                    ]
                },
            }
        ],
    }
    results = [
        _r(
            "kubernetes",
            summary="kubelet restarted nvidia-device-plugin; device plugin re-registered",
            details=healthy_node,
        ),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 4}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    by_family = {c.family: c for c in ranked}
    if "node_kubelet_pressure" in by_family:
        node = by_family["node_kubelet_pressure"]
        assert node.confidence != "high"
        assert not any("blast radius" in r for r in node.rationale)


def test_r1_abnormal_node_condition_in_details_force_highs() -> None:
    # The structured, abnormal-only node_conditions signal (DiskPressure status
    # True) IS a genuine node condition and must still force-high with a blast.
    pressured_node = {
        "node_conditions": [
            {"type": "DiskPressure", "status": "True", "reason": "KubeletHasDiskPressure",
             "message": "kubelet has disk pressure"}
        ],
    }
    results = [
        _r(
            "kubernetes",
            summary="node under pressure; pods being removed",
            details=pressured_node,
            artifacts=[
                artifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="cluster_api",
                    status="ok",
                    confidence="low",
                    summary="current node snapshot",
                    result={"observation": {"polarity": "unknown", "coverage": "partial"}},
                ),
                artifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="kubernetes_warning_events",
                    status="ok",
                    confidence="high",
                    summary="EvictionThresholdMet in incident window",
                    result={"observation": {"polarity": "present", "coverage": "scoped"}},
                ),
            ],
        ),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_r1_current_node_snapshot_cannot_force_high_for_historical_incident() -> None:
    results = [
        _r(
            "kubernetes",
            summary="Node currently reports DiskPressure=True",
            details={
                "node_conditions": [
                    {"type": "DiskPressure", "status": "True", "reason": "KubeletHasDiskPressure"}
                ]
            },
            artifacts=[
                artifact(
                    agent="kubernetes",
                    source="kubernetes",
                    type="cluster_api",
                    status="ok",
                    confidence="low",
                    summary="current node snapshot",
                    result={"observation": {"polarity": "unknown", "coverage": "partial"}},
                )
            ],
        ),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
    ]

    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    by_family = {candidate.family: candidate for candidate in ranked}

    if candidate := by_family.get("node_kubelet_pressure"):
        assert candidate.confidence != "high"
        assert not any("blast radius" in rationale for rationale in candidate.rationale)


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


def test_component_identity_leads_over_incidental_node_pressure() -> None:
    # The reported mis-attribution: a KubeDaemonSetRolloutStuck alert ON the
    # runai-container-toolkit DaemonSet, while the node happens to carry a stray
    # pressure line. Without topology, node_kubelet_pressure won on the keyword.
    # With the component identity (runai-container-toolkit → gpu_hardware_error,
    # depends_on the GPU Operator stack) the right subsystem must lead.
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition MemoryPressure noted once"),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=[
            "runai-container-toolkit",
            "nvidia-container-toolkit-daemonset",
            "nvidia-driver-daemonset",
            "gpu-operator",
        ],
    )
    assert ranked[0].family == "gpu_hardware_error"
    assert any("depends_on" in r for r in ranked[0].rationale)


def test_component_identity_disables_node_force_high_from_blast() -> None:
    # A non-node component is the alert target, yet the KG reports blast radius.
    # The blast must NOT force node_kubelet_pressure to HIGH — the component's
    # rollout/health explains the multi-pod impact.
    results = [
        _r("kubernetes", summary="Node gpu-node-17 DiskPressure=True; kubelet evicting pods"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 4}),
        _r("loki", summary="logs nominal"),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=["runai-container-toolkit", "gpu-operator"],
    )
    by_family = {c.family: c for c in ranked}
    # node pressure may still appear, but never as a forced-HIGH top cause here.
    assert ranked[0].family == "gpu_hardware_error"
    if "node_kubelet_pressure" in by_family:
        assert by_family["node_kubelet_pressure"].confidence != "high"


def test_component_identity_absent_keeps_legacy_behavior() -> None:
    # Regression guard: with no component identity passed, ranking is unchanged
    # (R1 still force-highs node pressure with blast radius).
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_component_identity_single_weak_hit_not_high_confidence() -> None:
    # The synthetic "topology" agent floors the identity family's score, but it
    # does NOT independently observe a failure. With only ONE real evidence agent
    # weakly matching, the family must stay at medium — HIGH needs >=2 real agents.
    results = [
        _r("kubernetes", summary="nouveau driver noted on gpu-node-17"),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=["runai-container-toolkit", "gpu-operator"],
    )
    top = ranked[0]
    assert top.family == "gpu_hardware_error"
    assert top.confidence != "high"


def _change_result(changes, summary="recent changes"):
    return CollectorResult(
        agent="change",
        status="ok",
        summary=summary,
        details={"changes": changes},
        artifacts=[],
    )


def test_lifecycle_gate_leads_when_target_component_mid_rollout() -> None:
    # The reported case: a KubeDaemonSetRolloutStuck alert on runai-container-toolkit
    # caused by a GPU-operator upgrade. The DaemonSet is mid-rollout, the node has a
    # stray pressure line. Nature (lifecycle/upgrade) must headline over the fault.
    results = [
        _r("kubernetes", summary="Node gpu-node-17 MemoryPressure noted once"),
        _r("loki", summary="workload namespace logs nominal"),
        _change_result(
            [
                {
                    "name": "runai-container-toolkit",
                    "kind": "DaemonSet",
                    "rollout": True,
                    "namespace": "runai",
                    "summary": "mid-rollout (generation 5, observed 3)",
                }
            ]
        ),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=["runai-container-toolkit", "gpu-operator"],
        lifecycle={
            "active": True,
            "components": ["runai-container-toolkit"],
            "target_rollout": True,
        },
    )
    assert ranked[0].family == "platform_lifecycle_change"
    assert ranked[0].confidence == "high"  # the alert's own component is rolling => dispositive
    by_family = {c.family: c for c in ranked}
    if "node_kubelet_pressure" in by_family:
        assert by_family["node_kubelet_pressure"].confidence != "high"


def test_lifecycle_gate_absent_keeps_legacy_behavior() -> None:
    # No lifecycle signal => ranking is 100% unchanged (R1 still force-highs node).
    results = [
        _r("kubernetes", summary="Node gpu-node-17 condition DiskPressure=True; pods evicted"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 3}),
        _r("loki", summary="workload namespace logs nominal"),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert ranked[0].family == "node_kubelet_pressure"
    assert ranked[0].confidence == "high"


def test_lifecycle_upstream_rollout_is_medium_not_forced_high() -> None:
    # Only an UPSTREAM dependency (gpu-operator) is rolling, the alert's own
    # component is not => lifecycle leads but stays medium (one real observer,
    # not dispositive) rather than forced HIGH.
    results = [
        _r("kubernetes", summary="workload events sparse"),
        _r("loki", summary="logs nominal"),
        _change_result(
            [
                {
                    "name": "gpu-operator",
                    "kind": "Deployment",
                    "rollout": True,
                    "namespace": "gpu-operator",
                    "summary": "mid-rollout (generation 8, observed 7)",
                }
            ]
        ),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck", pod="runai-container-toolkit-vttmr"),
        results,
        component_family="gpu_hardware_error",
        component="runai-container-toolkit",
        depends_on_chain=["runai-container-toolkit", "gpu-operator"],
        lifecycle={
            "active": True,
            "components": ["gpu-operator"],
            "target_rollout": False,
        },
    )
    assert ranked[0].family == "platform_lifecycle_change"
    assert ranked[0].confidence == "medium"


def test_lifecycle_gate_clears_node_force_high_from_blast() -> None:
    # A rollout is active AND the KG reports blast radius that R1 would force-high
    # node pressure on. The lifecycle event must strip that node force-high even
    # when the target is NOT a known component (component identity can't guard it).
    results = [
        _r("kubernetes", summary="Node gpu-node-17 DiskPressure=True; kubelet evicting pods"),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 4}),
        _change_result(
            [
                {
                    "name": "some-daemonset",
                    "kind": "DaemonSet",
                    "rollout": True,
                    "namespace": "runai",
                    "summary": "mid-rollout (generation 2, observed 1)",
                }
            ]
        ),
    ]
    ranked = rank_root_cause_candidates(
        _target(alert_name="KubeDaemonSetRolloutStuck"),
        results,
        lifecycle={
            "active": True,
            "components": ["some-daemonset"],
            "target_rollout": False,
        },
    )
    by_family = {c.family: c for c in ranked}
    assert "node_kubelet_pressure" in by_family
    assert by_family["node_kubelet_pressure"].confidence != "high"


def test_soft_tokens_alone_do_not_create_node_pressure_candidate() -> None:
    # Fix A: kubelet / device plugin / node condition are SOFT co-occurrence
    # tokens a GPU-Operator (device-plugin DaemonSet) rollout always emits with NO
    # node pressure. They were removed from the scoring keywords, so with a Ready
    # node and no hard condition token, node_kubelet_pressure must not even appear.
    results = [
        _r(
            "kubernetes",
            summary=(
                "kubelet restarted nvidia-device-plugin; device plugin re-registered "
                "on gpu-node-17 (node reports Ready); node condition changed"
            ),
        ),
        _r("typedb", summary="kg lookup", details={"blast_radius_workloads": 4}),
    ]
    ranked = rank_root_cause_candidates(_target(), results, occurrence_count=5)
    assert "node_kubelet_pressure" not in {c.family for c in ranked}


def test_hard_token_still_scores_node_pressure_after_soft_token_removal() -> None:
    # Guard Fix A from over-correcting: a real hard token (evict) must still score.
    results = [_r("kubernetes", summary="kubelet evicting pods on gpu-node-17")]
    ranked = rank_root_cause_candidates(_target(), results)
    assert "node_kubelet_pressure" in {c.family for c in ranked}


def test_benign_container_ready_ratio_does_not_score_scheduling() -> None:
    # Fix B: a bare "0/" matched benign transient states — a pod showing "0/1"
    # containers ready, a deployment at "0/3" available. Only the scheduler
    # predicate phrase ("nodes are available") should score k8s_scheduling_error.
    results = [
        _r("kubernetes", summary="pods: web 0/1 running, sidecar 0/3 available; all starting normally")
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert "k8s_scheduling_error" not in {c.family for c in ranked}


def test_real_failedscheduling_still_scores_after_token_tightening() -> None:
    results = [
        _r(
            "kubernetes",
            summary="FailedScheduling: 0/5 nodes are available: 5 node(s) had untolerated taint",
        )
    ]
    ranked = rank_root_cause_candidates(_target(), results)
    assert "k8s_scheduling_error" in {c.family for c in ranked}


def test_prometheus_metric_labels_do_not_leak_or_score_node_pressure() -> None:
    # Fix C: a prometheus series' `metric` label set is query IDENTITY, not
    # evidence. A HEALTHY node's kube_node_status_condition{condition="DiskPressure",
    # status="true"} series has VALUE 0 — but the label literals "DiskPressure" /
    # "true" used to leak (the metadata-key prune only fired on scalar leaves, and
    # `metric` holds a dict). node_kubelet_pressure must not score off them.
    details = {
        "queries": {
            "result": [
                {
                    "metric": {
                        "__name__": "kube_node_status_condition",
                        "condition": "DiskPressure",
                        "status": "true",
                        "node": "gpu-01",
                    },
                    "value": [1720000000, "0"],
                }
            ]
        }
    }
    results = [_r("prometheus", summary="node condition series returned; all conditions nominal", details=details)]
    ranked = rank_root_cause_candidates(_target(alert_name="SparseMetrics"), results)
    assert "node_kubelet_pressure" not in {c.family for c in ranked}
