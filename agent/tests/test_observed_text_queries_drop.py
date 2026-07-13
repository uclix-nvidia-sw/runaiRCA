from __future__ import annotations

import os

from app.collectors.base import CollectorResult, artifact
from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.services.pipeline import _evidence_leaf_text, _observed_text


def _healthy_node_k8s_result(node_conditions: list) -> CollectorResult:
    # Exactly how the kubernetes collector embeds the raw node object under
    # details["queries"] (and mirrors details into the artifact result).
    healthy_node = {
        "name": "n1",
        "conditions": [
            {"type": "DiskPressure", "status": "False", "message": "kubelet has no disk pressure"},
            {"type": "MemoryPressure", "status": "False", "message": "kubelet has sufficient memory available"},
            {"type": "PIDPressure", "status": "False", "message": "kubelet has sufficient PID available"},
            {"type": "Ready", "status": "True", "message": "kubelet is posting ready status"},
        ],
    }
    details = {
        "namespace": "runai",
        "pod": "",
        "workload_name": "runai-container-toolkit",
        "node_conditions": node_conditions,
        "warning_events": [],
        "queries": [{"name": "node", "path": "/api/v1/nodes/n1", "data": healthy_node}],
    }
    return CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="Kubernetes API queries completed for the resolved alert target.",
        confidence="high",
        details=details,
        artifacts=[
            artifact(
                agent="kubernetes",
                source="kubernetes",
                type="cluster_api",
                status="ok",
                confidence="high",
                query="/api/v1/nodes/n1",
                summary="Kubernetes API queries completed.",
                result={
                    **details,
                    "observation": {"polarity": "unknown", "coverage": "partial"},
                },
            )
        ],
    )


def _failure_modes():
    return load_failure_modes(os.getenv("FAILURE_MODES_FILE", "knowledge/failure_modes.yaml"))


def test_evidence_leaf_text_drops_kubernetes_queries_firehose():
    node = {"conditions": [{"type": "DiskPressure", "status": "False"}]}
    details = {"node_conditions": [{"node_conditions_healthy": True}], "queries": [{"data": node}]}
    text = _evidence_leaf_text(details, drop_keys=frozenset({"queries"}))
    assert "diskpressure" not in text.lower()
    # Non-queries structured signal survives the drop.
    assert "node_conditions_healthy" not in text  # key names are never emitted
    kept = _evidence_leaf_text(details)  # no drop -> raw node leaks
    assert "diskpressure" in kept.lower()


def test_healthy_node_does_not_signature_match_node_pressure_symptom():
    # The signature/symptom matcher shares the ranker's queries-drop policy, so a
    # perfectly healthy node must NOT match the curated Node Disk Pressure symptom.
    result = _healthy_node_k8s_result([{"node_conditions_healthy": True, "checked": 4}])
    observed = _observed_text([result])
    assert "diskpressure" not in observed
    matches = match_failure_mode_symptoms(_failure_modes(), observed)
    assert not any(family == "node_kubelet_pressure" for family, _ in matches)


def test_current_node_pressure_snapshot_does_not_signature_match():
    # A current node condition is useful context, but a resolved historical
    # incident needs a time-bounded artifact before it can promote a signature.
    result = _healthy_node_k8s_result(
        [
            {
                "type": "DiskPressure",
                "status": "True",
                "reason": "KubeletHasDiskPressure",
                "message": "kubelet has disk pressure",
            }
        ]
    )
    observed = _observed_text([result])
    assert "diskpressure" not in observed
    matches = match_failure_mode_symptoms(_failure_modes(), observed)
    assert not any(family == "node_kubelet_pressure" for family, _ in matches)


def test_scoped_warning_event_can_signature_match_node_pressure():
    result = _healthy_node_k8s_result([{"node_conditions_healthy": True, "checked": 4}])
    result.artifacts.append(
        artifact(
            agent="kubernetes",
            source="kubernetes",
            type="kubernetes_warning_events",
            status="ok",
            confidence="high",
            summary="EvictionThresholdMet in incident window",
            result={
                "observation": {"polarity": "present", "coverage": "scoped"},
                "events": [{"reason": "EvictionThresholdMet", "message": "DiskPressure"}],
            },
        )
    )

    observed = _observed_text([result])
    assert "diskpressure" in observed
    assert any(
        family == "node_kubelet_pressure"
        for family, _ in match_failure_mode_symptoms(_failure_modes(), observed)
    )


def test_evidence_leaf_text_prunes_metadata_key_subtrees():
    # Fix C: a metadata key (metric, error, ...) can hold a DICT/LIST, not just a
    # scalar. The prune must drop the whole subtree so a prometheus `metric` label
    # set ("DiskPressure"/"true") or an MCP transport `error` message
    # ("no route to host") cannot leak into the signature-match text.
    payload = {
        "metric": {"condition": "DiskPressure", "status": "true", "node": "gpu-01"},
        "error": {"message": "no route to host"},
        "value": [1720000000, "0"],
        "warning_events": [{"message": "Attempting to reclaim ephemeral-storage"}],
    }
    text = _evidence_leaf_text(payload)
    assert "diskpressure" not in text.lower()
    assert "no route to host" not in text.lower()
    # Real, non-metadata evidence still survives.
    assert "reclaim ephemeral-storage" in text.lower()
