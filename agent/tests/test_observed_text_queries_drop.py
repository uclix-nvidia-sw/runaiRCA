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
                result=details,
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


def test_real_node_pressure_still_signature_matches():
    # A genuine DiskPressure=True lives in the abnormal-only node_conditions (NOT
    # the dropped queries), so the symptom must still match.
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
    assert "diskpressure" in observed
    matches = match_failure_mode_symptoms(_failure_modes(), observed)
    assert any(family == "node_kubelet_pressure" for family, _ in matches)
