from __future__ import annotations

from app.collectors.base import CollectorResult
from app.services.pipeline import _affected_pods_from_results


def _k8s_result(details: dict) -> CollectorResult:
    return CollectorResult(
        agent="kubernetes",
        status="ok",
        summary="k8s",
        confidence="high",
        details=details,
    )


def test_workload_scoped_discovery_returns_real_pod_names():
    # KSM alert names the exporter pod, but the investigation was scoped to the
    # runai-container-toolkit workload; its real pods must surface as affected.
    results = [
        _k8s_result(
            {
                "workload_name": "runai-container-toolkit",
                "pod": "",
                "pod_statuses": [
                    {"name": "runai-container-toolkit-vttmr", "phase": "Running"},
                    {"name": "runai-container-toolkit-8kd2p", "phase": "Pending"},
                ],
            }
        )
    ]
    assert _affected_pods_from_results(results) == [
        "runai-container-toolkit-vttmr",
        "runai-container-toolkit-8kd2p",
    ]


def test_pod_scoped_discovery_returns_the_target_pod():
    results = [
        _k8s_result(
            {
                "workload_name": "",
                "pod": "gpu-operator-abc",
                "pod_statuses": [{"name": "gpu-operator-abc"}],
            }
        )
    ]
    assert _affected_pods_from_results(results) == ["gpu-operator-abc"]


def test_unscoped_investigation_returns_empty():
    # No named pod and no workload → a namespace listing is not "affected pods".
    results = [
        _k8s_result(
            {
                "workload_name": "",
                "pod": "",
                "pod_statuses": [{"name": "some-random-pod"}],
            }
        )
    ]
    assert _affected_pods_from_results(results) == []


def test_dedupes_and_skips_blank_names():
    results = [
        _k8s_result(
            {
                "workload_name": "dcgm-exporter",
                "pod_statuses": [
                    {"name": "dcgm-exporter-1"},
                    {"name": "dcgm-exporter-1"},
                    {"name": "  "},
                    {"phase": "Running"},
                    {"metadata": {"name": "dcgm-exporter-2"}},
                ],
            }
        )
    ]
    assert _affected_pods_from_results(results) == ["dcgm-exporter-1", "dcgm-exporter-2"]


def test_no_kubernetes_result_returns_empty():
    results = [
        CollectorResult(agent="loki", status="ok", summary="loki", details={"queries": []})
    ]
    assert _affected_pods_from_results(results) == []
