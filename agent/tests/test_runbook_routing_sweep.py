"""Every closed-family fixture must route to its runbook conclusion."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.services.decision_tree import load_tree, walk_tree

ROOT = Path(__file__).parents[1]
TREE = ROOT / "knowledge/k8s_troubleshooting_tree.yaml"
FAMILIES = {
    entry["family"]
    for entry in yaml.safe_load((ROOT / "knowledge/families.yaml").read_text())
}

# These are casefolded machine observations, as produced by pipeline._observed_text.
ROUTING_FIXTURES = {
    "node_kubelet_pressure": ["diskpressure=true", "memorypressure=true evicted"],
    "runai_scheduling_quota": ["runai-scheduler-default preemptlowerpriority", "podgroup gang scheduling fairshare"],
    "k8s_scheduling_error": ["pending failedscheduling 0/5 nodes are available: insufficient cpu", "pending unschedulable 0/3 nodes are available: untolerated taint"],
    "runai_control_plane_error": ["cluster-sync reconcile failed", "runai-backend database error"],
    "k8s_control_plane_error": ["etcdserver: request timed out", "failed calling webhook validate.pods"],
    "workload_startup_error": ["createcontainerconfigerror configmap not found", "containercannotrun executable file not found"],
    "image_pull_error": ["imagepullbackoff failed to pull image", "errimagepull pull access denied"],
    "gpu_hardware_error": ["nvrm: xid 79", "no runtime for \"nvidia\""],
    "network_fabric_error": ["nccl warn ibv_create_qp failed", "infiniband rdma remote transport"],
    "cluster_network_error": ["failed to create pod sandbox cni plugin", "network plugin failed to setup network for sandbox"],
    "k8s_storage_error": ["failedmount mountvolume.setup failed", "failedattachvolume multi-attach error"],
    "storage_backend_error": ["stale file handle", "mount.nfs: access denied by server"],
    "workload_runtime_error": ["traceback (most recent call last)", "segmentation fault core dumped"],
    "observability_accuracy": ["target down scrape failed", "dashboard shows stale metrics"],
    "platform_auth_error": ["forbidden cannot list resource", "oidc invalid token"],
    "platform_lifecycle_change": ["rollingupdate revision change", "helm upgrade rollout"],
}


@pytest.mark.parametrize(
    ("family", "observed"),
    [(family, observed) for family, fixtures in ROUTING_FIXTURES.items() for observed in fixtures],
)
def test_every_catalog_family_routes_from_realistic_observed_text(
    family: str, observed: str
) -> None:
    conclusion = walk_tree(load_tree(TREE), observed)["conclusion"]
    assert conclusion and conclusion["family"] == family


def test_routing_sweep_enumerates_the_closed_catalog() -> None:
    assert set(ROUTING_FIXTURES) == FAMILIES
    assert all(len(fixtures) >= 2 for fixtures in ROUTING_FIXTURES.values())


def test_pod_not_ready_token_never_routes_to_node_not_ready() -> None:
    result = walk_tree(load_tree(TREE), "kubepodnotready crashloopbackoff")
    assert "node_not_ready" not in result["path"]
    assert result["conclusion"] and result["conclusion"]["family"] == "workload_startup_error"


def test_healthy_text_routes_to_insufficient_evidence() -> None:
    result = walk_tree(load_tree(TREE), "pod running ready=true all checks healthy")
    assert result["conclusion"] and result["conclusion"]["family"] == "insufficient_evidence"
