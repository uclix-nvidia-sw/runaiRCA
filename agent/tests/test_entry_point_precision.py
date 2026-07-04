"""Precision: the ontology entry point is the fine-grained signature match across
ALL families, not the coarse 4-family ranking. A wrong/absent top family must not
hide a precise curated fix (regression guard for the family-gating bug)."""

from __future__ import annotations

from app.knowledge import load_failure_modes, match_failure_mode_symptoms
from app.schemas import Alert, AlertAnalysisRequest
from app.services.orchestrator import _numbered_actions
from app.services.root_cause_ranking import RankedCause

FM = "knowledge/failure_modes.yaml"


def test_symptom_from_non_top_family_still_matches() -> None:
    fm = load_failure_modes(FM)
    # Ranker says node pressure, but the evidence signature is an OOMKilled
    # (workload_startup_error). The precise fix must still surface.
    matches = match_failure_mode_symptoms(
        fm, "the container was oomkilled", "node_kubelet_pressure"
    )
    fams = {f for f, _ in matches}
    assert "workload_startup_error" in fams


def test_gpu_hardware_error_symptom_is_reachable() -> None:
    fm = load_failure_modes(FM)
    # gpu_hardware_error is NOT one of the four ranked families, so it can never be
    # top_family — its curated symptoms were previously unreachable. They must match.
    matches = match_failure_mode_symptoms(fm, "GPU thermal slowdown observed on the node", "")
    assert any(f == "gpu_hardware_error" for f, _ in matches)
    # and the NCCL-NVLS case we added lands here too
    ncnvls = match_failure_mode_symptoms(fm, "transport/nvls.cc NCCL WARN Cuda failure", "")
    assert any(s.get("symptom") == "NCCL NVLS Cuda Failure" for _, s in ncnvls)


def test_top_family_is_ordered_first() -> None:
    fm = load_failure_modes(FM)
    # Evidence hits both node pressure (diskpressure) and startup (oomkilled).
    matches = match_failure_mode_symptoms(
        fm, "node diskpressure then pod oomkilled", "node_kubelet_pressure"
    )
    assert matches and matches[0][0] == "node_kubelet_pressure"


def test_numbered_actions_surfaces_cross_family_fix() -> None:
    fm = load_failure_modes(FM)
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, annotations={}, fingerprint="fp")
    )
    actions = _numbered_actions(
        None,
        None,
        [RankedCause(family="node_kubelet_pressure", confidence="low", score=1.0)],
        "the training container was oomkilled (exit 137)",
        fm,
        [],
        request,
    )
    assert any("memory limit" in a.lower() for a in actions)
