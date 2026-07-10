from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from app.collectors.base import CollectorResult
from app.masking import build_masker
from app.plan import InvestigationPlan
from app.progress import ProgressReporter
from app.schemas import Alert, AlertAnalysisRequest
from app.services.decision_tree import load_tree, walk_tree
from app.services.kg_enrichment import KGContext
from app.services.pipeline import PipelineState, synthesize_stage
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings, make_target

TREE = Path("knowledge/k8s_troubleshooting_tree.yaml")


def test_pending_failed_scheduling_walks_to_scheduling_leaf() -> None:
    tree = load_tree(TREE)
    walked = walk_tree(
        tree,
        """
        Pod trainer-0 phase: Pending.
        Warning FailedScheduling from default-scheduler:
        0/4 nodes are available: 4 Insufficient nvidia.com/gpu.
        Event reason: FailedScheduling.
        """,
    )

    assert walked["path"][-1] == "scheduling_capacity"
    assert walked["conclusion"]["family"] == "k8s_scheduling_error"
    assert "insufficient nvidia.com/gpu" in walked["steps"][-1]["matched"]


def test_crashloop_oomkilled_walks_to_startup_leaf() -> None:
    tree = load_tree(TREE)
    walked = walk_tree(
        tree,
        """
        Pod trainer-0 container state waiting reason: CrashLoopBackOff.
        Last state terminated reason: OOMKilled, exit code 137.
        Event BackOff restarting failed container.
        """,
    )

    assert walked["path"][-1] == "crash_oomkilled"
    assert walked["conclusion"]["family"] == "workload_startup_error"
    assert "oomkilled" in walked["steps"][-1]["matched"]


def test_pending_capacity_preserves_senior_diagnostic_sequence() -> None:
    tree = load_tree(TREE)
    walked = walk_tree(
        tree,
        """
        Pod trainer-0 phase: Pending.
        Warning FailedScheduling from default-scheduler:
        0/4 nodes are available: 4 Insufficient nvidia.com/gpu.
        """,
    )

    assert walked["path"][-1] == "scheduling_capacity"
    assert "Compare the pod's requests" in walked["steps"][-1]["verify"]
    assert "total cluster free capacity" in walked["steps"][-1]["interpretation"]


def test_admission_webhook_takes_control_plane_path() -> None:
    walked = walk_tree(
        load_tree(TREE),
        "failed calling webhook validate.example.io: no endpoints available",
    )

    assert walked["path"] == [
        "incident_scope",
        "control_plane_failure",
        "admission_webhook_failure",
    ]
    assert walked["conclusion"]["family"] == "k8s_control_plane_error"


def test_unknown_symptom_keeps_an_explicit_evidence_path() -> None:
    walked = walk_tree(load_tree(TREE), "workload emitted an unfamiliar warning")

    assert walked["path"] == ["incident_scope", "insufficient_k8s_evidence"]
    assert walked["conclusion"]["family"] == "insufficient_evidence"


def test_empty_evidence_still_returns_collection_plan() -> None:
    walked = walk_tree(load_tree(TREE), "")

    assert walked["path"] == ["incident_scope", "insufficient_k8s_evidence"]
    assert walked["conclusion"]["next_steps"]


def test_multi_signal_incident_preserves_competing_branches() -> None:
    walked = walk_tree(
        load_tree(TREE),
        "node NotReady with DiskPressure while pod also reports FailedMount",
    )

    assert walked["path"][1] == "node_not_ready"
    alternatives = walked["steps"][0]["alternatives"]
    assert any(item["id"] == "storage_failure" for item in alternatives)
    assert walked["principles"]


@pytest.mark.parametrize(
    ("evidence", "leaf", "family"),
    [
        (
            "NVRM: Xid 79 GPU has fallen off the bus; NCCL WARN collective timeout",
            "gpu_xid_failure",
            "gpu_hardware_error",
        ),
        (
            "NCCL WARN collective operation timeout in rank 3",
            "nccl_unresolved_collective_failure",
            "insufficient_evidence",
        ),
        (
            "runai-scheduler-default reclaimed over-quota workload for fairshare",
            "runai_reclaim_or_preemption",
            "runai_scheduling_quota",
        ),
        (
            "forbidden: serviceaccount trainer cannot list resource pods",
            "kubernetes_rbac_failure",
            "platform_auth_error",
        ),
        (
            "thanos-receive target down and metrics missing",
            "metrics_pipeline_failure",
            "observability_accuracy",
        ),
    ],
)
def test_extended_senior_tracks(evidence: str, leaf: str, family: str) -> None:
    walked = walk_tree(load_tree(TREE), evidence)

    assert walked["path"][-1] == leaf
    assert walked["conclusion"]["family"] == family


def test_precise_gpu_fault_keeps_downstream_nccl_as_alternative() -> None:
    walked = walk_tree(
        load_tree(TREE),
        "NVRM: Xid 79 GPU has fallen off the bus; NCCL WARN collective timeout",
    )

    alternatives = walked["steps"][0]["alternatives"]
    assert any(item["id"] == "distributed_training_failure" for item in alternatives)


@pytest.mark.asyncio
async def test_missing_tree_returns_empty_and_synthesis_still_completes(tmp_path) -> None:
    missing_failure_modes = tmp_path / "failure_modes.yaml"
    settings = replace(
        make_settings(),
        failure_modes_file=str(missing_failure_modes),
        troubleshooting_cases_file=str(tmp_path / "missing_cases.md"),
        architecture_file=str(tmp_path / "missing_architecture.yaml"),
        runai_known_issues_file=str(tmp_path / "missing_known_issues.yaml"),
    )
    empty = {"path": [], "steps": [], "conclusion": None}
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("nodes: [", encoding="utf-8")
    empty_file = tmp_path / "empty.yaml"
    empty_file.write_text("", encoding="utf-8")

    assert load_tree(tmp_path / "missing_tree.yaml") is None
    assert load_tree(malformed) is None
    assert load_tree(empty_file) is None
    assert walk_tree(None, "pod Pending FailedScheduling") == empty

    state = PipelineState(
        settings=settings,
        request=AlertAnalysisRequest(
            alert=Alert(
                status="firing",
                labels={"alertname": "RunAIWorkloadPending", "namespace": "runai-vision"},
                annotations={"summary": "pod Pending FailedScheduling"},
                fingerprint="fp-tree-missing",
            )
        ),
        target=make_target(),
        progress=ProgressReporter(settings, run_id=""),
        masker=build_masker(()),
        collectors=[],
        kg_context=KGContext(),
        plan=InvestigationPlan(namespaces=["runai-vision"], pod="trainer-0"),
        results=[
            CollectorResult(
                agent="kubernetes",
                status="ok",
                summary="Pod trainer-0 Pending with FailedScheduling.",
            )
        ],
        root_cause_candidates=[
            RankedCause(family="k8s_scheduling_error", confidence="high", score=6.0)
        ],
    )

    await synthesize_stage(state)

    assert state.troubleshooting_path == empty
    assert state.response is not None
    assert state.response.root_cause_family == "k8s_scheduling_error"


def test_tree_families_exist_in_catalog() -> None:
    families = {
        str(entry.get("family"))
        for entry in yaml.safe_load(Path("knowledge/families.yaml").read_text())
    }
    tree = yaml.safe_load(TREE.read_text())
    tree_families = {
        node["conclusion"]["family"]
        for node in tree["nodes"]
        if isinstance(node, dict) and isinstance(node.get("conclusion"), dict)
    }

    # insufficient_evidence is a deliberate terminal state, not a ranked
    # operational family in families.yaml.
    assert tree_families - {"insufficient_evidence"} <= families
