from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from app.collectors.base import CollectorResult
from app.collectors.kubernetes import resolve_read_kind
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


def test_curated_probe_templates_use_only_executable_read_only_tools() -> None:
    """Runbook probes are data, but must stay compatible with drilldown's registry.

    This catches a tempting but unsafe regression where a prose-only command or
    an unknown placeholder is added to YAML and silently becomes a no-op at
    runtime.  Optional backends (Prometheus/Loki) are still valid: the domain
    registry decides whether they are available for a particular deployment.
    """
    raw = yaml.safe_load(TREE.read_text(encoding="utf-8"))
    allowed_tools = {"k8s_read", "k8s_describe", "k8s_logs", "promql_query", "logql_query"}
    allowed_placeholders = {
        "namespace",
        "pod",
        "node",
        "workload",
        "workload_name",
        "project",
        "service",
        "component",
        "storage_claim",
        "volume",
    }
    probes = [
        probe
        for node in raw["nodes"]
        for probe in node.get("probes", [])
    ]
    assert len(probes) >= 20, "keep executable coverage broad across RCA layers"
    for probe in probes:
        assert probe["tool"] in allowed_tools
        arguments = probe.get("arguments_template")
        assert isinstance(arguments, dict) and arguments
        serialized = yaml.safe_dump(arguments)
        for placeholder in re.findall(r"{{([a-zA-Z_][a-zA-Z0-9_]*)}}", serialized):
            assert placeholder in allowed_placeholders
        if probe["tool"] == "k8s_describe":
            assert {"kind", "name"} <= arguments.keys()
            assert resolve_read_kind(str(arguments["kind"])) is not None
        if probe["tool"] == "k8s_read":
            assert resolve_read_kind(str(arguments.get("kind") or "")) is not None
        support_signals = probe.get("support_signal_any") or []
        refute_signals = probe.get("refute_signal_any") or []
        assert isinstance(support_signals, list)
        assert isinstance(refute_signals, list)
        assert all(isinstance(signal, str) and signal.strip() for signal in support_signals)
        assert all(isinstance(signal, str) and signal.strip() for signal in refute_signals)
        assert not {signal.lower() for signal in support_signals} & {
            signal.lower() for signal in refute_signals
        }
        if probe["tool"] == "k8s_logs":
            assert {"pod", "namespace"} <= arguments.keys()


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


def test_every_conclusion_has_disconfirm_and_confidence() -> None:
    """Terminal diagnoses need both a confidence boundary and a falsifier."""
    tree = yaml.safe_load(TREE.read_text())
    conclusions = [
        node["conclusion"]
        for node in tree["nodes"]
        if isinstance(node, dict) and isinstance(node.get("conclusion"), dict)
    ]

    assert conclusions
    for conclusion in conclusions:
        confidence = conclusion.get("confidence")
        disconfirm = conclusion.get("disconfirm")
        assert isinstance(confidence, str) and confidence.strip()
        assert isinstance(disconfirm, list) and any(
            isinstance(item, str) and item.strip() for item in disconfirm
        )
