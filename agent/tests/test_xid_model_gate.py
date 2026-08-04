"""Model-inapplicable XID ancestors must not be recommended.

A real report for an "XID 48" incident told the operator to first fix XIDs
144/145/146 (NVLINK_SAW/RLW/TLW_ERROR). Those three are B100/GB200-only in
agent/knowledge/xid_catalog.yaml, while 48 itself spans A100/H100/B100/GB200.
On an A100/H100 cluster that upstream advice cannot occur. `_query_remediation`
must restrict `root_xids` (and the `xid_fixes`/`xid_triggers` entries the
recommended-actions renderer reads) to the detected GPU model's own XID set,
without ever discarding an observed XID.
"""

from __future__ import annotations

from contextlib import contextmanager

from app.services.kg_enrichment import _query_remediation


def _root_chain_run(extra):
    """A fake TypeDB `run` for observed XID 48 with ancestors 144/145/146,
    plus whatever `extra` supplies for `fixes_for_xid`/`xids_for_gpu_model`.
    """

    def run(query: str) -> list[dict]:
        if "root_xid_chain_for(48)" in query:
            return [{"x": 144}, {"x": 145}, {"x": 146}]
        if "root_xids_for(48)" in query:
            return [{"x": 144}, {"x": 145}, {"x": 146}]
        if (
            "root_xids_for(144)" in query
            or "root_xids_for(145)" in query
            or "root_xids_for(146)" in query
        ):
            return []
        return extra(query)

    return run


class _FakeClient:
    def __init__(self, run) -> None:
        self._run = run

    @contextmanager
    def open_reader(self):
        yield self._run


def test_query_remediation_gates_ancestors_not_valid_for_detected_model() -> None:
    """H100 cluster: 144/145/146 are B100/GB200-only -> gated away; 48 (observed)
    keeps its own fix/trigger; a warning records what was dropped and why."""

    def extra(query: str) -> list[dict]:
        if "fixes_for_xid(48)" in query:
            return [{"x": "Power-cycle or reset the GPU."}]
        if "fixes_for_xid(144)" in query:
            return [{"x": "Reseat or replace the NVLink cable."}]
        if "fixes_for_xid(145)" in query:
            return [{"x": "Reset the NVLink fabric."}]
        if "fixes_for_xid(146)" in query:
            return [{"x": "Replace the NVSwitch tray."}]
        if "trigger_for_xid(48)" in query:
            return [{"x": "Check ECC counters before reset."}]
        if "xids_for_gpu_model" in query:
            return [{"x": code} for code in (8, 11, 48, 79)]  # no 144/145/146
        return []

    out = _query_remediation(
        _FakeClient(_root_chain_run(extra)), "", [48], "H100"
    )  # type: ignore[arg-type]

    # Ancestors gone from every map the recommended-actions renderer reads.
    assert 48 not in out.root_xids
    assert 48 not in out.root_xid_status
    assert 144 not in out.xid_fixes and 145 not in out.xid_fixes and 146 not in out.xid_fixes
    assert 144 not in out.xid_triggers

    # The observed XID's own finding survives untouched.
    assert out.xid_fixes == {48: ["Power-cycle or reset the GPU."]}
    assert out.xid_triggers == {48: "Check ECC counters before reset."}
    assert out.model_xids == {"H100": [8, 11, 48, 79]}

    # Auditable: exactly one warning, naming the model and the dropped codes.
    assert len(out.warnings) == 1
    assert "H100" in out.warnings[0]
    for code in ("144", "145", "146"):
        assert code in out.warnings[0]


def test_query_remediation_keeps_ancestors_valid_for_detected_model() -> None:
    """GB200 cluster: 144/145/146 ARE valid there -> nothing is filtered."""

    def extra(query: str) -> list[dict]:
        if "fixes_for_xid" in query:
            return [{"x": "fix"}]
        if "xids_for_gpu_model" in query:
            return [{"x": code} for code in (48, 144, 145, 146)]
        return []

    out = _query_remediation(
        _FakeClient(_root_chain_run(extra)), "", [48], "GB200"
    )  # type: ignore[arg-type]

    assert out.root_xids == {48: [144, 145, 146]}
    assert out.root_xid_status[48] == "ordered"
    assert set(out.xid_fixes) == {48, 144, 145, 146}
    assert out.warnings == []


def test_query_remediation_unknown_model_does_not_gate() -> None:
    """No gpu_model, and separately an empty model catalog: unknown model
    means no gating (today's behaviour), not silently dropped knowledge."""

    def extra_no_lookup(query: str) -> list[dict]:
        if "fixes_for_xid" in query:
            return [{"x": "fix"}]
        return []

    def extra_empty_lookup(query: str) -> list[dict]:
        if "fixes_for_xid" in query:
            return [{"x": "fix"}]
        if "xids_for_gpu_model" in query:
            return []  # model name TypeDB doesn't recognise
        return []

    # gpu_model empty -> the lookup is never even run.
    out_no_model = _query_remediation(
        _FakeClient(_root_chain_run(extra_no_lookup)), "", [48], ""
    )  # type: ignore[arg-type]
    assert out_no_model.root_xids == {48: [144, 145, 146]}
    assert set(out_no_model.xid_fixes) == {48, 144, 145, 146}
    assert out_no_model.model_xids == {}
    assert out_no_model.warnings == []

    # gpu_model set, but the catalog lookup came back empty.
    out_empty_catalog = _query_remediation(
        _FakeClient(_root_chain_run(extra_empty_lookup)), "", [48], "UnknownModel"
    )  # type: ignore[arg-type]
    assert out_empty_catalog.root_xids == {48: [144, 145, 146]}
    assert set(out_empty_catalog.xid_fixes) == {48, 144, 145, 146}
    assert out_empty_catalog.model_xids == {}
    assert out_empty_catalog.warnings == []


def test_query_remediation_warns_but_keeps_observed_xid_missing_from_model() -> None:
    """The observed XID itself being absent from the model's catalog is a
    detection mismatch, not grounds to delete the operator's own finding."""

    def run(query: str) -> list[dict]:
        if "fixes_for_xid(48)" in query:
            return [{"x": "Power-cycle or reset the GPU."}]
        if "xids_for_gpu_model" in query:
            return [{"x": code} for code in (8, 11, 79)]  # 48 not listed
        return []

    out = _query_remediation(_FakeClient(run), "", [48], "H100")  # type: ignore[arg-type]

    assert out.xid_fixes == {48: ["Power-cycle or reset the GPU."]}
    assert len(out.warnings) == 1
    assert "48" in out.warnings[0] and "H100" in out.warnings[0]


def test_node_label_reaches_the_model_gate_as_a_catalog_name() -> None:
    """A gate nothing feeds is worse than the bug it guards against.

    GPU Feature Discovery publishes ``NVIDIA-H100-80GB-HBM3`` on the node while
    the XID catalog stores ``H100``, and ``xids_for_gpu_model`` matches the
    catalog name exactly. Without the node projection keeping the label AND the
    token extraction below, ``gpu_model`` is never populated from a real cluster
    and the per-model gate above can never fire.
    """
    from app.collectors.kubernetes import _node_gpu_product, _node_summary
    from app.services.kg_enrichment import _gpu_model_candidates

    node = {
        "metadata": {
            "name": "dgx01",
            "labels": {"nvidia.com/gpu.product": "NVIDIA-H100-80GB-HBM3"},
        },
        "status": {},
        "spec": {},
    }
    summary = _node_summary(node)
    assert summary["gpu_product"] == "NVIDIA-H100-80GB-HBM3"
    assert _node_gpu_product([{"name": "node", "data": summary}]) == (
        "NVIDIA-H100-80GB-HBM3"
    )
    # The raw label is tried first, then the catalog-shaped token inside it.
    assert _gpu_model_candidates(summary["gpu_product"]) == [
        "NVIDIA-H100-80GB-HBM3",
        "H100",
    ]
    # The superchip name wins over any bare token inside it.
    assert _gpu_model_candidates("NVIDIA-GB200") == ["NVIDIA-GB200", "GB200"]

    # Unknown model => no extra candidate => gate stays off rather than guessing.
    bare = _node_summary({"metadata": {"name": "cpu-01"}, "status": {}, "spec": {}})
    assert "gpu_product" not in bare
    assert _node_gpu_product([{"name": "node", "data": bare}]) == ""
    assert _gpu_model_candidates("") == []
    assert _gpu_model_candidates("some-accelerator") == ["some-accelerator"]


def test_no_node_cluster_inventory_reaches_the_model_gate() -> None:
    """A real operator question ("XID48 에러가 발생했는데 어떤 걸 해야할까요?")
    names no node, so the Kubernetes node label (the other test above) can
    never populate ``gpu_model``. The Run:ai cluster-wide inventory
    (``get_cluster_physical_inventory``'s ``byGpuModel``, surfaced by the
    runai drill-down into its own CollectorResult.details -- see
    test_drilldown.py's ``test_cluster_physical_inventory_sets_runai_gpu_model_with_no_node``)
    is the only reachable source. This closes the full chain: no-node target
    -> runai collector result -> ``_gpu_model_from`` -> ``_query_remediation``
    dropping XID 48's B100/GB200-only ancestors while keeping 48's own fix.
    """
    from app.collectors.base import AnalysisTarget, CollectorResult
    from app.services.pipeline import _gpu_model_from

    target = AnalysisTarget(
        cluster="prod-cluster",
        project="",
        queue="",
        namespace="runai-vision",
        workload_name="",
        workload_type="",
        runai_workload_id="",
        node="",  # the operator's question named no node
        pod="",
        severity="warning",
        alert_name="Xid48",
    )
    # What drilldown._run_query writes into the runai CollectorResult once
    # get_cluster_physical_inventory succeeds.
    runai_result = CollectorResult(
        agent="runai",
        status="ok",
        summary="Run:ai queried",
        details={"gpu_model": "NVIDIA-H100-80GB-HBM3"},
    )
    kubernetes_result = CollectorResult(
        agent="kubernetes", status="unavailable", summary="no node in the alert"
    )

    detected_model = _gpu_model_from(target, [kubernetes_result, runai_result])
    assert detected_model == "NVIDIA-H100-80GB-HBM3"

    def extra(query: str) -> list[dict]:
        if "fixes_for_xid(48)" in query:
            return [{"x": "Power-cycle or reset the GPU."}]
        if "fixes_for_xid(144)" in query:
            return [{"x": "Reseat or replace the NVLink cable."}]
        if "fixes_for_xid(145)" in query:
            return [{"x": "Reset the NVLink fabric."}]
        if "fixes_for_xid(146)" in query:
            return [{"x": "Replace the NVSwitch tray."}]
        if "trigger_for_xid(48)" in query:
            return [{"x": "Check ECC counters before reset."}]
        if "xids_for_gpu_model" in query:
            return [{"x": code} for code in (8, 11, 48, 79)]  # no 144/145/146
        return []

    out = _query_remediation(
        _FakeClient(_root_chain_run(extra)), "", [48], detected_model
    )  # type: ignore[arg-type]

    # The B100/GB200-only upstream ancestors are gone from every map the
    # recommended-actions renderer reads...
    assert 48 not in out.root_xids
    assert 144 not in out.xid_fixes and 145 not in out.xid_fixes and 146 not in out.xid_fixes
    # ...but the OBSERVED xid keeps its own fix and trigger.
    assert out.xid_fixes == {48: ["Power-cycle or reset the GPU."]}
    assert out.xid_triggers == {48: "Check ECC counters before reset."}
    assert len(out.warnings) == 1
    for code in ("144", "145", "146"):
        assert code in out.warnings[0]


def test_cluster_inventory_is_gathered_without_the_llm_choosing_it() -> None:
    """The model gate must not depend on which tools the LLM happened to pick.

    GPU model is an invariant property of the cluster and the input to a
    correctness gate, so it is gathered like list_node_pools -- unconditionally
    -- not as a drill-down. Before this, the same XID question answered
    differently on the same cluster depending on the model's tool choice.
    """
    import asyncio
    from dataclasses import replace
    from types import SimpleNamespace

    from app.collectors import runai_mcp
    from app.collectors.runai import _mcp_cluster_gpu_model
    from tests.test_orchestrator import make_settings, make_target

    called: list[tuple[str, dict]] = []

    async def fake_mcp_call(url, tool, arguments, headers=None):  # noqa: ANN001
        called.append((tool, dict(arguments)))
        # The official server returns structuredContent per its outputSchema.
        payload = (
            {"byGpuModel": [{"gpuModel": "NVIDIA-H100-80GB-HBM3", "nodes": 4}]}
            if tool == "get_cluster_physical_inventory"
            else {}
        )
        return SimpleNamespace(isError=False, structuredContent=payload)

    async def fake_resolve(_settings, _target):  # noqa: ANN001
        return "11111111-2222-3333-4444-555555555555"

    original_call, original_resolve = runai_mcp.mcp_call, runai_mcp.resolve_runai_cluster_id
    runai_mcp.mcp_call = fake_mcp_call
    runai_mcp.resolve_runai_cluster_id = fake_resolve
    try:
        # No node, no workload id, no project: an operator question's shape.
        target = replace(make_target(), node="", pod="", runai_workload_id="", project="")
        settings = replace(make_settings(), runai_mcp_url="http://runai-mcp.local")
        results = asyncio.run(
            runai_mcp.gather_runai_via_mcp(
                settings, target, headers={"Authorization": "Bearer t"}
            )
        )
    finally:
        runai_mcp.mcp_call = original_call
        runai_mcp.resolve_runai_cluster_id = original_resolve

    tools = [tool for tool, _args in called]
    assert "get_cluster_physical_inventory" in tools, tools
    assert _mcp_cluster_gpu_model(results) == "NVIDIA-H100-80GB-HBM3"


def test_cluster_inventory_failure_never_breaks_the_gather() -> None:
    """Resolution failure is one evidence row, not a lost Run:ai snapshot."""
    import asyncio
    from dataclasses import replace
    from types import SimpleNamespace

    from app.collectors import runai_mcp
    from app.collectors.runai import _mcp_cluster_gpu_model
    from tests.test_orchestrator import make_settings, make_target

    async def fake_mcp_call(url, tool, arguments, headers=None):  # noqa: ANN001
        return SimpleNamespace(isError=False, structuredContent={"ok": True})

    async def boom(_settings, _target):  # noqa: ANN001
        raise RuntimeError("Run:ai base URL is not configured")

    original_call, original_resolve = runai_mcp.mcp_call, runai_mcp.resolve_runai_cluster_id
    runai_mcp.mcp_call = fake_mcp_call
    runai_mcp.resolve_runai_cluster_id = boom
    try:
        results = asyncio.run(
            runai_mcp.gather_runai_via_mcp(
                replace(make_settings(), runai_mcp_url="http://runai-mcp.local"),
                replace(make_target(), node=""),
                headers={"Authorization": "Bearer t"},
            )
        )
    finally:
        runai_mcp.mcp_call = original_call
        runai_mcp.resolve_runai_cluster_id = original_resolve

    assert any(not item.get("error") for item in results), "other tools must survive"
    inventory = [item for item in results if item.get("name") == "cluster_inventory"]
    assert len(inventory) == 1 and inventory[0]["error"]
    # Unknown model => gate stays off rather than guessing.
    assert _mcp_cluster_gpu_model(results) == ""
