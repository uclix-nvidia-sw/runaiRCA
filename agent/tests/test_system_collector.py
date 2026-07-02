from __future__ import annotations

import pytest

from app.collectors import system as system_mod
from app.collectors.base import AnalysisTarget
from app.collectors.http_json import JsonResponse
from app.collectors.system import SystemCollector, _base_url_for_node, _lines


def _target(node: str = "gpu-node-1") -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="trainer",
        workload_type="",
        runai_workload_id="",
        node=node,
        pod="",
        severity="warning",
        alert_name="RunAIAlert",
    )


class _Settings:
    enable_system_agent = True
    system_agent_url = "http://{node}:9095"
    system_agent_token = ""
    system_agent_timeout_seconds = 6
    # llm_configured() reads these; unset -> deterministic path.
    llm_base_url = ""
    llm_model = ""
    llm_api_key = ""


def test_base_url_substitutes_node() -> None:
    assert _base_url_for_node("http://{node}:9095", "n1") == "http://n1:9095"
    # No placeholder -> used as-is (shared endpoint).
    assert _base_url_for_node("http://svc:9095", "n1") == "http://svc:9095"


def test_lines_tolerates_shapes() -> None:
    assert _lines({"lines": ["a", "b"]}) == ["a", "b"]
    assert _lines({"body": "a\nb"}) == ["a", "b"]
    assert _lines(["x", 1]) == ["x", "1"]
    assert _lines("nope") == []


@pytest.mark.asyncio
async def test_unconfigured_is_unavailable() -> None:
    class Off(_Settings):
        enable_system_agent = False

    result = await SystemCollector(Off()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.url"]


@pytest.mark.asyncio
async def test_no_node_is_unavailable() -> None:
    result = await SystemCollector(_Settings()).collect(_target(node=""))
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.node"]


@pytest.mark.asyncio
async def test_detects_kernel_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = {
        "dmesg": [
            "NVRM: Xid (PCI:0000:65:00): 79, GPU has fallen off the bus.",
            "eth0: link up",
        ],
        "journal": ["systemd: started thing"],
        "syslog": ["kernel: EXT4-fs error (device sda1): bad block"],
    }

    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        source = params["source"]
        return JsonResponse(
            url=f"{base_url}{path}?source={source}",
            status_code=200,
            data={"lines": payloads[source]},
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)

    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    assert result.confidence == "high"
    # XID + "fallen off the bus" + ext4 error surfaced; benign lines dropped.
    detail_sources = {s["source"]: s for s in result.details["sources"]}
    assert detail_sources["dmesg"]["error_count"] == 1
    assert detail_sources["journal"]["error_count"] == 0
    assert detail_sources["syslog"]["error_count"] == 1


@pytest.mark.asyncio
async def test_reachable_but_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=200, data={"lines": ["all good"]})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "ok"
    assert result.confidence == "medium"
    assert result.missing_data == []


@pytest.mark.asyncio
async def test_all_sources_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=0, error="ConnectError: refused")

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.query"]
    assert result.warnings
