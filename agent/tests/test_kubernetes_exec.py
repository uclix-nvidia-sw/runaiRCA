from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors.base import AnalysisTarget
from app.collectors.kubernetes import KubernetesCollector, exec_command_allowed
from app.config import load_settings


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        cluster="",
        project="",
        queue="",
        namespace="runai",
        workload_name="",
        workload_type="",
        runai_workload_id="",
        node="",
        pod="trainer-0",
        severity="warning",
        alert_name="RunAIAlert",
    )


def test_readonly_command_allowed() -> None:
    assert exec_command_allowed(["nvidia-smi"]) is True
    assert exec_command_allowed(["cat", "/proc/driver/nvidia/version"]) is True
    assert exec_command_allowed(["env"]) is False  # environment variables often carry secrets


def test_mutating_command_rejected() -> None:
    # Not on the allowlist at all.
    assert exec_command_allowed(["rm", "-rf", "/data"]) is False
    assert exec_command_allowed(["kubectl", "delete", "pod", "trainer-0"]) is False
    # Empty argv.
    assert exec_command_allowed([]) is False
    # Shell-injection / chaining tokens are refused even if a prefix looks benign.
    assert exec_command_allowed(["nvidia-smi", ";", "rm", "-rf", "/"]) is False
    assert exec_command_allowed(["cat", "/etc/passwd", "&&", "reboot"]) is False
    assert exec_command_allowed(["sh", "-c", "nvidia-smi"]) is False


@pytest.mark.asyncio
async def test_collector_degrades_when_token_unavailable() -> None:
    # Point token/CA at paths that do not exist -> collector reports unavailable, never raises.
    settings = replace(load_settings(), kubernetes_token_path="/nonexistent/token")
    result = await KubernetesCollector(settings).collect(_target())
    assert result.status == "unavailable"
    assert "kubernetes.service_account_token" in result.missing_data


@pytest.mark.asyncio
async def test_exec_probes_skipped_when_pod_exec_disabled() -> None:
    from app.collectors import kubernetes as k8s

    settings = replace(load_settings(), enable_pod_exec=False)
    probes = await k8s._collect_exec_probes(
        settings=settings,
        target=_target(),
        containers=["main"],
    )
    assert probes == []


@pytest.mark.asyncio
async def test_k8s_exec_gate_and_allowlist() -> None:
    from app.collectors.kubernetes import k8s_exec

    # Disabled -> refuses regardless of command.
    off = replace(load_settings(), enable_pod_exec=False, kubernetes_mcp_url="http://mcp")
    r = await k8s_exec(off, "runai", "trainer-0", ["nvidia-smi"])
    assert "disabled" in (r.get("error") or "")

    # Enabled but a non-allowlisted command is refused before any transport call.
    on = replace(load_settings(), enable_pod_exec=True, kubernetes_mcp_url="http://mcp")
    r = await k8s_exec(on, "runai", "trainer-0", ["env"])  # env leaks secrets -> not allowlisted
    assert "allowlist" in (r.get("error") or "")
    r = await k8s_exec(on, "runai", "trainer-0", ["cat", "/etc/shadow"])
    assert "allowlist" in (r.get("error") or "")


@pytest.mark.asyncio
async def test_k8s_exec_streams_an_allowlisted_command(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    calls: list[dict] = []

    async def fake_exec(_settings, **kwargs):
        calls.append(kwargs)
        return "GPU 0\n", "", ""

    monkeypatch.setattr(k8s, "_read_file", lambda _path: "service-account-token")
    monkeypatch.setattr(k8s, "_exec_via_websocket", fake_exec)
    result = await k8s.k8s_exec(
        replace(load_settings(), enable_pod_exec=True),
        "runai",
        "trainer-0",
        ["nvidia-smi"],
        container="main",
    )

    assert result["error"] is None
    assert result["output"] == "GPU 0\n"
    assert result["observed_entity"] == {
        "kind": "pod",
        "name": "trainer-0",
        "namespace": "runai",
    }
    assert calls == [
        {
            "namespace": "runai",
            "pod": "trainer-0",
            "command": ["nvidia-smi"],
            "container": "main",
            "token": "service-account-token",
        }
    ]


@pytest.mark.asyncio
async def test_k8s_exec_classifies_forbidden_handshake_without_echoing_url(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    class ForbiddenHandshake(Exception):
        status = 403

    async def denied(_settings, **_kwargs):
        raise ForbiddenHandshake(
            "403, url='wss://kubernetes.default.svc/api/v1/pods/trainer-0/exec?command=free'"
        )

    monkeypatch.setattr(k8s, "_read_file", lambda _path: "service-account-token")
    monkeypatch.setattr(k8s, "_exec_via_websocket", denied)
    result = await k8s.k8s_exec(
        replace(load_settings(), enable_pod_exec=True),
        "runai",
        "trainer-0",
        ["free", "-h"],
    )

    assert result["error_code"] == "kubernetes_exec_forbidden"
    assert result["transport_error"] is True
    assert result["retryable"] is False
    assert result["status_code"] == 403
    assert "get/create" in str(result["error"])
    assert "pods/exec" in str(result["error"])
    assert "wss://" not in str(result["error"])
    assert "command=free" not in str(result["error"])


@pytest.mark.asyncio
async def test_exec_probe_batch_stops_after_transport_failure(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    calls: list[tuple[str, ...]] = []

    async def forbidden(_settings, _namespace, _pod, command, container=""):
        calls.append(tuple(command))
        return {
            "namespace": "runai",
            "pod": "trainer-0",
            "container": container,
            "error": "pod exec denied",
            "error_code": "kubernetes_exec_forbidden",
            "transport_error": True,
        }

    monkeypatch.setattr(k8s, "k8s_exec", forbidden)
    probes = await k8s._collect_exec_probes(
        settings=replace(load_settings(), enable_pod_exec=True),
        target=_target(),
        containers=["main"],
    )

    assert calls == [("free", "-h")]
    assert len(probes) == 1
    assert probes[0]["error_code"] == "kubernetes_exec_forbidden"


def test_exec_probe_aggregate_requires_one_verified_pod_identity() -> None:
    from app.collectors.kubernetes import _exec_probes_observed_entity

    entity = {"kind": "pod", "name": "trainer-0", "namespace": "runai"}
    assert _exec_probes_observed_entity(
        [{"observed_entity": entity}, {"observed_entity": dict(entity)}]
    ) == entity
    assert _exec_probes_observed_entity(
        [{"observed_entity": entity}, {"observed_entity": {"kind": "pod", "name": "other"}}]
    ) is None


def test_exec_frame_demux_routes_channels() -> None:
    from app.collectors.kubernetes import _accumulate_exec_frame

    out: list[str] = []
    err: list[str] = []
    # channel 1 = stdout, channel 2 = stderr, channel 3 = status (Success -> no error).
    assert _accumulate_exec_frame(b"\x01GPU-0\n", out, err) == ""
    assert _accumulate_exec_frame(b"\x02warn\n", out, err) == ""
    assert _accumulate_exec_frame(b'\x03{"status":"Success"}', out, err) == ""
    assert out == ["GPU-0\n"] and err == ["warn\n"]
    # A Failure status surfaces its message as the error.
    msg = _accumulate_exec_frame(b'\x03{"status":"Failure","message":"boom"}', out, err)
    assert msg == "boom"


@pytest.mark.asyncio
async def test_exec_probes_are_allowlisted_and_executed_when_enabled(monkeypatch) -> None:
    from app.collectors import kubernetes as k8s

    settings = replace(load_settings(), enable_pod_exec=True)
    calls: list[tuple[str, ...]] = []

    async def fake_k8s_exec(settings, namespace, pod, command, container=""):
        calls.append(tuple(command))
        return {
            "namespace": namespace,
            "pod": pod,
            "container": container,
            "status_code": 200,
            "error": None,
            "output": "ok",
        }

    monkeypatch.setattr(k8s, "k8s_exec", fake_k8s_exec)
    probes = await k8s._collect_exec_probes(
        settings=settings,
        target=_target(),
        containers=["main"],
    )
    assert probes, "expected allowlisted probes when pod exec is enabled"
    # The bounded base set is truly streamed, never a placeholder card.
    assert all(p["allowed"] is True for p in probes)
    assert all(p["attempted"] is True for p in probes)
    assert all(p["error"] is None for p in probes)
    assert calls == [
        ("free", "-h"),
        ("df", "-h"),
        ("nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv"),
    ]
