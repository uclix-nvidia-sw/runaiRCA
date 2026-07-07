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
        headers={},
        verify=True,
    )
    assert probes == []


@pytest.mark.asyncio
async def test_exec_probes_are_allowlisted_and_not_executed_when_enabled() -> None:
    from app.collectors import kubernetes as k8s

    settings = replace(load_settings(), enable_pod_exec=True)
    probes = await k8s._collect_exec_probes(
        settings=settings,
        target=_target(),
        containers=["main"],
        headers={},
        verify=True,
    )
    assert probes, "expected allowlisted probes when pod exec is enabled"
    # Every recorded probe is read-only allowlisted and not actually streamed (see comment).
    assert all(p["allowed"] is True for p in probes)
    assert all(p["attempted"] is False for p in probes)
