from __future__ import annotations

from dataclasses import replace

import pytest

from app.collectors import system as system_mod
from app.collectors.base import AnalysisTarget
from app.collectors.http_json import JsonResponse
from app.collectors.kubernetes import _scope_target
from app.collectors.system import SystemCollector, _base_url_for_node, _lines, system_log_query
from app.plan import InvestigationPlan


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
    assert _base_url_for_node("http://{node}:9095", "n1/../../evil@host") == (
        "http://n1%2F..%2F..%2Fevil%40host:9095"
    )
    # No placeholder -> used as-is (shared endpoint).
    assert _base_url_for_node("http://svc:9095", "n1") == "http://svc:9095"


@pytest.mark.asyncio
async def test_node_internal_ip_encodes_node_path_segment(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Settings(_Settings):
        kubernetes_token_path = "/token"
        kubernetes_ca_path = ""
        kubernetes_api_url = "https://kubernetes.default.svc"
        kubernetes_timeout_seconds = 5

    async def fake_get_json(**kwargs):
        calls.append(kwargs["path"])
        return JsonResponse(url=kwargs["path"], status_code=404, data={})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    monkeypatch.setattr("app.collectors.kubernetes._read_file", lambda _path: "token")

    await system_mod._node_internal_ip(Settings(), "node/../../pods")

    assert calls == ["/api/v1/nodes/node%2F..%2F..%2Fpods"]


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
        "fabricmanager": ["Fabric Manager healthy"],
        "nvidia-smi": ["GPU 0: healthy"],
        "nvlink": ["GPU 0: NVLink status active"],
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
    assert detail_sources["fabricmanager"]["error_count"] == 0
    assert detail_sources["nvidia-smi"]["error_count"] == 0
    assert detail_sources["nvlink"]["error_count"] == 0
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")


@pytest.mark.asyncio
async def test_reachable_but_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=200, data={"lines": ["all good"]})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "partial"
    assert result.confidence == "low"
    assert result.missing_data == []


@pytest.mark.asyncio
async def test_historical_incident_scopes_journal_and_ignores_current_tails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(*, params, **kwargs):
        calls.append(params)
        source = params["source"]
        # A current dmesg/syslog error is useful context, but cannot establish
        # a cause for a months-old incident. The time-bounded journal is clean.
        lines = ["NVRM: Xid 79"] if source in {"dmesg", "syslog"} else ["all good"]
        data = {"lines": lines}
        if source == "journal":
            data.update({"source": source, "since": params["since"], "until": params["until"]})
        return JsonResponse(url="http://node/logs", status_code=200, data=data)

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-01-02T03:00:00Z",
        resolved_at="2026-01-02T03:10:00Z",
    )
    result = await SystemCollector(_Settings()).collect(target)

    journal_params = next(params for params in calls if params["source"] == "journal")
    assert journal_params == {
        "source": "journal",
        "lines": "500",
        "since": "2026-01-02T02:55:00Z",
        "until": "2026-01-02T03:15:00Z",
    }
    assert all(
        "since" not in params
        for params in calls
        if params["source"] in {"dmesg", "syslog", "nvidia-smi", "nvlink"}
    )
    fabricmanager_params = next(params for params in calls if params["source"] == "fabricmanager")
    assert fabricmanager_params == {
        "source": "fabricmanager",
        "lines": "500",
        "since": "2026-01-02T02:55:00Z",
        "until": "2026-01-02T03:15:00Z",
    }
    assert result.status == "partial"
    assert result.confidence == "low"
    assert "journal" in result.summary
    assert result.details["time_range"] == {
        "start": "2026-01-02T02:55:00Z",
        "end": "2026-01-02T03:15:00Z",
    }
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")


@pytest.mark.asyncio
async def test_all_sources_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_json(*, base_url, path, timeout_seconds, params, **kwargs):
        return JsonResponse(url=base_url, status_code=0, error="ConnectError: refused")

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    result = await SystemCollector(_Settings()).collect(_target())
    assert result.status == "unavailable"
    assert result.missing_data == ["system_agent.query"]
    assert result.warnings


@pytest.mark.asyncio
async def test_system_log_query_is_scoped_bounded_and_body_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        return JsonResponse(
            url="http://node/logs",
            status_code=200,
            data={"body": "api_key=raw-host-secret", "lines": ["NVRM: Xid 79", "healthy"]},
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    query = await system_log_query(
        _Settings(),
        _target(),
        {"source": "journal", "lookback_seconds": 120, "lines": 2, "grep": "NVRM: Xid"},
    )

    assert calls[0]["params"] == {"source": "journal", "lines": "2", "grep": r"NVRM:\ Xid"}
    assert query["source_group"] == "node_system"
    assert query["independence_group"] == "node_system"
    observation = query["observation"]
    assert observation["observed_entity"] == {"kind": "node", "name": "gpu-node-1"}
    assert observation["window"] == {"lookback_seconds": 120}
    assert observation["polarity"] == "present"
    assert observation["coverage"] == "partial"
    assert set(observation["observation_window"]) == {"start", "end"}
    assert observation["signal_types"] == ["gpu_driver"]
    assert observation["body_included"] is False
    assert "raw-host-secret" not in str(query)
    assert "NVRM: Xid 79" not in str(query)


@pytest.mark.asyncio
async def test_system_log_query_scopes_historical_journalctl_sources_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        params = kwargs["params"]
        return JsonResponse(
            url="http://node/logs",
            status_code=200,
            data={
                "source": params["source"],
                "since": params.get("since"),
                "until": params.get("until"),
                "lines": ["2026-07-13T21:44:00Z kernel: NVRM: Xid 79"],
            },
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )

    journal = await system_log_query(
        _Settings(), target, {"source": "journal", "lookback_seconds": 60, "lines": 2}
    )
    dmesg = await system_log_query(
        _Settings(), target, {"source": "dmesg", "lookback_seconds": 60, "lines": 2}
    )
    fabricmanager = await system_log_query(
        _Settings(), target, {"source": "fabricmanager", "lookback_seconds": 60, "lines": 2}
    )

    assert calls[0]["params"] == {
        "source": "journal",
        "lines": "2",
        "since": "2026-07-13T21:38:47Z",
        "until": "2026-07-13T21:50:47Z",
    }
    assert calls[1]["params"] == {"source": "dmesg", "lines": "2"}
    assert calls[2]["params"] == {
        "source": "fabricmanager",
        "lines": "2",
        "since": "2026-07-13T21:38:47Z",
        "until": "2026-07-13T21:50:47Z",
    }
    assert journal["observation"]["historical_scope"] is True
    assert journal["observation"]["observation_window"] == {
        "start": "2026-07-13T21:38:47Z",
        "end": "2026-07-13T21:50:47Z",
    }
    assert journal["observation"]["window"] == {"lookback_seconds": 720}
    assert (journal["polarity"], journal["coverage"]) == ("present", "scoped")
    assert journal["observation"]["evidence_window"] == {
        "start": "2026-07-13T21:44:00Z",
        "end": "2026-07-13T21:44:00Z",
    }
    assert dmesg["observation"]["historical_scope"] is False
    assert dmesg["coverage"] == "partial"
    assert fabricmanager["observation"]["historical_scope"] is True
    assert fabricmanager["coverage"] == "scoped"


@pytest.mark.asyncio
async def test_system_log_query_accepts_new_sources_and_rejects_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def fake_get_json(**kwargs):
        calls.append(kwargs["params"]["source"])
        return JsonResponse(url="http://node/logs", status_code=200, data={"lines": []})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    for source in ("fabricmanager", "nvidia-smi", "nvlink"):
        query = await system_log_query(_Settings(), _target(), {"source": source})
        assert query["error"] is None
    unknown = await system_log_query(_Settings(), _target(), {"source": "not-a-source"})

    assert calls == ["fabricmanager", "nvidia-smi", "nvlink"]
    assert unknown["error"] == (
        "source must be one of: dmesg, journal, syslog, fabricmanager, nvidia-smi, nvlink"
    )


@pytest.mark.asyncio
async def test_historical_journal_keeps_post_resolution_match_as_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-resolution log match must retain its own occurrence instant."""
    async def fake_get_json(**kwargs):
        params = kwargs["params"]
        return JsonResponse(
            url="http://node/logs",
            status_code=200,
            data={
                "source": "journal",
                "since": params["since"],
                "until": params["until"],
                # Resolution is 21:45:47; this belongs only to recovery context.
                "lines": ["2026-07-13T21:48:00Z kernel: NVRM: Xid 79"],
            },
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(),
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )

    query = await system_log_query(_Settings(), target, {"source": "journal"})

    assert (query["polarity"], query["coverage"]) == ("unknown", "partial")
    assert query["observation"]["observation_window"] == {
        "start": "2026-07-13T21:38:47Z",
        "end": "2026-07-13T21:50:47Z",
    }
    assert "evidence_window" not in query["observation"]
    assert query["observation"]["matching_line_count"] == 1


@pytest.mark.asyncio
async def test_shared_system_agent_receives_target_node(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    class SharedSettings(_Settings):
        system_agent_url = "http://system-agent.runai-rca:9095"

    async def fake_get_json(**kwargs):
        calls.append(kwargs)
        params = kwargs["params"]
        return JsonResponse(
            url="http://system-agent/logs",
            status_code=200,
            data={
                "source": params["source"],
                "since": params.get("since"),
                "until": params.get("until"),
                "lines": ["2026-07-13T21:44:00Z kernel: NVRM: Xid 79"],
            },
        )

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(), fired_at="2026-07-13T21:43:47Z", resolved_at="2026-07-13T21:45:47Z"
    )
    result = await SystemCollector(SharedSettings()).collect(target)
    query = await system_log_query(SharedSettings(), target, {"source": "journal"})

    assert all(call["params"]["node"] == "gpu-node-1" for call in calls)
    assert result.artifacts[0].result["observation"]["coverage"] == "scoped"
    assert query["coverage"] == "scoped"


@pytest.mark.asyncio
async def test_historical_malformed_journal_is_context_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_json(**kwargs):
        # A proxy/old endpoint can still be 200 and carry a matching text, but
        # without the chart envelope it does not prove source or time window.
        return JsonResponse(url="http://node/logs", status_code=200, data=["NVRM: Xid 79"])

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(), fired_at="2026-07-13T21:43:47Z", resolved_at="2026-07-13T21:45:47Z"
    )

    query = await system_log_query(_Settings(), target, {"source": "journal"})
    result = await SystemCollector(_Settings()).collect(target)

    assert (query["polarity"], query["coverage"]) == ("present", "partial")
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("unknown", "partial")
    assert result.status == "partial"
    assert any("historical journalctl window" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_live_pod_node_fallback_runs_but_historical_evidence_stays_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_node_from_target_pod(*_args, **_kwargs):
        return "gpu-node-live", "trainer-1"

    async def fake_get_json(*, params, **_kwargs):
        source = params["source"]
        data = {
            "lines": ["2026-07-13T21:44:00Z kernel: NVRM: Xid 79"]
            if source == "journal"
            else []
        }
        if source == "journal":
            data.update({"source": source, "since": params["since"], "until": params["until"]})
        return JsonResponse(url="http://node/logs", status_code=200, data=data)

    monkeypatch.setattr(system_mod, "_node_from_target_pod", fake_node_from_target_pod)
    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(node="",),
        pod="trainer-0",
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )

    result = await SystemCollector(_Settings()).collect(target)

    assert result.details["node"] == "gpu-node-live"
    assert result.details["resolved_pod"] == "trainer-1"
    assert result.details["node_origin"] == "live_pod"
    observation = result.artifacts[0].result["observation"]
    assert observation["observed_entity"] == {"kind": "node", "name": "gpu-node-live"}
    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")


@pytest.mark.asyncio
async def test_resolved_pod_node_comes_from_incident_window_event_not_live_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.collectors import kubernetes as k8s

    seen: dict[str, object] = {}

    async def fake_describe_events(
        _settings,
        *,
        namespace,
        name,
        expected_kind,
        expected_uid,
        time_range,
    ):
        seen.update(
            namespace=namespace,
            name=name,
            expected_kind=expected_kind,
            expected_uid=expected_uid,
            time_range=time_range,
        )
        return [
            {
                "source": {"component": "kubelet", "host": "gpu-node-old"},
                "involvedObject": {"kind": "Pod", "name": name, "uid": expected_uid},
                "lastTimestamp": "2026-07-13T21:44:00Z",
            }
        ]

    async def live_resolver_must_not_run(*_args, **_kwargs):
        raise AssertionError("resolved incidents must not follow a live replacement Pod")

    monkeypatch.setattr(k8s, "_describe_events", fake_describe_events)
    monkeypatch.setattr(k8s, "resolve_live_pod_node", live_resolver_must_not_run)
    target = replace(
        _target(node=""),
        pod="trainer-dead",
        pod_uid="uid-dead",
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )

    placement = await system_mod._node_from_target_pod(
        _Settings(), target, InvestigationPlan(pod="trainer-dead")
    )

    assert placement == ("gpu-node-old", "trainer-dead", "historical_pod_event")
    assert seen == {
        "namespace": "runai",
        "name": "trainer-dead",
        "expected_kind": "Pod",
        "expected_uid": "uid-dead",
        "time_range": {
            "start": "2026-07-13T21:38:47Z",
            "end": "2026-07-13T21:50:47Z",
        },
    }


@pytest.mark.asyncio
async def test_historical_pod_event_node_scopes_incident_journal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_node_from_target_pod(*_args, **_kwargs):
        return "gpu-node-old", "trainer-dead", "historical_pod_event"

    async def fake_get_json(*, params, **_kwargs):
        source = params["source"]
        data = {
            "source": source,
            "since": params.get("since"),
            "until": params.get("until"),
            "lines": (
                ["2026-07-13T21:44:00Z kernel: NVRM: Xid 79"]
                if source == "journal"
                else []
            ),
        }
        return JsonResponse(url="http://node/logs", status_code=200, data=data)

    monkeypatch.setattr(system_mod, "_node_from_target_pod", fake_node_from_target_pod)
    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    target = replace(
        _target(node=""),
        pod="trainer-dead",
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )

    result = await SystemCollector(_Settings()).collect(target)

    assert result.status == "ok"
    assert result.confidence == "high"
    assert result.details["node_origin"] == "historical_pod_event"
    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "scoped")


@pytest.mark.asyncio
async def test_pipeline_plan_node_provenance_stays_contextual_for_historical_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_json(*, params, **_kwargs):
        source = params["source"]
        data = {
            "lines": ["2026-07-13T21:44:00Z kernel: NVRM: Xid 79"]
            if source == "journal"
            else []
        }
        if source == "journal":
            data.update({"source": source, "since": params["since"], "until": params["until"]})
        return JsonResponse(url="http://node/logs", status_code=200, data=data)

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    alert_target = replace(
        _target(node=""),
        pod="trainer-0",
        fired_at="2026-07-13T21:43:47Z",
        resolved_at="2026-07-13T21:45:47Z",
    )
    plan = InvestigationPlan(node="gpu-node-live", pod="trainer-1")
    scoped_target = _scope_target(alert_target, plan)

    assert (scoped_target.node, scoped_target.node_source) == ("gpu-node-live", "plan")
    result = await SystemCollector(_Settings()).collect(scoped_target, plan)

    observation = result.artifacts[0].result["observation"]
    assert (observation["polarity"], observation["coverage"]) == ("present", "partial")
    assert result.status == "partial"


@pytest.mark.asyncio
async def test_many_log_matches_do_not_pass_compact_marker_to_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    async def fake_get_json(*, params, **_kwargs):
        lines = [f"NVRM: Xid {index}" for index in range(9)] if params["source"] == "dmesg" else []
        return JsonResponse(url="http://node/logs", status_code=200, data={"lines": lines})

    async def fake_insight(_settings, _node, error_lines):
        seen.extend(error_lines)
        return "nine matching lines"

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    monkeypatch.setattr(system_mod, "llm_configured", lambda _settings: True)
    monkeypatch.setattr(system_mod, "_llm_insight", fake_insight)

    result = await SystemCollector(_Settings()).collect(_target())

    assert len(seen) == 9
    assert all(isinstance(line, str) for line in seen)
    assert result.summary == "nine matching lines"


@pytest.mark.asyncio
async def test_system_log_query_refuses_scope_or_limit_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fake_get_json(**kwargs):
        nonlocal called
        called = True
        return JsonResponse(url="u", status_code=200, data={"lines": []})

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    query = await system_log_query(
        _Settings(), _target(), {"source": "journal", "node": "other-node", "lines": 1001}
    )

    assert query["error"] == "node must match the alert node scope"
    assert query["observation"]["coverage"] == "unknown"
    assert called is False


@pytest.mark.asyncio
async def test_system_log_query_refuses_unsafe_grep_and_line_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_json(**kwargs):
        raise AssertionError("invalid arguments must not make a request")

    monkeypatch.setattr(system_mod, "get_json", fake_get_json)
    too_many = await system_log_query(_Settings(), _target(), {"source": "journal", "lines": 1001})
    unsafe = await system_log_query(
        _Settings(), _target(), {"source": "journal", "grep": "line\nnext"}
    )

    assert too_many["error"] == "lines must be between 1 and 1000"
    assert unsafe["error"] == "grep must not contain control characters"


def test_fabric_manager_evidence_reaches_the_knowledge_matcher() -> None:
    """End-to-end delivery chain for Fabric Manager incidents: a fabricmanager
    log line the system agent gathers must be (A) surfaced by the error filter
    (not dropped) AND (B) matched by the loaded network_fabric_error knowledge,
    so the RCA actually references the FM/SXid troubleshooting knowledge."""
    from app.collectors.system import _ERROR_PATTERNS
    from app.knowledge import load_failure_modes, match_failure_mode_symptoms

    modes = load_failure_modes("knowledge/failure_modes.yaml")

    def chain(line: str) -> bool:
        return bool(_ERROR_PATTERNS.search(line)) and any(
            family == "network_fabric_error"
            for family, _ in match_failure_mode_symptoms(modes, line, "")
        )

    # SXid codes flow capture -> matcher -> the correct severity symptom.
    assert chain("nvswitch: SXid 23001 egress DST-VC credit overflow")  # always-fatal
    assert chain("SXid 20034 LTSSM Fault Up; GPU reported Xid 74")  # fatal
    assert chain("fmActivateFabricPartition failed: FM_ST_IN_USE")  # partition life-cycle
    # Fabric Manager init failure signal is at least captured (was dropped before).
    assert _ERROR_PATTERNS.search("nvidia-fabricmanager: GPU system not yet initialized")


def test_same_instant_tolerates_timestamp_reformatting() -> None:
    """A correctly-windowed journalctl response must not be false-negatived into
    'context only' just because the agent echoes Z vs +00:00 or reformats."""
    from app.collectors.system import _same_instant

    assert _same_instant("2026-07-14T01:00:00Z", "2026-07-14T01:00:00Z")
    assert _same_instant("2026-07-14T01:00:00+00:00", "2026-07-14T01:00:00Z")
    assert not _same_instant("2026-07-14T01:00:00Z", "2026-07-14T02:00:00Z")
    assert not _same_instant("", "2026-07-14T01:00:00Z")
