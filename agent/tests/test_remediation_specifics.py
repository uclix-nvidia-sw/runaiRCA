"""An operator must read the observed numbers, not a placeholder."""

from __future__ import annotations

from app.collectors.base import CollectorResult, artifact, resolve_target
from app.collectors.kubernetes import (
    _container_diagnostics,
    _node_condition_artifacts,
    _pod_scheduling_artifact,
)
from app.schemas import Alert, AlertAnalysisRequest
from app.services import pipeline
from app.services.harness import assign_evidence_ids
from app.services.remediation import (
    fill_placeholders,
    format_memory,
    image_repository,
    image_typo_hint,
    memory_sizing_action,
    parse_memory,
)
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings


def _lifecycle(container: dict[str, object]) -> CollectorResult:
    item = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_container_lifecycle",
        status="ok",
        confidence="high",
        summary="typed state",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "pod": "trainer-0",
            "namespace": "runai-team-a",
            "containers": [container],
        },
    )
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="typed state", artifacts=[item]
    )
    assign_evidence_ids([result])
    return result


def _request(**labels: str) -> AlertAnalysisRequest:
    return AlertAnalysisRequest(
        alert=Alert(
            status="firing",
            labels={"alertname": "KubePodCrashLooping", "namespace": "runai-team-a", **labels},
        )
    )


def _oom_container() -> dict[str, object]:
    return {
        "name": "main",
        "restartCount": 4,
        "image": "docker.io/library/python:3.11",
        "resources": {
            "limits": {"memory": "512Mi", "cpu": "2"},
            "requests": {"memory": "256Mi"},
        },
        "lastTerminated": {"phase": "terminated", "reason": "OOMKilled", "exitCode": 137},
    }


def test_memory_quantities_round_trip() -> None:
    assert parse_memory("512Mi") == 512 * 1024**2
    assert parse_memory("1Gi") == 1024**3
    assert parse_memory("500M") == 500 * 1000**2
    assert parse_memory("536870912") == 536870912
    assert parse_memory("garbage") is None
    assert format_memory(1024**3) == "1Gi"
    assert format_memory(512 * 1024**2) == "512Mi"
    # Not an exact multiple of a binary unit -> round UP, never below the need.
    assert format_memory(1500 * 1000**2) == "1431Mi"


def test_container_diagnostics_carry_spec_resources_and_image() -> None:
    """The typed artifact is the only path these facts have to the report."""
    diagnostics = _container_diagnostics(
        {
            "containerStatuses": [{"name": "main", "image": "nginx:1.25", "restartCount": 3}],
            "resources": {"main": {"limits": {"memory": "512Mi"}}},
        }
    )

    assert diagnostics[0]["image"] == "nginx:1.25"
    assert diagnostics[0]["resources"] == {"limits": {"memory": "512Mi"}}


def test_oom_cause_statement_names_current_limit_and_request() -> None:
    results = [_lifecycle(_oom_container())]
    candidate = RankedCause(
        "workload_runtime_error",
        "high",
        9.0,
        mechanism="typed container state OOMKilled on the alert Pod (machine-reported)",
    )

    english = pipeline._specific_cause_statement(
        candidate, results, {"E01"}, language="en", request=_request()
    )
    korean = pipeline._specific_cause_statement(
        candidate, results, {"E01"}, language="ko", request=_request()
    )

    assert "OOM-killed it (exit 137)" in english
    assert "memory limit 512Mi" in english and "request 256Mi" in english
    assert "OOM kill(exit 137)" in korean
    assert "memory limit 512Mi" in korean and "request 256Mi" in korean


def test_oom_actions_recommend_values_and_a_command() -> None:
    results = [_lifecycle(_oom_container())]
    target = resolve_target(
        {"namespace": "runai-team-a", "pod": "trainer-0", "workload_kind": "Deployment"}, {}
    )
    facts = pipeline._remediation_facts(results, {"E01"}, target)

    assert facts["memory_limit"] == "512Mi"
    assert facts["memory_request"] == "256Mi"
    assert facts["container"] == "main"

    action = memory_sizing_action(facts, "en")
    assert "512Mi → 1Gi" in action
    assert "256Mi → 512Mi" in action
    assert "kubectl -n runai-team-a set resources" in action
    assert "--limits=memory=1Gi --requests=memory=512Mi" in action
    # No limit configured means node-level pressure, not a sizing problem.
    assert memory_sizing_action({"oom": "true"}, "en") == ""
    assert memory_sizing_action({"memory_limit": "512Mi"}, "en") == ""


def test_missing_request_is_reported_as_unset() -> None:
    facts = {"oom": "true", "container": "main", "memory_limit": "1Gi"}

    assert "unset → 1Gi" in memory_sizing_action(facts, "en")
    assert "미설정 → 1Gi" in memory_sizing_action(facts, "ko")


def test_curated_placeholders_are_filled_with_observed_values() -> None:
    facts = {"namespace": "runai-team-a", "pod": "trainer-0", "image": "ngink:1.25"}
    filled = fill_placeholders(
        "Read `kubectl describe pod <pod> -n <ns>` then `crane manifest <image:tag>`", facts
    )

    assert "pod trainer-0 -n runai-team-a" in filled
    assert "crane manifest ngink:1.25" in filled
    # Ambiguous placeholders stay blank rather than becoming a wrong command.
    assert "<name>" in fill_placeholders("kubectl describe pvc <name> -n <ns>", facts)


def test_image_pull_names_the_reference_and_suspects_a_typo() -> None:
    container = {
        "name": "web",
        "image": "docker.io/library/ngink:1.25",
        "state": {"phase": "waiting", "reason": "ImagePullBackOff", "message": "back-off pulling"},
    }
    results = [_lifecycle(container)]
    candidate = RankedCause(
        "image_pull_error",
        "high",
        9.0,
        mechanism="typed container state ImagePullBackOff on the alert Pod (machine-reported)",
    )

    statement = pipeline._specific_cause_statement(
        candidate, results, {"E01"}, language="en", request=_request()
    )
    assert "docker.io/library/ngink:1.25" in statement

    facts = pipeline._remediation_facts(
        results, {"E01"}, resolve_target({"namespace": "runai-team-a"}, {})
    )
    assert facts["repo"] == "docker.io/library/ngink"
    assert "nginx" in image_typo_hint(facts, "en")
    assert "nginx" in image_typo_hint(facts, "ko")
    # A deliberate in-house name must not be accused of being a typo.
    assert image_typo_hint({"repo": "registry.local/team/feature-store"}, "en") == ""


def test_image_repository_strips_tag_and_digest_but_keeps_registry_port() -> None:
    assert image_repository("registry.local:5000/team/app:v2") == "registry.local:5000/team/app"
    assert image_repository("nginx@sha256:" + "0" * 64) == "nginx"


def _actions(container: dict[str, object], family: str, reason: str, observed: str) -> str:
    results = [_lifecycle(container)]
    target = resolve_target({"namespace": "runai-team-a", "pod": "trainer-0"}, {})
    candidates = [
        RankedCause(
            family,
            "high",
            9.0,
            mechanism=f"typed container state {reason} on the alert Pod (machine-reported)",
        )
    ]
    return "\n".join(
        pipeline._numbered_actions(
            None,
            None,
            candidates,
            observed,
            pipeline.load_failure_modes("knowledge/failure_modes.yaml"),
            [],
            _request(),
            facts=pipeline._remediation_facts(results, {"E01"}, target),
        )
    )


def test_actions_are_concrete_end_to_end() -> None:
    """The whole point: section 3 carries the numbers, not `<placeholders>`."""
    joined = _actions(_oom_container(), "workload_runtime_error", "OOMKilled", "oomkilled")

    assert "512Mi → 1Gi" in joined
    assert "kubectl -n runai-team-a set resources" in joined
    assert "<pod>" not in joined and "<ns>" not in joined


def _configuration(item: object, language: str = "en") -> list[str]:
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="typed state", artifacts=[item]
    )
    assign_evidence_ids([result])
    return pipeline._observed_configuration_lines([result], {"E01"}, language)


def test_unschedulable_pod_reports_what_it_asked_for() -> None:
    """The scheduler names the shortage; the report must name the demand."""
    pod = {
        "metadata": {"name": "trainer-0", "namespace": "runai-team-a"},
        "spec": {
            "nodeSelector": {"gpu-type": "a100"},
            "schedulerName": "runai-scheduler-default",
            "containers": [
                {
                    "name": "main",
                    "resources": {
                        "requests": {"cpu": "8", "memory": "64Gi", "nvidia.com/gpu": "4"},
                        "limits": {"memory": "64Gi", "nvidia.com/gpu": "4"},
                    },
                }
            ],
        },
        "status": {
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": "0/3 nodes are available: 3 Insufficient nvidia.com/gpu.",
                }
            ]
        },
    }
    target = resolve_target({"namespace": "runai-team-a", "pod": "trainer-0"}, {})
    item = _pod_scheduling_artifact("kubernetes", make_settings(), target, pod)

    assert item.result["resources"]["main"]["requests"]["nvidia.com/gpu"] == "4"
    line = "\n".join(_configuration(item))
    assert "main: memory 64Gi, cpu 8, nvidia.com/gpu 4" in line
    assert "nodeSelector gpu-type=a100" in line
    # Run:ai's scheduler is its own subsystem — naming it routes the investigation.
    assert "scheduler runai-scheduler-default" in line
    assert "요청 리소스" in "\n".join(_configuration(item, "ko"))


def test_node_pressure_reports_the_capacity_it_ran_out_of() -> None:
    target = resolve_target({"node": "dgx-01"}, {})
    items = _node_condition_artifacts(
        "kubernetes",
        target,
        [
            {
                "name": "node",
                "data": {
                    "name": "dgx-01",
                    "allocatable": {
                        "memory": "128Gi",
                        "cpu": "64",
                        "ephemeral-storage": "200Gi",
                        "pods": "110",
                    },
                    "conditions": [
                        {
                            "type": "DiskPressure",
                            "status": "True",
                            "lastTransitionTime": "2026-07-30T02:10:00Z",
                        }
                    ],
                },
            }
        ],
        time_range={"start": "2026-07-30T02:00:00Z", "end": "2026-07-30T02:20:00Z"},
    )

    line = "\n".join(_configuration(items[0]))
    assert "Node capacity (dgx-01)" in line
    assert "memory 128Gi" in line and "ephemeral-storage 200Gi" in line and "pods 110" in line


def test_scheduler_verdict_is_quoted_whole() -> None:
    """The tail of the tally lists every OTHER reason nodes were rejected."""
    message = (
        "0/5 nodes are available: 2 Insufficient nvidia.com/gpu, "
        "3 node(s) didn't match Pod's node affinity/selector."
    )

    detail = pipeline._scheduling_detail([message], "en")
    # A resource name contains a dot, so cutting at the first period truncates it.
    assert "2 Insufficient nvidia.com/gpu" in detail
    assert "3 node(s) didn't match" in detail
    assert "스케줄러:" in pipeline._scheduling_detail([message], "ko")
    # Not a scheduler tally -> nothing quoted.
    assert "scheduler:" not in pipeline._scheduling_detail(["Insufficient cpu"], "en")


def test_restart_loop_names_the_counter() -> None:
    assert "exit 1, 137 restarts" in pipeline._restart_loop_detail(1, 137, "en")
    assert "137회 재시작" in pipeline._restart_loop_detail(1, 137, "ko")
    # A first crash has no counter to report.
    assert "restarts" not in pipeline._restart_loop_detail(1, 0, "en")


def test_probe_settings_surface_when_a_probe_actually_failed() -> None:
    """A not-Ready container has no causal STATE, so the event is the evidence."""
    probes = {
        "readiness": {
            "handler": "httpGET /healthz:8080",
            "initialDelaySeconds": 5,
            "timeoutSeconds": 1,
            "failureThreshold": 3,
        }
    }
    lifecycle = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_container_lifecycle",
        status="ok",
        confidence="low",
        summary="lifecycle",
        result={
            "observation": {
                "polarity": "unknown",
                "coverage": "partial",
                "target_identity_verified": True,
            },
            "containers": [{"name": "main", "ready": False, "probes": probes}],
        },
    )
    unhealthy = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_warning_events",
        status="ok",
        confidence="high",
        summary="events",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "events": [
                {
                    "type": "Warning",
                    "reason": "Unhealthy",
                    "target_identity_verified": True,
                    "message": "Readiness probe failed: HTTP probe failed with statuscode: 503",
                }
            ],
        },
    )
    result = CollectorResult(
        agent="kubernetes", status="ok", summary="k8s", artifacts=[lifecycle, unhealthy]
    )
    assign_evidence_ids([result])
    ids = {str(item.evidence_id) for item in result.artifacts}

    line = "\n".join(pipeline._observed_configuration_lines([result], ids, "en"))
    assert "Probe settings (main)" in line
    assert "httpGET /healthz:8080" in line
    assert "timeout 1s, failures 3" in line  # seconds get a unit, counts do not

    # Without the Unhealthy event, probe settings are not this incident's business.
    quiet = CollectorResult(agent="kubernetes", status="ok", summary="k8s", artifacts=[lifecycle])
    assign_evidence_ids([quiet])
    assert pipeline._observed_configuration_lines([quiet], {"E01"}, "en") == []


def test_probe_summary_reads_every_handler_shape() -> None:
    from app.collectors.kubernetes import _probe_summary

    summary = _probe_summary(
        {
            "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}, "timeoutSeconds": 2},
            "livenessProbe": {"tcpSocket": {"port": 9000}},
            "startupProbe": {"exec": {"command": ["sh", "-c", "test -f /tmp/ok"]}},
        }
    )

    assert summary["readiness"] == {"handler": "httpGET /ready:8080", "timeoutSeconds": 2}
    assert summary["liveness"]["handler"] == "tcpSocket 9000"
    assert summary["startup"]["handler"].startswith("exec sh -c")
    assert _probe_summary({"name": "main"}) == {}


def test_configuration_lines_need_eligible_evidence() -> None:
    """No eligible observation means no claim about the target's settings."""
    results = [_lifecycle(_oom_container())]

    assert pipeline._observed_configuration_lines(results, set(), "en") == []
    assert pipeline._observed_configuration_lines(results, None, "en") == []


def test_configuration_line_skips_a_container_with_no_declared_resources() -> None:
    results = [_lifecycle({"name": "main", "state": {"phase": "running"}})]

    assert pipeline._observed_configuration_lines(results, {"E01"}, "en") == []


def test_image_pull_actions_check_the_observed_reference() -> None:
    container = {
        "name": "web",
        "image": "docker.io/library/ngink:1.25",
        "state": {"phase": "waiting", "reason": "ImagePullBackOff", "message": "back-off pulling"},
    }
    joined = _actions(container, "image_pull_error", "ImagePullBackOff", "imagepullbackoff")

    assert "crane manifest docker.io/library/ngink:1.25" in joined
    assert "crane ls docker.io/library/ngink" in joined
    assert "kubectl describe pod trainer-0 -n runai-team-a" in joined
    assert "<image:tag>" not in joined and "<repo>" not in joined
