"""An operator must read the observed numbers, not a placeholder."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from app.collectors.base import CollectorResult, artifact, resolve_target
from app.collectors.kubernetes import (
    _container_diagnostics,
    _node_condition_artifacts,
    _pod_scheduling_artifact,
    _runai_allocation,
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


# Verbatim from a live Run:ai 2.26 cluster (super-agg-ingress-0-vllmworker,
# a Grove PodClique-owned vLLM worker): the scheduler's own accounting.
_LIVE_RUNAI_ANNOTATIONS = {
    "pod-group-name": "pg-super-agg-ingress-0-vllmworker-j6f2l-49b17049",
    "received-resource-type": "Regular",
    "runai-allocated-gpu-memory": "343597",
    "runai-allocated-gpus": "4",
    "runai-calculated-status": "Running",
    "runai-current-allocated-gpus": "4",
    "runai-current-allocated-gpus-memory": "343597",
    "runai-current-requested-gpus": "4",
    "runai-pending-pods": "0",
    "runai-podgroup-requested-gpus": "4",
    "runai-running-pods": "1",
    "runai-total-requested-gpus": "4",
    "runai-used-nodes": "dgx01",
    "cni.projectcalico.org/podIP": "10.33.94.191/32",
}


def test_runai_allocation_is_read_off_the_pod_annotations() -> None:
    """Request-vs-allocated needs no Run:ai API — the scheduler writes it here."""
    from app.collectors.kubernetes import _pod_summary

    allocation = _runai_allocation(_LIVE_RUNAI_ANNOTATIONS)
    assert allocation["requested_gpus"] == "4"
    assert allocation["allocated_gpus"] == "4"
    assert allocation["resource_type"] == "Regular"
    assert allocation["pending_pods"] == "0"
    # Unknown keys are ignored, never guessed at.
    assert "cni.projectcalico.org/podIP" not in allocation.values()

    summary = _pod_summary(
        {
            "metadata": {"name": "w-0", "annotations": _LIVE_RUNAI_ANNOTATIONS},
            "spec": {"containers": []},
            "status": {},
        }
    )
    assert summary["runai_allocation"]["allocated_gpus"] == "4"
    # No annotations at all -> the key is absent, not an empty dict.
    assert "runai_allocation" not in _pod_summary(
        {"metadata": {"name": "w-0"}, "spec": {}, "status": {}}
    )


def test_pending_gang_reports_allocated_against_requested() -> None:
    """The shape that answers "why is it pending": granted less than it asked."""
    pending = {
        **_LIVE_RUNAI_ANNOTATIONS,
        "runai-current-allocated-gpus": "0",
        "runai-pending-pods": "2",
        "runai-running-pods": "1",
        "runai-podgroup-requested-gpus": "12",
        "runai-calculated-status": "Pending",
    }
    scheduling = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_pod_scheduling",
        status="ok",
        confidence="high",
        summary="scheduling",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "resources": {"main": {"requests": {"nvidia.com/gpu": "4"}}},
            "runai_allocation": _runai_allocation(pending),
            "scheduler": "runai-scheduler-default",
            "condition": {"reason": "Unschedulable", "message": "0/3 nodes are available"},
        },
    )

    line = "\n".join(_configuration(scheduling))
    assert "Run:ai GPUs allocated/requested 0/4" in line
    assert "pod group requests 12" in line  # gang wants more than this Pod
    assert "gang 1 running / 2 pending" in line
    assert "resource type Regular" in line
    assert "Run:ai status Pending" in line
    assert "Run:ai GPU 할당/요청 0/4" in "\n".join(_configuration(scheduling, "ko"))


# Verbatim from a live fractional (shared-GPU) workload Pod. Note there is NO
# nvidia.com/gpu request anywhere in its spec — the slice exists only here.
_LIVE_FRACTION_ANNOTATIONS = {
    "gpu-fraction": "0.5",
    "gpu-fraction-num-devices": "1",
    "pod-group-name": "pg-fraction-0-74e237bd",
    "received-resource-type": "Fraction",
    "runai-allocated-gpu-memory": "21474",
    "runai-allocated-gpus": "0.5",
    "runai-allocated-mig-gpus": "0",
    "runai-calculated-status": "Running",
    "runai-nodepools": "default",
}


def test_fraction_workload_reports_its_slice() -> None:
    """A whole-GPU report would show nothing: there is no nvidia.com/gpu request."""
    allocation = _runai_allocation(_LIVE_FRACTION_ANNOTATIONS)
    assert allocation["allocated_gpus"] == "0.5"
    assert allocation["gpu_fraction"] == "0.5"
    assert allocation["resource_type"] == "Fraction"

    scheduling = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_pod_scheduling",
        status="ok",
        confidence="high",
        summary="scheduling",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            # cpu/memory only — exactly what a fraction Pod declares.
            "resources": {"main": {"requests": {"cpu": "50m", "memory": "52428800"}}},
            "runai_allocation": allocation,
            "condition": {"reason": "Unschedulable", "message": "0/2 nodes are available"},
        },
    )
    line = "\n".join(_configuration(scheduling))

    assert "Run:ai GPUs allocated 0.5" in line
    assert "GPU fraction 0.5" in line
    assert "× 1" not in line  # a single device adds no information
    assert "resource type Fraction" in line
    assert "Run:ai GPU 할당 0.5" in "\n".join(_configuration(scheduling, "ko"))


def test_fraction_pods_are_counted_against_node_gpus() -> None:
    """A node packed with half-GPU Pods used to report its GPUs as entirely free."""
    from app.collectors.kubernetes import _pod_gpu_request

    fraction_pod = {
        "metadata": {"annotations": _LIVE_FRACTION_ANNOTATIONS},
        "spec": {"containers": [{"resources": {"requests": {"cpu": "50m"}}}]},
    }
    quantity, invalid = _pod_gpu_request(fraction_pod)
    assert (float(quantity), invalid) == (0.5, 0)

    # A whole-GPU Pod declares both; it must not be counted twice.
    whole = {
        "metadata": {"annotations": {"runai-allocated-gpus": "4"}},
        "spec": {"containers": [{"resources": {"requests": {"nvidia.com/gpu": "4"}}}]},
    }
    assert float(_pod_gpu_request(whole)[0]) == 4.0

    # No Run:ai annotation at all stays zero.
    assert _pod_gpu_request({"spec": {"containers": [{}]}})[0] == 0


def test_set_resources_command_only_for_kinds_kubectl_can_patch() -> None:
    """A Grove/Run:ai Pod is CRD-owned; `kubectl set resources` fails on it."""
    facts = {
        "oom": "true",
        "container": "main",
        "memory_limit": "512Mi",
        "namespace": "runai-test1",
        "workload": "trainer",
    }

    builtin = memory_sizing_action({**facts, "workload_kind": "Deployment"}, "en")
    assert "kubectl -n runai-test1 set resources deployment/trainer" in builtin

    crd = memory_sizing_action({**facts, "workload_kind": "PodClique"}, "en")
    assert "set resources" not in crd  # the command kubectl would reject
    assert "kubectl edit -n runai-test1 podclique/trainer" in crd
    assert "512Mi → 1Gi" in crd  # the numbers still stand


def test_memory_request_in_raw_bytes_is_understood() -> None:
    """A live cluster wrote `memory: 419430400` — bytes, not a Mi suffix."""
    assert parse_memory("419430400") == 419430400
    assert format_memory(419430400) == "400Mi"
    # Displayed in the unit form only when it is exact.
    assert pipeline._resource_display("memory", "419430400") == "400Mi"
    assert pipeline._resource_display("memory", "1500000000") == "1500000000"
    assert pipeline._resource_display("cpu", "400") == "400"


def test_request_already_at_the_limit_is_not_told_to_change() -> None:
    action = memory_sizing_action(
        {"oom": "true", "container": "main", "memory_limit": "400Mi", "memory_request": "400Mi"},
        "en",
    )

    assert "400Mi → 800Mi" in action
    assert "stays at 400Mi" in action
    assert "400Mi → 400Mi" not in action


# Verbatim from `kubectl get queues.scheduling.run.ai -o yaml` on a live cluster.
_LIVE_QUEUE = {
    "metadata": {
        "name": "project-test-a",
        "labels": {
            "project": "project-test-a",
            "runai/department-name": "default",
            "run.ai/project-id": "1b3b0e46-088d-4080-b73e-5b7a995241ad",
        },
    },
    "spec": {
        "displayName": "project-test-a",
        "parentQueue": "q-4500000",
        "priority": 100,
        "resources": {
            "cpu": {"limit": -1, "overQuotaWeight": 1, "quota": -1},
            "gpu": {"limit": -1, "overQuotaWeight": 1, "quota": 1},
            "memory": {"limit": -1, "overQuotaWeight": 1, "quota": -1},
        },
    },
    "status": {
        "allocated": {"cpu": "16", "memory": "64G", "nvidia.com/gpu": "1"},
        "requested": {"cpu": "16", "memory": "64G", "nvidia.com/gpu": "1"},
    },
}


def test_queue_quota_summary_reads_the_measured_shape() -> None:
    from app.collectors.kubernetes import _queue_quota_summary

    summary = _queue_quota_summary(_LIVE_QUEUE)

    assert summary["gpu_quota"] == "1"
    assert summary["gpu_requested"] == "1"
    assert summary["gpu_allocated"] == "1"
    assert summary["gpu_over_quota_weight"] == "1"
    assert summary["department"] == "default"
    assert summary["parent_queue"] == "q-4500000"
    # -1 means unset: it must not be printed as a real ceiling of minus one GPU.
    assert "gpu_limit" not in summary


def test_quota_line_needs_an_unschedulable_observation() -> None:
    """Quota states the ceiling; only the pending Pod makes it relevant."""
    from app.collectors.kubernetes import _queue_quota_summary

    quota = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="runai_queue_quota",
        status="ok",
        confidence="medium",
        summary="quota",
        result={
            # Deliberately NOT scoped: reading a policy object proves nothing
            # about the incident window.
            "observation": {
                "polarity": "unknown",
                "coverage": "partial",
                "target_identity_verified": True,
            },
            **_queue_quota_summary(_LIVE_QUEUE),
        },
    )
    alone = CollectorResult(agent="kubernetes", status="ok", summary="k8s", artifacts=[quota])
    assign_evidence_ids([alone])
    assert pipeline._observed_configuration_lines([alone], {"E01"}, "en") == []

    scheduling = artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_pod_scheduling",
        status="ok",
        confidence="high",
        summary="scheduling",
        result={
            "observation": {
                "polarity": "present",
                "coverage": "scoped",
                "target_identity_verified": True,
            },
            "resources": {"main": {"requests": {"nvidia.com/gpu": "2"}}},
            "condition": {"reason": "Unschedulable", "message": "0/2 nodes are available"},
        },
    )
    both = CollectorResult(
        agent="kubernetes", status="ok", summary="k8s", artifacts=[scheduling, quota]
    )
    assign_evidence_ids([both])
    ids = {str(item.evidence_id) for item in both.artifacts}
    line = "\n".join(pipeline._observed_configuration_lines([both], ids, "en"))

    assert "Project quota (project-test-a)" in line
    assert "GPUs requested/quota 1/1" in line
    assert "over-quota weight 1" in line
    assert "hard limit" not in line  # -1 is unset, not a ceiling
    assert "프로젝트 quota" in "\n".join(pipeline._observed_configuration_lines([both], ids, "ko"))


def test_unknown_scheduling_reason_still_yields_the_artifact(caplog) -> None:
    """Run:ai's scheduler writes reasons kube-scheduler never does.

    An allowlist used to drop the whole artifact for those, taking the requests,
    quota and nodeSelector lines with it.
    """
    pod = {
        "metadata": {"name": "w-0", "namespace": "runai-test1"},
        "spec": {
            "schedulerName": "runai-scheduler-default",
            "containers": [{"name": "main", "resources": {"requests": {"nvidia.com/gpu": "4"}}}],
        },
        "status": {
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "BindingError",
                    "message": "failed to bind pod runai-test1/w-0 to node dgx01",
                }
            ]
        },
    }
    target = resolve_target({"namespace": "runai-test1", "pod": "w-0"}, {})

    with caplog.at_level("WARNING"):
        item = _pod_scheduling_artifact("kubernetes", make_settings(), target, pod)

    assert item is not None
    assert item.result["condition"]["reason"] == "bindingerror"
    # Reported verbatim, and the absence of a family mapping is diagnosable.
    assert "unmapped PodScheduled=False reason" in caplog.text
    line = "\n".join(_configuration(item))
    assert "nvidia.com/gpu 4" in line
    assert "scheduler runai-scheduler-default" in line


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


def _storage_claim(phase: str, *, blocking: bool) -> object:
    return artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_storage_claim",
        status="ok",
        confidence="high" if blocking else "low",
        summary="pvc",
        result={
            "observation": {
                "polarity": "present" if blocking else "unknown",
                "coverage": "scoped" if blocking else "partial",
                "target_identity_verified": True,
            },
            "claim": "data-0",
            "namespace": "runai-team-a",
            "phase": phase,
            "requested_storage": "100Gi",
            "storage_class": "fast-rwo",
            "access_modes": ["ReadWriteOnce"],
            "volume_mode": "Filesystem",
            **({"volume_name": "pvc-9f3a"} if phase == "Bound" else {}),
        },
    )


def test_pending_claim_reports_its_size_and_class() -> None:
    line = "\n".join(_configuration(_storage_claim("Pending", blocking=True)))

    assert "Storage claim (data-0)" in line
    assert "requested 100Gi" in line
    assert "storageClass fast-rwo" in line
    assert "ReadWriteOnce" in line and "phase Pending" in line
    assert "스토리지 클레임" in "\n".join(
        _configuration(_storage_claim("Pending", blocking=True), "ko")
    )


def test_bound_claim_needs_a_storage_event_to_be_printed() -> None:
    """A Bound claim is not blocked; a failed mount makes its spec relevant."""
    claim = _storage_claim("Bound", blocking=False)
    mount_failure = artifact(
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
                    "reason": "FailedMount",
                    "target_identity_verified": True,
                    "message": "Unable to attach or mount volumes: unmounted volumes=[data]",
                }
            ],
        },
    )

    quiet = CollectorResult(agent="kubernetes", status="ok", summary="k8s", artifacts=[claim])
    assign_evidence_ids([quiet])
    # Bound + no storage event: not this incident's subject.
    assert pipeline._observed_configuration_lines([quiet], {"E01"}, "en") == []

    noisy = CollectorResult(
        agent="kubernetes", status="ok", summary="k8s", artifacts=[claim, mount_failure]
    )
    assign_evidence_ids([noisy])
    ids = {str(item.evidence_id) for item in noisy.artifacts}
    line = "\n".join(pipeline._observed_configuration_lines([noisy], ids, "en"))
    assert "Storage claim (data-0)" in line and "PV pvc-9f3a" in line


def _gpu_snapshot(free: int, *, scoped: bool) -> object:
    return artifact(
        agent="kubernetes",
        source="kubernetes",
        type="kubernetes_node_gpu_resources",
        status="ok",
        confidence="high",
        summary="gpu snapshot",
        result={
            "observation": {
                "polarity": "present" if scoped else "unknown",
                "coverage": "scoped" if scoped else "partial",
            },
            "node": "dgx-01",
            "gpu_capacity": 8,
            "gpu_allocatable": 8,
            "gpu_requested": 8 - free,
            "gpu_estimated_free": free,
            "scheduled_non_terminal_pods": 4,
        },
    )


def test_gpu_exhaustion_reports_requested_against_available() -> None:
    """The comparison a pending GPU workload turns on."""
    line = "\n".join(_configuration(_gpu_snapshot(0, scoped=True)))

    assert "Node GPUs (dgx-01)" in line
    assert "free 0/8" in line
    assert "held by scheduled Pods 8" in line
    assert "여유 0/8" in "\n".join(_configuration(_gpu_snapshot(0, scoped=True), "ko"))

    # Free GPUs are never promoted, so they can never substantiate a shortage.
    assert _configuration(_gpu_snapshot(2, scoped=False)) == []


def test_configuration_lines_need_eligible_evidence() -> None:
    """No eligible observation means no claim about the target's settings."""
    results = [_lifecycle(_oom_container())]

    assert pipeline._observed_configuration_lines(results, set(), "en") == []
    assert pipeline._observed_configuration_lines(results, None, "en") == []


def test_storage_claim_collector_types_the_pod_s_own_claims(monkeypatch) -> None:
    """Identity needs no inference: the claim came out of this Pod's spec.volumes."""
    from app.collectors import kubernetes as k8s

    async def fake_read(settings, kind, **kwargs):  # noqa: ANN001, ANN202
        assert kind == "persistentvolumeclaims"
        assert kwargs["name"] == "data-0" and kwargs["namespace"] == "runai-team-a"
        return {
            "kind": kind,
            "error": None,
            "data": {
                "metadata": {"name": "data-0", "namespace": "runai-team-a"},
                "spec": {
                    "storageClassName": "fast-rwo",
                    "accessModes": ["ReadWriteOnce"],
                    "volumeMode": "Filesystem",
                    "resources": {"requests": {"storage": "100Gi"}},
                },
                "status": {"phase": "Pending"},
            },
        }

    monkeypatch.setattr(k8s, "k8s_read", fake_read)
    target = resolve_target({"namespace": "runai-team-a", "pod": "trainer-0"}, {})
    items = asyncio.run(
        k8s._storage_claim_artifacts(
            "kubernetes",
            make_settings(),
            target,
            ["data-0"],
            time_range={"start": "2026-07-30T02:00:00Z", "end": "2026-07-30T02:20:00Z"},
        )
    )

    assert len(items) == 1
    observation = items[0].result["observation"]
    # Firing + unbound: what the Pod is waiting on, so it is a scoped observation.
    assert observation["polarity"] == "present" and observation["coverage"] == "scoped"
    assert observation["target_identity_verified"] is True
    assert items[0].result["requested_storage"] == "100Gi"

    # A resolved incident is not explained by a claim that is unbound right now.
    resolved = replace(target, resolved_at="2026-07-30T03:00:00Z")
    historical = asyncio.run(
        k8s._storage_claim_artifacts(
            "kubernetes",
            make_settings(),
            resolved,
            ["data-0"],
            time_range={"start": "2026-07-30T02:00:00Z", "end": "2026-07-30T02:20:00Z"},
        )
    )
    assert historical[0].result["observation"]["polarity"] == "unknown"


def test_gpu_snapshot_promotes_only_live_exhaustion() -> None:
    from app.collectors import kubernetes as k8s

    def snapshot(free_gpus: int, **target_kwargs) -> dict:
        node = {
            "metadata": {"name": "dgx-01"},
            "status": {
                "capacity": {"nvidia.com/gpu": "8"},
                "allocatable": {"nvidia.com/gpu": "8"},
            },
        }
        pods = {
            "items": [
                {
                    "spec": {
                        "nodeName": "dgx-01",
                        "containers": [
                            {"resources": {"requests": {"nvidia.com/gpu": str(8 - free_gpus)}}}
                        ],
                    },
                    "status": {"phase": "Running"},
                }
            ]
        }
        return {"node": node, "pods": pods, "target_kwargs": target_kwargs}

    async def run(free_gpus: int, **target_kwargs) -> dict:
        async def fake_read(settings, kind, **kwargs):  # noqa: ANN001, ANN202
            data = snapshot(free_gpus)["node" if kind == "nodes" else "pods"]
            return {"kind": kind, "error": None, "data": data, "url": "", "status_code": 200}

        import unittest.mock

        target = replace(
            resolve_target({"namespace": "runai-team-a", "node": "dgx-01"}, {}),
            fired_at="2026-07-30T02:00:00Z",
            **target_kwargs,
        )
        with unittest.mock.patch.object(k8s, "k8s_read", fake_read):
            snapshots = await k8s._collect_gpu_node_resource_observations(
                make_settings(),
                target,
                pipeline.InvestigationPlan(
                    hypotheses=[
                        {
                            "family": "k8s_scheduling_error",
                            "reason": "FailedScheduling: Insufficient nvidia.com/gpu",
                        }
                    ]
                ),
                [
                    {
                        "reason": "FailedScheduling",
                        "message": "Insufficient nvidia.com/gpu on node dgx-01",
                        "target_identity_verified": True,
                    }
                ],
            )
        return snapshots[0]

    exhausted = asyncio.run(run(0))
    assert exhausted["gpu_estimated_free"] == 0
    assert exhausted["observation"]["polarity"] == "present"
    assert exhausted["observation"]["coverage"] == "scoped"
    assert exhausted["snapshot_role"] == "live_incident"

    # GPUs still free -> a sampled snapshot, never support for a shortage.
    spare = asyncio.run(run(2))
    assert spare["observation"]["polarity"] == "unknown"
    assert spare["snapshot_role"] == "current_context"

    # Exhausted now cannot explain an incident that already ended.
    historical = asyncio.run(run(0, resolved_at="2026-07-30T03:00:00Z"))
    assert historical["observation"]["polarity"] == "unknown"


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
