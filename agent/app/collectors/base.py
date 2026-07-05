from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.schemas import AlertAnalysisArtifact

# Honest gap marker: every collector uses this (optionally + a short reason) when
# it has no matching evidence — unconfigured, reachable-but-empty, or scoped out.
# The synthesis surfaces it verbatim so an operator sees where evidence is missing
# rather than a confident-but-empty summary. Always this Korean phrase — the system
# is deployed in Korean (settings.language defaults to "ko"); not language-switched.
NO_EVIDENCE = "증거를 찾기 어렵습니다."


@dataclass(frozen=True)
class AnalysisTarget:
    cluster: str
    project: str
    queue: str
    namespace: str
    workload_name: str
    workload_type: str
    runai_workload_id: str
    node: str
    pod: str
    severity: str
    alert_name: str


@dataclass
class CollectorResult:
    agent: str
    status: str
    summary: str
    confidence: str = "low"
    details: dict[str, Any] = field(default_factory=dict)
    missing_data: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    artifacts: list[AlertAnalysisArtifact] = field(default_factory=list)


def value_from(labels: dict[str, str], annotations: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = labels.get(key) or annotations.get(key)
        if value:
            return value
    return ""


# Problem signals worth pulling out of raw evidence so the operator sees the
# finding, not "HTTP 200". Deliberately specific (CamelCase reasons, kernel/GPU
# markers, phrases) — a bare lowercase "error"/"failed" would light up every
# JSON blob that merely HAS an error field.
SALIENT_PATTERN = re.compile(
    r"(CrashLoopBackOff|OOMKill(?:ed|ing)?|ImagePullBackOff|ErrImagePull(?:BackOff)?|"
    r"ErrImageNeverPull|CreateContainerConfigError|CreateContainerError|RunContainerError|"
    r"ContainerCannotRun|FailedScheduling|FailedMount|FailedAttachVolume|FailedCreate|"
    r"Unschedulable|Evicted|Preempt(?:ed|ion|or)?|[Rr]eclaim(?:ed|ing)?|NotReady|"
    r"DiskPressure|MemoryPressure|PIDPressure|NetworkUnavailable|Unhealthy|"
    r"Back-?[Oo]ff restarting|startup probe failed|liveness probe failed|"
    r"readiness probe failed|Xid\s*[:=]?\s*\d+|NVRM|NCCL\s+WARN|fell off the bus|"
    r"no space left|read-?only file ?system|connection refused|permission denied|"
    r"[Uu]nauthorized|[Ff]orbidden|panic:|segfault|out of memory|deadline exceeded|"
    r"context canceled|exit code \d+|Terminated|CUDA(?:_ERROR)?[ _][A-Za-z_]+)"
)


def salient_markers(value: Any, *, limit: int = 6) -> list[str]:
    """Distinct problem signals found in the STRING LEAVES of raw evidence.

    Walks dicts/lists and scans only leaf strings, so JSON keys ("error": null)
    and non-string values never false-match. Order of first appearance, deduped
    case-insensitively, capped at `limit` — meant for artifact highlights and
    finding-first summaries."""
    found: list[str] = []
    seen: set[str] = set()

    def _scan(node: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, str):
            for match in SALIENT_PATTERN.findall(node):
                key = match.lower().strip()
                if key and key not in seen:
                    seen.add(key)
                    found.append(match.strip())
                    if len(found) >= limit:
                        return
        elif isinstance(node, dict):
            for child in node.values():
                _scan(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                _scan(child)

    _scan(value)
    return found


def project_from_namespace(namespace: str) -> str:
    prefix = "runai-"
    return namespace[len(prefix) :] if namespace.startswith(prefix) else ""


def normalize_project_name(value: str) -> str:
    return project_from_namespace(value) or value


def resolve_target(labels: dict[str, str], annotations: dict[str, str]) -> AnalysisTarget:
    namespace = value_from(labels, annotations, "namespace", "kubernetes_namespace")
    project = value_from(labels, annotations, "project", "runai_project", "runai.io/project")
    return AnalysisTarget(
        cluster=value_from(labels, annotations, "cluster", "runai_cluster", "runai.io/cluster"),
        project=normalize_project_name(project) if project else project_from_namespace(namespace),
        queue=value_from(labels, annotations, "queue", "runai_queue", "runai.io/queue"),
        namespace=namespace,
        workload_name=value_from(
            labels,
            annotations,
            "workload",
            "workload_name",
            "runai_workload_name",
            "pod",
            "job_name",
        ),
        workload_type=value_from(
            labels, annotations, "workload_type", "kind", "runai_workload_type"
        ),
        runai_workload_id=value_from(labels, annotations, "runai_workload_id", "workload_id"),
        node=value_from(labels, annotations, "node", "node_name", "kubernetes_node"),
        pod=value_from(labels, annotations, "pod", "pod_name", "kubernetes_pod_name"),
        severity=value_from(labels, annotations, "severity") or "warning",
        alert_name=value_from(labels, annotations, "alertname", "alert_name") or "RunAIAlert",
    )


def artifact(
    *,
    agent: str,
    source: str,
    type: str,
    status: str,
    confidence: str,
    summary: str,
    query: str | None = None,
    result: dict[str, Any] | list[Any] | str | None = None,
    title: str | None = None,
    highlights: list[str] | None = None,
) -> AlertAnalysisArtifact:
    return AlertAnalysisArtifact(
        agent=agent,
        source=source,
        type=type,
        status=status,
        confidence=confidence,
        query=query,
        result=result,
        summary=summary,
        title=title,
        highlights=highlights,
    )
