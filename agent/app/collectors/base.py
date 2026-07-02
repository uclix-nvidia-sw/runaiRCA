from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.schemas import AlertAnalysisArtifact

# Honest gap marker: every collector uses this (optionally + a short reason) when
# it has no matching evidence — unconfigured, reachable-but-empty, or scoped out.
# The synthesis surfaces it verbatim so an operator sees where evidence is missing
# rather than a confident-but-empty summary. Korean per settings.language == "ko".
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
    )
