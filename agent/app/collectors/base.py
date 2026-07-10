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


def ko_en(settings: Any, ko: str, en: str) -> str:
    """The reason text that follows NO_EVIDENCE, in the deployment language.

    These strings surface verbatim on the evidence cards; a Korean deployment
    was showing '증거를 찾기 어렵습니다. Prometheus is reachable, but …'."""
    return ko if getattr(settings, "language", "en") == "ko" else en


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
    fired_at: str = ""
    resolved_at: str = ""
    # Optional resource identities are intentionally separate from the workload
    # target.  A PVC or Service alert often has no affected pod yet, and using a
    # broad namespace query in its place makes an executable runbook probe both
    # noisier and less trustworthy.  Keep these at the end with defaults so
    # existing positional callers remain compatible.
    service: str = ""
    component: str = ""
    storage_claim: str = ""
    volume: str = ""


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


def target_identifier_from(
    labels: dict[str, str], annotations: dict[str, str], *keys: str
) -> str:
    """Return an alert-declared resource identifier safe for probe substitution.

    These values are passed through to Kubernetes and query tools.  They are not
    inferred from prose or evidence, and a control character/template marker is
    rejected rather than being allowed to alter a later query.  Normal resource
    names are otherwise left intact: different APIs permit different valid name
    shapes (for example a CSI volume handle need not look like a DNS label).
    """
    # Prefer any label over any annotation.  An annotation named ``component``
    # must not eclipse a label using the canonical Kubernetes spelling
    # ``app.kubernetes.io/component``.
    for metadata in (labels, annotations):
        for key in keys:
            raw = metadata.get(key)
            if raw is None:
                continue
            value = str(raw).strip()
            if not value or "{{" in value or "}}" in value:
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                continue
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
            from app.knowledge import _keyword_negated

            lowered = node.lower()
            for match in SALIENT_PATTERN.finditer(node):
                if _keyword_negated(lowered, match.start(), match.end()):
                    continue
                marker = match.group(0)
                key = marker.lower().strip()
                if key and key not in seen:
                    seen.add(key)
                    found.append(marker.strip())
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


def signals_line(markers: list[str], language: str = "en") -> str:
    """A finding-first 'signals' line with each marker bolded in the text itself.

    The emphasis lives in the evidence TEXT (markdown `**`), not a frontend-only
    colour, so it survives into the report, the Word export, and the raw JSON —
    the UI just renders the markdown. Empty markers -> empty string."""
    if not markers:
        return ""
    label = "주요 신호" if language == "ko" else "signals"
    return f"{label}: " + ", ".join(f"**{marker}**" for marker in markers)


# Namespaces that start with "runai-" but are NOT a Run:ai user project: the
# platform (runai-backend) and the RCA product's own namespace (runai-rca).
# Stripping "runai-" off these fabricated a bogus project ("backend"/"rca") that
# both mislabeled the UI and pulled the RCA toward a Run:ai-workload framing.
_NON_PROJECT_NAMESPACES = frozenset({"runai", "runai-backend", "runai-rca"})


def project_from_namespace(namespace: str) -> str:
    if namespace in _NON_PROJECT_NAMESPACES:
        return ""
    prefix = "runai-"
    return namespace[len(prefix) :] if namespace.startswith(prefix) else ""


def normalize_project_name(value: str) -> str:
    return project_from_namespace(value) or value


# kube-state-metrics names the failing object in a workload-KIND label
# (kube_daemonset_*{daemonset=…}, kube_deployment_*{deployment=…}, …). On those
# metric families the `pod` label is the KSM EXPORTER pod that served the metric,
# NOT a subject pod — so an alert like RunaiDaemonSetUnavailableOnNodes carries
# daemonset="runai-container-toolkit" (the real subject) alongside
# pod="prometheus-kube-state-metrics-…" (the exporter). We must read the subject
# from the workload-kind label, or the topology identity (component_for_target →
# GPU Operator depends_on chain) resolves to the exporter and the RCA misfires.
# NOTE: bare `job` is deliberately excluded — in Prometheus that is the SCRAPE
# job (e.g. job="kube-state-metrics"), not a Kubernetes Job; the Job object's KSM
# label is `job_name`.
_WORKLOAD_KIND_LABELS = (
    "daemonset",
    "deployment",
    "statefulset",
    "replicaset",
    "cronjob",
    "job_name",
)


def resolve_target(
    labels: dict[str, str],
    annotations: dict[str, str],
    *,
    fired_at: str = "",
    resolved_at: str = "",
) -> AnalysisTarget:
    namespace = value_from(labels, annotations, "namespace", "kubernetes_namespace")
    project = value_from(labels, annotations, "project", "runai_project", "runai.io/project")
    # If a workload-kind label named the subject, the `pod` label is the KSM
    # exporter — drop it so collectors discover the real workload's pods by name
    # instead of investigating the (healthy) metrics pod.
    workload_kind_name = value_from(labels, annotations, *_WORKLOAD_KIND_LABELS)
    pod = (
        ""
        if workload_kind_name
        else value_from(labels, annotations, "pod", "pod_name", "kubernetes_pod_name")
    )
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
            # KSM workload-kind labels name the real subject; consult them before
            # falling back to the `pod` label (which may be the exporter).
            *_WORKLOAD_KIND_LABELS,
            "pod",
        ),
        workload_type=value_from(
            labels, annotations, "workload_type", "kind", "runai_workload_type"
        ),
        runai_workload_id=value_from(labels, annotations, "runai_workload_id", "workload_id"),
        node=value_from(labels, annotations, "node", "node_name", "kubernetes_node"),
        pod=pod,
        severity=value_from(labels, annotations, "severity") or "warning",
        alert_name=value_from(labels, annotations, "alertname", "alert_name") or "RunAIAlert",
        fired_at=fired_at,
        resolved_at=resolved_at,
        # These are explicit alert metadata only.  In particular, do not guess
        # a Service/PVC from a workload or from free-form annotation prose.
        service=target_identifier_from(
            labels,
            annotations,
            "service",
            "service_name",
            "kubernetes_service",
            "k8s_service",
        ),
        component=target_identifier_from(
            labels,
            annotations,
            "component",
            "kubernetes_component",
            "app.kubernetes.io/component",
            "app_kubernetes_io_component",
        ),
        storage_claim=target_identifier_from(
            labels,
            annotations,
            "persistentvolumeclaim",
            "persistent_volume_claim",
            "pvc",
            "claim_name",
            "volume_claim_name",
        ),
        volume=target_identifier_from(
            labels,
            annotations,
            "persistentvolume",
            "persistent_volume",
            "pv",
            "volume_name",
            "volume",
        ),
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
