from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    # Immutable identity supplied explicitly by alert metadata. It is not
    # inferred from a generic ``uid`` field or from resource text.
    pod_uid: str = ""
    # Provenance for ``node``. The pipeline can enrich it from a live Pod; old
    # node logs from that inferred location are useful context, not proof about
    # a historical alert unless Alertmanager named the node itself.
    node_source: str = ""


_INCIDENT_PRELUDE = timedelta(minutes=5)
_INCIDENT_EPILOGUE = timedelta(minutes=5)
_FIRING_INCIDENT_DURATION = timedelta(minutes=15)


def incident_time_range(target: AnalysisTarget) -> dict[str, str] | None:
    """Return the bounded evidence window for an alert, in UTC RFC3339.

    Every historical collector must use the same range: five minutes before the
    alert through five minutes after resolution. A firing alert has no reliable
    end, so it is deliberately capped instead of querying from its start through
    the present (which would mix unrelated current-state evidence into the RCA).
    """
    fired = _parse_incident_time(target.fired_at)
    if fired is None:
        return None
    resolved = _parse_incident_time(target.resolved_at)
    if resolved is None or resolved < fired:
        resolved = fired + _FIRING_INCIDENT_DURATION
    return {
        "start": _format_incident_time(fired - _INCIDENT_PRELUDE),
        "end": _format_incident_time(resolved + _INCIDENT_EPILOGUE),
    }


def parse_incident_time(value: object) -> datetime | None:
    """Parse a Kubernetes/Alertmanager timestamp without accepting local time."""
    return _parse_incident_time(str(value or ""))


def _parse_incident_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_incident_time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


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


def target_identifier_from(labels: dict[str, str], annotations: dict[str, str], *keys: str) -> str:
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

_BOOLEAN_CONDITION_TYPES = frozenset(
    {"diskpressure", "memorypressure", "pidpressure", "networkunavailable"}
)


def _truthy_status(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"true", "1", "yes", "active", "firing"}


def _sample_values(value: Any) -> list[float]:
    values: list[float] = []

    def collect(node: Any) -> None:
        if isinstance(node, (list, tuple)):
            if len(node) == 2 and not isinstance(node[1], (list, tuple, dict)):
                try:
                    values.append(float(node[1]))
                except (TypeError, ValueError):
                    pass
                return
            for child in node:
                collect(child)

    collect(value)
    return values


def condition_observations(value: Any, *, limit: int = 20) -> list[dict[str, Any]]:
    """Extract explicit condition polarity from Kubernetes and Prometheus evidence."""
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, bool, str]] = set()

    def add(condition: str, active: bool, source: str, **extra: Any) -> None:
        key = (condition.lower(), active, source)
        if key in seen or len(observations) >= limit:
            return
        seen.add(key)
        observations.append(
            {"condition": condition, "active": active, "source": source, **extra}
        )

    def walk(node: Any) -> None:
        if len(observations) >= limit:
            return
        if isinstance(node, dict):
            condition_type = str(node.get("type") or "").strip()
            if condition_type.lower() in _BOOLEAN_CONDITION_TYPES and "status" in node:
                status = str(node.get("status") or "")
                add(condition_type, _truthy_status(status), "kubernetes_condition", status=status)
                return

            metric = node.get("metric")
            samples = _sample_values(node.get("value") or node.get("values"))
            if isinstance(metric, dict) and samples:
                condition = str(metric.get("condition") or metric.get("type") or "").strip()
                if condition.lower() in _BOOLEAN_CONDITION_TYPES:
                    metric_status = str(metric.get("status") or "").strip()
                    active = _truthy_status(metric_status) and any(sample > 0 for sample in samples)
                    add(
                        condition,
                        active,
                        "prometheus_condition",
                        metric_status=metric_status,
                        sample=max(samples),
                    )
                    return
            for child in node.values():
                walk(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                walk(child)

    walk(value)
    return observations


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
            condition_type = str(node.get("type") or "").strip()
            if condition_type.lower() in _BOOLEAN_CONDITION_TYPES and "status" in node:
                if _truthy_status(node.get("status")):
                    _scan(condition_type)
                return

            metric = node.get("metric")
            samples = _sample_values(node.get("value") or node.get("values"))
            if isinstance(metric, dict) and samples:
                condition = str(metric.get("condition") or metric.get("type") or "").strip()
                metric_status = str(metric.get("status") or "").strip()
                active_sample = any(sample > 0 for sample in samples)
                if condition.lower() in _BOOLEAN_CONDITION_TYPES:
                    if _truthy_status(metric_status) and active_sample:
                        _scan(condition)
                elif active_sample:
                    _scan(metric)
                for key, child in node.items():
                    if key not in {"metric", "value", "values"}:
                        _scan(child)
                return
            for child in node.values():
                _scan(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                _scan(child)

    _scan(value)
    return found


def kubernetes_salient_markers(value: Any, *, limit: int = 6) -> list[str]:
    """Extract K8s highlights only from observed status/Event structures.

    A full Pod YAML contains configuration such as
    ``spec.preemptionPolicy=PreemptLowerPriority``.  That is not evidence that
    preemption occurred.  Keep highlights constrained to Warning Events, active
    Node conditions, and container runtime states (terminated/waiting), rather
    than keyword-scanning arbitrary spec/metadata leaf values.
    """
    found: list[str] = []
    seen: set[str] = set()

    def add_text(text: object) -> None:
        for marker in salient_markers(str(text or ""), limit=limit):
            key = marker.casefold()
            if key not in seen and len(found) < limit:
                seen.add(key)
                found.append(marker)

    def walk(node: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        condition_type = str(node.get("type") or "")
        if condition_type.casefold() in _BOOLEAN_CONDITION_TYPES and "status" in node:
            if _truthy_status(node.get("status")):
                add_text(condition_type)
            return
        # A Kubernetes Event's reason/message is an observation, but only a
        # Warning is relevant for failure highlights.
        if str(node.get("type") or "") == "Warning" and "involvedObject" in node:
            add_text(node.get("reason"))
            add_text(node.get("message"))
        # Container runtime states carry actual observed reasons. Pod spec,
        # labels, annotations, environment values and policy fields do not.
        for state_key in ("terminated", "waiting"):
            state = node.get(state_key)
            if isinstance(state, dict):
                add_text(state.get("reason"))
                add_text(state.get("message"))
        for key in (
            "status",
            "state",
            "lastState",
            "conditions",
            "containerStatuses",
            "initContainerStatuses",
            "ephemeralContainerStatuses",
            "events",
            "items",
            # Kubernetes MCP response envelopes retain the raw object below
            # these keys. They are not arbitrary user data; recurse so the
            # same status-only rule applies to direct and MCP-backed reads.
            "data",
            "object",
        ):
            child = node.get(key)
            if child is not None:
                walk(child)

    walk(value)
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

_WORKLOAD_KIND_TYPES = {
    "daemonset": "DaemonSet",
    "deployment": "Deployment",
    "statefulset": "StatefulSet",
    "replicaset": "ReplicaSet",
    "cronjob": "CronJob",
    "job_name": "Job",
}


def _workload_kind_identity(labels: dict[str, str], annotations: dict[str, str]) -> tuple[str, str]:
    for key in _WORKLOAD_KIND_LABELS:
        value = value_from(labels, annotations, key)
        if value:
            return value, _WORKLOAD_KIND_TYPES[key]
    return "", ""


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
    workload_kind_name, inferred_workload_type = _workload_kind_identity(labels, annotations)
    explicit_workload_name = value_from(
        labels, annotations, "workload", "workload_name", "runai_workload_name"
    )
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
        workload_name=(
            explicit_workload_name or workload_kind_name or value_from(labels, annotations, "pod")
        ),
        workload_type=(
            value_from(labels, annotations, "workload_type", "kind", "runai_workload_type")
            # Infer a Kubernetes controller kind only when that controller label
            # supplied the workload identity. An explicit Run:ai workload name
            # may coexist with a lower-level Deployment label and must keep its
            # own type/identity.
            or (inferred_workload_type if not explicit_workload_name else "")
        ),
        runai_workload_id=value_from(labels, annotations, "runai_workload_id", "workload_id"),
        node=value_from(labels, annotations, "node", "node_name", "kubernetes_node"),
        pod=pod,
        severity=value_from(labels, annotations, "severity") or "warning",
        alert_name=value_from(labels, annotations, "alertname", "alert_name") or "RunAIAlert",
        fired_at=fired_at,
        resolved_at=resolved_at,
        node_source=(
            "alert"
            if value_from(labels, annotations, "node", "node_name", "kubernetes_node")
            else ""
        ),
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
        pod_uid=target_identifier_from(
            labels,
            annotations,
            "pod_uid",
            "podUid",
            "kubernetes_pod_uid",
            "k8s_pod_uid",
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
