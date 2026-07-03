from __future__ import annotations

import shlex
from pathlib import Path
from urllib.parse import quote

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import complete, llm_configured

# READ-ONLY diagnostic commands allowed inside a container via pods/exec.
# Strictly non-mutating: viewing GPU/driver/env state only. Anything not here is refused.
# ponytail: allowlist of exact argv prefixes, extend here if new read-only probes are needed.
_EXEC_ALLOWLIST: tuple[tuple[str, ...], ...] = (
    ("nvidia-smi",),
    ("nvidia-smi", "-q"),
    ("nvidia-smi", "-L"),
    ("nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv"),
    ("cat", "/proc/driver/nvidia/version"),
    ("env",),
    ("nproc",),
    ("uptime",),
)
# Never allow these regardless of the allowlist (defence in depth against a bad edit above).
_EXEC_FORBIDDEN_TOKENS: frozenset[str] = frozenset(
    {
        ";", "&&", "||", "|", ">", ">>", "<", "`", "$(", "rm", "kill", "mv", "cp", "dd",
        "chmod", "chown", "reboot", "shutdown", "mkfs", "delete", "sh", "bash", "-c",
    }
)


def exec_command_allowed(argv: list[str]) -> bool:
    """True only for exact read-only allowlisted commands. Refuse everything else."""
    if not argv:
        return False
    if any(tok in _EXEC_FORBIDDEN_TOKENS for tok in argv):
        return False
    return tuple(argv) in _EXEC_ALLOWLIST


# "kubectl for the agent": read-only ad-hoc queries the investigation loop can run.
# kubectl is just a CLI over this same API, so nothing is lost by going direct —
# what was missing was FREEFORM querying beyond the collector's fixed set. Kind
# allowlist + GET/LIST-only by construction (secrets deliberately absent); RBAC
# (agent-rbac.yaml) is the second fence.
_READ_KINDS: dict[str, tuple[str, bool]] = {
    # kind -> (API prefix, namespaced)
    "pods": ("/api/v1", True),
    "events": ("/api/v1", True),
    "nodes": ("/api/v1", False),
    "namespaces": ("/api/v1", False),
    "services": ("/api/v1", True),
    "endpoints": ("/api/v1", True),
    "persistentvolumeclaims": ("/api/v1", True),
    "persistentvolumes": ("/api/v1", False),
    "configmaps": ("/api/v1", True),
    "resourcequotas": ("/api/v1", True),
    "deployments": ("/apis/apps/v1", True),
    "replicasets": ("/apis/apps/v1", True),
    "statefulsets": ("/apis/apps/v1", True),
    "daemonsets": ("/apis/apps/v1", True),
    "jobs": ("/apis/batch/v1", True),
    "cronjobs": ("/apis/batch/v1", True),
    "storageclasses": ("/apis/storage.k8s.io/v1", False),
}
_KIND_ALIASES = {
    "po": "pods", "pod": "pods",
    "no": "nodes", "node": "nodes",
    "event": "events",
    "ns": "namespaces", "namespace": "namespaces",
    "svc": "services", "service": "services",
    "ep": "endpoints", "endpoint": "endpoints",
    "pvc": "persistentvolumeclaims", "persistentvolumeclaim": "persistentvolumeclaims",
    "pv": "persistentvolumes", "persistentvolume": "persistentvolumes",
    "cm": "configmaps", "configmap": "configmaps",
    "quota": "resourcequotas", "resourcequota": "resourcequotas",
    "deploy": "deployments", "deployment": "deployments",
    "rs": "replicasets", "replicaset": "replicasets",
    "sts": "statefulsets", "statefulset": "statefulsets",
    "ds": "daemonsets", "daemonset": "daemonsets",
    "job": "jobs", "cronjob": "cronjobs",
    "sc": "storageclasses", "storageclass": "storageclasses",
}


def resolve_read_kind(kind: str) -> str | None:
    """Canonical allowlisted kind for a kubectl-style name/alias, None if refused."""
    normalized = (kind or "").strip().lower()
    if normalized in _READ_KINDS:
        return normalized
    return _KIND_ALIASES.get(normalized)


async def k8s_read(
    settings: Settings,
    kind: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
) -> dict:
    """One read-only GET/LIST against the Kubernetes API, kubectl-style.

    Never raises; returns {kind, namespace, name, url, status_code, error, data}
    so the investigation loop can treat any failure as an observation."""
    resolved = resolve_read_kind(kind)
    if not resolved:
        return {
            "kind": kind,
            "error": "kind is not in the read-only allowlist",
            "allowed_kinds": sorted(_READ_KINDS),
        }
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {"kind": resolved, "error": "kubernetes service account token unavailable"}
    prefix, namespaced = _READ_KINDS[resolved]
    parts = [prefix.rstrip("/")]
    if namespaced and namespace:
        parts += ["namespaces", quote(namespace)]
    parts.append(resolved)
    if name:
        parts.append(quote(name))
    path = "/".join(parts)
    params: dict[str, str] = {}
    if not name:
        params["limit"] = str(settings.kubernetes_list_limit)
        if label_selector:
            params["labelSelector"] = label_selector
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    response = await get_json(
        base_url=settings.kubernetes_api_url,
        path=path,
        timeout_seconds=settings.kubernetes_timeout_seconds,
        params=params or None,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
    )
    return {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "url": response.url,
        "status_code": response.status_code,
        "error": response.error,
        "data": compact(response.data, limit=8),
    }


class KubernetesCollector:
    name = "kubernetes"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:  # noqa: ANN001
        target = _scope_target(target, plan)
        missing: list[str] = []
        if not target.namespace:
            missing.append("kubernetes.namespace")
        if not target.pod and not target.workload_name and not target.node:
            missing.append("kubernetes.target")
        if target.namespace and not _namespace_allowed(self._settings, target.namespace):
            missing.append("kubernetes.namespace_scope")

        token = _read_file(self._settings.kubernetes_token_path)
        if not token:
            summary = f"{NO_EVIDENCE} Kubernetes service account token is not available."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                details={"kubernetes_api_url": self._settings.kubernetes_api_url},
                missing_data=missing + ["kubernetes.service_account_token"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="kubernetes",
                        type="cluster_api",
                        status="unavailable",
                        confidence="low",
                        query=None,
                        summary=summary,
                        result={"token_path": self._settings.kubernetes_token_path},
                    )
                ],
            )

        headers = {"Authorization": f"Bearer {token}"}
        verify: bool | str = (
            self._settings.kubernetes_ca_path
            if Path(self._settings.kubernetes_ca_path).exists()
            else True
        )
        responses = await _collect_kubernetes_responses(
            settings=self._settings,
            target=target,
            headers=headers,
            verify=verify,
            # Only sweep the Run:ai control-plane namespaces when the plan says this
            # alert implicates the control plane — mirrors the loki collector so a
            # node/GPU/workload alert stops always scraping runai/runai-backend.
            control_plane_in_scope=(plan.check_control_plane if plan is not None else True),
        )
        # Deeper, read-only inspection: container logs (always) and, when explicitly
        # enabled, allowlisted read-only exec probes. Both degrade gracefully.
        pod_summary_data = _target_pod_summary(responses)
        containers = _container_names(pod_summary_data)
        logs = await _collect_pod_logs(
            settings=self._settings,
            target=target,
            containers=containers,
            headers=headers,
            verify=verify,
        )
        exec_probes = await _collect_exec_probes(
            settings=self._settings,
            target=target,
            containers=containers,
            headers=headers,
            verify=verify,
        )
        container_diagnostics = _container_diagnostics(pod_summary_data)
        warnings = [
            f"Kubernetes {item['name']} query failed: {item['error']}"
            for item in responses
            if item.get("error")
        ]
        successful = [item for item in responses if not item.get("error")]
        pod_statuses = _pod_statuses(responses)
        warning_events = _warning_events(responses)
        node_conditions = _node_conditions(responses)
        runai_control_plane_pods = _runai_control_plane_pods(responses)
        runai_control_plane_events = _runai_control_plane_warning_events(responses)

        if successful and not missing:
            status = "ok"
            confidence = "high"
            summary = "Kubernetes API queries completed for the resolved alert target."
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = (
                "Kubernetes API is reachable, but the alert target is incomplete. "
                "Namespace, pod, workload, or node labels may be missing."
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} Kubernetes API direct queries failed."

        insight = await _senior_insight(
            self._settings,
            summary=summary,
            container_diagnostics=container_diagnostics,
            warning_events=warning_events,
            logs=logs,
            exec_probes=exec_probes,
        )

        details = {
            "kubernetes_api_url": self._settings.kubernetes_api_url,
            "kubernetes_namespaces": self._settings.kubernetes_namespaces,
            "kubernetes_cluster_scope_enabled": self._settings.kubernetes_cluster_scope_enabled,
            "namespace": target.namespace,
            "pod": target.pod,
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "node": target.node,
            "pod_statuses": pod_statuses,
            "container_diagnostics": container_diagnostics,
            "warning_events": warning_events,
            "node_conditions": node_conditions,
            "pod_logs": logs,
            "exec_probes": exec_probes,
            "runai_control_plane_pods": runai_control_plane_pods,
            "runai_control_plane_warning_events": runai_control_plane_events,
            "insight": insight,
            "queries": responses,
        }
        if insight:
            summary = f"{summary} {insight}"

        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=details,
            missing_data=missing,
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="cluster_api",
                    status=status,
                    confidence=confidence,
                    query="; ".join(item["path"] for item in responses),
                    summary=summary,
                    result=details,
                )
            ],
        )


async def _collect_kubernetes_responses(
    *,
    settings: Settings,
    target: AnalysisTarget,
    headers: dict[str, str],
    verify: bool | str,
    control_plane_in_scope: bool = True,
) -> list[dict[str, object]]:
    requests: list[tuple[str, str, dict[str, str] | None]] = []
    namespace = quote(target.namespace, safe="")
    target_namespace_allowed = _namespace_allowed(settings, target.namespace)
    if target.namespace and target_namespace_allowed and target.pod:
        pod = quote(target.pod, safe="")
        requests.append(("pod", f"/api/v1/namespaces/{namespace}/pods/{pod}", None))
        requests.append(
            (
                "pod_events",
                f"/api/v1/namespaces/{namespace}/events",
                _list_params(settings, {"fieldSelector": f"involvedObject.name={target.pod}"}),
            )
        )
    elif target.namespace and target_namespace_allowed:
        requests.append(
            ("namespace_pods", f"/api/v1/namespaces/{namespace}/pods", _list_params(settings))
        )
        requests.append(
            (
                "namespace_events",
                f"/api/v1/namespaces/{namespace}/events",
                _list_params(settings),
            )
        )
    if target.node and settings.kubernetes_cluster_scope_enabled:
        node = quote(target.node, safe="")
        requests.append(("node", f"/api/v1/nodes/{node}", None))
    for runai_namespace in settings.runai_log_namespaces if control_plane_in_scope else ():
        if not _namespace_allowed(settings, runai_namespace):
            continue
        namespace_name = quote(runai_namespace, safe="")
        requests.append(
            (
                f"runai_control_plane_pods:{runai_namespace}",
                f"/api/v1/namespaces/{namespace_name}/pods",
                _list_params(settings),
            )
        )
        requests.append(
            (
                f"runai_control_plane_events:{runai_namespace}",
                f"/api/v1/namespaces/{namespace_name}/events",
                _list_params(settings),
            )
        )

    responses: list[dict[str, object]] = []
    for name, path, params in requests:
        response = await get_json(
            base_url=settings.kubernetes_api_url,
            path=path,
            timeout_seconds=settings.kubernetes_timeout_seconds,
            params=params,
            headers=headers,
            verify=verify,
        )
        responses.append(
            {
                "name": name,
                "path": path,
                "url": response.url,
                "status_code": response.status_code,
                "error": response.error,
                "data": compact(_filter_kubernetes_data(name, response.data, target), limit=5),
            }
        )
    return responses


def _scope_target(target: AnalysisTarget, plan) -> AnalysisTarget:  # noqa: ANN001
    """Narrow the target using the plan when present; fall back to target as-is."""
    if plan is None:
        return target
    pod = getattr(plan, "pod", "") or target.pod
    node = getattr(plan, "node", "") or target.node
    workload = getattr(plan, "workload", "") or target.workload_name
    namespaces = getattr(plan, "namespaces", None) or []
    namespace = namespaces[0] if namespaces else target.namespace
    if (pod, node, workload, namespace) == (
        target.pod,
        target.node,
        target.workload_name,
        target.namespace,
    ):
        return target
    return AnalysisTarget(
        cluster=target.cluster,
        project=target.project,
        queue=target.queue,
        namespace=namespace,
        workload_name=workload,
        workload_type=target.workload_type,
        runai_workload_id=target.runai_workload_id,
        node=node,
        pod=pod,
        severity=target.severity,
        alert_name=target.alert_name,
    )


def _target_pod_summary(responses: list[dict[str, object]]) -> dict[str, object] | None:
    for response in responses:
        if response.get("name") == "pod":
            data = response.get("data")
            if isinstance(data, dict):
                return data
    return None


def _container_names(pod_summary: dict[str, object] | None) -> list[str]:
    if not pod_summary:
        return []
    statuses = pod_summary.get("containerStatuses")
    names: list[str] = []
    if isinstance(statuses, list):
        for item in statuses:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
    return names


def _container_diagnostics(pod_summary: dict[str, object] | None) -> list[dict[str, object]]:
    """Restart reasons + last-terminated detail — the 'describe'-level depth."""
    if not pod_summary:
        return []
    statuses = pod_summary.get("containerStatuses")
    if not isinstance(statuses, list):
        return []
    diagnostics: list[dict[str, object]] = []
    for item in statuses:
        if not isinstance(item, dict):
            continue
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        last_state = item.get("lastState") if isinstance(item.get("lastState"), dict) else {}
        diagnostics.append(
            {
                "name": item.get("name"),
                "ready": item.get("ready"),
                "restartCount": item.get("restartCount"),
                "started": item.get("started"),
                "state": _state_reason(state),
                "lastTerminated": _state_reason(last_state.get("terminated"))
                if isinstance(last_state.get("terminated"), dict)
                else None,
            }
        )
    return diagnostics


def _state_reason(state: object) -> dict[str, object] | None:
    if not isinstance(state, dict):
        return None
    for kind in ("waiting", "running", "terminated"):
        inner = state.get(kind)
        if isinstance(inner, dict):
            return {"phase": kind, **{k: inner.get(k) for k in
                                     ("reason", "message", "exitCode", "signal", "startedAt",
                                      "finishedAt") if inner.get(k) is not None}}
    # Already an inner state dict (e.g. terminated) passed directly.
    return {k: state.get(k) for k in ("reason", "message", "exitCode", "signal", "finishedAt")
            if state.get(k) is not None} or None


async def _collect_pod_logs(
    *,
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
    headers: dict[str, str],
    verify: bool | str,
) -> list[dict[str, object]]:
    """Fetch READ-ONLY container logs via the pods/log subresource (GET, plain text)."""
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    namespace = quote(target.namespace, safe="")
    pod = quote(target.pod, safe="")
    tail = str(settings.kubernetes_list_limit)
    # One request per container; if none discovered, let the API pick the default container.
    targets: list[str | None] = list(containers) if containers else [None]
    logs: list[dict[str, object]] = []
    for container in targets:
        params: dict[str, str] = {"tailLines": tail, "timestamps": "true"}
        if container:
            params["container"] = container
        path = f"/api/v1/namespaces/{namespace}/pods/{pod}/log"
        response = await get_json(
            base_url=settings.kubernetes_api_url,
            path=path,
            timeout_seconds=settings.kubernetes_timeout_seconds,
            params=params,
            headers=headers,
            verify=verify,
        )
        logs.append(
            {
                "container": container,
                "status_code": response.status_code,
                "error": response.error,
                "lines": _log_lines(response.data),
            }
        )
    return logs


def _log_lines(data: object) -> list[str]:
    # get_json wraps non-JSON text as {"body": <text>}; logs are plain text.
    text = ""
    if isinstance(data, dict) and isinstance(data.get("body"), str):
        text = data["body"]
    elif isinstance(data, str):
        text = data
    if not text:
        return []
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-40:]


async def _collect_exec_probes(
    *,
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
    headers: dict[str, str],
    verify: bool | str,
) -> list[dict[str, object]]:
    """Best-effort read-only exec probes, gated by enable_pod_exec + allowlist.

    ponytail: the K8s pods/exec subresource speaks SPDY/websocket streaming, which the
    httpx GET/POST helper here cannot drive. Rather than pull in a websocket dependency,
    we record the intended allowlisted probes and mark them unattempted. pods/log above
    already covers the user's stated need ("view container logs"). Upgrade path: swap in
    kubernetes-asyncio's WsApiClient (or aiohttp ws) if live exec output is required.
    """
    if not settings.enable_pod_exec:
        return []
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    probes: list[dict[str, object]] = []
    container = containers[0] if containers else None
    for command in _EXEC_ALLOWLIST:
        argv = list(command)
        allowed = exec_command_allowed(argv)
        probes.append(
            {
                "container": container,
                "command": shlex.join(argv),
                "allowed": allowed,
                # Not executed: streaming subresource unsupported by the httpx helper.
                "attempted": False,
                "reason": "read-only allowlisted"
                if allowed
                else "refused: not on read-only allowlist",
            }
        )
    return probes


async def _senior_insight(
    settings: Settings,
    *,
    summary: str,
    container_diagnostics: list[dict[str, object]],
    warning_events: list[object],
    logs: list[dict[str, object]],
    exec_probes: list[dict[str, object]],
) -> str:
    """One-line senior insight via the LLM; deterministic fallback when unconfigured."""
    restarts = [
        d for d in container_diagnostics if isinstance(d.get("restartCount"), int)
        and d["restartCount"] > 0
    ]
    log_error_lines = [
        line
        for entry in logs
        for line in entry.get("lines", [])
        if isinstance(line, str) and any(
            token in line.lower() for token in ("error", "fail", "oom", "cuda", "panic")
        )
    ]
    if not llm_configured(settings):
        parts: list[str] = []
        if restarts:
            names = ", ".join(str(d.get("name")) for d in restarts)
            parts.append(f"container restarts on {names}")
        if warning_events:
            parts.append(f"{len(warning_events)} warning event(s)")
        if log_error_lines:
            parts.append(f"{len(log_error_lines)} error line(s) in logs")
        return ("Deep inspection flags: " + "; ".join(parts) + ".") if parts else ""

    user = compact(
        {
            "summary": summary,
            "container_diagnostics": container_diagnostics,
            "warning_events": warning_events,
            "log_error_lines": log_error_lines[-10:],
            "exec_probes": exec_probes,
        },
        limit=8,
    )
    system = (
        "You are a senior Kubernetes SRE reporting a finding to a colleague. From this "
        "read-only pod inspection, write ONE (max two) sentence shaped: what you "
        "OBSERVED (restarts/events/log lines, with timestamps or counts when present) "
        "-> what it MEANS -> WHEN it started. Grounded ONLY in the given data; never "
        "invent. No preamble."
    )
    if getattr(settings, "language", "en") == "ko":
        system += " 한국어로 답하세요 (관찰한 것 → 의미 → 시작 시점)."
    insight = await complete(
        settings,
        system=system,
        user=str(user),
        max_tokens=160,
    )
    return insight or ""


def _namespace_allowed(settings: Settings, namespace: str) -> bool:
    if not namespace or not settings.kubernetes_namespaces:
        return True
    return namespace in settings.kubernetes_namespaces


def _list_params(
    settings: Settings,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    params = {"limit": str(settings.kubernetes_list_limit)}
    if extra:
        params.update(extra)
    return params


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _filter_kubernetes_data(name: str, data: object, target: AnalysisTarget) -> object:
    if not isinstance(data, dict):
        return data
    if name == "namespace_pods" and isinstance(data.get("items"), list):
        items = data["items"]
        if target.workload_name:
            items = [
                item
                for item in items
                if isinstance(item, dict)
                and target.workload_name in item.get("metadata", {}).get("name", "")
            ]
        return {"items": [_pod_summary(item) for item in items[:10] if isinstance(item, dict)]}
    if name.startswith("runai_control_plane_pods:") and isinstance(data.get("items"), list):
        return {
            "namespace": _response_namespace(name),
            "items": [_pod_summary(item) for item in data["items"][:20] if isinstance(item, dict)],
        }
    if name == "pod":
        return _pod_summary(data)
    if (
        name in {"pod_events", "namespace_events"}
        or name.startswith("runai_control_plane_events:")
    ) and isinstance(data.get("items"), list):
        events = [
            _event_summary(item)
            for item in data["items"]
            if isinstance(item, dict) and item.get("type") in {"Warning", "Normal"}
        ]
        warnings = [event for event in events if event.get("type") == "Warning"]
        return {"namespace": _response_namespace(name), "items": (warnings or events)[-10:]}
    if name == "node":
        return _node_summary(data)
    return data


def _pod_summary(pod: dict[str, object]) -> dict[str, object]:
    metadata = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
    status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
    spec = pod.get("spec") if isinstance(pod.get("spec"), dict) else {}
    containers = status.get("containerStatuses", [])
    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "phase": status.get("phase"),
        "nodeName": spec.get("nodeName"),
        "podIP": status.get("podIP"),
        "conditions": status.get("conditions", []),
        "containerStatuses": compact(containers, limit=5),
    }


def _event_summary(event: dict[str, object]) -> dict[str, object]:
    involved = event.get("involvedObject") if isinstance(event.get("involvedObject"), dict) else {}
    return {
        "type": event.get("type"),
        "reason": event.get("reason"),
        "message": event.get("message"),
        "count": event.get("count"),
        "lastTimestamp": event.get("lastTimestamp") or event.get("eventTime"),
        "object": involved.get("name"),
        "kind": involved.get("kind"),
    }


def _node_summary(node: dict[str, object]) -> dict[str, object]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    status = node.get("status") if isinstance(node.get("status"), dict) else {}
    return {
        "name": metadata.get("name"),
        "conditions": status.get("conditions", []),
        "capacity": status.get("capacity", {}),
        "allocatable": status.get("allocatable", {}),
    }


def _response_namespace(name: str) -> str | None:
    if ":" not in name:
        return None
    return name.split(":", 1)[1]


def _pod_statuses(responses: list[dict[str, object]]) -> list[object]:
    statuses: list[object] = []
    for response in responses:
        data = response.get("data")
        if not isinstance(data, dict):
            continue
        if response.get("name") == "pod":
            statuses.append(data)
        if response.get("name") == "namespace_pods":
            items = data.get("items")
            if isinstance(items, list):
                statuses.extend(items)
    return statuses


def _warning_events(responses: list[dict[str, object]]) -> list[object]:
    events: list[object] = []
    for response in responses:
        if response.get("name") not in {"pod_events", "namespace_events"}:
            continue
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            events.extend(item for item in data["items"] if isinstance(item, dict))
    return events


def _node_conditions(responses: list[dict[str, object]]) -> list[object]:
    for response in responses:
        if response.get("name") != "node":
            continue
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("conditions"), list):
            return data["conditions"]
    return []


def _runai_control_plane_pods(responses: list[dict[str, object]]) -> dict[str, list[object]]:
    pods: dict[str, list[object]] = {}
    for response in responses:
        name = response.get("name")
        if not isinstance(name, str) or not name.startswith("runai_control_plane_pods:"):
            continue
        namespace = _response_namespace(name) or "unknown"
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            pods[namespace] = [item for item in data["items"] if isinstance(item, dict)]
    return pods


def _runai_control_plane_warning_events(
    responses: list[dict[str, object]],
) -> dict[str, list[object]]:
    events: dict[str, list[object]] = {}
    for response in responses:
        name = response.get("name")
        if not isinstance(name, str) or not name.startswith("runai_control_plane_events:"):
            continue
        namespace = _response_namespace(name) or "unknown"
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            events[namespace] = [item for item in data["items"] if isinstance(item, dict)]
    return events
