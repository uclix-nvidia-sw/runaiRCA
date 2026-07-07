from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from urllib.parse import quote

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import complete, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
    mcp_tool_text,
)

# READ-ONLY diagnostic commands allowed inside a container via pods/exec.
# Strictly non-mutating: viewing GPU/driver/env state only. Anything not here is refused.
# ponytail: allowlist of exact argv prefixes, extend here if new read-only probes are needed.
_EXEC_ALLOWLIST: tuple[tuple[str, ...], ...] = (
    ("nvidia-smi",),
    ("nvidia-smi", "-q"),
    ("nvidia-smi", "-L"),
    ("nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv"),
    ("cat", "/proc/driver/nvidia/version"),
    ("nproc",),
    ("uptime",),
)
# Never allow these regardless of the allowlist (defence in depth against a bad edit above).
_EXEC_FORBIDDEN_TOKENS: frozenset[str] = frozenset(
    {
        ";",
        "&&",
        "||",
        "|",
        ">",
        ">>",
        "<",
        "`",
        "$(",
        "rm",
        "kill",
        "mv",
        "cp",
        "dd",
        "chmod",
        "chown",
        "reboot",
        "shutdown",
        "mkfs",
        "delete",
        "sh",
        "bash",
        "-c",
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
    "po": "pods",
    "pod": "pods",
    "no": "nodes",
    "node": "nodes",
    "event": "events",
    "ns": "namespaces",
    "namespace": "namespaces",
    "svc": "services",
    "service": "services",
    "ep": "endpoints",
    "endpoint": "endpoints",
    "pvc": "persistentvolumeclaims",
    "persistentvolumeclaim": "persistentvolumeclaims",
    "pv": "persistentvolumes",
    "persistentvolume": "persistentvolumes",
    "cm": "configmaps",
    "configmap": "configmaps",
    "quota": "resourcequotas",
    "resourcequota": "resourcequotas",
    "deploy": "deployments",
    "deployment": "deployments",
    "rs": "replicasets",
    "replicaset": "replicasets",
    "sts": "statefulsets",
    "statefulset": "statefulsets",
    "ds": "daemonsets",
    "daemonset": "daemonsets",
    "job": "jobs",
    "cronjob": "cronjobs",
    "sc": "storageclasses",
    "storageclass": "storageclasses",
}


def resolve_read_kind(kind: str) -> str | None:
    """Canonical allowlisted kind for a kubectl-style name/alias, None if refused."""
    normalized = (kind or "").strip().lower()
    if normalized in _READ_KINDS:
        return normalized
    return _KIND_ALIASES.get(normalized)


# Operator-facing Korean labels for the read kinds ("파드 조회" artifact titles).
_KIND_LABELS_KO = {
    "pods": "파드",
    "events": "이벤트",
    "nodes": "노드",
    "namespaces": "네임스페이스",
    "services": "서비스",
    "endpoints": "엔드포인트",
    "persistentvolumeclaims": "PVC",
    "persistentvolumes": "PV",
    "configmaps": "컨피그맵",
    "resourcequotas": "리소스쿼터",
    "deployments": "디플로이먼트",
    "replicasets": "레플리카셋",
    "statefulsets": "스테이트풀셋",
    "daemonsets": "데몬셋",
    "jobs": "잡",
    "cronjobs": "크론잡",
    "storageclasses": "스토리지클래스",
}


def kind_lookup_title(kind: str, language: str) -> str:
    """Human card title for a read of `kind` — "파드 조회" (ko) / "pods lookup" (en)."""
    resolved = resolve_read_kind(kind) or (kind or "resource")
    if language == "ko":
        return f"{_KIND_LABELS_KO.get(resolved, resolved)} 조회"
    return f"{resolved} lookup"


def kubectl_repr(kind: str, namespace: str = "", name: str = "", label_selector: str = "") -> str:
    """The read as the kubectl command an operator would have typed — artifacts
    show the REAL query shape ("kubectl get pods -n runai train-0"), not an
    internal param dump."""
    def quote_arg(value: str) -> str:
        return shlex.quote(" ".join(str(value).split()))

    parts = ["kubectl get", resolve_read_kind(kind) or quote_arg(kind)]
    if name:
        parts.append(quote_arg(name))
    if namespace:
        parts.append(f"-n {quote_arg(namespace)}")
    if label_selector:
        parts.append(f"-l {quote_arg(label_selector)}")
    return " ".join(parts)


async def k8s_read(
    settings: Settings,
    kind: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
) -> dict:
    """One read-only GET/LIST of a Kubernetes kind — MCP-first, direct fallback.

    THE transport-policy point: the flowchart follow-ups, the investigation
    loop, and the drill-down tool all read through here, so a configured
    Kubernetes MCP service is used by every read path, not just the base sweep.
    Never raises; returns {kind, namespace, name, url, status_code, error, data}
    so callers can treat any failure as an observation."""
    resolved = resolve_read_kind(kind)
    if not resolved:
        return {
            "kind": kind,
            "error": "kind is not in the read-only allowlist",
            "allowed_kinds": sorted(_READ_KINDS),
        }
    mcp_note = ""
    if settings.kubernetes_mcp_url:
        try:
            return await _k8s_read_via_mcp(
                settings, resolved, namespace=namespace, name=name, label_selector=label_selector
            )
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            mcp_note = mcp_fallback_warning(exc)
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {"kind": resolved, "error": "kubernetes service account token unavailable"}
    prefix, namespaced = _READ_KINDS[resolved]
    parts = [prefix.rstrip("/")]
    if namespaced and namespace:
        parts += ["namespaces", quote(namespace, safe="")]
    parts.append(resolved)
    if name:
        parts.append(quote(name, safe=""))
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
    result = {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "label_selector": label_selector,
        "url": response.url,
        "status_code": response.status_code,
        "error": response.error,
        "data": compact(response.data, limit=8),
    }
    if mcp_note:
        result["mcp_fallback"] = mcp_note
    return result


async def _k8s_read_via_mcp(
    settings: Settings,
    resolved: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
) -> dict:
    """k8s_read over the Kubernetes MCP server; same result shape, raises to fall back."""
    api_version, mcp_kind = _k8s_mcp_resource_kind(resolved)
    candidates: list[tuple[str, dict[str, object]]] = []
    if name:
        if resolved == "pods":
            candidates.extend(
                [
                    ("pods_get", {"namespace": namespace, "name": name}),
                    ("pods_get", {"namespace": namespace, "pod": name}),
                ]
            )
        candidates.extend(
            [
                (
                    "resources_get",
                    {
                        "apiVersion": api_version,
                        "kind": mcp_kind,
                        "namespace": namespace,
                        "name": name,
                    },
                ),
                ("resources_get", {"kind": resolved, "namespace": namespace, "name": name}),
            ]
        )
    else:
        # A requested label selector must ride on EVERY candidate — a shortcut
        # tool called without it would "succeed" with the unfiltered namespace
        # and silently drop the filter the caller asked for.
        if resolved == "pods":
            pod_args: dict[str, object] = {"namespace": namespace}
            if label_selector:
                pod_args["labelSelector"] = label_selector
            candidates.extend(
                [
                    ("pods_list_in_namespace", dict(pod_args)),
                    ("pods_list", dict(pod_args)),
                ]
            )
        elif resolved == "events" and not label_selector:
            candidates.append(("events_list", {"namespace": namespace}))
        args: dict[str, object] = {
            "apiVersion": api_version,
            "kind": mcp_kind,
            "namespace": namespace,
        }
        fallback_args: dict[str, object] = {"kind": resolved, "namespace": namespace}
        if label_selector:
            args["labelSelector"] = label_selector
            fallback_args["labelSelector"] = label_selector
        candidates.extend([("resources_list", args), ("resources_list", fallback_args)])
    data = await _k8s_mcp_json(settings, candidates)
    if not name and label_selector:
        # Belt and suspenders: an MCP server may ACCEPT labelSelector and still
        # ignore it — enforce equality selectors client-side.
        data = _apply_label_selector(data, label_selector)
    return {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "label_selector": label_selector,
        "url": f"{settings.kubernetes_mcp_url}#read_{resolved}",
        "status_code": 200,
        "error": None,
        "data": compact(data, limit=8),
    }


def _apply_label_selector(data: object, selector: str) -> object:
    """Filter a k8s list result by an EQUALITY label selector, client-side.

    ponytail: pure-equality terms only (a=b,c==d) — set-based/inequality
    selectors pass through untouched (the direct API fallback evaluates those
    exactly; MCP servers that honor the arg already filtered)."""
    terms: dict[str, str] = {}
    for part in selector.split(","):
        part = part.strip()
        if not part:
            continue
        if any(op in part for op in ("!=", "!", "(", " in ", " notin ")) or "=" not in part:
            return data  # not pure equality — leave the server's result as-is
        key, _, value = part.partition("==") if "==" in part else part.partition("=")
        key = key.strip()
        if not key:
            return data
        terms[key] = value.strip()
    items = data if isinstance(data, list) else None
    if items is None and isinstance(data, dict) and isinstance(data.get("items"), list):
        items = data["items"]
    if items is None or not terms:
        return data
    filtered = [
        item
        for item in items
        if isinstance(item, dict)
        and all(
            (((item.get("metadata") or {}).get("labels") or {}).get(key) == value)
            for key, value in terms.items()
        )
    ]
    return filtered if isinstance(data, list) else {**data, "items": filtered}


def _k8s_mcp_resource_kind(kind: str) -> tuple[str, str]:
    mapping = {
        "pods": ("v1", "Pod"),
        "events": ("v1", "Event"),
        "nodes": ("v1", "Node"),
        "namespaces": ("v1", "Namespace"),
        "services": ("v1", "Service"),
        "endpoints": ("v1", "Endpoints"),
        "persistentvolumeclaims": ("v1", "PersistentVolumeClaim"),
        "persistentvolumes": ("v1", "PersistentVolume"),
        "configmaps": ("v1", "ConfigMap"),
        "resourcequotas": ("v1", "ResourceQuota"),
        "deployments": ("apps/v1", "Deployment"),
        "replicasets": ("apps/v1", "ReplicaSet"),
        "statefulsets": ("apps/v1", "StatefulSet"),
        "daemonsets": ("apps/v1", "DaemonSet"),
        "jobs": ("batch/v1", "Job"),
        "cronjobs": ("batch/v1", "CronJob"),
        "storageclasses": ("storage.k8s.io/v1", "StorageClass"),
    }
    return mapping.get(kind, ("v1", kind))


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

        warnings: list[str] = []
        used_mcp = False
        control_plane_in_scope = plan.check_control_plane if plan is not None else True
        if self._settings.kubernetes_mcp_url:
            try:
                responses = await _collect_kubernetes_responses_via_mcp(
                    settings=self._settings,
                    target=target,
                    control_plane_in_scope=control_plane_in_scope,
                )
                pod_summary_data = _target_pod_summary(responses)
                containers = _container_names(pod_summary_data)
                logs = await _collect_pod_logs_via_mcp(
                    settings=self._settings,
                    target=target,
                    containers=containers,
                )
                exec_probes = []
                used_mcp = True
            except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
                warnings.append(mcp_fallback_warning(exc))
        else:
            warnings.append(f"{MCP_FALLBACK_WARNING}: KUBERNETES_MCP_URL not configured")

        if not used_mcp:
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
                    warnings=warnings,
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
                control_plane_in_scope=control_plane_in_scope,
            )
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
        warnings.extend(
            f"Kubernetes {item['name']} query failed: {item['error']}"
            for item in responses
            if item.get("error")
        )
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
            "kubernetes_mcp_url": self._settings.kubernetes_mcp_url,
            "used_mcp": used_mcp,
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


async def _collect_kubernetes_responses_via_mcp(
    *,
    settings: Settings,
    target: AnalysisTarget,
    control_plane_in_scope: bool = True,
) -> list[dict[str, object]]:
    responses: list[dict[str, object]] = []
    target_namespace_allowed = _namespace_allowed(settings, target.namespace)
    if target.namespace and target_namespace_allowed and target.pod:
        pod_data = await _k8s_mcp_json(
            settings,
            [
                ("pods_get", {"namespace": target.namespace, "name": target.pod}),
                ("pods_get", {"namespace": target.namespace, "pod": target.pod}),
                (
                    "resources_get",
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "namespace": target.namespace,
                        "name": target.pod,
                    },
                ),
            ],
        )
        responses.append(_mcp_k8s_response("pod", "MCP pods_get", pod_data, target))
        event_data = await _k8s_mcp_json(
            settings,
            [
                (
                    "events_list",
                    {
                        "namespace": target.namespace,
                        "fieldSelector": f"involvedObject.name={target.pod}",
                    },
                ),
                (
                    "resources_list",
                    {
                        "apiVersion": "v1",
                        "kind": "Event",
                        "namespace": target.namespace,
                        "fieldSelector": f"involvedObject.name={target.pod}",
                    },
                ),
            ],
        )
        responses.append(_mcp_k8s_response("pod_events", "MCP events_list", event_data, target))
    elif target.namespace and target_namespace_allowed:
        pod_data = await _k8s_mcp_json(
            settings,
            [
                ("pods_list_in_namespace", {"namespace": target.namespace}),
                ("pods_list", {"namespace": target.namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Pod", "namespace": target.namespace},
                ),
            ],
        )
        responses.append(
            _mcp_k8s_response("namespace_pods", "MCP pods_list", pod_data, target)
        )
        event_data = await _k8s_mcp_json(
            settings,
            [
                ("events_list", {"namespace": target.namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Event", "namespace": target.namespace},
                ),
            ],
        )
        responses.append(
            _mcp_k8s_response("namespace_events", "MCP events_list", event_data, target)
        )
    if target.node and settings.kubernetes_cluster_scope_enabled:
        node_data = await _k8s_mcp_json(
            settings,
            [
                (
                    "resources_get",
                    {"apiVersion": "v1", "kind": "Node", "name": target.node},
                ),
                ("resources_get", {"kind": "nodes", "name": target.node}),
            ],
        )
        responses.append(_mcp_k8s_response("node", "MCP resources_get node", node_data, target))
    for runai_namespace in settings.runai_log_namespaces if control_plane_in_scope else ():
        if not _namespace_allowed(settings, runai_namespace):
            continue
        pod_data = await _k8s_mcp_json(
            settings,
            [
                ("pods_list_in_namespace", {"namespace": runai_namespace}),
                ("pods_list", {"namespace": runai_namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Pod", "namespace": runai_namespace},
                ),
            ],
        )
        responses.append(
            _mcp_k8s_response(
                f"runai_control_plane_pods:{runai_namespace}",
                f"MCP pods_list {runai_namespace}",
                pod_data,
                target,
            )
        )
        event_data = await _k8s_mcp_json(
            settings,
            [
                ("events_list", {"namespace": runai_namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Event", "namespace": runai_namespace},
                ),
            ],
        )
        responses.append(
            _mcp_k8s_response(
                f"runai_control_plane_events:{runai_namespace}",
                f"MCP events_list {runai_namespace}",
                event_data,
                target,
            )
        )
    return responses


def _mcp_k8s_response(
    name: str, path: str, data: object, target: AnalysisTarget
) -> dict[str, object]:
    normalized = _normalize_k8s_payload(data)
    return {
        "name": name,
        "path": path,
        "url": path,
        "status_code": 200,
        "error": None,
        "data": compact(_filter_kubernetes_data(name, normalized, target), limit=5),
    }


def _normalize_k8s_payload(data: object) -> object:
    if isinstance(data, list):
        return {"items": data}
    if not isinstance(data, dict):
        return data
    for key in ("items", "metadata", "status"):
        if key in data:
            return data
    for key in ("resources", "result", "data"):
        value = data.get(key)
        if isinstance(value, list):
            return {"items": value}
        if isinstance(value, dict):
            return value
    return data


async def _k8s_mcp_json(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
) -> object:
    result = await _k8s_mcp_result(settings, candidates)
    data = mcp_tool_json(result)
    if isinstance(data, dict) and "raw" in data:
        raise RuntimeError("MCP result was not JSON")
    return data


async def _k8s_mcp_result(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
):
    last_error = ""
    for tool, args in candidates:
        try:
            result = await mcp_call(settings.kubernetes_mcp_url, tool, args)
        except Exception as exc:  # noqa: BLE001 - try the next schema candidate.
            last_error = f"{tool}: {exc.__class__.__name__}: {exc}"
            continue
        error = mcp_error(result)
        if error:
            last_error = f"{tool}: {error}"
            continue
        return result
    raise RuntimeError(last_error or "Kubernetes MCP tool failed")


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


def pod_name_stem(name: str) -> str:
    """'runai-container-toolkit-vttmr' -> 'runai-container-toolkit-'.

    Controllers recreate pods keeping everything but the RANDOM suffix (DaemonSet/
    ReplicaSet hash suffix); the stem is the stable identity. An all-digit suffix
    is a StatefulSet ordinal — that pod name is stable and a stem would match
    SIBLING replicas on other nodes, so no stem is returned for it."""
    name = name.strip()
    suffix = re.search(r"-([a-z0-9]{1,10})$", name)
    if not suffix or suffix.group(1).isdigit():
        return ""
    return name[: suffix.start() + 1]


def _pod_unhealthy(pod: dict) -> bool:
    """True when the pod looks like the subject of a firing alert (not clean)."""
    status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
    if status.get("phase") not in (None, "Running", "Succeeded"):
        return True
    for cs in status.get("containerStatuses") or []:
        if not isinstance(cs, dict):
            continue
        if (cs.get("restartCount") or 0) > 0:
            return True
        state = cs.get("state") if isinstance(cs.get("state"), dict) else {}
        waiting = state.get("waiting") if isinstance(state.get("waiting"), dict) else None
        if waiting and waiting.get("reason") not in (None, "", "ContainerCreating"):
            return True
    return False


def best_matching_pod(items: list[dict], stems: list[str]) -> dict | None:
    """The stem-matching pod that is most plausibly the alert's subject.

    Prefer UNHEALTHY matches: a crashlooping workload's replacement is unhealthy
    too, while e.g. a DaemonSet has healthy siblings on every OTHER node —
    newest-wins alone would happily pick one of those and attach node evidence
    to the wrong node. The preferred pool is only trusted when it is
    unambiguous: a single pod, or several pods all on the SAME node (successive
    incarnations). Unhealthy siblings spread across nodes cannot be attributed
    to the alert's pod — None; no evidence beats wrong-node evidence."""
    matches: list[tuple[str, dict]] = []
    for item in items:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = str(metadata.get("name") or "")
        if not name or not any(stem and name.startswith(stem) for stem in stems):
            continue
        matches.append((str(metadata.get("creationTimestamp") or ""), item))
    pool = [entry for entry in matches if _pod_unhealthy(entry[1])] or matches
    nodes = {
        str((entry[1].get("spec") or {}).get("nodeName") or "") for entry in pool
    }
    if pool and (len(pool) == 1 or len(nodes) == 1):
        return max(pool, key=lambda entry: entry[0])[1]
    return None


def node_from_pod_events(items: list[dict]) -> str:
    """The node a (possibly deleted) pod ran on, from ITS OWN events.

    kubelet-sourced events (BackOff, Unhealthy, Killing, ...) carry the node in
    `source.host`; the scheduler's Scheduled event names it in the message
    ("Successfully assigned ns/pod to <node>"). This attributes the node to the
    EXACT pod the alert named — precise even after the pod is gone."""
    for item in reversed(items):  # newest last; any hit is authoritative
        if not isinstance(item, dict):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        host = str(source.get("host") or "")
        if host:
            return host
        matched = re.search(r"[Aa]ssigned \S+ to (\S+)\s*$", str(item.get("message") or ""))
        if matched:
            return matched.group(1)
    return ""


async def resolve_live_pod_node(
    settings: Settings, namespace: str, pod: str, extra_pods: list[str] | None = None
) -> tuple[str, str]:
    """(live_pod, node) for the alert's pod; re-resolves recreated pods by name stem.

    Alert labels frequently name a pod the controller has already replaced
    (grouped CrashLoop occurrences) and carry no node label at all — so pod GETs
    404 and the system agent has no node to read. Resolution tiers:
    1. GET the named pod — exact.
    2. The DEAD pod's own events (node_from_pod_events) — exact node attribution
       even after deletion; beats any stem-match guess.
    3. Stem-match live siblings (best_matching_pod) — the live pod for k8s/log
       queries; its node only counts when unambiguous.
    Best-effort: ('', '') on any failure — callers keep their own fallbacks.
    """
    if not namespace or not pod:
        return "", ""
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return "", ""
    headers = {"Authorization": f"Bearer {token}"}
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    try:
        encoded_namespace = quote(namespace, safe="")
        encoded_pod = quote(pod, safe="")
        response = await get_json(
            base_url=settings.kubernetes_api_url,
            path=f"/api/v1/namespaces/{encoded_namespace}/pods/{encoded_pod}",
            timeout_seconds=settings.kubernetes_timeout_seconds,
            headers=headers,
            verify=verify,
        )
        if response.ok and isinstance(response.data, dict):
            spec = response.data.get("spec") or {}
            return pod, str(spec.get("nodeName") or "")

        names = [name for name in dict.fromkeys([pod, *(extra_pods or [])]) if name]
        event_node = ""
        for name in names[:3]:
            events = await get_json(
                base_url=settings.kubernetes_api_url,
                path=f"/api/v1/namespaces/{encoded_namespace}/events",
                timeout_seconds=settings.kubernetes_timeout_seconds,
                params=_list_params(
                    settings, {"fieldSelector": f"involvedObject.name={name}"}
                ),
                headers=headers,
                verify=verify,
            )
            if events.ok and isinstance(events.data, dict):
                event_node = node_from_pod_events(
                    [e for e in events.data.get("items") or [] if isinstance(e, dict)]
                )
                if event_node:
                    break

        listing = await get_json(
            base_url=settings.kubernetes_api_url,
            path=f"/api/v1/namespaces/{encoded_namespace}/pods",
            timeout_seconds=settings.kubernetes_timeout_seconds,
            params=_list_params(settings),
            headers=headers,
            verify=verify,
        )
        live_pod, live_node = "", ""
        if listing.ok and isinstance(listing.data, dict):
            items = [item for item in listing.data.get("items") or [] if isinstance(item, dict)]
            match = best_matching_pod(items, [pod_name_stem(name) for name in names])
            if match is not None:
                live_pod = str((match.get("metadata") or {}).get("name") or "")
                live_node = str((match.get("spec") or {}).get("nodeName") or "")
        # The dead pod's OWN node (from events) outranks a sibling's node.
        return live_pod, event_node or live_node
    except Exception:  # noqa: BLE001 - resolution is best-effort enrichment
        return "", ""


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
            return {
                "phase": kind,
                **{
                    k: inner.get(k)
                    for k in ("reason", "message", "exitCode", "signal", "startedAt", "finishedAt")
                    if inner.get(k) is not None
                },
            }
    # Already an inner state dict (e.g. terminated) passed directly.
    return {
        k: state.get(k)
        for k in ("reason", "message", "exitCode", "signal", "finishedAt")
        if state.get(k) is not None
    } or None


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


async def _collect_pod_logs_via_mcp(
    *,
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
) -> list[dict[str, object]]:
    """Fetch READ-ONLY container logs through the Kubernetes MCP server."""
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    targets: list[str | None] = list(containers) if containers else [None]
    logs: list[dict[str, object]] = []
    for container in targets:
        args: dict[str, object] = {
            "namespace": target.namespace,
            "name": target.pod,
            "tailLines": settings.kubernetes_list_limit,
        }
        if container:
            args["container"] = container
        candidates = [
            ("pods_log", args),
            (
                "pods_log",
                {
                    **args,
                    "pod": target.pod,
                },
            ),
        ]
        result = await _k8s_mcp_result(settings, candidates)
        text = mcp_tool_text(result)
        data = mcp_tool_json(result)
        lines = _log_lines(text or data)
        logs.append(
            {
                "container": container,
                "status_code": 200,
                "error": None,
                "lines": lines,
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
        d
        for d in container_diagnostics
        if isinstance(d.get("restartCount"), int) and d["restartCount"] > 0
    ]
    log_error_lines = [
        line
        for entry in logs
        for line in entry.get("lines", [])
        if isinstance(line, str)
        and any(token in line.lower() for token in ("error", "fail", "oom", "cuda", "panic"))
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
        user=_collector_masker(settings).mask_text(str(user)),
        max_tokens=160,
    )
    return _collector_masker(settings).mask_text(insight or "")


def _collector_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


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
        name in {"pod_events", "namespace_events"} or name.startswith("runai_control_plane_events:")
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
    # Per-container limits/requests — the `kubectl describe` fact an operator
    # reaches for first on a memory/CPU-limit alert.
    resources: dict[str, object] = {}
    for container in spec.get("containers", []) if isinstance(spec.get("containers"), list) else []:
        if isinstance(container, dict) and isinstance(container.get("name"), str):
            resources[container["name"]] = container.get("resources") or {}
    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "phase": status.get("phase"),
        "nodeName": spec.get("nodeName"),
        "podIP": status.get("podIP"),
        "conditions": status.get("conditions", []),
        "containerStatuses": compact(containers, limit=5),
        "resources": resources,
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


# --- Deterministic flowchart-driven follow-up ---------------------------------
# The learnk8s debug flowchart as CODE: given what the collector found, keep
# pulling the evidence a human would next check. Runs with OR without the LLM
# investigation loop, so evidence collection stays iterative even when the LLM
# (litellm) is unavailable — which is exactly when the ReAct loop is skipped.
_FOLLOWUP_WAITING = {
    "crashloopbackoff",
    "imagepullbackoff",
    "errimagepull",
    "errimageneverpull",
    "createcontainerconfigerror",
    "createcontainererror",
    "runcontainererror",
    "containercannotrun",
}


def _followup_queries(details: dict, prior: list[dict], namespace: str) -> list[dict[str, str]]:
    if not namespace or not isinstance(details, dict):
        return []
    queries: list[dict[str, str]] = []
    statuses = details.get("pod_statuses") or []
    pending = any(
        isinstance(p, dict) and str(p.get("phase", "")).lower() == "pending" for p in statuses
    )
    waiting = False
    for d in details.get("container_diagnostics") or []:
        state = d.get("state") if isinstance(d, dict) else None
        if (
            isinstance(state, dict)
            and str(state.get("phase")) == "waiting"
            and (str(state.get("reason", "")).lower() in _FOLLOWUP_WAITING)
        ):
            waiting = True
    if pending:
        # "Why is my pod Pending?" branch: scheduling event -> quota -> PVC.
        queries += [
            {"kind": "events", "namespace": namespace},
            {"kind": "resourcequotas", "namespace": namespace},
            {"kind": "persistentvolumeclaims", "namespace": namespace},
        ]
    if waiting:
        # CrashLoop / ImagePull / CreateContainerConfigError -> read the Events tail.
        queries.append({"kind": "events", "namespace": namespace})
    # Chained step: a Pending/unbound PVC -> check the StorageClass provisioner.
    for res in prior:
        if res.get("kind") == "persistentvolumeclaims":
            blob = json.dumps(res.get("data") or {}).lower()
            if any(t in blob for t in ("pending", "unbound", "waitforfirstconsumer")):
                queries.append({"kind": "storageclasses"})
    return queries


def _followup_key(q: dict) -> tuple:
    return (q["kind"], q.get("namespace", ""), q.get("name", ""), q.get("label_selector", ""))


async def k8s_followup(
    settings: Settings,
    kubernetes_result: CollectorResult | None,
    target: AnalysisTarget,
    max_rounds: int = 3,
    max_reads: int = 8,
) -> list[dict]:
    """Iteratively pull follow-up k8s evidence per the debug flowchart and attach
    each read as a `followup_query` artifact on the kubernetes result. Best-effort,
    read-only, and bounded (rounds x reads); returns the raw read results."""
    if kubernetes_result is None or getattr(kubernetes_result, "agent", "") != "kubernetes":
        return []
    details = getattr(kubernetes_result, "details", {}) or {}
    namespace = getattr(target, "namespace", "") or ""
    done: set = set()
    results: list[dict] = []
    for _ in range(max(1, max_rounds)):
        wanted = _followup_queries(details, results, namespace)
        fresh = [q for q in wanted if _followup_key(q) not in done]
        if not fresh or len(results) >= max_reads:
            break
        for q in fresh[: max_reads - len(results)]:
            done.add(_followup_key(q))
            results.append(
                await k8s_read(
                    settings,
                    q["kind"],
                    namespace=q.get("namespace", ""),
                    name=q.get("name", ""),
                    label_selector=q.get("label_selector", ""),
                )
            )
    for res in results:
        err = res.get("error")
        kubernetes_result.artifacts.append(
            artifact(
                agent="kubernetes",
                source="kubernetes",
                type="followup_query",
                status="unavailable" if err else "ok",
                confidence="medium",
                query=kubectl_repr(
                    str(res.get("kind") or ""),
                    namespace=str(res.get("namespace") or ""),
                    name=str(res.get("name") or ""),
                    label_selector=str(res.get("label_selector") or ""),
                ),
                summary=(
                    str(err)
                    if err
                    else f"flowchart follow-up: {res.get('kind')} → HTTP {res.get('status_code')}"
                ),
                result=res,
            )
        )
    return results
