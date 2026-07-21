from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import replace
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote

import yaml

from app.collectors.base import (
    _FALSE_IS_FAILURE_CONDITION_TYPES,
    _OBSERVED_NORMAL_EVENT_REASONS,
    _TRUE_IS_FAILURE_CONDITION_TYPES,
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    _boolean_condition_status,
    artifact,
    causal_evidence_time_range,
    incident_time_range,
    ko_en,
    parse_incident_time,
    salient_markers,
)
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import cached_insight, complete, insight_cache_key, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_budget,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
    mcp_tool_raw_text,
    mcp_tool_text,
)

# pods/exec policy: DENYLIST. The drill-down runs read-only diagnostics of its
# own choosing — nvidia-smi, ping, cat /proc/*, ps, ss, ip addr, dig, curl, df,
# free, … — and only destructive or state-mutating commands are refused. One
# command per exec: no shell, so there is no pipe/redirect/`&&`/wrapper to smuggle
# a denied command through. To tighten or loosen, edit the sets below.
#
# Destructive: deletes, overwrites, wipes, kills, or mutates host/kernel/network
# state. Matched on the command's basename (so `/bin/rm` is caught too).
_EXEC_DENY_COMMANDS: frozenset[str] = frozenset(
    {
        # file / disk destruction (delete, overwrite, wipe)
        "rm", "rmdir", "unlink", "shred", "truncate", "fallocate", "mv", "cp",
        "dd", "mkfs", "wipefs", "fdisk", "parted", "mkswap", "tee",
        # process / host lifecycle
        "kill", "pkill", "killall", "skill", "fuser",
        "reboot", "shutdown", "halt", "poweroff", "init", "telinit", "systemctl", "service",
        # permission / mount / kernel / network / module mutation
        "chmod", "chown", "chattr", "setfacl", "mount", "umount", "sysctl",
        "iptables", "ip6tables", "nft", "modprobe", "insmod", "rmmod",
        # cluster / container control (can delete pods, kill containers, mutate state)
        "kubectl", "oc", "helm", "crictl", "docker", "podman", "ctr", "nerdctl",
    }
)
# Shells, interpreters, and command-wrappers all run *another* command inline —
# an open door around the denylist above — so the runner itself is refused.
_EXEC_DENY_RUNNERS: frozenset[str] = frozenset(
    {
        "sh", "bash", "zsh", "ash", "dash", "ksh", "csh", "tcsh", "fish",
        "python", "python2", "python3", "perl", "ruby", "node", "nodejs",
        "php", "lua", "tclsh", "expect", "awk", "gawk",
        "env", "xargs", "timeout", "nice", "ionice", "nohup", "setsid", "watch",
        "nsenter", "chroot", "unshare", "script", "stdbuf", "taskset", "flock",
        "sudo", "su", "runuser",
        # multiplexers (busybox rm / busybox sh) and editors/pagers with a shell escape
        "busybox", "toybox", "vi", "vim", "view", "ex", "nano", "ed", "emacs",
        "less", "more", "man",
    }
)
# find -delete/-exec erase or run other commands; redirection & chaining are shell
# smuggling — refused as standalone argv tokens.
_EXEC_DENY_TOKENS: frozenset[str] = frozenset(
    {"-delete", "-exec", "-execdir", "-fdelete", ";", "&&", "||", "|", "&", ">", ">>", "`", "$("}
)


def exec_command_allowed(argv: list[str]) -> bool:
    """Denylist gate for pods/exec: allow any read-only diagnostic command;
    refuse deletion, kill, host/kernel/network mutation, and any shell/interpreter/
    wrapper that could run a denied command past this check."""
    if not argv:
        return False
    command = argv[0].rsplit("/", 1)[-1]
    if command in _EXEC_DENY_COMMANDS or command in _EXEC_DENY_RUNNERS:
        return False
    return not any(tok in _EXEC_DENY_TOKENS for tok in argv)


# An exec probe that could not START (binary absent from the image, or the exec
# subresource itself failed) is not a diagnostic finding — keep "command not
# found" out of the evidence signal instead of minting it as a medium result.
_EXEC_UNUSABLE_MARKERS: tuple[str, ...] = (
    "executable file not found",
    "oci runtime exec failed",
    "container not found",
    "cannot exec",
)


def _exec_probe_unusable(error: str) -> bool:
    low = error.lower()
    return any(marker in low for marker in _EXEC_UNUSABLE_MARKERS)


# "kubectl for the agent": read-only ad-hoc queries the investigation loop can run.
# kubectl is just a CLI over this same API, so nothing is lost by going direct —
# what was missing was FREEFORM querying beyond the collector's fixed set. Kind
# allowlist + GET/LIST-only by construction (secrets deliberately absent); RBAC
# (agent-rbac.yaml) is the second fence.
# Run:ai CRDs the scheduler-RCA path must be able to read (kubectl parity:
# `kubectl get project/queue/podgroup …`). API versions differ across Run:ai
# releases, so the group's preferredVersion is discovered at runtime (cached);
# these kinds carry an empty prefix in _READ_KINDS as the discovery marker.
_RUNAI_CRD_KINDS: dict[str, tuple[str, str, bool]] = {
    # kind -> (API group, Kind, namespaced)
    "projects": ("run.ai", "Project", False),
    "queues": ("scheduling.run.ai", "Queue", False),
    "departments": ("scheduling.run.ai", "Department", False),
    "podgroups": ("scheduling.run.ai", "PodGroup", True),
    "bindrequests": ("scheduling.run.ai", "BindRequest", True),
    "nodepools": ("run.ai", "NodePool", False),
    "runaijobs": ("run.ai", "RunaiJob", True),
    "trainingworkloads": ("run.ai", "TrainingWorkload", True),
    "interactiveworkloads": ("run.ai", "InteractiveWorkload", True),
    "inferenceworkloads": ("run.ai", "InferenceWorkload", True),
    "distributedworkloads": ("run.ai", "DistributedWorkload", True),
    "distributedinferenceworkloads": ("run.ai", "DistributedInferenceWorkload", True),
    "externalworkloads": ("run.ai", "ExternalWorkload", True),
    "workloadrunners": ("run.ai", "WorkloadRunner", True),
    "runaiconfigs": ("run.ai", "RunaiConfig", True),
}

# The Run:ai workload CRD kinds (namespaced), most-specific first — enumerated
# when an alert lands in a Run:ai namespace but names no workload, so the RCA
# still finds which workloads are unhealthy from their own status.conditions.
_CRD_SCAN_SKIP_NAMESPACES: frozenset[str] = frozenset(
    {"kube-system", "kube-public", "kube-node-lease"}
)

_RUNAI_WORKLOAD_KINDS: tuple[str, ...] = (
    "trainingworkloads",
    "interactiveworkloads",
    "inferenceworkloads",
    "distributedworkloads",
    "distributedinferenceworkloads",
    "externalworkloads",
    "runaijobs",
)

_READ_KINDS: dict[str, tuple[str, bool]] = {
    # kind -> (API prefix, namespaced); "" prefix = discover via _RUNAI_CRD_KINDS
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
    **{kind: ("", crd[2]) for kind, crd in _RUNAI_CRD_KINDS.items()},
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
    "project": "projects",
    "queue": "queues",
    "department": "departments",
    "podgroup": "podgroups",
    "pg": "podgroups",
    "bindrequest": "bindrequests",
    "nodepool": "nodepools",
    "runaijob": "runaijobs",
    "trainingworkload": "trainingworkloads",
    "interactiveworkload": "interactiveworkloads",
    "inferenceworkload": "inferenceworkloads",
    "distributedworkload": "distributedworkloads",
    "externalworkload": "externalworkloads",
    "runaiconfig": "runaiconfigs",
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


def kubectl_repr(
    kind: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
    field_selector: str = "",
) -> str:
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
    if field_selector:
        parts.append(f"--field-selector {quote_arg(field_selector)}")
    return " ".join(parts)


def pod_inspection_repr(namespace: str, pod: str) -> str:
    """The full read-only Pod inspection shown to operators as familiar kubectl."""
    ns = f" -n {shlex.quote(namespace)}" if namespace else ""
    quoted_pod = shlex.quote(pod)
    return (
        f"kubectl get pod {quoted_pod}{ns} -o yaml; "
        f"kubectl describe pod {quoted_pod}{ns}"
    )


async def k8s_read(
    settings: Settings,
    kind: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
    field_selector: str = "",
    *,
    full_object: bool = False,
    continue_token: str = "",
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
    crd = _RUNAI_CRD_KINDS.get(resolved)
    if crd:
        # Warm the group→preferredVersion cache (one tiny discovery GET) so BOTH
        # transports address the CRD with the version this cluster actually runs.
        await _api_group_prefix(settings, crd[0])
    mcp_note = ""
    if settings.kubernetes_mcp_url:
        try:
            mcp_kwargs: dict[str, object] = {
                "namespace": namespace,
                "name": name,
                "label_selector": label_selector,
                "full_object": full_object,
            }
            # Keep compatibility with older injected adapters for ordinary
            # reads; only the new node-assignment lookup needs this argument.
            if field_selector:
                mcp_kwargs["field_selector"] = field_selector
            return await _k8s_read_via_mcp(settings, resolved, **mcp_kwargs)
        except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
            # "not found" is an ANSWER (the resource is gone), not a transport
            # failure — the direct API would only 404 the same question again.
            if "not found" in str(exc).lower() or "notfound" in str(exc).lower():
                return {
                    "kind": resolved,
                    "namespace": namespace,
                    "name": name,
                    "label_selector": label_selector,
                    "field_selector": field_selector,
                    "url": f"{settings.kubernetes_mcp_url}#read_{resolved}",
                    "status_code": 404,
                    "error": str(exc),
                    "data": None,
                }
            mcp_note = mcp_fallback_warning(exc)
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {"kind": resolved, "error": "kubernetes service account token unavailable"}
    prefix, namespaced = _READ_KINDS[resolved]
    if not prefix and crd:
        prefix = await _api_group_prefix(settings, crd[0])
        if not prefix:
            return {
                "kind": resolved,
                "namespace": namespace,
                "name": name,
                "error": (
                    f"could not discover the API version for group '{crd[0]}' "
                    "(is the Run:ai CRD installed?)"
                ),
            }
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
        if field_selector:
            params["fieldSelector"] = field_selector
        if continue_token:
            params["continue"] = continue_token
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
    safe_data = _collector_masker(settings).mask_object(response.data)
    result = {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "label_selector": label_selector,
        "field_selector": field_selector,
        "url": response.url,
        "status_code": response.status_code,
        "error": response.error,
        # A named Pod inspection is a diagnostic artifact, not a broad list.
        # Keep its full spec/status so the operator can inspect exactly what a
        # `kubectl get pod -o yaml` would expose. This remains one named,
        # read-only object rather than broadening the collector's data scope.
        "data": safe_data if full_object else compact(safe_data, limit=8),
    }
    if mcp_note:
        result["mcp_fallback"] = mcp_note
    return result


async def k8s_logs(
    settings: Settings,
    namespace: str,
    pod: str,
    container: str = "",
    tail: int = 0,
    previous: bool = False,
    since_time: str = "",
) -> dict:
    """One READ-ONLY pod-log fetch with a verifiable historical path.

    The on-demand sibling of the base sweep's _collect_pod_logs*, exposed to the
    drill-down/chat LLM loops so "look at the pod's logs" is executable. NOT
    namespace-gated (RBAC / the MCP server are the boundary).  The pinned MCP
    server cannot request ``sinceTime`` or Kubernetes-generated timestamps, so
    an incident-bounded request prefers the exact direct log subresource when
    the agent ServiceAccount is available.  An MCP tail remains useful context,
    but is explicitly marked as not time-scope-verified. Never raises."""
    if not (namespace and pod):
        return {"error": "namespace and pod are required", "lines": []}
    tail_lines = tail if tail > 0 else settings.kubernetes_list_limit
    mcp_note = ""
    token = _read_file(settings.kubernetes_token_path) if since_time else ""
    if token:
        # Intentional: MCP v0.0.62 cannot request sinceTime for this bounded read.
        return await _direct_pod_logs(
            settings,
            namespace=namespace,
            pod=pod,
            container=container,
            tail_lines=tail_lines,
            previous=previous,
            since_time=since_time,
            token=token,
        )
    if settings.kubernetes_mcp_url:
        # v0.0.62's actual tools/list schema calls this argument ``tail`` and
        # does not expose the Kubernetes API's ``sinceTime`` option.  Keep the
        # requested incident window on the result for timestamp filtering, but
        # send only schema-valid fields so the whole MCP collector is not
        # demoted to the direct API by an invalid-arguments error.
        args: dict[str, object] = {"namespace": namespace, "name": pod, "tail": tail_lines}
        if container:
            args["container"] = container
        if previous:
            args["previous"] = True
        try:
            result = await _k8s_mcp_result(settings, [("pods_log", args)])
            raw = mcp_tool_json(result)
            lines = _log_lines(mcp_tool_text(result) or raw)
            observed_entity = _mcp_pod_log_observed_entity(raw, namespace, pod)
            return {
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "previous": previous,
                "since_time": since_time or None,
                "transport": "mcp",
                # A plain-text MCP reply has no object identity.  It is still
                # useful operator context, but must not become scoped causal
                # evidence for the requested Pod unless the response itself
                # proves which Pod/namespace produced it.
                "source_verified": observed_entity is not None,
                # v0.0.62 cannot request Kubernetes timestamps or sinceTime.
                # Even a structured response that names the Pod cannot prove
                # that its text belongs to this historical incident window.
                "time_scope_verified": not bool(since_time),
                **({"observed_entity": observed_entity} if observed_entity else {}),
                "status_code": 200,
                "error": None,
                "lines": lines,
            }
        except Exception as exc:  # noqa: BLE001 - direct fallback is the behavior.
            mcp_note = mcp_fallback_warning(exc)
    if not token:
        token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {
            "namespace": namespace,
            "pod": pod,
            "error": "kubernetes service account token unavailable",
            "lines": [],
        }
    return await _direct_pod_logs(
        settings,
        namespace=namespace,
        pod=pod,
        container=container,
        tail_lines=tail_lines,
        previous=previous,
        since_time=since_time,
        token=token,
        mcp_note=mcp_note,
    )


async def _direct_pod_logs(
    settings: Settings,
    *,
    namespace: str,
    pod: str,
    container: str,
    tail_lines: int,
    previous: bool,
    since_time: str,
    token: str,
    mcp_note: str = "",
) -> dict[str, object]:
    """Fetch one exact Pod log stream with API-generated timestamps."""
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    params: dict[str, str] = {"tailLines": str(tail_lines), "timestamps": "true"}
    if container:
        params["container"] = container
    if previous:
        params["previous"] = "true"
    if since_time:
        params["sinceTime"] = since_time
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/pods/{quote(pod, safe='')}/log"
    response = await get_json(
        base_url=settings.kubernetes_api_url,
        path=path,
        timeout_seconds=settings.kubernetes_timeout_seconds,
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
    )
    result: dict = {
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "previous": previous,
        "since_time": since_time or None,
        "transport": "direct",
        # The direct API path is an exact /namespaces/{ns}/pods/{pod}/log URL.
        "source_verified": True,
        "time_scope_verified": True,
        "observed_entity": _pod_log_entity(namespace, pod),
        "status_code": response.status_code,
        "error": response.error,
        "lines": _log_lines(response.data, historical=bool(since_time)),
    }
    if mcp_note:
        result["mcp_fallback"] = mcp_note
    return result


async def k8s_describe(
    settings: Settings,
    kind: str,
    namespace: str = "",
    name: str = "",
    *,
    time_range: dict[str, str] | None = None,
) -> dict:
    """A describe-style read: the named object's full spec/status PLUS its events.

    Reuses k8s_read (MCP-first, direct fallback) for the object and filters the
    named object's events. Read-only."""
    resolved = resolve_read_kind(kind)
    if not resolved:
        return {
            "kind": kind,
            "error": "kind is not in the read-only allowlist",
            "allowed_kinds": sorted(_READ_KINDS),
        }
    if not name:
        return {"kind": resolved, "error": "name is required to describe a resource"}
    obj = await k8s_read(
        settings, resolved, namespace=namespace, name=name, full_object=True
    )
    expected_kind = _k8s_mcp_api_kinds(resolved)[0][1]
    object_data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    metadata = object_data.get("metadata") if isinstance(object_data.get("metadata"), dict) else {}
    event_result = await _describe_events(
        settings,
        namespace=namespace,
        name=name,
        expected_kind=expected_kind,
        expected_uid=str(metadata.get("uid") or ""),
        time_range=time_range,
    )
    events = event_result.get("items", []) if isinstance(event_result, dict) else event_result
    observed_entity = _described_resource_entity(
        expected_kind, namespace, name, object_data
    )
    return {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "object": obj.get("data"),
        "status_code": obj.get("status_code"),
        "error": obj.get("error"),
        "events": events,
        **(
            {"events_error": event_result["error"]}
            if isinstance(event_result, dict) and event_result.get("error")
            else {}
        ),
        **({"observed_entity": observed_entity} if observed_entity else {}),
        **(
            {
                "mcp_fallback": " | ".join(
                    str(note)
                    for note in (
                        obj.get("mcp_fallback"),
                        event_result.get("mcp_fallback") if isinstance(event_result, dict) else "",
                    )
                    if note
                )
            }
            if obj.get("mcp_fallback")
            or (isinstance(event_result, dict) and event_result.get("mcp_fallback"))
            else {}
        ),
    }


def _described_resource_entity(
    expected_kind: str, namespace: str, name: str, object_data: object
) -> dict[str, str] | None:
    """Return named-resource provenance only when the returned object proves it."""
    if not isinstance(object_data, dict):
        return None
    metadata = object_data.get("metadata")
    if not isinstance(metadata, dict) or str(metadata.get("name") or "") != name:
        return None
    observed_namespace = str(metadata.get("namespace") or "")
    if namespace and observed_namespace != namespace:
        return None
    entity = {"kind": expected_kind.casefold(), "name": name}
    if namespace:
        entity["namespace"] = namespace
    return entity


async def _describe_events(
    settings,
    *,
    namespace: str,
    name: str,
    expected_kind: str,
    expected_uid: str = "",
    time_range: dict[str, str] | None = None,
) -> dict[str, object]:
    """Events for ONE object, preferring Kubernetes MCP plus local verification.

    In v0.0.62 the generic ``resources_list`` tool exposes ``fieldSelector``;
    the ``events_list`` shortcut does not. Prefer the generic tool so a busy
    namespace cannot truncate the target's Events out of the result. Retain
    client-side identity filtering because alternate adapters may accept but
    ignore selectors.
    """
    if not name:
        return {"items": []}
    field_selector = ",".join(
        value
        for value in (
            f"involvedObject.name={name}",
            f"involvedObject.kind={expected_kind}",
            f"involvedObject.uid={expected_uid}" if expected_uid else "",
        )
        if value
    )
    mcp_note = ""
    if settings.kubernetes_mcp_url:
        try:
            data = await _k8s_mcp_json(
                settings,
                [
                    (
                        "resources_list",
                        {
                            "apiVersion": "v1",
                            "kind": "Event",
                            "namespace": namespace,
                            "fieldSelector": field_selector,
                        },
                    ),
                    ("events_list", {"namespace": namespace}),
                ],
            )
            normalized = _normalize_k8s_payload(data)
            raw_items = normalized.get("items") if isinstance(normalized, dict) else None
            items = raw_items if isinstance(raw_items, list) else []
            matching = [
                item
                for item in items
                if isinstance(item, dict)
                if isinstance(item.get("involvedObject"), dict)
                if str((item.get("involvedObject") or {}).get("name") or "") == name
                if str((item.get("involvedObject") or {}).get("kind") or "").casefold()
                == expected_kind.casefold()
                if _event_matches_namespace(item, namespace)
                if _event_matches_uid(item, expected_uid)
            ]
            filtered = _events_in_time_range(matching, time_range)
            return {"items": compact(filtered, limit=12) if filtered else []}
        except Exception as exc:  # noqa: BLE001 - direct API fallback is the behavior.
            mcp_note = mcp_fallback_warning(exc)
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {
            "items": [],
            "error": "kubernetes service account token unavailable for events read",
            **({"mcp_fallback": mcp_note} if mcp_note else {}),
        }
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    parts = ["/api/v1"]
    if namespace:
        parts += ["namespaces", quote(namespace, safe="")]
    parts.append("events")
    response = await get_json(
        base_url=settings.kubernetes_api_url,
        path="/".join(parts),
        timeout_seconds=settings.kubernetes_timeout_seconds,
        params={
            "fieldSelector": field_selector,
            "limit": str(settings.kubernetes_list_limit),
        },
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
    )
    items = (response.data or {}).get("items") if isinstance(response.data, dict) else None
    raw_items = items if isinstance(items, list) else []
    filtered = [
        item
        for item in raw_items
        if isinstance(item, dict)
        and isinstance(item.get("involvedObject"), dict)
        and str((item.get("involvedObject") or {}).get("name") or "") == name
        and str((item.get("involvedObject") or {}).get("kind") or "").casefold()
        == expected_kind.casefold()
        and _event_matches_namespace(item, namespace)
        and _event_matches_uid(item, expected_uid)
    ]
    filtered = _events_in_time_range(filtered, time_range)
    return {
        "items": compact(filtered, limit=12) if filtered else [],
        **({"error": response.error} if response.error else {}),
        **({"mcp_fallback": mcp_note} if mcp_note else {}),
    }


async def k8s_exec(
    settings: Settings, namespace: str, pod: str, command: list[str], container: str = ""
) -> dict:
    """Actually run ONE read-only diagnostic command in a container.

    Uses the agent's OWN ServiceAccount over the Kubernetes exec subresource
    (WebSocket, v4.channel.k8s.io) — deliberately NOT the MCP, which the chart pins
    to a hard read-only boundary (no pods/exec). Gate = enable_pod_exec +
    exec_command_allowed (a denylist: any command runs except destructive/mutating
    ones and shells/interpreters — see _EXEC_DENY_*). Never raises; returns an
    observation. This is the path the base _collect_exec_probes uses too."""
    if not settings.enable_pod_exec:
        return {"error": "pod exec is disabled (set ENABLE_POD_EXEC=true + grant pods/exec RBAC)"}
    if not (namespace and pod and command):
        return {"error": "namespace, pod and command (argv list) are required"}
    if not exec_command_allowed(command):
        return {
            "error": (
                "command refused: destructive/mutating commands (rm, kill, mv, dd, chmod, "
                f"mount, systemctl, …) and shells/interpreters are not permitted: {command}"
            ),
        }
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return {
            "namespace": namespace,
            "pod": pod,
            "command": command,
            "error": "kubernetes service account token unavailable",
            "error_code": "kubernetes_token_unavailable",
            "transport_error": True,
            "retryable": False,
        }
    try:
        stdout, stderr, status_err = await _exec_via_websocket(
            settings,
            namespace=namespace,
            pod=pod,
            command=command,
            container=container,
            token=token,
        )
    except Exception as exc:  # noqa: BLE001 - observation, not a raise.
        return {
            "namespace": namespace,
            "pod": pod,
            "command": command,
            **_exec_transport_failure(settings, exc),
        }
    result: dict = {
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "command": command,
        "status_code": 200,
        "error": status_err or None,
        "output": (stdout or "")[-4000:],
        # The websocket is opened against this exact namespaced Pod path. It
        # proves current resource identity, but its untimestamped output still
        # remains snapshot/context evidence rather than historical causality.
        "observed_entity": _pod_log_entity(namespace, pod),
    }
    if stderr.strip():
        result["stderr"] = stderr[-1000:]
    return result


def _exec_transport_failure(settings: Settings, exc: Exception) -> dict[str, object]:
    """Classify an exec transport failure without echoing its full request URL.

    ``aiohttp.WSServerHandshakeError`` includes every command query parameter in
    ``str(exc)``. Besides producing an unreadable artifact, repeating that text
    for each base probe makes one missing ``pods/exec`` permission look like
    three independent findings. A failed WebSocket handshake is transport-wide
    for this Pod, so callers can stop the remaining probe batch safely.
    """
    raw_status = getattr(exc, "status", None)
    status = raw_status if isinstance(raw_status, int) else None
    if status in {401, 403}:
        return {
            "error": ko_en(
                settings,
                (
                    f"Kubernetes API가 pod exec 접근을 거부했습니다(HTTP {status}). "
                    "agent ServiceAccount에 pods/exec get/create 권한을 부여하거나 "
                    "ENABLE_POD_EXEC=false로 비활성화하세요."
                ),
                (
                    f"Kubernetes API denied pod exec access (HTTP {status}); grant the agent "
                    "ServiceAccount get/create on pods/exec or set ENABLE_POD_EXEC=false."
                ),
            ),
            "error_code": "kubernetes_exec_forbidden",
            "transport_error": True,
            "retryable": False,
            "status_code": status,
        }
    if status == 404:
        message = ko_en(
            settings,
            "Pod 또는 exec 하위 리소스를 찾을 수 없습니다(HTTP 404).",
            "The Pod or exec subresource was not found (HTTP 404).",
        )
        code, retryable = "kubernetes_exec_not_found", False
    elif status is not None:
        message = ko_en(
            settings,
            f"Pod exec WebSocket 연결에 실패했습니다(HTTP {status}).",
            f"Pod exec WebSocket handshake failed (HTTP {status}).",
        )
        code, retryable = "kubernetes_exec_handshake_failed", status >= 429
    elif isinstance(exc, TimeoutError):
        message = ko_en(
            settings,
            "Pod exec 연결 시간이 초과되었습니다.",
            "Pod exec transport timed out.",
        )
        code, retryable = "kubernetes_exec_timeout", True
    else:
        error_type = exc.__class__.__name__
        message = ko_en(
            settings,
            f"Pod exec 전송에 실패했습니다({error_type}).",
            f"Pod exec transport failed ({error_type}).",
        )
        code, retryable = "kubernetes_exec_transport_failed", True
    return {
        "error": message,
        "error_code": code,
        "transport_error": True,
        "retryable": retryable,
        **({"status_code": status} if status is not None else {}),
    }


async def _exec_via_websocket(
    settings: Settings,
    *,
    namespace: str,
    pod: str,
    command: list[str],
    container: str,
    token: str,
) -> tuple[str, str, str]:
    """Stream one command via the pod exec subresource. Returns (stdout, stderr,
    status_error). k8s channels: 1=stdout, 2=stderr, 3=error/status (JSON)."""
    import ssl

    import aiohttp

    base = settings.kubernetes_api_url.replace("https://", "wss://").replace("http://", "ws://")
    params: list[tuple[str, str]] = [("container", container)] if container else []
    params += [("command", part) for part in command]
    params += [("stdout", "true"), ("stderr", "true"), ("stdin", "false"), ("tty", "false")]
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params)
    url = (
        f"{base}/api/v1/namespaces/{quote(namespace, safe='')}"
        f"/pods/{quote(pod, safe='')}/exec?{query}"
    )
    ca = settings.kubernetes_ca_path
    ssl_ctx = (
        ssl.create_default_context(cafile=ca)
        if ca and Path(ca).exists()
        else ssl.create_default_context()
    )
    out: list[str] = []
    err: list[str] = []
    status_err = ""
    timeout = aiohttp.ClientTimeout(total=settings.pod_exec_timeout_seconds)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.ws_connect(
            url,
            protocols=("v4.channel.k8s.io", "channel.k8s.io"),
            headers={"Authorization": f"Bearer {token}"},
            ssl=ssl_ctx,
        ) as ws:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.BINARY or not msg.data:
                    continue
                status_err = _accumulate_exec_frame(msg.data, out, err) or status_err
    return "".join(out), "".join(err), status_err


def _accumulate_exec_frame(data: bytes, out: list[str], err: list[str]) -> str:
    """Route one k8s exec WS binary frame by its channel byte (1=stdout, 2=stderr,
    3=error/status). Appends stdout/stderr in place; returns a status-error message
    only when channel 3 reports a Failure, else ''."""
    if not data:
        return ""
    channel, text = data[0], data[1:].decode("utf-8", "replace")
    if channel == 1:
        out.append(text)
    elif channel == 2:
        err.append(text)
    elif channel == 3:
        try:
            status = json.loads(text)
        except ValueError:
            return text
        if isinstance(status, dict) and status.get("status") == "Failure":
            return status.get("message") or text
    return ""


async def _k8s_read_via_mcp(
    settings: Settings,
    resolved: str,
    namespace: str = "",
    name: str = "",
    label_selector: str = "",
    field_selector: str = "",
    full_object: bool = False,
) -> dict:
    """k8s_read over the Kubernetes MCP server; same result shape, raises to fall back."""
    api_kinds = _k8s_mcp_api_kinds(resolved)
    candidates: list[tuple[str, dict[str, object]]] = []
    if name:
        resource_get_candidates = [
            (
                "resources_get",
                {
                    "apiVersion": api_version,
                    "kind": mcp_kind,
                    "namespace": namespace,
                    "name": name,
                },
            )
            for api_version, mcp_kind in api_kinds
        ]
        resource_get_candidates.append(
            ("resources_get", {"kind": resolved, "namespace": namespace, "name": name})
        )
        pod_get_candidates: list[tuple[str, dict[str, object]]] = []
        if resolved == "pods":
            pod_get_candidates.extend(
                [
                    ("pods_get", {"namespace": namespace, "name": name}),
                    ("pods_get", {"namespace": namespace, "pod": name}),
                ]
            )
        # `resources_get` returns the server's YAML representation. For an
        # explicit Pod inspection this is deliberately first, matching
        # `kubectl get pod <name> -n <namespace> -o yaml`; compact sweep reads
        # retain the shortcut tool first for lower overhead.
        candidates.extend(
            resource_get_candidates + pod_get_candidates
            if full_object
            else pod_get_candidates + resource_get_candidates
        )
    else:
        # A requested label selector must ride on EVERY candidate — a shortcut
        # tool called without it would "succeed" with the unfiltered namespace
        # and silently drop the filter the caller asked for.
        if resolved == "pods" and not field_selector:
            pod_args: dict[str, object] = {"namespace": namespace}
            if label_selector:
                pod_args["labelSelector"] = label_selector
            candidates.extend(
                [
                    ("pods_list_in_namespace", dict(pod_args)),
                    ("pods_list", dict(pod_args)),
                ]
            )
        elif resolved == "events" and not label_selector and not field_selector:
            candidates.append(("events_list", {"namespace": namespace}))
        for api_version, mcp_kind in api_kinds:
            args: dict[str, object] = {
                "apiVersion": api_version,
                "kind": mcp_kind,
                "namespace": namespace,
            }
            if label_selector:
                args["labelSelector"] = label_selector
            if field_selector:
                args["fieldSelector"] = field_selector
            candidates.append(("resources_list", args))
        fallback_args: dict[str, object] = {"kind": resolved, "namespace": namespace}
        if label_selector:
            fallback_args["labelSelector"] = label_selector
        if field_selector:
            fallback_args["fieldSelector"] = field_selector
        candidates.append(("resources_list", fallback_args))
    data = await _k8s_mcp_json(settings, candidates)
    if name and not _mcp_named_resource_matches(
        data,
        expected_name=name,
        expected_namespace=namespace,
    ):
        # MCP servers can accept a resources_get/pods_get call while silently
        # ignoring its name or namespace.  Never treat another resource's YAML
        # as the alert object; raise so k8s_read performs its exact direct-API
        # fallback instead.
        raise RuntimeError(
            "Kubernetes MCP named read did not return the requested resource "
            f"{namespace}/{name}"
        )
    if not name and label_selector:
        # Belt and suspenders: an MCP server may ACCEPT labelSelector and still
        # ignore it — enforce equality selectors client-side.
        data = _apply_label_selector(data, label_selector)
    if not name and field_selector:
        # The official generic resources_list schema carries fieldSelector,
        # but enforce the exact assignment locally as well in case a proxy
        # accepts and then drops it.
        data = _apply_field_selector(_normalize_k8s_payload(data), field_selector)
    safe_data = _collector_masker(settings).mask_object(data)
    return {
        "kind": resolved,
        "namespace": namespace,
        "name": name,
        "label_selector": label_selector,
        "field_selector": field_selector,
        "url": f"{settings.kubernetes_mcp_url}#read_{resolved}",
        "status_code": 200,
        "error": None,
        "data": safe_data if full_object else compact(safe_data, limit=8),
    }


def _mcp_named_resource_matches(
    data: object, *, expected_name: str, expected_namespace: str
) -> bool:
    """Whether a named MCP get proves it returned the requested object.

    An object without metadata or an explicit name/namespace mismatch is
    rejected. Some Kubernetes MCP YAML views omit metadata.namespace even for a
    correctly namespace-scoped get; that omission remains partial context in
    downstream evidence handling, rather than forcing an avoidable direct
    fallback. A single-item list or single top-level object wrapper is accepted
    only when its contained object's identity matches exactly.
    """
    payload = _normalize_k8s_payload(data)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        items = payload["items"]
        if len(items) != 1:
            return False
        payload = items[0]
    elif isinstance(payload, dict) and not isinstance(payload.get("metadata"), dict):
        wrapped = [value for value in payload.values() if isinstance(value, dict)]
        if len(payload) == 1 and len(wrapped) == 1:
            payload = wrapped[0]
    if not isinstance(payload, dict):
        return False
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict) or str(metadata.get("name") or "") != expected_name:
        return False
    observed_namespace = str(metadata.get("namespace") or "")
    if expected_namespace and observed_namespace and observed_namespace != expected_namespace:
        return False
    return True


def _mcp_pod_log_observed_entity(
    data: object, namespace: str, pod: str
) -> dict[str, str] | None:
    """Return provenance only when an MCP log reply names the requested Pod.

    pods_log commonly returns raw log text.  Call arguments alone are not
    evidence that the server honored them, so raw text is intentionally not a
    source-verified observation.  Structured adapters may include either
    metadata.name/namespace or top-level name/pod + namespace fields.
    """
    payload = _normalize_k8s_payload(data)
    if not isinstance(payload, dict):
        return None
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    observed_name = str(
        metadata.get("name") or payload.get("pod") or payload.get("name") or ""
    )
    observed_namespace = str(metadata.get("namespace") or payload.get("namespace") or "")
    if observed_name != pod or observed_namespace != namespace:
        return None
    return _pod_log_entity(observed_namespace, observed_name)


def _mcp_pod_log_source_verified(data: object, namespace: str, pod: str) -> bool:
    """Compatibility predicate for callers that only need source verification."""
    return _mcp_pod_log_observed_entity(data, namespace, pod) is not None


def _pod_log_entity(namespace: str, pod: str) -> dict[str, str]:
    """The concrete namespaced Pod provenance required for log causality."""
    return {"kind": "pod", "name": pod, "namespace": namespace}


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


def _apply_field_selector(data: object, selector: str) -> object:
    """Filter a Kubernetes list by pure-equality dotted field selectors.

    The official MCP's generic ``resources_list`` accepts ``fieldSelector``,
    but a proxy can accept an argument without forwarding it.  The scheduler
    snapshot relies on an exact ``spec.nodeName=<node>`` assignment, so verify
    that equality locally before summing Pod GPU requests.  Unsupported selector
    operators are left to the server rather than approximated incorrectly.
    """
    terms: dict[str, str] = {}
    for part in selector.split(","):
        part = part.strip()
        if not part:
            continue
        if any(op in part for op in ("!=", "!", "(", " in ", " notin ")) or "=" not in part:
            return data
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

    def field_value(item: dict[str, object], path: str) -> object:
        value: object = item
        for segment in path.split("."):
            if not isinstance(value, dict):
                return None
            value = value.get(segment)
        return value

    filtered = [
        item
        for item in items
        if isinstance(item, dict)
        and all(str(field_value(item, key) or "") == value for key, value in terms.items())
    ]
    return filtered if isinstance(data, list) else {**data, "items": filtered}


# group -> "/apis/{group}/{preferredVersion}" once discovered. Module-level on
# purpose: the group's served version is a cluster property, not per-request.
_API_GROUP_PREFIX_CACHE: dict[str, str] = {}


async def _api_group_prefix(settings: Settings, group: str) -> str:
    """Discover "/apis/{group}/{version}" from the group's preferredVersion.

    Cached per group; "" when the group is not served (CRD not installed) or
    discovery itself failed."""
    cached = _API_GROUP_PREFIX_CACHE.get(group)
    if cached:
        return cached
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return ""
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    response = await get_json(
        base_url=settings.kubernetes_api_url,
        path=f"/apis/{quote(group, safe='')}",
        timeout_seconds=settings.kubernetes_timeout_seconds,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
    )
    group_version = ""
    if response.ok and isinstance(response.data, dict):
        preferred = response.data.get("preferredVersion")
        if isinstance(preferred, dict):
            group_version = str(preferred.get("groupVersion") or "")
        if not group_version:
            versions = response.data.get("versions")
            if isinstance(versions, list) and versions and isinstance(versions[0], dict):
                group_version = str(versions[0].get("groupVersion") or "")
    if not group_version:
        return ""
    prefix = f"/apis/{group_version}"
    _API_GROUP_PREFIX_CACHE[group] = prefix
    return prefix


def _k8s_mcp_api_kinds(kind: str) -> list[tuple[str, str]]:
    """Ordered (apiVersion, Kind) candidates for the MCP resources_* tools.

    Core kinds have one fixed mapping. Run:ai CRDs use the discovered
    preferredVersion when the cache is warm (k8s_read warms it), else a short
    list of versions Run:ai has shipped."""
    crd = _RUNAI_CRD_KINDS.get(kind)
    if not crd:
        return [_k8s_mcp_resource_kind(kind)]
    group, kind_name, _namespaced = crd
    discovered = _API_GROUP_PREFIX_CACHE.get(group, "").removeprefix("/apis/")
    versions = [discovered] if discovered else []
    versions.extend(
        f"{group}/{version}"
        for version in ("v2alpha1", "v1", "v2")
        if f"{group}/{version}" != discovered
    )
    return [(version, kind_name) for version in versions if version]


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


def _kubernetes_exact_absence(item: dict[str, object]) -> bool:
    """Treat an exact named-resource 404 as a completed lookup, not outage."""
    return item.get("status_code") == 404 and str(item.get("name") or "") in {
        "pod",
        "node",
    }


class KubernetesCollector:
    name = "kubernetes"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:  # noqa: ANN001
        target = _scope_target(target, plan)
        time_range = incident_time_range(target)
        causal_time_range = causal_evidence_time_range(target)
        event_time_range = _event_collection_time_range(target)
        since_time = time_range["start"] if time_range else ""
        missing: list[str] = []
        if not target.namespace:
            missing.append("kubernetes.namespace")
        if not target.pod and not target.workload_name and not target.node:
            missing.append("kubernetes.target")
        if target.namespace and not _namespace_allowed(self._settings, target.namespace):
            missing.append("kubernetes.namespace_scope")

        warnings: list[str] = []
        used_mcp = False
        responses: list[dict[str, object]] = []
        pod_summary_data: dict[str, object] | None = None
        logs: list[dict[str, object]] = []
        exec_probes: list[dict[str, object]] = []
        control_plane_in_scope = plan.check_control_plane if plan is not None else True
        # A controller-only alert does not name its concrete Pod. Resolve it
        # before the broad Event sweep so every Event layer can use the same
        # exact Pod identity, while retaining the declared workload as the
        # alert entity reported by the artifact.
        workload_resolution: dict[str, object] = {}
        resolved_pod_anchor: AnalysisTarget | None = None
        if not target.pod:
            if target.namespace and not _namespace_allowed(self._settings, target.namespace):
                warnings.append("Resolved workload pod lookup skipped by namespace scope configuration.")
            else:
                workload_resolution = await _resolve_workload_pod(self._settings, target)
            resolved_pod = str(workload_resolution.get("selected_pod") or "")
            if resolved_pod:
                resolved_pod_anchor = replace(
                    target,
                    pod=resolved_pod,
                    pod_uid=str(workload_resolution.get("selected_pod_uid") or ""),
                )
        if self._settings.kubernetes_mcp_url:
            try:
                async with mcp_budget(self._settings.kubernetes_timeout_seconds):
                    responses = await _collect_kubernetes_responses_via_mcp(
                        settings=self._settings,
                        target=target,
                        control_plane_in_scope=control_plane_in_scope,
                        resolved_pod_anchor=resolved_pod_anchor,
                    )
                    pod_summary_data = _target_pod_summary(responses)
                    if _pod_matches_target_uid(pod_summary_data, target):
                        containers = _container_names(pod_summary_data)
                        logs = await _collect_pod_logs_via_mcp(
                            settings=self._settings,
                            target=target,
                            containers=containers,
                            previous_containers=_restarted_container_names(
                                pod_summary_data
                            ),
                            since_time=since_time,
                        )
                        # pods/exec is intentionally outside the read-only Kubernetes
                        # MCP ServiceAccount. Run the same tightly allowlisted probes
                        # through the agent's own ServiceAccount; this does not turn
                        # ordinary Kubernetes reads into direct API calls.
                        exec_probes = await _collect_exec_probes(
                            settings=self._settings,
                            target=target,
                            containers=containers,
                        )
                    elif target.pod_uid:
                        warnings.append(
                            "current Pod UID does not match the alert Pod UID; "
                            "skipped logs and exec"
                        )
                        pod_summary_data = None
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
                resolved_pod_anchor=resolved_pod_anchor,
            )
            pod_summary_data = _target_pod_summary(responses)
            if _pod_matches_target_uid(pod_summary_data, target):
                containers = _container_names(pod_summary_data)
                logs = await _collect_pod_logs(
                    settings=self._settings,
                    target=target,
                    containers=containers,
                    headers=headers,
                    verify=verify,
                    previous_containers=_restarted_container_names(pod_summary_data),
                    since_time=since_time,
                )
                exec_probes = await _collect_exec_probes(
                    settings=self._settings,
                    target=target,
                    containers=containers,
                )
            elif target.pod_uid:
                warnings.append(
                    "current Pod UID does not match the alert Pod UID; skipped logs and exec"
                )
                pod_summary_data = None

        # The initial sweep's `pods_get` is deliberately compact so broad RCA
        # evidence stays readable. A named alert pod is different: preserve one
        # full MCP-backed object + its filtered events, equivalent to `get -o
        # yaml` and `describe`, so lifecycle/volume/security/resource details
        # are available before the optional LLM loop decides whether to drill in.
        target_pod_describe: dict[str, object] = {}
        if target.namespace and target.pod and _namespace_allowed(self._settings, target.namespace):
            target_pod_describe = await k8s_describe(
                self._settings,
                "pods",
                namespace=target.namespace,
                name=target.pod,
                time_range=event_time_range,
            )
            described_object = target_pod_describe.get("object")
            if isinstance(described_object, dict):
                described_summary = _pod_summary(described_object)
                if _pod_matches_target_uid(described_summary, target):
                    pod_summary_data = described_summary
                elif target.pod_uid:
                    target_pod_describe["identity_mismatch"] = True
                    warnings.append(
                        "described Pod UID does not match the alert Pod UID; "
                        "ignored replacement Pod"
                    )

        # Controller-level alerts (Deployment/StatefulSet/DaemonSet/ReplicaSet/
        # Job/CronJob) commonly carry only the controller label. Resolve its pod
        # selector deterministically, choose the most unhealthy pod, then collect
        # the same describe/log evidence as a pod-level alert. This must not be
        # left to the optional LLM drill-down loop.
        resolved_pod_describe: dict[str, object] = {}
        if not target.pod:
            resolved_pod = str(workload_resolution.get("selected_pod") or "")
            if resolved_pod and _namespace_allowed(self._settings, target.namespace):
                resolved_target = replace(target, pod=resolved_pod)
                resolved_pod_describe = await k8s_describe(
                    self._settings,
                    "pods",
                    namespace=target.namespace,
                    name=resolved_pod,
                    time_range=event_time_range,
                )
                described_object = resolved_pod_describe.get("object")
                if isinstance(described_object, dict):
                    pod_summary_data = _pod_summary(described_object)
                containers = _container_names(pod_summary_data)
                logs = await _collect_resolved_pod_logs(
                    self._settings,
                    resolved_target,
                    containers,
                    previous_containers=_restarted_container_names(pod_summary_data),
                    since_time=since_time,
                )
        container_diagnostics = _container_diagnostics(pod_summary_data)
        warnings.extend(
            f"Kubernetes {item['name']} query failed: {item['error']}"
            for item in responses
            if item.get("error")
        )
        successful = [item for item in responses if not item.get("error")]
        required_responses = [
            item
            for item in responses
            if not str(item.get("name") or "").startswith("runai_control_plane_")
        ]
        required_failures = [
            item
            for item in required_responses
            if item.get("error") and not _kubernetes_exact_absence(item)
        ]
        required_completed = [
            item
            for item in required_responses
            if not item.get("error") or _kubernetes_exact_absence(item)
        ]
        if required_failures and "kubernetes.query" not in missing:
            missing.append("kubernetes.query")
        pod_statuses = _pod_statuses(responses)
        warning_events = _warning_events(responses)
        target_described_events = (
            None
            if target_pod_describe.get("identity_mismatch")
            else target_pod_describe.get("events")
        )
        if isinstance(target_described_events, list):
            warning_events.extend(
                _event_summary(event, target=target)
                for event in target_described_events
                if isinstance(event, dict) and event.get("type") == "Warning"
            )
        if pod_summary_data and workload_resolution.get("selected_pod"):
            pod_statuses.append(pod_summary_data)
        described_events = resolved_pod_describe.get("events")
        if isinstance(described_events, list):
            warning_events.extend(
                _event_summary(
                    event, target=target, resolved_pod_anchor=resolved_pod_anchor
                )
                for event in described_events
                if isinstance(event, dict) and event.get("type") == "Warning"
            )
        warning_events = _dedupe_warning_events(warning_events)
        causal_warning_events = _warning_events_in_time_range(
            warning_events, causal_time_range
        )
        # Namespace/control-plane Event messages remain useful context, but the
        # causal Event card is allowed to support RCA only with an involved
        # object that proves the concrete alert target. Mixing a message-only
        # Event into the same aggregate used to demote (or contaminate) the
        # otherwise exact target evidence.
        causal_target_warning_events = (
            [
                event
                for event in causal_warning_events
                if event.get("target_identity_verified") is True
            ]
            if _warning_events_are_target_scoped(target)
            else causal_warning_events
        )
        gpu_node_resource_observations = await _collect_gpu_node_resource_observations(
            self._settings,
            target,
            plan,
            causal_target_warning_events,
        )
        node_conditions = _node_conditions(responses)
        runai_control_plane_pods = _runai_control_plane_pods(responses)
        runai_control_plane_events = _runai_control_plane_warning_events(responses)

        # Run:ai CRD enumeration: when the alert is in a Run:ai namespace, read
        # the actual project/queue/workload/podgroup CRDs (status.conditions) so
        # a control-plane alert with NO workload label still yields "project X
        # not Ready" instead of "can't correlate". Best-effort, MCP-first.
        runai_crds: dict[str, object] = {"checked": [], "findings": []}
        if control_plane_in_scope:
            crd_namespaces = [target.namespace, *self._settings.runai_log_namespaces]
            try:
                runai_crds = await collect_runai_crd_findings(
                    self._settings, target, crd_namespaces
                )
            except Exception:  # noqa: BLE001 - enumeration is best-effort
                pass
        crd_findings = runai_crds.get("findings") or []
        warnings.extend(str(item) for item in runai_crds.get("warnings") or [])
        if runai_crds.get("truncated"):
            warnings.append(
                "Run:ai CRD scan was truncated after five pages for "
                + ", ".join(map(str, runai_crds["truncated"]))
                + "."
            )

        if required_completed and not required_failures and not missing:
            status = "ok"
            confidence = "high"
            summary = ko_en(
                self._settings,
                "알림 대상에 대한 Kubernetes 조회를 완료했습니다.",
                "Kubernetes API queries completed for the resolved alert target.",
            )
        elif successful or required_completed:
            status = "partial"
            confidence = "medium"
            if required_failures:
                failed_names = ", ".join(
                    str(item.get("name") or "query") for item in required_failures
                )
                summary = ko_en(
                    self._settings,
                    "Kubernetes 대상 쿼리 일부가 실패했습니다. 성공한 쿼리 증거는 "
                    f"유지했습니다. 실패: {failed_names}.",
                    "Kubernetes target queries were incomplete; usable per-query "
                    f"evidence was retained. Failed: {failed_names}.",
                )
            else:
                summary = ko_en(
                    self._settings,
                    "Kubernetes API에는 접속했지만 알림 대상 정보가 불완전합니다. "
                    "네임스페이스/파드/워크로드/노드 레이블이 없을 수 있습니다.",
                    "Kubernetes API is reachable, but the alert target is incomplete. "
                    "Namespace, pod, workload, or node labels may be missing.",
                )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "네임스페이스가 범위 설정에서 제외되어 Kubernetes 조회를 건너뛰었습니다."
                if target.namespace and not target.node and not _namespace_allowed(self._settings, target.namespace)
                else "Kubernetes API 조회가 실패했습니다.",
                "Kubernetes queries were skipped because the namespace is excluded by scope configuration."
                if target.namespace and not target.node and not _namespace_allowed(self._settings, target.namespace)
                else "Kubernetes API direct queries failed.",
            )

        # The alert names a pod that no longer exists (and left no live sibling
        # or events): say so — it IS the finding. Without this the report blames
        # whatever keyword noise survives, when the truth is "already replaced /
        # recovered, or a stale alert".
        target_pod_missing = _target_pod_missing(target, responses)
        if target_pod_missing:
            note = (
                f"알림 대상 pod '{target.pod}'은(는) 현재 클러스터에 존재하지 않습니다 — "
                "이미 교체/복구되었거나 오래된 알림일 수 있습니다."
                if self._settings.language == "ko"
                else (
                    f"The alerted pod '{target.pod}' no longer exists in the cluster — "
                    "it may have been replaced/recovered already, or the alert is stale."
                )
            )
            summary = f"{note} {summary}"

        # A CRD finding IS the correlation the missing label denied us: name the
        # not-Ready Run:ai entities and lift the result out of "partial".
        if crd_findings:
            named = ", ".join(f"{f['kind']}/{f['name']} ({f['reason']})" for f in crd_findings[:3])
            lead = ko_en(
                self._settings,
                f"정상 상태가 아닌 Run:ai 리소스 {len(crd_findings)}건 확인: {named}.",
                f"Found {len(crd_findings)} Run:ai resource(s) not Ready: {named}.",
            )
            summary = f"{lead} {summary}"
            if status != "ok" and not required_failures:
                status, confidence = "ok", "high"

        if _pod_event_scope_empty(responses):
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "조회한 범위에서 파드 또는 이벤트가 관찰되지 않았습니다.",
                "No pods or events were observed for the queried scope.",
            )
            confidence = "low"

        insight = await _senior_insight(
            self._settings,
            summary=summary,
            container_diagnostics=container_diagnostics,
            warning_events=causal_target_warning_events,
            logs=_verified_logs_in_time_range(logs, causal_time_range),
            # A denied/unavailable exec capability is collection metadata, not
            # a workload observation for the insight model to explain.
            exec_probes=[probe for probe in exec_probes if not probe.get("error")],
        )

        details = {
            "kubernetes_api_url": self._settings.kubernetes_api_url,
            "kubernetes_mcp_url": self._settings.kubernetes_mcp_url,
            "used_mcp": used_mcp,
            "time_range": time_range,
            "causal_time_range": causal_time_range,
            "target_pod_missing": target_pod_missing,
            "kubernetes_namespaces": self._settings.kubernetes_namespaces,
            "kubernetes_cluster_scope_enabled": self._settings.kubernetes_cluster_scope_enabled,
            "namespace": target.namespace,
            "pod": target.pod,
            "resolved_pod": workload_resolution.get("selected_pod", ""),
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "node": target.node,
            "pod_statuses": pod_statuses,
            "container_diagnostics": container_diagnostics,
            "warning_events": warning_events,
            "gpu_node_resource_observations": gpu_node_resource_observations,
            "node_conditions": node_conditions,
            "pod_logs": logs,
            "target_pod_describe": target_pod_describe,
            "workload_resolution": workload_resolution,
            "resolved_pod_describe": resolved_pod_describe,
            "exec_probes": exec_probes,
            "runai_control_plane_pods": runai_control_plane_pods,
            "runai_control_plane_warning_events": runai_control_plane_events,
            "runai_crd_findings": crd_findings,
            "runai_crds_checked": runai_crds.get("checked"),
            "runai_crd_failed_kinds": runai_crds.get("failed_kinds"),
            "runai_crd_truncated": runai_crds.get("truncated"),
            "insight": insight,
            "queries": responses,
        }
        if insight:
            summary = f"{summary} {insight}"

        artifacts = [
            artifact(
                agent=self.name,
                source="kubernetes",
                type="cluster_api",
                status=status,
                confidence=confidence,
                query="; ".join(item["path"] for item in responses),
                summary=summary,
                # The broad sweep includes live Pod/Node snapshots. Keep it
                # available to operators, but do not let a current-state
                # summary masquerade as a historical root-cause predicate.
                result={
                    **details,
                    "observation": {
                        "kind": "kubernetes_collector_summary",
                        "predicate": "kubernetes_collector_summary",
                        "polarity": "unknown",
                        "coverage": "partial",
                    },
                },
            )
        ]
        artifacts.append(_pod_lifecycle_artifact(self.name, target, responses))
        artifacts.append(
            _container_lifecycle_artifact(
                self.name,
                self._settings,
                target,
                pod_summary_data,
                container_diagnostics,
                time_range=causal_time_range,
            )
        )
        artifacts.extend(
            _runai_crd_health_artifacts(
                self.name,
                self._settings,
                crd_findings,
                time_range=causal_time_range,
            )
        )
        event_observation = _warning_event_observation(
            causal_target_warning_events,
            time_range=causal_time_range,
            status=status,
            target_scoped=_warning_events_are_target_scoped(target),
            queries_complete=_warning_event_queries_complete(responses),
            target=target,
            resolved_pod_anchor=resolved_pod_anchor,
        )
        artifacts.append(
            artifact(
                agent=self.name,
                source="kubernetes",
                type="kubernetes_warning_events",
                status="unavailable" if event_observation["polarity"] == "unavailable" else "ok",
                confidence=(
                    "high"
                    if event_observation["polarity"] in {"present", "absent"}
                    else "low"
                ),
                title=ko_en(
                    self._settings,
                    "원인 시간창 Warning 이벤트",
                    "Causal-window Warning events",
                ),
                query=kubectl_repr("events", namespace=target.namespace),
                summary=ko_en(
                    self._settings,
                    (
                        "원인 시간창에서 대상이 확인된 Warning 이벤트 "
                        f"{len(causal_target_warning_events)}건을 확인했습니다."
                        if causal_target_warning_events
                        else "원인 시간창에 대상이 확인된 Warning 이벤트가 없습니다."
                    ),
                    (
                        "Collected "
                        f"{len(causal_target_warning_events)} target-verified Warning event(s) "
                        "in the causal window."
                        if causal_target_warning_events
                        else "No target-verified Warning events in the causal window."
                    ),
                ),
                result={
                    "observation": event_observation,
                    "events": causal_target_warning_events,
                    "time_range": causal_time_range,
                    "collection_time_range": time_range,
                },
            )
        )
        artifacts.extend(
            _node_condition_artifacts(
                self.name,
                target,
                responses,
                time_range=causal_time_range,
            )
        )
        artifacts.extend(
            _node_cordon_artifact(
                self.name,
                target,
                responses,
                time_range=causal_time_range,
            )
        )
        artifacts.extend(
            _gpu_node_resource_artifact(self.name, self._settings, snapshot)
            for snapshot in gpu_node_resource_observations
        )
        # Container logs are collected with ``sinceTime`` and can include a
        # restarted container's ``previous`` instance. Keep them distinct from
        # live YAML/describe/exec state. A tail-limited logs endpoint cannot
        # prove absence, but API-timestamped lines inside the causal window are
        # precise positive evidence. Recovery-epilogue lines stay in details,
        # outside the card that semantic ranking can use as causal support.
        artifacts.extend(
            _pod_log_artifact(self.name, log, time_range=causal_time_range)
            for log in logs
        )
        if target_pod_describe:
            describe_error = target_pod_describe.get("error")
            describe_events_error = target_pod_describe.get("events_error")
            describe_events = target_pod_describe.get("events")
            event_count = len(describe_events) if isinstance(describe_events, list) else 0
            snapshot_observation: dict[str, object] = {
                "kind": "kubernetes_pod_snapshot",
                "predicate": "kubernetes_pod_snapshot",
                # YAML/describe is a live snapshot. Do not let the pipeline's
                # broad incident window stand in for an occurrence time.
                "polarity": "unknown",
                "coverage": "partial",
                "observation_window": {},
            }
            described_entity = _pod_log_observed_entity(
                {"observed_entity": target_pod_describe.get("observed_entity")}
            )
            if described_entity:
                snapshot_observation["observed_entity"] = described_entity
            artifacts.append(
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="pod_inspection",
                    # A failed events read must not discard the successfully
                    # collected Pod YAML from the usable evidence set.
                    status=(
                        "unavailable"
                        if describe_error
                        else "partial"
                        if describe_events_error
                        else "ok"
                    ),
                    confidence=(
                        "high" if not describe_error and not describe_events_error else "low"
                    ),
                    title=ko_en(self._settings, "Pod YAML + 상세 점검", "Pod YAML + describe"),
                    query=pod_inspection_repr(target.namespace, target.pod),
                    summary=(
                        str(describe_error)
                        if describe_error
                        else (
                            ko_en(
                                self._settings,
                                "Pod 전체 YAML을 수집했지만 incident 시간창 이벤트 조회를 "
                                f"완료하지 못했습니다: {describe_events_error}",
                                "Collected full Pod YAML, but the incident-window events read was "
                                f"unavailable: {describe_events_error}",
                            )
                            if describe_events_error
                            else ko_en(
                            self._settings,
                            (
                                "Pod 전체 YAML과 incident 시간창 이벤트 "
                                f"{event_count}건을 확인했습니다."
                            ),
                            f"Collected full Pod YAML and {event_count} incident-window event(s).",
                            )
                        )
                    ),
                    # YAML is a live inspection; its filtered events are
                    # represented by the dedicated historical event artifact.
                    result={
                        **target_pod_describe,
                        "observation": snapshot_observation,
                    },
                )
            )
        if exec_probes:
            exec_successes = [probe for probe in exec_probes if not probe.get("error")]
            # A probe that couldn't START (binary absent, exec subresource down) is
            # not a finding — exclude it so "command not found" never becomes a
            # medium card (owner rule: a probe that can't run is not evidence).
            real_errors = [
                str(probe.get("error"))
                for probe in exec_probes
                if probe.get("error")
                and not probe.get("transport_error")
                and not _exec_probe_unusable(str(probe.get("error")))
            ]
            # Nothing usable ran: no successful probe and no real error to report.
            exec_unavailable = not exec_successes and not real_errors
            exec_observation: dict[str, object] = {
                "kind": "kubernetes_live_exec",
                "predicate": "kubernetes_live_exec",
                # Exec output has exact Pod provenance but is sampled now; it
                # cannot establish a condition during a past incident.
                "polarity": "unavailable" if exec_unavailable else "unknown",
                "coverage": "unknown" if exec_unavailable else "partial",
                "observation_window": {},
            }
            exec_entity = _exec_probes_observed_entity(exec_probes)
            if exec_entity:
                exec_observation["observed_entity"] = exec_entity
            if exec_unavailable:
                # Probes couldn't run (e.g. the binaries aren't in a minimal image);
                # mark no-evidence so the trail hides it instead of showing errors.
                exec_summary = f"{NO_EVIDENCE} " + ko_en(
                    self._settings,
                    "컨테이너에서 진단 명령을 실행할 수 없었습니다 (해당 바이너리 없음 또는 exec 불가).",
                    "Diagnostic commands could not run in the container (binaries absent or exec unavailable).",
                )
            elif real_errors:
                exec_summary = "; ".join(real_errors)
            else:
                exec_summary = ko_en(
                    self._settings,
                    f"읽기 전용 진단 명령 {len(exec_successes)}개를 실행했습니다.",
                    f"Executed {len(exec_successes)} read-only diagnostic command(s).",
                )
            artifacts.append(
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="pod_exec",
                    status=(
                        "unavailable" if exec_unavailable else "partial" if real_errors else "ok"
                    ),
                    confidence=("low" if exec_unavailable else "medium" if real_errors else "high"),
                    title=ko_en(
                        self._settings, "컨테이너 읽기 전용 exec", "Read-only container exec"
                    ),
                    query="; ".join(
                        f"kubectl exec {target.pod} -n {target.namespace} -- {probe['command']}"
                        for probe in exec_probes
                    ),
                    summary=exec_summary,
                    result={
                        "probes": exec_probes,
                        "observation": exec_observation,
                    },
                )
            )

        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=details,
            missing_data=missing,
            warnings=warnings,
            artifacts=artifacts,
        )


def _warning_event_observation(
    warning_events: list[dict[str, object]],
    *,
    time_range: dict[str, str] | None,
    status: str,
    target_scoped: bool = True,
    queries_complete: bool = True,
    target: AnalysisTarget | None = None,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> dict[str, object]:
    """Make filtered event presence/absence a typed historical predicate."""
    observed_entity = _event_target_entity(target) if target is not None else None
    event_uids = {
        str(event.get("uid") or "")
        for event in warning_events
        if str(event.get("uid") or "")
    }
    identity_ambiguous = bool(
        target is not None
        and target.pod
        and not target.pod_uid
        and len(event_uids) > 1
    )
    verified_events = bool(warning_events) and all(
        event.get("target_identity_verified") is True
        and event.get("observed_entity") == observed_entity
        for event in warning_events
    ) and not identity_ambiguous
    # A workload-only alert can retain controller Events, but a returned child
    # Pod Event must also carry the exact live-Pod verification that admitted it
    # through the response filter.
    if resolved_pod_anchor and any(
        str(event.get("kind") or "").casefold() == "pod" for event in warning_events
    ):
        verified_events = verified_events and any(
            event.get("target_identity_anchor_verified") is True
            for event in warning_events
        )
    if status == "unavailable":
        polarity, coverage = "unavailable", "unknown"
    elif not target_scoped or (target is not None and observed_entity is None):
        # A namespace-only event list says nothing about this alert's resource.
        # Do not turn its emptiness into a false negative for the incident.
        polarity, coverage = "unknown", "partial"
    elif warning_events:
        # One returned, target-correlated event is a fact even if another Event
        # source failed. Query completeness is required only to turn EMPTY into
        # an absence claim.
        polarity, coverage = (
            ("present", "scoped")
            if time_range and (target is None or verified_events)
            else ("present", "partial")
        )
    elif not queries_complete:
        polarity, coverage = "unknown", "partial"
    elif not time_range:
        # Without alert timestamps the Events API read remains useful context,
        # but an empty list is not a time-bounded negative.
        polarity, coverage = "unknown", "partial"
    else:
        polarity, coverage = "absent", "scoped"
    observation = {
        "kind": "kubernetes_warning_events",
        "predicate": "kubernetes_warning_events",
        "polarity": polarity,
        "coverage": coverage,
        "event_count": len(warning_events),
        "target_scoped": target_scoped,
        "target_identity_verified": verified_events,
        "target_identity_ambiguous": identity_ambiguous,
        "queries_complete": queries_complete,
        "observation_window": time_range or {},
    }
    if observed_entity:
        observation["observed_entity"] = observed_entity
    # Event list reads intentionally include the post-resolution collection
    # epilogue.  Keep the returned Event occurrence span distinct from that
    # query coverage so an Event first seen only after recovery cannot become
    # causal support merely because it was in the same API response.
    if polarity == "present":
        evidence_window = _warning_event_evidence_window(warning_events, time_range)
        if evidence_window:
            observation["evidence_window"] = evidence_window
    return observation


def _warning_event_evidence_window(
    warning_events: list[dict[str, object]], time_range: dict[str, str] | None
) -> dict[str, str]:
    """Return the actual timestamp span carried by filtered Warning Events."""
    if not time_range:
        return {}
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return {}
    timestamps: list[tuple[object, str]] = []
    for event in warning_events:
        values = event.get("observedTimestamps")
        if not isinstance(values, list):
            values = [event.get("lastTimestamp")]
        for raw in values:
            parsed = parse_incident_time(raw)
            if parsed is not None and start <= parsed <= end:
                timestamps.append((parsed, str(raw)))
    if not timestamps:
        return {}
    timestamps.sort(key=lambda item: item[0])
    return {"start": timestamps[0][1], "end": timestamps[-1][1]}


def _warning_events_in_time_range(
    warning_events: list[dict[str, object]], time_range: dict[str, str] | None
) -> list[dict[str, object]]:
    """Project summarized Events onto one occurrence window.

    Collection keeps a short recovery epilogue.  The causal artifact must not
    aggregate a benign incident-time Event with a failure first observed after
    resolution, because the aggregate span would overlap and make both texts
    eligible. Repeating Events are retained when any observation is in range,
    but their projected timestamp list is trimmed to that range.
    """
    if not time_range:
        return [dict(event) for event in warning_events]
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return []
    projected: list[dict[str, object]] = []
    for event in warning_events:
        values = event.get("observedTimestamps")
        if not isinstance(values, list):
            values = [event.get("lastTimestamp")]
        retained: list[tuple[object, str]] = []
        for raw in values:
            observed_at = parse_incident_time(raw)
            if observed_at is not None and start <= observed_at <= end:
                retained.append((observed_at, str(raw)))
        if not retained:
            continue
        retained.sort(key=lambda item: item[0])
        item = dict(event)
        item["observedTimestamps"] = [raw for _, raw in retained]
        item["lastTimestamp"] = retained[-1][1]
        projected.append(item)
    return projected


def _dedupe_warning_events(
    warning_events: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Remove duplicate Event projections returned by sweep and describe."""
    seen: set[tuple[object, ...]] = set()
    deduped: list[dict[str, object]] = []
    for event in warning_events:
        timestamps = event.get("observedTimestamps")
        key = (
            event.get("type"),
            event.get("reason"),
            event.get("message"),
            event.get("object"),
            event.get("kind"),
            event.get("namespace"),
            event.get("uid"),
            tuple(str(value) for value in timestamps)
            if isinstance(timestamps, list)
            else (str(event.get("lastTimestamp") or ""),),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _warning_event_queries_complete(responses: list[dict[str, object]]) -> bool:
    """Whether every Event list completed without an omitted next page."""
    event_responses = [
        response
        for response in responses
        if str(response.get("name") or "")
        in {"pod_events", "workload_events", "namespace_events"}
        or str(response.get("name") or "").startswith("runai_control_plane_events:")
    ]
    return bool(event_responses) and all(
        not response.get("error")
        and response.get("list_complete", True)
        and response.get("event_time_complete", True)
        for response in event_responses
    )


def _pod_log_artifact(
    agent: str, log: dict[str, object], *, time_range: dict[str, str] | None
):
    """Represent one Pod log request without turning a tail into a negative."""
    observation, entries = _pod_log_observation(log, time_range=time_range)
    previous = bool(log.get("previous"))
    container = str(log.get("container") or "default")
    label = f"previous {container}" if previous else container
    polarity = str(observation["polarity"])
    if polarity == "present":
        summary = (
            f"Kubernetes Pod log {label}: {len(entries)} timestamped line(s) "
            "inside incident window."
        )
    elif polarity == "unavailable":
        summary = f"Kubernetes Pod log {label}: log request was unavailable."
    else:
        summary = (
            f"Kubernetes Pod log {label}: no timestamped line could be confirmed "
            "inside incident window."
        )
    return artifact(
        agent=agent,
        source="kubernetes",
        type="kubernetes_pod_log",
        status="unavailable" if polarity == "unavailable" else "ok",
        confidence="high" if polarity == "present" else "low",
        title=f"Kubernetes · Pod log · {label}",
        query=f"kubectl logs <pod> -c {container}" + (" --previous" if previous else ""),
        summary=summary,
        result={
            "observation": observation,
            "container": container,
            "previous": previous,
            "sample_entries": entries[:8],
        },
    )


def _pod_log_observation(
    log: dict[str, object], *, time_range: dict[str, str] | None
) -> tuple[dict[str, object], list[dict[str, str]]]:
    """Return only time-bounded log lines; logs API tails never prove absence."""
    source_verified = log.get("source_verified") is True
    # Backward-compatible default for direct/fabricated observations. Current
    # MCP paths explicitly set False when the server could not request an
    # incident bound or Kubernetes-generated timestamps.
    time_scope_verified = log.get("time_scope_verified") is not False
    if log.get("error"):
        polarity, coverage, entries = "unavailable", "unknown", []
    elif not source_verified:
        # An MCP text response that does not identify its Pod may contain a
        # real failure line, but cannot be attributed to this incident's
        # entity. Keep it visible as context, never scoped causal support.
        polarity, coverage = "unknown", "partial"
        entries = _log_entries_in_window(log.get("lines"), time_range or {})
    elif not time_scope_verified:
        # Application text can begin with something that looks like RFC3339,
        # but an unbounded MCP tail cannot prove that it is a Kubernetes log
        # timestamp or that it came from the historical Pod incarnation.
        polarity, coverage = "unknown", "partial"
        entries = _log_entries_in_window(log.get("lines"), time_range or {})
    elif not time_range:
        polarity, coverage, entries = "unknown", "partial", []
    else:
        entries = _log_entries_in_window(log.get("lines"), time_range)
        polarity, coverage = (
            ("present", "scoped") if entries else ("unknown", "partial")
        )
    observed_entity = _pod_log_observed_entity(log) if source_verified else None
    if polarity in {"present", "absent"} and observed_entity is None:
        # The direct API URL or structured MCP response must name both the
        # namespace and Pod. Requested arguments alone are not evidence that
        # an MCP adapter actually returned that resource.
        polarity, coverage = "unknown", "partial"
    container = str(log.get("container") or "default")
    predicate = f"kubernetes_pod_log:{'previous:' if log.get('previous') else ''}{container}"
    observation = {
        "kind": "kubernetes_pod_log",
        "predicate": predicate,
        "polarity": polarity,
        "coverage": coverage,
        "previous": bool(log.get("previous")),
        "source_verified": source_verified,
        "time_scope_verified": time_scope_verified,
        "observation_window": time_range or {},
    }
    if observed_entity:
        observation["observed_entity"] = observed_entity
    if polarity == "present" and entries:
        observation["evidence_window"] = {
            "start": entries[0]["timestamp"],
            "end": entries[-1]["timestamp"],
        }
    return observation, entries


def _verified_logs_in_time_range(
    logs: list[dict[str, object]], time_range: dict[str, str] | None
) -> list[dict[str, object]]:
    """Return only verified, in-window lines for the narrative insight helper."""
    projected: list[dict[str, object]] = []
    for log in logs:
        observation, entries = _pod_log_observation(log, time_range=time_range)
        if observation.get("polarity") != "present":
            continue
        projected.append(
            {
                **log,
                "lines": [f"{entry['timestamp']} {entry['line']}" for entry in entries],
            }
        )
    return projected


def _pod_log_observed_entity(log: dict[str, object]) -> dict[str, str] | None:
    """Validate the namespaced Pod provenance attached by the log transport."""
    candidate = log.get("observed_entity")
    if not isinstance(candidate, dict):
        return None
    kind = str(candidate.get("kind") or candidate.get("type") or "").strip().lower()
    name = str(candidate.get("name") or candidate.get("id") or "").strip()
    namespace = str(candidate.get("namespace") or "").strip()
    if kind not in {"pod", "pods"} or not name or not namespace:
        return None
    return _pod_log_entity(namespace, name)


def _log_entries_in_window(
    lines: object, time_range: dict[str, str]
) -> list[dict[str, str]]:
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None:
        return []
    entries: list[dict[str, str]] = []
    for value in lines if isinstance(lines, list) else []:
        line = str(value).strip()
        timestamp, _, message = line.partition(" ")
        observed_at = parse_incident_time(timestamp)
        if observed_at is None or not (start <= observed_at <= end):
            continue
        entries.append({"timestamp": timestamp, "line": message or line})
    # MCP implementations are not required to return log lines in timestamp
    # order.  The evidence window must describe the actual earliest/latest
    # retained line, not transport order.
    entries.sort(key=lambda entry: parse_incident_time(entry["timestamp"]) or start)
    return entries


async def _collect_kubernetes_responses(
    *,
    settings: Settings,
    target: AnalysisTarget,
    headers: dict[str, str],
    verify: bool | str,
    control_plane_in_scope: bool = True,
    resolved_pod_anchor: AnalysisTarget | None = None,
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
    # A Run:ai scheduling Warning is commonly attached to PodGroup/workload,
    # not to the concrete Pod named by the alert.  Query that exact declared
    # identity even when a Pod is also present; otherwise a successful Pod-only
    # read silently drops the strongest scheduling evidence.
    if target.namespace and target_namespace_allowed and target.workload_name:
        requests.append(
            (
                "workload_events",
                f"/api/v1/namespaces/{namespace}/events",
                _list_params(
                    settings,
                    {"fieldSelector": f"involvedObject.name={target.workload_name}"},
                ),
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
                "list_complete": _kubernetes_list_complete(response.data),
                "event_time_complete": _event_time_range_complete(
                    name, response.data, target, resolved_pod_anchor=resolved_pod_anchor
                ),
                "data": compact(
                    _filter_kubernetes_data(
                        name, response.data, target, resolved_pod_anchor=resolved_pod_anchor
                    ),
                    limit=5,
                ),
            }
        )
    return responses


async def _collect_kubernetes_responses_via_mcp(
    *,
    settings: Settings,
    target: AnalysisTarget,
    control_plane_in_scope: bool = True,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> list[dict[str, object]]:
    """The base sweep over the Kubernetes MCP service.

    Per-query errors are OBSERVATIONS, not transport failures: a dead alert pod
    404ing its GET used to raise out of the first query and demote the WHOLE
    sweep to the direct API (so MCP looked permanently unused). Mirror the
    direct sweep: record {name, error} and keep going. Only when EVERY query
    errored (transport truly down) does this raise so collect() falls back."""
    responses: list[dict[str, object]] = []
    ok_count = 0

    async def block(name: str, label: str, candidates: list[tuple[str, dict[str, object]]]) -> None:
        nonlocal ok_count
        try:
            data = await _k8s_mcp_json(settings, candidates)
        except TimeoutError:
            # The shared collector deadline is a transport-level stop, not a
            # target query observation. Propagate it even after earlier MCP
            # calls succeeded so collect() can still use the direct API.
            raise
        except Exception as exc:  # noqa: BLE001 - a per-query miss is evidence
            responses.append(
                {
                    "name": name,
                    "path": label,
                    "url": label,
                    "status_code": None,
                    "error": str(exc),
                    "data": None,
                }
            )
            return
        ok_count += 1
        responses.append(
            _mcp_k8s_response(
                name, label, data, target, resolved_pod_anchor=resolved_pod_anchor
            )
        )

    target_namespace_allowed = _namespace_allowed(settings, target.namespace)
    if target.namespace and target_namespace_allowed and target.pod:
        await block(
            "pod",
            "MCP pods_get",
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
        await block(
            "pod_events",
            "MCP resources_list Event",
            [
                (
                    "resources_list",
                    {
                        "apiVersion": "v1",
                        "kind": "Event",
                        "namespace": target.namespace,
                        "fieldSelector": f"involvedObject.name={target.pod}",
                    },
                ),
                ("events_list", {"namespace": target.namespace}),
            ],
        )
    elif target.namespace and target_namespace_allowed:
        await block(
            "namespace_pods",
            "MCP pods_list",
            [
                ("pods_list_in_namespace", {"namespace": target.namespace}),
                ("pods_list", {"namespace": target.namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Pod", "namespace": target.namespace},
                ),
            ],
        )
        await block(
            "namespace_events",
            "MCP events_list",
            [
                ("events_list", {"namespace": target.namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Event", "namespace": target.namespace},
                ),
            ],
        )
    if target.namespace and target_namespace_allowed and target.workload_name:
        await block(
            "workload_events",
            "MCP resources_list Event for workload",
            [
                (
                    "resources_list",
                    {
                        "apiVersion": "v1",
                        "kind": "Event",
                        "namespace": target.namespace,
                        "fieldSelector": (
                            f"involvedObject.name={target.workload_name}"
                        ),
                    },
                ),
                ("events_list", {"namespace": target.namespace}),
            ],
        )
    if target.node and settings.kubernetes_cluster_scope_enabled:
        await block(
            "node",
            "MCP resources_get node",
            [
                (
                    "resources_get",
                    {"apiVersion": "v1", "kind": "Node", "name": target.node},
                ),
                ("resources_get", {"kind": "nodes", "name": target.node}),
            ],
        )
    for runai_namespace in settings.runai_log_namespaces if control_plane_in_scope else ():
        if not _namespace_allowed(settings, runai_namespace):
            continue
        await block(
            f"runai_control_plane_pods:{runai_namespace}",
            f"MCP pods_list {runai_namespace}",
            [
                ("pods_list_in_namespace", {"namespace": runai_namespace}),
                ("pods_list", {"namespace": runai_namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Pod", "namespace": runai_namespace},
                ),
            ],
        )
        await block(
            f"runai_control_plane_events:{runai_namespace}",
            f"MCP events_list {runai_namespace}",
            [
                ("events_list", {"namespace": runai_namespace}),
                (
                    "resources_list",
                    {"apiVersion": "v1", "kind": "Event", "namespace": runai_namespace},
                ),
            ],
        )
    if responses and ok_count == 0:
        first_error = next((str(r.get("error")) for r in responses if r.get("error")), "")
        raise RuntimeError(first_error or "every Kubernetes MCP query failed")
    return responses


def _mcp_k8s_response(
    name: str,
    path: str,
    data: object,
    target: AnalysisTarget,
    *,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> dict[str, object]:
    normalized = _normalize_k8s_payload(data)
    return {
        "name": name,
        "path": path,
        "url": path,
        "status_code": 200,
        "error": None,
        # A bare MCP array (or an items-only wrapper) carries no Kubernetes
        # List metadata.  It may be a server-side capped page, so it must not
        # turn an empty historical Event result into a scoped absence claim.
        "list_complete": _mcp_kubernetes_list_complete(normalized),
        "event_time_complete": _event_time_range_complete(
            name, normalized, target, resolved_pod_anchor=resolved_pod_anchor
        ),
        "data": compact(
            _filter_kubernetes_data(
                name, normalized, target, resolved_pod_anchor=resolved_pod_anchor
            ),
            limit=5,
        ),
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


def _kubernetes_list_complete(data: object) -> bool:
    """Return false when a Kubernetes list response advertises another page.

    Both the direct client and resources_list MCP tools may return a normal 200
    response with ``metadata.continue``. The display projection intentionally
    drops metadata, so preserve this bit before filtering to prevent an empty
    first page from becoming a false incident-window absence verdict.
    """
    payload = _normalize_k8s_payload(data)
    if not isinstance(payload, dict):
        return True
    metadata = payload.get("metadata")
    return not (isinstance(metadata, dict) and bool(metadata.get("continue")))


def _mcp_kubernetes_list_complete(data: object) -> bool:
    """Whether an MCP list proves it returned the final Kubernetes page.

    The direct Kubernetes API always supplies List metadata.  MCP tool
    adapters, however, can flatten a response to ``items`` or a bare array;
    without metadata there is no way to distinguish a complete empty list from
    a truncated first page.
    """
    payload = _normalize_k8s_payload(data)
    if not isinstance(payload, dict):
        return False
    metadata = payload.get("metadata")
    return isinstance(metadata, dict) and not bool(metadata.get("continue"))


async def _k8s_mcp_json(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
) -> object:
    async with mcp_budget(settings.kubernetes_timeout_seconds):
        return await _k8s_mcp_json_within_budget(settings, candidates)


async def _k8s_mcp_json_within_budget(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
) -> object:
    # Walk candidates and return the first one that yields a machine-readable
    # payload. A candidate can "succeed" at the MCP protocol level yet answer with
    # a human table (kubernetes-mcp-server's events_list does) that _k8s_yaml_payload
    # can't parse — when that happens, fall through to the next candidate (e.g.
    # resources_list, which honors --list-output=yaml) instead of raising and
    # losing the evidence to the direct-API fallback.
    last_error = ""
    for tool, args in candidates:
        try:
            result = await mcp_call(settings.kubernetes_mcp_url, tool, args)
        except TimeoutError:
            raise
        except Exception as exc:  # noqa: BLE001 - try the next schema candidate.
            last_error = f"{tool}: {exc.__class__.__name__}: {exc}"
            continue
        error = mcp_error(result)
        if error:
            last_error = f"{tool}: {error}"
            continue
        try:
            data = _k8s_mcp_payload(result)
        except RuntimeError as exc:
            last_error = f"{tool}: {exc}"
            continue
        if not _k8s_mcp_payload_recognized(data, tool=tool):
            last_error = f"{tool}: MCP response missing a Kubernetes object/list payload"
            continue
        return data
    raise RuntimeError(last_error or "Kubernetes MCP tool failed")


_KUBERNETES_GO_KEY_ALIASES = {
    "APIVersion": "apiVersion",
    "EventTime": "eventTime",
    "FirstTimestamp": "firstTimestamp",
    "InvolvedObject": "involvedObject",
    "Items": "items",
    "Kind": "kind",
    "LastTimestamp": "lastTimestamp",
    "Message": "message",
    "Metadata": "metadata",
    "Name": "name",
    "Namespace": "namespace",
    "Reason": "reason",
    "Series": "series",
    "Spec": "spec",
    "Status": "status",
    # Some kubectl-get-events-style adapters expose the legacy Event time as
    # Timestamp. Preserve it as the canonical legacy Event occurrence field.
    "Timestamp": "lastTimestamp",
    "Type": "type",
    "UID": "uid",
}
_KUBERNETES_METADATA_VALUE_KEYS = frozenset({"annotations", "data", "labels"})


def _canonicalize_kubernetes_payload(value: object, *, metadata_values: bool = False) -> object:
    """Normalize MCP Go-field payloads before masking and evidence projection."""
    if isinstance(value, list):
        return [
            _canonicalize_kubernetes_payload(item, metadata_values=metadata_values)
            for item in value
        ]
    if not isinstance(value, dict):
        return value
    normalized: dict[object, object] = {}
    for key, item in value.items():
        canonical_key = (
            _KUBERNETES_GO_KEY_ALIASES.get(key, key)
            if isinstance(key, str) and not metadata_values
            else key
        )
        normalized[canonical_key] = _canonicalize_kubernetes_payload(
            item,
            metadata_values=canonical_key in _KUBERNETES_METADATA_VALUE_KEYS,
        )
    return normalized


def _k8s_mcp_payload(result: object) -> object:
    """Parse, normalize, then mask one Kubernetes MCP reply.

    MCP responses may serialize Kubernetes Go struct fields rather than the
    JSON field names consumed by the collector. Normalization belongs at this
    transport boundary so all downstream identity, time, and signal code sees
    one canonical schema without altering arbitrary metadata values.
    """
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        parsed = structured
    else:
        text = mcp_tool_raw_text(result)
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            parsed = _parse_k8s_yaml_payload(text)
    if not isinstance(parsed, (dict, list)):
        raise RuntimeError("MCP result was not JSON or YAML (set --list-output=yaml)")
    return build_masker(()).mask_object(_canonicalize_kubernetes_payload(parsed))


def _k8s_yaml_payload(text: str) -> object:
    """Return a masked Kubernetes YAML reply for compatibility callers.

    Parsing occurs before masking so secret-shaped values cannot corrupt YAML
    syntax. The MCP transport uses the same parser, then normalizes Go-field
    keys before applying this mask.
    """
    return build_masker(()).mask_object(_parse_k8s_yaml_payload(text))


def _parse_k8s_yaml_payload(text: str) -> object:
    """Parse a Kubernetes YAML reply without masking it first.

    Raises on table/plain text so the caller records an observation."""
    try:
        parsed = yaml.safe_load(text or "")
    except yaml.YAMLError:
        try:
            docs = [doc for doc in yaml.safe_load_all(text or "") if doc is not None]
        except yaml.YAMLError as exc:
            raise RuntimeError(f"MCP result was not JSON or YAML: {exc}") from exc
        parsed = docs[0] if len(docs) == 1 else {"items": docs}
    if isinstance(parsed, (dict, list)):
        return parsed
    # A bare string means table/plain-text output — not machine-readable.
    raise RuntimeError("MCP result was not JSON or YAML (set --list-output=yaml)")


def _k8s_mcp_payload_recognized(data: object, *, tool: str) -> bool:
    """Require an actual Kubernetes object or List after an MCP success."""
    payload = _normalize_k8s_payload(data)
    if not isinstance(payload, dict):
        return False
    if tool in {
        "events_list",
        "pods_list",
        "pods_list_in_namespace",
        "resources_list",
    }:
        return isinstance(payload.get("items"), list)
    return isinstance(payload.get("metadata"), dict)


async def _k8s_mcp_result(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
):
    async with mcp_budget(settings.kubernetes_timeout_seconds):
        return await _k8s_mcp_result_within_budget(settings, candidates)


async def _k8s_mcp_result_within_budget(
    settings: Settings, candidates: list[tuple[str, dict[str, object]]]
):
    last_error = ""
    for tool, args in candidates:
        try:
            result = await mcp_call(settings.kubernetes_mcp_url, tool, args)
        except TimeoutError:
            raise
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
    planned_node = getattr(plan, "node", "") or ""
    node = planned_node or target.node
    node_source = (
        "plan"
        if planned_node and planned_node != target.node
        else (target.node_source or ("alert" if target.node else ""))
    )
    workload = getattr(plan, "workload", "") or target.workload_name
    namespaces = getattr(plan, "namespaces", None) or []
    namespace = namespaces[0] if namespaces else target.namespace
    if (pod, node, workload, namespace, node_source) == (
        target.pod,
        target.node,
        target.workload_name,
        target.namespace,
        target.node_source,
    ):
        return target
    # Keep immutable alert identities and its incident window while applying
    # only the planner's allowed narrowing fields.
    return replace(
        target,
        namespace=namespace,
        workload_name=workload,
        node=node,
        node_source=node_source,
        pod=pod,
        # A plan-selected different Pod cannot inherit the alert Pod's UID.
        pod_uid=target.pod_uid if pod == target.pod else "",
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


_WORKLOAD_READ_KINDS = {
    "deployment": "deployments",
    "statefulset": "statefulsets",
    "daemonset": "daemonsets",
    "replicaset": "replicasets",
    "job": "jobs",
    "cronjob": "cronjobs",
}


def _read_items(result: object) -> list[dict]:
    if not isinstance(result, dict):
        return []
    data = result.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    items = data.get("items")
    return [item for item in items or [] if isinstance(item, dict)]


def _controller_observation(result: object) -> dict[str, object]:
    """Keep controller health/status without retaining its full pod template."""
    if not isinstance(result, dict):
        return {}
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else {}
    status = data.get("status") if isinstance(data.get("status"), dict) else {}
    return {
        "kind": result.get("kind"),
        "status_code": result.get("status_code"),
        "error": result.get("error"),
        "metadata": {
            key: metadata.get(key)
            for key in ("name", "namespace", "generation", "creationTimestamp")
            if metadata.get(key) is not None
        },
        "spec": {
            key: spec.get(key)
            for key in (
                "replicas",
                "parallelism",
                "completions",
                "backoffLimit",
                "activeDeadlineSeconds",
                "suspend",
                "schedule",
            )
            if spec.get(key) is not None
        },
        "status": compact(status, limit=12),
    }


def _list_observation(result: object) -> dict[str, object]:
    if not isinstance(result, dict):
        return {}
    return {
        "kind": result.get("kind"),
        "label_selector": result.get("label_selector"),
        "status_code": result.get("status_code"),
        "error": result.get("error"),
    }


def _selector_from_controller(controller: object) -> str:
    if not isinstance(controller, dict):
        return ""
    data = controller.get("data")
    if not isinstance(data, dict):
        return ""
    spec = data.get("spec")
    selector = spec.get("selector") if isinstance(spec, dict) else None
    if not isinstance(selector, dict):
        return ""
    parts: list[str] = []
    labels = selector.get("matchLabels")
    if isinstance(labels, dict):
        parts.extend(f"{key}={value}" for key, value in sorted(labels.items()) if str(key))
    expressions = selector.get("matchExpressions")
    for expression in expressions if isinstance(expressions, list) else []:
        if not isinstance(expression, dict):
            continue
        key = str(expression.get("key") or "").strip()
        operator = str(expression.get("operator") or "").strip()
        values = [str(value) for value in expression.get("values") or []]
        if not key:
            continue
        if operator in {"In", "NotIn"} and values:
            token = "in" if operator == "In" else "notin"
            parts.append(f"{key} {token} ({','.join(values)})")
        elif operator == "Exists":
            parts.append(key)
        elif operator == "DoesNotExist":
            parts.append(f"!{key}")
    return ",".join(parts)


def _owned_by(item: dict, kind: str, name: str) -> bool:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    for owner in metadata.get("ownerReferences") or []:
        if not isinstance(owner, dict):
            continue
        if str(owner.get("kind") or "").lower() == kind.lower() and owner.get("name") == name:
            return True
    return False


def _diagnostic_pod(items: list[dict], workload_name: str) -> dict | None:
    """Choose the pod most likely to retain the controller's failure evidence."""

    def score(pod: dict) -> tuple[int, str]:
        metadata = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
        status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
        phase = str(status.get("phase") or "")
        severity = {"Failed": 5, "Pending": 4, "Unknown": 3, "Running": 2, "Succeeded": 1}.get(
            phase, 0
        )
        if _pod_unhealthy(pod):
            severity += 3
        return severity, str(metadata.get("creationTimestamp") or "")

    stem = workload_name.casefold()
    candidates = [
        item
        for item in items
        if str((item.get("metadata") or {}).get("name") or "")
        and (
            not workload_name
            or stem in str((item.get("metadata") or {}).get("name") or "").casefold()
            or any(stem in str(value).casefold() for value in ((item.get("metadata") or {}).get("labels") or {}).values())
            or any(stem in str(owner.get("name") or "").casefold() for owner in ((item.get("metadata") or {}).get("ownerReferences") or []) if isinstance(owner, dict))
        )
    ]
    # Preserve namespace-level diagnostic context when controller matching is
    # inconclusive instead of silently dropping every unhealthy pod.
    return max(candidates or items, key=score) if items else None


def _generated_workload_pod_name(name: str, workload: str) -> bool:
    if not name.startswith(f"{workload}-"):
        return False
    suffix = name[len(workload) + 1 :]
    return bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", suffix)) and "-" not in suffix or bool(re.fullmatch(r"[a-z0-9]+-[a-z0-9]+", suffix))


def _diagnostic_job(items: list[dict], cronjob_name: str) -> dict | None:
    owned = [item for item in items if _owned_by(item, "CronJob", cronjob_name)]
    if not owned:
        owned = [
            item
            for item in items
            if str((item.get("metadata") or {}).get("name") or "").startswith(f"{cronjob_name}-")
        ]

    def score(job: dict) -> tuple[int, str]:
        metadata = job.get("metadata") if isinstance(job.get("metadata"), dict) else {}
        status = job.get("status") if isinstance(job.get("status"), dict) else {}
        severity = 4 if status.get("failed") else 3 if status.get("active") else 1
        return severity, str(metadata.get("creationTimestamp") or "")

    return max(owned, key=score) if owned else None


async def _resolve_workload_pod(settings: Settings, target: AnalysisTarget) -> dict[str, object]:
    """Resolve a controller-only alert to one diagnostic pod, MCP-first.

    Selectors are authoritative for Deployment/StatefulSet/DaemonSet/ReplicaSet/
    Job. CronJob adds the owner-reference hop through its most relevant Job.
    """
    kind = _WORKLOAD_READ_KINDS.get(str(target.workload_type or "").lower())
    if target.pod or not (kind and target.namespace and target.workload_name):
        return {}
    if not _namespace_allowed(settings, target.namespace):
        return {"namespace_scope_blocked": True}

    controller = await k8s_read(
        settings, kind, namespace=target.namespace, name=target.workload_name
    )
    resolution: dict[str, object] = {
        "workload_kind": kind,
        "workload_name": target.workload_name,
        "controller": _controller_observation(controller),
    }

    if kind == "cronjobs":
        jobs = await k8s_read(settings, "jobs", namespace=target.namespace)
        resolution["jobs"] = _list_observation(jobs)
        job = _diagnostic_job(_read_items(jobs), target.workload_name)
        if job is None:
            return resolution
        job_name = str((job.get("metadata") or {}).get("name") or "")
        resolution["resolved_job"] = job_name
        nested = await _resolve_workload_pod(
            settings,
            replace(target, workload_name=job_name, workload_type="Job"),
        )
        resolution["job_resolution"] = nested
        resolution["selected_pod"] = nested.get("selected_pod", "")
        resolution["selected_pod_uid"] = nested.get("selected_pod_uid", "")
        return resolution

    selector = _selector_from_controller(controller)
    if not selector and kind == "jobs":
        selector = f"batch.kubernetes.io/job-name={target.workload_name}"
    pods = await k8s_read(
        settings,
        "pods",
        namespace=target.namespace,
        label_selector=selector,
        full_object=True,
    )
    items = _read_items(pods)
    if not selector:
        items = [
            item
            for item in items
            if _owned_by(item, target.workload_type, target.workload_name)
            or _generated_workload_pod_name(
                str((item.get("metadata") or {}).get("name") or ""), target.workload_name
            )
        ]
    selected = _diagnostic_pod(items, target.workload_name)
    selected_metadata = selected.get("metadata") if isinstance(selected, dict) and isinstance(selected.get("metadata"), dict) else {}
    selected_text = " ".join(
        [str(selected_metadata.get("name") or ""), *map(str, (selected_metadata.get("labels") or {}).values())]
        + [str(owner.get("name") or "") for owner in selected_metadata.get("ownerReferences") or [] if isinstance(owner, dict)]
    ).casefold()
    resolution.update(
        {
            "selector": selector,
            "pods": _list_observation(pods),
            "candidate_pods": [
                str((item.get("metadata") or {}).get("name") or "") for item in items
            ],
            "selected_pod": (
                str((selected.get("metadata") or {}).get("name") or "") if selected else ""
            ),
            "selected_pod_uid": (
                str((selected.get("metadata") or {}).get("uid") or "") if selected else ""
            ),
            "namespace_context_fallback": bool(
                selected and target.workload_name and target.workload_name.casefold() not in selected_text
            ),
        }
    )
    return resolution


async def _collect_resolved_pod_logs(
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
    *,
    previous_containers: list[str] | None = None,
    since_time: str = "",
) -> list[dict[str, object]]:
    if not _namespace_allowed(settings, target.namespace):
        return []
    targets: list[str | None] = list(containers) if containers else [None]
    logs: list[dict[str, object]] = []
    for container in targets:
        previous_requests = [False] + (
            [True] if container and container in (previous_containers or []) else []
        )
        for previous in previous_requests:
            if previous and not container:
                continue
            item = await k8s_logs(
                settings,
                target.namespace,
                target.pod,
                container=container or "",
                tail=settings.kubernetes_list_limit,
                previous=previous,
                since_time=since_time,
            )
            logs.append(
                {
                    "namespace": item.get("namespace") or target.namespace,
                    "pod": item.get("pod") or target.pod,
                    "container": container,
                    "previous": previous,
                    "since_time": since_time or None,
                    "transport": item.get("transport"),
                    "source_verified": item.get("source_verified") is True,
                    "time_scope_verified": item.get("time_scope_verified") is not False,
                    **(
                        {"observed_entity": item["observed_entity"]}
                        if isinstance(item.get("observed_entity"), dict)
                        else {}
                    ),
                    "status_code": item.get("status_code"),
                    "error": item.get("error"),
                    "lines": item.get("lines") or [],
                }
            )
    return logs


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
    return _best_unambiguous_pod(matches)


def _best_unambiguous_pod(matches: list[tuple[str, dict]]) -> dict | None:
    """Choose one live Pod without guessing between nodes.

    Exact occurrence names, generated-name stems, and workload prefixes all use
    the same safety rule: prefer unhealthy Pods, then require either one Pod or
    one common node.  A multi-replica workload spread across nodes cannot tell
    us which node belonged to a stale alert Pod.
    """
    pool = [entry for entry in matches if _pod_unhealthy(entry[1])] or matches
    nodes = {str((entry[1].get("spec") or {}).get("nodeName") or "") for entry in pool}
    if pool and (len(pool) == 1 or len(nodes) == 1):
        return max(pool, key=lambda entry: entry[0])[1]
    return None


def _best_live_target_pod(
    items: list[dict], names: list[str], workload: str = ""
) -> dict | None:
    """Resolve a stale Pod from exact occurrences, generated stems, or workload.

    The tiers are deliberately ordered.  An occurrence Pod is a concrete alert
    identity; a controller-generated stem is narrower than a workload prefix;
    and a workload prefix is accepted only on a Kubernetes name boundary.
    """

    def entries(predicate) -> list[tuple[str, dict]]:  # noqa: ANN001
        matched: list[tuple[str, dict]] = []
        for item in items:
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            name = str(metadata.get("name") or "")
            if name and predicate(name):
                matched.append((str(metadata.get("creationTimestamp") or ""), item))
        return matched

    exact_names = set(names)
    match = _best_unambiguous_pod(entries(lambda name: name in exact_names))
    if match is not None:
        return match

    stems = [stem for name in names if (stem := pod_name_stem(name))]
    match = _best_unambiguous_pod(
        entries(lambda name: any(name.startswith(stem) for stem in stems))
    )
    if match is not None:
        return match

    workload = workload.strip().rstrip("-")
    if not workload:
        return None
    return _best_unambiguous_pod(
        entries(lambda name: name == workload or name.startswith(f"{workload}-"))
    )


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


_NODE_RESOLUTION_MAX_LIST_PAGES = 10
_NODE_RESOLUTION_MAX_LIST_ITEMS = 500


async def _node_resolution_pod_items(
    settings: Settings,
    namespace: str,
    listing: dict[str, object],
) -> tuple[list[dict], bool]:
    """Return bounded namespace Pods and whether the LIST reached its last page.

    Exact named Pod rows remain usable from any page, but generated-name and
    workload-prefix replacement inference is safe only after Kubernetes proves
    the namespace LIST is complete. MCP-only adapters that omit List metadata,
    an unavailable continuation credential, repeated tokens, page errors, and
    the page/item ceilings all return ``complete=False``.
    """
    status_code = listing.get("status_code")
    if listing.get("error") or (
        isinstance(status_code, int) and not 200 <= status_code < 300
    ):
        return [], False
    payload = _normalize_k8s_payload(listing.get("data"))
    raw_items = payload.get("items") if isinstance(payload, dict) else None
    items = [item for item in raw_items or [] if isinstance(item, dict)]
    if len(items) > _NODE_RESOLUTION_MAX_LIST_ITEMS:
        return items[:_NODE_RESOLUTION_MAX_LIST_ITEMS], False
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    if not isinstance(metadata, dict):
        return items, False
    continuation = str(metadata.get("continue") or "")
    if not continuation:
        return items, True

    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return items, False

    async def paginate() -> tuple[list[dict], bool]:
        pages = 1
        seen_tokens: set[str] = set()
        verify: bool | str = (
            settings.kubernetes_ca_path
            if Path(settings.kubernetes_ca_path).exists()
            else True
        )
        path = f"/api/v1/namespaces/{quote(namespace, safe='')}/pods"
        next_token = continuation
        while next_token:
            if (
                pages >= _NODE_RESOLUTION_MAX_LIST_PAGES
                or len(items) >= _NODE_RESOLUTION_MAX_LIST_ITEMS
                or next_token in seen_tokens
            ):
                return items, False
            seen_tokens.add(next_token)
            response = await get_json(
                base_url=settings.kubernetes_api_url,
                path=path,
                timeout_seconds=settings.kubernetes_timeout_seconds,
                params={
                    "limit": str(settings.kubernetes_list_limit),
                    "continue": next_token,
                },
                headers={"Authorization": f"Bearer {token}"},
                verify=verify,
            )
            if not response.ok:
                return items, False
            page = _normalize_k8s_payload(
                _collector_masker(settings).mask_object(response.data)
            )
            page_items = page.get("items") if isinstance(page, dict) else None
            page_metadata = page.get("metadata") if isinstance(page, dict) else None
            if not isinstance(page_items, list) or not isinstance(page_metadata, dict):
                return items, False
            items.extend(item for item in page_items if isinstance(item, dict))
            pages += 1
            if len(items) > _NODE_RESOLUTION_MAX_LIST_ITEMS:
                del items[_NODE_RESOLUTION_MAX_LIST_ITEMS:]
                return items, False
            next_token = str(page_metadata.get("continue") or "")
        return items, True

    try:
        # One total continuation deadline prevents a large namespace from
        # multiplying the ordinary per-request timeout across every page.
        return await asyncio.wait_for(
            paginate(), timeout=max(1, settings.kubernetes_timeout_seconds)
        )
    except TimeoutError:
        return items, False


async def resolve_live_pod_node(
    settings: Settings,
    namespace: str,
    pod: str,
    extra_pods: list[str] | None = None,
    workload: str = "",
) -> tuple[str, str]:
    """(live_pod, node) via the equivalent of ``get pods -n NS -o wide``.

    Alert labels frequently name a pod the controller has already replaced
    and carry no node label.  Use the normal MCP-first Kubernetes read path, so
    node discovery does not silently disappear when only the Kubernetes MCP has
    cluster credentials.  The namespace Pod list preserves ``spec.nodeName``
    and ``status.phase`` (the API equivalent of ``kubectl ... -o wide``).

    Resolution tiers:
    1. GET/list the exact named Pod and read ``spec.nodeName``.
    2. For a deleted Pod, select an unambiguous live occurrence/generated-name/
       workload-prefix match from the namespace list.
    3. If there is no live replacement, use the deleted Pod's own Event node.

    A live replacement's node stays paired with that replacement; an Event node
    for the deleted Pod is never attached to a different live Pod.
    Best-effort: ('', '') on any failure — callers keep their own fallbacks.
    """
    if not namespace or not pod:
        return "", ""
    try:
        exact = await k8s_read(
            settings,
            "pods",
            namespace=namespace,
            name=pod,
            full_object=True,
        )
        names = [name for name in dict.fromkeys([pod, *(extra_pods or [])]) if name]
        exact_data = exact.get("data") if isinstance(exact.get("data"), dict) else None
        exact_exists = _pod_object_matches(exact_data, namespace=namespace, name=pod)
        exact_node = ""
        if exact_exists and exact_data is not None:
            exact_node = str((exact_data.get("spec") or {}).get("nodeName") or "")

        # Always perform the namespace-wide placement read when the alert had
        # no node label. Besides finding stale replacements, this is the exact
        # API payload behind `kubectl get pods -n <namespace> -o wide`.
        listing = await k8s_read(
            settings,
            "pods",
            namespace=namespace,
            full_object=True,
        )

        first_payload = _normalize_k8s_payload(listing.get("data"))
        first_raw_items = (
            first_payload.get("items") if isinstance(first_payload, dict) else None
        )
        first_items = [
            item for item in first_raw_items or [] if isinstance(item, dict)
        ]

        # A named MCP shortcut can miss fields or race a namespace list.  Trust
        # the exact first-page row before spending time on continuation pages.
        listed_exact = next(
            (
                item
                for item in first_items
                if _pod_object_matches(item, namespace=namespace, name=pod)
            ),
            None,
        )
        if listed_exact is not None:
            node = str((listed_exact.get("spec") or {}).get("nodeName") or "")
            return pod, node

        # A named GET can remain authoritative when a capped/broken MCP list
        # omitted the exact row.
        if exact_node:
            return pod, exact_node

        # An existing unscheduled Pod genuinely has no node.  A sibling's node
        # is not a substitute, even though it appears in the same wide listing.
        if exact_exists:
            return pod, ""

        items, listing_complete = await _node_resolution_pod_items(
            settings,
            namespace,
            listing,
        )
        # The named GET and first page can race a replacement. A later exact
        # row remains authoritative even if the bounded LIST ultimately stops
        # before proving namespace completeness.
        listed_exact = next(
            (
                item
                for item in items
                if _pod_object_matches(item, namespace=namespace, name=pod)
            ),
            None,
        )
        if listed_exact is not None:
            node = str((listed_exact.get("spec") or {}).get("nodeName") or "")
            return pod, node

        match = (
            _best_live_target_pod(items, names, workload) if listing_complete else None
        )
        if match is not None:
            live_pod = str((match.get("metadata") or {}).get("name") or "")
            live_node = str((match.get("spec") or {}).get("nodeName") or "")
            return live_pod, live_node

        event_node = ""
        event_pod = ""
        for name in names[:3]:
            event_result = await _describe_events(
                settings,
                namespace=namespace,
                name=name,
                expected_kind="Pod",
            )
            events = (
                event_result.get("items", []) if isinstance(event_result, dict) else event_result
            )
            event_node = node_from_pod_events(
                [event for event in events if isinstance(event, dict)]
            )
            if event_node:
                event_pod = name
                break
        return (event_pod, event_node) if event_node else ("", "")
    except Exception:  # noqa: BLE001 - resolution is best-effort enrichment
        return "", ""


def _pod_object_matches(data: object, *, namespace: str, name: str) -> bool:
    """Verify a Pod object returned by a GET/list before using its placement."""
    if not isinstance(data, dict):
        return False
    metadata = data.get("metadata")
    if not isinstance(metadata, dict) or str(metadata.get("name") or "") != name:
        return False
    observed_namespace = str(metadata.get("namespace") or "")
    return not observed_namespace or observed_namespace == namespace


def _target_pod_missing(target: AnalysisTarget, responses: list[dict[str, object]]) -> bool:
    """True when the alert's named pod was queried and is definitively gone.

    Requires an explicit not-found answer on the pod GET (HTTP 404, or an MCP
    not-found observation with no data) — a transport error or an RBAC failure
    is NOT "the pod is gone"."""
    if not target.pod:
        return False
    for item in responses:
        if item.get("name") != "pod":
            continue
        if item.get("status_code") == 404:
            return True
        error_text = str(item.get("error") or "").lower()
        if item.get("data") is None and ("not found" in error_text or "notfound" in error_text):
            return True
    return False


def _pod_lifecycle_artifact(
    agent: str, target: AnalysisTarget, responses: list[dict[str, object]]
):
    """Expose the exact alert Pod's current lifecycle without implying cause.

    A Pod GET is necessarily current state. It can establish that an alerting
    Pod was replaced or still exists, but cannot prove what happened inside the
    historical incident window. The partial coverage keeps it context-only in
    the blackboard while making the replacement state visible to the operator.
    """
    pod_response = next(
        (item for item in responses if item.get("name") == "pod"), None
    )
    if not target.pod:
        state, polarity, coverage = "not_targeted", "unknown", "partial"
    elif _target_pod_missing(target, responses):
        state, polarity, coverage = "missing_now", "present", "partial"
    elif not isinstance(pod_response, dict) or pod_response.get("error"):
        state, polarity, coverage = "unavailable", "unavailable", "unknown"
    else:
        state, polarity, coverage = "live_now", "present", "partial"
    if state == "missing_now":
        summary = f"Kubernetes target Pod {target.pod} is missing at current inspection."
    elif state == "live_now":
        summary = f"Kubernetes target Pod {target.pod} exists at current inspection."
    elif state == "unavailable":
        summary = f"Kubernetes target Pod {target.pod} lifecycle inspection was unavailable."
    else:
        summary = "Kubernetes target Pod lifecycle was not inspected (no Pod identity)."
    return artifact(
        agent=agent,
        source="kubernetes",
        type="kubernetes_pod_lifecycle",
        status="unavailable" if polarity == "unavailable" else "ok",
        confidence="medium" if polarity == "present" else "low",
        title="Kubernetes · target Pod lifecycle",
        query=(f"kubectl get pod {target.pod} -n {target.namespace}" if target.pod else None),
        summary=summary,
        result={
            "observation": {
                "kind": "kubernetes_pod_lifecycle",
                "predicate": "kubernetes_target_pod_lifecycle",
                "polarity": polarity,
                "coverage": coverage,
                "state": state,
            },
            "pod": target.pod,
            "namespace": target.namespace,
            "status_code": (
                pod_response.get("status_code") if isinstance(pod_response, dict) else None
            ),
        },
    )


def _container_lifecycle_artifact(
    agent: str,
    settings: Settings,
    target: AnalysisTarget,
    pod_summary: dict[str, object] | None,
    container_diagnostics: list[dict[str, object]],
    *,
    time_range: dict[str, str] | None,
):
    """Expose target-container lifecycle facts with their actual occurrence time.

    Pod status is otherwise a current snapshot.  A previous termination has a
    Kubernetes-provided ``finishedAt`` though, so it can be typed as causal
    support only when that occurrence belongs to the exact alert Pod and falls
    within the shared causal window.  A still-firing alert may also be observed
    in a generic waiting/restart loop when Kubernetes has no termination time.
    """
    target_identity_verified = _container_lifecycle_target_verified(pod_summary, target)
    terminated_times = _container_termination_times_in_range(
        container_diagnostics, time_range
    )
    current_restart_loop = (
        target_identity_verified
        and bool(time_range)
        and not target.resolved_at
        and any(_container_is_waiting_with_restarts(item) for item in container_diagnostics)
    )
    if target_identity_verified and (terminated_times or current_restart_loop):
        polarity, coverage = "present", "scoped"
    else:
        polarity, coverage = "unknown", "partial"

    observation: dict[str, object] = {
        "kind": "kubernetes_container_lifecycle",
        "predicate": "kubernetes_target_container_lifecycle",
        "polarity": polarity,
        "coverage": coverage,
        "target_identity_verified": target_identity_verified,
        "observation_window": time_range or {},
    }
    if target_identity_verified:
        observation["observed_entity"] = {
            "kind": "pod",
            "name": target.pod,
            "namespace": target.namespace,
        }
    if terminated_times:
        observation["evidence_window"] = {
            "start": terminated_times[0][1],
            "end": terminated_times[-1][1],
        }
    if current_restart_loop:
        observation["current_restart_loop"] = True

    summary = _container_lifecycle_summary(container_diagnostics)
    return artifact(
        agent=agent,
        source="kubernetes",
        type="kubernetes_container_lifecycle",
        status="ok",
        confidence="high" if polarity == "present" else "low",
        title=ko_en(
            settings,
            "컨테이너 상태(재시작/종료)",
            "Container lifecycle (restarts/termination)",
        ),
        query=(
            f"kubectl get pod {target.pod} -n {target.namespace}"
            if target.pod
            else None
        ),
        summary=summary,
        result={
            "observation": observation,
            "pod": target.pod,
            "namespace": target.namespace,
            "containers": container_diagnostics,
        },
        highlights=salient_markers(container_diagnostics),
    )


def _container_lifecycle_target_verified(
    pod_summary: dict[str, object] | None, target: AnalysisTarget
) -> bool:
    """Require the named alert Pod (and UID when declared) for lifecycle evidence."""
    return bool(
        target.pod
        and isinstance(pod_summary, dict)
        and str(pod_summary.get("name") or "") == target.pod
        and (
            not target.namespace
            or str(pod_summary.get("namespace") or "") == target.namespace
        )
        and _pod_matches_target_uid(pod_summary, target)
    )


def _container_termination_times_in_range(
    container_diagnostics: list[dict[str, object]], time_range: dict[str, str] | None
) -> list[tuple[object, str]]:
    if not time_range:
        return []
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return []
    timestamps: list[tuple[object, str]] = []
    for diagnostic in container_diagnostics:
        last_terminated = diagnostic.get("lastTerminated")
        if not isinstance(last_terminated, dict):
            continue
        finished_at = last_terminated.get("finishedAt")
        parsed = parse_incident_time(finished_at)
        if parsed is not None and start <= parsed <= end:
            timestamps.append((parsed, str(finished_at)))
    return sorted(timestamps, key=lambda item: item[0])


def _container_is_waiting_with_restarts(diagnostic: dict[str, object]) -> bool:
    state = diagnostic.get("state")
    if not isinstance(state, dict) or str(state.get("phase") or "") != "waiting":
        return False
    last_terminated = diagnostic.get("lastTerminated")
    if isinstance(last_terminated, dict) and last_terminated.get("finishedAt"):
        return False
    try:
        return int(diagnostic.get("restartCount") or 0) > 0
    except (TypeError, ValueError):
        return False


def _container_lifecycle_summary(container_diagnostics: list[dict[str, object]]) -> str:
    """Keep lifecycle leaf values in the card text as well as its result payload."""
    if not container_diagnostics:
        return "No container lifecycle status was returned for the target Pod."
    containers: list[str] = []
    for diagnostic in container_diagnostics:
        name = str(diagnostic.get("name") or "unnamed")
        fields = [f"restartCount={diagnostic.get('restartCount')}"]
        state = diagnostic.get("state")
        if isinstance(state, dict):
            fields.append("current " + _container_state_text(state))
        last_terminated = diagnostic.get("lastTerminated")
        if isinstance(last_terminated, dict):
            fields.append("lastTerminated " + _container_state_text(last_terminated))
        containers.append(f"{name}: " + "; ".join(fields))
    return "Target Pod container lifecycle: " + " | ".join(containers)


def _container_state_text(state: dict[str, object]) -> str:
    fields = [
        f"{key}={state[key]}"
        for key in ("phase", "reason", "exitCode", "finishedAt")
        if state.get(key) is not None
    ]
    return ", ".join(fields) if fields else "state reported"


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


def _restarted_container_names(pod_summary: dict[str, object] | None) -> list[str]:
    """Names whose prior terminated instance is available via pods/log previous=true."""
    if not pod_summary:
        return []
    statuses = pod_summary.get("containerStatuses")
    if not isinstance(statuses, list):
        return []
    names: list[str] = []
    for item in statuses:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        try:
            restarted = int(item.get("restartCount") or 0) > 0
        except (TypeError, ValueError):
            restarted = False
        if restarted and isinstance(name, str) and name:
            names.append(name)
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
    previous_containers: list[str] | None = None,
    since_time: str = "",
) -> list[dict[str, object]]:
    """Fetch READ-ONLY container logs via the pods/log subresource (GET, plain text)."""
    # Respect the KUBERNETES_NAMESPACES scope like the rest of the base sweep (pods/
    # events gate the same way) — an operator that restricts namespaces must not have
    # logs leak from excluded ones. On-demand log reads for a specific alerting pod go
    # through the ungated k8s_logs tool (RBAC-bounded, like k8s_read) instead.
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    namespace = quote(target.namespace, safe="")
    pod = quote(target.pod, safe="")
    tail = str(settings.kubernetes_list_limit)
    # One request per container; if none discovered, let the API pick the default container.
    targets: list[str | None] = list(containers) if containers else [None]
    logs: list[dict[str, object]] = []
    for container in targets:
        previous_requests = [False] + (
            [True] if container and container in (previous_containers or []) else []
        )
        for previous in previous_requests:
            if previous and not container:
                continue
            params: dict[str, str] = {"tailLines": tail, "timestamps": "true"}
            if container:
                params["container"] = container
            if previous:
                params["previous"] = "true"
            if since_time:
                params["sinceTime"] = since_time
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
                    "namespace": target.namespace,
                    "pod": target.pod,
                    "container": container,
                    "previous": previous,
                    "since_time": since_time or None,
                    "transport": "direct",
                    "source_verified": True,
                    "time_scope_verified": True,
                    "observed_entity": _pod_log_entity(target.namespace, target.pod),
                    "status_code": response.status_code,
                    "error": response.error,
                    "lines": _log_lines(response.data, historical=bool(since_time)),
                }
            )
    return logs


async def _collect_pod_logs_via_mcp(
    *,
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
    previous_containers: list[str] | None = None,
    since_time: str = "",
) -> list[dict[str, object]]:
    """Fetch logs through MCP, preferring direct time-bounded API for history."""
    # See _collect_pod_logs: same KUBERNETES_NAMESPACES scope as the rest of the sweep.
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    targets: list[str | None] = list(containers) if containers else [None]
    logs: list[dict[str, object]] = []
    for container in targets:
        previous_requests = [False] + (
            [True] if container and container in (previous_containers or []) else []
        )
        for previous in previous_requests:
            if previous and not container:
                continue
            item = await k8s_logs(
                settings,
                target.namespace,
                target.pod,
                container=container or "",
                tail=settings.kubernetes_list_limit,
                previous=previous,
                since_time=since_time,
            )
            logs.append(
                {
                    "namespace": item.get("namespace") or target.namespace,
                    "pod": item.get("pod") or target.pod,
                    "container": container,
                    "previous": previous,
                    "since_time": since_time or None,
                    "transport": item.get("transport"),
                    "source_verified": item.get("source_verified") is True,
                    "time_scope_verified": item.get("time_scope_verified") is not False,
                    **(
                        {"observed_entity": item["observed_entity"]}
                        if isinstance(item.get("observed_entity"), dict)
                        else {}
                    ),
                    "status_code": item.get("status_code"),
                    "error": item.get("error"),
                    "lines": item.get("lines") or [],
                }
            )
    return logs


def _log_lines(data: object, *, historical: bool = False) -> list[str]:
    # get_json wraps non-JSON text as {"body": <text>}; logs are plain text.
    text = ""
    if isinstance(data, dict) and isinstance(data.get("body"), str):
        text = data["body"]
    elif isinstance(data, str):
        text = data
    if not text:
        return []
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[:40] if historical else lines[-40:]


async def _collect_exec_probes(
    *,
    settings: Settings,
    target: AnalysisTarget,
    containers: list[str],
) -> list[dict[str, object]]:
    """Run a small set of read-only, allowlisted exec diagnostics.

    The base sweep stays bounded: high-signal CPU/memory/filesystem/GPU checks
    execute once against the alert Pod's primary container. The drill-down
    agent can request another exact allowlisted probe when that evidence makes
    it useful. Kubernetes MCP remains the path for get/list/log; its
    deliberately read-only ServiceAccount has no pods/exec permission.
    """
    if not settings.enable_pod_exec:
        return []
    if not (target.namespace and target.pod and _namespace_allowed(settings, target.namespace)):
        return []
    probes: list[dict[str, object]] = []
    container = containers[0] if containers else None
    base_commands = (
        ("free", "-h"),
        ("df", "-h"),
        ("nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv"),
    )
    for command in base_commands:
        argv = list(command)
        result = await k8s_exec(
            settings,
            target.namespace,
            target.pod,
            argv,
            container=container or "",
        )
        probes.append(
            {
                **result,
                "command": shlex.join(argv),
                "allowed": True,
                "attempted": True,
            }
        )
        # A transport/authorization failure applies to the exec subresource,
        # not to this particular command. Do not repeat the same doomed
        # WebSocket handshake for every probe in the bounded base set.
        if result.get("transport_error") is True:
            break
    return probes


def _exec_probes_observed_entity(probes: list[dict[str, object]]) -> dict[str, str] | None:
    """Keep an exec card's Pod provenance only when every probe agrees on it."""
    if not probes:
        return None
    entities = [_pod_log_observed_entity(probe) for probe in probes]
    if any(entity is None for entity in entities):
        return None
    first = entities[0]
    if first is None or any(entity != first for entity in entities[1:]):
        return None
    return first


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
    if summary.strip().startswith(NO_EVIDENCE):
        return ""
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
    insight_model = getattr(settings, "llm_model_insight", "")
    if not llm_configured(settings, insight_model):
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
    masked_user = _collector_masker(settings).mask_text(str(user))
    key = insight_cache_key("kubernetes", getattr(settings, "language", "en"), masked_user)

    async def compute() -> str | None:
        return await complete(
            settings,
            system=system,
            user=masked_user,
            max_tokens=getattr(settings, "llm_insight_max_tokens", 512),
            model=insight_model or None,
        )

    insight = await cached_insight(key, compute)
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


def _event_collection_time_range(target: AnalysisTarget) -> dict[str, str] | None:
    """Keep resolved-event collection coverage while admitting firing evidence now."""
    fired = parse_incident_time(target.fired_at)
    resolved = parse_incident_time(target.resolved_at)
    if resolved is None or (fired is not None and resolved < fired):
        return causal_evidence_time_range(target)
    return incident_time_range(target)


def _filter_kubernetes_data(
    name: str,
    data: object,
    target: AnalysisTarget,
    *,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> object:
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
        return _prioritized_pod_list(items)
    if name.startswith("runai_control_plane_pods:") and isinstance(data.get("items"), list):
        return {
            "namespace": _response_namespace(name),
            **_prioritized_pod_list(data["items"]),
        }
    if name == "pod":
        return _pod_summary(data)
    if (
        name in {"pod_events", "workload_events", "namespace_events"}
        or name.startswith("runai_control_plane_events:")
    ) and isinstance(data.get("items"), list):
        items = _events_in_time_range(data["items"], _event_collection_time_range(target))
        # Kubernetes MCP's events_list does not reliably honor fieldSelector.
        # The named-pod sweep must never promote another object's warning as
        # evidence for this alert, so apply the selector locally as well.
        if name == "pod_events" and target.pod:
            items = [
                item
                for item in items
                if isinstance(item, dict)
                and isinstance(item.get("involvedObject"), dict)
                and str((item.get("involvedObject") or {}).get("kind") or "").casefold() == "pod"
                and str((item.get("involvedObject") or {}).get("name") or "") == target.pod
                and _event_matches_namespace(item, target.namespace)
                and _event_matches_uid(item, target.pod_uid)
            ]
        elif name in {"workload_events", "namespace_events"}:
            # MCP tools can ignore their namespace argument; an event matching
            # only by name from another tenant must not become alert evidence.
            items = [
                item
                for item in items
                if _event_matches_namespace(item, target.namespace)
                and _event_matches_target(
                    item, target, resolved_pod_anchor=resolved_pod_anchor
                )
            ]
        elif name.startswith("runai_control_plane_events:"):
            # Control-plane Events intentionally live outside the workload
            # namespace, but still must originate from the control-plane
            # namespace requested from the MCP tool.
            items = [
                item
                for item in items
                if _event_matches_namespace(item, _response_namespace(name) or "")
                and _event_matches_target(
                    item, target, resolved_pod_anchor=resolved_pod_anchor
                )
            ]
        events = [
            item
            for item in items
            if isinstance(item, dict)
            and (
                str(item.get("type") or "").casefold() == "warning"
                or (
                    str(item.get("type") or "").casefold() == "normal"
                    and str(item.get("reason") or "").casefold()
                    in _OBSERVED_NORMAL_EVENT_REASONS
                )
            )
        ]
        events.sort(key=_event_sort_timestamp)
        omitted_events = max(0, len(events) - 5)
        filtered = {
            "namespace": _response_namespace(name),
            "items": [
                _event_summary(
                    item, target=target, resolved_pod_anchor=resolved_pod_anchor
                )
                for item in events[-5:]
            ],
        }
        if omitted_events:
            filtered["omitted_events"] = omitted_events
        return filtered
    if name == "node":
        return _node_summary(data)
    return data


def _event_time_range_complete(
    name: str,
    data: object,
    target: AnalysisTarget,
    *,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> bool:
    """Whether target-correlated Warning Events have usable historical times.

    An Event without a usable time cannot be placed inside or outside an
    incident window.  Dropping it from the range projection is correct, but an
    otherwise complete empty list must then remain ``unknown/partial`` rather
    than becoming a false absence claim.
    """
    if not (
        name in {"pod_events", "workload_events", "namespace_events"}
        or name.startswith("runai_control_plane_events:")
    ):
        return True
    if not _event_collection_time_range(target):
        return True
    payload = _normalize_k8s_payload(data)
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return False
    if name == "pod_events" and target.pod:
        candidates = [
            item
            for item in items
            if isinstance(item, dict)
            and isinstance(item.get("involvedObject"), dict)
            and str((item.get("involvedObject") or {}).get("kind") or "").casefold() == "pod"
            and str((item.get("involvedObject") or {}).get("name") or "") == target.pod
            and _event_matches_namespace(item, target.namespace)
            and _event_matches_uid(item, target.pod_uid)
        ]
    elif name in {"workload_events", "namespace_events"}:
        candidates = [
            item
            for item in items
            if isinstance(item, dict)
            and _event_matches_namespace(item, target.namespace)
            and _event_matches_target(
                item, target, resolved_pod_anchor=resolved_pod_anchor
            )
        ]
    else:
        candidates = [
            item
            for item in items
            if isinstance(item, dict)
            and _event_matches_namespace(item, _response_namespace(name) or "")
            and _event_matches_target(
                item, target, resolved_pod_anchor=resolved_pod_anchor
            )
        ]
    window = _event_collection_time_range(target) or {}
    return all(
        _event_times_are_complete_for_window(item, window)
        for item in candidates
        if str(item.get("type") or "") == "Warning"
    )


def _warning_events_are_target_scoped(target: AnalysisTarget) -> bool:
    return _event_target_entity(target) is not None


_WORKLOAD_EVENT_KINDS = frozenset(
    {
        "deployment",
        "statefulset",
        "daemonset",
        "replicaset",
        "job",
        "cronjob",
        "podgroup",
        "runaijob",
        "trainingworkload",
        "interactiveworkload",
        "inferenceworkload",
        "distributedworkload",
        "distributedinferenceworkload",
        "externalworkload",
        "workloadrunner",
    }
)


def _event_target_entity(target: AnalysisTarget | None) -> dict[str, str] | None:
    """Return the concrete resource an Events query can safely speak for."""
    if target is None:
        return None
    if target.pod and target.namespace:
        return {"kind": "pod", "name": target.pod, "namespace": target.namespace}
    if target.workload_name and target.namespace:
        return {
            "kind": "workload_name",
            "name": target.workload_name,
            "namespace": target.namespace,
        }
    if target.node:
        return {"kind": "node", "name": target.node}
    return None


def _event_matches_declared_workload(
    event: dict[str, object], target: AnalysisTarget
) -> bool:
    """Match an exact workload identity without relying on message keywords."""
    workload = target.workload_name.strip()
    if not workload or not target.namespace:
        return False
    involved = event.get("involvedObject")
    involved = involved if isinstance(involved, dict) else {}
    name = str(involved.get("name") or "")
    kind = str(involved.get("kind") or "").strip().casefold()
    if name != workload or not _event_matches_namespace(event, target.namespace):
        return False
    expected_kind = target.workload_type.strip().casefold()
    # When the alert omitted workload_type, accept only known workload or
    # controller kinds. A same-named ConfigMap/Secret remains unverified.
    return kind == expected_kind if expected_kind else kind in _WORKLOAD_EVENT_KINDS


def _event_target_identity(
    event: dict[str, object],
    target: AnalysisTarget,
    *,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> dict[str, str] | None:
    """Verify that an Event's involved object is the concrete alert resource.

    Message text is retained for operator context and may select a useful
    control-plane Event, but it cannot establish causal target provenance.
    """
    involved = event.get("involvedObject")
    involved = involved if isinstance(involved, dict) else {}
    name = str(involved.get("name") or "")
    kind = str(involved.get("kind") or "").casefold()
    entity = _event_target_entity(target)
    if entity is None:
        return None
    if _event_matches_resolved_pod(event, resolved_pod_anchor):
        return entity
    if (
        target.pod
        and kind == "pod"
        and name == target.pod
        and _event_matches_namespace(event, target.namespace)
        and _event_matches_uid(event, target.pod_uid)
    ):
        return entity
    if _event_matches_declared_workload(event, target):
        return entity
    if target.node and kind == "node" and name == target.node:
        return entity
    return None


def _event_matches_target(
    event: dict[str, object],
    target: AnalysisTarget,
    *,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> bool:
    involved = event.get("involvedObject")
    involved = involved if isinstance(involved, dict) else {}
    name = str(involved.get("name") or "")
    kind = str(involved.get("kind") or "").casefold()
    if _event_matches_resolved_pod(event, resolved_pod_anchor):
        return True
    if (
        target.pod
        and kind == "pod"
        and name == target.pod
        and _event_matches_uid(event, target.pod_uid)
    ):
        return True
    if target.node and kind == "node" and name == target.node:
        return True
    workload = target.workload_name.strip()
    if workload:
        if _event_matches_declared_workload(event, target):
            return True
        # Controllers commonly emit Events on a child Pod.  Do not accept a
        # same-named ConfigMap/Secret/etc. simply because its name resembles
        # the workload identity.
        if kind == "pod" and name.startswith(f"{workload}-"):
            return True
    # A Run:ai scheduler/backend Event commonly involves its own controller
    # Pod, not the user workload Pod. Accept it only when the event message
    # explicitly names an alert identity — never based on error vocabulary.
    message = str(event.get("message") or "")
    return _event_message_mentions_target(message, target)


def _event_matches_resolved_pod(
    event: dict[str, object], resolved_pod_anchor: AnalysisTarget | None
) -> bool:
    """Match an Event to the live Pod selected for a controller alert.

    A controller's declared workload remains the artifact's observed entity.
    The selected Pod is solely an exact identity anchor for child-Pod Events:
    another Pod in the namespace cannot pass this check. A supplied Event UID
    that disagrees with the selected Pod rejects even a same-name replacement;
    matching UID also permits API variants that omit or alter the name.
    """
    if resolved_pod_anchor is None or not resolved_pod_anchor.pod:
        return False
    involved = event.get("involvedObject")
    involved = involved if isinstance(involved, dict) else {}
    if (
        str(involved.get("kind") or "").casefold() != "pod"
        or not _event_matches_namespace(event, resolved_pod_anchor.namespace)
    ):
        return False
    name = str(involved.get("name") or "")
    event_uid = str(involved.get("uid") or "")
    anchor_uid = resolved_pod_anchor.pod_uid
    if anchor_uid and event_uid and event_uid != anchor_uid:
        return False
    return name == resolved_pod_anchor.pod or bool(anchor_uid and event_uid == anchor_uid)


def _event_matches_namespace(event: dict[str, object], namespace: str) -> bool:
    """Reject an Event that explicitly belongs to another namespace.

    Kubernetes MCP list tools may ignore their namespace argument.  Event
    metadata is authoritative and ``involvedObject.namespace`` is an
    additional consistency check when supplied.  Some API variants omit the
    latter, so an absent field is not treated as a mismatch.
    """
    if not namespace:
        return True
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    involved = event.get("involvedObject") if isinstance(event.get("involvedObject"), dict) else {}
    event_namespace = str(metadata.get("namespace") or "")
    involved_namespace = str(involved.get("namespace") or "")
    return (not event_namespace or event_namespace == namespace) and (
        not involved_namespace or involved_namespace == namespace
    )


def _event_matches_uid(event: dict[str, object], expected_uid: str) -> bool:
    """Require the immutable Pod UID only when the alert declared one."""
    if not expected_uid:
        return True
    involved = event.get("involvedObject") if isinstance(event.get("involvedObject"), dict) else {}
    return str(involved.get("uid") or "") == expected_uid


def _pod_matches_target_uid(pod: dict[str, object] | None, target: AnalysisTarget) -> bool:
    """A same-name current Pod is usable only when an explicit alert UID agrees."""
    if not target.pod_uid:
        return True
    if not isinstance(pod, dict):
        return False
    return str(pod.get("uid") or "") == target.pod_uid


def _event_message_mentions_target(message: str, target: AnalysisTarget) -> bool:
    text = message.casefold()
    identifiers = [
        target.pod,
        target.workload_name,
        target.runai_workload_id,
    ]
    # Project is shared by many workloads. It is only a usable message-level
    # identity when the alert supplied no concrete Pod/workload/Run:ai ID.
    if not any(value.strip() for value in identifiers):
        identifiers.append(target.project)
    for value in identifiers:
        normalized = value.strip().casefold()
        if len(normalized) < 3:
            continue
        # Token boundaries prevent ``train`` from matching ``trainer`` while
        # allowing Kubernetes names like ``trainer-0`` / ``trainer/abc``.
        if re.search(rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])", text):
            return True
    return False


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
    conditions = [
        condition for condition in status.get("conditions", []) if isinstance(condition, dict)
    ]
    conditions.sort(
        key=lambda condition: (
            not _condition_is_failure(condition),
            str(condition.get("type") or ""),
        )
    )
    return {
        "name": metadata.get("name"),
        "uid": metadata.get("uid"),
        "namespace": metadata.get("namespace"),
        "phase": status.get("phase"),
        "nodeName": spec.get("nodeName"),
        "podIP": status.get("podIP"),
        "conditions": compact(conditions, limit=5),
        "containerStatuses": compact(containers, limit=5),
        "resources": resources,
        **({"reason": status["reason"]} if status.get("reason") else {}),
        **({"message": status["message"]} if status.get("message") else {}),
    }


def _condition_is_failure(condition: dict[str, object]) -> bool:
    condition_type = str(condition.get("type") or "").casefold()
    status = _boolean_condition_status(condition.get("status"))
    return status is not None and (
        (condition_type in _FALSE_IS_FAILURE_CONDITION_TYPES and not status)
        or (condition_type in _TRUE_IS_FAILURE_CONDITION_TYPES and status)
    )


def _pod_priority(pod: dict[str, object]) -> tuple[int, bool, int, str]:
    metadata = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
    status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
    phase = str(status.get("phase") or "").casefold()
    phase_priority = {
        "failed": 0,
        "unknown": 1,
        "pending": 2,
        "running": 3,
        "succeeded": 4,
    }.get(phase, 5)
    container_failure = False
    restarts = 0
    containers = status.get("containerStatuses", [])
    for container in containers if isinstance(containers, list) else []:
        if not isinstance(container, dict):
            continue
        restarts += int(container.get("restartCount") or 0)
        state = container.get("state") if isinstance(container.get("state"), dict) else {}
        for state_name in ("waiting", "terminated"):
            detail = state.get(state_name) if isinstance(state.get(state_name), dict) else {}
            if str(detail.get("reason") or "") not in {"", "Completed"}:
                container_failure = True
    return phase_priority, not container_failure, -restarts, str(metadata.get("name") or "")


def _prioritized_pod_list(items: object) -> dict[str, object]:
    pods = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    pods.sort(key=_pod_priority)
    omitted_pods = max(0, len(pods) - 5)
    result: dict[str, object] = {"items": [_pod_summary(pod) for pod in pods[:5]]}
    if omitted_pods:
        result["omitted_pods"] = omitted_pods
    return result


def _event_summary(
    event: dict[str, object],
    *,
    target: AnalysisTarget | None = None,
    resolved_pod_anchor: AnalysisTarget | None = None,
) -> dict[str, object]:
    involved = event.get("involvedObject") if isinstance(event.get("involvedObject"), dict) else {}
    timestamps = _event_timestamps(event)
    observed_entity = (
        _event_target_identity(
            event, target, resolved_pod_anchor=resolved_pod_anchor
        )
        if target is not None
        else None
    )
    summary = {
        "type": event.get("type"),
        "reason": event.get("reason"),
        "message": event.get("message"),
        "count": event.get("count"),
        "lastTimestamp": timestamps[-1][1] if timestamps else None,
        # Preserve the event's full observed span.  A repeating Event can have
        # an old first observation and a later last observation; retaining
        # only the latter would misclassify a legitimate incident-time event
        # as a recovery-only signal.
        "observedTimestamps": [str(value) for _, value in timestamps],
        "object": involved.get("name"),
        "kind": involved.get("kind"),
        "namespace": involved.get("namespace")
        or (event.get("metadata") or {}).get("namespace")
        if isinstance(event.get("metadata"), dict)
        else involved.get("namespace"),
        "uid": involved.get("uid"),
        "target_identity_verified": observed_entity is not None,
    }
    if resolved_pod_anchor is not None:
        summary["target_identity_anchor_verified"] = _event_matches_resolved_pod(
            event, resolved_pod_anchor
        )
    if observed_entity:
        summary["observed_entity"] = observed_entity
    return summary


def _event_timestamp(event: dict[str, object]) -> object:
    timestamps = _event_timestamps(event)
    return timestamps[-1][1] if timestamps else None


def _event_sort_timestamp(event: dict[str, object]) -> tuple[bool, str]:
    timestamps = _event_timestamps(event)
    timestamp = timestamps[-1][0] if timestamps else None
    return timestamp is not None, timestamp.isoformat() if timestamp is not None else ""


def _event_timestamps(event: dict[str, object]) -> list[tuple[object, object]]:
    """All usable Event timestamps, ordered oldest to newest.

    Events can have both an older ``eventTime`` and a newer repeating-series
    observation.  Filtering only the first populated field loses the latter
    and can incorrectly assert that nothing happened in an incident window.
    """
    series = event.get("series") if isinstance(event.get("series"), dict) else {}
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    timestamps: list[tuple[object, object]] = []
    for value in (
        event.get("eventTime"),
        series.get("lastObservedTime"),
        event.get("firstTimestamp"),
        event.get("lastTimestamp"),
        metadata.get("creationTimestamp"),
    ):
        parsed = parse_incident_time(value)
        # ``0001-01-01T00:00:00Z`` is Kubernetes' zero-value eventTime.  It is
        # not an observed time and must not hide a usable legacy timestamp.
        if parsed is not None and parsed.year > 1:
            timestamps.append((parsed, value))
    return sorted(timestamps, key=lambda item: item[0])


def _event_times_are_complete_for_window(
    event: dict[str, object], time_range: dict[str, str]
) -> bool:
    """An Event spanning the window cannot establish a negative without a sample."""
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    timestamps = _event_timestamps(event)
    if start is None or end is None or not timestamps:
        return False
    values = [parsed for parsed, _ in timestamps]
    # A first/last observation on opposite sides of the incident could cover
    # the window even when neither endpoint itself lies inside it.
    return not (min(values) < start and max(values) > end)


def _events_in_time_range(
    items: object, time_range: dict[str, str] | None
) -> list[dict[str, object]]:
    """Client-side event time filter because the Kubernetes Events API has no range selector."""
    if not isinstance(items, list):
        return []
    if not time_range:
        return [item for item in items if isinstance(item, dict)]
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None:
        return []
    filtered: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        timestamps = _event_timestamps(item)
        if any(start <= observed_at <= end for observed_at, _ in timestamps):
            filtered.append(item)
    return filtered


def _node_summary(node: dict[str, object]) -> dict[str, object]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    status = node.get("status") if isinstance(node.get("status"), dict) else {}
    spec = node.get("spec") if isinstance(node.get("spec"), dict) else {}
    return {
        "name": metadata.get("name"),
        "conditions": status.get("conditions", []),
        "capacity": status.get("capacity", {}),
        "allocatable": status.get("allocatable", {}),
        "unschedulable": bool(spec.get("unschedulable")),
        "taints": spec.get("taints", []),
    }


_GPU_RESOURCE = "nvidia.com/gpu"
_GPU_SCHEDULING_FAMILIES = frozenset(
    {"k8s_scheduling_error", "runai_scheduling_quota"}
)
_NODE_DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z"
)
_NODE_IN_EVENT_PATTERNS = (
    re.compile(r"(?i)\bnode/([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)"),
    re.compile(r"(?i)\bnode\s*[=:]\s*([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)"),
    re.compile(r"(?i)\bnode\s+['\"]([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)['\"]"),
    re.compile(r"(?i)\bon\s+node\s+([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)"),
    # Run:ai scheduler Events commonly render the evaluated node as
    # ``Unschedulable: <dgx02>: Node didn't have enough resources``.
    re.compile(r"(?i)<([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)>"),
)
_NON_NODE_EVENT_WORDS = frozenset(
    {
        "affinity",
        "selector",
        "selectors",
        "taint",
        "taints",
        "label",
        "labels",
        "condition",
        "conditions",
        "pressure",
        "pool",
        "pools",
        "none",
        "unknown",
        "pending",
    }
)


def _gpu_shortage_signal(text: object) -> bool:
    value = str(text or "").casefold()
    if not value:
        return False
    # An exact extended-resource name is already a scheduler capacity signal.
    # A generic "gpu" token is not: image names and healthy specs contain it.
    if re.search(r"\bnvidia\.com/(?:gpu|mig-[a-z0-9.-]+)\b", value):
        return True
    return bool(
        re.search(
            r"\binsufficient\s+(?:available\s+)?gpus?\b|"
            r"\bnot\s+(?:have\s+)?enough\s+resources?\s*:\s*gpus?\b|"
            r"\b(?:did(?:\s+not|n't)|does(?:\s+not|n't))\s+have\s+enough\s+"
            r"resources?\s*:\s*gpus?\b|"
            r"\b(?:gpu|gpus)\s+(?:capacity|shortage|exhausted|unavailable)\b|"
            r"\b(?:no|zero|not enough)\s+(?:available\s+)?gpus?\b",
            value,
        )
    )


def _gpu_scheduling_snapshot_requested(plan: object, events: list[dict[str, object]]) -> bool:
    """Gate the extra node reads on a real scheduling + GPU-shortage hypothesis."""
    hypotheses = getattr(plan, "hypotheses", None) or []
    active = [
        item
        for item in hypotheses
        if isinstance(item, dict)
        and str(item.get("family") or "") in _GPU_SCHEDULING_FAMILIES
    ]
    if not active:
        return False
    if any(_gpu_shortage_signal(item.get("reason")) for item in active):
        return True
    for event in events:
        reason = str(event.get("reason") or "").casefold()
        message = str(event.get("message") or "")
        scheduling = (
            reason in {"failedscheduling", "unschedulable"}
            or "unschedulable" in message.casefold()
            or "nodes are available" in message.casefold()
        )
        if scheduling and _gpu_shortage_signal(message):
            return True
    return False


def _gpu_snapshot_candidate_nodes(
    target: AnalysisTarget, events: list[dict[str, object]], *, limit: int = 4
) -> list[str]:
    """Exact node names from the scoped target or target-verified Events only."""
    candidates: list[str] = []

    def add(value: object) -> None:
        name = str(value or "").strip().casefold()
        if name and _NODE_DNS_NAME.fullmatch(name) and name not in candidates:
            candidates.append(name)

    add(target.node)
    for event in events:
        message = str(event.get("message") or "")
        for pattern in _NODE_IN_EVENT_PATTERNS:
            for match in pattern.finditer(message):
                candidate = match.group(1).casefold()
                # Phrases such as "on node affinity" name a scheduling rule,
                # not a Node. Likewise do not truncate resource paths such as
                # nvidia.com/gpu into a plausible-looking DNS name.
                followed_by_slash = message[match.end(1) :].startswith("/")
                if candidate in _NON_NODE_EVENT_WORDS or followed_by_slash:
                    continue
                add(candidate)
                if len(candidates) >= limit:
                    return candidates
    return candidates[:limit]


def _gpu_quantity(value: object) -> tuple[Decimal, bool]:
    """Parse one scalar extended-resource quantity; missing means zero."""
    if value in (None, ""):
        return Decimal(0), True
    if isinstance(value, bool):
        return Decimal(0), False
    try:
        quantity = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return Decimal(0), False
    return (quantity, quantity >= 0)


def _container_gpu_request(container: object) -> tuple[Decimal, int]:
    if not isinstance(container, dict):
        return Decimal(0), 0
    resources = container.get("resources")
    if not isinstance(resources, dict):
        return Decimal(0), 0
    requests = resources.get("requests")
    limits = resources.get("limits")
    requests = requests if isinstance(requests, dict) else {}
    limits = limits if isinstance(limits, dict) else {}
    # Extended resources permit limits-only declarations; Kubernetes treats
    # that limit as the request. Mirror it when the requests map omits the key.
    raw = requests[_GPU_RESOURCE] if _GPU_RESOURCE in requests else limits.get(_GPU_RESOURCE)
    quantity, valid = _gpu_quantity(raw)
    return quantity, 0 if valid else 1


def _pod_gpu_request(pod: object) -> tuple[Decimal, int]:
    """Approximate Kubernetes' effective Pod request for one scalar GPU resource."""
    if not isinstance(pod, dict):
        return Decimal(0), 0
    spec = pod.get("spec")
    if not isinstance(spec, dict):
        return Decimal(0), 0
    invalid = 0
    regular = Decimal(0)
    containers = spec.get("containers")
    for container in containers if isinstance(containers, list) else []:
        quantity, bad = _container_gpu_request(container)
        regular += quantity
        invalid += bad

    # Restartable init containers (sidecars) remain resident. Non-restartable
    # init containers contribute their peak alongside any earlier sidecars.
    restartable_init = Decimal(0)
    init_peak = Decimal(0)
    init_containers = spec.get("initContainers")
    for container in init_containers if isinstance(init_containers, list) else []:
        quantity, bad = _container_gpu_request(container)
        invalid += bad
        if isinstance(container, dict) and container.get("restartPolicy") == "Always":
            restartable_init += quantity
            init_peak = max(init_peak, restartable_init)
        else:
            init_peak = max(init_peak, restartable_init + quantity)
    effective = max(regular + restartable_init, init_peak)

    pod_resources = spec.get("resources")
    if isinstance(pod_resources, dict):
        requests = pod_resources.get("requests")
        if isinstance(requests, dict) and _GPU_RESOURCE in requests:
            pod_level, valid = _gpu_quantity(requests.get(_GPU_RESOURCE))
            effective = max(effective, pod_level)
            invalid += 0 if valid else 1
    overhead = spec.get("overhead")
    if isinstance(overhead, dict) and _GPU_RESOURCE in overhead:
        overhead_gpu, valid = _gpu_quantity(overhead.get(_GPU_RESOURCE))
        effective += overhead_gpu
        invalid += 0 if valid else 1
    return effective, invalid


def _display_gpu_quantity(value: Decimal | None) -> int | float | None:
    if value is None:
        return None
    integral = value.to_integral_value()
    return int(integral) if value == integral else float(value)


def _node_gpu_value(node: dict[str, object], field: str) -> tuple[Decimal | None, bool]:
    status = node.get("status")
    values = status.get(field) if isinstance(status, dict) else None
    if not isinstance(values, dict) or _GPU_RESOURCE not in values:
        return None, True
    value, valid = _gpu_quantity(values.get(_GPU_RESOURCE))
    return (value if valid else None), valid


async def _collect_gpu_node_resource_observations(
    settings: Settings,
    target: AnalysisTarget,
    plan: object,
    events: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Collect exact live Node + assigned-Pod resource snapshots before synthesis."""
    if not settings.kubernetes_cluster_scope_enabled:
        return []
    if not _gpu_scheduling_snapshot_requested(plan, events):
        return []
    nodes = _gpu_snapshot_candidate_nodes(target, events)
    if not nodes:
        return []

    async def collect_node(node: str) -> dict[str, object]:
        selector = f"spec.nodeName={node}"
        node_result, pods_result = await asyncio.gather(
            k8s_read(settings, "nodes", name=node, full_object=True),
            k8s_read(
                settings,
                "pods",
                field_selector=selector,
                full_object=True,
            ),
        )
        node_payload = _normalize_k8s_payload(node_result.get("data"))
        metadata = (
            node_payload.get("metadata") if isinstance(node_payload, dict) else None
        )
        node_verified = (
            isinstance(metadata, dict) and str(metadata.get("name") or "") == node
        )
        node_object = node_payload if node_verified and isinstance(node_payload, dict) else {}
        capacity, capacity_valid = _node_gpu_value(node_object, "capacity")
        allocatable, allocatable_valid = _node_gpu_value(node_object, "allocatable")

        pods_payload = _normalize_k8s_payload(pods_result.get("data"))
        raw_pod_items = pods_payload.get("items") if isinstance(pods_payload, dict) else None
        pods_query_ok = not pods_result.get("error") and isinstance(raw_pod_items, list)
        pod_items = raw_pod_items if isinstance(raw_pod_items, list) else []
        from_mcp = bool(
            settings.kubernetes_mcp_url
            and str(pods_result.get("url") or "").startswith(settings.kubernetes_mcp_url)
        )
        pods_list_complete = (
            _mcp_kubernetes_list_complete(pods_payload)
            if from_mcp
            else _kubernetes_list_complete(pods_payload)
        )
        assigned: list[dict[str, object]] = []
        requested = Decimal(0)
        invalid_quantities = 0
        scheduled_pod_count = 0
        if pods_query_ok:
            for pod in pod_items:
                if not isinstance(pod, dict):
                    continue
                spec = pod.get("spec") if isinstance(pod.get("spec"), dict) else {}
                status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
                # Enforce the assignment a second time even after the MCP
                # client-side selector; never charge another node's Pods.
                if str(spec.get("nodeName") or "") != node:
                    continue
                if str(status.get("phase") or "") in {"Succeeded", "Failed"}:
                    continue
                scheduled_pod_count += 1
                pod_request, invalid = _pod_gpu_request(pod)
                requested += pod_request
                invalid_quantities += invalid
                if pod_request > 0 and len(assigned) < 20:
                    pod_metadata = (
                        pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
                    )
                    assigned.append(
                        {
                            "namespace": pod_metadata.get("namespace"),
                            "pod": pod_metadata.get("name"),
                            "phase": status.get("phase"),
                            "requested_gpu": _display_gpu_quantity(pod_request),
                        }
                    )
        request_complete = pods_query_ok and pods_list_complete and not invalid_quantities
        requested_value = requested if request_complete else None
        estimated_free = (
            allocatable - requested_value
            if allocatable is not None and requested_value is not None
            else None
        )
        node_error = str(node_result.get("error") or "")
        if not node_error and not node_verified:
            node_error = "node response did not match the requested node"
        pods_error = str(pods_result.get("error") or "")
        if not pods_error and not pods_query_ok:
            pods_error = "assigned Pod list was not machine-readable"
        observation: dict[str, object] = {
            "kind": "kubernetes_node_gpu_resources",
            "predicate": "kubernetes_node_gpu_resources",
            # These values are sampled now. They explain current capacity but
            # cannot prove that the same state caused a historical incident.
            "polarity": "unknown" if node_verified else "unavailable",
            "coverage": "partial",
            "observation_window": {},
            "snapshot_role": "current_context",
        }
        if node_verified:
            observation["observed_entity"] = {"kind": "node", "name": node}
        return {
            "node": node,
            "resource": _GPU_RESOURCE,
            "gpu_capacity": _display_gpu_quantity(capacity),
            "gpu_allocatable": _display_gpu_quantity(allocatable),
            "gpu_requested": _display_gpu_quantity(requested_value),
            "gpu_requested_in_returned_page": (
                _display_gpu_quantity(requested) if pods_query_ok else None
            ),
            "gpu_estimated_free": _display_gpu_quantity(estimated_free),
            "scheduled_non_terminal_pods": scheduled_pod_count if pods_query_ok else None,
            "pod_gpu_requests": assigned,
            "request_calculation_complete": request_complete,
            "pods_list_complete": pods_list_complete if pods_query_ok else False,
            "invalid_gpu_quantities": invalid_quantities,
            "capacity_quantity_valid": capacity_valid,
            "allocatable_quantity_valid": allocatable_valid,
            "node_query_error": node_error or None,
            "pods_query_error": pods_error or None,
            "node_query_url": node_result.get("url"),
            "node_query_status_code": node_result.get("status_code"),
            "pods_query_url": pods_result.get("url"),
            "pods_query_status_code": pods_result.get("status_code"),
            "snapshot_role": "current_context",
            "observation": observation,
        }

    return list(await asyncio.gather(*(collect_node(node) for node in nodes)))


def _gpu_node_resource_artifact(
    agent: str, settings: Settings, snapshot: dict[str, object]
):
    node = str(snapshot.get("node") or "")
    node_error = str(snapshot.get("node_query_error") or "")
    pods_error = str(snapshot.get("pods_query_error") or "")
    partial = bool(node_error or pods_error or not snapshot.get("request_calculation_complete"))
    if node_error:
        summary = ko_en(
            settings,
            f"현재 노드 GPU 스냅샷을 수집하지 못했습니다: {node_error}",
            f"Could not collect the current node GPU snapshot: {node_error}",
        )
    else:
        requested = snapshot.get("gpu_requested")
        requested_text = "unknown" if requested is None else str(requested)
        summary = ko_en(
            settings,
            (
                f"현재 스냅샷 기준 node/{node}: {_GPU_RESOURCE} capacity "
                f"{snapshot.get('gpu_capacity')}, allocatable {snapshot.get('gpu_allocatable')}, "
                f"실행 중 Pod requests {requested_text}, 추정 여유 "
                f"{snapshot.get('gpu_estimated_free')}."
            ),
            (
                f"Current snapshot for node/{node}: {_GPU_RESOURCE} capacity "
                f"{snapshot.get('gpu_capacity')}, allocatable {snapshot.get('gpu_allocatable')}, "
                f"non-terminal Pod requests {requested_text}, estimated free "
                f"{snapshot.get('gpu_estimated_free')}."
            ),
        )
    selector = shlex.quote(f"spec.nodeName={node}")
    return artifact(
        agent=agent,
        source="kubernetes",
        type="kubernetes_node_gpu_resources",
        status="unavailable" if node_error else ("partial" if partial else "ok"),
        confidence="low" if node_error else ("medium" if partial else "high"),
        title=ko_en(settings, "노드 GPU 리소스 스냅샷", "Node GPU resource snapshot"),
        query=(
            f"{kubectl_repr('nodes', name=node)} -o json; "
            f"kubectl get pods -A --field-selector {selector} -o json"
        ),
        summary=summary,
        result=snapshot,
    )


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
        name = response.get("name")
        if not isinstance(name, str) or (
            name not in {"pod_events", "workload_events", "namespace_events"}
            and not name.startswith("runai_control_plane_events:")
        ):
            continue
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            events.extend(
                item
                for item in data["items"]
                if isinstance(item, dict)
                and (
                    str(item.get("type") or "").casefold() == "warning"
                    or (
                        str(item.get("type") or "").casefold() == "normal"
                        and str(item.get("reason") or "").casefold()
                        in _OBSERVED_NORMAL_EVENT_REASONS
                    )
                )
            )
    return events


def _pod_event_scope_empty(responses: list[dict[str, object]]) -> bool:
    if any(
        response.get("name") == "pod"
        and not response.get("error")
        and isinstance(response.get("data"), dict)
        and response["data"]
        for response in responses
    ):
        return False
    scoped_lists = [
        response
        for response in responses
        if str(response.get("name") or "")
        in {
            "namespace_pods",
            "pod_events",
            "workload_events",
            "namespace_events",
        }
        or str(response.get("name") or "").startswith(
            ("runai_control_plane_pods:", "runai_control_plane_events:")
        )
    ]
    if not scoped_lists or any(response.get("error") for response in scoped_lists):
        return False
    return all(
        isinstance(response.get("data"), dict)
        and isinstance(response["data"].get("items"), list)
        and not response["data"]["items"]
        for response in scoped_lists
    )


def _node_conditions(responses: list[dict[str, object]]) -> list[object]:
    """Only ABNORMAL node conditions become evidence text.

    Healthy conditions carry the failure vocabulary anyway — type
    "DiskPressure" status False, message "kubelet has sufficient memory" —
    and kept feeding the keyword ranker a node_kubelet_pressure score on
    perfectly healthy nodes (the 2026-07-08 re-analysis landed on
    node_kubelet_pressure while its own self-check said there was no pressure
    evidence). A healthy node is summarized as one marker entry instead."""
    for response in responses:
        if response.get("name") != "node":
            continue
        data = response.get("data")
        if isinstance(data, dict) and isinstance(data.get("conditions"), list):
            # Compact MCP responses can append transport sentinels such as
            # {"truncated": 1}. They are not Kubernetes conditions and must
            # not inflate the checked count or enter polarity evaluation.
            conditions = [
                c
                for c in data["conditions"]
                if isinstance(c, dict)
                and str(c.get("type") or "").strip()
                and "status" in c
            ]
            abnormal = [
                c
                for c in conditions
                if (str(c.get("type")) == "Ready" and str(c.get("status")) != "True")
                or (str(c.get("type")) != "Ready" and str(c.get("status")) == "True")
            ]
            if abnormal:
                return abnormal
            if conditions:
                return [{"node_conditions_healthy": True, "checked": len(conditions)}]
    return []


_CAUSE_BEARING_NODE_CONDITIONS = frozenset(
    {"DiskPressure", "MemoryPressure", "PIDPressure", "NetworkUnavailable"}
)
_NODE_CONDITION_TIMESTAMP_FIELDS = ("lastTransitionTime", "lastHeartbeatTime")


def _node_condition_artifacts(
    agent: str,
    target: AnalysisTarget,
    responses: list[dict[str, object]],
    *,
    time_range: dict[str, str] | None,
):
    """Publish condition-value facts without backdating a live Node snapshot.

    The broad Node response remains operator context. A pressure/network
    condition gets a causal card only while the alert is still firing, or when
    Kubernetes' own transition/heartbeat timestamp falls inside the incident
    window. This keeps a condition that became true after a historical incident
    from explaining that incident, while preserving an exact in-window signal
    that Warning Events or Prometheus may not have captured.
    """
    artifacts = []
    historical = bool(str(target.resolved_at or "").strip())
    bounded_window = _valid_node_condition_window(time_range)
    live_scoped = not historical and bounded_window
    for response in responses:
        if response.get("name") != "node" or response.get("error"):
            continue
        data = response.get("data")
        if not isinstance(data, dict):
            continue
        node = str(data.get("name") or target.node or "").strip()
        conditions = data.get("conditions")
        if not node or not isinstance(conditions, list):
            continue
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            condition_type = str(condition.get("type") or "").strip()
            if condition_type not in _CAUSE_BEARING_NODE_CONDITIONS:
                continue
            raw_status = str(condition.get("status") or "").strip()
            normalized_status = raw_status.casefold()
            evidence_window, matched_timestamps = _node_condition_evidence_window(
                condition, time_range
            )
            timestamp_scoped = bool(evidence_window)
            semantically_known = normalized_status in {"true", "false"}
            scoped = semantically_known and (live_scoped or timestamp_scoped)
            if scoped:
                polarity = "present" if normalized_status == "true" else "absent"
                coverage = "scoped"
            else:
                # Unknown condition states and current snapshots taken while
                # replaying a resolved incident remain visible, not causal.
                polarity, coverage = "unknown", "partial"
            if live_scoped:
                snapshot_role = "live_incident"
            elif timestamp_scoped:
                snapshot_role = "incident_window"
            else:
                snapshot_role = "current_context"

            observation: dict[str, object] = {
                "kind": "kubernetes_node_condition",
                "predicate": f"kubernetes_node_condition:{condition_type.casefold()}",
                "polarity": polarity,
                "coverage": coverage,
                "observed_entity": {"kind": "node", "name": node},
                "observation_window": time_range if scoped else {},
                "snapshot_role": snapshot_role,
            }
            if evidence_window:
                observation["evidence_window"] = evidence_window

            timestamps = {
                field: str(condition.get(field) or "")
                for field in _NODE_CONDITION_TIMESTAMP_FIELDS
                if str(condition.get(field) or "").strip()
            }
            matched_at = str(evidence_window.get("end") or "")
            if scoped:
                scope_note = (
                    "live firing snapshot"
                    if live_scoped and not matched_at
                    else f"incident timestamp {matched_at}"
                )
            else:
                scope_note = "current context; no condition timestamp overlaps the incident"
            summary = f"node/{node} {condition_type}={raw_status or 'Unknown'} ({scope_note})."
            artifacts.append(
                artifact(
                    agent=agent,
                    source="kubernetes",
                    type="kubernetes_node_condition",
                    status="ok",
                    confidence="high" if scoped else "low",
                    title=f"Kubernetes · node/{node} · {condition_type}",
                    query=f"{kubectl_repr('nodes', name=node)} -o json",
                    summary=summary,
                    result={
                        "node": node,
                        "condition": condition_type,
                        "status": raw_status or "Unknown",
                        "timestamp_provenance": timestamps,
                        "matched_incident_timestamps": matched_timestamps,
                        "observation": observation,
                    },
                )
            )
    return artifacts


def _node_cordon_artifact(
    agent: str,
    target: AnalysisTarget,
    responses: list[dict[str, object]],
    *,
    time_range: dict[str, str] | None,
):
    """Publish a cordon snapshot without backdating its current-state value."""
    artifacts = []
    historical = bool(str(target.resolved_at or "").strip())
    causal = not historical and _incident_shows_unschedulable(target, responses)
    for response in responses:
        if response.get("name") != "node" or response.get("error"):
            continue
        data = response.get("data")
        if not isinstance(data, dict):
            continue
        node = str(data.get("name") or target.node or "").strip()
        unschedulable = bool(data.get("unschedulable"))
        if not node or not unschedulable:
            continue

        polarity, coverage, confidence, snapshot_role = (
            ("present", "scoped", "high", "live_incident")
            if causal
            else ("unknown", "partial", "low", "current_context")
        )
        scope_note = (
            "current context; a resolved incident is not explained by a current cordon"
            if historical
            else "current context; no unschedulable/pending symptom in this incident"
            if not causal
            else "live firing snapshot; incident shows an unschedulable/pending symptom"
        )
        observation = {
            "kind": "kubernetes_node_cordon",
            "predicate": "kubernetes_node_cordon",
            "polarity": polarity,
            "coverage": coverage,
            "observed_entity": {"kind": "node", "name": node},
            "observation_window": time_range if causal else {},
            "snapshot_role": snapshot_role,
        }
        artifacts.append(
            artifact(
                agent=agent,
                source="kubernetes",
                type="kubernetes_node_cordon",
                status="ok",
                confidence=confidence,
                title=f"Kubernetes · node/{node} · Cordoned",
                query=f"{kubectl_repr('nodes', name=node)} -o json",
                summary=(
                    f"node/{node} is cordoned (SchedulingDisabled — "
                    "spec.unschedulable=true), so it is excluded from scheduling and "
                    "pending pods may report 'node(s) were unschedulable'. "
                    f"({scope_note})"
                ),
                result={
                    "node": node,
                    "unschedulable": True,
                    "observation": observation,
                },
            )
        )
    return artifacts


_UNSCHEDULABLE_ALERT_MARKERS = ("unschedulable", "pending", "failedscheduling")
_UNSCHEDULABLE_EVENT_REASONS = frozenset({"failedscheduling", "unschedulable"})
_UNSCHEDULABLE_EVENT_MESSAGE_MARKERS = (
    "unschedulable",
    "were unschedulable",
    "nodes are available",
)


def _incident_shows_unschedulable(
    target: AnalysisTarget, responses: list[dict[str, object]]
) -> bool:
    """Whether alert metadata or collected Kubernetes objects show scheduling failure."""
    target_text = [str(target.alert_name or "")]
    # AnalysisTarget normally keeps alert_name only. Accept optional summary/
    # annotation attributes as well so callers with richer target objects get
    # the same safe scheduling gate without changing the target schema.
    for field in ("annotation", "annotations", "summary", "description"):
        value = getattr(target, field, "")
        if isinstance(value, dict):
            target_text.extend(str(item or "") for item in value.values())
        elif isinstance(value, (str, int, float)):
            target_text.append(str(value))
    if any(
        marker in text.casefold()
        for text in target_text
        for marker in _UNSCHEDULABLE_ALERT_MARKERS
    ):
        return True

    for response in responses:
        if not isinstance(response, dict) or response.get("error"):
            continue
        for item in _response_dicts(response.get("data")):
            reason = str(item.get("reason") or "").casefold()
            message = str(item.get("message") or "").casefold()
            if (
                reason in _UNSCHEDULABLE_EVENT_REASONS
                or any(marker in message for marker in _UNSCHEDULABLE_EVENT_MESSAGE_MARKERS)
            ):
                return True
            status = item.get("status")
            phase = (
                status.get("phase")
                if isinstance(status, dict)
                else item.get("phase")
            )
            if str(phase or "").casefold() == "pending":
                return True
    return False


def _response_dicts(value: object):
    """Yield every structured object in a compacted Kubernetes response."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _response_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _response_dicts(child)


def _valid_node_condition_window(time_range: dict[str, str] | None) -> bool:
    if not time_range:
        return False
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    return start is not None and end is not None and start <= end


def _node_condition_evidence_window(
    condition: dict[str, object], time_range: dict[str, str] | None
) -> tuple[dict[str, str], dict[str, str]]:
    """Return exact Kubernetes condition timestamps that overlap the incident."""
    if not _valid_node_condition_window(time_range):
        return {}, {}
    assert time_range is not None
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    assert start is not None and end is not None
    matched: list[tuple[object, str, str]] = []
    for field in _NODE_CONDITION_TIMESTAMP_FIELDS:
        raw = str(condition.get(field) or "").strip()
        observed_at = parse_incident_time(raw)
        if observed_at is not None and observed_at.year > 1 and start <= observed_at <= end:
            matched.append((observed_at, field, raw))
    if not matched:
        return {}, {}
    matched.sort(key=lambda item: item[0])
    return (
        {"start": matched[0][2], "end": matched[-1][2]},
        {field: raw for _, field, raw in matched},
    )


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


def _crd_items(read_result: dict) -> list[dict]:
    data = read_result.get("data") if isinstance(read_result, dict) else None
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        # A single object (name= read) — treat as a one-item list.
        if data.get("kind") or data.get("metadata"):
            return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _crd_not_ready(item: dict) -> dict[str, str] | None:
    """Report a not-healthy Run:ai CRD with its transition timestamp.

    Reads the standard K8s status.conditions (Ready/Succeeded != True is a
    problem; explicit Failed/Degraded == True is a problem) plus a top-level
    status.phase of Failed/Error/Pending. None for a healthy object."""
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    status = item.get("status") if isinstance(item.get("status"), dict) else {}
    name = str(metadata.get("name") or "")
    namespace = str(metadata.get("namespace") or "")
    conditions = status.get("conditions")
    for cond in conditions if isinstance(conditions, list) else []:
        if not isinstance(cond, dict):
            continue
        ctype = str(cond.get("type") or "")
        cstatus = str(cond.get("status") or "")
        bad = (ctype in ("Ready", "Available", "Succeeded") and cstatus == "False") or (
            ctype in ("Failed", "Degraded", "Error") and cstatus == "True"
        )
        if bad:
            return {
                "kind": str(item.get("kind") or ""),
                "name": name,
                "namespace": namespace,
                "reason": str(cond.get("reason") or ctype),
                "message": _clip(str(cond.get("message") or ""), 200),
                "lastTransitionTime": str(cond.get("lastTransitionTime") or ""),
            }
    phase = str(status.get("phase") or "")
    if phase and phase.lower() in ("failed", "error", "pending", "unschedulable"):
        return {
            "kind": str(item.get("kind") or ""),
            "name": name,
            "namespace": namespace,
            "reason": phase,
            "message": _clip(str(status.get("message") or ""), 200),
            "lastTransitionTime": "",
        }
    return None


def _runai_crd_health_artifacts(
    agent: str,
    settings: Settings,
    findings: list[dict[str, str]],
    *,
    time_range: dict[str, str] | None,
):
    """Publish each not-Ready Run:ai CRD as a timestamp-scoped health fact."""
    start = parse_incident_time((time_range or {}).get("start"))
    end = parse_incident_time((time_range or {}).get("end"))
    artifacts = []
    for finding in findings:
        transitioned_at = str(finding.get("lastTransitionTime") or "").strip()
        transition = parse_incident_time(transitioned_at)
        namespace = str(finding.get("namespace") or "").strip()
        # A cluster-scoped CRD cannot stand in for a namespaced incident target.
        # Keep it as context even when its transition falls inside the window.
        scoped = bool(namespace and transition and start and end and start <= transition <= end)
        polarity, coverage = ("present", "scoped") if scoped else ("unknown", "partial")
        kind = str(finding.get("kind") or "Run:ai resource")
        name = str(finding.get("name") or "unknown")
        reason = str(finding.get("reason") or "NotReady")
        message = str(finding.get("message") or "")
        summary = f"{kind}/{name} is not Ready: {reason}" + (f" — {message}" if message else ".")
        observation: dict[str, object] = {
            "kind": "runai_crd_health",
            "predicate": "runai_crd_health",
            "polarity": polarity,
            "coverage": coverage,
            "observed_entity": {"kind": kind, "name": name, "namespace": namespace},
            "observation_window": time_range if scoped else {},
        }
        if scoped:
            observation["evidence_window"] = {"start": transitioned_at, "end": transitioned_at}
        artifacts.append(
            artifact(
                agent=agent,
                source="kubernetes",
                type="runai_crd_health",
                status="ok",
                confidence="high" if scoped else "low",
                title=ko_en(settings, "Run:ai 리소스 상태", "Run:ai resource health"),
                summary=summary,
                result={"finding": finding, "observation": observation},
                highlights=salient_markers(finding),
            )
        )
    return artifacts


def _clip(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


async def collect_runai_crd_findings(
    settings: Settings, target: AnalysisTarget, namespaces: list[str]
) -> dict[str, object]:
    """Enumerate the Run:ai CRDs a human would check for a control-plane alert.

    Uses k8s_read (MCP-first), so it works even when the alert carries no
    workload/project label — turning "no workload identity, can't correlate"
    into "these projects/workloads are NOT Ready". Best-effort: returns
    {checked, findings} with findings=[] on any failure, never raises."""
    findings: list[dict[str, str]] = []
    checked: list[str] = []
    failed_kinds: list[str] = []
    warnings: list[str] = []
    truncated: list[str] = []

    async def scan(kind: str, namespace: str = "") -> None:
        token = ""
        label = f"{kind}{('/' + namespace) if namespace else ''}"
        for page in range(3):
            try:
                try:
                    result = await k8s_read(
                        settings, kind, namespace=namespace, continue_token=token, full_object=True
                    )
                except TypeError:
                    # Preserve compatibility with older injected/read adapters.
                    result = await k8s_read(settings, kind, namespace=namespace)
            except Exception as exc:  # noqa: BLE001 - enumeration is best-effort evidence
                failed_kinds.append(label)
                warnings.append(f"Run:ai CRD {label} scan failed: {exc.__class__.__name__}.")
                return
            if result.get("error"):
                # A 404 means this CRD kind is not served at the group's discovered
                # version (or is not installed) — the same "no such workloads here"
                # signal as an empty namespace, not a scan failure. Record it quietly
                # and warn only on real failures (auth, timeout, 5xx).
                if result.get("status_code") == 404 or "404" in str(result.get("error") or ""):
                    checked.append(label)
                else:
                    failed_kinds.append(label)
                    warnings.append(f"Run:ai CRD {label} scan failed: {result['error']}.")
                return
            if not page:
                checked.append(label)
            for item in _crd_items(result)[: settings.kubernetes_list_limit]:
                finding = _crd_not_ready(item)
                if finding:
                    finding["namespace"] = namespace
                    findings.append(finding)
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            token = str((data.get("metadata") or {}).get("continue") or "")
            if not token:
                return
            if settings.kubernetes_mcp_url and str(result.get("url") or "").startswith(settings.kubernetes_mcp_url):
                # The pinned MCP list schema has no continuation argument. Do
                # not re-read page one under a token it cannot honor.
                truncated.append(label)
                return
        if token:
            truncated.append(label)

    # Cluster-scoped org tree: which projects/queues/departments are unhealthy.
    for kind in ("projects", "queues", "departments"):
        await scan(kind)
    # Namespaced workloads + their pod-groups in the alert's own namespaces.
    # Run:ai workloads never live in cluster system namespaces, so scanning them
    # for Run:ai CRDs only produces 404/empty noise (e.g. a kube-system alert).
    scan_namespaces = _dedup_str(
        [n for n in namespaces if n and n not in _CRD_SCAN_SKIP_NAMESPACES]
    )
    for namespace in scan_namespaces[:4]:
        for kind in (*_RUNAI_WORKLOAD_KINDS, "podgroups"):
            await scan(kind, namespace)
    return {
        "checked": checked,
        "findings": findings[:20],
        "failed_kinds": failed_kinds,
        "warnings": warnings,
        "truncated": truncated,
    }


def _dedup_str(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


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
                result={
                    **res,
                    # Flowchart reads are live resource/API state.  Preserve
                    # them for operator context, but do not imply that a GET
                    # observed the historical incident condition.
                    "observation": {
                        "kind": "kubernetes_followup_read",
                        "predicate": f"kubernetes:{res.get('kind') or 'followup'}",
                        "polarity": "unavailable" if err else "unknown",
                        "coverage": "unknown" if err else "partial",
                    },
                },
            )
        )
    return results
