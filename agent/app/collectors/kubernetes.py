from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.config import Settings


class KubernetesCollector:
    name = "kubernetes"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        missing: list[str] = []
        if not target.namespace:
            missing.append("kubernetes.namespace")
        if not target.pod and not target.workload_name and not target.node:
            missing.append("kubernetes.target")

        token = _read_file(self._settings.kubernetes_token_path)
        if not token:
            summary = "Kubernetes service account token is not available."
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
        )
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
            summary = "Kubernetes API direct queries failed."

        details = {
            "kubernetes_api_url": self._settings.kubernetes_api_url,
            "namespace": target.namespace,
            "pod": target.pod,
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "node": target.node,
            "pod_statuses": pod_statuses,
            "warning_events": warning_events,
            "node_conditions": node_conditions,
            "runai_control_plane_pods": runai_control_plane_pods,
            "runai_control_plane_warning_events": runai_control_plane_events,
            "queries": responses,
        }

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
) -> list[dict[str, object]]:
    requests: list[tuple[str, str, dict[str, str] | None]] = []
    namespace = quote(target.namespace, safe="")
    if target.namespace and target.pod:
        pod = quote(target.pod, safe="")
        requests.append(("pod", f"/api/v1/namespaces/{namespace}/pods/{pod}", None))
        requests.append(
            (
                "pod_events",
                f"/api/v1/namespaces/{namespace}/events",
                _list_params(settings, {"fieldSelector": f"involvedObject.name={target.pod}"}),
            )
        )
    elif target.namespace:
        requests.append(("namespace_pods", f"/api/v1/namespaces/{namespace}/pods", _list_params(settings)))
        requests.append(("namespace_events", f"/api/v1/namespaces/{namespace}/events", _list_params(settings)))
    if target.node:
        node = quote(target.node, safe="")
        requests.append(("node", f"/api/v1/nodes/{node}", None))
    for runai_namespace in settings.runai_log_namespaces:
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
