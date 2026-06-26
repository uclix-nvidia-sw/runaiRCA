from __future__ import annotations

from urllib.parse import quote

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json, post_form_json
from app.config import Settings


class RunAICollector:
    name = "runai"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        missing: list[str] = []
        if not target.project:
            missing.append("runai.project")
        if not target.queue:
            missing.append("runai.queue")
        if not target.workload_name and not target.runai_workload_id:
            missing.append("runai.workload")

        if not self._settings.runai_base_url:
            summary = (
                "Run:ai API is not configured. Using alert labels and annotations "
                "as scheduling context."
            )
            status = "partial" if len(missing) < 3 else "unavailable"
            confidence = "low"
        else:
            headers, auth_warnings = await _runai_headers(self._settings)
            query_results = await _collect_runai_responses(self._settings, target, headers)
            successful = [item for item in query_results if not item.get("error")]
            if successful and not missing:
                summary = (
                    "Run:ai API direct queries completed for workload, project, "
                    "and queue context."
                )
                status = "ok"
                confidence = "high"
            elif successful:
                summary = (
                    "Run:ai API is reachable, but alert labels are missing some project, queue, "
                    "or workload identity needed for complete correlation."
                )
                status = "partial"
                confidence = "medium"
            else:
                summary = "Run:ai API direct queries failed."
                status = "unavailable"
                confidence = "low"
                missing.append("runai.query")

            details = {
                "cluster": target.cluster,
                "project": target.project,
                "queue": target.queue,
                "workload_name": target.workload_name,
                "workload_type": target.workload_type,
                "runai_workload_id": target.runai_workload_id,
                "runai_base_url": self._settings.runai_base_url,
                "queries": query_results,
            }
            warnings = auth_warnings + [
                f"Run:ai {item['name']} query failed: {item['error']}"
                for item in query_results
                if item.get("error")
            ]
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
                        source="runai",
                        type="workload_context",
                        status=status,
                        confidence=confidence,
                        query="; ".join(item["path"] for item in query_results),
                        summary=summary,
                        result=details,
                    )
                ],
            )

        details = {
            "cluster": target.cluster,
            "project": target.project,
            "queue": target.queue,
            "workload_name": target.workload_name,
            "workload_type": target.workload_type,
            "runai_workload_id": target.runai_workload_id,
            "gpu_context": {
                "gpu_request": "",
                "gpu_allocated": "",
                "scheduler": "runai-scheduler",
            },
        }

        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=details,
            missing_data=missing,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="runai",
                    type="workload_context",
                    status=status,
                    confidence=confidence,
                    query="runai workload/project/queue lookup",
                    summary=summary,
                    result=details,
                )
            ],
        )


async def _runai_headers(settings: Settings) -> tuple[dict[str, str], list[str]]:
    warnings: list[str] = []
    token = settings.runai_bearer_token
    if not token and settings.runai_token_url and settings.runai_client_id:
        response = await post_form_json(
            url=settings.runai_token_url,
            timeout_seconds=settings.runai_timeout_seconds,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.runai_client_id,
                "client_secret": settings.runai_client_secret,
            },
        )
        if response.ok and isinstance(response.data, dict):
            value = response.data.get("access_token")
            if isinstance(value, str):
                token = value
        elif response.error:
            warnings.append(f"Run:ai token request failed: {response.error}")
    elif settings.runai_client_id and settings.runai_client_secret and not settings.runai_token_url:
        warnings.append(
            "RUNAI_CLIENT_ID and RUNAI_CLIENT_SECRET are configured, "
            "but RUNAI_TOKEN_URL is not set."
        )

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers, warnings


async def _collect_runai_responses(
    settings: Settings,
    target: AnalysisTarget,
    headers: dict[str, str],
) -> list[dict[str, object]]:
    requests: list[tuple[str, str, dict[str, str] | None]] = []
    if target.runai_workload_id:
        workload_id = quote(target.runai_workload_id, safe="")
        requests.append(
            ("workload_by_id", f"{settings.runai_workloads_path.rstrip('/')}/{workload_id}", None)
        )
    else:
        params = _query_params(
            {
                "name": target.workload_name,
                "workloadName": target.workload_name,
                "project": target.project,
                "queue": target.queue,
                "namespace": target.namespace,
            }
        )
        requests.append(("workloads", settings.runai_workloads_path, params))

    if target.project:
        project = quote(target.project, safe="")
        requests.append(("project", f"{settings.runai_projects_path.rstrip('/')}/{project}", None))
    if target.queue:
        queue = quote(target.queue, safe="")
        requests.append(("queue", f"{settings.runai_queues_path.rstrip('/')}/{queue}", None))

    responses: list[dict[str, object]] = []
    for name, path, params in requests:
        response = await get_json(
            base_url=settings.runai_base_url,
            path=path,
            timeout_seconds=settings.runai_timeout_seconds,
            params=params,
            headers=headers,
        )
        responses.append(
            {
                "name": name,
                "path": path,
                "url": response.url,
                "status_code": response.status_code,
                "error": response.error,
                "data": compact(response.data, limit=5),
            }
        )
    return responses


def _query_params(values: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in values.items() if value}
