from __future__ import annotations

from urllib.parse import quote

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json, post_form_json, post_json
from app.collectors.loki import _llm_insight
from app.config import Settings


class RunAICollector:
    name = "runai"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
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
            if not headers.get("Authorization"):
                if "runai.auth" not in missing:
                    missing.append("runai.auth")
                if "runai.query" not in missing:
                    missing.append("runai.query")
                summary = "Run:ai API authentication is unavailable; direct queries were skipped."
                details = {
                    "cluster": target.cluster,
                    "project": target.project,
                    "queue": target.queue,
                    "workload_name": target.workload_name,
                    "workload_type": target.workload_type,
                    "runai_workload_id": target.runai_workload_id,
                    "runai_base_url": self._settings.runai_base_url,
                    "queries": [],
                }
                return CollectorResult(
                    agent=self.name,
                    status="unavailable",
                    summary=summary,
                    confidence="low",
                    details=details,
                    missing_data=missing,
                    warnings=auth_warnings,
                    artifacts=[
                        artifact(
                            agent=self.name,
                            source="runai",
                            type="workload_context",
                            status="unavailable",
                            confidence="low",
                            query=(
                                "Run:ai API query skipped because no Authorization header "
                                "was available."
                            ),
                            summary=summary,
                            result=details,
                        )
                    ],
                )
            query_results = await _collect_runai_responses(self._settings, target, headers)
            auth_failed = any(item.get("status_code") == 401 for item in query_results)
            if auth_failed and _can_refresh_runai_token(self._settings):
                retry_headers, retry_warnings = await _runai_headers(
                    self._settings, prefer_oauth=True
                )
                if retry_headers.get("Authorization"):
                    auth_warnings.append(
                        "Run:ai returned HTTP 401; refreshed OAuth token and retried once."
                    )
                    auth_warnings.extend(retry_warnings)
                    query_results = await _collect_runai_responses(
                        self._settings, target, retry_headers
                    )
                    auth_failed = any(item.get("status_code") == 401 for item in query_results)
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
            if auth_failed and "runai.auth" not in missing:
                missing.append("runai.auth")

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
            if auth_failed:
                warnings.append("Run:ai API rejected the request with HTTP 401.")
            insight = await _llm_insight(
                self._settings, "Run:ai API", summary, query_results
            )
            if insight:
                summary = insight
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


def _can_refresh_runai_token(settings: Settings) -> bool:
    return bool(
        settings.runai_token_url
        and settings.runai_client_id
        and settings.runai_client_secret
    )


async def _runai_headers(
    settings: Settings, *, prefer_oauth: bool = False
) -> tuple[dict[str, str], list[str]]:
    warnings: list[str] = []
    token = "" if prefer_oauth else settings.runai_bearer_token
    if (
        not token
        and settings.runai_client_id
        and settings.runai_client_secret
        and (settings.runai_token_url or settings.runai_base_url)
    ):
        token = await _request_runai_token(settings, warnings)
    elif not token and (settings.runai_client_id or settings.runai_client_secret):
        warnings.append(
            "Run:ai client credential configuration is incomplete. "
            "Set both RUNAI_CLIENT_ID and RUNAI_CLIENT_SECRET; RUNAI_TOKEN_URL is optional "
            "when RUNAI_BASE_URL can infer a token endpoint."
        )

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = _bearer_header_value(token)
    elif settings.runai_base_url:
        warnings.append(
            "Run:ai API URL is configured, but no Authorization header could be built. "
            "Set RUNAI_BEARER_TOKEN or configure RUNAI_TOKEN_URL with RUNAI_CLIENT_ID "
            "and RUNAI_CLIENT_SECRET."
        )
    return headers, warnings


async def _request_runai_token(settings: Settings, warnings: list[str]) -> str:
    attempts: list[str] = []
    for url in _runai_token_urls(settings):
        json_response = await post_json(
            url=url,
            timeout_seconds=settings.runai_timeout_seconds,
            json_body={
                "grantType": "client_credentials",
                "clientId": settings.runai_client_id,
                "clientSecret": settings.runai_client_secret,
            },
            headers={"Content-Type": "application/json"},
        )
        token = _token_from_response(json_response.data)
        if json_response.ok and token:
            return token
        attempts.append(f"{url} json={json_response.error or 'missing access token'}")

        form_response = await post_form_json(
            url=url,
            timeout_seconds=settings.runai_timeout_seconds,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.runai_client_id,
                "client_secret": settings.runai_client_secret,
            },
        )
        token = _token_from_response(form_response.data)
        if form_response.ok and token:
            return token
        attempts.append(f"{url} form={form_response.error or 'missing access token'}")

    if attempts:
        warnings.append("Run:ai token request failed: " + "; ".join(attempts[:4]))
    else:
        warnings.append(
            "RUNAI_CLIENT_ID and RUNAI_CLIENT_SECRET are configured, "
            "but neither RUNAI_TOKEN_URL nor RUNAI_BASE_URL can produce a token URL."
        )
    return ""


def _runai_token_urls(settings: Settings) -> list[str]:
    urls: list[str] = []
    if settings.runai_token_url:
        urls.append(settings.runai_token_url)
    base_url = settings.runai_base_url.rstrip("/")
    if base_url:
        urls.extend(
            [
                f"{base_url}/auth/realms/runai/protocol/openid-connect/token",
                f"{base_url}/api/v1/token",
                f"{base_url}/api/v1/auth/token",
            ]
        )
    deduped: list[str] = []
    for url in urls:
        if url and url not in deduped:
            deduped.append(url)
    return deduped


def _token_from_response(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    for key in ("accessToken", "access_token", "token", "id_token"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _bearer_header_value(token: str) -> str:
    if token.lower().startswith("bearer "):
        return token
    return f"Bearer {token}"


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
