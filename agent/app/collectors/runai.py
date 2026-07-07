from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json, post_form_json, post_json
from app.collectors.loki import _llm_insight
from app.collectors.runai_mcp import gather_runai_via_mcp
from app.config import Settings

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _version_from_results(query_results: list[dict[str, Any]]) -> str:
    """Pull the Run:ai version out of the MCP 'version' query result, if present."""
    for item in query_results or []:
        if item.get("name") == "version" and not item.get("error"):
            return _extract_version(item.get("data"))
    return ""


def _extract_version(data: Any) -> str:
    """Find a semver-ish version string in an arbitrary Run:ai version payload.

    Prefers dict keys that look like a version field, then falls back to any nested
    string that matches N.N(.N). Returns '' when nothing looks like a version."""
    if isinstance(data, str):
        match = _VERSION_RE.search(data)
        return match.group(0) if match else ""
    if isinstance(data, dict):
        for key, value in data.items():
            if "version" in str(key).lower():
                found = _extract_version(value)
                if found:
                    return found
        for value in data.values():
            found = _extract_version(value)
            if found:
                return found
    if isinstance(data, list):
        for item in data:
            found = _extract_version(item)
            if found:
                return found
    return ""


async def _fetch_runai_version(settings: Settings, headers: dict[str, str]) -> str:
    """Best-effort Run:ai control-plane version, '' when unavailable.

    The path is configurable (RUNAI_VERSION_PATH) and this never fails the collector
    — an unknown version simply means no version-aware known-issue suppression."""
    if not settings.runai_base_url or not settings.runai_version_path:
        return ""
    resp = await get_json(
        base_url=settings.runai_base_url,
        path=settings.runai_version_path,
        timeout_seconds=settings.runai_timeout_seconds,
        headers=headers,
    )
    return _extract_version(resp.data) if resp.ok else ""


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
                f"{NO_EVIDENCE} Run:ai API is not configured. Using alert labels and "
                "annotations as scheduling context."
            )
            status = "partial" if len(missing) < 3 else "unavailable"
            confidence = "low"
        else:
            headers, auth_warnings = await _runai_headers(self._settings)
            if not headers.get("Authorization") and not self._settings.runai_mcp_url:
                if "runai.auth" not in missing:
                    missing.append("runai.auth")
                if "runai.query" not in missing:
                    missing.append("runai.query")
                summary = (
                    f"{NO_EVIDENCE} Run:ai API authentication is unavailable; direct "
                    "queries were skipped."
                )
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
            # Prefer the runai-mcp server when configured (richer, spec-aware,
            # auto-authed by the managed service); fall back to direct HTTP on any MCP issue.
            query_results = await gather_runai_via_mcp(self._settings, target)
            used_mcp = query_results is not None
            if not used_mcp:
                query_results = await _collect_runai_responses(self._settings, target, headers)
            if used_mcp:
                auth_warnings.append("Run:ai queries gathered via the runai-mcp server.")
            auth_failed = any(item.get("status_code") == 401 for item in query_results)
            if auth_failed and not used_mcp and _can_refresh_runai_token(self._settings):
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
                summary = f"{NO_EVIDENCE} Run:ai API direct queries failed."
                status = "unavailable"
                confidence = "low"
                missing.append("runai.query")
            if auth_failed and "runai.auth" not in missing:
                missing.append("runai.auth")

            # Version comes from the MCP "version" query when MCP was used, else a
            # direct best-effort fetch (empty headers just yield "").
            runai_version = _version_from_results(query_results) if used_mcp else ""
            if not runai_version:
                runai_version = await _fetch_runai_version(self._settings, headers)
            details = {
                "cluster": target.cluster,
                "project": target.project,
                "queue": target.queue,
                "workload_name": target.workload_name,
                "workload_type": target.workload_type,
                "runai_workload_id": target.runai_workload_id,
                "runai_base_url": self._settings.runai_base_url,
                "runai_version": runai_version,
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
                        query="; ".join(
                            str(item.get("path") or item.get("query") or "")
                            for item in query_results
                        ),
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
