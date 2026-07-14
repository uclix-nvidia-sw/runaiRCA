from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any
from urllib.parse import quote

from app.collectors.base import (
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    artifact,
    incident_time_range,
    ko_en,
)
from app.collectors.http_json import compact, get_json, post_oauth_token
from app.collectors.loki import _llm_insight
from app.collectors.runai_mcp import (
    gather_runai_via_mcp,
    valid_official_workload_id,
)
from app.config import Settings

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_RUNAI_TOKEN_CACHE_TTL_SECONDS = 30.0
_RUNAI_TOKEN_CACHE: dict[tuple[str, str, str, str], tuple[str, float]] = {}
_RUNAI_TOKEN_INFLIGHT: dict[
    tuple[int, tuple[str, str, str, str]],
    asyncio.Task[tuple[str, tuple[str, ...]]],
] = {}


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
            if not headers.get("Authorization"):
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
            # Prefer NVIDIA's official Run:ai MCP when configured. Its protected
            # HTTP endpoint verifies the same Run:ai bearer token used by direct
            # API reads; fall back to direct HTTP on any MCP issue.
            mcp_target_supported = not (
                target.workload_name or target.runai_workload_id
            ) or valid_official_workload_id(target.runai_workload_id)
            if self._settings.runai_mcp_url and not mcp_target_supported:
                auth_warnings.append(
                    "Official Run:ai MCP workload tools require an immutable UUID; "
                    "used direct API fallback for this alert identity."
                )
                query_results = None
            else:
                query_results = await gather_runai_via_mcp(
                    self._settings, target, headers=headers
                )
            if query_results is not None:
                query_results = _validated_runai_query_results(query_results)
            # A streamable MCP call can technically succeed while its tool body
            # is a gateway error page or an otherwise unparseable text payload.
            # That is not usable Run:ai evidence and must not turn into a
            # reassuring "queries completed" headline. The collector's MCP
            # snapshot is atomic: if any planned tool is unusable, fall back to
            # the authenticated direct API rather than reporting partial MCP
            # context as a complete target lookup.
            used_mcp = bool(query_results) and all(
                not item.get("error") for item in query_results
            )
            if not used_mcp:
                if query_results:
                    for item in query_results:
                        if item.get("error"):
                            auth_warnings.append(
                                "Run:ai MCP "
                                f"{item.get('name') or 'tool'} failed before direct "
                                f"fallback: {str(item['error'])[:300]}"
                            )
                    auth_warnings.append(
                        "Run:ai MCP returned an incomplete or unusable response; used "
                        "direct API fallback."
                    )
                query_results = _validated_runai_query_results(
                    await _collect_runai_responses(self._settings, target, headers)
                )
            if used_mcp:
                auth_warnings.append(
                    "Run:ai queries gathered via the official NVIDIA Run:ai MCP server."
                )
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
                    query_results = _validated_runai_query_results(
                        await _collect_runai_responses(
                            self._settings, target, retry_headers
                        )
                    )
                    auth_failed = any(item.get("status_code") == 401 for item in query_results)
            successful = [item for item in query_results if not item.get("error")]
            failed = [item for item in query_results if item.get("error")]
            if failed and "runai.query" not in missing:
                missing.append("runai.query")
            if auth_failed and "runai.auth" not in missing:
                missing.append("runai.auth")
            if successful and not failed and not missing:
                if used_mcp:
                    summary = ko_en(
                        self._settings,
                        "Run:ai MCP에서 워크로드/프로젝트 리소스/클러스터 "
                        "컨텍스트 조회를 완료했습니다.",
                        "Run:ai MCP queries completed for workload, project-resource, "
                        "and cluster context.",
                    )
                else:
                    summary = ko_en(
                        self._settings,
                        "Run:ai 직접 API에서 워크로드/프로젝트/큐 컨텍스트 "
                        "조회를 완료했습니다.",
                        "Run:ai direct API queries completed for workload, project, "
                        "and queue context.",
                    )
                status = "ok"
                confidence = "high"
            elif successful:
                retrieved = ", ".join(
                    sorted({str(item.get("name")) for item in successful if item.get("name")})
                )
                gaps = ", ".join(
                    [
                        *(str(item.get("name") or "query") for item in failed),
                        *(item for item in missing if item != "runai.query"),
                    ]
                ) or "remaining context"
                transport = "MCP" if used_mcp else "direct API"
                summary = ko_en(
                    self._settings,
                    f"Run:ai {transport}에서 {retrieved} 컨텍스트만 조회했습니다. "
                    f"확인하지 못한 항목: {gaps}.",
                    f"Run:ai {transport} returned partial context for {retrieved}; "
                    f"unavailable: {gaps}.",
                )
                status = "partial"
                confidence = "medium"
            else:
                summary = f"{NO_EVIDENCE} " + ko_en(
                    self._settings,
                    "Run:ai API 조회가 실패했습니다.",
                    "Run:ai API direct queries failed.",
                )
                status = "unavailable"
                confidence = "low"
                if "runai.query" not in missing:
                    missing.append("runai.query")
            # NVIDIA's focused MCP exposes no generic version endpoint. Retain
            # version-aware known-issue suppression through a direct best-effort
            # read using the same authorization header.
            runai_version = ""
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
            # A successful API round trip is context, not proof that every
            # queried Run:ai resource was healthy or even present. Preserve the
            # aggregate for operators, then emit one constrained observation per
            # API result so synthesis can distinguish an explicit 404/empty
            # workload result from a broad, paginated MCP list.
            collector_observation = {
                "kind": "runai_collector_summary",
                "predicate": "runai_collector_summary",
                "polarity": "unknown",
                "coverage": "partial",
            }
            artifacts = [
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
                    result={**details, "observation": collector_observation},
                )
            ]
            artifacts.extend(
                _runai_query_artifact(
                    self.name, item, target=target, used_mcp=used_mcp
                )
                for item in query_results
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
        (settings.runai_token_url or settings.runai_base_url)
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
        token = await _cached_runai_token(
            settings, warnings, force_refresh=prefer_oauth
        )
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
            "Set RUNAI_BEARER_TOKEN or configure RUNAI_CLIENT_ID and "
            "RUNAI_CLIENT_SECRET; RUNAI_TOKEN_URL is an optional endpoint override."
        )
    return headers, warnings


async def _cached_runai_token(
    settings: Settings,
    warnings: list[str],
    *,
    force_refresh: bool = False,
) -> str:
    """Share one short-lived OAuth exchange across concurrent MCP tool calls."""
    key = _runai_token_cache_key(settings)
    now = time.monotonic()
    if force_refresh:
        _RUNAI_TOKEN_CACHE.pop(key, None)
    else:
        cached = _RUNAI_TOKEN_CACHE.get(key)
        if cached and cached[1] > now:
            return cached[0]

    loop = asyncio.get_running_loop()
    inflight_key = (id(loop), key)
    task = _RUNAI_TOKEN_INFLIGHT.get(inflight_key)
    if task is None:

        async def exchange() -> tuple[str, tuple[str, ...]]:
            exchange_warnings: list[str] = []
            token = await _request_runai_token(settings, exchange_warnings)
            if token:
                _RUNAI_TOKEN_CACHE[key] = (
                    token,
                    time.monotonic() + _RUNAI_TOKEN_CACHE_TTL_SECONDS,
                )
            return token, tuple(exchange_warnings)

        task = asyncio.create_task(exchange())
        _RUNAI_TOKEN_INFLIGHT[inflight_key] = task

        def cleanup(done: asyncio.Task[tuple[str, tuple[str, ...]]]) -> None:
            if _RUNAI_TOKEN_INFLIGHT.get(inflight_key) is done:
                _RUNAI_TOKEN_INFLIGHT.pop(inflight_key, None)

        task.add_done_callback(cleanup)
    # One cancelled analysis/startup probe must not cancel the OAuth exchange
    # shared by other concurrent MCP calls.
    token, exchange_warnings = await asyncio.shield(task)
    warnings.extend(exchange_warnings)
    return token


def _runai_token_cache_key(settings: Settings) -> tuple[str, str, str, str]:
    secret_fingerprint = hashlib.sha256(
        settings.runai_client_secret.encode("utf-8")
    ).hexdigest()
    return (
        settings.runai_token_url,
        settings.runai_base_url,
        settings.runai_client_id,
        secret_fingerprint,
    )


async def _request_runai_token(settings: Settings, warnings: list[str]) -> str:
    attempts: list[str] = []
    for url in _runai_token_urls(settings):
        json_response = await post_oauth_token(
            url=url,
            timeout_seconds=settings.runai_timeout_seconds,
            json_body={
                "grantType": "client_credentials",
                "clientId": settings.runai_client_id,
                "clientSecret": settings.runai_client_secret,
            },
            headers={"Content-Type": "application/json"},
        )
        if json_response.ok:
            return json_response.token
        attempts.append(f"{url} json={json_response.error or 'missing access token'}")

        form_response = await post_oauth_token(
            url=url,
            timeout_seconds=settings.runai_timeout_seconds,
            form_data={
                "grant_type": "client_credentials",
                "client_id": settings.runai_client_id,
                "client_secret": settings.runai_client_secret,
            },
        )
        if form_response.ok:
            return form_response.token
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
                "transport": "direct",
            }
        )
    return responses


def _query_params(values: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in values.items() if value}


def _validated_runai_query_results(
    query_results: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Reject successful transports whose payload was not structured JSON.

    ``mcp_tool_json`` represents non-JSON tool text as ``{"raw": ...}``;
    the direct HTTP helper similarly preserves a non-JSON body as
    ``{"body": ...}``. Neither shape can establish the returned Run:ai
    resource state. Keep the payload visible to the operator, but surface it
    as an unavailable query rather than treating its HTTP/MCP round trip as a
    successful evidence collection.
    """
    validated: list[dict[str, object]] = []
    for raw_item in query_results:
        item = dict(raw_item)
        if not item.get("error"):
            payload_error = _runai_payload_error(
                item.get("data"), transport=str(item.get("transport") or "")
            )
            if payload_error:
                item["error"] = payload_error
        validated.append(item)
    return validated


def _runai_payload_error(data: object, *, transport: str = "") -> str:
    if data is None:
        return "Run:ai response did not contain JSON data"
    if isinstance(data, dict) and set(data) == {"raw"}:
        return "Run:ai MCP response was not JSON"
    if isinstance(data, dict) and set(data) == {"body"}:
        return "Run:ai API response was not JSON"
    if transport == "mcp" and (
        data in ({}, [], "") or _runai_is_explicitly_empty(data)
    ):
        return "Run:ai MCP response contained no resource data"
    return ""


def _runai_query_artifact(
    agent: str,
    item: dict[str, object],
    *,
    target: AnalysisTarget,
    used_mcp: bool,
):
    """Turn one Run:ai API result into a narrowly scoped evidence fact."""
    observation = _runai_query_observation(item, target=target, used_mcp=used_mcp)
    name = str(item.get("name") or "resource")
    polarity = str(observation["polarity"])
    status = "unavailable" if polarity == "unavailable" else "ok"
    confidence = "high" if polarity in {"present", "absent"} else "low"
    if polarity == "present":
        summary = f"Run:ai {name}: queried target resource was present."
    elif polarity == "absent":
        summary = f"{NO_EVIDENCE} Run:ai {name}: queried target resource was absent."
    else:
        summary = f"Run:ai {name}: query was unavailable or did not prove target coverage."
    return artifact(
        agent=agent,
        source="runai",
        type="runai_api_signal",
        status=status,
        confidence=confidence,
        title=f"Run:ai · {name}",
        query=str(item.get("path") or item.get("query") or ""),
        summary=summary,
        result={
            "observation": observation,
            "status_code": item.get("status_code"),
            "data": item.get("data"),
        },
    )


def _runai_query_observation(
    item: dict[str, object], *, target: AnalysisTarget, used_mcp: bool
) -> dict[str, object]:
    """Classify resource presence without treating a broad list as a negative.

    Direct resource paths and filtered workload lookups are scoped to the
    alert's identity. MCP's projects/queues calls may be paginated broad lists,
    so a missing name there remains unknown rather than becoming false evidence.
    """
    name = str(item.get("name") or "resource")
    time_range = incident_time_range(target)
    expected = _runai_expected_identity(name, target)
    status_code = item.get("status_code")
    if item.get("error"):
        if _runai_exact_resource_lookup(name, used_mcp=used_mcp) and status_code == 404:
            polarity, coverage = "absent", "scoped"
        else:
            polarity, coverage = "unavailable", "unknown"
    elif name == "version" or not expected:
        polarity, coverage = "unknown", "partial"
    elif _runai_data_contains_identity(
        item.get("data"), expected, resource=name, target=target
    ):
        polarity, coverage = "present", "scoped"
    elif _runai_is_explicitly_empty(item.get("data")):
        # A successful but empty body can be an ignored filter, an API gateway
        # envelope, or a truncated MCP response. Only an explicit 404 above
        # proves current absence for an exact Run:ai resource.
        polarity, coverage = "unknown", "partial"
    else:
        polarity, coverage = "unknown", "partial"
    # The Run:ai API exposes present resource state; unlike audit/event APIs it
    # does not make this lookup historical merely because the alert has a past
    # timestamp.  A current 404 or a currently-present workload is useful for
    # recovery context, but cannot prove the resource's state during a closed
    # incident window without a returned resource timestamp in that window.
    if time_range and polarity in {"present", "absent"}:
        polarity, coverage = "unknown", "partial"
    return {
        "kind": "runai_api_query",
        "predicate": f"runai:{name}",
        "polarity": polarity,
        "coverage": coverage,
        "expected_identity": expected,
        "observed_entity": _runai_observed_entity(name, target),
        "status_code": status_code,
        "observation_window": time_range or {},
    }


def _runai_exact_resource_lookup(name: str, *, used_mcp: bool) -> bool:
    """Whether a 404 names one requested resource rather than a collection.

    Run:ai MCP calls use collection endpoints (``/projects``, ``/queues``, and
    ``/workloads``).  A 404 there can mean an unsupported API path or a gateway
    route, not that the alert's project/queue/workload is absent.  Only the
    direct HTTP collector's per-resource paths can establish scoped absence.
    """
    return not used_mcp and name in {"workload_by_id", "project", "queue"}


def _runai_expected_identity(name: str, target: AnalysisTarget) -> str:
    if name in {"workloads", "workload_by_id", "workload_status"}:
        return target.runai_workload_id or target.workload_name
    if name in {"project", "projects"}:
        return target.project
    if name in {"queue", "queues"}:
        return target.queue
    return ""


def _runai_data_contains_identity(
    data: object,
    expected: str,
    *,
    resource: str,
    target: AnalysisTarget | None = None,
) -> bool:
    """Match only the queried resource's own identity fields.

    A workload response can embed a Project/Queue object. Recursing through
    every nested ``name`` made such context look like a matching workload.
    Traverse only known result envelopes, then inspect each resource item's
    top-level identity fields.
    """
    wanted = expected.strip().casefold()
    if not wanted:
        return False
    fields = {
        "workloads": {"name", "id", "workloadname", "workloadid"},
        "workload_by_id": {"name", "id", "workloadname", "workloadid"},
        "workload_status": {"name", "id", "workloadname", "workloadid"},
        "project": {"name", "id", "project", "projectname"},
        "projects": {"name", "id", "project", "projectname"},
        "queue": {"name", "id", "queue", "queuename"},
        "queues": {"name", "id", "queue", "queuename"},
    }.get(resource, {"name", "id"})
    for item in _runai_resource_items(data, resource):
        for key, value in item.items():
            normalized = str(key).replace("_", "").replace("-", "").casefold()
            if normalized in fields and str(value).strip().casefold() == wanted:
                # A human-readable workload name is not globally unique. When
                # the returned resource declares its project or queue, make
                # sure those values agree with the alert instead of relabelling
                # a same-named workload from another scope as the target.  An
                # immutable workload id remains the authoritative identity and
                # deliberately does not lose to stale auxiliary labels.
                if (
                    resource in {"workloads", "workload_by_id", "workload_status"}
                    and target is not None
                    and not target.runai_workload_id
                    and not _runai_workload_scope_matches(item, target)
                ):
                    continue
                return True
    return False


def _runai_workload_scope_matches(item: dict[str, object], target: AnalysisTarget) -> bool:
    """Reject a same-named workload when returned scope conflicts with alert.

    Some Run:ai responses embed ``project``/``queue`` as objects while others
    expose ``projectName``/``queueName``.  Absence of those fields is not a
    conflict (the request may already have filtered it), but an explicit
    different value must not be used as scoped target evidence.
    """
    project_matches = _runai_scope_matches(
        item, target.project, {"project", "projectname"}
    )
    queue_matches = _runai_scope_matches(
        item, target.queue, {"queue", "queuename"}
    )
    return project_matches and queue_matches


def _runai_scope_matches(
    item: dict[str, object], expected: str, aliases: set[str]
) -> bool:
    wanted = expected.strip().casefold()
    if not wanted:
        return True
    observed: list[str] = []
    for key, value in item.items():
        normalized = str(key).replace("_", "").replace("-", "").casefold()
        if normalized not in aliases:
            continue
        if isinstance(value, dict):
            value = value.get("name") or value.get("displayName") or ""
        if isinstance(value, (str, int, float)) and str(value).strip():
            observed.append(str(value).strip().casefold())
    return not observed or wanted in observed


def _runai_resource_items(data: object, resource: str) -> list[dict[str, object]]:
    """Flatten only API collection/envelope layers, never nested resource context."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        collection_keys = {
            "workloads": ("workloads", "items", "data", "results"),
            "workload_by_id": ("workloads", "items", "data", "results"),
            "workload_status": ("workloads", "items", "data", "results"),
            "project": ("projects", "items", "data", "results"),
            "projects": ("projects", "items", "data", "results"),
            "queue": ("queues", "items", "data", "results"),
            "queues": ("queues", "items", "data", "results"),
        }.get(resource, ("items", "data", "results"))
        items: list[dict[str, object]] = [data]
        for key in collection_keys:
            value = data.get(key)
            if isinstance(value, list):
                items.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                items.append(value)
        return items
    return []


def _runai_observed_entity(name: str, target: AnalysisTarget) -> dict[str, str]:
    if name in {"workloads", "workload_by_id", "workload_status"}:
        if target.runai_workload_id:
            return {"kind": "runai_workload_id", "name": target.runai_workload_id}
        return {"kind": "workload_name", "name": target.workload_name}
    if name in {"project", "projects"}:
        return {"kind": "project", "name": target.project}
    if name in {"queue", "queues"}:
        return {"kind": "queue", "name": target.queue}
    return {}


def _runai_is_explicitly_empty(data: object) -> bool:
    if data in (None, "", [], {}):
        return True
    if isinstance(data, list):
        return False
    if not isinstance(data, dict):
        return False
    envelope_keys = {
        "items",
        "workloads",
        "projects",
        "queues",
        "resources",
        "data",
        "result",
        "results",
    }
    metadata_keys = {
        "count",
        "total",
        "page",
        "pageSize",
        "page_size",
        "nextPageToken",
        "next_page_token",
        "status",
    }
    envelopes = [value for key, value in data.items() if key in envelope_keys]
    if not envelopes:
        return bool(data) and all(key in metadata_keys for key in data)
    if not all(_runai_is_explicitly_empty(value) for value in envelopes):
        return False
    # An empty resource envelope may carry pagination/status metadata. A real
    # sibling identity or resource field makes the payload non-empty.
    return all(
        key in envelope_keys
        or key in metadata_keys
        or _runai_is_explicitly_empty(value)
        for key, value in data.items()
    )
