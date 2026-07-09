from __future__ import annotations

import base64
import json
import re
from typing import Any

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact, ko_en
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import cached_insight, complete, insight_cache_key, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)


class LokiCollector:
    name = "loki"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.loki_url and not self._settings.loki_mcp_url:
            summary = f"{NO_EVIDENCE} Loki is not configured; log evidence was skipped."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["loki.url"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="loki",
                        type="logs",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"loki_url_configured": False},
                    )
                ],
            )

        selector = _selector_for(target, plan)
        skipped_target_scope = ""
        # Loki rejects an empty stream selector `{}` with HTTP 400. When the alert has
        # no namespace/pod/workload to scope by, skip the target log queries (the
        # control-plane sweep below still runs on its own valid selector).
        if selector == "{}":
            queries = []
            skipped_target_scope = (
                "no namespace/pod/workload on this alert, so the target log queries "
                "were skipped (Loki forbids an empty {} selector)."
            )
        else:
            error_query = (
                f'{selector} |~ "(?i)(error|fail|oom|evict|crash|pending|unschedul|back-off)"'
            )
            queries = [("error_logs", error_query), ("recent_logs", selector)]
        # Control-plane sweep only when the plan says this alert implicates Run:ai —
        # otherwise every alert scraped runai/runai-backend and skewed ranking.
        control_plane_in_scope = plan.check_control_plane if plan is not None else True
        runai_selector = (
            _namespace_regex_selector(self._settings.runai_log_namespaces)
            if control_plane_in_scope
            else ""
        )
        if runai_selector:
            # Require an error-indicating term to co-occur with the control-plane
            # subsystem (or an outright panic/fatal). The previous broad
            # `error|fail|...|scheduler|queue|database` alternation matched almost
            # every control-plane log line, so this query returned rows for every
            # alert regardless of target and always steered ranking to
            # runai_control_plane_error. Keep it specific to real failures.
            runai_error_query = (
                f'{runai_selector} |~ '
                '"(?i)(reconcile.*(error|fail)|admission.*(error|denied|reject)|'
                'scheduler.*(error|fail|panic)|authorization.*(error|denied)|'
                'database.*(error|fail|timeout)|panic|fatal)"'
            )
            queries.append(("runai_control_plane_errors", runai_error_query))
            # A dying workload's real cause often sits in scheduler/backend logs that
            # NAME the workload but don't match the generic error regex above
            # ("evicted", "preempted", "over quota for project X", "unschedulable").
            # Correlate the control-plane namespaces to THIS workload so those lines
            # surface — targeted by identifier, so it doesn't re-introduce the broad
            # scrape that skewed every alert to runai_control_plane_error.
            correlation = _control_plane_correlation_term(target, plan)
            if correlation:
                queries.append(
                    (
                        "runai_control_plane_for_workload",
                        f'{runai_selector} |~ "(?i)({correlation})"',
                    )
                )
        query_results = []
        warnings: list[str] = []
        if skipped_target_scope:
            warnings.append(skipped_target_scope)

        used_mcp = False
        if self._settings.loki_mcp_url:
            try:
                query_results = await _collect_loki_mcp(self._settings, queries)
                used_mcp = True
            except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
                warnings.append(mcp_fallback_warning(exc))
        else:
            warnings.append(f"{MCP_FALLBACK_WARNING}: LOKI_MCP_URL not configured")

        if not used_mcp:
            if not self._settings.loki_url:
                summary = f"{NO_EVIDENCE} Loki MCP failed and direct URL is not configured."
                return CollectorResult(
                    agent=self.name,
                    status="unavailable",
                    summary=summary,
                    confidence="low",
                    missing_data=["loki.url"],
                    warnings=warnings,
                    artifacts=[
                        artifact(
                            agent=self.name,
                            source="loki",
                            type="logql",
                            status="unavailable",
                            confidence="low",
                            query="; ".join(query for _, query in queries),
                            summary=summary,
                            result={"loki_mcp_url_configured": True},
                        )
                    ],
                )
            query_results = await _collect_loki_direct(self._settings, queries, warnings)

        successful = [item for item in query_results if not item["error"]]
        populated = [item for item in successful if item["line_count"]]
        auth_failed = any(item["status_code"] == 401 for item in query_results)
        if populated:
            status = "ok"
            confidence = "high"
            summary = ko_en(
                self._settings,
                f"Loki {'MCP' if used_mcp else '직접'} 조회 완료 — "
                f"{len(query_results)}개 쿼리 그룹 중 {len(populated)}개에서 "
                "일치하는 로그 라인을 확인했습니다.",
                f"Loki {'MCP' if used_mcp else 'direct'} queries completed with matching log lines "
                f"for {len(populated)} of {len(query_results)} query group(s).",
            )
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "Loki에는 접속했지만 워크로드 로그 쿼리에 일치하는 라인이 없습니다. "
                "레이블 이름과 로그 보존 기간을 확인하세요.",
                "Loki is reachable, but the workload log queries returned "
                "no lines. Check label names and log retention.",
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "Loki 직접 조회가 실패했습니다.",
                "Loki direct queries failed.",
            )

        insight = await _llm_insight(self._settings, "Loki logs", summary, query_results)
        if insight:
            summary = insight
        result = {
            "loki_url": self._settings.loki_url,
            "loki_mcp_url": self._settings.loki_mcp_url,
            "used_mcp": used_mcp,
            "queries": query_results,
        }
        missing_data = [] if successful else ["loki.query"]
        if auth_failed:
            missing_data.append("loki.auth")
        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=result,
            missing_data=missing_data,
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="loki",
                    type="logql",
                    status=status,
                    confidence=confidence,
                    query="; ".join(item["query"] for item in query_results),
                    summary=summary,
                    result=result,
                )
            ],
        )


async def _llm_insight(
    settings: Settings, source: str, deterministic: str, evidence: object
) -> str | None:
    """Distill raw collector evidence into ONE senior-SRE insight line.

    Returns None when no LLM is configured or the call fails, so callers keep
    their deterministic summary.
    """
    if deterministic.strip().startswith(NO_EVIDENCE):
        return None
    insight_model = getattr(settings, "llm_model_insight", "")
    if not llm_configured(settings, insight_model):
        return None
    try:
        blob = json.dumps(evidence, default=str)[:3000]
    except (TypeError, ValueError):
        blob = str(evidence)[:3000]
    masker = _collector_masker(settings)
    source = masker.mask_text(source)
    blob = masker.mask_text(blob)
    deterministic = masker.mask_text(deterministic)
    system = (
        "You are a senior SRE reporting a finding to a colleague. From this one "
        "collector's raw evidence, write ONE (max two) sentence shaped: what you "
        "OBSERVED -> what it MEANS -> WHEN it started (include timestamps/counts when "
        "the data has them, e.g. 'reconcile failures repeating 40x since 10:52 — began "
        "6 minutes before the alert'). Grounded ONLY in the given evidence; never "
        "invent. If nothing notable, say so briefly. No preamble, no markdown."
    )
    if getattr(settings, "language", "en") == "ko":
        system += (
            " 한국어로 답하세요 (관찰한 것 → 의미 → 시작 시점). "
            "증거가 없으면 '증거를 찾기 어렵습니다.'라고만 답하세요."
        )
    user = f"Source: {source}\nDeterministic summary: {deterministic}\nRaw evidence:\n{blob}"
    key = insight_cache_key(source, getattr(settings, "language", "en"), deterministic, blob)

    async def compute() -> str | None:
        return await complete(
            settings,
            system=system,
            user=user,
            max_tokens=160,
            model=insight_model or None,
        )

    text = await cached_insight(key, compute)
    if not text:
        return None
    return masker.mask_text(" ".join(text.split())[:400])


def _collector_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _loki_headers(settings: Settings) -> tuple[dict[str, str], list[str]]:
    headers = {"Accept": "application/json"}
    warnings: list[str] = []
    if settings.loki_tenant_id:
        headers["X-Scope-OrgID"] = settings.loki_tenant_id
    if settings.loki_bearer_token:
        headers["Authorization"] = _bearer_header_value(settings.loki_bearer_token)
    elif settings.loki_basic_username or settings.loki_basic_password:
        if settings.loki_basic_username and settings.loki_basic_password:
            raw = f"{settings.loki_basic_username}:{settings.loki_basic_password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            warnings.append(
                "LOKI_BASIC_USERNAME and LOKI_BASIC_PASSWORD must both be set for Loki basic auth."
            )
    return headers, warnings


async def _collect_loki_direct(
    settings: Settings, queries: list[tuple[str, str]], warnings: list[str]
) -> list[dict[str, object]]:
    query_results: list[dict[str, object]] = []
    headers, auth_warnings = _loki_headers(settings)
    warnings.extend(auth_warnings)
    for name, query in queries:
        response = await get_json(
            base_url=settings.loki_url,
            path="/loki/api/v1/query_range",
            timeout_seconds=settings.loki_timeout_seconds,
            params={
                "query": query,
                "limit": str(settings.loki_query_limit),
                "direction": "BACKWARD",
            },
            headers=headers,
        )
        streams = _loki_streams(response.data)
        line_count = sum(len(stream.get("values", [])) for stream in streams)
        query_results.append(
            {
                "name": name,
                "query": query,
                "url": response.url,
                "status_code": response.status_code,
                "status": _loki_status(response.data),
                "stream_count": len(streams),
                "line_count": line_count,
                "sample_lines": _sample_lines(streams),
                "sample": compact(streams, limit=3),
                "error": response.error,
            }
        )
        if response.error:
            warnings.append(f"Loki query failed for {name}: {response.error}")
            if response.status_code == 401:
                warnings.append(_loki_unauthorized_warning(settings))
    return query_results


async def _collect_loki_mcp(
    settings: Settings, queries: list[tuple[str, str]]
) -> list[dict[str, object]]:
    datasource_uid = await _grafana_datasource_uid(settings.loki_mcp_url, "loki")
    return [
        await _mcp_query_loki(
            settings.loki_mcp_url, name, query, settings.loki_query_limit, datasource_uid
        )
        for name, query in queries
    ]


async def loki_mcp_query(settings: Settings, name: str, logql: str) -> dict[str, object]:
    datasource_uid = await _grafana_datasource_uid(settings.loki_mcp_url, "loki")
    return await _mcp_query_loki(
        settings.loki_mcp_url, name, logql, settings.loki_query_limit, datasource_uid
    )


async def _mcp_query_loki(
    url: str, name: str, logql: str, limit: int, datasource_uid: str = ""
) -> dict[str, object]:
    # grafana-mcp's query_loki_logs REQUIRES a real datasourceUid. Sending an empty
    # one (uid unresolved) makes it GET /datasources/uid/ -> 400 "id is invalid" on
    # EVERY query. Fail fast with an actionable message instead of that noise; the
    # caller records a clean fallback warning. (uid usually empty because grafana-mcp
    # can't list datasources — set secrets.grafanaServiceAccountToken.)
    if not datasource_uid:
        raise RuntimeError(
            "grafana datasource uid unresolved for loki — set "
            "secrets.grafanaServiceAccountToken so grafana-mcp can list datasources"
        )
    base_args = {"limit": limit, "direction": "BACKWARD"}
    args_list: list[dict[str, object]] = [
        {"datasourceUid": datasource_uid, "query": logql, **base_args},
        {"datasourceUid": datasource_uid, "logql": logql, **base_args},
        {"datasource_uid": datasource_uid, "query": logql, **base_args},
    ]
    data = await _call_mcp_json(url, "query_loki_logs", args_list)
    streams = _loki_streams(data)
    lines = _sample_lines(streams)
    if not lines:
        lines = _log_lines_from_mcp_data(data)
    line_count = sum(len(stream.get("values", [])) for stream in streams) or len(lines)
    return {
        "name": name,
        "query": logql,
        "url": f"{url}#query_loki_logs",
        "status_code": 200,
        "status": _loki_status(data),
        "stream_count": len(streams),
        "line_count": line_count,
        "sample_lines": lines[:8],
        "sample": compact(streams or data, limit=3),
        "error": None,
    }


# Grafana datasource uids are ^[a-zA-Z0-9\-_]{1,40}$; a numeric row id or a
# display name passed as datasourceUid makes grafana-mcp fail EVERY query with
# 400 "id is invalid" — which demoted the whole collector to the direct fallback.
_GRAFANA_UID = re.compile(r"^[a-zA-Z0-9\-_]{1,40}$")


async def _grafana_datasource_uid(url: str, datasource_type: str) -> str:
    try:
        data = await _call_mcp_json(url, "list_datasources", [{}])
    except Exception:  # noqa: BLE001 - query tools may work without discovery.
        return ""
    for datasource in _datasource_items(data):
        dtype = str(datasource.get("type") or "").lower()
        name = str(datasource.get("name") or "").lower()
        if datasource_type in dtype or datasource_type in name:
            uid = str(datasource.get("uid") or "")
            if _GRAFANA_UID.match(uid):
                return uid
    return ""


def _datasource_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("datasources", "items", "result"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    nested = data.get("data")
    if isinstance(nested, list):
        return [item for item in nested if isinstance(item, dict)]
    return []


async def _call_mcp_json(
    url: str, tool: str, args_list: list[dict[str, object]]
) -> object:
    last_error = ""
    for args in args_list:
        try:
            result = await mcp_call(url, tool, args)
        except Exception as exc:  # noqa: BLE001 - try the next schema candidate.
            last_error = f"{exc.__class__.__name__}: {exc}"
            continue
        error = mcp_error(result)
        if error:
            last_error = error
            continue
        data = mcp_tool_json(result)
        if isinstance(data, dict) and "raw" in data:
            last_error = "MCP result was not JSON"
            continue
        return data
    raise RuntimeError(last_error or f"{tool} failed")


def _log_lines_from_mcp_data(data: object) -> list[str]:
    if isinstance(data, str):
        return [line[:240] for line in data.splitlines() if line.strip()][:8]
    if isinstance(data, list):
        lines: list[str] = []
        for item in data:
            if isinstance(item, str) and item.strip():
                lines.append(item[:240])
            elif isinstance(item, dict):
                text = item.get("line") or item.get("message") or item.get("body")
                if isinstance(text, str) and text.strip():
                    lines.append(text[:240])
            if len(lines) >= 8:
                break
        return lines
    if isinstance(data, dict):
        for key in ("lines", "logs", "entries"):
            lines = _log_lines_from_mcp_data(data.get(key))
            if lines:
                return lines
    return []


def _bearer_header_value(token: str) -> str:
    if token.lower().startswith("bearer "):
        return token
    return f"Bearer {token}"


def _loki_auth_configured(settings: Settings) -> bool:
    return bool(
        settings.loki_bearer_token
        or (settings.loki_basic_username and settings.loki_basic_password)
    )


def _loki_unauthorized_warning(settings: Settings) -> str:
    if _loki_auth_configured(settings):
        return "Loki authentication was configured but the endpoint rejected it with HTTP 401."
    endpoint = settings.loki_url.lower()
    if "loki-gateway" in endpoint:
        return (
            "Loki returned HTTP 401 from loki-gateway. That is gateway Basic Auth, "
            "not a loki-read eviction symptom; set LOKI_URL to the direct loki-read service."
        )
    return (
        "Loki returned HTTP 401 from the configured endpoint. Evicted loki-read pods "
        "typically cause timeouts, 5xx responses, or no endpoints rather than HTTP 401; "
        "check whether LOKI_URL still points at an authenticated proxy or tenant-enforced endpoint."
    )


def _selector_for(target: AnalysisTarget, plan=None) -> str:
    namespace = target.namespace
    pod = target.pod
    workload = target.workload_name
    if plan is not None:
        # Plan scopes the query; fall back to target values it does not override.
        if plan.namespaces:
            namespace = plan.namespaces[0]
        pod = plan.pod or pod
        workload = plan.workload or workload
    selector_parts = []
    if namespace:
        selector_parts.append(f'namespace="{namespace}"')
    if pod:
        selector_parts.append(f'pod="{pod}"')
    elif workload:
        selector_parts.append(f'app=~".*{workload}.*"')
    return "{" + ",".join(selector_parts) + "}" if selector_parts else "{}"


def _control_plane_correlation_term(target: AnalysisTarget, plan=None) -> str:
    """Regex alternation of the identifiers the control plane logs THIS workload by
    (workload name, then project). Empty when nothing specific enough to correlate —
    a too-short term would match unrelated control-plane lines."""
    workload = (getattr(plan, "workload", "") or target.workload_name or "").strip()
    project = (target.project or "").strip()
    terms: list[str] = []
    for value in (workload, project):
        escaped = re.escape(value)
        if len(value) >= 3 and escaped not in terms:
            terms.append(escaped)
    return "|".join(terms)


def _namespace_regex_selector(namespaces: tuple[str, ...]) -> str:
    escaped = [namespace.replace("\\", "\\\\").replace('"', '\\"') for namespace in namespaces]
    if not escaped:
        return ""
    return '{namespace=~"' + "|".join(escaped) + '"}'


def _loki_status(data: object) -> str:
    if isinstance(data, dict):
        value = data.get("status")
        if isinstance(value, str):
            return value
    return "unknown"


def _loki_streams(data: object) -> list[dict[str, object]]:
    if not isinstance(data, dict):
        return []
    payload = data.get("data")
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    if not isinstance(result, list):
        return []
    return [item for item in result if isinstance(item, dict)]


def _sample_lines(streams: list[dict[str, object]], limit: int = 8) -> list[str]:
    """Readable log lines from Loki streams (values are [timestamp, line] pairs).

    Queries run direction=BACKWARD, so the first values are the newest — keep
    that order and cap line length so the artifact stays skimmable."""
    lines: list[str] = []
    for stream in streams:
        values = stream.get("values")
        if not isinstance(values, list):
            continue
        for pair in values:
            if isinstance(pair, list) and len(pair) >= 2:
                text = " ".join(str(pair[1]).split())
                if text:
                    lines.append(text[:240])
            if len(lines) >= limit:
                return lines
    return lines
