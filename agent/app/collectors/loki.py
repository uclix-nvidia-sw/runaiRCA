from __future__ import annotations

import base64
import json

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import complete, llm_configured


class LokiCollector:
    name = "loki"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.loki_url:
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
        error_query = f'{selector} |~ "(?i)(error|fail|oom|evict|crash|pending|unschedul|back-off)"'
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
            # control_plane_error. Keep it specific to real failures.
            runai_error_query = (
                f'{runai_selector} |~ '
                '"(?i)(reconcile.*(error|fail)|admission.*(error|denied|reject)|'
                'scheduler.*(error|fail|panic)|authorization.*(error|denied)|'
                'database.*(error|fail|timeout)|panic|fatal)"'
            )
            queries.append(("runai_control_plane_errors", runai_error_query))
        query_results = []
        headers, warnings = _loki_headers(self._settings)

        for name, query in queries:
            response = await get_json(
                base_url=self._settings.loki_url,
                path="/loki/api/v1/query_range",
                timeout_seconds=self._settings.loki_timeout_seconds,
                params={
                    "query": query,
                    "limit": str(self._settings.loki_query_limit),
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
                    "sample": compact(streams, limit=3),
                    "error": response.error,
                }
            )
            if response.error:
                warnings.append(f"Loki query failed for {name}: {response.error}")
                if response.status_code == 401:
                    warnings.append(_loki_unauthorized_warning(self._settings))

        successful = [item for item in query_results if not item["error"]]
        populated = [item for item in successful if item["line_count"]]
        auth_failed = any(item["status_code"] == 401 for item in query_results)
        if populated:
            status = "ok"
            confidence = "high"
            summary = (
                "Loki direct queries completed with matching log lines "
                f"for {len(populated)} of {len(query_results)} query group(s)."
            )
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = (
                f"{NO_EVIDENCE} Loki is reachable, but the workload log queries returned "
                "no lines. Check label names and log retention."
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} Loki direct queries failed."

        insight = await _llm_insight(self._settings, "Loki logs", summary, query_results)
        if insight:
            summary = insight
        result = {
            "loki_url": self._settings.loki_url,
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
    if not llm_configured(settings):
        return None
    try:
        blob = json.dumps(evidence, default=str)[:3000]
    except (TypeError, ValueError):
        blob = str(evidence)[:3000]
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
    text = await complete(
        settings,
        system=system,
        user=f"Source: {source}\nDeterministic summary: {deterministic}\nRaw evidence:\n{blob}",
        max_tokens=160,
    )
    if not text:
        return None
    return " ".join(text.split())[:400]


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
