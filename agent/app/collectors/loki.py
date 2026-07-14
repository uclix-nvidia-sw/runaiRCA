from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from typing import Any

from app.collectors.base import (
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    artifact,
    incident_time_range,
    ko_en,
    parse_incident_time,
)
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.knowledge import _keyword_negated
from app.llm import cached_insight, complete, insight_cache_key, llm_configured
from app.masking import build_masker
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)

_LOKI_FAILURE_TOKEN_RE = re.compile(
    r"\b(?:error|fail(?:ed|ure)?|oom(?:killed)?|evict(?:ed|ion)?|"
    r"crash(?:ed|loop)?|pending|unschedul(?:able|ed)?|back-?off)\b",
    re.IGNORECASE,
)
_LOKI_NON_CAUSAL_LINE_RE = re.compile(
    r"\b(?:healthy|normal|nominal|ready|recovered|recovery|resolved|cleared|"
    r"fixed|remediated|succeed(?:ed|ing|s)?|success(?:ful(?:ly)?)?|no\s+(?:error|fail|"
    r"oom|evict|crash|pending|issue)|without\s+(?:error|fail|oom|evict|crash|pending))\b"
    r"|(?:정상|복구|해결|오류\s*없|실패\s*없|문제\s*없)",
    re.IGNORECASE,
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

        time_range = _incident_time_range(target)
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
            # Pod names are ephemeral. A restarted/replaced Pod can no longer
            # match the alert's exact {pod="…"} stream label even though Loki
            # still retains its incident-window lines. Add a narrowly scoped
            # namespace/body correlation using stable workload identity.
            if history_query := _workload_history_query(target, plan):
                queries.append(("workload_history_logs", history_query))
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
                query_results = await _collect_loki_mcp(
                    self._settings, queries, time_range
                )
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
            query_results = await _collect_loki_direct(
                self._settings, queries, warnings, time_range
            )

        successful = [item for item in query_results if not item["error"]]
        populated = [
            item
            for item in successful
            # A positive line count without retained timestamps is useful
            # operator context, not verified historical incident evidence.
            if item["line_count"]
            and _loki_entries_in_window(item.get("sample_entries"), time_range) is True
        ]
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
            "time_range": time_range,
            "queries": query_results,
        }
        missing_data = [] if successful else ["loki.query"]
        if auth_failed:
            missing_data.append("loki.auth")
        # The aggregate card is useful context for an operator, but a matching
        # line in one broad query must not be treated as proof for every log
        # hypothesis.  Each query below has its own predicate, polarity and
        # incident window so synthesis can distinguish e.g. "no OOM line" from
        # "scheduler line present" instead of keyword-counting the whole blob.
        collector_observation = {
            "kind": "loki_collector_summary",
            "predicate": "loki_collector_summary",
            "polarity": "unknown",
            "coverage": "partial",
            "observation_window": time_range or {},
        }
        artifacts = [
            artifact(
                agent=self.name,
                source="loki",
                type="logql",
                status=status,
                confidence=confidence,
                query="; ".join(item["query"] for item in query_results),
                summary=summary,
                result={**result, "observation": collector_observation},
            )
        ]
        artifacts.extend(
            _loki_query_artifact(
                self.name, item, target=target, plan=plan, time_range=time_range
            )
            for item in query_results
        )
        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=result,
            missing_data=missing_data,
            warnings=warnings,
            artifacts=artifacts,
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
    settings: Settings,
    queries: list[tuple[str, str]],
    warnings: list[str],
    time_range: dict[str, str] | None = None,
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
                **(time_range or {}),
            },
            headers=headers,
        )
        streams = _loki_streams(response.data)
        line_count = sum(len(stream.get("values", [])) for stream in streams)
        error = response.error
        if error is None and not _loki_native_response_complete(response.data):
            error = "Loki response missing successful data.result"
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
                "sample_entries": _sample_entries(streams),
                "stream_labels": _stream_label_sets(streams),
                "stream_labels_complete": _stream_labels_complete(streams),
                "sample": compact(streams, limit=3),
                "error": error,
                **({"time_range": time_range} if time_range else {}),
            }
        )
        if error:
            warnings.append(f"Loki query failed for {name}: {error}")
            if response.status_code == 401:
                warnings.append(_loki_unauthorized_warning(settings))
    return query_results


async def _collect_loki_mcp(
    settings: Settings, queries: list[tuple[str, str]], time_range: dict[str, str] | None = None
) -> list[dict[str, object]]:
    datasource_uid = await _grafana_datasource_uid(settings.loki_mcp_url, "loki")
    return [
        await _mcp_query_loki(
            settings.loki_mcp_url,
            name,
            query,
            settings.loki_query_limit,
            datasource_uid,
            time_range,
        )
        for name, query in queries
    ]


async def loki_mcp_query(
    settings: Settings,
    name: str,
    logql: str,
    *,
    time_range: dict[str, str] | None = None,
) -> dict[str, object]:
    datasource_uid = await _grafana_datasource_uid(settings.loki_mcp_url, "loki")
    return await _mcp_query_loki(
        settings.loki_mcp_url,
        name,
        logql,
        settings.loki_query_limit,
        datasource_uid,
        time_range,
    )


async def _mcp_query_loki(
    url: str,
    name: str,
    logql: str,
    limit: int,
    datasource_uid: str = "",
    time_range: dict[str, str] | None = None,
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
    # Match mcp-grafana's query_loki_logs schema exactly. The previous compatibility
    # retries mixed old argument names (`query`, `datasource_uid`, `startTime`) with
    # the current schema. When those retries failed, the last error came from a call
    # with no recognized datasourceUid and misleadingly reported "id is invalid".
    args: dict[str, object] = {
        "datasourceUid": datasource_uid,
        "logql": logql,
        "limit": limit,
        "direction": "backward",
        "queryType": "range",
    }
    if time_range:
        # mcp-grafana expects RFC3339 startRfc3339/endRfc3339, while Loki's
        # direct API calls them start/end. Keep the conversion at this boundary.
        args.update(
            {
                "startRfc3339": time_range["start"],
                "endRfc3339": time_range["end"],
            }
        )
    data = await _call_mcp_json(url, "query_loki_logs", [args])
    if not _loki_mcp_response_complete(data):
        return {
            "name": name,
            "query": logql,
            "url": f"{url}#query_loki_logs",
            "status_code": 200,
            "status": _loki_status(data),
            "stream_count": 0,
            "line_count": 0,
            "sample_lines": [],
            "sample_entries": [],
            "stream_labels": [],
            "stream_labels_complete": False,
            "sample": compact(data, limit=3),
            "error": "Loki MCP response missing a recognized log result",
            **({"time_range": time_range} if time_range else {}),
        }
    streams = _loki_streams(data)
    entries = _sample_entries(streams)
    if not entries:
        entries = _log_entries_from_mcp_data(data)
    if not entries:
        # Keep compatibility with MCP implementations that return plain text
        # rather than timestamped entries. Lack of a timestamp is explicit,
        # but the useful log line is not silently discarded.
        entries = [
            {"timestamp": "", "line": line}
            for line in _log_lines_from_mcp_data(data)
        ]
    lines = [entry["line"] for entry in entries]
    line_count = sum(len(stream.get("values", [])) for stream in streams) or _mcp_line_count(data)
    if not line_count:
        line_count = len(lines)
    status = _loki_status(data)
    # grafana-mcp returns log entries as {data: [{timestamp, line, labels}, ...]}
    # rather than Loki's native {data: {result: [...]}} payload.
    if status == "unknown" and lines:
        status = "success"
    return {
        "name": name,
        "query": logql,
        "url": f"{url}#query_loki_logs",
        "status_code": 200,
        "status": status,
        "stream_count": len(streams),
        "line_count": line_count,
        "sample_lines": lines[:8],
        "sample_entries": entries[:8],
        # A native Loki result exposes one complete label set per stream.  The
        # Grafana MCP flat-entry shape does not promise that it returned every
        # stream, even when individual entries happen to include labels, so it
        # deliberately remains unverifiable for target-scoped RCA evidence.
        "stream_labels": _stream_label_sets(streams),
        "stream_labels_complete": bool(streams) and _stream_labels_complete(streams),
        "sample": compact(streams or data, limit=3),
        "error": None,
        **({"time_range": time_range} if time_range else {}),
    }


def _incident_time_range(target: AnalysisTarget) -> dict[str, str] | None:
    """Compatibility wrapper for callers/tests that imported Loki's helper."""
    return incident_time_range(target)


def _loki_query_artifact(
    agent: str,
    item: dict[str, object],
    *,
    target: AnalysisTarget,
    plan: object | None,
    time_range: dict[str, str] | None,
):
    """Expose one LogQL query's scoped verdict as RCA-safe evidence."""
    observation = _loki_query_observation(
        item, target=target, plan=plan, time_range=time_range
    )
    name = str(item.get("name") or "logs")
    polarity = str(observation["polarity"])
    status = "unavailable" if polarity == "unavailable" else "ok"
    confidence = "high" if polarity in {"present", "absent"} else "low"
    if polarity == "present":
        summary = f"Loki {name}: matching log lines were present in the incident window."
    elif polarity == "absent":
        summary = f"{NO_EVIDENCE} Loki {name}: no matching log lines in the incident window."
    else:
        summary = f"Loki {name}: query result was unavailable or outside an incident window."
    return artifact(
        agent=agent,
        source="loki",
        type="logql_signal",
        status=status,
        confidence=confidence,
        title=f"Loki · {name}",
        query=str(item.get("query") or ""),
        summary=summary,
        result={
            "observation": observation,
            "line_count": int(item.get("line_count") or 0),
            "stream_count": int(item.get("stream_count") or 0),
            "sample_entries": item.get("sample_entries") or [],
            "time_range": time_range,
        },
    )


def _loki_query_observation(
    item: dict[str, object],
    *,
    time_range: dict[str, str] | None,
    target: AnalysisTarget | None = None,
    plan: object | None = None,
) -> dict[str, object]:
    """Classify a LogQL result without making unbounded empty searches refute RCA."""
    name = str(item.get("name") or "logs")
    window_verified = _loki_entries_in_window(item.get("sample_entries"), time_range)
    affirmative_lines = _loki_affirmative_lines(item.get("sample_entries"), time_range)
    if item.get("error"):
        polarity, coverage = "unavailable", "unknown"
    elif name == "runai_control_plane_errors":
        # This is intentionally a broad health sweep across Run:ai namespaces.
        # It can explain why to inspect the control plane, but it has no
        # workload/project identity and therefore cannot prove the alert's RCA.
        polarity, coverage = "unknown", "partial"
    elif not time_range:
        # A current/live query can help an operator, but it cannot confirm that
        # the same condition was absent at the historical incident time.
        polarity, coverage = "unknown", "partial"
    elif name == "recent_logs":
        # This is an intentionally unfiltered tail.  A normal lifecycle line
        # can mention a failure token (or merely contain application prose),
        # so its presence cannot ground a causal hypothesis.  The targeted
        # error query below may still produce a typed signal.
        polarity, coverage = "unknown", "partial"
    elif int(item.get("line_count") or 0) == 0:
        polarity, coverage = "absent", "scoped"
    elif window_verified is not True:
        # A proxy/MCP can return current logs despite a range-shaped request,
        # and some MCP responses omit timestamps entirely. Historical support
        # requires a retained log timestamp inside the incident window.
        polarity, coverage = "unknown", "partial"
    elif name == "error_logs" and not affirmative_lines:
        # The broad LogQL token matcher also returns e.g. "no OOM", "crash
        # recovered" and "OOMKilled=false".  Retain those lines for the
        # operator, but do not let a negated/healthy/recovery sentence become
        # causal support just because it contains a scary word.
        polarity, coverage = "unknown", "partial"
    else:
        polarity, coverage = "present", "scoped"
    observed_entity: dict[str, str] | None = None
    target_scope_verified: bool | None = None
    if target is not None and polarity in {"present", "absent"}:
        observed_entity, target_scope_verified = _loki_target_scope(
            name, item, target=target, plan=plan
        )
        if target_scope_verified is not True:
            # A LogQL selector is request intent, not returned-data
            # provenance.  A proxy may ignore a matcher, and flat MCP results
            # do not establish that labels cover every returned stream.  Do
            # not let either shape inherit the pipeline target as RCA support.
            polarity, coverage = "unknown", "partial"
    observation = {
        "kind": "loki_query",
        "predicate": f"log:{name}",
        "polarity": polarity,
        "coverage": coverage,
        "line_count": int(item.get("line_count") or 0),
        "stream_count": int(item.get("stream_count") or 0),
        "affirmative_line_count": len(affirmative_lines),
        "observation_window": time_range or {},
        "log_window_verified": window_verified,
    }
    if observed_entity:
        observation["observed_entity"] = observed_entity
    if target_scope_verified is not None:
        observation["target_scope_verified"] = target_scope_verified
    if polarity == "present":
        evidence_window = _loki_evidence_window(item.get("sample_entries"), time_range)
        if evidence_window:
            observation["evidence_window"] = evidence_window
    return observation


def _loki_affirmative_lines(
    entries: object, time_range: dict[str, str] | None
) -> list[str]:
    """Return in-window log lines that affirm, rather than negate, a failure.

    This deliberately analyzes only the error-token query.  It is not an NLP
    classifier: any ambiguity is excluded from causal support and remains on
    the evidence card as context.
    """
    if not time_range:
        return []
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return []
    affirmative: list[str] = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        timestamp = parse_incident_time(entry.get("timestamp"))
        line = entry.get("line")
        if timestamp is None or not (start <= timestamp <= end) or not isinstance(line, str):
            continue
        if _loki_line_affirms_failure(line):
            affirmative.append(line)
    return affirmative


def _loki_line_affirms_failure(line: str) -> bool:
    lowered = line.casefold()
    # A recovery/healthy assertion can share a sentence with the earlier error
    # token ("failed then recovered").  Favor a false negative over claiming a
    # resolved status line is the incident's cause.
    if _LOKI_NON_CAUSAL_LINE_RE.search(lowered):
        return False
    return any(
        not _keyword_negated(lowered, match.start(), match.end())
        for match in _LOKI_FAILURE_TOKEN_RE.finditer(lowered)
    )


def _loki_target_scope(
    name: str,
    item: dict[str, object],
    *,
    target: AnalysisTarget,
    plan: object | None,
) -> tuple[dict[str, str] | None, bool]:
    """Validate native Loki stream labels against the selector's target scope.

    ``workload_history_logs`` and the Run:ai control-plane correlation query
    intentionally match text inside broader streams.  Their labels cannot
    prove the alert workload identity, so they stay context-only.  Primary
    target stream queries require every returned stream to name the requested
    namespace and either the exact Pod or an exact workload label.
    """
    if name not in {"error_logs", "recent_logs"}:
        return None, False
    labels = item.get("stream_labels")
    if item.get("stream_labels_complete") is not True or not isinstance(labels, list) or not labels:
        return None, False

    namespace = target.namespace
    pod = target.pod
    workload = target.workload_name
    if plan is not None:
        namespaces = getattr(plan, "namespaces", ())
        if isinstance(namespaces, (list, tuple)) and namespaces and str(namespaces[0]).strip():
            namespace = str(namespaces[0]).strip()
        pod = str(getattr(plan, "pod", "") or pod).strip()
        workload = str(getattr(plan, "workload", "") or workload).strip()

    if not namespace:
        return None, False
    required: tuple[tuple[str, str], ...]
    entity: dict[str, str]
    if pod:
        required = (("namespace", namespace), ("pod", pod))
        entity = {"kind": "pod", "name": pod}
    elif workload:
        required = (("namespace", namespace),)
        entity = {"kind": "workload_name", "name": workload}
    else:
        required = (("namespace", namespace),)
        entity = {"kind": "namespace", "name": namespace}

    for raw_labels in labels:
        if not isinstance(raw_labels, dict):
            return None, False
        normalized = {
            str(key).strip().casefold(): str(value).strip()
            for key, value in raw_labels.items()
            if isinstance(value, (str, int, float)) and str(value).strip()
        }
        if any(normalized.get(label) != expected for label, expected in required):
            return None, False
        if not pod and workload:
            workload_labels = (
                normalized.get("workload"),
                normalized.get("workload_name"),
                normalized.get("app"),
                normalized.get("app_kubernetes_io_name"),
                normalized.get("runai_workload_id"),
            )
            if workload not in workload_labels:
                return None, False
    return entity, True


def _loki_evidence_window(
    entries: object, time_range: dict[str, str] | None
) -> dict[str, str]:
    """Return the actual timestamp span of retained in-range log evidence."""
    if not time_range:
        return {}
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return {}
    timestamps: list[tuple[datetime, str]] = []
    for entry in entries if isinstance(entries, list) else []:
        raw = entry.get("timestamp") if isinstance(entry, dict) else None
        parsed = parse_incident_time(raw)
        if parsed is not None and start <= parsed <= end:
            timestamps.append((parsed, str(raw)))
    if not timestamps:
        return {}
    timestamps.sort(key=lambda item: item[0])
    return {"start": timestamps[0][1], "end": timestamps[-1][1]}


def _loki_entries_in_window(
    entries: object, time_range: dict[str, str] | None
) -> bool | None:
    """Return whether retained log entry timestamps intersect an incident window."""
    if not time_range:
        return None
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return None
    timestamps = []
    for entry in entries if isinstance(entries, list) else []:
        timestamp = entry.get("timestamp") if isinstance(entry, dict) else None
        parsed = parse_incident_time(timestamp)
        if parsed is not None:
            timestamps.append(parsed)
    if not timestamps:
        return None
    return any(start <= timestamp <= end for timestamp in timestamps)


def _loki_native_response_complete(data: object) -> bool:
    """Whether a direct Loki response is an explicit successful stream result."""
    if not (
        isinstance(data, dict)
        and str(data.get("status") or "").lower() == "success"
        and isinstance(data.get("data"), dict)
        and isinstance(data["data"].get("result"), list)
    ):
        return False
    streams = data["data"]["result"]
    return not streams or any(
        isinstance(stream, dict) and isinstance(stream.get("values"), list)
        for stream in streams
    )


def _loki_mcp_response_complete(data: object) -> bool:
    """Recognize native Loki and Grafana MCP log result envelopes.

    An HTTP/MCP success transport with an unrecognized empty body must not be
    interpreted as an empty historical search. Grafana MCP may return either
    native Loki streams or a flat list under one of these documented keys.
    """
    if _loki_native_response_complete(data):
        return True
    if not isinstance(data, dict):
        return False
    return any(
        _loki_flat_log_result_complete(data.get(key))
        for key in ("data", "lines", "logs", "entries")
    )


def _loki_flat_log_result_complete(value: object) -> bool:
    """Whether a Grafana MCP flat log response is recognizable."""
    if not isinstance(value, list):
        return False
    if not value:
        return True
    return any(
        (isinstance(item, str) and bool(item.strip()))
        or (
            isinstance(item, dict)
            and any(
                isinstance(item.get(key), str) and bool(item.get(key).strip())
                for key in ("line", "message", "body")
            )
        )
        for item in value
    )


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
        for key in ("lines", "logs", "entries", "data"):
            lines = _log_lines_from_mcp_data(data.get(key))
            if lines:
                return lines
    return []


def _mcp_line_count(data: object) -> int:
    """Count Grafana MCP log entries without mistaking metadata for evidence."""
    if not isinstance(data, dict):
        return 0
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        try:
            return max(0, int(metadata.get("linesReturned") or 0))
        except (TypeError, ValueError):
            pass
    entries = data.get("data")
    if isinstance(entries, list):
        return sum(1 for entry in entries if isinstance(entry, dict) and entry.get("line"))
    return 0


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


def _workload_history_query(target: AnalysisTarget, plan=None) -> str:
    """Find retained logs for replaced Pods through a stable workload identifier.

    Kubernetes Pod UID/name labels are intentionally not assumed: Loki label
    sets differ by deployment. Namespace plus an escaped workload name or
    Run:AI workload ID is portable and remains bounded to this incident.
    """
    namespace = target.namespace
    workload = target.workload_name
    if plan is not None:
        if plan.namespaces:
            namespace = plan.namespaces[0]
        workload = plan.workload or workload
    if not namespace:
        return ""
    terms = _workload_history_terms(workload, target.runai_workload_id)
    if not terms:
        return ""
    return f'{{namespace="{namespace}"}} |~ "(?i)({"|".join(terms)})"'


def _workload_history_terms(*values: str) -> list[str]:
    terms: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if len(normalized) < 3:
            continue
        escaped = re.escape(normalized).replace('"', r'\"')
        if escaped not in terms:
            terms.append(escaped)
    return terms


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


def _sample_entries(
    streams: list[dict[str, object]], limit: int = 8
) -> list[dict[str, object]]:
    """Bounded timestamped entries preserving the incident's log order."""
    entries: list[dict[str, object]] = []
    for stream in streams:
        values = stream.get("values")
        if not isinstance(values, list):
            continue
        labels = _stream_labels(stream)
        for pair in values:
            if not isinstance(pair, list) or len(pair) < 2:
                continue
            line = " ".join(str(pair[1]).split())
            if not line:
                continue
            entry: dict[str, object] = {"timestamp": _log_timestamp(pair[0]), "line": line[:240]}
            if labels:
                entry["labels"] = labels
            entries.append(entry)
            if len(entries) >= limit:
                return entries
    return entries


def _log_entries_from_mcp_data(data: object, limit: int = 8) -> list[dict[str, object]]:
    """Extract timestamped Grafana MCP entries ({timestamp, line, labels})."""
    if isinstance(data, list):
        entries: list[dict[str, object]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            line = item.get("line") or item.get("message") or item.get("body")
            if not isinstance(line, str) or not line.strip():
                continue
            entry: dict[str, object] = {
                "timestamp": _log_timestamp(item.get("timestamp") or ""),
                "line": " ".join(line.split())[:240],
            }
            if labels := _label_mapping(item.get("labels")):
                entry["labels"] = labels
            entries.append(entry)
            if len(entries) >= limit:
                break
        return entries
    if isinstance(data, dict):
        for key in ("lines", "logs", "entries", "data"):
            entries = _log_entries_from_mcp_data(data.get(key), limit)
            if entries:
                return entries
    return []


def _stream_label_sets(streams: list[dict[str, object]]) -> list[dict[str, str]]:
    """Retain the native label set for every returned stream, never samples only."""
    return [_stream_labels(stream) for stream in streams]


def _stream_labels_complete(streams: list[dict[str, object]]) -> bool:
    """Whether every returned native stream carries a usable label map."""
    return bool(streams) and all(bool(_stream_labels(stream)) for stream in streams)


def _stream_labels(stream: dict[str, object]) -> dict[str, str]:
    return _label_mapping(stream.get("stream"))


def _label_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key).strip(): str(item).strip()
        for key, item in value.items()
        if str(key).strip() and isinstance(item, (str, int, float)) and str(item).strip()
    }


def _log_timestamp(value: object) -> str:
    """Render Loki nanoseconds as UTC RFC3339 while retaining unknown formats."""
    raw = str(value).strip().strip('"')
    try:
        numeric = int(raw)
        if numeric >= 10**15:  # Loki normally sends nanoseconds since epoch.
            return datetime.fromtimestamp(numeric / 1_000_000_000, UTC).isoformat().replace(
                "+00:00", "Z"
            )
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    return raw
