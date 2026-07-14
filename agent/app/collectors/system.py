"""Node-level infrastructure collector (below Kubernetes).

The agent pod can't read host logs, so a privileged DaemonSet runs on every node
and exposes a read-only HTTP endpoint (GET /logs?source=dmesg|journal|syslog).
This collector queries that endpoint for the alert's node and surfaces
kernel/GPU/hardware errors (NVIDIA XID, NVRM, OOM, MCE, I/O errors, ext4, NVLink,
"fell off the bus") that RCA would otherwise never see.

Degrades gracefully exactly like loki.py: unconfigured -> status='unavailable'.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

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
from app.llm import complete, llm_configured
from app.masking import build_masker

# Host/kernel/GPU/hardware error signatures worth surfacing to RCA. Case-insensitive.
# ponytail: flat regex list, not a rule engine — add patterns here as they show up.
_ERROR_PATTERNS = re.compile(
    r"(?i)("
    r"xid|nvrm|nvlink|fell off the bus|"  # NVIDIA GPU driver / fabric
    r"\boom\b|out of memory|oom-kill|"  # memory pressure
    r"i/o error|ext4-fs error|ext4_|xfs|"  # filesystem / disk
    r"mce:|machine check|hardware error|"  # CPU/hardware
    r"call trace|kernel panic|bug:|segfault"  # kernel faults
    r")"
)

# Sources the DaemonSet endpoint understands.
_SOURCES = ("dmesg", "journal", "syslog")

# The ad-hoc capability remains bounded. It is an incident discriminator, not
# a way to export host logs.
_QUERY_MAX_LOOKBACK_SECONDS = 86400
_QUERY_DEFAULT_LOOKBACK_SECONDS = 900
_QUERY_MAX_LINES = 1000
_QUERY_DEFAULT_LINES = 100
_SYSTEM_LOG_SOURCE_GROUP = "node_system"


async def system_log_query(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    """Return one bounded, metadata-only node-log observation.

    This is deliberately separate from :class:`SystemCollector`'s base gather.
    Callers may select one known log source for the alert's node, but cannot
    redirect the request to another node, expand the lookback, or receive log
    bodies.  The returned observation contains counts and coarse signal types
    only, which keeps host logs (where credentials can appear) out of later
    reasoning and knowledge-candidate paths.
    """
    if not isinstance(args, dict):
        return _query_error("arguments must be an object")
    source = str(args.get("source") or "").strip().lower()
    if source not in _SOURCES:
        return _query_error(
            "source must be one of: " + ", ".join(_SOURCES),
            source=source,
        )
    node = str(target.node or "").strip()
    requested_node = str(args.get("node") or "").strip()
    if not node:
        return _query_error("the alert has no node scope", source=source)
    if requested_node and requested_node != node:
        return _query_error("node must match the alert node scope", source=source, node=node)
    requested_lookback = _bounded_int(
        args.get("lookback_seconds", _QUERY_DEFAULT_LOOKBACK_SECONDS),
        minimum=60,
        maximum=_QUERY_MAX_LOOKBACK_SECONDS,
        label="lookback_seconds",
    )
    if isinstance(requested_lookback, str):
        return _query_error(requested_lookback, source=source, node=node)
    line_value = args.get("lines", args.get("limit", _QUERY_DEFAULT_LINES))
    lines = _bounded_int(
        line_value,
        minimum=1,
        maximum=_QUERY_MAX_LINES,
        label="lines",
    )
    if isinstance(lines, str):
        return _query_error(lines, source=source, node=node, lookback=requested_lookback)
    grep, grep_error = _safe_grep(args.get("grep"))
    if grep_error:
        return _query_error(
            grep_error, source=source, node=node, lookback=requested_lookback, limit=lines
        )
    if not getattr(settings, "enable_system_agent", False) or not getattr(
        settings, "system_agent_url", ""
    ):
        return _query_error(
            "system agent is not configured",
            source=source,
            node=node,
            lookback=requested_lookback,
        )

    # Only journalctl accepts a trustworthy start/end predicate. For a past
    # incident, use it rather than a current log tail; dmesg/syslog remain live
    # context because their endpoints cannot safely reconstruct old state.
    time_range = incident_time_range(target) if source == "journal" else None
    if time_range:
        start = parse_incident_time(time_range["start"])
        end = parse_incident_time(time_range["end"])
        lookback = max(1, int((end - start).total_seconds())) if start and end else requested_lookback
        observation_window = time_range
    else:
        lookback = requested_lookback
        observation_window = _observation_window(lookback)

    address = node
    if "{node}" in settings.system_agent_url:
        internal_ip = await _node_internal_ip(settings, node)
        if internal_ip:
            address = internal_ip
    headers = (
        {"Authorization": f"Bearer {settings.system_agent_token}"}
        if getattr(settings, "system_agent_token", "")
        else None
    )
    params = {
        "source": source,
        "lines": str(lines),
        **({"grep": grep} if grep else {}),
        **({"since": time_range["start"], "until": time_range["end"]} if time_range else {}),
    }
    # A URL without ``{node}`` is a shared endpoint.  Its router needs the
    # explicit node parameter; otherwise a healthy response may belong to an
    # arbitrary/default node and be mislabeled as the alert node.
    if "{node}" not in settings.system_agent_url:
        params["node"] = node
    response = await get_json(
        base_url=_base_url_for_node(settings.system_agent_url, address),
        path="/logs",
        timeout_seconds=settings.system_agent_timeout_seconds,
        # `lines` is enforced by the system agent. `grep` is a literal escaped
        # here before being sent to the agent's regex endpoint.
        params=params,
        headers=headers,
    )
    if response.error:
        return _query_error(
            response.error, source=source, node=node, lookback=lookback, limit=lines
        )
    raw_lines = _lines(response.data)[-lines:]
    matching = [line for line in raw_lines if _ERROR_PATTERNS.search(line)]
    historical_window_verified = bool(
        time_range and _historical_journal_response_verified(response.data, time_range)
    )
    observation = _system_log_observation(
        source=source,
        node=node,
        lookback_seconds=lookback,
        limit=lines,
        scanned=len(raw_lines),
        matching=matching,
        observation_window=observation_window,
        historical_scope=historical_window_verified,
    )
    return {
        "query": (
            f"system logs source={source} node={node} start={observation_window['start']} "
            f"end={observation_window['end']} lines<={lines}"
        ),
        "title": "Node system logs",
        "summary": (
            f"{observation['matching_line_count']} matching system-log line(s) in "
            f"{source} (metadata only)"
        ),
        "error": None,
        "source_group": _SYSTEM_LOG_SOURCE_GROUP,
        "independence_group": _SYSTEM_LOG_SOURCE_GROUP,
        "observed_entity": observation["observed_entity"],
        "observation_window": observation_window,
        "polarity": observation["polarity"],
        "coverage": observation["coverage"],
        "observation": observation,
        "result": observation,
    }


def _query_error(
    error: str,
    *,
    source: str = "",
    node: str = "",
    lookback: int | None = None,
    limit: int | None = None,
) -> dict:
    """A query failure is itself safe, structured metadata; never include a body."""
    observation = {
        "schema_version": "v1",
        "kind": "system_log_query",
        "source_group": _SYSTEM_LOG_SOURCE_GROUP,
        "independence_group": _SYSTEM_LOG_SOURCE_GROUP,
        "scope": {"node": node, "source": source},
        "observed_entity": {"kind": "node", "name": node},
        "window": {"lookback_seconds": lookback},
        "observation_window": _observation_window(lookback),
        "polarity": "unavailable",
        "coverage": "unknown",
        "lookback_seconds": lookback,
        "result_limit": limit,
        "status": "unavailable",
    }
    return {
        "query": "system logs (bounded)",
        "title": "Node system logs",
        "summary": error,
        "error": error,
        "source_group": _SYSTEM_LOG_SOURCE_GROUP,
        "independence_group": _SYSTEM_LOG_SOURCE_GROUP,
        "observed_entity": observation["observed_entity"],
        "observation_window": observation["observation_window"],
        "polarity": observation["polarity"],
        "coverage": observation["coverage"],
        "observation": observation,
        "result": observation,
    }


def _bounded_int(value: object, *, minimum: int, maximum: int, label: str) -> int | str:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return f"{label} must be an integer between {minimum} and {maximum}"
    if not minimum <= parsed <= maximum:
        return f"{label} must be between {minimum} and {maximum}"
    return parsed


def _safe_grep(value: object) -> tuple[str, str]:
    """Return a literal bounded grep fit for the system-agent regex endpoint."""
    if value is None or value == "":
        return "", ""
    if not isinstance(value, str):
        return "", "grep must be a string"
    literal = value.strip()
    if not literal or len(literal) > 80:
        return "", "grep must be 1 to 80 characters"
    if any(ord(char) < 32 or ord(char) == 127 for char in literal):
        return "", "grep must not contain control characters"
    return re.escape(literal), ""


def _observation_window(
    lookback_seconds: int | None, end: datetime | None = None
) -> dict[str, str]:
    end = end or datetime.now(UTC)
    start = end - timedelta(seconds=lookback_seconds or 0)
    return {"start": start.isoformat(), "end": end.isoformat()}


def _system_log_observation(
    *,
    source: str,
    node: str,
    lookback_seconds: int,
    limit: int,
    scanned: int,
    matching: list[str],
    observation_window: dict[str, str],
    historical_scope: bool,
) -> dict:
    """Summarise log matches without retaining raw lines or response bodies."""
    categories = {
        "gpu_driver": r"(?i)xid|nvrm|nvlink|fell off the bus",
        "memory": r"(?i)\boom\b|out of memory|oom-kill",
        "filesystem": r"(?i)i/o error|ext4-fs error|ext4_|xfs",
        "hardware": r"(?i)mce:|machine check|hardware error",
        "kernel": r"(?i)call trace|kernel panic|bug:|segfault",
    }
    signal_types = [
        name
        for name, pattern in categories.items()
        if any(re.search(pattern, line) for line in matching)
    ]
    return {
        "schema_version": "v1",
        "kind": "system_log_query",
        "source_group": _SYSTEM_LOG_SOURCE_GROUP,
        "independence_group": _SYSTEM_LOG_SOURCE_GROUP,
        "scope": {"node": node, "source": source},
        "observed_entity": {"kind": "node", "name": node},
        "window": {"lookback_seconds": lookback_seconds},
        "observation_window": observation_window,
        # A bounded journal query can prove a matching line was inside the
        # incident window, but even that endpoint returns a finite tail: an
        # empty response cannot prove host-wide absence.
        "polarity": "present" if matching else "unknown",
        "coverage": "scoped" if matching and historical_scope else "partial",
        "lookback_seconds": lookback_seconds,
        "result_limit": limit,
        "status": "ok",
        "lines_scanned": scanned,
        "matching_line_count": len(matching),
        "signal_types": signal_types,
        "body_included": False,
        "historical_scope": historical_scope,
    }


def _historical_journal_response_verified(
    data: object, time_range: dict[str, str]
) -> bool:
    """Whether the endpoint confirms it returned the requested journal window.

    A bounded request alone is not evidence: a proxy or an incompatible system
    agent can return HTTP 200 with a bare body/list, another source, or a
    different time range.  The chart-owned endpoint echoes this small envelope,
    so require it before a historical log line can become scoped support.
    """
    return (
        isinstance(data, dict)
        and str(data.get("source") or "").strip().lower() == "journal"
        and str(data.get("since") or "") == time_range["start"]
        and str(data.get("until") or "") == time_range["end"]
        and isinstance(data.get("lines"), list)
    )


class SystemCollector:
    name = "system"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.enable_system_agent or not self._settings.system_agent_url:
            summary = (
                f"{NO_EVIDENCE} System agent is not configured; node/kernel evidence "
                "was skipped."
            )
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["system_agent.url"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="system_agent",
                        type="node_logs",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"system_agent_configured": False},
                    )
                ],
            )

        target_node = str(target.node or "").strip()
        node_source = str(getattr(target, "node_source", "") or "").strip()
        # Most unit/direct callers construct AnalysisTarget themselves; absent
        # provenance remains backward-compatible and treats their node as an
        # alert node. Pipeline-scoped targets explicitly label plan-derived
        # live nodes as ``plan``.
        alert_node = target_node if node_source in {"", "alert"} else ""
        planned_node = str(getattr(plan, "node", "") or "").strip()
        # The alert is authoritative when it names a node.  A plan may enrich
        # a missing node from a live replacement Pod, but it must not override
        # the resource identity the alert supplied.
        node = alert_node or planned_node or target_node
        node_origin = "alert" if alert_node else (node_source or ("plan" if planned_node else ""))
        resolved_pod = ""
        if not node:
            node, resolved_pod = await _node_from_target_pod(self._settings, target, plan)
            if node:
                node_origin = "live_pod"
        if not node:
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "이 알림에서 노드를 특정할 수 없어 노드/커널 증거 수집을 건너뛰었습니다 "
                "(노드 레이블이 없고 대상 pod로도 노드를 찾지 못한 경우).",
                "No node is associated with this alert; node/kernel "
                "evidence was skipped.",
            )
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["system_agent.node"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="system_agent",
                        type="node_logs",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"node": ""},
                    )
                ],
            )

        # Pod DNS usually cannot resolve bare node hostnames (http://dgx01:9095 ->
        # "Name or service not known"), so resolve the node's InternalIP from the
        # Kubernetes API and address the hostNetwork DaemonSet by IP. Falls back to
        # the node name when the lookup fails (e.g. no RBAC for nodes/get).
        address = node
        warnings: list[str] = []
        if "{node}" in self._settings.system_agent_url:
            internal_ip = await _node_internal_ip(self._settings, node)
            if internal_ip:
                address = internal_ip
            else:
                warnings.append(
                    f"Could not resolve InternalIP for node {node}; using the node "
                    "name, which may not resolve from pod DNS."
                )
        base_url = _base_url_for_node(self._settings.system_agent_url, address)
        token = self._settings.system_agent_token
        headers = {"Authorization": f"Bearer {token}"} if token else None
        time_range = incident_time_range(target)
        # A node discovered from a current Pod is useful to inspect, but cannot
        # prove that a historical incident occurred on that node.  Only an
        # alert-supplied node identity can scope old journal evidence.
        historical_node_scope_verified = bool(
            time_range and alert_node and node == alert_node
        )
        source_results = []
        raw_matches: dict[str, list[str]] = {}
        for source in _SOURCES:
            params = {"source": source, "lines": "500"}
            # Only journalctl has a trustworthy historical time predicate. A
            # dmesg/syslog tail is retained as *current-state* context but must
            # not be treated as proof about a past incident.
            if source == "journal" and time_range:
                params.update({"since": time_range["start"], "until": time_range["end"]})
            if "{node}" not in self._settings.system_agent_url:
                params["node"] = node
            response = await get_json(
                base_url=base_url,
                path="/logs",
                timeout_seconds=self._settings.system_agent_timeout_seconds,
                params=params,
                headers=headers,
            )
            lines = _lines(response.data)
            matches = [line for line in lines if _ERROR_PATTERNS.search(line)]
            raw_matches[source] = matches
            historical_window_verified = bool(
                source == "journal"
                and time_range
                and _historical_journal_response_verified(response.data, time_range)
            )
            source_results.append(
                {
                    "source": source,
                    "url": response.url,
                    "status_code": response.status_code,
                    "line_count": len(lines),
                    "error_count": len(matches),
                    "errors": compact(matches, limit=8),
                    "error": response.error,
                    "time_range": time_range if source == "journal" and time_range else None,
                    "historical_scope": bool(source == "journal" and time_range),
                    "historical_window_verified": historical_window_verified,
                }
            )
            if response.error:
                warnings.append(f"System agent query failed for {source}: {response.error}")

        successful = [item for item in source_results if not item["error"]]
        incident_sources = (
            [item for item in source_results if item["source"] == "journal"]
            if time_range
            else source_results
        )
        incident_successful = [
            item
            for item in incident_sources
            if not item["error"]
            and (not time_range or bool(item.get("historical_window_verified")))
        ]
        with_errors = [item for item in incident_successful if item["error_count"]]
        error_lines = [
            line
            for item in with_errors
            for line in raw_matches.get(str(item["source"]), [])
        ]
        journal = next((item for item in source_results if item["source"] == "journal"), None)
        historical_response_verified = bool(
            isinstance(journal, dict) and journal.get("historical_window_verified")
        )
        if time_range and isinstance(journal, dict) and not journal.get("error") and not historical_response_verified:
            warnings.append(
                "System agent did not confirm the requested historical journal window; "
                "its log lines are context only."
            )

        if time_range and not historical_response_verified:
            status = "partial"
            confidence = "low"
            deterministic = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                f"노드 {node}: system agent가 요청한 incident 시간창의 journal 응답을 확인하지 "
                "못했습니다. 반환된 로그는 참고용이며 과거 incident 증거로 사용하지 않습니다.",
                f"Node {node}: the system agent did not confirm the requested incident-window "
                "journal response. Returned logs are context only, not historical evidence.",
            )
        elif with_errors and time_range and not historical_node_scope_verified:
            status = "partial"
            confidence = "low"
            deterministic = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                f"노드 {node}: 현재 pod에서 추론한 노드의 incident 시간창 journal에 "
                f"커널/하드웨어 에러 라인 {len(error_lines)}건이 있지만, alert가 노드를 "
                "명시하지 않아 참고용으로만 사용합니다.",
                f"Node {node}: its incident-window journal has {len(error_lines)} kernel/hardware "
                "error line(s), but the node was inferred from a current Pod rather than the alert; "
                "this is context only.",
            )
        elif with_errors:
            status = "ok"
            confidence = "high"
            sources_text = ", ".join(sorted({item["source"] for item in with_errors}))
            deterministic = ko_en(
                self._settings,
                f"노드 {node}: {sources_text}에서 커널/하드웨어 에러 라인 "
                f"{len(error_lines)}건을 발견했습니다.",
                f"Node {node}: {len(error_lines)} kernel/hardware error line(s) found in "
                f"{sources_text}.",
            )
        elif incident_successful:
            # The endpoint returns a bounded journal tail. A clean tail is
            # useful context, but cannot rule out a node signal elsewhere in
            # the incident window.
            status = "partial"
            confidence = "low"
            deterministic = ko_en(
                self._settings,
                f"노드 {node}: incident 시간창에서 가져온 journal 줄에는 커널/GPU/하드웨어 "
                "에러 시그니처가 없습니다. 유한한 tail이므로 부재 증거는 아니며, "
                "dmesg/syslog는 현재 상태 참고입니다."
                if time_range
                else f"노드 {node}: 시스템 에이전트 접속 정상, 최근 dmesg/journal/syslog에 "
                "커널/GPU/하드웨어 에러 시그니처가 없습니다.",
                f"Node {node}: no kernel/GPU/hardware error signatures were found in the "
                "retrieved journal lines for the incident window. The finite tail is not "
                "absence evidence; dmesg/syslog are current-state context."
                if time_range
                else f"Node {node}: system agent reachable, no kernel/GPU/hardware "
                "error signatures in recent dmesg/journal/syslog.",
            )
        elif successful and time_range:
            status = "partial"
            confidence = "low"
            deterministic = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                f"노드 {node}: incident 시간창 journal 조회에 실패했습니다. "
                "dmesg/syslog는 현재 상태만 보여 과거 incident 반증으로 사용할 수 없습니다.",
                f"Node {node}: the incident-window journal query failed. Current dmesg/syslog "
                "tails cannot disprove a past incident.",
            )
        else:
            status = "unavailable"
            confidence = "low"
            deterministic = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                f"노드 {node}: 모든 소스에서 시스템 에이전트에 접속하지 못했습니다.",
                f"Node {node}: system agent unreachable on all sources.",
            )

        summary = deterministic
        if with_errors and (not time_range or historical_node_scope_verified) and llm_configured(self._settings):
            insight = await _llm_insight(self._settings, node, error_lines)
            if insight:
                summary = insight

        result = {
            "node": node,
            "node_address": address,
            "base_url": base_url,
            "time_range": time_range,
            "node_origin": node_origin,
            "resolved_pod": resolved_pod,
            "sources": source_results,
        }
        observation = _system_observation(
            source_results,
            time_range=time_range,
            node=node,
            historical_node_scope_verified=historical_node_scope_verified,
        )
        missing_data = [] if successful else ["system_agent.query"]
        if time_range and not incident_successful:
            missing_data.append("system_agent.journal_time_window")
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
                    source="system_agent",
                    type="node_logs",
                    status=status,
                    confidence=confidence,
                    query=f"node={node} sources={','.join(_SOURCES)}",
                    summary=summary,
                    result={**result, "observation": observation},
                )
            ],
        )


def _system_observation(
    source_results: list[dict[str, object]],
    *,
    time_range: dict[str, str] | None,
    node: str,
    historical_node_scope_verified: bool,
) -> dict[str, object]:
    """Classify only the source that actually covers the incident window."""
    if time_range:
        journal = next(
            (item for item in source_results if item.get("source") == "journal"), None
        )
        if not isinstance(journal, dict) or journal.get("error"):
            polarity, coverage = "unavailable", "unknown"
        elif int(journal.get("error_count") or 0) > 0:
            polarity = "present"
            coverage = (
                "scoped"
                if journal.get("historical_window_verified") and historical_node_scope_verified
                else "partial"
            )
        else:
            polarity, coverage = "unknown", "partial"
    else:
        successful = [item for item in source_results if not item.get("error")]
        if not successful:
            polarity, coverage = "unavailable", "unknown"
        elif any(int(item.get("error_count") or 0) > 0 for item in successful):
            # dmesg/syslog tails can be useful to an operator but do not prove
            # timing for an alert with no bounded incident window.
            polarity, coverage = "present", "partial"
        else:
            polarity, coverage = "unknown", "partial"
    return {
        "kind": "system_node_logs",
        "predicate": "system_node_logs",
        "source_group": _SYSTEM_LOG_SOURCE_GROUP,
        "independence_group": _SYSTEM_LOG_SOURCE_GROUP,
        "scope": {"node": node},
        "observed_entity": {"kind": "node", "name": node},
        "polarity": polarity,
        "coverage": coverage,
        "observation_window": time_range or {},
    }


async def _llm_insight(settings: Settings, node: str, error_lines: list[str]) -> str | None:
    system = (
        "You are a senior infrastructure engineer triaging a Kubernetes GPU node, "
        "reporting to a colleague. Given raw kernel/host log lines, write ONE (max two) "
        "sentence shaped: what you OBSERVED (the exact error, e.g. GPU XID fault, OOM "
        "kill, disk I/O failure — with timestamps/counts when the lines carry them) -> "
        "what it MEANS -> WHEN it started. Grounded ONLY in the given lines; never "
        "invent. No preamble, no list."
    )
    if getattr(settings, "language", "en") == "ko":
        system += " 한국어로 답하세요 (관찰한 것 → 의미 → 시작 시점)."
    user = _collector_masker(settings).mask_text(
        f"Node {node} recent kernel/host error lines:\n" + "\n".join(error_lines[:20])
    )
    text = await complete(settings, system=system, user=user, max_tokens=160) or ""
    return _collector_masker(settings).mask_text(text)


async def _node_from_target_pod(
    settings: Settings, target: AnalysisTarget, plan: object | None
) -> tuple[str, str]:
    """Best-effort node resolution from the target Pod's ``spec.nodeName``.

    ``resolve_live_pod_node`` first GETs the target Pod and then uses a bounded
    same-namespace list/event fallback for a replacement.  Keep this collector
    self-sufficient: direct collector use must not depend on pipeline planning
    having run first.
    """
    namespace = str(target.namespace or "").strip()
    pod = str(getattr(plan, "pod", "") or target.pod or "").strip()
    if not namespace or not pod:
        return "", ""
    try:
        from app.collectors.kubernetes import resolve_live_pod_node

        resolved_pod, node = await resolve_live_pod_node(settings, namespace, pod)
        return str(node or "").strip(), str(resolved_pod or "").strip()
    except Exception:  # noqa: BLE001 - system evidence remains optional
        return "", ""


def _collector_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


async def _node_internal_ip(settings: Settings, node: str) -> str:
    """The node's InternalIP from the Kubernetes API, '' when unavailable."""
    try:
        from app.collectors.kubernetes import _read_file

        token = _read_file(settings.kubernetes_token_path)
        if not token:
            return ""
        verify: bool | str = (
            settings.kubernetes_ca_path
            if Path(settings.kubernetes_ca_path).exists()
            else True
        )
        response = await get_json(
            base_url=settings.kubernetes_api_url,
            path=f"/api/v1/nodes/{quote(node, safe='')}",
            timeout_seconds=settings.kubernetes_timeout_seconds,
            headers={"Authorization": f"Bearer {token}"},
            verify=verify,
        )
        if not response.ok or not isinstance(response.data, dict):
            return ""
        addresses = (response.data.get("status") or {}).get("addresses") or []
        for item in addresses:
            if isinstance(item, dict) and item.get("type") == "InternalIP":
                value = str(item.get("address") or "").strip()
                if value:
                    return value
    except Exception:  # noqa: BLE001 - lookup is best-effort; caller falls back
        return ""
    return ""


def _base_url_for_node(url_template: str, node: str) -> str:
    """Resolve the per-node endpoint.

    The DaemonSet is reachable per node via hostNetwork, so the URL carries a
    `{node}` placeholder (e.g. http://{node}:9095). When no placeholder is
    present the value is used as-is (single shared endpoint that routes by ?node).
    """
    if "{node}" in url_template:
        return url_template.replace("{node}", quote(node, safe=".-"))
    return url_template


def _lines(data: object) -> list[str]:
    """Endpoint returns {"lines": [...]}; tolerate a bare list or a raw body string."""
    if isinstance(data, dict):
        value = data.get("lines")
        if isinstance(value, list):
            return [str(item) for item in value]
        body = data.get("body")
        if isinstance(body, str):
            return body.splitlines()
    if isinstance(data, list):
        return [str(item) for item in data]
    return []
