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
    lookback = _bounded_int(
        args.get("lookback_seconds", _QUERY_DEFAULT_LOOKBACK_SECONDS),
        minimum=60,
        maximum=_QUERY_MAX_LOOKBACK_SECONDS,
        label="lookback_seconds",
    )
    if isinstance(lookback, str):
        return _query_error(lookback, source=source, node=node)
    line_value = args.get("lines", args.get("limit", _QUERY_DEFAULT_LINES))
    lines = _bounded_int(
        line_value,
        minimum=1,
        maximum=_QUERY_MAX_LINES,
        label="lines",
    )
    if isinstance(lines, str):
        return _query_error(lines, source=source, node=node, lookback=lookback)
    grep, grep_error = _safe_grep(args.get("grep"))
    if grep_error:
        return _query_error(grep_error, source=source, node=node, lookback=lookback, limit=lines)
    if not getattr(settings, "enable_system_agent", False) or not getattr(
        settings, "system_agent_url", ""
    ):
        return _query_error(
            "system agent is not configured", source=source, node=node, lookback=lookback
        )

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
    response = await get_json(
        base_url=_base_url_for_node(settings.system_agent_url, address),
        path="/logs",
        timeout_seconds=settings.system_agent_timeout_seconds,
        # `lines` is enforced by the system agent. `grep` is a literal escaped
        # here before being sent to the agent's regex endpoint.
        params={
            "source": source,
            "lines": str(lines),
            **({"grep": grep} if grep else {}),
        },
        headers=headers,
    )
    if response.error:
        return _query_error(
            response.error, source=source, node=node, lookback=lookback, limit=lines
        )
    raw_lines = _lines(response.data)[-lines:]
    matching = [line for line in raw_lines if _ERROR_PATTERNS.search(line)]
    observation_window = _observation_window(lookback)
    observation = _system_log_observation(
        source=source,
        node=node,
        lookback_seconds=lookback,
        limit=lines,
        scanned=len(raw_lines),
        matching=matching,
        observation_window=observation_window,
    )
    return {
        "query": f"system logs source={source} node={node} lookback<={lookback}s lines<={lines}",
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


def _observation_window(lookback_seconds: int | None) -> dict[str, str]:
    end = datetime.now(UTC)
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
        "polarity": "present" if matching else "absent",
        # A finite tail of node logs cannot prove a host-wide absence.
        "coverage": "partial",
        "lookback_seconds": lookback_seconds,
        "result_limit": limit,
        "status": "ok",
        "lines_scanned": scanned,
        "matching_line_count": len(matching),
        "signal_types": signal_types,
        "body_included": False,
    }


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

        node = (getattr(plan, "node", "") or target.node or "").strip()
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
        source_results = []
        for source in _SOURCES:
            params = {"source": source, "lines": "500"}
            # Only journalctl has a trustworthy historical time predicate. A
            # dmesg/syslog tail is retained as *current-state* context but must
            # not be treated as proof about a past incident.
            if source == "journal" and time_range:
                params.update({"since": time_range["start"], "until": time_range["end"]})
            response = await get_json(
                base_url=base_url,
                path="/logs",
                timeout_seconds=self._settings.system_agent_timeout_seconds,
                params=params,
                headers=headers,
            )
            lines = _lines(response.data)
            matches = [line for line in lines if _ERROR_PATTERNS.search(line)]
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
        incident_successful = [item for item in incident_sources if not item["error"]]
        with_errors = [item for item in incident_successful if item["error_count"]]
        error_lines = [line for item in with_errors for line in item["errors"]]

        if with_errors:
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
            # Clean node is a POSITIVE finding only when the source covers the
            # incident window. For historical incidents, that is journalctl.
            status = "ok"
            confidence = "medium"
            deterministic = ko_en(
                self._settings,
                f"노드 {node}: incident 시간창의 journal에서 커널/GPU/하드웨어 "
                "에러 시그니처가 없습니다. dmesg/syslog는 현재 상태 참고입니다."
                if time_range
                else f"노드 {node}: 시스템 에이전트 접속 정상, 최근 dmesg/journal/syslog에 "
                "커널/GPU/하드웨어 에러 시그니처가 없습니다.",
                f"Node {node}: no kernel/GPU/hardware error signatures in journal for "
                "the incident window; dmesg/syslog are current-state context."
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
        if with_errors and llm_configured(self._settings):
            insight = await _llm_insight(self._settings, node, error_lines)
            if insight:
                summary = insight

        result = {
            "node": node,
            "node_address": address,
            "base_url": base_url,
            "time_range": time_range,
            "sources": source_results,
        }
        observation = _system_observation(source_results, time_range=time_range)
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
    source_results: list[dict[str, object]], *, time_range: dict[str, str] | None
) -> dict[str, object]:
    """Classify only the source that actually covers the incident window."""
    if time_range:
        journal = next(
            (item for item in source_results if item.get("source") == "journal"), None
        )
        if not isinstance(journal, dict) or journal.get("error"):
            polarity, coverage = "unavailable", "unknown"
        elif int(journal.get("error_count") or 0) > 0:
            polarity, coverage = "present", "scoped"
        else:
            polarity, coverage = "absent", "scoped"
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
