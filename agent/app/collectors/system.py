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

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import complete, llm_configured

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
            summary = (
                f"{NO_EVIDENCE} No node is associated with this alert; node/kernel "
                "evidence was skipped."
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

        base_url = _base_url_for_node(self._settings.system_agent_url, node)
        source_results = []
        warnings: list[str] = []
        for source in _SOURCES:
            response = await get_json(
                base_url=base_url,
                path="/logs",
                timeout_seconds=self._settings.system_agent_timeout_seconds,
                params={"source": source, "lines": "500"},
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
                }
            )
            if response.error:
                warnings.append(f"System agent query failed for {source}: {response.error}")

        successful = [item for item in source_results if not item["error"]]
        with_errors = [item for item in successful if item["error_count"]]
        error_lines = [line for item in with_errors for line in item["errors"]]

        if with_errors:
            status = "ok"
            confidence = "high"
            deterministic = (
                f"Node {node}: {len(error_lines)} kernel/hardware error line(s) found in "
                + ", ".join(sorted({item["source"] for item in with_errors}))
                + "."
            )
        elif successful:
            # Clean node is a POSITIVE finding (status ok) — NOT a "no evidence" case.
            status = "ok"
            confidence = "medium"
            deterministic = (
                f"Node {node}: system agent reachable, no kernel/GPU/hardware "
                "error signatures in recent dmesg/journal/syslog."
            )
        else:
            status = "unavailable"
            confidence = "low"
            deterministic = f"{NO_EVIDENCE} Node {node}: system agent unreachable on all sources."

        summary = deterministic
        if with_errors and llm_configured(self._settings):
            insight = await _llm_insight(self._settings, node, error_lines)
            if insight:
                summary = insight

        result = {
            "node": node,
            "base_url": base_url,
            "sources": source_results,
        }
        missing_data = [] if successful else ["system_agent.query"]
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
                    result=result,
                )
            ],
        )


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
    user = f"Node {node} recent kernel/host error lines:\n" + "\n".join(error_lines[:20])
    return await complete(settings, system=system, user=user, max_tokens=160)


def _base_url_for_node(url_template: str, node: str) -> str:
    """Resolve the per-node endpoint.

    The DaemonSet is reachable per node via hostNetwork, so the URL carries a
    `{node}` placeholder (e.g. http://{node}:9095). When no placeholder is
    present the value is used as-is (single shared endpoint that routes by ?node).
    """
    if "{node}" in url_template:
        return url_template.replace("{node}", node)
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
