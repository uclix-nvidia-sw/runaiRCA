"""Run-scoped memory for read-only evidence executions.

The evidence blackboard intentionally stores query-free facts.  This companion
keeps only SHA-256 execution identities so investigator, deterministic follow-up,
domain drill-down, and re-analysis can share what was already read without
exposing raw LogQL/PromQL/SQL/resource queries to reasoning prompts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.collectors.base import CollectorResult, incident_time_range


def _clean(value: object) -> str:
    return " ".join(str(value or "").split())


def _hash(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return "Q-" + hashlib.sha256(encoded).hexdigest()


def _target_scope(target: object, fields: Iterable[str]) -> dict[str, str]:
    return {name: _clean(getattr(target, name, "")) for name in fields}


def _collector_target_scope(agent: str, target: object) -> dict[str, str]:
    common = ("cluster", "fired_at", "resolved_at")
    per_agent = {
        "kubernetes": ("namespace", "pod", "node", "workload_name"),
        "prometheus": ("namespace", "pod", "node", "workload_name"),
        "loki": ("namespace", "pod", "node", "workload_name"),
        "runai": ("project", "queue", "runai_workload_id", "workload_name", "node"),
        "postgres": (),
        "system": ("node",),
        "change": ("namespace", "node", "workload_name", "component"),
    }
    return _target_scope(target, (*common, *per_agent.get(agent.casefold(), ())))


def collector_probe_key(
    agent: str, target: object, scope: Mapping[str, object] | None = None
) -> str:
    return _hash(
        {
            "kind": "collector_probe",
            "agent": _clean(agent).casefold(),
            "target": _collector_target_scope(_clean(agent), target),
            "scope": dict(scope or {}),
        }
    )


def domain_query_key(agent: str, query: Mapping[str, Any], target: object) -> str:
    """Canonical execution identity for every domain drill-down/follow-up query."""
    domain = _clean(agent).casefold()
    tool = _clean(query.get("tool")).casefold()
    args = query.get("args") if isinstance(query.get("args"), Mapping) else {}
    if tool in {"k8s_change_timeline", "change_query"}:
        domain, tool = "change", "change_query"
    if tool in {"k8s_read", "k8s_describe"}:
        from app.collectors.kubernetes import resolve_read_kind

        kind = resolve_read_kind(_clean(args.get("kind"))) or _clean(args.get("kind"))
        namespace = _clean(args.get("namespace"))
        if tool == "k8s_describe" and not namespace:
            namespace = _clean(getattr(target, "namespace", ""))
        name = _clean(args.get("name"))
        operation = "describe" if kind == "pods" and name else "read"
        identity: dict[str, object] = {
            "operation": operation,
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "label_selector": _clean(args.get("label_selector")),
        }
    elif tool in {"logql_query", "promql_query"}:
        identity = {
            "operation": tool,
            "query": _normalized_metric_query(args.get("query")),
            "window": _query_window(args, target),
        }
    elif "sql" in args or tool in {"postgres_query", "sql_query", "sql_select"}:
        identity = {
            "operation": "sql_query",
            "sql": _clean(args.get("sql") or args.get("query")),
        }
    elif tool == "system_log_query":
        identity = {
            "operation": tool,
            "source": _clean(args.get("source")).casefold(),
            "node": _clean(args.get("node") or getattr(target, "node", "")),
            "lookback_seconds": _clean(args.get("lookback_seconds") or 900),
            "lines": _clean(args.get("lines") or args.get("limit") or 100),
            "grep": _clean(args.get("grep")),
        }
    elif tool == "change_query":
        source = _clean(args.get("source") or args.get("kind") or "all").casefold()
        source = {
            "controllers": "controller",
            "pods": "pod",
            "node_conditions": "node_condition",
            "events": "event",
        }.get(source, source)
        identity = {
            "operation": tool,
            "source": source,
            "namespace": _clean(args.get("namespace") or getattr(target, "namespace", "")),
            "node": _clean(args.get("node") or getattr(target, "node", "")),
            "component": _clean(args.get("component")),
            "lookback_seconds": _clean(args.get("lookback_seconds") or 900),
            "limit": _clean(args.get("limit") or 20),
        }
    else:
        normalized_args = _normalized_mapping(args)
        identity = {
            "operation": tool,
            "args": normalized_args,
        }
    return _hash(
        {
            "kind": "domain_query",
            "agent": domain,
            "target": _collector_target_scope(domain, target),
            "identity": identity,
        }
    )


def _query_window(args: Mapping[str, Any], target: object) -> dict[str, str]:
    raw = args.get("time_range") if isinstance(args.get("time_range"), Mapping) else {}
    default_window = incident_time_range(target) or {}
    start = _clean(
        raw.get("start")
        or args.get("start")
        or default_window.get("start")
        or getattr(target, "fired_at", "")
    )
    explicit_end = _clean(raw.get("end") or args.get("end"))
    target_end = _clean(default_window.get("end") or getattr(target, "resolved_at", ""))
    return {"start": start, "end": explicit_end or target_end or "<live>"}


def _normalized_metric_query(value: object) -> str:
    # Drill-down accepts JSON-double-escaped quotes and normalizes them before
    # transport. The receipt must use that effective query too, or the same
    # base LogQL/PromQL read can bypass memory through an escaping difference.
    return _clean(value).replace(r'\"', '"')


def _normalized_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if str(key).startswith("_"):
            continue
        if isinstance(item, Mapping):
            normalized[str(key)] = _normalized_mapping(item)
        elif isinstance(item, list):
            normalized[str(key)] = [
                _normalized_mapping(part) if isinstance(part, Mapping) else _clean(part)
                for part in item
            ]
        else:
            normalized[str(key)] = _clean(item)
    return normalized


def result_query_keys(result: CollectorResult, target: object) -> set[str]:
    """Recover completed execution IDs from all collector result envelopes."""
    keys: set[str] = set()
    details = result.details if isinstance(result.details, Mapping) else {}
    raw_queries = details.get("queries")
    for item in raw_queries if isinstance(raw_queries, list) else []:
        if isinstance(item, Mapping):
            if item.get("error") or _failed_status_code(item.get("status_code")):
                continue
            key = _collector_query_item_key(result.agent, item, target)
            if key:
                keys.add(key)
    if result.agent == "system":
        source_results = details.get("sources")
        for item in source_results if isinstance(source_results, list) else []:
            if not isinstance(item, Mapping):
                continue
            if item.get("error") or _failed_status_code(item.get("status_code")):
                continue
            source = _clean(item.get("source"))
            if source:
                keys.add(
                    domain_query_key(
                        "system",
                        {
                            "tool": "system_log_query",
                            "args": {
                                "source": source,
                                "node": details.get("node") or getattr(target, "node", ""),
                            },
                        },
                        target,
                    )
                )
    for item in result.artifacts or []:
        status = _clean(getattr(item, "status", "")).casefold()
        if status != "ok":
            continue
        payload = getattr(item, "result", None)
        artifact_type = _clean(getattr(item, "type", ""))
        if result.agent == "kubernetes":
            query = _kubernetes_artifact_query(artifact_type, payload, target)
            if query:
                keys.add(domain_query_key(result.agent, query, target))
        raw_query = _clean(getattr(item, "query", ""))
        if raw_query:
            key = _text_query_key(result.agent, raw_query, target)
            if key:
                keys.add(key)
    return keys


def _collector_query_item_key(
    agent: str, item: Mapping[str, Any], target: object
) -> str:
    if _clean(agent).casefold() == "runai":
        tool = {
            "workloads": "runai_workload_summary",
            "workload_status": "runai_workload_status",
            "project_resources": "runai_project_resources",
            "node_pools": "runai_node_pools",
        }.get(_clean(item.get("name")).casefold())
        if tool:
            return domain_query_key("runai", {"tool": tool, "args": {}}, target)
    query_text = _clean(item.get("query") or item.get("sql"))
    if query_text:
        return _text_query_key(agent, query_text, target, item)
    path = _clean(item.get("path") or item.get("url"))
    if path:
        return _hash(
            {
                "kind": "collector_path",
                "agent": _clean(agent).casefold(),
                "target": _collector_target_scope(_clean(agent), target),
                "path": path,
            }
        )
    return ""


def _failed_status_code(value: object) -> bool:
    try:
        return int(value) >= 400
    except (TypeError, ValueError):
        return False


def _text_query_key(
    agent: str,
    text: str,
    target: object,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    domain = _clean(agent).casefold()
    if domain == "loki":
        tool = "logql_query"
    elif domain == "prometheus":
        tool = "promql_query"
    elif domain == "postgres":
        tool = "sql_query"
    else:
        return ""
    args: dict[str, Any] = {"query": text}
    if tool == "sql_query":
        args = {"sql": text}
    elif metadata and isinstance(metadata.get("time_range"), Mapping):
        args["time_range"] = metadata["time_range"]
    return domain_query_key(domain, {"tool": tool, "args": args}, target)


def _kubernetes_artifact_query(
    artifact_type: str, payload: object, target: object
) -> dict[str, Any] | None:
    if artifact_type == "kubernetes_warning_events" and getattr(target, "namespace", ""):
        return {
            "tool": "k8s_read",
            "args": {"kind": "events", "namespace": getattr(target, "namespace", "")},
        }
    if artifact_type == "kubernetes_node_condition" and getattr(target, "node", ""):
        return {
            "tool": "k8s_read",
            "args": {"kind": "nodes", "name": getattr(target, "node", "")},
        }
    if artifact_type == "pod_inspection" and getattr(target, "pod", ""):
        return {
            "tool": "k8s_describe",
            "args": {
                "kind": "pods",
                "namespace": getattr(target, "namespace", ""),
                "name": getattr(target, "pod", ""),
            },
        }
    if artifact_type not in {
        "adhoc_query",
        "followup_query",
        "ontology_probe",
        "drilldown_query",
    } or not isinstance(payload, Mapping) or not payload.get("kind"):
        return None
    return {
        "tool": (
            "k8s_describe"
            if _clean(payload.get("operation")) == "describe"
            else "k8s_read"
        ),
        "args": {
            "kind": payload.get("kind"),
            "namespace": payload.get("namespace") or "",
            "name": payload.get("name") or "",
            "label_selector": payload.get("label_selector") or "",
        },
    }


@dataclass
class QueryReceipt:
    status: str
    attempts: int = 1


@dataclass
class QueryMemory:
    """Run-scoped claim/complete ledger containing hashed identities only.

    A successful or currently-running read cannot start again. A failed read may
    be retried once by a later bounded path, which avoids both permanent gaps and
    unbounded replay of a broken datasource query.
    """

    _receipts: dict[str, QueryReceipt] = field(default_factory=dict)
    max_attempts: int = 2

    def claim(self, key: str) -> bool:
        if not key:
            return False
        current = self._receipts.get(key)
        if current is None:
            self._receipts[key] = QueryReceipt("running")
            return True
        if current.status != "failed" or current.attempts >= self.max_attempts:
            return False
        current.status = "running"
        current.attempts += 1
        return True

    def complete(self, key: str, *, succeeded: bool) -> None:
        current = self._receipts.get(key)
        if current is None:
            self._receipts[key] = QueryReceipt("succeeded" if succeeded else "failed")
            return
        current.status = "succeeded" if succeeded else "failed"

    def remember(self, key: str) -> None:
        if key:
            self._receipts[key] = QueryReceipt("succeeded")

    def remember_many(self, keys: Iterable[str]) -> None:
        for key in keys:
            self.remember(key)

    def seed_result(self, result: CollectorResult, target: object) -> None:
        self.remember_many(result_query_keys(result, target))

    def seed_results(self, results: Iterable[CollectorResult], target: object) -> None:
        for result in results:
            self.seed_result(result, target)

    def contains(self, key: str) -> bool:
        receipt = self._receipts.get(key)
        return receipt is not None and receipt.status in {"running", "succeeded"}

    def status(self, key: str) -> str:
        receipt = self._receipts.get(key)
        return receipt.status if receipt is not None else ""

    def __len__(self) -> int:
        return len(self._receipts)
