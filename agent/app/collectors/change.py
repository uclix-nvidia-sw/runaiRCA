"""Change-detection collector — the senior's first question: "무엇이 바뀌었지?".

Reads recently-changed things around the alert window straight from the K8s API
(same in-cluster token/CA pattern as the kubernetes collector):
  - workload controllers (Deployment/StatefulSet/DaemonSet) whose
    metadata.generation was bumped or whose status changed recently,
  - pods newly created or being deleted (deletionTimestamp set),
  - node condition transitions (e.g. Ready -> NotReady),
  - recent Events sorted by lastTimestamp.

Scoped to the plan/target namespace + node. Degrades to NO_EVIDENCE when the
token is missing or nothing recently changed. One optional senior insight line
via the LLM (Korean when settings.language == "ko").
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import re
import time
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from app.collectors.base import (
    _OBSERVED_NORMAL_EVENT_REASONS,
    NO_EVIDENCE,
    AnalysisTarget,
    CollectorResult,
    artifact,
    causal_evidence_time_range,
    incident_time_range,
    ko_en,
    parse_incident_time,
)
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.knowledge import dependency_path, load_architecture
from app.llm import cached_insight, complete, insight_cache_key, llm_configured
from app.masking import build_masker

# How far back a change still counts as "recent" and relevant to this alert.
# ponytail: fixed window; make it an env setting only if a real alert needs tuning.
_RECENT_WINDOW_SECONDS = 3600

# The query capability is deliberately narrower than the base collector: it can
# only inspect the alerted namespace/node and returns a small metadata timeline.
_QUERY_DEFAULT_LOOKBACK_SECONDS = 900
_QUERY_MIN_LOOKBACK_SECONDS = 60
_QUERY_MAX_LOOKBACK_SECONDS = 86400
_QUERY_MAX_RESULTS = 20
_QUERY_KINDS = frozenset({"all", "controller", "pod", "node_condition", "event", "helm"})
_QUERY_KIND_ALIASES = {
    "controllers": "controller",
    "pods": "pod",
    "node_conditions": "node_condition",
    "events": "event",
}
_CHANGE_SOURCE_GROUP = "kubernetes_api"
_COMPONENT_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?")
_log = logging.getLogger(__name__)
_HELM_DIFF_MAX_KEYS = 25
_HELM_VALUE_MAX_LENGTH = 256


def _helm_change_detection_enabled(settings: Settings) -> bool:
    """Whether the caller explicitly allowed Helm's Secret-backed history scan."""
    return bool(getattr(settings, "enable_helm_change_detection", False))


async def change_query(settings: Settings, target: AnalysisTarget, args: dict) -> dict:
    """Return a bounded, body-free change timeline for the alert's own scope.

    Kubernetes Event messages and Helm Secret payloads are untrusted bodies and
    may contain credentials.  This capability exposes only explicit resource
    metadata (kind/name/timestamp/status), never the API response or summaries
    derived from body text.  Namespace and node cannot be widened beyond the
    resolved alert target.
    """
    if not isinstance(args, dict):
        return _query_error("arguments must be an object")
    source = str(args.get("kind") or args.get("source") or "all").strip().lower()
    source = _QUERY_KIND_ALIASES.get(source, source)
    if source not in _QUERY_KINDS:
        return _query_error("kind must be one of: " + ", ".join(sorted(_QUERY_KINDS)))
    if source == "helm" and not _helm_change_detection_enabled(settings):
        return _query_error(
            "Helm release metadata scanning is disabled because it requires Secret-list RBAC",
            source=source,
        )
    namespace = str(target.namespace or "").strip()
    requested_namespace = str(args.get("namespace") or "").strip()
    if not namespace:
        return _query_error("the alert has no namespace scope", source=source)
    if requested_namespace and requested_namespace != namespace:
        return _query_error("namespace must match the alert namespace scope", source=source)
    if not _namespace_allowed(settings, namespace):
        return _query_error("alert namespace is outside the configured allowlist", source=source)
    node = str(target.node or "").strip()
    requested_node = str(args.get("node") or "").strip()
    if requested_node and requested_node != node:
        return _query_error("node must match the alert node scope", source=source)
    component = str(args.get("component") or "").strip()
    if component and not _COMPONENT_RE.fullmatch(component):
        return _query_error("component must be a bounded resource identifier", source=source)
    requested_lookback = _bounded_int(
        args.get("lookback_seconds", _QUERY_DEFAULT_LOOKBACK_SECONDS),
        minimum=_QUERY_MIN_LOOKBACK_SECONDS,
        maximum=_QUERY_MAX_LOOKBACK_SECONDS,
        label="lookback_seconds",
    )
    if isinstance(requested_lookback, str):
        return _query_error(requested_lookback, source=source, namespace=namespace, node=node)
    limit = _bounded_int(
        args.get("limit", _QUERY_MAX_RESULTS),
        minimum=1,
        maximum=_QUERY_MAX_RESULTS,
        label="limit",
    )
    if isinstance(limit, str):
        return _query_error(
            limit, source=source, namespace=namespace, node=node, lookback=requested_lookback
        )
    token = _read_file(settings.kubernetes_token_path)
    if not token:
        return _query_error(
            "kubernetes service account token unavailable",
            source=source,
            namespace=namespace,
            node=node,
            lookback=requested_lookback,
            limit=limit,
        )

    headers = {"Authorization": f"Bearer {token}"}
    verify: bool | str = (
        settings.kubernetes_ca_path if Path(settings.kubernetes_ca_path).exists() else True
    )
    # A historical alert must use its bounded incident window. A moving
    # "last N seconds" window would otherwise return changes from the present
    # and make them look causal for an already-resolved incident.
    window_start, window_end, incident_window = _collection_window(target)
    historical_window = incident_time_range(target) is not None
    now = window_end if historical_window else datetime.now(UTC)
    lookback = requested_lookback
    if historical_window:
        window_start = window_end - timedelta(seconds=lookback)
        fired_at = parse_incident_time(target.fired_at)
        if fired_at is not None:
            window_start = fired_at - timedelta(seconds=lookback)
        observation_window = {
            "start": window_start.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end": incident_window["end"],
        }
    else:
        observation_window = _observation_window(lookback, now)
    collection_lookback = (
        max(1, int((window_end - window_start).total_seconds()))
        if historical_window
        else lookback
    )
    collector = ChangeCollector(settings)
    warnings: list[str] = []
    ns = quote(namespace, safe="")
    query_limit = max(1, min(int(getattr(settings, "kubernetes_list_limit", limit)), limit))
    changes: list[dict] = []
    if source in {"all", "controller"}:
        changes += await collector._recent_controllers(
            ns, node, headers, verify, now, warnings, window_seconds=collection_lookback, limit=query_limit
        )
    if source in {"all", "pod"}:
        changes += await collector._recent_pods(
            ns, headers, verify, now, warnings, window_seconds=collection_lookback, limit=query_limit
        )
    if source in {"all", "node_condition"} and node:
        changes += await collector._node_conditions(
            node, headers, verify, now, warnings, window_seconds=collection_lookback
        )
    if source in {"all", "event"}:
        changes += await collector._recent_events(
            ns, query_limit, headers, verify, now, warnings, window_seconds=collection_lookback
        )
    if source in {"all", "helm"} and _helm_change_detection_enabled(settings):
        changes += await collector._recent_helm_releases(
            namespace,
            ns,
            query_limit,
            headers,
            verify,
            now,
            warnings,
            window_seconds=collection_lookback,
        )
    # A stalled rollout can be older than the requested window. Do not smuggle
    # it into a short incident query merely because it remains mid-rollout.
    changes = [
        item
        for item in changes
        if (
            window_start <= timestamp <= window_end
            if historical_window and (timestamp := parse_incident_time(item.get("timestamp"))) is not None
            else _within_window(item.get("timestamp"), now, window_seconds=lookback)
        )
    ]
    if component:
        changes = [item for item in changes if str(item.get("name") or "") == component]
    changes.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    correlated_changes, context_changes = _partition_target_changes(
        changes,
        target=target,
        primary_namespace=namespace,
        dependency_namespaces=[],
    )
    observation = _change_observation(
        namespace=namespace,
        node=node,
        source=source,
        lookback_seconds=lookback,
        limit=limit,
        changes=correlated_changes[:limit],
        context_changes=context_changes,
        truncated=max(0, len(correlated_changes) - limit),
        warnings=warnings,
        component=component,
        observation_window=observation_window,
        historical_window=historical_window,
        causal_window=causal_evidence_time_range(target) if historical_window else None,
    )
    return {
        "query": (
            f"kubernetes changes source={source} namespace={namespace} "
            f"node={node or 'n/a'} start={observation_window['start']} "
            f"end={observation_window['end']} results<={limit}"
        ),
        "title": "Kubernetes change timeline",
        "summary": (
            f"{len(observation['changes'])} change observation(s) (metadata only)"
            + (f"; {'; '.join(warnings)}" if warnings else "")
        ),
        "error": None,
        "source_group": _CHANGE_SOURCE_GROUP,
        "independence_group": _CHANGE_SOURCE_GROUP,
        "observed_entity": observation["observed_entity"],
        "observation_window": observation_window,
        "polarity": observation["polarity"],
        "coverage": observation["coverage"],
        "observation": observation,
        "result": observation,
        "warnings": warnings,
    }


def _query_error(
    error: str,
    *,
    source: str = "",
    namespace: str = "",
    node: str = "",
    lookback: int | None = None,
    limit: int | None = None,
) -> dict:
    observation = {
        "schema_version": "v1",
        "kind": "change_query",
        "source_group": _CHANGE_SOURCE_GROUP,
        "independence_group": _CHANGE_SOURCE_GROUP,
        "scope": {"namespace": namespace, "node": node, "source": source},
        "observed_entity": {"kind": "namespace", "name": namespace},
        "window": {"lookback_seconds": lookback},
        "observation_window": _observation_window(lookback),
        "polarity": "unavailable",
        "coverage": "unknown",
        "lookback_seconds": lookback,
        "result_limit": limit,
        "status": "unavailable",
        "changes": [],
    }
    return {
        "query": "kubernetes changes (bounded)",
        "title": "Kubernetes change timeline",
        "summary": error,
        "error": error,
        "source_group": _CHANGE_SOURCE_GROUP,
        "independence_group": _CHANGE_SOURCE_GROUP,
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


def _change_observation(
    *,
    namespace: str,
    node: str,
    source: str,
    lookback_seconds: int,
    limit: int,
    changes: list[dict],
    context_changes: list[dict],
    truncated: int,
    warnings: list[str],
    component: str,
    observation_window: dict[str, str],
    historical_window: bool,
    causal_window: dict[str, str] | None = None,
) -> dict:
    """Project only safe change metadata; never copy Event or Secret bodies."""
    safe_changes = [_safe_change_metadata(change, namespace) for change in changes]
    # The request window only says what the API was asked to search.  It is not
    # proof that a returned change actually occurred during the incident.  Keep
    # an occurrence window only when the individual metadata timestamps are
    # valid, timezone-aware instants inside that bounded query.
    evidence_window = _change_evidence_window(
        safe_changes, causal_window or observation_window
    )
    timed_changes = bool(evidence_window)
    invalid_timing = bool(safe_changes) and historical_window and not timed_changes
    return {
        "schema_version": "v1",
        "kind": "change_query",
        "source_group": _CHANGE_SOURCE_GROUP,
        "independence_group": _CHANGE_SOURCE_GROUP,
        "scope": {
            "namespace": namespace,
            "node": node,
            "source": source,
            **({"component": component} if component else {}),
        },
        "observed_entity": {
            "kind": "component" if component else "namespace",
            "name": component or namespace,
        },
        "window": {"lookback_seconds": lookback_seconds},
        "observation_window": observation_window,
        **({"evidence_window": evidence_window} if evidence_window else {}),
        # A live query is a useful operator hint, but cannot establish a
        # causal absence/presence for an alert without an incident timestamp.
        "polarity": (
            "present"
            if safe_changes and (not historical_window or timed_changes)
            else (
                "unknown"
                if warnings or not historical_window or context_changes or invalid_timing
                else "absent"
            )
        ),
        "coverage": (
            "partial"
            if warnings or not historical_window or context_changes or invalid_timing
            else "scoped"
        ),
        "lookback_seconds": lookback_seconds,
        "result_limit": limit,
        "status": "partial" if warnings else "ok",
        "changes": safe_changes,
        "context_change_count": len(context_changes),
        "truncated_count": truncated,
        "body_included": False,
        "historical_window": historical_window,
    }


def _safe_change_metadata(change: dict, namespace: str) -> dict:
    """Whitelist metadata fields so Event messages and Secret data cannot escape."""
    safe = {
        key: change[key]
        for key in (
            "timestamp",
            "kind",
            "name",
            "namespace",
            "rollout",
            "helm_status",
            "helm_pending",
            "revision",
            "condition",
            "condition_status",
            "reason",
            "object_kind",
        )
        if key in change and change[key] is not None
    }
    if "namespace" not in safe and change.get("kind") != "NodeCondition":
        safe["namespace"] = namespace
    return safe


def _observation_window(
    lookback_seconds: int | None, now: datetime | None = None
) -> dict[str, str]:
    end = now or datetime.now(UTC)
    start = end - timedelta(seconds=lookback_seconds or 0)
    return {"start": start.isoformat(), "end": end.isoformat()}


def _collection_window(
    target: AnalysisTarget,
) -> tuple[datetime, datetime, dict[str, str]]:
    """Use the incident's historical window, not a moving 'last hour'.

    Change evidence is causal only when it is adjacent to the alert. A past
    incident therefore cannot safely use the collector's current wall clock.
    Alerts without a timestamp retain the bounded one-hour live fallback.
    """
    time_range = incident_time_range(target)
    if time_range:
        fired = parse_incident_time(target.fired_at)
        end = parse_incident_time(time_range.get("end"))
        if fired is not None and end is not None and end >= fired:
            start = fired - timedelta(seconds=_RECENT_WINDOW_SECONDS)
            return start, end, {
                "start": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "end": time_range["end"],
            }
    end = datetime.now(UTC)
    start = end - timedelta(seconds=_RECENT_WINDOW_SECONDS)
    return (
        start,
        end,
        {
            "start": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end": end.isoformat(timespec="seconds").replace("+00:00", "Z"),
        },
    )


class ChangeCollector:
    name = "change"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._cache: dict[tuple, tuple[CollectorResult, float]] = {}
        self._components: dict[str, dict] | None = None

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:  # noqa: ANN001
        namespace = _first_namespace(plan) or target.namespace
        node = getattr(plan, "node", "") or target.node
        window_start, window_end, time_range = _collection_window(target)
        window_seconds = max(1, int((window_end - window_start).total_seconds()))
        historical_window = incident_time_range(target) is not None
        # depends_on namespaces (e.g. gpu-operator) the alert's component sits on:
        # an upstream operator/Helm upgrade is the usual root cause of a stuck
        # downstream DaemonSet, so scan those too (P2b).
        dep_namespaces = self._dependency_namespaces(plan, namespace)
        # Correlation happens after the shared namespace sweep.  Cache entries
        # must therefore retain the exact alert identity too: two workloads on
        # the same node can have the same incident window but entirely
        # different target-correlated changes.
        target_identity = (
            str(target.workload_name or ""),
            str(target.runai_workload_id or ""),
            str(target.pod or ""),
            str(getattr(plan, "component", "") or target.component or ""),
        )
        cache_key = (
            namespace or "",
            node or "",
            target_identity,
            tuple(dep_namespaces),
            (time_range["start"], time_range["end"])
            if historical_window
            else ("live", _RECENT_WINDOW_SECONDS),
        )
        cached = self._cache.get(cache_key)
        if cached and time.monotonic() - cached[1] <= 120:
            return cached[0]

        token = _read_file(self._settings.kubernetes_token_path)
        if not token or not namespace or not _namespace_allowed(self._settings, namespace):
            reason = (
                "Kubernetes service account token is not available."
                if not token
                else "no in-scope namespace was resolved for change detection."
            )
            result = self._empty(f"{NO_EVIDENCE} {reason}", missing=["change.unconfigured"])
            self._cache_result(cache_key, result)
            return result

        headers = {"Authorization": f"Bearer {token}"}
        verify: bool | str = (
            self._settings.kubernetes_ca_path
            if Path(self._settings.kubernetes_ca_path).exists()
            else True
        )
        ns = quote(namespace, safe="")
        limit = str(self._settings.kubernetes_list_limit)
        warnings: list[str] = []
        scope_missing: list[str] = []

        controllers = await self._recent_controllers(
            ns,
            node,
            headers,
            verify,
            window_end,
            warnings,
            window_seconds=window_seconds,
            historical_window=historical_window,
        )
        pods = await self._recent_pods(
            ns, headers, verify, window_end, warnings, window_seconds=window_seconds
        )
        node_changes = await self._node_conditions(
            node, headers, verify, window_end, warnings, window_seconds=window_seconds
        )
        if node and not self._settings.kubernetes_cluster_scope_enabled:
            scope_missing.append("change.node_condition_scope")
        events = await self._recent_events(
            ns, limit, headers, verify, window_end, warnings, window_seconds=window_seconds
        )
        helm = []
        if _helm_change_detection_enabled(self._settings):
            helm = await self._recent_helm_releases(
                namespace,
                ns,
                limit,
                headers,
                verify,
                window_end,
                warnings,
                window_seconds=window_seconds,
            )

        changes = controllers + pods + node_changes + events + helm
        # Upstream depends_on namespaces: only rollouts / Helm changes there matter
        # (that's what a downstream stall points back to) — skip pod/event churn.
        for dep_ns in dep_namespaces:
            dep_q = quote(dep_ns, safe="")
            changes += await self._recent_controllers(
                dep_q,
                "",
                headers,
                verify,
                window_end,
                warnings,
                window_seconds=window_seconds,
                historical_window=historical_window,
            )
            if _helm_change_detection_enabled(self._settings):
                changes += await self._recent_helm_releases(
                    dep_ns,
                    dep_q,
                    limit,
                    headers,
                    verify,
                    window_end,
                    warnings,
                    window_seconds=window_seconds,
                )
        changes.sort(key=lambda c: c.get("timestamp") or "", reverse=True)
        correlated_changes, context_changes = _partition_target_changes(
            changes,
            target=target,
            primary_namespace=namespace,
            dependency_namespaces=dep_namespaces,
        )

        if not changes:
            observation = _collector_change_observation(
                changes=[],
                time_range=time_range,
                historical_window=historical_window,
                warnings=warnings,
                target=target,
            )
            result = self._empty(
                f"{NO_EVIDENCE} "
                + ko_en(
                    self._settings,
                    f"incident 시간창 내 네임스페이스 {namespace}에서 "
                    "변경된 워크로드/파드/노드/이벤트가 없습니다.",
                    "No changed workloads, pods, nodes, or events were found in "
                    f"namespace {namespace} inside the incident time window.",
                ),
                missing=[],
                warnings=warnings,
                details={
                    "namespace": namespace,
                    "node": node,
                    "time_range": time_range,
                    "historical_window": historical_window,
                },
                observation=observation,
            )
            self._cache_result(cache_key, result)
            return result

        observation = _collector_change_observation(
            changes=correlated_changes,
            context_changes=context_changes,
            time_range=time_range,
            historical_window=historical_window,
            warnings=warnings,
            target=target,
        )
        if not correlated_changes:
            details = {
                "namespace": namespace,
                "node": node,
                "dependency_namespaces": dep_namespaces,
                "time_range": time_range,
                "historical_window": historical_window,
                "window_seconds": window_seconds,
                "changes": [],
                "context_changes": context_changes,
            }
            result = self._empty(
                "Namespace changes were observed, but none matched the incident target or "
                "its declared dependency chain.",
                missing=[],
                warnings=warnings,
                details=details,
                observation=observation,
            )
            self._cache_result(cache_key, result)
            return result

        summary = _deterministic_summary(correlated_changes, namespace)
        insight = await _senior_insight(self._settings, correlated_changes)
        if insight:
            summary = f"{summary} {insight}"

        details = {
            "namespace": namespace,
            "node": node,
            "dependency_namespaces": dep_namespaces,
            "time_range": time_range,
            "historical_window": historical_window,
            "window_seconds": window_seconds,
            "changes": correlated_changes,
            "context_changes": context_changes,
            "insight": insight,
        }
        confidence = "high" if len(correlated_changes) >= 2 else "medium"
        result = CollectorResult(
            agent=self.name,
            status="ok",
            summary=summary,
            confidence=confidence,
            details=details,
            missing_data=scope_missing,
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="change_detection",
                    status="ok",
                    confidence=confidence,
                    query=(
                        f"namespace={namespace} node={node or 'n/a'} "
                        f"start={time_range['start']} end={time_range['end']}"
                    ),
                    summary=summary,
                    result={
                        **details,
                        "observation": observation,
                    },
                )
            ],
        )
        self._cache_result(cache_key, result)
        return result

    def _cache_result(self, key: tuple, result: CollectorResult) -> None:
        if result.status == "ok":
            self._cache[key] = (result, time.monotonic())

    def clear_cache(self) -> None:
        """Start each analysis with fresh change evidence."""
        self._cache.clear()

    def _empty(
        self,
        summary: str,
        *,
        missing: list[str],
        warnings: list[str] | None = None,
        details: dict | None = None,
        observation: dict | None = None,
    ) -> CollectorResult:
        # Even an unconfigured collector must publish a typed verdict. Without
        # it this otherwise-structured collector falls back to legacy summary
        # parsing in downstream consumers.
        observation = observation or {
            "kind": "change_detection",
            "predicate": "change_detection",
            "polarity": "unavailable" if missing else "unknown",
            "coverage": "unknown" if missing else "partial",
        }
        return CollectorResult(
            agent=self.name,
            status="unavailable" if missing else "partial",
            summary=summary,
            confidence="low",
            details=details or {},
            missing_data=missing,
            warnings=warnings or [],
            artifacts=[
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="change_detection",
                    status="unavailable" if missing else "partial",
                    confidence="low",
                    summary=summary,
                    result={
                        **(details or {}),
                        "observation": observation,
                    },
                )
            ],
        )

    async def _get(self, path, params, headers, verify, warnings, label):  # noqa: ANN001
        response = await get_json(
            base_url=self._settings.kubernetes_api_url,
            path=path,
            timeout_seconds=self._settings.kubernetes_timeout_seconds,
            params=params,
            headers=headers,
            verify=verify,
        )
        if response.error:
            if label == "helm" and response.status_code == 403:
                warning = (
                    "Helm release metadata skipped: Kubernetes RBAC does not allow "
                    "listing Secrets"
                )
            else:
                warning = f"change {label} query failed: {response.error}"
            if warning not in warnings:
                warnings.append(warning)
            return None
        data = response.data
        # A bounded list can be paginated by the API server. Without consuming
        # the continuation token, an empty page cannot safely mean that no
        # incident-adjacent change exists elsewhere in the resource list.
        metadata = _dict(data.get("metadata")) if isinstance(data, dict) else {}
        if metadata.get("continue"):
            warnings.append(f"change {label} query was truncated by Kubernetes pagination")
        return data

    async def _recent_controllers(
        self,
        ns,
        node,
        headers,
        verify,
        now,
        warnings,
        *,
        window_seconds: int = _RECENT_WINDOW_SECONDS,
        limit: int | None = None,
        historical_window: bool = False,
    ) -> list[dict]:  # noqa: ANN001
        out: list[dict] = []
        params = {"limit": str(limit or self._settings.kubernetes_list_limit)}
        for kind, api in (
            ("Deployment", "deployments"),
            ("StatefulSet", "statefulsets"),
            ("DaemonSet", "daemonsets"),
        ):
            data = await self._get(
                f"/apis/apps/v1/namespaces/{ns}/{api}",
                params, headers, verify, warnings, kind,
            )
            for item in _items(data):
                meta = _dict(item.get("metadata"))
                status = _dict(item.get("status"))
                # A generation bump the status hasn't caught up to = spec just changed.
                gen = meta.get("generation")
                observed = status.get("observedGeneration")
                changed_recently = _within_window(
                    meta.get("creationTimestamp"), now, window_seconds=window_seconds
                )
                cond_ts = _latest_condition_time(status.get("conditions"))
                if _within_window(cond_ts, now, window_seconds=window_seconds):
                    changed_recently = True
                rollout = isinstance(gen, int) and gen != observed
                if not (rollout or changed_recently):
                    continue
                out.append(
                    {
                        "timestamp": cond_ts or meta.get("creationTimestamp"),
                        "kind": kind,
                        "name": meta.get("name"),
                        "namespace": meta.get("namespace"),
                        "rollout": bool(rollout),
                        "corroborated": bool(changed_recently),
                        # A currently pending generation can predate the
                        # incident by days. Keep it for operator context, but
                        # require a creation/condition timestamp in a closed
                        # incident window before it becomes support.
                        "time_window_verified": bool(changed_recently)
                        if historical_window
                        else True,
                        "summary": (
                            f"{kind} {meta.get('name')} "
                            + (
                                f"is mid-rollout (generation {gen}, observed {observed})"
                                if rollout
                                else "changed recently"
                            )
                        ),
                    }
                )
        return out

    def _dependency_namespaces(self, plan, primary_ns: str) -> list[str]:  # noqa: ANN001
        """Namespaces of the alert component's depends_on chain (P2b).

        An alert ON runai-container-toolkit (ns runai) depends on the GPU Operator
        stack (ns gpu-operator); an upstream Helm upgrade / operator rollout there
        is the real trigger of a downstream stall. We scan those namespaces for
        rollouts + Helm changes so `_lifecycle_signal` can attribute the upstream
        cause. Returns a sorted, de-duped list excluding the primary namespace and
        anything outside the configured namespace allowlist."""
        component = str(getattr(plan, "component", "") or "").strip()
        if not component:
            return []
        if self._components is None:
            self._components = load_architecture(
                getattr(self._settings, "architecture_file", "")
            )
        components = self._components or {}
        if component not in components:
            return []
        chain = dependency_path(components, component)
        out: set[str] = set()
        for name in chain:
            entry = components.get(name) or {}
            dep_ns = str(entry.get("namespace") or "").strip()
            if dep_ns and dep_ns != primary_ns and _namespace_allowed(self._settings, dep_ns):
                out.add(dep_ns)
        return sorted(out)

    async def _recent_helm_releases(
        self,
        namespace,
        ns,
        limit,
        headers,
        verify,
        now,
        warnings,
        *,
        window_seconds: int = _RECENT_WINDOW_SECONDS,
    ) -> list[dict]:  # noqa: ANN001
        """Helm v3 release revisions changed within the window (P2b).

        Helm v3 stores each revision as a Secret `sh.helm.release.v1.<rel>.v<N>`
        (labels owner=helm, name=<release>, version=<N>, status=<deployed|
        pending-upgrade|pending-install|failed|...>). A revision Secret created
        inside the window means an install/upgrade just happened; a non-deployed
        status means it's mid-flight. Either way it's a lifecycle signal. RBAC on
        secrets may 403 — that degrades to a warning + no entries, never an error."""
        data = await self._get(
            f"/api/v1/namespaces/{ns}/secrets",
            {"labelSelector": "owner=helm", "limit": str(limit)},
            headers, verify, warnings, "helm",
        )
        # Keep only the newest revision per release within the window.
        latest: dict[str, dict] = {}
        revisions: dict[str, list[int]] = {}
        revision_items: dict[str, dict[int, dict]] = {}
        for item in _items(data):
            meta = _dict(item.get("metadata"))
            labels = _dict(meta.get("labels"))
            release = str(labels.get("name") or "").strip()
            if not release:
                continue
            try:
                version = int(labels.get("version") or 0)
            except (TypeError, ValueError):
                version = 0
            # Retain EVERY revision's Secret for the value-diff — the prior
            # revision is normally OLDER than the window, so window-filtering it
            # out here would make the diff impossible.
            revision_items.setdefault(release, {})[version] = item
            created = meta.get("creationTimestamp")
            if not _within_window(created, now, window_seconds=window_seconds):
                continue
            revisions.setdefault(release, []).append(version)
            prev = latest.get(release)
            if prev is None or version >= prev["_version"]:
                status = str(labels.get("status") or "").strip()
                pending = status in {"pending-upgrade", "pending-install", "pending-rollback"}
                latest[release] = {
                    "_version": version,
                    "timestamp": created,
                    "kind": "HelmRelease",
                    "name": release,
                    "namespace": namespace,
                    # A recent Helm revision (deployed or mid-flight) is a rollout
                    # signal — it explains churn in the release's workloads.
                    "rollout": True,
                    "helm_status": status,
                    "helm_pending": pending,
                    "revision": version,
                    "summary": (
                        f"Helm release {release} revision {version} is "
                        f"{status or 'changed'} in {namespace}"
                    ),
                }
        out = []
        for release, entry in latest.items():
            item = {k: v for k, v in entry.items() if k != "_version"}
            observed = sorted(set(revisions.get(release, [])), reverse=True)
            item["revision_count"] = len(observed)
            item["prior_revisions"] = [revision for revision in observed if revision != entry["revision"]]
            all_revisions = sorted(revision_items.get(release, {}))
            prior = max((r for r in all_revisions if r < entry["revision"]), default=None)
            current_secret = revision_items.get(release, {}).get(entry["revision"])
            prior_secret = revision_items.get(release, {}).get(prior) if prior is not None else None
            _add_helm_payload_diff(item, current_secret, prior_secret, self._settings)
            out.append(item)
        return out

    async def _recent_pods(
        self,
        ns,
        headers,
        verify,
        now,
        warnings,
        *,
        window_seconds: int = _RECENT_WINDOW_SECONDS,
        limit: int | None = None,
    ) -> list[dict]:  # noqa: ANN001
        data = await self._get(
            f"/api/v1/namespaces/{ns}/pods",
            {"limit": str(limit or self._settings.kubernetes_list_limit)},
            headers, verify, warnings, "pods",
        )
        out: list[dict] = []
        for item in _items(data):
            meta = _dict(item.get("metadata"))
            name = meta.get("name")
            created = meta.get("creationTimestamp")
            deleted = meta.get("deletionTimestamp")
            if deleted and _within_window(deleted, now, window_seconds=window_seconds):
                out.append(
                    {
                        "timestamp": deleted,
                        "kind": "PodDeleted",
                        "name": name,
                        "namespace": meta.get("namespace"),
                        "summary": f"Pod {name} is terminating (deletionTimestamp set).",
                    }
                )
            elif _within_window(created, now, window_seconds=window_seconds):
                out.append(
                    {
                        "timestamp": created,
                        "kind": "PodCreated",
                        "name": name,
                        "namespace": meta.get("namespace"),
                        "summary": f"Pod {name} was created recently.",
                    }
                )
        return out

    async def _node_conditions(
        self,
        node,
        headers,
        verify,
        now,
        warnings,
        *,
        window_seconds: int = _RECENT_WINDOW_SECONDS,
    ) -> list[dict]:  # noqa: ANN001
        if not (node and self._settings.kubernetes_cluster_scope_enabled):
            return []
        data = await self._get(
            f"/api/v1/nodes/{quote(node, safe='')}",
            None, headers, verify, warnings, "node",
        )
        if not isinstance(data, dict):
            return []
        out: list[dict] = []
        for cond in _list(_dict(data.get("status")).get("conditions")):
            cond = _dict(cond)
            transition = cond.get("lastTransitionTime")
            if not _within_window(transition, now, window_seconds=window_seconds):
                continue
            ctype, cstatus = cond.get("type"), cond.get("status")
            # Ready=False/Unknown or any pressure=True is a meaningful transition.
            bad = (ctype == "Ready" and cstatus != "True") or (
                ctype != "Ready" and cstatus == "True"
            )
            if not bad:
                continue
            out.append(
                {
                    "timestamp": transition,
                    "kind": "NodeCondition",
                    "name": node,
                    "condition": ctype,
                    "condition_status": cstatus,
                    "reason": cond.get("reason"),
                    "summary": f"Node {node} condition {ctype}={cstatus} "
                    f"({cond.get('reason') or 'transitioned'}).",
                }
            )
        return out

    async def _recent_events(
        self,
        ns,
        limit,
        headers,
        verify,
        now,
        warnings,
        *,
        window_seconds: int = _RECENT_WINDOW_SECONDS,
    ) -> list[dict]:  # noqa: ANN001
        data = await self._get(
            f"/api/v1/namespaces/{ns}/events",
            {"limit": limit}, headers, verify, warnings, "events",
        )
        events = []
        for item in _items(data):
            item = _dict(item)
            meta = _dict(item.get("metadata"))
            ts = item.get("lastTimestamp") or item.get("eventTime")
            if not _within_window(ts, now, window_seconds=window_seconds):
                continue
            involved = _dict(item.get("involvedObject"))
            events.append(
                {
                    "timestamp": ts,
                    "kind": f"Event/{item.get('type', 'Normal')}",
                    "name": involved.get("name"),
                    "namespace": meta.get("namespace"),
                    "reason": item.get("reason"),
                    "object_kind": involved.get("kind"),
                    "summary": f"{item.get('reason')}: {item.get('message')}",
                    "_type": item.get("type"),
                }
            )
        # Warnings first, but always retain decisive Normal lifecycle events.
        events.sort(
            key=lambda e: (str(e.get("_type") or "") == "Warning", e.get("timestamp") or ""),
            reverse=True,
        )
        retained = events[:10]
        retained_ids = {id(event) for event in retained}
        retained.extend(
            event for event in events[10:]
            if str(event.get("_type") or "").casefold() == "normal"
            and str(event.get("reason") or "").casefold() in _OBSERVED_NORMAL_EVENT_REASONS
            and id(event) not in retained_ids
        )
        omitted = len(events) - len(retained)
        if omitted:
            for event in retained:
                event["omitted_count"] = omitted
        return sorted(retained, key=lambda event: event.get("timestamp") or "", reverse=True)


def _collector_change_observation(
    *,
    changes: list[dict],
    context_changes: list[dict] | None = None,
    time_range: dict[str, str],
    historical_window: bool,
    warnings: list[str],
    target: AnalysisTarget | None = None,
) -> dict[str, object]:
    """State whether target-scope change evidence is truly incident-bounded."""
    # Do not let the broad collection range stand in for the time of an
    # individual rollout/Event/Pod transition.  A malformed or untimed record
    # remains useful operator context but cannot activate a lifecycle cause.
    causal_time_range = causal_evidence_time_range(target) if target is not None else None
    evidence_window = _change_evidence_window(changes, causal_time_range or time_range)
    timed_changes = bool(evidence_window)
    observed_entity: dict[str, str] | None = None
    target_scope_verified: bool | None = None
    if target is not None and historical_window:
        observed_entity, target_scope_verified = _collector_change_target_scope(changes, target)

    if not historical_window:
        # The live one-hour fallback helps an operator but cannot establish a
        # trigger for an alert with no timestamp.
        polarity, coverage = ("present", "partial") if changes else ("unknown", "partial")
    elif warnings:
        # A failed resource class leaves the historical sweep incomplete; don't
        # make an empty/partial result refute a lifecycle-change hypothesis.
        polarity, coverage = ("present", "partial") if changes else ("unknown", "partial")
    elif target is not None and target_scope_verified is not True:
        # Correlation by namespace, a workload-name prefix, or a declared
        # dependency namespace is useful investigation context, but it does
        # not prove that this historical change belongs to the alert target.
        # Do not let the blackboard inherit the pipeline target for it.
        polarity, coverage = "unknown", "partial"
    elif changes and timed_changes:
        polarity, coverage = "present", "scoped"
    elif changes:
        polarity, coverage = "unknown", "partial"
    elif context_changes:
        # A namespace sweep was not empty, but its lifecycle activity belongs
        # to another workload. It is operator context, never target evidence.
        polarity, coverage = "unknown", "partial"
    else:
        polarity, coverage = "absent", "scoped"
    observation: dict[str, object] = {
        "kind": "kubernetes_change_window",
        "predicate": "kubernetes_change_window",
        "polarity": polarity,
        "coverage": coverage,
        "change_count": len(changes),
        "context_change_count": len(context_changes or []),
        "observation_window": time_range,
        **({"evidence_window": evidence_window} if evidence_window else {}),
    }
    if observed_entity:
        observation["observed_entity"] = observed_entity
    if target_scope_verified is not None:
        observation["target_scope_verified"] = target_scope_verified
    return observation


def _collector_change_target_scope(
    changes: list[dict], target: AnalysisTarget
) -> tuple[dict[str, str] | None, bool]:
    """Prove that every correlated change names the alert resource itself.

    ``_partition_target_changes`` deliberately keeps useful near matches (for
    example a Pod whose name merely starts with a workload name) and every
    rollout in a declared dependency namespace.  Those are not enough to own
    a scoped historical verdict.  This narrower gate accepts only an exact
    target Pod/Node or an exact, known controller for the target workload.
    """
    pod = str(target.pod or "").strip()
    node = str(target.node or "").strip()
    workload = str(target.workload_name or "").strip()

    if not changes:
        # An empty, completed historical sweep can only refute changes for an
        # entity the alert named explicitly; namespace-only emptiness remains
        # an open-world result.
        if pod:
            return {"kind": "pod", "name": pod}, True
        if node:
            return {"kind": "node", "name": node}, True
        if workload:
            return {"kind": "workload_name", "name": workload}, True
        return None, False

    pod_folded = pod.casefold()
    node_folded = node.casefold()
    workload_folded = workload.casefold()

    def name_of(change: dict) -> str:
        return str(change.get("name") or "").strip().casefold()

    def is_exact_pod(change: dict) -> bool:
        kind = str(change.get("kind") or "")
        object_kind = str(change.get("object_kind") or "")
        return (
            bool(target.namespace)
            and str(change.get("namespace") or "").strip() == target.namespace
            and bool(pod_folded)
            and name_of(change) == pod_folded
            and (
            kind.startswith("Pod") or (kind.startswith("Event/") and object_kind == "Pod")
            )
        )

    def is_exact_node(change: dict) -> bool:
        return (
            bool(node_folded)
            and str(change.get("kind") or "") == "NodeCondition"
            and name_of(change) == node_folded
        )

    def is_verified_controller(change: dict) -> bool:
        kind = str(change.get("kind") or "")
        object_kind = str(change.get("object_kind") or "")
        return (
            bool(target.namespace)
            and str(change.get("namespace") or "").strip() == target.namespace
            and bool(workload_folded)
            and name_of(change) == workload_folded
            and (
            kind in {"Deployment", "StatefulSet", "DaemonSet", "HelmRelease"}
            or (
                kind.startswith("Event/")
                and object_kind in {"Deployment", "StatefulSet", "DaemonSet"}
            )
            )
        )

    if all(is_exact_pod(change) for change in changes):
        return {"kind": "pod", "name": pod}, True
    if all(is_exact_node(change) for change in changes):
        return {"kind": "node", "name": node}, True
    if workload and all(is_verified_controller(change) or is_exact_pod(change) for change in changes):
        return {"kind": "workload_name", "name": workload}, True
    return None, False


def _change_evidence_window(
    changes: list[dict], query_window: dict[str, str]
) -> dict[str, str] | None:
    """Return the actual timestamp span of valid individual change records.

    Kubernetes list responses may be stale, malformed, or contain a pending
    rollout whose only usable timestamp predates this incident.  The response
    must therefore carry at least one timestamped change inside the explicit
    query bounds before an aggregate change artifact can be causal evidence.
    """
    start = parse_incident_time(query_window.get("start"))
    end = parse_incident_time(query_window.get("end"))
    if start is None or end is None or end < start:
        return None
    instants = [
        instant
        for change in changes
        if isinstance(change, dict)
        if (instant := parse_incident_time(change.get("timestamp"))) is not None
        and start <= instant <= end
    ]
    if not instants:
        return None
    first, last = min(instants), max(instants)
    return {
        "start": first.isoformat().replace("+00:00", "Z"),
        "end": last.isoformat().replace("+00:00", "Z"),
    }


def _partition_target_changes(
    changes: list[dict],
    *,
    target: AnalysisTarget,
    primary_namespace: str,
    dependency_namespaces: list[str],
) -> tuple[list[dict], list[dict]]:
    """Separate target/dependency lifecycle evidence from namespace churn."""
    correlated: list[dict] = []
    context: list[dict] = []
    workload = str(target.workload_name or "").strip().casefold()
    pod = str(target.pod or "").strip().casefold()
    node = str(target.node or "").strip().casefold()
    component = str(target.component or "").strip().casefold()
    dependency_set = {str(namespace).strip() for namespace in dependency_namespaces}
    for change in changes:
        name = str(change.get("name") or "").strip().casefold()
        namespace = str(change.get("namespace") or primary_namespace).strip()
        change = {**change, "namespace": namespace}
        kind = str(change.get("kind") or "")
        relation = ""
        if change.get("time_window_verified") is False:
            context.append({**change, "relation": "stale_or_untimed_context"})
            continue
        if namespace in dependency_set:
            relation = "declared_dependency"
        elif kind == "NodeCondition" and node and name == node:
            relation = "target_node"
        elif namespace == primary_namespace and (
            (pod and name == pod)
            or (workload and (name == workload or name.startswith(f"{workload}-")))
            or (component and name == component)
        ):
            relation = "target_component" if component and name == component else "target_workload"
        if relation:
            correlated.append({**change, "relation": relation})
        else:
            context.append({**change, "relation": "namespace_context"})
    return correlated, context


def _deterministic_summary(changes: list[dict], namespace: str) -> str:
    from collections import Counter

    counts = Counter(str(c.get("kind", "")).split("/")[0] for c in changes)
    parts = ", ".join(f"{n} {kind}" for kind, n in counts.most_common())
    return f"Recent changes in {namespace} ({parts}); most recent: {changes[0].get('summary')}"


async def _senior_insight(settings: Settings, changes: list[dict]) -> str:
    insight_model = getattr(settings, "llm_model_insight", "")
    if not llm_configured(settings, insight_model):
        return ""
    system = (
        "You are a senior SRE asking the first question of any incident: what changed? "
        "Given the recently-changed resources around an alert, write ONE (max two) "
        "sentence shaped: what CHANGED (which resource, with the change time when "
        "present) -> whether that change likely TRIGGERED the alert. Grounded ONLY in "
        "the given changes; never invent. No preamble."
    )
    if getattr(settings, "language", "en") == "ko":
        system += " 한국어로 답하세요 (무엇이 언제 바뀌었고 → 알림을 유발했을 가능성)."
    user = _collector_masker(settings).mask_text(
        str(compact([c.get("summary") for c in changes[:15]], limit=15))
    )
    key = insight_cache_key("change", getattr(settings, "language", "en"), user)

    async def compute() -> str | None:
        return await complete(
            settings,
            system=system,
            user=user,
            max_tokens=getattr(settings, "llm_insight_max_tokens", 512),
            model=insight_model or None,
        )

    text = await cached_insight(key, compute) or ""
    return _collector_masker(settings).mask_text(text)


def _collector_masker(settings: Settings):
    return build_masker(
        getattr(settings, "masking_regex_list", ()),
        builtin_enabled=getattr(settings, "builtin_redaction_enabled", True),
        hash_mode=getattr(settings, "builtin_redaction_hash_mode", False),
    )


def _add_helm_payload_diff(
    item: dict, current_secret: object, prior_secret: object, settings: Settings
) -> None:
    """Best-effort Helm payload evidence; labels remain the fallback on any failure."""
    current = _decode_helm_release(current_secret)
    prior = _decode_helm_release(prior_secret)
    if current is None or prior is None:
        return

    current_chart = _dict(current.get("chart"))
    prior_chart = _dict(prior.get("chart"))
    current_metadata = _dict(current_chart.get("metadata"))
    prior_metadata = _dict(prior_chart.get("metadata"))
    current_version = current_metadata.get("version")
    prior_version = prior_metadata.get("version")
    current_app_version = current_metadata.get("appVersion")
    prior_app_version = prior_metadata.get("appVersion")
    if current_version != prior_version:
        item["chart_version_change"] = {"from": prior_version, "to": current_version}
    if current_app_version != prior_app_version:
        item["chart_app_version_change"] = {"from": prior_app_version, "to": current_app_version}
    current_values = _helm_effective_values(current)
    prior_values = _helm_effective_values(prior)
    diff = _helm_values_diff(current_values, prior_values, _collector_masker(settings))
    if diff:
        item["helm_values_changed"] = diff


def _decode_helm_release(secret: object) -> dict | None:
    if not isinstance(secret, dict):
        return None
    encoded = _dict(secret.get("data")).get("release")
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        payload = base64.b64decode(encoded, validate=True)
        # Kubernetes JSON uses one base64 layer around Helm's base64 payload.
        text = payload.strip()
        if text and len(text) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", text):
            payload = base64.b64decode(text, validate=True)
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError):
            payload = zlib.decompress(payload)
        decoded = json.loads(payload.decode("utf-8"))
    except (
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
        EOFError,
        zlib.error,
    ):
        return None
    return decoded if isinstance(decoded, dict) else None


def _helm_effective_values(release: dict) -> dict:
    config = _dict(release.get("config"))
    chart = _dict(release.get("chart"))
    chart_values = _dict(chart.get("values"))
    return _merge_helm_values(chart_values, config)


def _merge_helm_values(base: dict, overrides: dict) -> dict:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_helm_values(merged[key], value)
        else:
            merged[key] = value
    return merged


def _flatten_helm_values(value: object, prefix: str = "") -> dict[str, object]:
    if not isinstance(value, dict):
        return {prefix: value}
    flattened: dict[str, object] = {}
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, dict) and child:
            flattened.update(_flatten_helm_values(child, path))
        else:
            flattened[path] = child
    return flattened


def _helm_values_diff(current: dict, prior: dict, masker) -> list[dict]:  # noqa: ANN001
    current_flat = _flatten_helm_values(current)
    prior_flat = _flatten_helm_values(prior)
    changes = []
    for key in sorted(set(current_flat) | set(prior_flat)):
        if key in current_flat and key in prior_flat and current_flat[key] == prior_flat[key]:
            continue
        changes.append({
            "key": key,
            "from": _mask_and_truncate_helm_value(masker, key, prior_flat.get(key)),
            "to": _mask_and_truncate_helm_value(masker, key, current_flat.get(key)),
        })
    dropped = max(0, len(changes) - _HELM_DIFF_MAX_KEYS)
    if dropped:
        _log.warning("helm values diff capped; dropped %d keys", dropped)
    return changes[:_HELM_DIFF_MAX_KEYS]


def _mask_and_truncate_helm_value(masker, key: str, value: object) -> object:  # noqa: ANN001
    leaf = key.rsplit(".", 1)[-1]
    masked = masker.mask_object({leaf: value}).get(leaf)
    if isinstance(masked, (dict, list, tuple)):
        masked = json.dumps(masked, sort_keys=True, default=str)
    if isinstance(masked, str) and len(masked) > _HELM_VALUE_MAX_LENGTH:
        return masked[:_HELM_VALUE_MAX_LENGTH] + "…"
    return masked


def _first_namespace(plan) -> str:  # noqa: ANN001
    namespaces = getattr(plan, "namespaces", None) or []
    return namespaces[0] if namespaces else ""


def _within_window(
    ts: object, now: datetime, *, window_seconds: int = _RECENT_WINDOW_SECONDS
) -> bool:
    parsed = _parse_time(ts)
    if parsed is None:
        return False
    return 0 <= (now - parsed).total_seconds() <= window_seconds


def _latest_condition_time(conditions: object) -> str | None:
    times = [
        _dict(c).get("lastTransitionTime") or _dict(c).get("lastUpdateTime")
        for c in _list(conditions)
    ]
    times = [t for t in times if isinstance(t, str)]
    return max(times) if times else None


def _parse_time(ts: object) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _namespace_allowed(settings: Settings, namespace: str) -> bool:
    if not namespace or not settings.kubernetes_namespaces:
        return True
    return namespace in settings.kubernetes_namespaces


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _items(data: object) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [i for i in data["items"] if isinstance(i, dict)]
    return []


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}
