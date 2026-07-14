from __future__ import annotations

import math
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
from app.collectors.loki import _llm_insight
from app.config import Settings
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)

# These queries expose useful operating context, but a raw non-zero reading has
# no failure semantics on its own. They need an explicit threshold or a derived
# comparison (for example request > allocation) before they can support/refute
# a root-cause hypothesis.
_CONTEXT_ONLY_METRICS = frozenset(
    {
        "container_memory",
        "container_cpu",
        "runai_queue_allocated_gpus",
        "runai_queue_requested_gpus",
        "runai_project_allocated_gpus",
        "runai_project_requested_gpus",
    }
)


class PrometheusCollector:
    name = "prometheus"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        if not self._settings.prometheus_url and not self._settings.prometheus_mcp_url:
            summary = f"{NO_EVIDENCE} Prometheus is not configured; metric evidence was skipped."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["prometheus.url"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="prometheus",
                        type="metrics",
                        status="unavailable",
                        confidence="low",
                        query=None,
                        summary=summary,
                        result={"prometheus_url_configured": False},
                    )
                ],
            )

        control_plane_namespaces = (
            self._settings.runai_log_namespaces
            if plan is not None and getattr(plan, "check_control_plane", False)
            else ()
        )
        queries = _queries_for(target, plan, control_plane_namespaces)
        time_range = incident_time_range(target)
        query_results = []
        warnings: list[str] = []

        used_mcp = False
        if self._settings.prometheus_mcp_url:
            try:
                query_results = await _collect_prometheus_mcp(
                    self._settings, queries, time_range=time_range
                )
                used_mcp = True
            except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
                warnings.append(mcp_fallback_warning(exc))
        else:
            warnings.append(f"{MCP_FALLBACK_WARNING}: PROMETHEUS_MCP_URL not configured")

        if not used_mcp:
            if not self._settings.prometheus_url:
                summary = f"{NO_EVIDENCE} Prometheus MCP failed and direct URL is not configured."
                return CollectorResult(
                    agent=self.name,
                    status="unavailable",
                    summary=summary,
                    confidence="low",
                    missing_data=["prometheus.url"],
                    warnings=warnings,
                    artifacts=[
                        artifact(
                            agent=self.name,
                            source="prometheus",
                            type="promql",
                            status="unavailable",
                            confidence="low",
                            query="; ".join(query for _, query in queries),
                            summary=summary,
                            result={"prometheus_mcp_url_configured": True},
                        )
                    ],
                )
            query_results = await _collect_prometheus_direct(
                self._settings, queries, warnings, time_range=time_range
            )

        _annotate_capacity_gap_coverage(query_results, time_range=time_range)

        successful = [item for item in query_results if not item["error"]]
        populated = [
            item
            for item in successful
            if item["series_count"] and item["name"] != "prometheus_up"
        ]
        if populated:
            status = "ok"
            confidence = "high"
            summary = ko_en(
                self._settings,
                f"Prometheus {'MCP' if used_mcp else '직접'} 조회 완료 — "
                f"{len(query_results)}개 쿼리 그룹 중 {len(populated)}개에서 "
                "메트릭 시리즈를 확인했습니다.",
                f"Prometheus {'MCP' if used_mcp else 'direct'} queries completed with "
                "matching metric series "
                f"for {len(populated)} of {len(query_results)} query group(s).",
            )
        elif successful:
            status = "partial"
            confidence = "medium"
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "Prometheus에는 접속했지만 워크로드 메트릭 쿼리에 시리즈가 없습니다. "
                "메트릭 레이블과 수집(scrape) 설정을 확인하세요.",
                "Prometheus is reachable, but the workload metric queries "
                "returned no series. Check metric labels and scrape configuration.",
            )
        else:
            status = "unavailable"
            confidence = "low"
            summary = f"{NO_EVIDENCE} " + ko_en(
                self._settings,
                "Prometheus 직접 조회가 실패했습니다.",
                "Prometheus direct queries failed.",
            )

        insight = await _llm_insight(
            self._settings, "Prometheus metrics", summary, query_results
        )
        if insight:
            summary = insight
        result = {
            "prometheus_url": self._settings.prometheus_url,
            "prometheus_mcp_url": self._settings.prometheus_mcp_url,
            "used_mcp": used_mcp,
            "time_range": time_range,
            "queries": query_results,
        }
        # Keep the collector-level artifact as operational context only. Exact
        # query artifacts below carry the predicate and polarity used by RCA.
        collector_observation = {
            "kind": "prometheus_collector_summary",
            "predicate": "prometheus_collector_summary",
            "polarity": "unknown",
            "coverage": "partial",
            "observation_window": time_range or {},
        }
        artifacts = [
            artifact(
                agent=self.name,
                source="prometheus",
                type="promql",
                status=status,
                confidence=confidence,
                query="; ".join(item["query"] for item in query_results),
                summary=summary,
                result={**result, "observation": collector_observation},
            )
        ]
        artifacts.extend(
            _prometheus_query_artifact(
                self.name, item, target=target, time_range=time_range
            )
            for item in query_results
        )
        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence=confidence,
            details=result,
            missing_data=(
                []
                if populated
                else ["prometheus.workload_metrics"]
                if successful
                else ["prometheus.query"]
            ),
            warnings=warnings,
            artifacts=artifacts,
        )


def _queries_for(
    target: AnalysisTarget, plan=None, control_plane_namespaces: tuple[str, ...] = ()
) -> list[tuple[str, str]]:
    namespace = target.namespace
    pod = target.pod
    if plan is not None:
        if plan.namespaces:
            namespace = plan.namespaces[0]
        pod = plan.pod or pod
    selectors = []
    if namespace:
        selectors.append(f'namespace="{namespace}"')
    if pod:
        selectors.append(f'pod="{pod}"')
    pod_selector = ",".join(selectors)

    queries: list[tuple[str, str]] = [("prometheus_up", "up")]
    # A Pod name is namespaced.  Querying only ``pod="name"`` can return a
    # same-named workload from a different namespace and then get relabelled as
    # the alert target by downstream evidence consumers.  Do not manufacture a
    # pod-scoped verdict until both halves of that identity are known.
    if namespace and pod:
        queries.extend(
            [
                ("container_memory", f"container_memory_working_set_bytes{{{pod_selector}}}"),
                ("container_cpu", f"rate(container_cpu_usage_seconds_total{{{pod_selector}}}[5m])"),
                (
                    "container_restarts",
                    f"kube_pod_container_status_restarts_total{{{pod_selector}}}",
                ),
            ]
        )
    elif namespace:
        namespace_selector = f'namespace="{namespace}"'
        queries.extend(
            [
                (
                    "namespace_pending_pods",
                    f'kube_pod_status_phase{{{namespace_selector},phase="Pending"}}',
                ),
                (
                    "namespace_restarts",
                    f"kube_pod_container_status_restarts_total{{{namespace_selector}}}",
                ),
            ]
        )
    if target.queue:
        queries.append(
            (
                "runai_queue_allocated_gpus",
                f'runai_queue_allocated_gpus{{queue="{target.queue}"}}',
            )
        )
        queries.append(
            (
                "runai_queue_capacity_gap",
                "max by (queue) "
                f'(runai_queue_requested_gpus{{queue="{target.queue}"}}) '
                "> on(queue) max by (queue) "
                f'(runai_queue_allocated_gpus{{queue="{target.queue}"}})',
            )
        )
        queries.append(
            (
                "runai_queue_requested_gpus",
                f'runai_queue_requested_gpus{{queue="{target.queue}"}}',
            )
        )
    if target.project:
        queries.extend(
            [
                (
                    "runai_project_allocated_gpus",
                    f'runai_project_allocated_gpus{{project="{target.project}"}}',
                ),
                (
                    "runai_project_requested_gpus",
                    f'runai_project_requested_gpus{{project="{target.project}"}}',
                ),
                (
                    "runai_project_capacity_gap",
                    "max by (project) "
                    f'(runai_project_requested_gpus{{project="{target.project}"}}) '
                    "> on(project) max by (project) "
                    f'(runai_project_allocated_gpus{{project="{target.project}"}})',
                ),
            ]
        )
    # Control-plane health: when the alert implicates Run:ai, check whether the
    # scheduler/backend pods themselves are crashlooping or stuck Pending — a dying
    # workload's cause is often an unhealthy control plane, not the workload.
    # Namespaces are DNS-1123 labels (lowercase alnum + '-'), none of which are
    # RE2-special, so they drop straight into the =~ matcher. NOT re.escape():
    # that emits Python-regex backslashes ("runai-backend" -> "runai\\-backend"),
    # and "\\-" is an illegal escape INSIDE a PromQL double-quoted string literal,
    # which Prometheus rejects at the lexer with HTTP 400 before any regex runs.
    ns_re = "|".join(ns for ns in control_plane_namespaces if ns)
    if ns_re:
        cp = f'namespace=~"{ns_re}"'
        queries.extend(
            [
                (
                    "runai_control_plane_restarts",
                    f"kube_pod_container_status_restarts_total{{{cp}}}",
                ),
                (
                    "runai_control_plane_pending",
                    f'kube_pod_status_phase{{{cp},phase="Pending"}}',
                ),
            ]
        )
    return queries


def _prometheus_status(data: object) -> str:
    if isinstance(data, dict):
        value = data.get("status")
        if isinstance(value, str):
            return value
    return "unknown"


def _prometheus_result(data: object) -> list[object]:
    if not isinstance(data, dict):
        return []
    payload = data.get("data")
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    return result if isinstance(result, list) else []


def _prometheus_result_complete(data: object) -> bool:
    """Return whether a native Prometheus response explicitly contains a vector.

    ``status: success`` alone does not prove that the query was answered.  In
    particular, a proxy can return a truncated JSON object such as
    ``{status: success, data: {}}``.  That must not become a scoped absence just
    because the permissive result parser represents both malformed and explicit
    empty vectors as ``[]``.
    """
    if not isinstance(data, dict):
        return False
    payload = data.get("data")
    return isinstance(payload, dict) and isinstance(payload.get("result"), list)


async def _collect_prometheus_direct(
    settings: Settings,
    queries: list[tuple[str, str]],
    warnings: list[str],
    time_range: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    query_results: list[dict[str, object]] = []
    for name, query in queries:
        response = await get_json(
            base_url=settings.prometheus_url,
            path="/api/v1/query_range" if time_range else "/api/v1/query",
            timeout_seconds=settings.prometheus_timeout_seconds,
            params=(
                {"query": query, **time_range, "step": "60"}
                if time_range
                else {"query": query}
            ),
        )
        status = _prometheus_status(response.data)
        error = response.error or _prometheus_api_error(
            response.data, status, require_success_status=True
        )
        result_data = _prometheus_result(response.data)
        if error is None and not _prometheus_result_complete(response.data):
            error = "Prometheus response missing data.result"
        query_results.append(
            {
                "name": name,
                "query": query,
                "url": response.url,
                "status_code": response.status_code,
                "status": status,
                "series_count": len(result_data),
                "sample": compact(result_data, limit=3),
                "value_summary": _prometheus_value_summary(result_data),
                "error": error,
                **({"time_range": time_range} if time_range else {}),
            }
        )
        if error:
            warnings.append(f"Prometheus query failed for {name}: {error}")
    return query_results


def _prometheus_api_error(
    data: object, status: str, *, require_success_status: bool = False
) -> str | None:
    """Return a native Prometheus API error hidden behind an HTTP 200 response.

    A malformed PromQL query can yield ``{status: error}`` without a transport
    error. It must not fall through as a zero-series result, which would turn a
    failed lookup into an RCA-safe absence verdict.
    """
    if status == "success" or (status == "unknown" and not require_success_status):
        return None
    if isinstance(data, dict):
        detail = str(data.get("error") or data.get("errorType") or "").strip()
        if detail:
            return f"Prometheus API status {status}: {detail}"
    return f"Prometheus API status {status}"


async def _collect_prometheus_mcp(
    settings: Settings,
    queries: list[tuple[str, str]],
    *,
    time_range: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    datasource_uid = await _grafana_datasource_uid(settings.prometheus_mcp_url, "prometheus")
    return [
        await _mcp_query_prometheus(
            settings.prometheus_mcp_url, name, query, datasource_uid, time_range=time_range
        )
        for name, query in queries
    ]


async def prom_mcp_query(
    settings: Settings,
    name: str,
    promql: str,
    *,
    time_range: dict[str, str] | None = None,
) -> dict[str, object]:
    datasource_uid = await _grafana_datasource_uid(settings.prometheus_mcp_url, "prometheus")
    return await _mcp_query_prometheus(
        settings.prometheus_mcp_url,
        name,
        promql,
        datasource_uid,
        time_range=time_range,
    )


async def _mcp_query_prometheus(
    url: str,
    name: str,
    promql: str,
    datasource_uid: str = "",
    *,
    time_range: dict[str, str] | None = None,
) -> dict[str, object]:
    # Same contract as Loki: grafana-mcp needs a real datasourceUid. An empty one
    # 400s with "id is invalid" on every query; fail fast so the caller falls back
    # cleanly. (uid usually empty when grafana-mcp can't list datasources — set
    # secrets.grafanaServiceAccountToken.)
    if not datasource_uid:
        raise RuntimeError(
            "grafana datasource uid unresolved for prometheus — set "
            "secrets.grafanaServiceAccountToken so grafana-mcp can list datasources"
        )
    # mcp-grafana query_prometheus takes a range query as datasourceUid/expr/
    # startTime/endTime/stepSeconds. Keep this exact: the older `query` aliases
    # silently caused an instant query (or a schema 400), which sampled *now*
    # instead of the incident.
    query_window = time_range or {"start": "now-15m", "end": "now"}
    args = {
        "datasourceUid": datasource_uid,
        "expr": promql,
        "queryType": "range",
        "startTime": query_window["start"],
        "endTime": query_window["end"],
        "stepSeconds": 60,
    }
    data = await _call_mcp_json(url, "query_prometheus", [args])
    status = _prometheus_status(data)
    result_data = _prometheus_mcp_result(data)
    error = _prometheus_api_error(data, status)
    # Grafana MCP can wrap a range vector in a flat data or result list.
    # Do not recursively accept arbitrary lists: a misrouted datasource
    # response used to look like non-empty metric series.
    if error is None and not _prometheus_mcp_response_complete(data):
        error = "Prometheus MCP response missing a recognized metric result"
    return {
        "name": name,
        "query": promql,
        "url": f"{url}#query_prometheus",
        "status_code": 200,
        "status": status,
        "series_count": len(result_data),
        "sample": compact(result_data, limit=3),
        "value_summary": _prometheus_value_summary(result_data),
        "error": error,
        "time_range": query_window,
    }


def _prometheus_value_summary(result_data: list[object]) -> dict[str, object]:
    """Summarise range values so zero/False is visible as refuting evidence.

    A non-empty Prometheus vector is not automatically evidence of a failure:
    e.g. ``kube_pod_status_phase{phase="Pending"}`` can legitimately be all
    zero. Preserve a bounded per-series timeline plus aggregate extrema rather
    than asking the ranker to infer state from raw samples.
    """
    # Keep only a few labelled series for the artifact UI, but aggregate every
    # returned series for the RCA verdict. A fourth target must not be able to
    # hide a scrape outage or a counter change behind three healthy examples.
    summaries: list[dict[str, object]] = []
    all_series: list[dict[str, object]] = []
    all_values: list[float] = []
    observed_label_values: dict[str, set[str]] = {}
    observed_label_series_counts: dict[str, int] = {}
    for index, item in enumerate(result_data):
        if not isinstance(item, dict):
            continue
        metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
        for key in ("namespace", "pod", "node", "project", "queue"):
            value = metric.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                observed_label_values.setdefault(key, set()).add(str(value).strip())
                observed_label_series_counts[key] = observed_label_series_counts.get(key, 0) + 1
        samples = _prometheus_samples(item)
        numeric = [value for _, value in samples if value is not None]
        all_values.extend(numeric)
        summary: dict[str, object] = {
            "sample_count": len(samples),
            "numeric_sample_count": len(numeric),
        }
        if samples:
            summary["first_timestamp"] = samples[0][0]
            summary["last_timestamp"] = samples[-1][0]
            # Keep every raw timestamp for verification.  A proxy is allowed
            # to return an unsorted vector, so first/last alone cannot prove
            # that no interior sample came from outside the incident window.
            summary["sample_timestamps"] = [timestamp for timestamp, _ in samples]
        if numeric:
            summary.update(
                {
                    "min": min(numeric),
                    "max": max(numeric),
                    "last": numeric[-1],
                    "zero_sample_count": sum(value == 0 for value in numeric),
                    "nonzero_sample_count": sum(value != 0 for value in numeric),
                    "all_zero": all(value == 0 for value in numeric),
                }
            )
            if len(numeric) >= 2:
                # Counter resets are also meaningful lifecycle activity, so a
                # decrease counts as a change as well as an increase. Compare
                # every adjacent pair: a counter can increase then reset within
                # one incident window and finish at its starting value.
                summary["changed_during_window"] = any(
                    current != previous
                    for previous, current in zip(numeric, numeric[1:], strict=False)
                )
        all_series.append(summary)
        if index < 3:
            summary = {
                **summary,
                "labels": {
                    str(key): str(metric[key])
                    for key in sorted(metric)
                    if key
                    in {
                        "namespace",
                        "pod",
                        "container",
                        "node",
                        "phase",
                        "condition",
                        "project",
                        "queue",
                    }
                },
            }
            summaries.append(summary)
    aggregate: dict[str, object] = {
        "series": summaries,
        # These compact bounds cover every returned series. They are evidence
        # metadata only; labelled samples above remain intentionally bounded.
        "sample_windows": [
            {
                key: summary[key]
                for key in ("first_timestamp", "last_timestamp", "sample_timestamps")
                if key in summary
            }
            for summary in all_series
        ],
        "series_count_observed": len(all_series),
        # Preserve every returned target-relevant label, not merely the first
        # three display samples.  RCA scope must be validated against the full
        # vector: a fourth series for another Pod must not be relabelled as the
        # alert target by the pipeline fallback.
        "observed_label_values": {
            key: sorted(values) for key, values in sorted(observed_label_values.items())
        },
        "observed_label_series_counts": dict(sorted(observed_label_series_counts.items())),
        "sample_timestamp_verification_required": True,
        "numeric_sample_count": len(all_values),
    }
    if all_values:
        aggregate.update(
            {
                "min": min(all_values),
                "max": max(all_values),
                "zero_sample_count": sum(value == 0 for value in all_values),
                "nonzero_sample_count": sum(value != 0 for value in all_values),
                "all_zero": all(value == 0 for value in all_values),
                "series_with_multiple_samples": sum(
                    int(item.get("numeric_sample_count") or 0) >= 2 for item in all_series
                ),
                "any_series_changed_during_window": any(
                    item.get("changed_during_window") is True for item in all_series
                ),
            }
        )
    return aggregate


def _prometheus_query_artifact(
    agent: str,
    item: dict[str, object],
    *,
    target: AnalysisTarget,
    time_range: dict[str, str] | None,
):
    """Expose one query's verified truth value as an RCA-safe evidence card."""
    observation = _prometheus_query_observation(
        item, target=target, time_range=time_range
    )
    name = str(item.get("name") or "metric")
    polarity = str(observation["polarity"])
    status = "unavailable" if polarity == "unavailable" else "ok"
    confidence = "high" if polarity in {"present", "absent"} else "low"
    if polarity == "present":
        summary = f"Prometheus {name}: incident-window signal was present."
    elif polarity == "absent":
        summary = f"{NO_EVIDENCE} Prometheus {name}: signal was absent in the incident window."
    else:
        summary = f"Prometheus {name}: query result was unavailable or inconclusive."
    return artifact(
        agent=agent,
        source="prometheus",
        type="promql_signal",
        status=status,
        confidence=confidence,
        title=f"Prometheus · {name}",
        query=str(item.get("query") or ""),
        summary=summary,
        result={
            "observation": observation,
            "value_summary": item.get("value_summary") or {},
            "sample": item.get("sample") or [],
            "time_range": time_range,
        },
    )


def _annotate_capacity_gap_coverage(
    query_results: list[dict[str, object]], *, time_range: dict[str, str] | None = None
) -> None:
    """Allow a capacity-gap absence only when both operands were observed."""
    by_name = {str(item.get("name") or ""): item for item in query_results}
    for scope in ("queue", "project"):
        gap = by_name.get(f"runai_{scope}_capacity_gap")
        requested = by_name.get(f"runai_{scope}_requested_gpus")
        allocated = by_name.get(f"runai_{scope}_allocated_gpus")
        if gap is None:
            continue
        gap["capacity_sources_available"] = all(
            _has_prometheus_samples(item, time_range=time_range)
            for item in (requested, allocated)
        )


def _has_prometheus_samples(
    item: object, *, time_range: dict[str, str] | None = None
) -> bool:
    if not isinstance(item, dict) or item.get("error"):
        return False
    if int(item.get("series_count") or 0) == 0:
        return False
    summary = item.get("value_summary")
    if not isinstance(summary, dict) or int(summary.get("numeric_sample_count") or 0) <= 0:
        return False
    verified = _prometheus_samples_in_window(summary, time_range)
    if summary.get("sample_timestamp_verification_required") is True:
        return verified is True
    return verified is not False


def _prometheus_query_observation(
    item: dict[str, object],
    *,
    time_range: dict[str, str] | None,
    target: AnalysisTarget | None = None,
) -> dict[str, object]:
    """Classify output without treating a non-empty all-zero vector as a failure."""
    name = str(item.get("name") or "metric")
    value_summary = item.get("value_summary")
    summary = value_summary if isinstance(value_summary, dict) else {}
    sample_window_verified = _prometheus_samples_in_window(summary, time_range)
    if item.get("error"):
        polarity, coverage = "unavailable", "unknown"
    else:
        series_count = int(item.get("series_count") or 0)
        numeric_count = int(summary.get("numeric_sample_count") or 0)
        all_zero = summary.get("all_zero")
        if not time_range:
            # An unbounded/current metric lookup can help an operator, but it
            # cannot prove a signal was absent (or causal) during a historical
            # incident. Keep every such answer as context-only.
            polarity, coverage = "unknown", "partial"
        elif name in _CONTEXT_ONLY_METRICS:
            polarity, coverage = "unknown", "partial"
        elif name.endswith("capacity_gap"):
            if series_count and numeric_count:
                polarity, coverage = "present", "scoped"
            elif series_count:
                polarity, coverage = "unknown", "partial"
            elif item.get("capacity_sources_available") is True:
                polarity, coverage = "absent", "scoped"
            else:
                polarity, coverage = "unknown", "partial"
        elif series_count == 0:
            # An empty range response has no sample timestamp to inspect, but
            # remains a direct answer to the bounded query. Keep its existing
            # absence semantics; non-empty replies must prove their timing.
            polarity, coverage = "absent", "scoped"
        elif sample_window_verified is False or (
            summary.get("sample_timestamp_verification_required") is True
            and sample_window_verified is not True
        ):
            # Grafana MCP/proxies can accept a range-shaped request but return
            # a current instant vector. Never relabel that live sample as
            # incident evidence merely because the client requested a window.
            polarity, coverage = "unknown", "partial"
        elif numeric_count == 0:
            polarity, coverage = "unknown", "partial"
        elif name == "prometheus_up":
            # The base query is intentionally global (``up`` has no target
            # selector), so a down scrape says something about telemetry
            # availability but not about this incident's resource.  Do not let
            # the blackboard relabel it as target-scoped RCA support.
            polarity, coverage = "unknown", "partial"
        elif name.endswith("restarts"):
            # Restart metrics are monotonically increasing counters. A
            # non-zero value can have been accumulated long before the alert;
            # only a change within this incident range supports a restart
            # hypothesis. One-sample replies cannot establish that difference.
            if int(summary.get("series_with_multiple_samples") or 0) == 0:
                polarity, coverage = "unknown", "partial"
            elif summary.get("any_series_changed_during_window") is True:
                polarity, coverage = "present", "scoped"
            else:
                polarity, coverage = "absent", "scoped"
        elif all_zero is True:
            polarity, coverage = "absent", "scoped"
        else:
            polarity, coverage = "present", "scoped"
    observed_entity: dict[str, str] | None = None
    target_scope_verified: bool | None = None
    if target is not None and polarity in {"present", "absent"}:
        observed_entity, target_scope_verified = _prometheus_target_scope(
            name,
            summary,
            target,
            has_series=bool(int(item.get("series_count") or 0)),
        )
        if target_scope_verified is not True:
            # The selector we sent is not proof that the proxy returned only
            # that selector.  Require labels from every non-empty series before
            # treating it as evidence for this incident; otherwise a broad or
            # misrouted response would inherit the pipeline's alert entity.
            polarity, coverage = "unknown", "partial"
    observation = {
        "kind": "prometheus_query",
        "predicate": f"metric:{name}",
        "polarity": polarity,
        "coverage": coverage,
        "series_count": int(item.get("series_count") or 0),
        "zero_sample_count": (
            (item.get("value_summary") or {}).get("zero_sample_count")
            if isinstance(item.get("value_summary"), dict)
            else 0
        ),
        "observation_window": time_range or {},
        "sample_window_verified": sample_window_verified,
    }
    if observed_entity:
        observation["observed_entity"] = observed_entity
    if target_scope_verified is not None:
        observation["target_scope_verified"] = target_scope_verified
    if polarity == "present":
        evidence_window = _prometheus_evidence_window(summary, time_range)
        if evidence_window:
            observation["evidence_window"] = evidence_window
    return observation


def _prometheus_target_scope(
    name: str,
    value_summary: dict[str, object],
    target: AnalysisTarget,
    *,
    has_series: bool,
) -> tuple[dict[str, str] | None, bool | None]:
    """Return the explicitly queried entity only when response labels prove it.

    Empty vectors are valid responses to the collector's fixed, target-scoped
    PromQL templates, so their absence can retain that query scope.  Non-empty
    vectors must carry exactly the requested target labels; the request text
    alone is not enough because a datasource proxy can ignore or rewrite it.
    Unknown/ad-hoc metric names intentionally return ``None`` and keep their
    existing context-only semantics.
    """
    requirements: tuple[tuple[str, str], ...]
    entity: dict[str, str]
    if name in {"container_memory", "container_cpu", "container_restarts"}:
        if not (target.namespace and target.pod):
            return None, False
        requirements = (("namespace", target.namespace), ("pod", target.pod))
        entity = {"kind": "pod", "name": target.pod}
    elif name in {"namespace_pending_pods", "namespace_restarts"}:
        if not target.namespace:
            return None, False
        requirements = (("namespace", target.namespace),)
        entity = {"kind": "namespace", "name": target.namespace}
    elif name.startswith("runai_queue_"):
        if not target.queue:
            return None, False
        requirements = (("queue", target.queue),)
        entity = {"kind": "queue", "name": target.queue}
    elif name.startswith("runai_project_"):
        if not target.project:
            return None, False
        requirements = (("project", target.project),)
        entity = {"kind": "project", "name": target.project}
    else:
        return None, None

    if not has_series:
        return entity, True
    labels = value_summary.get("observed_label_values")
    label_counts = value_summary.get("observed_label_series_counts")
    series_count = int(value_summary.get("series_count_observed") or 0)
    if not isinstance(labels, dict) or not isinstance(label_counts, dict) or series_count <= 0:
        return None, False
    for label, expected in requirements:
        values = labels.get(label)
        if (
            not isinstance(values, list)
            or int(label_counts.get(label) or 0) != series_count
            or {str(value).strip() for value in values} != {expected}
        ):
            return None, False
    return entity, True


def _prometheus_evidence_window(
    value_summary: dict[str, object], time_range: dict[str, str] | None
) -> dict[str, str]:
    """Return the actual timestamp span of returned, in-range metric samples."""
    if not time_range:
        return {}
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return {}
    timestamps: list[tuple[datetime, str]] = []
    series = value_summary.get("sample_windows")
    if not isinstance(series, list):
        series = value_summary.get("series")
    for item in series if isinstance(series, list) else []:
        if not isinstance(item, dict):
            continue
        values = item.get("sample_timestamps")
        candidates = (
            values
            if isinstance(values, list)
            else [item.get("first_timestamp"), item.get("last_timestamp")]
        )
        for raw in candidates:
            parsed = _parse_prometheus_timestamp(raw)
            if parsed is not None and start <= parsed <= end:
                timestamps.append((parsed, str(raw)))
    if not timestamps:
        return {}
    timestamps.sort(key=lambda item: item[0])
    return {"start": timestamps[0][1], "end": timestamps[-1][1]}


def _prometheus_samples_in_window(
    value_summary: dict[str, object], time_range: dict[str, str] | None
) -> bool | None:
    """Return whether every reported sample boundary is in the requested window.

    ``None`` preserves compatibility with legacy/stub responses that do not
    expose timestamps.  A single in-window point is insufficient: verdicts
    aggregate every returned sample, so one out-of-window point could otherwise
    create or erase an incident signal.  A definite out-of-window boundary is
    enough to reject a supposedly historical query, which catches instant-query
    fallbacks and mixed range responses.
    """
    if not time_range:
        return None
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return None
    timestamps: list[datetime] = []
    series = value_summary.get("sample_windows")
    if not isinstance(series, list):
        series = value_summary.get("series")
    for item in series if isinstance(series, list) else []:
        if not isinstance(item, dict):
            continue
        raw_timestamps = item.get("sample_timestamps")
        candidates = (
            raw_timestamps
            if isinstance(raw_timestamps, list)
            else [item.get("first_timestamp"), item.get("last_timestamp")]
        )
        for value in candidates:
            parsed = _parse_prometheus_timestamp(value)
            if parsed is None:
                # A non-empty sample with no parseable instant cannot prove
                # historical scope.  Do not silently ignore it.
                return None
            timestamps.append(parsed)
    if not timestamps:
        return None
    return all(start <= timestamp <= end for timestamp in timestamps)


def _parse_prometheus_timestamp(value: object) -> datetime | None:
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip()):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, TypeError, ValueError):
            pass
    return parse_incident_time(value)


def _prometheus_samples(item: dict[str, object]) -> list[tuple[str, float | None]]:
    raw = item.get("values")
    if not isinstance(raw, list):
        value = item.get("value")
        raw = [value] if isinstance(value, list) else []
    samples: list[tuple[str, float | None]] = []
    for pair in raw:
        if not isinstance(pair, list) or len(pair) < 2:
            continue
        try:
            numeric = float(str(pair[1]))
        except (TypeError, ValueError):
            numeric = None
        if numeric is not None and not math.isfinite(numeric):
            numeric = None
        samples.append((str(pair[0]), numeric))
    return samples


# Grafana datasource uids are ^[a-zA-Z0-9\-_]{1,40}$; a numeric row id or a
# display name ("Prometheus (default)") passed as datasourceUid makes grafana-mcp
# fail EVERY query with 400 "id is invalid" — which demoted the whole collector
# to the direct HTTP fallback.
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


def _first_result_list(data: object) -> list[object]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for value in data.values():
        if isinstance(value, list):
            return value
        found = _first_result_list(value)
        if found:
            return found
    return []


def _prometheus_mcp_result(data: object) -> list[object]:
    """Return only documented/native MCP metric-vector envelopes."""
    native = _prometheus_result(data)
    if _prometheus_result_complete(data):
        return native
    if not isinstance(data, dict):
        return []
    for key in ("result", "data"):
        value = data.get(key)
        if isinstance(value, list) and _prometheus_mcp_flat_result_complete(value):
            return value
    return []


def _prometheus_mcp_response_complete(data: object) -> bool:
    if _prometheus_result_complete(data):
        return True
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(key), list) and _prometheus_mcp_flat_result_complete(data[key])
        for key in ("result", "data")
    )


def _prometheus_mcp_flat_result_complete(value: list[object]) -> bool:
    """Whether a Grafana MCP flat result is explicitly a metric vector."""
    if not value:
        return True
    return all(
        isinstance(item, dict)
        and (
            isinstance(item.get("value"), list)
            or isinstance(item.get("values"), list)
        )
        for item in value
    )


# --- Cross-collector deterministic follow-up -----------------------------------
# The k8s->prometheus branches of the unified debug flowchart, as code: given what
# the kubernetes collector found, derive the PromQL a human runs next. Runs with or
# without the LLM. Read-only.
async def prom_query(
    settings: Settings, name: str, promql: str, *, time_range: dict[str, str] | None = None
) -> dict:
    """One ad-hoc PromQL query, bounded to the incident window when available."""
    if not settings.prometheus_url:
        return {"name": name, "query": promql, "error": "prometheus not configured", "data": None}
    resp = await get_json(
        base_url=settings.prometheus_url,
        path="/api/v1/query_range" if time_range else "/api/v1/query",
        timeout_seconds=settings.prometheus_timeout_seconds,
        params={"query": promql, **time_range, "step": "60"} if time_range else {"query": promql},
    )
    status = _prometheus_status(resp.data)
    error = resp.error or _prometheus_api_error(resp.data, status, require_success_status=True)
    result_data = _prometheus_result(resp.data)
    if error is None and not _prometheus_result_complete(resp.data):
        error = "Prometheus response missing data.result"
    return {
        "name": name,
        "query": promql,
        "status_code": resp.status_code,
        "status": status,
        "error": error,
        "series_count": len(result_data),
        "sample": compact(result_data, limit=3),
        "value_summary": _prometheus_value_summary(result_data),
        **({"time_range": time_range} if time_range else {}),
    }


def _prom_followup_queries(details: dict, target: AnalysisTarget) -> list[tuple[str, str]]:
    ns, pod, node = (target.namespace or ""), (target.pod or ""), (target.node or "")
    if not isinstance(details, dict):
        return []
    diags = details.get("container_diagnostics") or []
    statuses = details.get("pod_statuses") or []
    oom = any(
        isinstance(d, dict) and isinstance(d.get("lastTerminated"), dict)
        and "oomkilled" in str(d["lastTerminated"].get("reason", "")).lower()
        for d in diags
    )
    restarts = any(
        isinstance(d, dict) and isinstance(d.get("restartCount"), int) and d["restartCount"] > 0
        for d in diags
    )
    pending = any(
        isinstance(p, dict) and str(p.get("phase", "")).lower() == "pending" for p in statuses
    )
    out: list[tuple[str, str]] = []
    if oom and ns and pod:
        # ratio ~1 => own-limit OOM (raise limit / fix leak); <<1 => node pressure.
        out.append((
            "oom_working_set_vs_limit",
            f'max_over_time(container_memory_working_set_bytes{{namespace="{ns}",pod="{pod}",'
            f'container!="",container!="POD"}}[30m]) / on(namespace,pod,container) '
            f'kube_pod_container_resource_limits{{namespace="{ns}",pod="{pod}",resource="memory"}}',
        ))
        out.append((
            "oom_growth_shape",
            f'deriv(container_memory_working_set_bytes{{namespace="{ns}",pod="{pod}",'
            f'container!="",container!="POD"}}[30m])',
        ))
    if restarts and ns and pod:
        out.append((
            "active_restart_rate",
            f'increase(kube_pod_container_status_restarts_total{{namespace="{ns}",pod="{pod}"}}[15m])',
        ))
    if pending and node:
        out.append((
            "node_memory_headroom",
            f'node_memory_MemAvailable_bytes{{instance=~"{node}.*"}} / '
            f'node_memory_MemTotal_bytes{{instance=~"{node}.*"}}',
        ))
    return out


async def prometheus_followup(
    settings: Settings,
    prometheus_result: CollectorResult | None,
    kubernetes_result: CollectorResult | None,
    target: AnalysisTarget,
    max_reads: int = 6,
) -> list[dict]:
    """Fire k8s->prometheus follow-up queries and attach them as followup_query
    artifacts on the prometheus result. Best-effort, read-only, bounded."""
    if prometheus_result is None or getattr(prometheus_result, "agent", "") != "prometheus":
        return []
    details = getattr(kubernetes_result, "details", {}) or {}
    queries = _prom_followup_queries(details, target)[:max_reads]
    results: list[dict] = []
    time_range = incident_time_range(target)
    for name, promql in queries:
        results.append(await prom_query(settings, name, promql, time_range=time_range))
    for res in results:
        err = res.get("error")
        prometheus_result.artifacts.append(
            artifact(
                agent="prometheus", source="prometheus", type="followup_query",
                status="unavailable" if err else "ok", confidence="medium",
                query=res.get("query"),
                summary=(str(err) if err else f"flowchart follow-up: {res.get('name')}"),
                result={
                    **res,
                    # Follow-ups are correlation probes (for example, an OOM
                    # clue drives a memory-ratio query).  They use the correct
                    # historical window but have no universal failure threshold,
                    # so they remain context until a typed predicate is added.
                    "observation": {
                        "kind": "prometheus_followup_query",
                        "predicate": f"metric:{res.get('name') or 'followup'}",
                        "polarity": "unavailable" if err else "unknown",
                        "coverage": "unknown" if err else "partial",
                        "observation_window": time_range or {},
                    },
                },
            )
        )
    return results
