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

from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact, ko_en
from app.collectors.http_json import compact, get_json
from app.config import Settings
from app.llm import cached_insight, complete, insight_cache_key, llm_configured
from app.masking import build_masker

# How far back a change still counts as "recent" and relevant to this alert.
# ponytail: fixed window; make it an env setting only if a real alert needs tuning.
_RECENT_WINDOW_SECONDS = 3600


class ChangeCollector:
    name = "change"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:  # noqa: ANN001
        namespace = _first_namespace(plan) or target.namespace
        node = getattr(plan, "node", "") or target.node

        token = _read_file(self._settings.kubernetes_token_path)
        if not token or not namespace or not _namespace_allowed(self._settings, namespace):
            reason = (
                "Kubernetes service account token is not available."
                if not token
                else "no in-scope namespace was resolved for change detection."
            )
            return self._empty(f"{NO_EVIDENCE} {reason}", missing=["change.unconfigured"])

        headers = {"Authorization": f"Bearer {token}"}
        verify: bool | str = (
            self._settings.kubernetes_ca_path
            if Path(self._settings.kubernetes_ca_path).exists()
            else True
        )
        now = datetime.now(UTC)
        ns = quote(namespace, safe="")
        limit = str(self._settings.kubernetes_list_limit)
        warnings: list[str] = []

        controllers = await self._recent_controllers(ns, node, headers, verify, now, warnings)
        pods = await self._recent_pods(ns, headers, verify, now, warnings)
        node_changes = await self._node_conditions(node, headers, verify, now, warnings)
        events = await self._recent_events(ns, limit, headers, verify, warnings)

        changes = controllers + pods + node_changes + events
        changes.sort(key=lambda c: c.get("timestamp") or "", reverse=True)

        if not changes:
            return self._empty(
                f"{NO_EVIDENCE} "
                + ko_en(
                    self._settings,
                    f"최근 {_RECENT_WINDOW_SECONDS // 60}분 내 네임스페이스 {namespace}에서 "
                    "변경된 워크로드/파드/노드/이벤트가 없습니다.",
                    "No recently-changed workloads, pods, nodes, or events "
                    f"found in namespace {namespace} within the last "
                    f"{_RECENT_WINDOW_SECONDS // 60}m.",
                ),
                missing=[],
                warnings=warnings,
                details={"namespace": namespace, "node": node},
            )

        summary = _deterministic_summary(changes, namespace)
        insight = await _senior_insight(self._settings, changes)
        if insight:
            summary = f"{summary} {insight}"

        details = {
            "namespace": namespace,
            "node": node,
            "window_seconds": _RECENT_WINDOW_SECONDS,
            "changes": changes,
            "insight": insight,
        }
        return CollectorResult(
            agent=self.name,
            status="ok",
            summary=summary,
            confidence="high" if len(changes) >= 2 else "medium",
            details=details,
            missing_data=[],
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="kubernetes",
                    type="change_detection",
                    status="ok",
                    confidence="high",
                    query=f"namespace={namespace} node={node or 'n/a'}",
                    summary=summary,
                    result=details,
                )
            ],
        )

    def _empty(
        self,
        summary: str,
        *,
        missing: list[str],
        warnings: list[str] | None = None,
        details: dict | None = None,
    ) -> CollectorResult:
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
                    result=details or {},
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
            warnings.append(f"change {label} query failed: {response.error}")
            return None
        return response.data

    async def _recent_controllers(
        self, ns, node, headers, verify, now, warnings
    ) -> list[dict]:  # noqa: ANN001
        out: list[dict] = []
        params = {"limit": str(self._settings.kubernetes_list_limit)}
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
                changed_recently = _within_window(meta.get("creationTimestamp"), now)
                cond_ts = _latest_condition_time(status.get("conditions"))
                if _within_window(cond_ts, now):
                    changed_recently = True
                rollout = isinstance(gen, int) and gen != observed
                if not (rollout or changed_recently):
                    continue
                out.append(
                    {
                        "timestamp": cond_ts or meta.get("creationTimestamp"),
                        "kind": kind,
                        "name": meta.get("name"),
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

    async def _recent_pods(self, ns, headers, verify, now, warnings) -> list[dict]:  # noqa: ANN001
        data = await self._get(
            f"/api/v1/namespaces/{ns}/pods",
            {"limit": str(self._settings.kubernetes_list_limit)},
            headers, verify, warnings, "pods",
        )
        out: list[dict] = []
        for item in _items(data):
            meta = _dict(item.get("metadata"))
            name = meta.get("name")
            created = meta.get("creationTimestamp")
            deleted = meta.get("deletionTimestamp")
            if deleted:
                out.append(
                    {
                        "timestamp": deleted,
                        "kind": "PodDeleted",
                        "name": name,
                        "summary": f"Pod {name} is terminating (deletionTimestamp set).",
                    }
                )
            elif _within_window(created, now):
                out.append(
                    {
                        "timestamp": created,
                        "kind": "PodCreated",
                        "name": name,
                        "summary": f"Pod {name} was created recently.",
                    }
                )
        return out

    async def _node_conditions(self, node, headers, verify, now, warnings) -> list[dict]:  # noqa: ANN001
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
            if not _within_window(transition, now):
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
                    "summary": f"Node {node} condition {ctype}={cstatus} "
                    f"({cond.get('reason') or 'transitioned'}).",
                }
            )
        return out

    async def _recent_events(self, ns, limit, headers, verify, warnings) -> list[dict]:  # noqa: ANN001
        data = await self._get(
            f"/api/v1/namespaces/{ns}/events",
            {"limit": limit}, headers, verify, warnings, "events",
        )
        events = []
        for item in _items(data):
            item = _dict(item)
            ts = item.get("lastTimestamp") or item.get("eventTime")
            involved = _dict(item.get("involvedObject"))
            events.append(
                {
                    "timestamp": ts,
                    "kind": f"Event/{item.get('type', 'Normal')}",
                    "name": involved.get("name"),
                    "summary": f"{item.get('reason')}: {item.get('message')}",
                    "_type": item.get("type"),
                }
            )
        # Warnings first, then by recency; keep the most relevant handful.
        events.sort(
            key=lambda e: (e.pop("_type", "") == "Warning", e.get("timestamp") or ""),
            reverse=True,
        )
        return events[:10]


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
            max_tokens=160,
            model=insight_model or None,
        )

    text = await cached_insight(key, compute) or ""
    return _collector_masker(settings).mask_text(text)


def _collector_masker(settings: Settings):
    return build_masker(
        settings.masking_regex_list,
        builtin_enabled=settings.builtin_redaction_enabled,
        hash_mode=settings.builtin_redaction_hash_mode,
    )


def _first_namespace(plan) -> str:  # noqa: ANN001
    namespaces = getattr(plan, "namespaces", None) or []
    return namespaces[0] if namespaces else ""


def _within_window(ts: object, now: datetime) -> bool:
    parsed = _parse_time(ts)
    if parsed is None:
        return False
    return 0 <= (now - parsed).total_seconds() <= _RECENT_WINDOW_SECONDS


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
