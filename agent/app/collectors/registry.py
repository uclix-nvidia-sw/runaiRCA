from __future__ import annotations

import logging
from typing import Any

from app.collectors.change import ChangeCollector, change_query
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.collectors.system import SystemCollector, system_log_query
from app.config import Settings

_log = logging.getLogger(__name__)

COLLECTORS: dict[str, type[Any]] = {
    "runai": RunAICollector,
    "kubernetes": KubernetesCollector,
    "postgres": PostgresCollector,
    "prometheus": PrometheusCollector,
    "loki": LokiCollector,
    "system": SystemCollector,
    "change": ChangeCollector,
}
DEFAULT_COLLECTORS: tuple[str, ...] = tuple(COLLECTORS)

# Stable integration contract for bounded ad-hoc collector reads. Both calls
# return metadata observations only; their source groups are explicit so later
# consumers can avoid treating node logs and Kubernetes API evidence as
# independent corroboration. This adds no direct knowledge-authoring surface.
READ_ONLY_QUERY_CAPABILITIES: dict[str, dict[str, Any]] = {
    "system_log_query": {
        "collector": "system",
        "source_group": "node_system",
        "independence_group": "node_system",
        "call": system_log_query,
    },
    "change_query": {
        "collector": "change",
        "source_group": "kubernetes_api",
        "independence_group": "kubernetes_api",
        "call": change_query,
    },
}
QUERY_CAPABILITIES = READ_ONLY_QUERY_CAPABILITIES


def build_collectors(settings: Settings) -> list[Any]:
    names, unknown = _collector_configuration(settings)
    selected = [COLLECTORS[name](settings) for name in names]

    if unknown:
        _log.warning("ignoring unknown collectors from COLLECTORS: %s", ", ".join(unknown))
    configured = settings.collectors or DEFAULT_COLLECTORS
    if settings.collectors and not any(
        str(name).strip().lower() in COLLECTORS for name in configured
    ):
        _log.warning("COLLECTORS produced no valid collectors; falling back to default set")
    return selected


def unknown_collector_names(settings: Settings) -> list[str]:
    """Return normalized configured collector names with no registered plane."""
    return list(_collector_configuration(settings)[1])


def collector_names(settings: Settings) -> list[str]:
    return list(_collector_configuration(settings)[0])


def _collector_configuration(settings: Settings) -> tuple[tuple[str, ...], tuple[str, ...]]:
    selected: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for name in settings.collectors or DEFAULT_COLLECTORS:
        key = str(name).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        (selected if key in COLLECTORS else unknown).append(key)
    return (tuple(selected) or DEFAULT_COLLECTORS, tuple(unknown))
