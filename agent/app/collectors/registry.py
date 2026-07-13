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
    names = settings.collectors or DEFAULT_COLLECTORS
    selected: list[Any] = []
    seen: set[str] = set()
    unknown: list[str] = []

    for name in names:
        key = str(name).strip().lower()
        if not key or key in seen:
            continue
        cls = COLLECTORS.get(key)
        if cls is None:
            unknown.append(key)
            continue
        seen.add(key)
        selected.append(cls(settings))

    if unknown:
        _log.warning("ignoring unknown collectors from COLLECTORS: %s", ", ".join(unknown))
    if selected:
        return selected

    _log.warning("COLLECTORS produced no valid collectors; falling back to default set")
    return [COLLECTORS[name](settings) for name in DEFAULT_COLLECTORS]
