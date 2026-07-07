from __future__ import annotations

import logging
from typing import Any

from app.collectors.change import ChangeCollector
from app.collectors.kubernetes import KubernetesCollector
from app.collectors.loki import LokiCollector
from app.collectors.postgres import PostgresCollector
from app.collectors.prometheus import PrometheusCollector
from app.collectors.runai import RunAICollector
from app.collectors.system import SystemCollector
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
