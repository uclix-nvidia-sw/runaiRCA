"""Shared test isolation.

The Grafana datasource UID cache is module-level process state with a 300s
success TTL, so whether a test sees a resolved UID depends on what ran before it
in the same process. That is invisible serially — the tests that populate it
happen to run first — and shows up under ``pytest -n auto`` (CI's invocation) as
two failures in test_datasource_mcp_collectors, because xdist may put the
populating test on a different worker.

Clearing it per test makes each one state-independent instead of ordering-lucky.
"""

from __future__ import annotations

import pytest

from app.collectors.grafana_mcp import clear_grafana_datasource_cache


@pytest.fixture(autouse=True)
def _isolate_grafana_datasource_cache() -> None:
    clear_grafana_datasource_cache()
