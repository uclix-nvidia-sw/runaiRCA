from __future__ import annotations

import pytest

from app.collectors.base import AnalysisTarget
from app.collectors.postgres import _collect_postgres_checks


class FakePostgresConnection:
    def __init__(self) -> None:
        self.table_check_query = ""

    async def fetchval(self, query: str) -> int | bool:
        if "pg_extension" in query:
            return True
        if "pg_stat_activity" in query:
            return 2
        return 1

    async def fetch(self, query: str) -> list[dict[str, object]]:
        if "unnest" not in query:
            return []
        self.table_check_query = query
        return [
            {"table_name": "incidents", "exists": True},
            {"table_name": "alerts", "exists": True},
            {"table_name": "incident_embeddings", "exists": True},
            {"table_name": "rca_feedback", "exists": True},
            {"table_name": "analysis_runs", "exists": True},
        ]


@pytest.mark.asyncio
async def test_postgres_checks_include_all_backend_rca_tables() -> None:
    conn = FakePostgresConnection()

    checks = await _collect_postgres_checks(
        conn,
        AnalysisTarget(
            cluster="",
            project="",
            queue="",
            namespace="runai",
            workload_name="trainer",
            workload_type="",
            runai_workload_id="",
            node="",
            pod="",
            severity="warning",
            alert_name="RunAIAlert",
        ),
    )

    assert set(checks["rca_tables"]) == {
        "incidents",
        "alerts",
        "incident_embeddings",
        "rca_feedback",
        "analysis_runs",
    }
    assert "'analysis_runs'" in conn.table_check_query
