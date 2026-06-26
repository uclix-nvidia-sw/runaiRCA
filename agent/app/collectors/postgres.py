from __future__ import annotations

import asyncio
from typing import Any

from app.collectors.base import AnalysisTarget, CollectorResult, artifact
from app.config import Settings


class PostgresCollector:
    name = "postgres"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget) -> CollectorResult:
        if not self._settings.postgres_dsn:
            summary = (
                "Postgres DSN is not configured; database health, incident-store, "
                "and pgvector evidence were skipped."
            )
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["postgres.dsn"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="postgres",
                        type="database_health",
                        status="unavailable",
                        confidence="low",
                        query=None,
                        summary=summary,
                        result={"postgres_dsn_configured": False},
                    )
                ],
            )

        try:
            import asyncpg
        except ImportError:
            summary = "asyncpg is not installed, so Postgres diagnostics could not run."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["python.asyncpg"],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="postgres",
                        type="database_health",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"postgres_dsn_configured": True, "asyncpg_installed": False},
                    )
                ],
            )

        timeout = self._settings.postgres_timeout_seconds
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(self._settings.postgres_dsn, timeout=timeout),
                timeout=timeout + 1,
            )
        except Exception as exc:  # noqa: BLE001 - collector reports diagnostics, not failures.
            summary = f"Postgres connection failed: {exc.__class__.__name__}."
            return CollectorResult(
                agent=self.name,
                status="partial",
                summary=summary,
                confidence="medium",
                warnings=[summary],
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="postgres",
                        type="database_connectivity",
                        status="partial",
                        confidence="medium",
                        query="SELECT 1",
                        summary=summary,
                        result={
                            "postgres_dsn_configured": True,
                            "connected": False,
                            "error_type": exc.__class__.__name__,
                        },
                    )
                ],
            )

        try:
            checks = await _collect_postgres_checks(conn, target)
        finally:
            await conn.close()

        long_tx_count = len(checks["long_transactions"])
        pgvector = checks["pgvector_extension"]
        rca_tables = checks["rca_tables"]
        missing_tables = [name for name, exists in rca_tables.items() if not exists]
        status = "ok"
        warnings: list[str] = []
        if long_tx_count:
            status = "partial"
            warnings.append(f"{long_tx_count} long-running Postgres transaction(s) were found.")
        if missing_tables:
            status = "partial"
            warnings.append(f"Missing RCA table(s): {', '.join(missing_tables)}.")

        summary = (
            "Postgres diagnostics completed: connectivity ok, "
            f"{checks['active_connections']} active connection(s), "
            f"pgvector={'installed' if pgvector else 'missing'}."
        )
        return CollectorResult(
            agent=self.name,
            status=status,
            summary=summary,
            confidence="medium",
            details=checks,
            warnings=warnings,
            artifacts=[
                artifact(
                    agent=self.name,
                    source="postgres",
                    type="database_health",
                    status=status,
                    confidence="medium",
                    query=(
                        "SELECT 1; pg_stat_activity long transaction scan; "
                        "pg_extension vector check; to_regclass RCA table check"
                    ),
                    summary=summary,
                    result=checks,
                )
            ],
        )


async def _collect_postgres_checks(conn: Any, target: AnalysisTarget) -> dict[str, Any]:
    await conn.fetchval("SELECT 1")
    active_connections = await conn.fetchval(
        """
        SELECT count(*)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND state <> 'idle'
        """
    )
    long_transactions = await conn.fetch(
        """
        SELECT
          pid,
          usename,
          state,
          wait_event_type,
          wait_event,
          (now() - xact_start)::text AS xact_age,
          left(coalesce(query, ''), 240) AS query
        FROM pg_stat_activity
        WHERE xact_start IS NOT NULL
          AND state <> 'idle'
          AND now() - xact_start > interval '5 minutes'
        ORDER BY xact_start ASC
        LIMIT 5
        """
    )
    pgvector_extension = await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')"
    )
    table_rows = await conn.fetch(
        """
        SELECT table_name, to_regclass('public.' || table_name)::text IS NOT NULL AS exists
        FROM unnest(ARRAY[
          'incidents',
          'alerts',
          'incident_embeddings',
          'rca_feedback',
          'rca_comments'
        ])
          AS table_name
        """
    )
    return {
        "connected": True,
        "active_connections": int(active_connections or 0),
        "long_transactions": [_record_to_dict(record) for record in long_transactions],
        "pgvector_extension": bool(pgvector_extension),
        "rca_tables": {record["table_name"]: bool(record["exists"]) for record in table_rows},
        "correlation_hint": {
            "cluster": target.cluster,
            "project": target.project,
            "queue": target.queue,
            "namespace": target.namespace,
            "workload_name": target.workload_name,
        },
    }


def _record_to_dict(record: Any) -> dict[str, Any]:
    return {key: record[key] for key in record.keys()}
