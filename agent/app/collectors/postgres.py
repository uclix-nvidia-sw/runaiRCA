from __future__ import annotations

import asyncio
from typing import Any

from app.collectors.base import NO_EVIDENCE, AnalysisTarget, CollectorResult, artifact
from app.collectors.loki import _llm_insight
from app.config import Settings
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_call,
    mcp_error,
    mcp_fallback_warning,
    mcp_tool_json,
)


class PostgresCollector:
    name = "postgres"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def collect(self, target: AnalysisTarget, plan=None) -> CollectorResult:
        direct_dsn = _postgres_direct_dsn(self._settings)
        database_kind = "runai_control_plane" if self._settings.runai_db_dsn else "rca_store"
        check_rca_tables = database_kind == "rca_store"
        if not direct_dsn and not self._settings.postgres_mcp_url:
            summary = (
                f"{NO_EVIDENCE} Postgres MCP URL and DSN are not configured; database "
                "evidence was skipped."
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
                        result={
                            "postgres_dsn_configured": False,
                            "postgres_mcp_url_configured": False,
                        },
                    )
                ],
            )

        warnings: list[str] = []
        used_mcp = False
        if self._settings.postgres_mcp_url:
            try:
                checks = await _collect_postgres_checks_mcp(
                    self._settings, target, check_rca_tables=check_rca_tables
                )
                used_mcp = True
            except Exception as exc:  # noqa: BLE001 - fallback is the behavior.
                warnings.append(mcp_fallback_warning(exc))
        else:
            warnings.append(f"{MCP_FALLBACK_WARNING}: POSTGRES_MCP_URL not configured")

        if used_mcp:
            return await _postgres_result(
                self._settings,
                target,
                checks=checks,
                warnings=warnings,
                used_mcp=True,
                database_kind=database_kind,
                check_rca_tables=check_rca_tables,
            )

        if not direct_dsn:
            summary = f"{NO_EVIDENCE} Postgres MCP failed and direct DSN is not configured."
            return CollectorResult(
                agent=self.name,
                status="unavailable",
                summary=summary,
                confidence="low",
                missing_data=["postgres.dsn"],
                warnings=warnings,
                artifacts=[
                    artifact(
                        agent=self.name,
                        source="postgres",
                        type="database_health",
                        status="unavailable",
                        confidence="low",
                        summary=summary,
                        result={"postgres_mcp_url_configured": True},
                    )
                ],
            )

        try:
            import asyncpg
        except ImportError:
            summary = (
                f"{NO_EVIDENCE} asyncpg is not installed, so Postgres diagnostics "
                "could not run."
            )
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
                        result={
                            "postgres_dsn_configured": bool(direct_dsn),
                            "asyncpg_installed": False,
                        },
                    )
                ],
            )

        timeout = self._settings.postgres_timeout_seconds
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(direct_dsn, timeout=timeout),
                timeout=timeout + 1,
            )
        except Exception as exc:  # noqa: BLE001 - collector reports diagnostics, not failures.
            summary = f"{NO_EVIDENCE} Postgres connection failed: {exc.__class__.__name__}."
            return CollectorResult(
                agent=self.name,
                status="partial",
                summary=summary,
                confidence="medium",
                warnings=warnings + [summary],
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
            checks = await _collect_postgres_checks(
                conn, target, check_rca_tables=check_rca_tables
            )
        finally:
            await conn.close()

        return await _postgres_result(
            self._settings,
            target,
            checks=checks,
            warnings=warnings,
            used_mcp=False,
            database_kind=database_kind,
            check_rca_tables=check_rca_tables,
        )


async def _postgres_result(
    settings: Settings,
    target: AnalysisTarget,
    *,
    checks: dict[str, Any],
    warnings: list[str],
    used_mcp: bool,
    database_kind: str,
    check_rca_tables: bool,
) -> CollectorResult:
    long_tx_count = len(checks["long_transactions"])
    pgvector = checks["pgvector_extension"]
    rca_tables = checks["rca_tables"]
    missing_tables = [name for name, exists in rca_tables.items() if not exists]
    status = "ok"
    if long_tx_count:
        status = "partial"
        warnings.append(f"{long_tx_count} long-running Postgres transaction(s) were found.")
    if check_rca_tables and missing_tables:
        status = "partial"
        warnings.append(f"Missing RCA table(s): {', '.join(missing_tables)}.")

    if database_kind == "runai_control_plane":
        summary = (
            "Run:ai control-plane Postgres read-only check: connectivity ok, "
            f"{checks['active_connections']} active connection(s)."
        )
    else:
        summary = (
            "RCA store self-check (not an incident cause): connectivity ok, "
            f"{checks['active_connections']} active connection(s), "
            f"pgvector={'installed' if pgvector else 'missing'}."
        )
    # Owner rule: a PASSING healthcheck is NOT incident evidence. Lead with the
    # no-evidence marker (drops it from supporting evidence / signature matching)
    # and skip the LLM insight — only an actual DB finding earns evidence weight.
    healthy = status == "ok"
    confidence = "medium"
    if healthy:
        summary = f"{NO_EVIDENCE} {summary}"
        confidence = "low"
    else:
        insight = await _llm_insight(settings, "Postgres diagnostics", summary, checks)
        if insight:
            summary = insight
    return CollectorResult(
        agent="postgres",
        status=status,
        summary=summary,
        confidence=confidence,
        details={**checks, "used_mcp": used_mcp, "database_kind": database_kind},
        warnings=warnings,
        artifacts=[
            artifact(
                agent="postgres",
                source="postgres",
                type="database_health",
                status=status,
                confidence=confidence,
                query=(
                    "SELECT 1; pg_stat_activity long transaction scan; "
                    "pg_extension vector check; to_regclass RCA table check"
                ),
                summary=summary,
                result={**checks, "used_mcp": used_mcp, "database_kind": database_kind},
            )
        ],
    )


async def _collect_postgres_checks(
    conn: Any, target: AnalysisTarget, *, check_rca_tables: bool = True
) -> dict[str, Any]:
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
    table_rows = []
    visible_tables = []
    if check_rca_tables:
        table_rows = await conn.fetch(
            """
            SELECT table_name, to_regclass('public.' || table_name)::text IS NOT NULL AS exists
            FROM unnest(ARRAY[
              'incidents',
              'alerts',
              'incident_embeddings',
              'rca_feedback',
              'rca_comments',
              'analysis_runs'
            ])
              AS table_name
            """
        )
    else:
        visible_tables = await conn.fetch(
            """
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name
            LIMIT 20
            """
        )
    return {
        "connected": True,
        "active_connections": int(active_connections or 0),
        "long_transactions": [_record_to_dict(record) for record in long_transactions],
        "pgvector_extension": bool(pgvector_extension),
        "rca_tables": {record["table_name"]: bool(record["exists"]) for record in table_rows},
        "visible_tables": [_record_to_dict(record) for record in visible_tables],
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


def _postgres_direct_dsn(settings: Settings) -> str:
    return settings.runai_db_dsn or settings.postgres_dsn


async def _collect_postgres_checks_mcp(
    settings: Settings, target: AnalysisTarget, *, check_rca_tables: bool = True
) -> dict[str, Any]:
    await _mcp_fetchval(settings, "SELECT 1 AS ok")
    active_connections = await _mcp_fetchval(
        settings,
        """
        SELECT count(*) AS active_connections
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND state <> 'idle'
        """,
    )
    long_transactions = await _mcp_fetch(
        settings,
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
        """,
    )
    pgvector_extension = await _mcp_fetchval(
        settings, "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') AS exists"
    )
    table_rows: list[dict[str, Any]] = []
    visible_tables: list[dict[str, Any]] = []
    if check_rca_tables:
        table_rows = await _mcp_fetch(
            settings,
            """
            SELECT table_name, to_regclass('public.' || table_name)::text IS NOT NULL AS exists
            FROM unnest(ARRAY[
              'incidents',
              'alerts',
              'incident_embeddings',
              'rca_feedback',
              'rca_comments',
              'analysis_runs'
            ])
              AS table_name
            """,
        )
    else:
        visible_tables = await _mcp_fetch(
            settings,
            """
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name
            LIMIT 20
            """,
        )
    return {
        "connected": True,
        "active_connections": int(active_connections or 0),
        "long_transactions": long_transactions,
        "pgvector_extension": bool(pgvector_extension),
        "rca_tables": {row.get("table_name"): bool(row.get("exists")) for row in table_rows},
        "visible_tables": visible_tables,
        "correlation_hint": {
            "cluster": target.cluster,
            "project": target.project,
            "queue": target.queue,
            "namespace": target.namespace,
            "workload_name": target.workload_name,
        },
    }


async def _mcp_fetch(settings: Settings, sql: str) -> list[dict[str, Any]]:
    result = await mcp_call(settings.postgres_mcp_url, "query", {"sql": " ".join(sql.split())})
    error = mcp_error(result)
    if error:
        raise RuntimeError(error)
    data = mcp_tool_json(result)
    if isinstance(data, dict) and "raw" in data:
        raise RuntimeError("MCP result was not JSON")
    rows = _postgres_rows(data)
    return [row for row in rows if isinstance(row, dict)]


async def _mcp_fetchval(settings: Settings, sql: str) -> Any:
    rows = await _mcp_fetch(settings, sql)
    if not rows:
        return None
    first = rows[0]
    return next(iter(first.values()), None)


def _postgres_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rows", "result", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        if all(not isinstance(value, (list, dict)) for value in data.values()):
            return [data]
    return []
