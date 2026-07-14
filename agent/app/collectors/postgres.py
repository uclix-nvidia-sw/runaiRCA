from __future__ import annotations

import asyncio
import re
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
from app.collectors.loki import _llm_insight
from app.config import Settings
from app.mcp_client import (
    MCP_FALLBACK_WARNING,
    mcp_budget,
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
                async with mcp_budget(self._settings.postgres_timeout_seconds):
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
    incident_history = checks.get("incident_history", {})
    # An aggregate is only a count over the requested SQL range.  Do not let
    # it become a causal occurrence until the returned target rows themselves
    # prove an in-range timestamp and an allowlisted target identity.
    history_artifacts = _postgres_history_artifacts(target, incident_history)
    verified_history = [
        artifact_item
        for artifact_item in history_artifacts
        if isinstance(getattr(artifact_item, "result", None), dict)
        and isinstance(artifact_item.result.get("observation"), dict)
        and artifact_item.result["observation"].get("polarity") == "present"
        and artifact_item.result["observation"].get("coverage") == "scoped"
    ]
    history_rows = sum(
        _history_match_count(artifact_item.result.get("target_matching_rows"))
        for artifact_item in verified_history
    )
    history_match_tables = len(verified_history)
    history_unverified = any(
        isinstance(getattr(artifact_item, "result", None), dict)
        and isinstance(artifact_item.result.get("observation"), dict)
        and artifact_item.result["observation"].get("polarity") == "unknown"
        for artifact_item in history_artifacts
    )
    missing_tables = [name for name, exists in rca_tables.items() if not exists]
    status = "ok"
    if long_tx_count:
        status = "partial"
        warnings.append(f"{long_tx_count} long-running Postgres transaction(s) were found.")
    if check_rca_tables and missing_tables:
        status = "partial"
        warnings.append(f"Missing RCA table(s): {', '.join(missing_tables)}.")

    if database_kind == "runai_control_plane":
        history_summary = (
            f" incident 시간창 audit/history 레코드 {history_rows}건 "
            f"({history_match_tables}개 테이블)을 조회했습니다."
            if history_rows
            else (
                " incident 시간창 audit/history 응답 일부는 대상·시각을 검증할 수 없어 "
                "RCA 근거에서 제외했습니다."
                if history_unverified
                else " incident 시간창에 일치하는 audit/history 레코드는 없습니다."
            )
        )
        summary = ko_en(
            settings,
            "Run:ai 컨트롤플레인 Postgres 읽기 전용 점검: 연결 정상, "
            f"활성 연결 {checks['active_connections']}개.{history_summary}",
            "Run:ai control-plane Postgres read-only check: connectivity ok, "
            f"{checks['active_connections']} active connection(s)."
            + (
                f" Read {history_rows} audit/history record(s) from {history_match_tables} "
                "table(s) in the incident window."
                if history_rows
                else " No audit/history records matched the incident window."
                if not history_unverified
                else (
                    " Some incident-window audit/history responses could not be "
                    "verified for target identity and occurrence time, so they were "
                    "excluded from RCA evidence."
                )
            ),
        )
    else:
        summary = ko_en(
            settings,
            "RCA 저장소 자체 점검(장애 원인 아님): 연결 정상, "
            f"활성 연결 {checks['active_connections']}개, "
            f"pgvector {'설치됨' if pgvector else '미설치'}.",
            "RCA store self-check (not an incident cause): connectivity ok, "
            f"{checks['active_connections']} active connection(s), "
            f"pgvector={'installed' if pgvector else 'missing'}.",
        )
    # Owner rule: a PASSING healthcheck is NOT incident evidence. Lead with the
    # no-evidence marker (drops it from supporting evidence / signature matching)
    # and skip the LLM insight — only an actual DB finding earns evidence weight.
    # Audit/history rows are time-bounded incident observations. They are not a
    # health-check failure by themselves, but must not be discarded as a passing
    # current-state check or turned into a no-evidence marker.
    healthy = status == "ok" and not history_rows
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
                    "pg_extension vector check; to_regclass RCA table check; "
                    "incident-window audit/history scan"
                ),
                summary=summary,
                result={
                    **checks,
                    "used_mcp": used_mcp,
                    "database_kind": database_kind,
                    # Health-state aggregation is operational context. The
                    # table-specific historical artifacts below are the only
                    # Postgres records eligible to express incident predicates.
                    "observation": {
                        "kind": "postgres_collector_summary",
                        "predicate": "postgres_collector_summary",
                        "polarity": "unknown",
                        "coverage": "partial",
                    },
                },
            )
        ]
        + history_artifacts,
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
    incident_history = (
        await _collect_incident_history_direct(conn, target)
        if not check_rca_tables
        else _empty_incident_history(target)
    )
    return {
        "connected": True,
        "active_connections": int(active_connections or 0),
        "long_transactions": [_record_to_dict(record) for record in long_transactions],
        "pgvector_extension": bool(pgvector_extension),
        "rca_tables": {record["table_name"]: bool(record["exists"]) for record in table_rows},
        "visible_tables": [_record_to_dict(record) for record in visible_tables],
        "incident_history": incident_history,
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


_SQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HISTORY_TABLE_LIMIT = 6
_HISTORY_TIMESTAMP_TYPES = {"timestamp with time zone", "timestamp without time zone"}
_HISTORY_TIME_COLUMNS = (
    "occurred_at",
    "event_time",
    "created_at",
    "timestamp",
    "time",
    "updated_at",
)
_HISTORY_CONTEXT_COLUMNS = (
    "id",
    "action",
    "event_type",
    "event_name",
    "operation",
    "operation_type",
    "resource_type",
    "resource_id",
    "workload",
    "workload_name",
    "workload_id",
    "pod",
    "pod_name",
    "project",
    "project_name",
    "queue",
    "queue_name",
    "namespace",
    "status",
)
_HISTORY_IDENTITY_SCOPE_COLUMNS = (
    "resource_id",
    "workload_id",
    "workload_name",
    "workload",
    "pod_name",
    "pod",
    "namespace",
    "project_name",
    "project",
    "queue_name",
    "queue",
)


def _empty_incident_history(target: AnalysisTarget) -> dict[str, Any]:
    return {"time_range": incident_time_range(target), "tables": []}


def _history_column_discovery_sql() -> str:
    # Do not probe arbitrary application tables. Both the schema/table name and
    # timestamp type are constrained here; the result is later identifier-quoted
    # before it becomes a query. Context columns are a deliberately small allowlist
    # so audit payloads cannot expose token/password/blob fields as RCA evidence.
    context_columns = ", ".join(f"'{column}'" for column in _HISTORY_CONTEXT_COLUMNS)
    return f"""
        SELECT table_schema, table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
          AND (
            table_schema ILIKE '%audit%'
            OR table_schema ILIKE '%history%'
            OR table_name ILIKE '%audit%'
            OR table_name ILIKE '%history%'
          )
          AND (
            data_type IN ('timestamp with time zone', 'timestamp without time zone')
            OR column_name IN ({context_columns})
          )
        ORDER BY table_schema, table_name, ordinal_position
        LIMIT 160
    """


def _history_tables(column_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in column_rows:
        schema = str(row.get("table_schema") or "")
        table = str(row.get("table_name") or "")
        column = str(row.get("column_name") or "")
        data_type = str(row.get("data_type") or "").lower()
        if not all(_SQL_IDENTIFIER.fullmatch(value) for value in (schema, table, column)):
            continue
        entry = grouped.setdefault(
            (schema, table), {"schema": schema, "table": table, "timestamps": [], "context": []}
        )
        if data_type in _HISTORY_TIMESTAMP_TYPES:
            entry["timestamps"].append(column)
        elif column in _HISTORY_CONTEXT_COLUMNS:
            entry["context"].append(column)

    candidates: list[dict[str, Any]] = []
    for entry in grouped.values():
        timestamps = entry["timestamps"]
        if not timestamps:
            continue
        timestamp_column = next(
            (column for column in _HISTORY_TIME_COLUMNS if column in timestamps), timestamps[0]
        )
        discovered = set(entry["context"])
        # Keep correlation columns before generic audit display fields.  The
        # bounded projection otherwise commonly retained id/action/status and
        # silently dropped the pod/workload identity needed for safe evidence.
        context = list(
            dict.fromkeys(
                column
                for column in (*_HISTORY_IDENTITY_SCOPE_COLUMNS, *_HISTORY_CONTEXT_COLUMNS)
                if column in discovered
            )
        )
        candidates.append(
            {
                "schema": entry["schema"],
                "table": entry["table"],
                "timestamp_column": timestamp_column,
                "context_columns": context[:5],
            }
        )
    return candidates[:_HISTORY_TABLE_LIMIT]


def _quoted_identifier(value: str) -> str:
    if not _SQL_IDENTIFIER.fullmatch(value):
        raise ValueError("invalid Postgres identifier")
    return f'"{value}"'


def _history_query(table: dict[str, Any], *, mcp: bool, time_range: dict[str, str] | None) -> str:
    schema = _quoted_identifier(str(table["schema"]))
    name = _quoted_identifier(str(table["table"]))
    timestamp = _quoted_identifier(str(table["timestamp_column"]))
    if mcp:
        if not time_range:
            raise ValueError("incident time range is required for audit/history queries")
        start = f"'{time_range['start']}'::timestamptz"
        end = f"'{time_range['end']}'::timestamptz"
    else:
        start, end = "$1::timestamptz", "$2::timestamptz"
    columns = [f"{timestamp} AS event_time"]
    for column in table.get("context_columns", []):
        quoted = _quoted_identifier(str(column))
        columns.append(f"left(coalesce({quoted}::text, ''), 240) AS {quoted}")
    return f"""
        SELECT {', '.join(columns)}
        FROM {schema}.{name}
        WHERE {timestamp} >= {start}
          AND {timestamp} <= {end}
        ORDER BY {timestamp} DESC
        LIMIT 10
    """


def _history_aggregate_query(
    table: dict[str, Any], *, mcp: bool, time_range: dict[str, str] | None
) -> str:
    schema = _quoted_identifier(str(table["schema"]))
    name = _quoted_identifier(str(table["table"]))
    timestamp = _quoted_identifier(str(table["timestamp_column"]))
    if mcp:
        if not time_range:
            raise ValueError("incident time range is required for audit/history queries")
        start = f"'{time_range['start']}'::timestamptz"
        end = f"'{time_range['end']}'::timestamptz"
    else:
        start, end = "$1::timestamptz", "$2::timestamptz"
    return f"""
        SELECT count(*) AS matching_rows,
               min({timestamp}) AS first_event_at,
               max({timestamp}) AS last_event_at
        FROM {schema}.{name}
        WHERE {timestamp} >= {start}
          AND {timestamp} <= {end}
    """


def _history_target_clause(
    table: dict[str, Any], target: AnalysisTarget, *, mcp: bool
) -> tuple[str, list[list[str]]] | None:
    """Build an exact, allowlisted identity predicate for audit history.

    Sampling the newest audit rows and matching them in Python makes an older
    target event look absent whenever unrelated newer events fill the limit.
    Keep the predicate restricted to discovered context columns and bind every
    direct-DB value; MCP has no parameter channel, so encode its values as
    hexadecimal UTF-8 SQL expressions after constraining the column identifier.
    """
    expected = {
        "workload": (target.workload_name, target.runai_workload_id),
        "workload_name": (target.workload_name,),
        "workload_id": (target.runai_workload_id,),
        "pod": (target.pod,),
        "pod_name": (target.pod,),
        "project": (target.project,),
        "project_name": (target.project,),
        "queue": (target.queue,),
        "queue_name": (target.queue,),
        "namespace": (target.namespace,),
        "resource_id": (target.workload_name, target.runai_workload_id),
    }
    available = {str(column) for column in table.get("context_columns", [])}
    strong_columns = frozenset(
        {"workload", "workload_name", "workload_id", "pod", "pod_name", "resource_id"}
    )
    has_strong_alert_identity = any(
        str(value).strip()
        for column in strong_columns
        for value in expected[column]
    )
    # A workload/pod incident must not use a project/queue-only audit row as
    # proof: another workload in the same project is a common occurrence.
    # Project/queue correlation remains available when that is all the alert
    # itself identifies. ``id`` is intentionally excluded because generic
    # audit primary keys are not workload identities.
    allowed_columns = strong_columns if has_strong_alert_identity else _HISTORY_TARGET_COLUMNS
    identity_predicates: list[str] = []
    scope_predicates: list[str] = []
    parameters: list[list[str]] = []
    parameter_number = 3
    for column in _HISTORY_TARGET_COLUMNS:
        if column not in allowed_columns:
            continue
        values = sorted(
            {str(value).strip().casefold() for value in expected[column] if str(value).strip()}
        )
        if column not in available or not values:
            continue
        quoted = _quoted_identifier(column)
        normalized = f"lower(coalesce({quoted}::text, ''))"
        if mcp:
            expressions = ", ".join(_sql_text_expression(value) for value in values)
            identity_predicates.append(f"{normalized} IN ({expressions})")
        else:
            identity_predicates.append(f"{normalized} = ANY(${parameter_number}::text[])")
            parameters.append(values)
            parameter_number += 1
    if not identity_predicates:
        return None
    # A concrete pod/workload name is not globally unique. When an audit table
    # records namespace/project/queue too, require every declared scope that is
    # available in that table instead of treating it as an alternate identity.
    scope_columns = ("namespace", "project", "project_name", "queue", "queue_name")
    for column in scope_columns if has_strong_alert_identity else ():
        values = sorted(
            {str(value).strip().casefold() for value in expected[column] if str(value).strip()}
        )
        if column not in available or not values:
            continue
        quoted = _quoted_identifier(column)
        normalized = f"lower(coalesce({quoted}::text, ''))"
        if mcp:
            expressions = ", ".join(_sql_text_expression(value) for value in values)
            scope_predicates.append(f"{normalized} IN ({expressions})")
        else:
            scope_predicates.append(f"{normalized} = ANY(${parameter_number}::text[])")
            parameters.append(values)
            parameter_number += 1
    return " AND (" + " OR ".join(identity_predicates) + ")" + "".join(
        f" AND {predicate}" for predicate in scope_predicates
    ), parameters


def _sql_text_expression(value: str) -> str:
    """Return a non-interpolating SQL text expression for MCP-only queries."""
    encoded = value.encode("utf-8").hex()
    return f"convert_from(decode('{encoded}', 'hex'), 'UTF8')"


def _history_target_query(
    table: dict[str, Any],
    target: AnalysisTarget,
    *,
    mcp: bool,
    time_range: dict[str, str] | None,
) -> tuple[str, list[list[str]]] | None:
    clause = _history_target_clause(table, target, mcp=mcp)
    if clause is None:
        return None
    target_clause, parameters = clause
    schema = _quoted_identifier(str(table["schema"]))
    name = _quoted_identifier(str(table["table"]))
    timestamp = _quoted_identifier(str(table["timestamp_column"]))
    if mcp:
        if not time_range:
            raise ValueError("incident time range is required for audit/history queries")
        start = f"'{time_range['start']}'::timestamptz"
        end = f"'{time_range['end']}'::timestamptz"
    else:
        start, end = "$1::timestamptz", "$2::timestamptz"
    columns = [f"{timestamp} AS event_time"]
    for column in table.get("context_columns", []):
        quoted = _quoted_identifier(str(column))
        columns.append(f"left(coalesce({quoted}::text, ''), 240) AS {quoted}")
    return (
        f"""
        SELECT {', '.join(columns)}
        FROM {schema}.{name}
        WHERE {timestamp} >= {start}
          AND {timestamp} <= {end}{target_clause}
        ORDER BY {timestamp} DESC
        LIMIT 10
        """,
        parameters,
    )


def _history_target_aggregate_query(
    table: dict[str, Any],
    target: AnalysisTarget,
    *,
    mcp: bool,
    time_range: dict[str, str] | None,
) -> tuple[str, list[list[str]]] | None:
    clause = _history_target_clause(table, target, mcp=mcp)
    if clause is None:
        return None
    target_clause, parameters = clause
    schema = _quoted_identifier(str(table["schema"]))
    name = _quoted_identifier(str(table["table"]))
    timestamp = _quoted_identifier(str(table["timestamp_column"]))
    if mcp:
        if not time_range:
            raise ValueError("incident time range is required for audit/history queries")
        start = f"'{time_range['start']}'::timestamptz"
        end = f"'{time_range['end']}'::timestamptz"
    else:
        start, end = "$1::timestamptz", "$2::timestamptz"
    return (
        f"""
        SELECT count(*) AS matching_rows,
               min({timestamp}) AS first_event_at,
               max({timestamp}) AS last_event_at
        FROM {schema}.{name}
        WHERE {timestamp} >= {start}
          AND {timestamp} <= {end}{target_clause}
        """,
        parameters,
    )


def _verified_target_aggregate(
    aggregate: object, time_range: dict[str, str] | None
) -> tuple[int, bool]:
    """Decode a target aggregate without converting malformed data to absence."""
    if not isinstance(aggregate, dict) or not time_range:
        return 0, False
    count = _parse_history_match_count(aggregate.get("matching_rows"))
    if count is None:
        return 0, False
    if count == 0:
        return 0, True
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    first = parse_incident_time(aggregate.get("first_event_at"))
    last = parse_incident_time(aggregate.get("last_event_at"))
    if None in (start, end, first, last):
        return count, False
    assert start is not None and end is not None and first is not None and last is not None
    return count, start <= first <= last <= end


async def _collect_incident_history_direct(conn: Any, target: AnalysisTarget) -> dict[str, Any]:
    history = _empty_incident_history(target)
    time_range = history["time_range"]
    if not time_range:
        return history
    columns = await conn.fetch(_history_column_discovery_sql())
    tables: list[dict[str, Any]] = []
    for table in _history_tables([_record_to_dict(row) for row in columns]):
        aggregate_rows = await conn.fetch(
            _history_aggregate_query(table, mcp=False, time_range=time_range),
            time_range["start"],
            time_range["end"],
        )
        aggregate = _record_to_dict(aggregate_rows[0]) if aggregate_rows else {}
        rows = await conn.fetch(
            _history_query(table, mcp=False, time_range=time_range),
            time_range["start"],
            time_range["end"],
        )
        row_dicts = [_record_to_dict(row) for row in rows]
        target_aggregate_query = _history_target_aggregate_query(
            table, target, mcp=False, time_range=time_range
        )
        target_query = _history_target_query(table, target, mcp=False, time_range=time_range)
        target_aggregate: dict[str, Any] = {}
        target_rows: list[dict[str, Any]] = []
        if target_aggregate_query is not None and target_query is not None:
            query, parameters = target_aggregate_query
            aggregate_rows = await conn.fetch(
                query, time_range["start"], time_range["end"], *parameters
            )
            target_aggregate = _record_to_dict(aggregate_rows[0]) if aggregate_rows else {}
            query, parameters = target_query
            target_rows = [
                _record_to_dict(row)
                for row in await conn.fetch(query, time_range["start"], time_range["end"], *parameters)
            ]
        target_matches, target_verified = _verified_target_aggregate(target_aggregate, time_range)
        tables.append(
            {
                **table,
                "matching_rows": int(aggregate.get("matching_rows") or 0),
                "first_event_at": aggregate.get("first_event_at"),
                "last_event_at": aggregate.get("last_event_at"),
                "rows": row_dicts,
                "target_correlation_available": target_aggregate_query is not None,
                "target_matching_rows": target_matches,
                "target_aggregate_verified": target_verified,
                "target_first_event_at": target_aggregate.get("first_event_at"),
                "target_last_event_at": target_aggregate.get("last_event_at"),
                "target_rows": target_rows,
                "target_rows_truncated": target_verified and target_matches > len(target_rows),
            }
        )
    history["tables"] = tables
    return history


async def _collect_incident_history_mcp(
    settings: Settings, target: AnalysisTarget
) -> dict[str, Any]:
    history = _empty_incident_history(target)
    time_range = history["time_range"]
    if not time_range:
        return history
    columns = await _mcp_fetch(settings, _history_column_discovery_sql())
    tables: list[dict[str, Any]] = []
    for table in _history_tables(columns):
        aggregate_rows = await _mcp_fetch(
            settings, _history_aggregate_query(table, mcp=True, time_range=time_range)
        )
        aggregate = aggregate_rows[0] if aggregate_rows else {}
        rows = await _mcp_fetch(settings, _history_query(table, mcp=True, time_range=time_range))
        target_aggregate_query = _history_target_aggregate_query(
            table, target, mcp=True, time_range=time_range
        )
        target_query = _history_target_query(table, target, mcp=True, time_range=time_range)
        target_aggregate: dict[str, Any] = {}
        target_rows: list[dict[str, Any]] = []
        if target_aggregate_query is not None and target_query is not None:
            query, _ = target_aggregate_query
            aggregate_rows = await _mcp_fetch(settings, query)
            target_aggregate = aggregate_rows[0] if aggregate_rows else {}
            query, _ = target_query
            target_rows = await _mcp_fetch(settings, query)
        target_matches, target_verified = _verified_target_aggregate(target_aggregate, time_range)
        tables.append(
            {
                **table,
                "matching_rows": int(aggregate.get("matching_rows") or 0),
                "first_event_at": aggregate.get("first_event_at"),
                "last_event_at": aggregate.get("last_event_at"),
                "rows": rows,
                "target_correlation_available": target_aggregate_query is not None,
                "target_matching_rows": target_matches,
                "target_aggregate_verified": target_verified,
                "target_first_event_at": target_aggregate.get("first_event_at"),
                "target_last_event_at": target_aggregate.get("last_event_at"),
                "target_rows": target_rows,
                "target_rows_truncated": target_verified and target_matches > len(target_rows),
            }
        )
    history["tables"] = tables
    return history


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
    incident_history = (
        await _collect_incident_history_mcp(settings, target)
        if not check_rca_tables
        else _empty_incident_history(target)
    )
    return {
        "connected": True,
        "active_connections": int(active_connections or 0),
        "long_transactions": long_transactions,
        "pgvector_extension": bool(pgvector_extension),
        "rca_tables": {row.get("table_name"): bool(row.get("exists")) for row in table_rows},
        "visible_tables": visible_tables,
        "incident_history": incident_history,
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
    rows = _mcp_postgres_rows(data)
    if rows is None:
        raise RuntimeError("Postgres MCP response missing a recognized row result")
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


def _mcp_postgres_rows(data: Any) -> list[Any] | None:
    """Return a recognized SQL-row envelope, or None for malformed success.

    A successful MCP transport can still contain an empty object or an
    unrelated gateway payload. Treating that as an empty SELECT makes database
    health checks look successful without a verifiable database read.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rows", "result", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


_HISTORY_TARGET_COLUMNS = frozenset(
    {
        "workload",
        "workload_name",
        "workload_id",
        "pod",
        "pod_name",
        "project",
        "project_name",
        "queue",
        "queue_name",
        "resource_id",
    }
)


def _postgres_history_artifacts(
    target: AnalysisTarget, incident_history: object
) -> list[Any]:
    """Expose target-correlated audit tables as bounded, independent facts."""
    history = incident_history if isinstance(incident_history, dict) else {}
    time_range = history.get("time_range") if isinstance(history.get("time_range"), dict) else None
    artifacts = []
    for table in history.get("tables", []):
        if not isinstance(table, dict):
            continue
        schema = str(table.get("schema") or "audit")
        name = str(table.get("table") or "history")
        matches = _history_match_count(table.get("target_matching_rows"))
        count_verified = _history_match_count_is_valid(table.get("target_matching_rows"))
        correlated = bool(table.get("target_correlation_available"))
        aggregate_verified = bool(table.get("target_aggregate_verified"))
        rows_verified, evidence_window, observed_entity = _verified_target_history_rows(
            table, target, time_range, matches
        )
        if (
            not time_range
            or not correlated
            or not aggregate_verified
            or not count_verified
            or not rows_verified
        ):
            polarity, coverage = "unknown", "partial"
        elif matches:
            polarity, coverage = "present", "scoped"
        else:
            polarity, coverage = "absent", "scoped"
        if polarity == "present":
            summary = (
                f"Postgres {schema}.{name}: {matches} target-correlated audit row(s) "
                "in incident window."
            )
        elif polarity == "absent":
            summary = (
                f"{NO_EVIDENCE} Postgres {schema}.{name}: no target-correlated audit rows "
                "in incident window."
            )
        else:
            summary = (
                f"Postgres {schema}.{name}: audit rows could not be correlated "
                "to the incident target."
            )
        artifacts.append(
            artifact(
                agent="postgres",
                source="postgres",
                type="postgres_incident_history",
                status="ok",
                confidence="high" if polarity in {"present", "absent"} else "low",
                title=f"Postgres · {schema}.{name}",
                query=f"incident-window audit/history {schema}.{name}",
                summary=summary,
                result={
                    "observation": {
                        "kind": "postgres_incident_history",
                        "predicate": f"postgres_history:{schema}.{name}",
                        "polarity": polarity,
                        "coverage": coverage,
                        "observation_window": time_range or {},
                        **({"evidence_window": evidence_window} if evidence_window else {}),
                        **({"observed_entity": observed_entity} if observed_entity else {}),
                    },
                    "target_matching_rows": matches,
                    "target_rows": table.get("target_rows") or [],
                    "target_rows_truncated": bool(table.get("target_rows_truncated")),
                    "time_range": time_range,
                },
            )
        )
    return artifacts


def _history_match_count(value: object) -> int:
    """Decode an aggregate count without treating malformed data as evidence."""
    return _parse_history_match_count(value) or 0


def _history_match_count_is_valid(value: object) -> bool:
    """Require an explicit non-negative aggregate count before inferring absence."""
    return _parse_history_match_count(value) is not None


def _parse_history_match_count(value: object) -> int | None:
    """Accept only the integer count shape emitted by a SQL ``count(*)`` query."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        normalized = value.strip()
        if re.fullmatch(r"[0-9]+", normalized):
            return int(normalized)
    return None


def _verified_target_history_rows(
    table: dict[str, Any],
    target: AnalysisTarget,
    time_range: dict[str, str] | None,
    matches: int,
) -> tuple[bool, dict[str, str] | None, dict[str, str] | None]:
    """Verify sampled audit rows before an aggregate may support an RCA claim.

    The aggregate query is useful to find tables efficiently, but a malformed
    MCP response (or a schema whose selected identity was lost) must not be
    promoted merely because it says ``matching_rows > 0``.  Every sampled row
    must carry a timezone-aware in-window event time and an identity that
    matches the exact allowlisted predicate used for the query.  Aggregate
    absence remains valid: there is intentionally no row to sample when count
    is zero.
    """
    if not isinstance(time_range, dict):
        return False, None, None
    start = parse_incident_time(time_range.get("start"))
    end = parse_incident_time(time_range.get("end"))
    if start is None or end is None or end < start:
        return False, None, None
    if matches == 0:
        return True, None, _target_history_entity(target)
    rows = table.get("target_rows")
    if not isinstance(rows, list) or not rows:
        return False, None, None
    instants = []
    entities: list[dict[str, str]] = []
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            return False, None, None
        instant = parse_incident_time(raw_row.get("event_time"))
        entity = _target_history_row_entity(raw_row, table, target)
        if instant is None or not (start <= instant <= end) or entity is None:
            return False, None, None
        instants.append(instant)
        entities.append(entity)
    first, last = min(instants), max(instants)
    # A target query can legitimately match by workload in one row and pod in
    # another. Pick the most specific identity seen, while retaining the fact
    # that it was observed in an actual returned row rather than inferred from
    # the aggregate or broad namespace query.
    observed_entity = next(
        (entity for entity in entities if entity["kind"] in {"pod", "runai_workload_id"}),
        entities[0],
    )
    return (
        True,
        {
            "start": first.isoformat().replace("+00:00", "Z"),
            "end": last.isoformat().replace("+00:00", "Z"),
        },
        observed_entity,
    )


def _target_history_row_entity(
    row: dict[str, Any], table: dict[str, Any], target: AnalysisTarget
) -> dict[str, str] | None:
    """Return a row-proven target identity, never a fallback target label."""
    expected = {
        "workload": (target.workload_name, target.runai_workload_id),
        "workload_name": (target.workload_name,),
        "workload_id": (target.runai_workload_id,),
        "pod": (target.pod,),
        "pod_name": (target.pod,),
        "project": (target.project,),
        "project_name": (target.project,),
        "queue": (target.queue,),
        "queue_name": (target.queue,),
        "namespace": (target.namespace,),
        "resource_id": (target.workload_name, target.runai_workload_id),
    }
    strong_columns = {"workload", "workload_name", "workload_id", "pod", "pod_name", "resource_id"}
    has_strong_target = any(
        str(value).strip() for column in strong_columns for value in expected[column]
    )
    available = {str(column) for column in table.get("context_columns", [])}
    allowed = strong_columns if has_strong_target else set(_HISTORY_TARGET_COLUMNS)
    entity_fields = {
        "workload": "workload_name",
        "workload_name": "workload_name",
        "workload_id": "runai_workload_id",
        "pod": "pod",
        "pod_name": "pod",
        "project": "project",
        "project_name": "project",
        "queue": "queue",
        "queue_name": "queue",
        "namespace": "namespace",
    }
    match: tuple[str, str] | None = None
    for column in _HISTORY_TARGET_COLUMNS:
        if column not in allowed or column not in available:
            continue
        value = str(row.get(column) or "").strip()
        values = {str(item).strip().casefold() for item in expected[column] if str(item).strip()}
        if value and value.casefold() in values:
            if column == "resource_id":
                kind = "runai_workload_id" if value == str(target.runai_workload_id) else "workload_name"
            else:
                kind = entity_fields[column]
            match = (kind, value)
            break
    if match is None:
        return None
    # When scope columns were available to the SQL predicate, a returned row
    # must retain the same concrete values.  Missing or contradictory scope is
    # not silently repaired from the alert target.
    for column in ("namespace", "project", "project_name", "queue", "queue_name"):
        if column not in available:
            continue
        expected_values = {str(item).strip().casefold() for item in expected[column] if str(item).strip()}
        if not expected_values:
            continue
        value = str(row.get(column) or "").strip().casefold()
        if value not in expected_values:
            return None
    return {"kind": match[0], "name": match[1]}


def _target_history_entity(target: AnalysisTarget) -> dict[str, str] | None:
    for field, kind in (
        ("pod", "pod"),
        ("runai_workload_id", "runai_workload_id"),
        ("workload_name", "workload_name"),
        ("project", "project"),
        ("queue", "queue"),
        ("namespace", "namespace"),
    ):
        value = str(getattr(target, field, "") or "").strip()
        if value:
            return {"kind": kind, "name": value}
    return None
