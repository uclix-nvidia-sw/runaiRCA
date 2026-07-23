"""Idempotently project approved reasoning_trace_v3 records into TypeDB.

This deliberately reuses the normal incident writer only for approved incidents,
then lets its strict v3 branch create hypothesis/probe edges. It does not turn
trace-less or pre-v3 artifacts into trace-v3 facts.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from app.config import load_settings
from ontology.ingest import _fetch_trace_v3_page, _to_incident, _write


_CURSOR_TABLE = """
CREATE TABLE IF NOT EXISTS ontology_backfill_cursors (
    cursor_name TEXT PRIMARY KEY,
    approved_at TEXT NOT NULL DEFAULT '',
    case_id TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


async def _load_database_cursor(name: str) -> tuple[str, str]:
    """Read a durable cursor; absence is the initial keyset position."""
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        raise RuntimeError("POSTGRES_DSN is required for the durable trace-v3 cursor")
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        await conn.execute(_CURSOR_TABLE)
        row = await conn.fetchrow(
            "SELECT approved_at, case_id FROM ontology_backfill_cursors WHERE cursor_name = $1",
            name,
        )
    finally:
        await conn.close()
    if row is None:
        return "", ""
    return str(row["approved_at"] or ""), str(row["case_id"] or "")


async def _save_database_cursor(name: str, approved_at: str, case_id: str) -> None:
    """Durably advance only after the complete page has been mirrored."""
    import asyncpg

    settings = load_settings()
    if not settings.postgres_dsn:
        raise RuntimeError("POSTGRES_DSN is required for the durable trace-v3 cursor")
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        await conn.execute(_CURSOR_TABLE)
        await conn.execute(
            """
            INSERT INTO ontology_backfill_cursors (cursor_name, approved_at, case_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (cursor_name) DO UPDATE
              SET approved_at = EXCLUDED.approved_at,
                  case_id = EXCLUDED.case_id,
                  updated_at = now()
            """,
            name,
            approved_at,
            case_id,
        )
    finally:
        await conn.close()


def _cursor_file(path: str) -> tuple[str, str]:
    if not path:
        return "", ""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "", ""
    except (OSError, json.JSONDecodeError):
        return "", ""
    if not isinstance(raw, dict):
        return "", ""
    return str(raw.get("approved_at") or ""), str(raw.get("case_id") or "")


def _save_cursor(path: str, approved_at: str, case_id: str) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(f"{target.suffix}.tmp")
    temporary.write_text(
        json.dumps({"approved_at": approved_at, "case_id": case_id}, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(target)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill approved trace-v3 knowledge into TypeDB with an approval keyset cursor."
    )
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument(
        "--max-batches",
        type=int,
        default=0,
        help="stop after N successful pages (0 = process through the end)",
    )
    parser.add_argument("--after-approved-at", default="", help="exclusive cursor timestamp")
    parser.add_argument("--after-case-id", default="", help="exclusive cursor case ID")
    parser.add_argument(
        "--cursor-name",
        default="trace_v3",
        help="durable Postgres cursor name (default: trace_v3)",
    )
    parser.add_argument(
        "--cursor-file",
        default="",
        help="optional JSON cursor persisted after each complete, successful page",
    )
    args = parser.parse_args()
    if bool(args.after_approved_at) != bool(args.after_case_id):
        parser.error("--after-approved-at and --after-case-id must be supplied together")
    cursor = (args.after_approved_at, args.after_case_id)
    if not cursor[0]:
        try:
            cursor = asyncio.run(_load_database_cursor(args.cursor_name))
        except Exception as exc:  # noqa: BLE001 - no source read without durable resume state
            print(f"trace-v3 backfill cursor load failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if not cursor[0]:
            cursor = _cursor_file(args.cursor_file)
    pages = written = 0
    while args.max_batches <= 0 or pages < args.max_batches:
        try:
            rows = asyncio.run(_fetch_trace_v3_page(*cursor, limit=max(args.batch_size, 1)))
        except Exception as exc:  # noqa: BLE001 - source failure must leave cursor unchanged
            print(f"trace-v3 backfill fetch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if not rows:
            print(f"trace-v3 backfill complete: {written} written across {pages} page(s)")
            return 0
        selected = [
            incident
            for incident in (_to_incident(row) for row in rows)
            if incident.reasoning_trace_v3
        ]
        page_written, failed = _write(selected) if selected else (0, 0)
        written += page_written
        # Never advance over a failed write: re-running the exact cursor is
        # safe because all projection writes are idempotent.
        if failed:
            print(f"trace-v3 backfill stopped: {page_written} written, {failed} failed", file=sys.stderr)
            return 1
        last = rows[-1]
        cursor = (
            str(last.get("snapshot_approved_at") or ""),
            str(last.get("case_id") or ""),
        )
        if not all(cursor):
            print("trace-v3 backfill stopped: page lacked a keyset cursor", file=sys.stderr)
            return 1
        try:
            asyncio.run(_save_database_cursor(args.cursor_name, *cursor))
        except Exception as exc:  # noqa: BLE001 - do not claim a resumable page without its cursor
            print(f"trace-v3 backfill cursor save failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        _save_cursor(args.cursor_file, *cursor)
        pages += 1
        print(
            "trace-v3 backfill cursor: "
            f"--after-approved-at {cursor[0]!r} --after-case-id {cursor[1]!r}"
        )
    print(f"trace-v3 backfill paused after {pages} page(s); resume from the printed cursor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
