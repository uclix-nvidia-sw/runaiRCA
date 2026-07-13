from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

from ontology import backfill_trace_v3


def _row(case_id: str = "CASE-1") -> dict[str, str]:
    return {
        "snapshot_approved_at": "2026-07-13T00:00:00Z",
        "case_id": case_id,
    }


def test_successful_traceless_page_advances_durable_cursor(monkeypatch: Any) -> None:
    pages = [[_row()], []]
    saved: list[tuple[str, str, str]] = []

    async def fetch(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
        return pages.pop(0)

    async def load(_name: str) -> tuple[str, str]:
        return "", ""

    async def save(name: str, approved_at: str, case_id: str) -> None:
        saved.append((name, approved_at, case_id))

    monkeypatch.setattr(backfill_trace_v3, "_fetch_trace_v3_page", fetch)
    monkeypatch.setattr(backfill_trace_v3, "_load_database_cursor", load)
    monkeypatch.setattr(backfill_trace_v3, "_save_database_cursor", save)
    monkeypatch.setattr(
        backfill_trace_v3,
        "_to_incident",
        lambda _row: SimpleNamespace(reasoning_trace_v3={}),
    )
    monkeypatch.setattr(
        backfill_trace_v3,
        "_write",
        lambda _incidents: (_ for _ in ()).throw(AssertionError("traceless rows must not write")),
    )
    monkeypatch.setattr(sys, "argv", ["backfill_trace_v3.py", "--batch-size", "1"])

    assert backfill_trace_v3.main() == 0
    assert saved == [("trace_v3", "2026-07-13T00:00:00Z", "CASE-1")]


def test_failed_page_does_not_advance_durable_cursor(monkeypatch: Any) -> None:
    saved: list[tuple[str, str, str]] = []

    async def fetch(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
        return [_row()]

    async def load(_name: str) -> tuple[str, str]:
        return "2026-07-12T00:00:00Z", "CASE-0"

    async def save(name: str, approved_at: str, case_id: str) -> None:
        saved.append((name, approved_at, case_id))

    monkeypatch.setattr(backfill_trace_v3, "_fetch_trace_v3_page", fetch)
    monkeypatch.setattr(backfill_trace_v3, "_load_database_cursor", load)
    monkeypatch.setattr(backfill_trace_v3, "_save_database_cursor", save)
    monkeypatch.setattr(
        backfill_trace_v3,
        "_to_incident",
        lambda _row: SimpleNamespace(reasoning_trace_v3={"schema_version": 3}),
    )
    monkeypatch.setattr(backfill_trace_v3, "_write", lambda _incidents: (0, 1))
    monkeypatch.setattr(sys, "argv", ["backfill_trace_v3.py"])

    assert backfill_trace_v3.main() == 1
    assert saved == []


def test_explicit_cursor_overrides_durable_cursor(monkeypatch: Any) -> None:
    observed: list[tuple[str, str]] = []

    async def fetch(approved_at: str, case_id: str, **_kwargs: Any) -> list[dict[str, str]]:
        observed.append((approved_at, case_id))
        return []

    async def load(_name: str) -> tuple[str, str]:
        raise AssertionError("explicit cursor must not load durable state")

    monkeypatch.setattr(backfill_trace_v3, "_fetch_trace_v3_page", fetch)
    monkeypatch.setattr(backfill_trace_v3, "_load_database_cursor", load)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "backfill_trace_v3.py",
            "--after-approved-at",
            "2026-07-12T00:00:00Z",
            "--after-case-id",
            "CASE-explicit",
        ],
    )

    assert backfill_trace_v3.main() == 0
    assert observed == [("2026-07-12T00:00:00Z", "CASE-explicit")]
