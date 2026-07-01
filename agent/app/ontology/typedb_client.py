"""Thin synchronous TypeDB 3.x client.

The official `typedb-driver` is synchronous/promise-based — there is no asyncio.
Callers in the async service MUST run these methods via `asyncio.to_thread(...)`
so they never block the event loop (see app/services/kg_enrichment.py).

`typedb` is imported lazily inside methods so the module imports even when the
driver isn't installed (the collector reports that as `unavailable`).

ponytail: one driver connection per call. Add a pool only if KG query latency
shows up in /analyze timings.
"""

from __future__ import annotations

from typing import Any

from app.config import Settings


def escape_typeql(value: str) -> str:
    """Escape a string for safe interpolation into a quoted TypeQL literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def open_driver(settings: Settings) -> Any:
    """Return a connected TypeDB 3.x driver (caller uses it as a context manager).

    Single source of truth for the 3.11.x connection API: DriverOptions takes a
    DriverTlsConfig (not an is_tls_enabled flag). `typedb` is imported lazily.
    """
    from typedb.api.connection.driver_tls_config import DriverTlsConfig
    from typedb.driver import Credentials, DriverOptions, TypeDB

    tls = (
        DriverTlsConfig.enabled_with_native_root_ca()
        if settings.typedb_tls_enabled
        else DriverTlsConfig.disabled()
    )
    options = DriverOptions(
        tls, request_timeout_millis=max(settings.typedb_timeout_seconds, 1) * 1000
    )
    return TypeDB.driver(
        settings.typedb_address or "localhost:1729",
        Credentials(settings.typedb_username, settings.typedb_password),
        options,
    )


class TypeDBClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def fetch_rows(self, typeql: str) -> list[dict[str, Any]]:
        from typedb.driver import TransactionType  # lazy: optional dependency

        rows: list[dict[str, Any]] = []
        with open_driver(self._settings) as driver:
            with driver.transaction(
                self._settings.typedb_database, TransactionType.READ
            ) as tx:
                answer = tx.query(typeql).resolve()
                for row in answer.as_concept_rows():
                    rows.append(_row_to_dict(row))
        return rows


def _row_to_dict(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in row.column_names():
        try:
            out[name] = _concept_value(row.get(name))
        except Exception:  # noqa: BLE001 - a single odd column must not break the row
            out[name] = None
    return out


def _concept_value(concept: Any) -> Any:
    """Best-effort extraction of a Python value from a 3.x Concept.

    Attributes carry typed values; entities/relations only expose an iid/label.
    The exact getter surface shifts across 3.x point releases, so we probe a few.
    """
    for getter in ("get_value", "as_attribute", "get_label", "get_iid"):
        fn = getattr(concept, getter, None)
        if not callable(fn):
            continue
        try:
            result = fn()
        except Exception:  # noqa: BLE001
            continue
        if getter == "as_attribute":
            value_fn = getattr(result, "get_value", None)
            if callable(value_fn):
                try:
                    return value_fn()
                except Exception:  # noqa: BLE001
                    continue
            continue
        if result is not None:
            return result
    return str(concept)
