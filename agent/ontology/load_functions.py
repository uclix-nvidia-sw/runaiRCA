"""Define the ontology's TypeDB 3.x reasoning functions (ontology/functions.tql).

Run AFTER load_schema (functions reference schema types):

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 python -m ontology.load_functions

Functions are a required part of the runtime harness. Fresh databases use
`define`; upgrades retry with `redefine` so changed functions are applied rather
than silently leaving an old XID-only function set in production.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from app.config import load_settings
from app.ontology.typedb_client import open_driver

FUNCTIONS_FILE = Path(os.getenv("ONTOLOGY_FUNCTIONS_FILE", "ontology/functions.tql"))


def _function_definitions(tql: str) -> list[str]:
    """Split the schema file into independently-upgradable function statements.

    A TypeDB schema transaction is atomic: defining an already-existing legacy
    function would otherwise prevent every newly-added function in the same
    ``define`` block from being installed. Function bodies in this file do not
    contain a top-level ``fun`` token, so the small split is deliberately less
    clever than a TypeQL parser and keeps each migration independently retryable.
    """
    match = re.search(r"(?m)^define\s*$", tql)
    if match is None:
        raise ValueError("functions file must start with define")
    body = tql[match.end() :].strip()
    parts = re.split(r"(?m)^fun ", body)
    definitions: list[str] = []
    # The first split part holds comments between `define` and the first
    # function. Comments are documentation, not part of a function migration.
    for part in parts[1:]:
        function = ("fun " + part).strip()
        if function:
            definitions.append("define\n\n" + function)
    return definitions


def main() -> int:
    settings = load_settings()
    if not settings.enable_typedb:
        print("ENABLE_TYPEDB is not set; skipping function definitions.", file=sys.stderr)
        return 0

    tql = FUNCTIONS_FILE.read_text(encoding="utf-8")

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 0

    try:
        definitions = _function_definitions(tql)
        with open_driver(settings) as driver:
            for definition in definitions:
                try:
                    with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
                        tx.query(definition).resolve()
                        tx.commit()
                except Exception:
                    # Existing functions need an explicit schema redefine on
                    # upgrade; a newly-added function succeeds in the define
                    # branch above and never reaches this path.
                    redefined = definition.replace("define\n", "redefine\n", 1)
                    with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
                        tx.query(redefined).resolve()
                        tx.commit()
        print(f"defined/redefined {len(definitions)} ontology reasoning functions")
        return 0
    except Exception as exc:  # noqa: BLE001 - surface schema drift to Helm
        print(
            f"function definitions failed: {exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
