"""Define the ontology's TypeDB 3.x reasoning functions (ontology/functions.tql).

Run AFTER load_schema (functions reference schema types):

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 python -m ontology.load_functions

Best-effort and ISOLATED: any failure to define the functions logs a warning and
still returns 0, so it can never break the core schema/data load chain. The
`define fun` syntax was validated against TypeDB CE 3.11.5 (see functions.tql).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from app.config import load_settings
from app.ontology.typedb_client import open_driver

FUNCTIONS_FILE = Path(os.getenv("ONTOLOGY_FUNCTIONS_FILE", "ontology/functions.tql"))


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
        with open_driver(settings) as driver:
            with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
                tx.query(tql).resolve()
                tx.commit()
        print("defined ontology reasoning functions")
    except Exception as exc:  # noqa: BLE001 - best-effort; must not break the load chain
        print(
            f"function definitions skipped (non-fatal): {exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
