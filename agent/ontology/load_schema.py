"""Apply ontology/schema.tql to TypeDB (creates the database if needed).

Run from the agent/ directory after a TypeDB server is reachable:

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        ./.venv/bin/python -m ontology.load_schema

Connection comes from app.config (TYPEDB_* env vars); address defaults to
localhost:1729 so it works against a local `docker run typedb/typedb`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.config import load_settings

SCHEMA_FILE = Path(__file__).resolve().parent / "schema.tql"


def main() -> int:
    settings = load_settings()
    address = settings.typedb_address or "localhost:1729"
    schema = SCHEMA_FILE.read_text(encoding="utf-8")

    try:
        from typedb.driver import TransactionType

        from app.ontology.typedb_client import open_driver
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    with open_driver(settings) as driver:
        if not driver.databases.contains(settings.typedb_database):
            driver.databases.create(settings.typedb_database)
            print(f"created database '{settings.typedb_database}'")
        with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
            tx.query(schema).resolve()
            tx.commit()
    print(f"schema applied to '{settings.typedb_database}' at {address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
