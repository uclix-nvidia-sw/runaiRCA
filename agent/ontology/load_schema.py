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

# One-off annotation changes for databases created by an older schema.tql.
# `define` cannot alter an existing annotation, so each entry is applied with
# `redefine` in its own transaction BEFORE the main define. Failures are
# non-fatal: a fresh database has nothing to redefine (define below covers it),
# and an already-migrated database rejects the no-op redefine.
SCHEMA_MIGRATIONS = [
    # check_command widened from the implicit @card(0..1): components ship
    # several ready-to-run checks, so the architecture loader could never
    # commit a 2-check component against the old card.
    "redefine control_plane_component owns check_command @card(0..);",
    # Older schemas had a placeholder runbook with a non-key name. Diagnostic
    # loading needs one stable runbook identity for replace-in-place semantics.
    "redefine runbook owns name @key;",
    # Cosmetic: drop the 4 relations removed from schema.tql (fixed_by, has_cause,
    # observed_symptom, similar_to). `define` cannot delete a type, so an already-
    # loaded DB keeps them as harmless orphans. Undefine the plays capabilities
    # first, then the relations. Non-fatal per the loop below: a fresh DB has
    # nothing to undefine and an already-cleaned DB rejects the no-op.
    "undefine plays fixed_by:cause from root_cause;",
    "undefine plays fixed_by:remedy from action;",
    "undefine plays has_cause:incident from incident;",
    "undefine plays has_cause:cause from root_cause;",
    "undefine plays observed_symptom:incident from incident;",
    "undefine plays observed_symptom:run from analysis_run;",
    "undefine plays observed_symptom:symptom from symptom;",
    "undefine plays observed_symptom:proof from evidence;",
    "undefine plays similar_to:this from incident;",
    "undefine plays similar_to:other from incident;",
    "undefine relation fixed_by;",
    "undefine relation has_cause;",
    "undefine relation observed_symptom;",
    "undefine relation similar_to;",
]


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
        for migration in SCHEMA_MIGRATIONS:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
                    tx.query(migration).resolve()
                    tx.commit()
                print(f"schema migration applied: {migration}")
            except Exception as exc:  # fresh DB / already migrated — define below is authoritative
                print(
                    "schema migration skipped (non-fatal): "
                    f"{migration} -> {exc.__class__.__name__}"
                )
        with driver.transaction(settings.typedb_database, TransactionType.SCHEMA) as tx:
            tx.query(schema).resolve()
            tx.commit()
    print(f"schema applied to '{settings.typedb_database}' at {address}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
