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
    # 2026-07-27 infra-layer simplification: cluster/namespace/project/queue/pod
    # entities and their write-only relations are gone (identities became plain
    # attributes; the one topology relation is node runs_on workload). Surviving
    # types shed the dead plays first, then the relations and entities go.
    "undefine plays scopes:member from node;",
    "undefine plays belongs_to:owner from workload;",
    "undefine plays in_project:member from workload;",
    "undefine plays submitted_to:job from workload;",
    "undefine plays contains:occupant from workload;",
    "undefine plays emits:emitter from control_plane_component;",
    "undefine plays contains:occupant from control_plane_component;",
    "undefine plays emits:signal from symptom;",
    "undefine plays emits:signal from evidence;",
    "undefine relation scopes;",
    "undefine relation belongs_to;",
    "undefine relation in_project;",
    "undefine relation submitted_to;",
    "undefine relation contains;",
    "undefine relation emits;",
    "undefine entity pod;",
    "undefine entity cluster;",
    "undefine entity namespace;",
    "undefine entity project;",
    "undefine entity queue;",
]

# Instance deletions that must precede the schema undefines above: a type with
# live instances cannot be undefined. WRITE transactions, same non-fatal
# pattern (a fresh or already-cleaned DB simply has nothing to delete).
# runs_on is wholesale: every pre-migration edge is node->pod, and the next
# ingest pass rebuilds node->workload edges from the incident store.
DATA_MIGRATIONS = [
    "match $x isa runs_on; delete $x;",
    "match $x isa scopes; delete $x;",
    "match $x isa belongs_to; delete $x;",
    "match $x isa in_project; delete $x;",
    "match $x isa submitted_to; delete $x;",
    "match $x isa contains; delete $x;",
    "match $x isa emits; delete $x;",
    "match $x isa pod; delete $x;",
    "match $x isa cluster; delete $x;",
    "match $x isa namespace; delete $x;",
    "match $x isa project; delete $x;",
    "match $x isa queue; delete $x;",
    # Suffixed "workloads" minted by the old raw-pod-name fallback
    # (name-<rs-hash>-<random5>). Only the unambiguous Deployment shape is
    # cleaned — ordinal suffixes can be legitimate workload names. Non-fatal
    # like every entry here; re-ingest rebuilds the stem identities.
    'match $w isa workload, has name $n; $n like ".*-[0-9a-f]{8,10}-[a-z0-9]{5}"; delete $w;',
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
        for migration in DATA_MIGRATIONS:
            try:
                with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
                    tx.query(migration).resolve()
                    tx.commit()
                print(f"data migration applied: {migration}")
            except Exception as exc:  # fresh / already-cleaned DB — nothing to delete
                print(
                    "data migration skipped (non-fatal): "
                    f"{migration} -> {exc.__class__.__name__}"
                )
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
