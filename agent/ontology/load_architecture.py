"""Load the Run:ai platform topology (knowledge/runai_architecture.yaml) into TypeDB.

Mirrors the file-based architecture layer as control_plane_component entities
(purpose/failure_effect/owns_schema/checks as attributes) plus depends_on
relations — so graph queries can join "which component is implicated" with the
live incident facts the ingest cronjob writes.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        python -m ontology.load_architecture

Idempotent via replace semantics: single-valued attrs are delete-then-insert
(a changed YAML value would otherwise violate the @card(0..1) default), and
check_command mirrors the YAML list exactly. Same TypeDB 3.11 syntax
constraints as load_knowledge.py: no inline negation, `delete has $a of $x`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from app.config import load_settings
from app.knowledge import load_architecture
from app.ontology.typedb_client import escape_typeql as esc
from app.ontology.typedb_client import open_driver

ARCHITECTURE_FILE = Path("knowledge/runai_architecture.yaml")


def _exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def _ensure_component(tx: Any, entry: dict[str, Any]) -> None:
    name = entry["component"]
    if not _exists(tx, f'$x isa control_plane_component, has name "{esc(name)}";'):
        tx.query(f'insert $x isa control_plane_component, has name "{esc(name)}";').resolve()
    single_valued = {
        "layer": entry.get("layer"),
        "k8s_namespace": entry.get("namespace"),
        "description": entry.get("purpose"),
        "failure_effect": entry.get("failure_effect"),
        "owns_schema": entry.get("owns_schema"),
    }
    # Replace (not add-if-missing): these attrs are @card(0..1), so when the
    # YAML text changes, inserting alongside the old value fails the commit —
    # same pattern as ingest._replace_attr.
    for attr, value in single_valued.items():
        text = str(value or "").strip()
        if not text:
            continue
        if _exists(
            tx,
            f'$x isa control_plane_component, has name "{esc(name)}", has {attr} "{esc(text)}";',
        ):
            continue
        tx.query(
            f'match $c isa control_plane_component, has name "{esc(name)}", has {attr} $old; '
            f"delete has $old of $c;"
        ).resolve()
        tx.query(
            f'match $c isa control_plane_component, has name "{esc(name)}"; '
            f'insert $c has {attr} "{esc(text)}";'
        ).resolve()
    # check_command is multi-valued (@card(0..)): mirror the YAML list exactly
    # so checks dropped from the YAML don't linger as stale operator hints.
    tx.query(
        f'match $c isa control_plane_component, has name "{esc(name)}", has check_command $old; '
        f"delete has $old of $c;"
    ).resolve()
    for check in entry.get("checks") or []:
        text = str(check).strip()
        if not text:
            continue
        tx.query(
            f'match $c isa control_plane_component, has name "{esc(name)}"; '
            f'insert $c has check_command "{esc(text)}";'
        ).resolve()


def _relate_depends_on(tx: Any, dependent: str, dependency: str) -> None:
    if _exists(
        tx,
        f'$x isa control_plane_component, has name "{esc(dependent)}"; '
        f'$d isa control_plane_component, has name "{esc(dependency)}"; '
        f"(dependent: $x, dependency: $d) isa depends_on;",
    ):
        return
    tx.query(
        f'match $c isa control_plane_component, has name "{esc(dependent)}"; '
        f'$d isa control_plane_component, has name "{esc(dependency)}"; '
        f"insert (dependent: $c, dependency: $d) isa depends_on;"
    ).resolve()


def main() -> int:
    settings = load_settings()
    components = load_architecture(str(ARCHITECTURE_FILE))
    if not components:
        print(f"no components parsed from {ARCHITECTURE_FILE}", file=sys.stderr)
        return 1

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    loaded = edges = 0
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            for entry in components.values():
                _ensure_component(tx, entry)
                loaded += 1
            # Second pass so every dependency target exists before relating.
            for entry in components.values():
                for dependency in entry.get("depends_on") or []:
                    if dependency not in components:
                        print(
                            f"skip unknown dependency: {entry['component']} -> {dependency}",
                            file=sys.stderr,
                        )
                        continue
                    _relate_depends_on(tx, entry["component"], dependency)
                    edges += 1
            tx.commit()
    print(f"loaded {loaded} platform components, {edges} depends_on edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
