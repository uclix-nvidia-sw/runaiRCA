"""Load curated failure-mode knowledge (knowledge/failure_modes.yaml) into TypeDB.

Populates the ontology's knowledge layer:
    symptom  -indicates->  root_cause(family); symptom  -resolved_by->  action
i.e. the team-curated "this symptom -> this cause -> resolved by this action"
knowledge the synthesis step consults for remediation.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        python -m ontology.load_knowledge

Idempotent via a read-then-insert check (_exists), plus a load-time purge of
root_cause subtypes no longer present in the YAML catalog, so re-running after
editing the YAML is safe. Per-incident cause_instance subtypes are exempt.
Read-your-writes within the single WRITE txn makes the checks see earlier
inserts in the same run.
ponytail: uses exists() rather than inline `not { ... }` negation — TypeDB 3.11
rejects that negation form here ([TQL03] "expected pattern"). Only syntax proven
in app/services/kg_enrichment.py is used. First run needs live TypeDB validation;
TypeQL 3.x is not exercised by the unit tests.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from app.config import load_settings
from app.knowledge import load_family_catalog
from app.ontology.typedb_client import _concept_value, open_driver
from app.ontology.typedb_client import escape_typeql as esc
from ontology.upsert import (
    ensure_action,
    exists,
    relate_symptom_indicates,
    relate_symptom_resolved_by,
    selected_values,
)

KNOWLEDGE_FILE = Path(os.getenv("FAILURE_MODES_FILE", "knowledge/failure_modes.yaml"))
FAMILIES_FILE = Path(os.getenv("FAMILIES_FILE", "knowledge/families.yaml"))
_log = logging.getLogger(__name__)


def _catalog_families(path: str | Path = FAMILIES_FILE) -> set[str]:
    """The closed root-cause family vocabulary, read from the single
    authoritative catalog (families.yaml via app.knowledge.load_family_catalog)
    instead of a private copy of the list. A private copy is how this loader
    and ontology/load_troubleshooting.py (which imports FAMILIES from here)
    previously went stale the moment families.yaml grew a new family: this one
    silently skipped it, the other hard-raised.

    ``insufficient_evidence`` is schema.tql's root_cause subtype for "no
    diagnosis" and is deliberately absent from families.yaml (it is the
    ranker's built-in sentinel, not a curated diagnostic family) but curated
    knowledge is still allowed to target it, so it is added back here — same
    construction app/main.py uses for its own evaluation_families universe.
    """
    return {*load_family_catalog(str(path)).families, "insufficient_evidence"}


# Must match schema.tql sub-types and app/services/root_cause_ranking.FAMILIES.
FAMILIES = _catalog_families()


def purge_legacy_families(tx: Any, catalog_families: set[str]) -> list[str]:
    """Delete root-cause entities whose subtype left the current catalog.

    ``cause_instance`` rows are per-incident anchors and are deliberately
    exempt. Curated symptoms remain intact because current families may share
    them after a split or rename.
    """
    all_subtypes = selected_values(
        tx, "$rc isa root_cause, has subtype $f;", "f"
    )
    cause_instance_subtypes = selected_values(
        tx, "$ci isa cause_instance, has subtype $f;", "f"
    )
    legacy = sorted(all_subtypes - set(catalog_families) - cause_instance_subtypes)
    for family in legacy:
        tx.query(
            f'match $rel isa indicates, links (cause: $rc); '
            f'$rc has subtype "{esc(family)}"; delete $rel;'
        ).resolve()
        tx.query(
            f'match $rc isa root_cause, has subtype "{esc(family)}"; '
            "delete $rc;"
        ).resolve()
    if legacy:
        _log.warning("purged legacy families from the ontology: %s", legacy)
    return legacy


def _ensure_cause(tx: Any, family: str) -> None:
    if not exists(tx, f'$x isa {family}, has subtype "{esc(family)}";'):
        tx.query(f'insert $x isa {family}, has subtype "{esc(family)}";').resolve()


def _replace_attribute(
    tx: Any, symptom_name: str, attribute: str, desired_values: list[str]
) -> None:
    """Reconcile a scalar or multi-valued symptom attribute with YAML."""
    desired = {value for value in desired_values if value}
    current_rows = list(
        tx.query(
            f'match $s isa symptom, has name "{esc(symptom_name)}", '
            f'has {attribute} $value; select $value;'
        ).resolve().as_concept_rows()
    )
    for row in current_rows:
        get = getattr(row, "get", None)
        if not callable(get):
            continue
        concept = get("value")
        if concept is None:
            continue
        current = str(_concept_value(concept))
        if current in desired:
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(symptom_name)}", '
            f'has {attribute} $value; $value == "{esc(current)}"; '
            "delete has $value of $s;"
        ).resolve()
    for value in desired_values:
        if not value:
            continue
        if exists(
            tx,
            f'$x isa symptom, has name "{esc(symptom_name)}", '
            f'has {attribute} "{esc(value)}";',
        ):
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(symptom_name)}"; '
            f'insert $s has {attribute} "{esc(value)}";'
        ).resolve()


def _ensure_symptom(
    tx: Any,
    name: str,
    keywords: list[str],
    reason: str = "",
    reason_ko: str = "",
    exclusive_actions: bool = False,
    actions_ko: list[str] | None = None,
    component: str = "",
    name_ko: str = "",
    requires_lifecycle_signal: bool = False,
) -> None:
    if not exists(tx, f'$x isa symptom, has name "{esc(name)}";'):
        tx.query(f'insert $x isa symptom, has name "{esc(name)}";').resolve()
    for kw in keywords:
        if exists(tx, f'$x isa symptom, has name "{esc(name)}", has keyword "{esc(kw)}";'):
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            f'insert $s has keyword "{esc(kw)}";'
        ).resolve()
    desired_keywords = {str(kw) for kw in keywords}
    # Materialize the read stream before issuing deletes: every other loader in
    # this package wraps as_concept_rows() in list(), because writing on the same
    # transaction while a query stream is still open can invalidate it.
    current_keywords = list(
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}", has keyword $kw; '
            "select $kw;"
        ).resolve().as_concept_rows()
    )
    for row in current_keywords:
        get = getattr(row, "get", None)
        if not callable(get):
            continue
        concept = get("kw")
        if concept is None:
            continue
        current = str(_concept_value(concept))
        if current in desired_keywords:
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}", has keyword $kw; '
            f'$kw == "{esc(current)}"; delete has $kw of $s;'
        ).resolve()
    _replace_attribute(tx, name, "reason", [reason])
    _replace_attribute(tx, name, "reason_ko", [reason_ko])
    _replace_attribute(tx, name, "component", [component])
    _replace_attribute(tx, name, "name_ko", [name_ko])
    if exclusive_actions and not exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has exclusive_actions true;'
    ):
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            "insert $s has exclusive_actions true;"
        ).resolve()
    if requires_lifecycle_signal and not exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has requires_lifecycle_signal true;'
    ):
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            "insert $s has requires_lifecycle_signal true;"
        ).resolve()
    _replace_attribute(tx, name, "statement_ko", actions_ko or [])


def main() -> int:
    settings = load_settings()
    raw = yaml.safe_load(KNOWLEDGE_FILE.read_text(encoding="utf-8")) or []

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    families = symptoms = actions = 0
    catalog_families = {
        str(entry.get("family", "")).strip()
        for entry in raw
        if isinstance(entry, dict) and str(entry.get("family", "")).strip()
    }
    # Re-read per call (not the import-time FAMILIES) so a settings-level
    # FAMILIES_FILE override is honored the same way settings.typedb_database
    # already is, just below.
    valid_families = _catalog_families(settings.families_file)
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            purge_legacy_families(tx, catalog_families)
            for entry in raw:
                family = str(entry.get("family", "")).strip()
                if family not in valid_families:
                    print(f"skip unknown family: {family!r}", file=sys.stderr)
                    continue
                _ensure_cause(tx, family)
                families += 1
                for sym in entry.get("symptoms", []):
                    name = str(sym.get("name", "")).strip()
                    if not name:
                        continue
                    _ensure_symptom(
                        tx,
                        name,
                        [str(k) for k in sym.get("keywords", [])],
                        str(sym.get("reason", "")).strip(),
                        str(sym.get("reason_ko", "")).strip(),
                        sym.get("exclusive_actions") is True,
                        [
                            str(action).strip()
                            for action in sym.get("actions_ko", [])
                            if str(action).strip()
                        ],
                        str(sym.get("component") or "").strip(),
                        str(sym.get("name_ko") or "").strip(),
                        sym.get("requires_lifecycle_signal") is True,
                    )
                    relate_symptom_indicates(tx, name, family)
                    symptoms += 1
                    for act in sym.get("actions", []):
                        statement = str(act).strip()
                        if not statement:
                            continue
                        ensure_action(tx, statement)
                        relate_symptom_resolved_by(tx, name, statement)
                        actions += 1
            tx.commit()

    print(f"loaded knowledge: {families} families, {symptoms} symptoms, {actions} actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
