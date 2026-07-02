"""Load the Run:ai known-issues catalog (knowledge/runai_known_issues.yaml) into TypeDB.

Each real operator case becomes a name-keyed symptom, uniform with the curated
failure modes and the built-in alert catalog:
    symptom(issue)  -indicates->   <family>(root_cause)
    symptom(issue)  -resolved_by-> action   (the remediation steps)
plus optional reason / affected_version / fixed_version attributes so the
synthesis step can surface "known issue, affected vX, fixed in vY". Run:

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 python -m ontology.load_known_issues

Idempotent via a read-then-insert check (_exists). Only TypeQL 3.x syntax proven
in load_knowledge.py / load_alerts.py is used; not exercised by unit tests — first
run needs live TypeDB validation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import yaml

from app.config import load_settings
from app.ontology.typedb_client import escape_typeql as esc
from app.ontology.typedb_client import open_driver

KNOWN_ISSUES_FILE = Path(
    os.getenv("RUNAI_KNOWN_ISSUES_FILE", "knowledge/runai_known_issues.yaml")
)

# Must match the root_cause subtypes in schema.tql.
FAMILIES = {
    "node_kubelet_pressure",
    "scheduling_quota_exhaustion",
    "control_plane_error",
    "workload_startup_image_failure",
    "gpu_hardware_error",
    "platform_version_bug",
    "observability_accuracy",
    "expected_known_behavior",
    "insufficient_evidence",
}


def _exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def _ensure_family(tx: Any, family: str) -> None:
    if not _exists(tx, f'$x isa {family}, has subtype "{esc(family)}";'):
        tx.query(f'insert $x isa {family}, has subtype "{esc(family)}";').resolve()


def _ensure_symptom(tx: Any, name: str, reason: str, affected: str, fixed: str) -> None:
    # Name-keyed symptom created once with its single-valued attributes attached.
    # Empty version/reason strings are skipped so we don't store blank attributes.
    if _exists(tx, f'$x isa symptom, has name "{esc(name)}";'):
        return
    parts = [f'has name "{esc(name)}"']
    if reason:
        parts.append(f'has reason "{esc(reason)}"')
    if affected:
        parts.append(f'has affected_version "{esc(affected)}"')
    if fixed:
        parts.append(f'has fixed_version "{esc(fixed)}"')
    tx.query(f"insert $x isa symptom, {', '.join(parts)};").resolve()


def _add_keyword(tx: Any, name: str, keyword: str) -> None:
    if _exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has keyword "{esc(keyword)}";'
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(name)}"; '
        f'insert $s has keyword "{esc(keyword)}";'
    ).resolve()


def _ensure_action(tx: Any, statement: str) -> None:
    if not _exists(tx, f'$x isa action, has statement "{esc(statement)}";'):
        tx.query(f'insert $x isa action, has statement "{esc(statement)}";').resolve()


def _relate_indicates(tx: Any, name: str, family: str) -> None:
    if _exists(
        tx,
        f'$x isa symptom, has name "{esc(name)}"; $rc isa {family}; '
        f"(symptom: $x, cause: $rc) isa indicates;",
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(name)}"; $rc isa {family}; '
        f"insert (symptom: $s, cause: $rc) isa indicates;"
    ).resolve()


def _relate_resolved_by(tx: Any, name: str, statement: str) -> None:
    if _exists(
        tx,
        f'$x isa symptom, has name "{esc(name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        f"(symptom: $x, remedy: $a) isa resolved_by;",
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        f"insert (symptom: $s, remedy: $a) isa resolved_by;"
    ).resolve()


def main() -> int:
    settings = load_settings()
    if not settings.enable_typedb:
        print("ENABLE_TYPEDB is not set; skipping Run:ai known-issues load.", file=sys.stderr)
        return 0

    raw = yaml.safe_load(KNOWN_ISSUES_FILE.read_text(encoding="utf-8")) or []

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    n_issues = n_actions = 0
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            for entry in raw if isinstance(raw, list) else []:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("issue") or "").strip()
                family = str(entry.get("family") or "").strip()
                if not name:
                    continue
                if family not in FAMILIES:
                    print(f"skip unknown family: {family!r} ({name})", file=sys.stderr)
                    continue
                _ensure_family(tx, family)
                _ensure_symptom(
                    tx,
                    name,
                    str(entry.get("reason") or "").strip(),
                    str(entry.get("affected_version") or "").strip(),
                    str(entry.get("fixed_version") or "").strip(),
                )
                for kw in entry.get("keywords") or []:
                    kw = str(kw).strip()
                    if kw:
                        _add_keyword(tx, name, kw)
                _relate_indicates(tx, name, family)
                for action in entry.get("actions") or []:
                    statement = str(action).strip()
                    if not statement:
                        continue
                    _ensure_action(tx, statement)
                    _relate_resolved_by(tx, name, statement)
                    n_actions += 1
                n_issues += 1
            tx.commit()

    print(f"loaded Run:ai known issues: {n_issues} issues, {n_actions} action links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
