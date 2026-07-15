"""Load curated failure-mode knowledge (knowledge/failure_modes.yaml) into TypeDB.

Populates the ontology's knowledge layer:
    symptom  -indicates->  root_cause(family); symptom  -resolved_by->  action
i.e. the team-curated "this symptom -> this cause -> resolved by this action"
knowledge the synthesis step consults for remediation.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        python -m ontology.load_knowledge

Idempotent via a read-then-insert check (_exists), so re-running after editing
the YAML is safe. Read-your-writes within the single WRITE txn makes the checks
see earlier inserts in the same run.
ponytail: uses _exists() rather than inline `not { ... }` negation — TypeDB 3.11
rejects that negation form here ([TQL03] "expected pattern"). Only syntax proven
in app/services/kg_enrichment.py is used. First run needs live TypeDB validation;
TypeQL 3.x is not exercised by the unit tests.
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

KNOWLEDGE_FILE = Path(os.getenv("FAILURE_MODES_FILE", "knowledge/failure_modes.yaml"))

# Must match schema.tql sub-types and app/services/root_cause_ranking.py.
FAMILIES = {
    "node_kubelet_pressure",
    "runai_scheduling_quota",
    "k8s_scheduling_error",
    "runai_control_plane_error",
    "k8s_control_plane_error",
    "workload_startup_error",
    "image_pull_error",
    "gpu_hardware_error",
    "network_fabric_error",
    "cluster_network_error",
    "k8s_storage_error",
    "storage_backend_error",
    "workload_runtime_error",
    "observability_accuracy",
    "platform_auth_error",
    "platform_lifecycle_change",
    "insufficient_evidence",
}


def _exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def _ensure_cause(tx: Any, family: str) -> None:
    if not _exists(tx, f'$x isa {family}, has subtype "{esc(family)}";'):
        tx.query(f'insert $x isa {family}, has subtype "{esc(family)}";').resolve()


def _ensure_symptom(
    tx: Any,
    name: str,
    keywords: list[str],
    reason: str = "",
    reason_ko: str = "",
    exclusive_actions: bool = False,
    actions_ko: list[str] | None = None,
) -> None:
    if not _exists(tx, f'$x isa symptom, has name "{esc(name)}";'):
        tx.query(f'insert $x isa symptom, has name "{esc(name)}";').resolve()
    for kw in keywords:
        if _exists(tx, f'$x isa symptom, has name "{esc(name)}", has keyword "{esc(kw)}";'):
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            f'insert $s has keyword "{esc(kw)}";'
        ).resolve()
    if reason and not _exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has reason "{esc(reason)}";'
    ):
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            f'insert $s has reason "{esc(reason)}";'
        ).resolve()
    if reason_ko and not _exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has reason_ko "{esc(reason_ko)}";'
    ):
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            f'insert $s has reason_ko "{esc(reason_ko)}";'
        ).resolve()
    if exclusive_actions and not _exists(
        tx, f'$x isa symptom, has name "{esc(name)}", has exclusive_actions true;'
    ):
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            "insert $s has exclusive_actions true;"
        ).resolve()
    for statement_ko in actions_ko or []:
        if _exists(
            tx,
            f'$x isa symptom, has name "{esc(name)}", has statement_ko "{esc(statement_ko)}";',
        ):
            continue
        tx.query(
            f'match $s isa symptom, has name "{esc(name)}"; '
            f'insert $s has statement_ko "{esc(statement_ko)}";'
        ).resolve()


def _ensure_action(tx: Any, statement: str) -> None:
    if not _exists(tx, f'$x isa action, has statement "{esc(statement)}";'):
        tx.query(f'insert $x isa action, has statement "{esc(statement)}";').resolve()


def _relate_indicates(tx: Any, symptom_name: str, family: str) -> None:
    if _exists(
        tx,
        f'$x isa symptom, has name "{esc(symptom_name)}"; $rc isa {family}; '
        f"(symptom: $x, cause: $rc) isa indicates;",
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(symptom_name)}"; $rc isa {family}; '
        f"insert (symptom: $s, cause: $rc) isa indicates;"
    ).resolve()


def _relate_resolved_by(tx: Any, symptom_name: str, statement: str) -> None:
    if _exists(
        tx,
        f'$x isa symptom, has name "{esc(symptom_name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        f"(symptom: $x, remedy: $a) isa resolved_by;",
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(symptom_name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        f"insert (symptom: $s, remedy: $a) isa resolved_by;"
    ).resolve()


def main() -> int:
    settings = load_settings()
    raw = yaml.safe_load(KNOWLEDGE_FILE.read_text(encoding="utf-8")) or []

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    families = symptoms = actions = 0
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            for entry in raw:
                family = str(entry.get("family", "")).strip()
                if family not in FAMILIES:
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
                        [str(action).strip() for action in sym.get("actions_ko", []) if str(action).strip()],
                    )
                    _relate_indicates(tx, name, family)
                    symptoms += 1
                    for act in sym.get("actions", []):
                        statement = str(act).strip()
                        if not statement:
                            continue
                        _ensure_action(tx, statement)
                        _relate_resolved_by(tx, name, statement)
                        actions += 1
            tx.commit()

    print(f"loaded knowledge: {families} families, {symptoms} symptoms, {actions} actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
