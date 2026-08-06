"""Load Run:ai built-in alerts (knowledge/runai_alerts_catalog.yaml) into TypeDB.

Each documented built-in alert becomes a symptom keyed by its name:
    symptom(alert)  -indicates->   <family>(root_cause)
    symptom(alert)  -resolved_by-> action   (the doc's remediation steps)

so recognizing the alert by name yields its family + fix from the graph, uniform
with the curated failure modes. Run:

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 python -m ontology.load_alerts

Idempotent via a read-then-insert check (_exists). Only TypeQL 3.x syntax proven
in load_knowledge.py / load_xids.py is used; not exercised by unit tests — first
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
from ontology.families import ingestable_families
from ontology.upsert import (
    ensure_action,
    ensure_family,
    exists,
    relate_symptom_indicates,
    relate_symptom_resolved_by,
)

ALERTS_FILE = Path(os.getenv("RUNAI_ALERTS_FILE", "knowledge/runai_alerts_catalog.yaml"))

FAMILIES = ingestable_families()


def _ensure_symptom(tx: Any, name: str, keyword: str) -> None:
    if exists(tx, f'$x isa symptom, has name "{esc(name)}";'):
        return
    tx.query(
        f'insert $x isa symptom, has name "{esc(name)}", has keyword "{esc(keyword)}";'
    ).resolve()


def _keyword(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())


def main() -> int:
    settings = load_settings()
    if not settings.enable_typedb:
        print("ENABLE_TYPEDB is not set; skipping Run:ai alerts load.", file=sys.stderr)
        return 0

    raw = yaml.safe_load(ALERTS_FILE.read_text(encoding="utf-8")) or []

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    n_alerts = n_actions = 0
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            for entry in raw if isinstance(raw, list) else []:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("alert") or "").strip()
                family = str(entry.get("family") or "").strip()
                if not name or family not in FAMILIES:
                    continue
                ensure_family(tx, family)
                _ensure_symptom(tx, name, _keyword(name))
                relate_symptom_indicates(tx, name, family)
                for action in entry.get("actions") or []:
                    statement = str(action).strip()
                    if not statement:
                        continue
                    ensure_action(tx, statement)
                    relate_symptom_resolved_by(tx, name, statement)
                    n_actions += 1
                n_alerts += 1
            tx.commit()

    print(f"loaded Run:ai built-in alerts: {n_alerts} alerts, {n_actions} action links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
