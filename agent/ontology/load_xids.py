"""Load the NVIDIA XID GPU-error catalog (knowledge/xid_catalog.yaml) into TypeDB.

Populates the ontology's GPU-hardware-fault layer:
    xid_error  -applies_to->  gpu_model
    xid_error  -indicates->   gpu_hardware_error(root_cause family)
    xid_error  -resolved_by->  action   (the immediate/investigatory buckets)

so an NVIDIA XID becomes a first-class RCA candidate alongside the curated
failure modes. Run:

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        python -m ontology.load_xids

Idempotent via a read-then-insert check (_exists); re-running after editing the
YAML is safe. Read-your-writes within the single WRITE txn makes checks see
earlier inserts in the same run.

ponytail: uses _exists() rather than inline `not { ... }` negation — TypeDB 3.11
rejects that negation form here ([TQL03]). Only syntax proven in load_knowledge.py
and kg_enrichment.py is used. First run needs live TypeDB validation; TypeQL 3.x
is not exercised by the unit tests.
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

XID_CATALOG_FILE = Path(os.getenv("XID_CATALOG_FILE", "knowledge/xid_catalog.yaml"))

# The one root_cause family XIDs indicate — must match schema.tql.
GPU_HARDWARE_ERROR = "gpu_hardware_error"


def _exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def _ensure_family(tx: Any) -> None:
    if not _exists(
        tx, f'$x isa {GPU_HARDWARE_ERROR}, has subtype "{esc(GPU_HARDWARE_ERROR)}";'
    ):
        tx.query(
            f'insert $x isa {GPU_HARDWARE_ERROR}, has subtype "{esc(GPU_HARDWARE_ERROR)}";'
        ).resolve()


def _ensure_gpu_model(tx: Any, name: str) -> None:
    if not _exists(tx, f'$x isa gpu_model, has name "{esc(name)}";'):
        tx.query(f'insert $x isa gpu_model, has name "{esc(name)}";').resolve()


def _ensure_xid(tx: Any, code: int, mnemonic: str, description: str, severity: str) -> None:
    # xid_code is @key, so the entity is created once; attributes attach on create.
    if _exists(tx, f"$x isa xid_error, has xid_code {code};"):
        return
    tx.query(
        f"insert $x isa xid_error, has xid_code {code}, "
        f'has mnemonic "{esc(mnemonic)}", '
        f'has description "{esc(description)}", '
        f'has severity "{esc(severity)}";'
    ).resolve()


def _ensure_action(tx: Any, statement: str) -> None:
    if not _exists(tx, f'$x isa action, has statement "{esc(statement)}";'):
        tx.query(f'insert $x isa action, has statement "{esc(statement)}";').resolve()


def _relate_applies_to(tx: Any, code: int, model: str) -> None:
    if _exists(
        tx,
        f"$x isa xid_error, has xid_code {code}; "
        f'$g isa gpu_model, has name "{esc(model)}"; '
        f"(fault: $x, model: $g) isa applies_to;",
    ):
        return
    tx.query(
        f"match $x isa xid_error, has xid_code {code}; "
        f'$g isa gpu_model, has name "{esc(model)}"; '
        f"insert (fault: $x, model: $g) isa applies_to;"
    ).resolve()


def _relate_indicates(tx: Any, code: int) -> None:
    if _exists(
        tx,
        f"$x isa xid_error, has xid_code {code}; $rc isa {GPU_HARDWARE_ERROR}; "
        f"(symptom: $x, cause: $rc) isa indicates;",
    ):
        return
    tx.query(
        f"match $x isa xid_error, has xid_code {code}; $rc isa {GPU_HARDWARE_ERROR}; "
        f"insert (symptom: $x, cause: $rc) isa indicates;"
    ).resolve()


def _relate_resolved_by(tx: Any, code: int, statement: str) -> None:
    if _exists(
        tx,
        f"$x isa xid_error, has xid_code {code}; "
        f'$a isa action, has statement "{esc(statement)}"; '
        f"(symptom: $x, remedy: $a) isa resolved_by;",
    ):
        return
    tx.query(
        f"match $x isa xid_error, has xid_code {code}; "
        f'$a isa action, has statement "{esc(statement)}"; '
        f"insert (symptom: $x, remedy: $a) isa resolved_by;"
    ).resolve()


def main() -> int:
    settings = load_settings()
    if not settings.enable_typedb:
        print("ENABLE_TYPEDB is not set; skipping XID catalog load.", file=sys.stderr)
        return 0

    data = yaml.safe_load(XID_CATALOG_FILE.read_text(encoding="utf-8")) or {}
    xids = data.get("xids", [])
    buckets = data.get("resolution_buckets", {})

    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    n_xids = n_models = n_actions = 0
    seen_models: set[str] = set()
    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            _ensure_family(tx)
            for entry in xids:
                code = entry.get("code")
                if code is None:
                    continue
                code = int(code)
                _ensure_xid(
                    tx,
                    code,
                    str(entry.get("mnemonic", "")),
                    str(entry.get("description", "")),
                    str(entry.get("severity", "")),
                )
                _relate_indicates(tx, code)
                n_xids += 1
                for model in entry.get("gpu_models", []) or []:
                    model = str(model).strip()
                    if not model:
                        continue
                    if model not in seen_models:
                        _ensure_gpu_model(tx, model)
                        seen_models.add(model)
                        n_models += 1
                    _relate_applies_to(tx, code, model)
                # Resolve the bucket names to their action text; fall back to the
                # bucket name itself when it isn't in the resolution_buckets map.
                for key in ("immediate_action", "investigatory_action"):
                    bucket = str(entry.get(key, "")).strip()
                    if not bucket:
                        continue
                    statement = str(buckets.get(bucket, bucket)).strip()
                    if not statement:
                        continue
                    _ensure_action(tx, statement)
                    _relate_resolved_by(tx, code, statement)
                    n_actions += 1
            tx.commit()

    print(f"loaded XID catalog: {n_xids} xids, {n_models} gpu models, {n_actions} action links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
