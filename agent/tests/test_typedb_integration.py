"""Loader behaviour that only a REAL TypeDB can show.

The fake-transaction tests exercise the TypeQL strings but never the graph, so
they cannot see a relation that was written and never retired. That is exactly
the failure mode here: when a symptom's family moves in YAML, the old
``indicates`` edge stays unless the loader deletes it, and the symptom then
counts for two families in the ranker and shows the operator the same guidance
twice.

Destructive: it runs the loaders and plants relations in TYPEDB_DATABASE, so it
is behind its OWN opt-in rather than TYPEDB_ADDRESS — a developer whose shell
already points at a real graph must not wipe it by running the suite.

    docker run -d --name rca-typedb -p 1729:1729 docker.io/typedb/typedb:3.11.5
    RCA_TEST_TYPEDB=1 ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \\
      TYPEDB_USERNAME=admin TYPEDB_PASSWORD=password TYPEDB_DATABASE=runai_rca \\
      .venv/bin/python -m pytest tests/test_typedb_integration.py -v
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest
import yaml

from app.config import load_settings
from app.ontology.typedb_client import escape_typeql as esc
from app.ontology.typedb_client import open_driver

pytestmark = pytest.mark.skipif(
    not os.getenv("RCA_TEST_TYPEDB"), reason="RCA_TEST_TYPEDB not set (destructive)"
)

# In every loader's whitelist, and owned by none of the symptoms under test —
# so an edge to it can only be the stale one this test plants.
_STALE_FAMILY = "cluster_network_error"
_KNOWLEDGE = pathlib.Path(__file__).parents[1] / "knowledge"


def _transaction(kind: str):
    from typedb.driver import TransactionType

    settings = load_settings()
    driver = open_driver(settings)
    return driver, settings, TransactionType.READ if kind == "read" else TransactionType.WRITE


def _families_for(symptom: str) -> set[str]:
    driver_cm, settings, tx_type = _transaction("read")
    with driver_cm as driver, driver.transaction(settings.typedb_database, tx_type) as tx:
        rows = list(
            tx.query(
                "match $rel isa indicates, links (symptom: $s, cause: $rc); "
                f'$s isa symptom, has name "{esc(symptom)}"; $rc has subtype $f; select $f;'
            )
            .resolve()
            .as_concept_rows()
        )
    values = set()
    for row in rows:
        concept = row.get("f")
        values.add(str(getattr(concept, "get_value", lambda: concept)()))
    return values


def _plant_stale_edge(symptom: str) -> None:
    driver_cm, settings, tx_type = _transaction("write")
    with driver_cm as driver, driver.transaction(settings.typedb_database, tx_type) as tx:
        tx.query(f'insert $x isa {_STALE_FAMILY}, has subtype "{_STALE_FAMILY}";').resolve()
        tx.query(
            f'match $s isa symptom, has name "{esc(symptom)}"; $rc isa {_STALE_FAMILY}; '
            "insert (symptom: $s, cause: $rc) isa indicates;"
        ).resolve()
        tx.commit()


def _run_loader(module: str) -> None:
    done = subprocess.run(
        [sys.executable, "-m", module], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, f"{module} failed: {done.stderr[-500:]}"
    # A loader that skipped (ENABLE_TYPEDB unset) would make this test vacuous.
    assert "skipping" not in done.stderr, f"{module} skipped: {done.stderr.strip()}"


def _restore_planted_family() -> None:
    """Leave the graph as a plain loader run would.

    The planted family is an entity, not just an edge, so leaving the extras
    behind accumulates duplicate root_cause rows — the very condition the
    reconciling write exists to prevent. Deleting them all would go one BELOW a
    loader run, which legitimately creates one, so re-insert exactly that one.
    """
    driver_cm, settings, tx_type = _transaction("write")
    with driver_cm as driver, driver.transaction(settings.typedb_database, tx_type) as tx:
        tx.query(
            f'match $x isa {_STALE_FAMILY}, has subtype "{_STALE_FAMILY}"; delete $x;'
        ).resolve()
        tx.query(f'insert $x isa {_STALE_FAMILY}, has subtype "{_STALE_FAMILY}";').resolve()
        tx.commit()


@pytest.fixture(scope="module", autouse=True)
def _loaded_graph():
    for module in (
        "ontology.load_schema",
        "ontology.load_knowledge",
        "ontology.load_alerts",
        "ontology.load_known_issues",
    ):
        if module == "ontology.load_schema":
            subprocess.run([sys.executable, "-m", module], check=True, capture_output=True)
            continue
        _run_loader(module)
    yield
    _restore_planted_family()


def _first_alert_name() -> str:
    entries = yaml.safe_load((_KNOWLEDGE / "runai_alerts_catalog.yaml").read_text())
    return str(entries[0]["alert"])


def _first_known_issue_name() -> str:
    entries = yaml.safe_load((_KNOWLEDGE / "runai_known_issues.yaml").read_text())
    return str(entries[0]["issue"])


@pytest.mark.parametrize(
    ("module", "symptom_name"),
    [
        ("ontology.load_alerts", _first_alert_name),
        ("ontology.load_known_issues", _first_known_issue_name),
    ],
)
def test_loader_retires_a_stale_family_edge(module: str, symptom_name) -> None:
    """Both loaders used to carry the pre-reconcile copy of this write, so a
    family move left the old edge behind. They share the reconciling one now."""
    symptom = symptom_name()
    before = _families_for(symptom)
    assert before, f"{symptom!r} has no indicates edge; fixture did not load"
    assert _STALE_FAMILY not in before

    _plant_stale_edge(symptom)
    assert _STALE_FAMILY in _families_for(symptom), "could not plant the stale edge"

    _run_loader(module)

    after = _families_for(symptom)
    assert _STALE_FAMILY not in after, (
        f"{module} left a stale indicates edge on {symptom!r}: {sorted(after)} — "
        "the symptom now counts for two families in the ranker"
    )
    assert after == before, f"reconcile changed the real family too: {sorted(after)}"
