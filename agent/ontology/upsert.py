"""Idempotent TypeQL writes every knowledge loader needs.

These were copied into each loader — ``exists`` into six modules, ``ensure_action``
into five — and the copies had already drifted where it mattered: only
load_knowledge.py's ``indicates`` write reconciled stale edges, so moving a
symptom to another family in runai_alerts_catalog.yaml or runai_known_issues.yaml
left the old edge in the graph and the symptom counted for two families at once.
One implementation, so a fix lands everywhere it applies.
"""

from __future__ import annotations

from typing import Any

from app.ontology.typedb_client import _concept_value
from app.ontology.typedb_client import escape_typeql as esc


def exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def selected_values(tx: Any, match: str, variable: str) -> set[str]:
    rows = list(tx.query(f"match {match} select ${variable};").resolve().as_concept_rows())
    values: set[str] = set()
    for row in rows:
        get = getattr(row, "get", None)
        if not callable(get):
            continue
        concept = get(variable)
        if concept is None:
            continue
        value = str(_concept_value(concept)).strip()
        if value:
            values.add(value)
    return values


def ensure_family(tx: Any, family: str) -> None:
    if not exists(tx, f'$x isa {family}, has subtype "{esc(family)}";'):
        tx.query(f'insert $x isa {family}, has subtype "{esc(family)}";').resolve()


def ensure_action(tx: Any, statement: str) -> None:
    if not exists(tx, f'$x isa action, has statement "{esc(statement)}";'):
        tx.query(f'insert $x isa action, has statement "{esc(statement)}";').resolve()


def relate_symptom_indicates(tx: Any, symptom_name: str, family: str) -> None:
    """Point a symptom at exactly one family, dropping edges to any other.

    Purging only on the way in is not enough: a symptom that MOVED family keeps
    its previous ``indicates`` edge, which shows the operator the same guidance
    twice and counts the symptom for two families in the ranker.
    """
    current = selected_values(
        tx,
        "$rel isa indicates, links (symptom: $s, cause: $rc); "
        f'$s isa symptom, has name "{esc(symptom_name)}"; $rc has subtype $f;',
        "f",
    )
    for stale in sorted(current - {family}):
        tx.query(
            "match $rel isa indicates, links (symptom: $s, cause: $rc); "
            f'$s isa symptom, has name "{esc(symptom_name)}"; '
            f'$rc has subtype "{esc(stale)}"; delete $rel;'
        ).resolve()
    if family in current:
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(symptom_name)}"; $rc isa {family}; '
        "insert (symptom: $s, cause: $rc) isa indicates;"
    ).resolve()


def relate_symptom_resolved_by(tx: Any, symptom_name: str, statement: str) -> None:
    if exists(
        tx,
        f'$x isa symptom, has name "{esc(symptom_name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        "(symptom: $x, remedy: $a) isa resolved_by;",
    ):
        return
    tx.query(
        f'match $s isa symptom, has name "{esc(symptom_name)}"; '
        f'$a isa action, has statement "{esc(statement)}"; '
        "insert (symptom: $s, remedy: $a) isa resolved_by;"
    ).resolve()
