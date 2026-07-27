"""schema.tql structural integrity — the unit tests never apply the schema to a
live TypeDB, so a `plays X:role` whose relation was never declared used to ship
undetected and fail the deployment's schema job (exposes/uses_storage, 2026-07-27).
"""

from __future__ import annotations

import re
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[1] / "ontology" / "schema.tql"


def _schema() -> str:
    return SCHEMA.read_text(encoding="utf-8")


def _relations(schema: str) -> dict[str, set[str]]:
    return {
        match.group(1): set(re.findall(r"relates (\w+)", match.group(2)))
        for match in re.finditer(r"^relation (\w+)((?:[^;]|\n)*);", schema, re.M)
    }


def test_every_played_relation_is_declared() -> None:
    schema = _schema()
    declared = set(_relations(schema))
    played = {match.group(1) for match in re.finditer(r"plays (\w+):", schema)}
    assert not (played - declared), f"plays references undeclared relation(s): {sorted(played - declared)}"


def test_every_played_role_exists_on_its_relation() -> None:
    schema = _schema()
    roles = _relations(schema)
    bad = [
        f"{relation}:{role}"
        for match in re.finditer(r"plays (\w+):(\w+)", schema)
        for relation, role in [(match.group(1), match.group(2))]
        if role not in roles.get(relation, set())
    ]
    assert not bad, f"plays references undeclared role(s): {bad}"


def test_every_owned_attribute_is_declared() -> None:
    schema = _schema()
    declared = {match.group(1) for match in re.finditer(r"^attribute (\w+)", schema, re.M)}
    owned = {match.group(1) for match in re.finditer(r"owns (\w+)", schema)}
    assert not (owned - declared), f"owns references undeclared attribute(s): {sorted(owned - declared)}"


def test_every_subtype_parent_exists() -> None:
    schema = _schema()
    types = {match.group(1) for match in re.finditer(r"^entity (\w+)", schema, re.M)}
    parents = {match.group(2) for match in re.finditer(r"^entity (\w+) sub (\w+)", schema, re.M)}
    assert not (parents - types), f"sub references undeclared parent(s): {sorted(parents - types)}"
