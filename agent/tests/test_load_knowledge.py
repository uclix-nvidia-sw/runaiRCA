from __future__ import annotations

from typing import Any

from ontology.load_knowledge import _ensure_symptom
from ontology.upsert import relate_symptom_indicates


class _Concept:
    def __init__(self, value: str) -> None:
        self.value = value

    def get_value(self) -> str:
        return self.value


class _Row:
    def __init__(self, keyword: str) -> None:
        self.keyword = keyword

    def get(self, name: str) -> _Concept:
        assert name == "kw"
        return _Concept(self.keyword)


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def resolve(self) -> _Result:
        return self

    def as_concept_rows(self) -> list[Any]:
        return self.rows


class _Tx:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, query: str) -> _Result:
        self.queries.append(query)
        if "select $kw;" in query:
            return _Result([_Row("A"), _Row("B")])
        if "select $x;" in query:
            if 'has keyword "C"' in query:
                return _Result([])
            return _Result([object()])
        return _Result([])


def test_ensure_symptom_reconciles_removed_keywords() -> None:
    tx = _Tx()

    _ensure_symptom(tx, "symptom-1", ["A", "C"])

    assert any('insert $s has keyword "C";' in query for query in tx.queries)
    assert any('$kw == "B"; delete has $kw of $s;' in query for query in tx.queries)
    assert not any('$kw == "A"; delete has $kw of $s;' in query for query in tx.queries)


class _ValueRow:
    def __init__(self, value: str) -> None:
        self.value = value

    def get(self, name: str) -> _Concept:
        assert name == "value"
        return _Concept(self.value)


class _AttributeTx(_Tx):
    def query(self, query: str) -> _Result:
        self.queries.append(query)
        if "select $value;" in query:
            return _Result([_ValueRow("old reason")])
        if "select $x;" in query:
            return _Result([])
        return _Result([])


def test_ensure_symptom_replaces_old_reason_before_inserting_new_value() -> None:
    tx = _AttributeTx()

    _ensure_symptom(tx, "symptom-1", [], reason="new reason")

    delete_index = next(
        index
        for index, query in enumerate(tx.queries)
        if "delete has $value of $s;" in query
    )
    insert_index = next(
        index
        for index, query in enumerate(tx.queries)
        if 'insert $s has reason "new reason";' in query
    )
    assert delete_index < insert_index


class _FamilyRow:
    def __init__(self, family: str) -> None:
        self.family = family

    def get(self, name: str) -> _Concept:
        assert name == "f"
        return _Concept(self.family)


class _IndicatesTx(_Tx):
    def __init__(self, families: list[str]) -> None:
        super().__init__()
        self.families = families

    def query(self, query: str) -> _Result:
        self.queries.append(query)
        if "select $f;" in query:
            return _Result([_FamilyRow(family) for family in self.families])
        return _Result([])


def test_relate_indicates_retires_the_stale_family_edge() -> None:
    # The live INC-1785128597 duplicate: OOMKilled moved workload_startup_error
    # -> workload_runtime_error in the YAML, but both families stayed in the
    # catalog, so purge never touched the old edge and the symptom matched twice.
    tx = _IndicatesTx(["workload_startup_error", "workload_runtime_error"])

    relate_symptom_indicates(tx, "OOMKilled", "workload_runtime_error")

    assert any(
        '$rc has subtype "workload_startup_error"; delete $rel;' in query
        for query in tx.queries
    )
    # The current edge already exists — no delete for it, no re-insert.
    assert not any(
        '$rc has subtype "workload_runtime_error"; delete $rel;' in query
        for query in tx.queries
    )
    assert not any("insert (symptom: $s, cause: $rc) isa indicates;" in q for q in tx.queries)


def test_relate_indicates_inserts_for_a_new_symptom() -> None:
    tx = _IndicatesTx([])

    relate_symptom_indicates(tx, "OOMKilled", "workload_runtime_error")

    assert not any("delete $rel;" in query for query in tx.queries)
    assert any("insert (symptom: $s, cause: $rc) isa indicates;" in q for q in tx.queries)


def test_alert_and_known_issue_loaders_retire_stale_family_edges() -> None:
    """The whole point of sharing relate_symptom_indicates: load_alerts.py and
    load_known_issues.py used to carry the pre-reconcile copy, so moving a
    symptom's family in runai_alerts_catalog.yaml / runai_known_issues.yaml left
    the old indicates edge behind and the symptom counted for two families."""
    from ontology import load_alerts, load_known_issues
    from ontology.upsert import relate_symptom_indicates as shared

    assert load_alerts.relate_symptom_indicates is shared
    assert load_known_issues.relate_symptom_indicates is shared
