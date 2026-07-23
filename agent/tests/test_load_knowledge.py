from __future__ import annotations

from typing import Any

from ontology.load_knowledge import _ensure_symptom


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
