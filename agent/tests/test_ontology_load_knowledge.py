from __future__ import annotations

from typing import Any

from ontology.load_knowledge import purge_legacy_families


class _Concept:
    def __init__(self, value: str) -> None:
        self.value = value

    def get_value(self) -> str:
        return self.value


class _Row:
    def __init__(self, value: str) -> None:
        self.value = value

    def get(self, name: str) -> _Concept:
        assert name == "f"
        return _Concept(self.value)


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    def resolve(self) -> _Result:
        return self

    def as_concept_rows(self) -> list[Any]:
        return self.rows


class _Tx:
    def __init__(self, all_subtypes: list[str], cause_instance_subtypes: list[str]) -> None:
        self.all_subtypes = all_subtypes
        self.cause_instance_subtypes = cause_instance_subtypes
        self.queries: list[str] = []

    def query(self, query: str) -> _Result:
        self.queries.append(query)
        if "isa cause_instance" in query and "select $f;" in query:
            return _Result([_Row(value) for value in self.cause_instance_subtypes])
        if "isa root_cause" in query and "select $f;" in query:
            return _Result([_Row(value) for value in self.all_subtypes])
        return _Result([])


def test_purge_deletes_legacy_family_relations_before_entities(caplog) -> None:
    tx = _Tx(["image_pull_error", "legacy_family"], [])

    with caplog.at_level("WARNING"):
        purged = purge_legacy_families(tx, {"image_pull_error"})

    relation_delete = next(
        index for index, query in enumerate(tx.queries) if "delete $rel;" in query
    )
    entity_delete = next(
        index for index, query in enumerate(tx.queries) if "delete $rc;" in query
    )
    assert purged == ["legacy_family"]
    assert relation_delete < entity_delete
    assert "legacy_family" in caplog.text


def test_purge_exempts_cause_instance_and_catalog_families() -> None:
    tx = _Tx(
        ["image_pull_error", "legacy_family", "incident_only_family"],
        ["incident_only_family"],
    )

    purged = purge_legacy_families(tx, {"image_pull_error"})

    assert purged == ["legacy_family"]
    delete_queries = [query for query in tx.queries if "delete" in query]
    assert all("image_pull_error" not in query for query in delete_queries)
    assert all("incident_only_family" not in query for query in delete_queries)


def test_purge_noop_when_graph_clean(caplog) -> None:
    tx = _Tx(["image_pull_error", "incident_only_family"], ["incident_only_family"])

    with caplog.at_level("WARNING"):
        purged = purge_legacy_families(tx, {"image_pull_error"})

    assert purged == []
    assert not any("delete" in query for query in tx.queries)
    assert "purged legacy families" not in caplog.text
