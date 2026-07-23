from __future__ import annotations

from types import SimpleNamespace

import pytest

from ontology.load_schema import _remove_trace_stop_reason


class _Concept:
    def get_label(self) -> str:
        return "trace_stop_reason"


class _Row:
    def get(self, _name: str) -> _Concept:
        return _Concept()


class _Result:
    def __init__(self, rows: list[_Row] | None = None) -> None:
        self._rows = rows or []

    def resolve(self) -> _Result:
        return self

    def as_concept_rows(self) -> list[_Row]:
        return self._rows


class _Transaction:
    def __init__(self, driver: _Driver, kind: str) -> None:
        self.driver = driver
        self.kind = kind

    def __enter__(self) -> _Transaction:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def query(self, query: str) -> _Result:
        self.driver.events.append((self.kind, query))
        if self.driver.fail_on_undefine and query == "undefine trace_stop_reason;":
            raise RuntimeError("schema cleanup failed")
        if query == "undefine trace_stop_reason;":
            self.driver.has_attribute = False
        if query == "match attribute $a; select $a;":
            return _Result([_Row()] if self.driver.has_attribute else [])
        return _Result()

    def commit(self) -> None:
        self.driver.events.append((self.kind, "commit"))


class _Driver:
    def __init__(self, *, has_attribute: bool, fail_on_undefine: bool = False) -> None:
        self.has_attribute = has_attribute
        self.fail_on_undefine = fail_on_undefine
        self.events: list[tuple[str, str]] = []

    def transaction(self, _database: str, kind: str) -> _Transaction:
        return _Transaction(self, kind)


_TRANSACTION_TYPE = SimpleNamespace(READ="read", WRITE="write", SCHEMA="schema")


def test_trace_stop_reason_cleanup_orders_data_before_schema_and_is_idempotent() -> None:
    driver = _Driver(has_attribute=True)

    _remove_trace_stop_reason(driver, "runai_rca", _TRANSACTION_TYPE)
    _remove_trace_stop_reason(driver, "runai_rca", _TRANSACTION_TYPE)

    queries = [query for _, query in driver.events]
    ownership_delete = queries.index(
        "match $r isa analysis_run, has trace_stop_reason $reason; "
        "delete has $reason of $r;"
    )
    instance_delete = queries.index(
        "match $reason isa trace_stop_reason; delete $reason;"
    )
    ownership_undefine = queries.index(
        "undefine owns trace_stop_reason from analysis_run;"
    )
    type_undefine = queries.index("undefine trace_stop_reason;")
    assert ownership_delete < instance_delete < ownership_undefine < type_undefine
    assert driver.has_attribute is False
    assert sum(
        query == "undefine trace_stop_reason;" for _, query in driver.events
    ) == 1


def test_trace_stop_reason_cleanup_is_noop_on_fresh_schema() -> None:
    driver = _Driver(has_attribute=False)

    _remove_trace_stop_reason(driver, "runai_rca", _TRANSACTION_TYPE)

    assert driver.events == [("read", "match attribute $a; select $a;")]


def test_trace_stop_reason_cleanup_does_not_hide_schema_failure() -> None:
    driver = _Driver(has_attribute=True, fail_on_undefine=True)

    with pytest.raises(RuntimeError, match="schema cleanup failed"):
        _remove_trace_stop_reason(driver, "runai_rca", _TRANSACTION_TYPE)
