"""`load_schema._wait_until_ready`: the self-healing TypeDB readiness wait.

Live-TypeDB verification of the Helm schema job found that its initContainer
only proves a TCP connect to typedb:1729 succeeds -- the TypeDB JVM opens that
port before the query engine/auth can actually create a database or commit a
schema transaction, so on a cold start the first job attempt could fail and
burn a chart backoffLimit retry. The fix is a bounded, capped-backoff retry at
the loader's own entry point. These tests fake `open_driver` and the clock, so
they run fully offline (no TypeDB, no docker, no sleeping).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ontology import load_schema

_SETTINGS = SimpleNamespace(typedb_database="runai_rca", typedb_address="typedb:1729")


class _FakeDriverCM:
    """Minimal stand-in for what `open_driver(settings)` returns."""

    def __enter__(self) -> _FakeDriverCM:
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        return False

    @property
    def databases(self) -> _FakeDriverCM:
        return self

    def contains(self, name: str) -> bool:
        return True


def _flaky_open_driver(fail_times: int, exc_cls: type[Exception] = RuntimeError) -> Any:
    """`open_driver` fake: raises on the first `fail_times` calls, then succeeds."""
    calls = {"n": 0}

    def fake(settings: Any) -> _FakeDriverCM:
        calls["n"] += 1
        if calls["n"] <= fail_times:
            raise exc_cls(f"not ready yet ({calls['n']})")
        return _FakeDriverCM()

    fake.calls = calls
    return fake


def test_wait_until_ready_retries_then_succeeds(monkeypatch: Any) -> None:
    fake = _flaky_open_driver(fail_times=2)
    monkeypatch.setattr(load_schema, "open_driver", fake)
    sleeps: list[float] = []
    monkeypatch.setattr(load_schema.time, "sleep", lambda s: sleeps.append(s))

    assert load_schema._wait_until_ready(_SETTINGS, budget_seconds=90.0) is True
    assert fake.calls["n"] == 3
    assert sleeps == [1.0, 2.0]


def test_wait_until_ready_succeeds_first_try_sleeps_never_called(monkeypatch: Any) -> None:
    fake = _flaky_open_driver(fail_times=0)
    monkeypatch.setattr(load_schema, "open_driver", fake)
    sleeps: list[float] = []
    monkeypatch.setattr(load_schema.time, "sleep", lambda s: sleeps.append(s))

    assert load_schema._wait_until_ready(_SETTINGS, budget_seconds=90.0) is True
    assert fake.calls["n"] == 1
    assert sleeps == []


def test_wait_until_ready_exhausts_budget_and_returns_false(monkeypatch: Any) -> None:
    """A server that never becomes ready must give up within the budget, and
    never sleep past the remaining time (fake clock advances 1s per call: the
    second sleep would naturally be 2s but only 1s of budget is left)."""
    fake = _flaky_open_driver(fail_times=10**6)  # always raises
    monkeypatch.setattr(load_schema, "open_driver", fake)
    sleeps: list[float] = []
    monkeypatch.setattr(load_schema.time, "sleep", lambda s: sleeps.append(s))

    clock = {"t": 0.0}

    def fake_monotonic() -> float:
        value = clock["t"]
        clock["t"] += 1.0
        return value

    monkeypatch.setattr(load_schema.time, "monotonic", fake_monotonic)

    assert load_schema._wait_until_ready(_SETTINGS, budget_seconds=3.0) is False
    assert fake.calls["n"] == 3
    assert sleeps == [1.0, 1.0]
    assert all(s <= 3.0 for s in sleeps)


def test_main_gives_up_without_touching_typedb_when_never_ready(monkeypatch: Any) -> None:
    """main() must exit nonzero on a readiness timeout without ever reaching the
    schema-apply block (no `open_driver` call for the real work)."""
    monkeypatch.setattr(load_schema, "_wait_until_ready", lambda settings: False)

    def _boom(settings: Any) -> Any:
        raise AssertionError("main() must not open a driver for schema work after timeout")

    monkeypatch.setattr(load_schema, "open_driver", _boom)

    assert load_schema.main() == 1
