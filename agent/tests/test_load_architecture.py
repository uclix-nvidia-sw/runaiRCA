from __future__ import annotations

from typing import Any

from ontology.load_architecture import _ensure_service


class _Result:
    def resolve(self) -> _Result:
        return self

    def as_concept_rows(self) -> list[Any]:
        return []


class _Tx:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, text: str) -> _Result:
        self.queries.append(text)
        return _Result()


def test_service_projection_seeds_namespace_workload_and_exposes_edge_idempotently() -> None:
    tx = _Tx()
    _ensure_service(tx, "runai-backend-nats", "runai-backend", "runai-backend-nats")
    emitted = "\n".join(tx.queries)
    assert 'isa service, has name "runai-backend-nats"' in emitted
    assert 'isa workload, has name "runai-backend-nats"' in emitted
    assert 'has namespace_name "runai-backend"' in emitted
    assert "(endpoint: $s, backend: $w) isa exposes" in emitted
    # Every insert has a prior match, so real re-runs see the edge and skip it.
    assert emitted.count("select $x;") == 3
