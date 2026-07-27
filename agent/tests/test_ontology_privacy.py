from __future__ import annotations

from typing import Any

from ontology import ingest
from ontology.incident import OntologyIncident


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


def test_ingest_masks_sensitive_evidence_before_typeql_write() -> None:
    tx = _Tx()
    inc = OntologyIncident(incident_id="INC-privacy", run_id="ANL-privacy")

    ingest._ensure_evidence(
        tx,
        inc,
        {
            "evidence_id": "E-privacy",
            "source": "loki",
            "summary": "Bearer abc123token from 10.42.0.7",
        },
    )

    emitted = "\n".join(tx.queries)
    assert "abc123token" not in emitted
    assert "10.42.0.7" not in emitted
    assert "[MASKED]" in emitted
