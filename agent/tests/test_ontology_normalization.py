from __future__ import annotations

from typing import Any

from ontology import ingest
from ontology.normalization import confidence_score


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


class _ExistingEvidenceResult(_Result):
    def as_concept_rows(self) -> list[Any]:
        return [object()]


class _ExistingEvidenceTx(_Tx):
    def query(self, text: str) -> _Result:
        self.queries.append(text)
        if 'match $x isa evidence, has evidence_id "ANL-1:E-1"' in text:
            return _ExistingEvidenceResult()
        return _Result()


def test_confidence_mapping_and_evidence_projection() -> None:
    assert confidence_score("high") == 0.9
    assert confidence_score("medium") == 0.7
    assert confidence_score("low") == 0.4
    assert confidence_score("unknown") is None

    tx = _Tx()
    inc = type("Incident", (), {"run_id": "ANL-1"})()
    ingest._ensure_evidence(
        tx, inc, {"evidence_id": "E-1", "source": "prometheus", "confidence": "high"}
    )
    emitted = "\n".join(tx.queries)
    assert "isa metric_evidence" in emitted
    assert "has confidence_score 0.9" in emitted


def test_evidence_upsert_reuses_a_legacy_generic_evidence_entity() -> None:
    tx = _ExistingEvidenceTx()
    inc = type("Incident", (), {"run_id": "ANL-1"})()

    ingest._ensure_evidence(tx, inc, {"evidence_id": "E-1", "source": "kubernetes"})

    emitted = "\n".join(tx.queries)
    assert 'match $x isa evidence, has evidence_id "ANL-1:E-1"' in emitted
    assert "insert $x isa state_evidence" not in emitted


def test_iso_or_empty_rejects_non_utc_and_malformed_values() -> None:
    assert ingest._iso_or_empty("2026-07-27T00:00:00Z") == "2026-07-27T00:00:00Z"
    assert ingest._iso_or_empty("2026-07-27T09:00:00+09:00") == ""
    assert ingest._iso_or_empty("not-a-time") == ""


def test_schema_migrations_cover_new_keys_and_signal_supertype() -> None:
    from ontology.load_schema import DATA_MIGRATIONS, SCHEMA_MIGRATIONS

    assert "redefine symptom owns name @key;" in SCHEMA_MIGRATIONS
    assert "redefine action owns statement @key;" in SCHEMA_MIGRATIONS
    assert "redefine entity xid_error sub signal;" in SCHEMA_MIGRATIONS
    assert any("isa action" in query and "delete $y" in query for query in DATA_MIGRATIONS)
