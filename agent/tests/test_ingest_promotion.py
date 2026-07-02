"""Tests for ontology/ingest.py --promote-knowledge (operator-confirmed RCA promotion).

No TypeDB / Postgres: TypeQL semantics are live-validated separately; here we test
the gating (row eligibility, family derivation, action extraction), the read-then-
insert idempotency contract, and that the flag defaults to off.
"""

from __future__ import annotations

import sys
from typing import Any

import ontology.ingest as ingest

# --- fakes -------------------------------------------------------------------


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def as_concept_rows(self) -> list[Any]:
        return self._rows


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def resolve(self) -> _Rows:
        return _Rows(self._rows)


class FakeTx:
    """Records every query; existence reads answer `exists`, inserts return empty."""

    def __init__(self, exists: bool) -> None:
        self.exists = exists
        self.queries: list[str] = []

    def query(self, q: str) -> _Result:
        self.queries.append(q)
        is_insert = q.lstrip().startswith("insert") or " insert " in q
        return _Result([] if is_insert or not self.exists else [object()])

    def inserts(self) -> list[str]:
        return [q for q in self.queries if q.lstrip().startswith("insert") or " insert " in q]


def _row(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "incident_id": "inc-1",
        "alert_id": "al-1",
        "status": "resolved",
        "positive_feedback": 2,
        "negative_feedback": 0,
        "labels": {"alertname": "KubeNodeDiskPressure", "node": "gpu-node-1"},
        "annotations": {},
        "analysis_summary": "Likely cause: node kubelet pressure on gpu-node-1.",
        "analysis_detail": (
            "## Root Cause\n\n- text\n\n## Recommended Actions\n\n"
            "- Free disk space on the node\n- Cordon and drain gpu-node-1\n"
            "- Raise the eviction threshold\n- A fourth action beyond the cap\n\n"
            "## Alert Labels\n\n- not an action\n"
        ),
    }
    base.update(overrides)
    return base


# --- family derivation ---------------------------------------------------------


def test_derive_family_label_is_decisive() -> None:
    assert ingest._derive_family("Likely cause: node kubelet pressure.") == (
        "node_kubelet_pressure"
    )
    assert ingest._derive_family("cause **workload startup/image failure** seen") == (
        "workload_startup_image_failure"
    )


def test_derive_family_keywords_need_two_hits_and_unique_winner() -> None:
    assert ingest._derive_family("pod ImagePullBackOff then CrashLoopBackOff") == (
        "workload_startup_image_failure"
    )
    # one weak hit only -> ambiguous
    assert ingest._derive_family("pod was oomkilled") == ""
    # empty / unrelated text
    assert ingest._derive_family("") == ""
    assert ingest._derive_family("everything is fine") == ""


# --- action extraction ----------------------------------------------------------


def test_extract_actions_caps_and_scopes_to_recommended_actions() -> None:
    actions = ingest._extract_actions(_row()["analysis_detail"])
    assert actions == [
        "Free disk space on the node",
        "Cordon and drain gpu-node-1",
        "Raise the eviction threshold",
    ]


def test_extract_actions_truncates_and_handles_missing_section() -> None:
    assert ingest._extract_actions("## Root Cause\n\n- no actions here") == []
    assert ingest._extract_actions("") == []
    long = "## Recommended Actions\n- " + "x" * 500
    assert len(ingest._extract_actions(long)[0]) == ingest._ACTION_MAXLEN


def test_extract_actions_matches_numbered_and_korean_headings() -> None:
    # The live report now emits numbered/Korean headings — both must still parse.
    assert ingest._extract_actions("## 3. Recommended Actions\n- do the thing") == [
        "do the thing"
    ]
    assert ingest._extract_actions("## 3. 권장 조치 (Recommended Actions)\n- 조치하기") == [
        "조치하기"
    ]


# --- row eligibility -------------------------------------------------------------


def test_promotion_from_row_happy_path() -> None:
    rec = ingest._promotion_from_row(_row())
    assert rec is not None
    alert_name, family, actions = rec
    assert alert_name == "KubeNodeDiskPressure"
    assert family == "node_kubelet_pressure"
    assert len(actions) == 3


def test_promotion_from_row_skips_malformed_rows() -> None:
    assert ingest._promotion_from_row(_row(status="firing")) is None
    assert ingest._promotion_from_row(_row(positive_feedback=1, negative_feedback=1)) is None
    assert ingest._promotion_from_row(_row(positive_feedback=0, negative_feedback=0)) is None
    # no alertname label -> resolve_target falls back to RunAIAlert -> skip
    assert ingest._promotion_from_row(_row(labels={}, annotations={})) is None
    # labels not valid JSON -> same fallback path, skipped, no raise
    assert ingest._promotion_from_row(_row(labels="{broken", annotations="")) is None
    # no recoverable family
    assert (
        ingest._promotion_from_row(_row(analysis_summary="fine", analysis_detail="fine")) is None
    )
    # feedback columns absent entirely (old rows) -> not promotable, no raise
    row = _row()
    del row["positive_feedback"], row["negative_feedback"]
    assert ingest._promotion_from_row(row) is None


# --- idempotency (read-then-insert contract) -------------------------------------


def test_promote_one_inserts_when_absent() -> None:
    tx = FakeTx(exists=False)
    ingest._promote_one(tx, "KubeNodeDiskPressure", "node_kubelet_pressure", ["Fix it"])
    inserts = tx.inserts()
    assert inserts, "expected inserts on an empty knowledge layer"
    assert any('"confirmed:KubeNodeDiskPressure"' in q for q in inserts)
    assert any('has keyword "kubenodediskpressure"' in q for q in inserts)
    assert any("isa indicates" in q for q in inserts)
    assert any("isa resolved_by" in q for q in inserts)


def test_promote_one_is_noop_when_everything_exists() -> None:
    tx = FakeTx(exists=True)
    ingest._promote_one(tx, "KubeNodeDiskPressure", "node_kubelet_pressure", ["Fix it"])
    assert tx.inserts() == []


# --- CLI gating -------------------------------------------------------------------


def test_flag_off_means_no_promotion(monkeypatch: Any) -> None:
    calls: list[str] = []

    async def fake_fetch(limit: int, grace: int = 0) -> list[dict[str, Any]]:
        return [_row()]

    monkeypatch.setattr(ingest, "_fetch", fake_fetch)
    monkeypatch.setattr(ingest, "_write", lambda incidents: (len(incidents), 0))
    monkeypatch.setattr(ingest, "_promote", lambda rows: calls.append("promote") or (1, 0))

    monkeypatch.setattr(sys, "argv", ["ingest", "--all"])
    assert ingest.main() == 0
    assert calls == []

    monkeypatch.setattr(sys, "argv", ["ingest", "--all", "--promote-knowledge"])
    assert ingest.main() == 0
    assert calls == ["promote"]
