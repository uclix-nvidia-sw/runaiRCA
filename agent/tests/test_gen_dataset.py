"""Tests for eval/gen_dataset.py — the deterministic RCA dataset generator.

No DB / no LLM: synthetic generation, the confirmed approved/pending split, dedup,
and the curated-merge preservation invariant are all pure and tested from fixtures.
"""

from __future__ import annotations

import json
from typing import Any

import eval.gen_dataset as gen

# --- fixtures ----------------------------------------------------------------

_XID_CATALOG: dict[str, Any] = {
    "xids": [
        {"code": 79, "mnemonic": "FALLEN_OFF_THE_BUS", "description": "GPU fell off bus", "gpu_models": ["A100"]},
        {"code": 48, "mnemonic": "DBE", "description": "Double bit ECC"},
        {"code": None, "mnemonic": "IGNORED"},  # no code -> skipped
    ]
}

_FAILURE_MODES: list[dict[str, Any]] = [
    {
        "family": "workload_startup_error",
        "symptoms": [
            {"name": "CrashLoopBackOff", "keywords": ["crashloopbackoff", "back-off restarting"]},
            {"name": "NoKeywords", "keywords": []},  # skipped
        ],
    },
    {"family": "", "symptoms": [{"name": "X", "keywords": ["y"]}]},  # no family -> skipped
]

_KNOWN_ISSUES: list[dict[str, Any]] = [
    {
        "issue": "Scheduler Reclaim Panic",
        "family": "platform_version_bug",
        "keywords": ["reclaim.go", "runtime/panic.go"],
        "affected_version": "<=2.22.43",
    },
    {"issue": "NoFamily", "family": "", "keywords": ["z"]},  # skipped
]


def _db_row(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "incident_id": "inc-1",
        "root_cause_family": "gpu_hardware_error",
        "labels": {"alertname": "NVRMXidCritical", "node": "dgx-1"},
        "annotations": {"summary": "Xid 79 fell off the bus"},
        "fingerprint": "fp-inc-1",
        "user_approved_at": "",
    }
    base.update(overrides)
    return base


# --- synthetic ---------------------------------------------------------------

def test_gen_xid_rows_maps_every_code_to_gpu_family() -> None:
    rows = gen.gen_xid_rows(_XID_CATALOG)
    assert len(rows) == 2  # code=None skipped
    assert {r["answer"]["expected_family"] for r in rows} == {"gpu_hardware_error"}
    by_id = {r["id"]: r for r in rows}
    assert "synthetic:xid-79" in by_id
    assert by_id["synthetic:xid-79"]["question"]["alert"]["labels"]["alertname"] == "NVRMXidCritical"
    assert "79" in by_id["synthetic:xid-79"]["question"]["alert"]["annotations"]["summary"]


def test_gen_failure_mode_rows_embeds_keyword_and_skips_empty() -> None:
    rows = gen.gen_failure_mode_rows(_FAILURE_MODES)
    assert len(rows) == 1  # NoKeywords + empty-family skipped
    row = rows[0]
    assert row["answer"]["expected_family"] == "workload_startup_error"
    assert "crashloopbackoff" in row["question"]["alert"]["annotations"]["summary"].lower()
    assert row["id"] == "synthetic:workload-startup-error-crashloopbackoff"


def test_gen_known_issue_rows_maps_family() -> None:
    rows = gen.gen_known_issue_rows(_KNOWN_ISSUES)
    assert len(rows) == 1
    assert rows[0]["answer"]["expected_family"] == "platform_version_bug"
    assert "2.22.43" in rows[0]["question"]["alert"]["annotations"]["description"]


def test_build_synthetic_is_sorted_and_idempotent() -> None:
    a = gen.build_synthetic(_XID_CATALOG, _FAILURE_MODES, _KNOWN_ISSUES)
    b = gen.build_synthetic(_XID_CATALOG, _FAILURE_MODES, _KNOWN_ISSUES)
    assert a == b  # deterministic
    assert [r["id"] for r in a] == sorted(r["id"] for r in a)


# --- confirmed ---------------------------------------------------------------

def test_build_confirmed_splits_on_user_approved_at() -> None:
    approved, pending = gen.build_confirmed(
        [
            _db_row(incident_id="a", user_approved_at="2026-01-01T00:00:00Z"),
            _db_row(incident_id="b", user_approved_at=""),
        ]
    )
    assert [r["id"] for r in approved] == ["confirmed:a"]
    assert [r["id"] for r in pending] == ["confirmed:b"]
    assert approved[0]["meta"]["approved"] is True
    assert pending[0]["meta"]["approved"] is False


def test_build_confirmed_skips_weak_rows() -> None:
    approved, pending = gen.build_confirmed(
        [
            _db_row(incident_id="c", root_cause_family=""),  # no family
            _db_row(incident_id="d", root_cause_family="insufficient_evidence"),
            _db_row(incident_id="e", labels={}, annotations={}),  # RunAIAlert fallback
        ]
    )
    assert approved == []
    assert pending == []


def test_build_confirmed_uses_real_labels_and_family() -> None:
    approved, _ = gen.build_confirmed(
        [_db_row(incident_id="f", root_cause_family="runai_scheduling_quota", user_approved_at="t")]
    )
    assert approved[0]["answer"]["expected_family"] == "runai_scheduling_quota"
    assert approved[0]["question"]["alert"]["labels"]["node"] == "dgx-1"  # preserved


# --- curated merge -----------------------------------------------------------

def test_merge_curated_preserves_hand_rows_and_refreshes_confirmed() -> None:
    hand = {
        "id": "xid-79-hand",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "NVRMXidCritical"}, "annotations": {"summary": "hand"}, "fingerprint": "fp-h"}},
        "answer": {"expected_family": "gpu_hardware_error"},
    }
    stale_confirmed = {
        "id": "confirmed:old",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "X"}, "annotations": {"summary": "old"}, "fingerprint": "fp-o"}},
        "answer": {"expected_family": "workload_startup_error"},
        "meta": {"source": "confirmed"},
    }
    new_confirmed = {
        "id": "confirmed:new",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "Y"}, "annotations": {"summary": "new"}, "fingerprint": "fp-n"}},
        "answer": {"expected_family": "image_pull_error"},
        "meta": {"source": "confirmed", "approved": True},
    }
    merged = gen.merge_curated([hand, stale_confirmed], [new_confirmed])
    ids = [r["id"] for r in merged]
    assert "xid-79-hand" in ids  # hand row preserved
    assert "confirmed:old" not in ids  # stale generator row dropped
    assert "confirmed:new" in ids  # current approved row added
    assert ids[0] == "xid-79-hand"  # hand rows keep original order (first)


def test_merge_curated_hand_row_wins_signature_conflict() -> None:
    hand = {
        "id": "hand-dup",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "NVRMXidCritical"}, "annotations": {"summary": "dup"}, "fingerprint": "fp-h"}},
        "answer": {"expected_family": "gpu_hardware_error"},
    }
    # same signature (alertname+family+annotation text) as the hand row
    confirmed_dup = {
        "id": "confirmed:dup",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "NVRMXidCritical"}, "annotations": {"summary": "dup"}, "fingerprint": "fp-c"}},
        "answer": {"expected_family": "gpu_hardware_error"},
        "meta": {"source": "confirmed", "approved": True},
    }
    merged = gen.merge_curated([hand], [confirmed_dup])
    assert [r["id"] for r in merged] == ["hand-dup"]  # confirmed dup suppressed


# --- durable store round-trip ------------------------------------------------

def test_dataset_params_flattens_row() -> None:
    approved, _ = gen.build_confirmed(
        [_db_row(incident_id="z", root_cause_family="image_pull_error", user_approved_at="t")]
    )
    params = gen._dataset_params(approved[0])
    dataset_id, source, origin, incident_id, alertname, family, question_json, is_approved = params
    assert dataset_id == "confirmed:z"
    assert source == "confirmed"
    assert incident_id == "z"  # parsed out of origin "incident:z"
    assert family == "image_pull_error"
    assert is_approved is True
    assert "alert" in json.loads(question_json)


def test_row_from_db_reconstructs_row() -> None:
    rec = {
        "dataset_id": "confirmed:q",
        "source": "confirmed",
        "origin": "incident:q",
        "expected_family": "gpu_hardware_error",
        "question": {"alert": {"status": "firing", "labels": {"alertname": "NVRMXidCritical"}, "annotations": {}, "fingerprint": "fp"}},
        "approved": True,
    }
    row = gen._row_from_db(rec)
    assert row["id"] == "confirmed:q"
    assert row["answer"]["expected_family"] == "gpu_hardware_error"
    assert row["meta"]["approved"] is True
    # accepts jsonb returned as a string too
    rec_str = dict(rec, question=json.dumps(rec["question"]))
    assert gen._row_from_db(rec_str)["question"]["alert"]["labels"]["alertname"] == "NVRMXidCritical"


def test_dataset_params_and_row_from_db_are_consistent() -> None:
    approved, _ = gen.build_confirmed(
        [_db_row(incident_id="rt", root_cause_family="node_kubelet_pressure", user_approved_at="t")]
    )
    p = gen._dataset_params(approved[0])
    rec = {
        "dataset_id": p[0], "source": p[1], "origin": p[2],
        "expected_family": p[5], "question": p[6], "approved": p[7],
    }
    back = gen._row_from_db(rec)
    assert back["id"] == approved[0]["id"]
    assert back["answer"] == approved[0]["answer"]
    assert back["question"] == approved[0]["question"]

