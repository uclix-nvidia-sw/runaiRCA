"""Offline eval for root-cause-candidate ranking.

Measures Top-1 / Top-3 hit-rate of `rank_root_cause_candidates` against labeled
fixtures (eval/fixtures.jsonl), plus a false-assertion count (confidently naming
the wrong family when the answer is insufficient_evidence).

This is the harness the plan calls for BEFORE trusting the KG: run it with the
KG blast-radius signal on (default) and off (--kg-off) to A/B the signal's
contribution. To grade against REAL incidents, append hold-out lines to
fixtures.jsonl (symptoms+alerts only, with the known `expected` family).

    ./.venv/bin/python -m eval.run_eval            # KG signal on
    ./.venv/bin/python -m eval.run_eval --kg-off   # KG signal off (baseline)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.collectors.base import AnalysisTarget, CollectorResult
from app.services.root_cause_ranking import rank_root_cause_candidates

FIXTURES = Path(__file__).resolve().parent / "fixtures.jsonl"

_EMPTY_TARGET = AnalysisTarget(
    cluster="", project="", queue="", namespace="", workload_name="",
    workload_type="", runai_workload_id="", node="", pod="", severity="", alert_name="",
)


def _results(fixture: dict, kg_on: bool) -> list[CollectorResult]:
    status = fixture.get("status", {})
    results = [
        CollectorResult(agent=agent, status=status.get(agent, "ok"), summary=text)
        for agent, text in fixture["evidence"].items()
    ]
    blast = int(fixture.get("blast_radius_workloads", 0))
    if kg_on and blast:
        results.append(
            CollectorResult(
                agent="typedb", status="ok", summary="kg",
                details={"blast_radius_workloads": blast},
            )
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Root-cause ranking eval.")
    parser.add_argument("--kg-off", action="store_true", help="drop the KG blast-radius signal")
    args = parser.parse_args()
    kg_on = not args.kg_off

    fixtures = [
        json.loads(line) for line in FIXTURES.read_text().splitlines() if line.strip()
    ]
    top1 = top3 = false_assert = 0
    for fx in fixtures:
        ranked = rank_root_cause_candidates(
            _EMPTY_TARGET, _results(fx, kg_on), occurrence_count=fx.get("occurrence_count", 0)
        )
        families = [c.family for c in ranked]
        expected = fx["expected"]
        hit1 = bool(ranked) and families[0] == expected
        hit3 = expected in families[:3]
        top1 += hit1
        top3 += hit3
        confidently_wrong = (
            bool(ranked)
            and expected == "insufficient_evidence"
            and families[0] != "insufficient_evidence"
            and ranked[0].confidence == "high"
        )
        false_assert += confidently_wrong
        mark = "OK " if hit1 else ("~3 " if hit3 else "MISS")
        got = families[0] if ranked else "(none)"
        print(f"  [{mark}] {fx['id']:<16} expected={expected:<28} got={got}")

    n = len(fixtures)
    print(
        f"\nKG signal: {'on' if kg_on else 'off'} | n={n} | "
        f"Top-1={top1}/{n} ({top1/n:.0%}) | Top-3={top3}/{n} ({top3/n:.0%}) | "
        f"false-assertions={false_assert}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
