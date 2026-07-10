"""Evaluate root-cause ranking on vocabulary-held-out RCA scenarios.

The fixtures deliberately avoid catalog-family labels in their evidence.  This
does not replace end-to-end LLM evaluation; it prevents a keyword-only change
from looking good merely because its answer label appears in the prompt.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.collectors.base import AnalysisTarget, CollectorResult
from app.services.root_cause_ranking import merge_open_world_candidates, rank_root_cause_candidates

DEFAULT_FIXTURES = Path(__file__).with_name("ood_cases.jsonl")
_TARGET = AnalysisTarget(
    cluster="", project="", queue="", namespace="", workload_name="", workload_type="",
    runai_workload_id="", node="", pod="", severity="", alert_name="",
)


def _fixtures(path: Path) -> list[dict]:
    fixtures = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for fixture in fixtures:
        expected = str(fixture.get("expected") or "")
        if expected and any(expected.lower() in str(text).lower() for text in fixture.get("evidence", {}).values()):
            raise ValueError(f"{fixture.get('id', '<unknown>')}: expected family leaked into evidence")
    return fixtures


def main() -> int:
    parser = argparse.ArgumentParser(description="Vocabulary-held-out RCA ranking evaluation.")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--min-top1", type=float, default=0.0)
    args = parser.parse_args()
    fixtures = _fixtures(args.fixtures)
    if not fixtures:
        raise SystemExit("no OOD fixtures")
    hits = layer_hits = false_novel = ranked_cases = 0
    gate_hits = gate_cases = 0
    for fixture in fixtures:
        results = [CollectorResult(agent=agent, status="ok", summary=text) for agent, text in fixture["evidence"].items()]
        ranked = rank_root_cause_candidates(_TARGET, results)
        top = ranked[0] if ranked else None
        expected = str(fixture.get("expected") or "")
        if expected:
            ranked_cases += 1
            hits += bool(top and top.family == expected)
            layer_hits += bool(top and top.subsystem == fixture.get("expected_layer", top.subsystem))
            false_novel += bool(top and top.family.startswith("novel_") and expected != top.family)
            print(f"{fixture['id']}: expected={expected} got={top.family if top else '(none)'}")

        hypothesis = fixture.get("novel_hypothesis")
        if isinstance(hypothesis, dict):
            raw_groups = fixture.get("fact_groups")
            groups = raw_groups if isinstance(raw_groups, dict) else {}
            merged = merge_open_world_candidates(
                ranked,
                [hypothesis],
                fact_groups={str(key): str(value) for key, value in groups.items()},
                enabled=True,
            )
            admitted = any(candidate.novelty == "open_world" for candidate in merged)
            want_admitted = bool(fixture.get("expect_novel"))
            gate_cases += 1
            gate_hits += admitted == want_admitted
            print(f"{fixture['id']}: novel_expected={want_admitted} admitted={admitted}")

    rate = hits / ranked_cases if ranked_cases else 1.0
    layer_rate = layer_hits / ranked_cases if ranked_cases else 1.0
    print(
        f"OOD n={ranked_cases} top1={rate:.0%} layer={layer_rate:.0%} false_novel={false_novel}; "
        f"open_world_gates n={gate_cases} pass={gate_hits}/{gate_cases}"
    )
    return 0 if rate >= args.min_top1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
