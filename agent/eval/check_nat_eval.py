from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _items(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        value = payload.get("eval_output_items") or payload.get("items") or []
        return value if isinstance(value, list) else []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NAT eval and enforce RCA family accuracy.")
    parser.add_argument("--min-avg", type=float, default=1.0)
    parser.add_argument("--config", default="configs/runai_rca_eval.yml")
    parser.add_argument("--output", default=".tmp/nat/runai_rca_eval/family_output.json")
    args = parser.parse_args()

    nat = Path(sys.executable).with_name("nat")
    cmd = [str(nat if nat.exists() else "nat"), "eval", "--config_file", args.config]
    subprocess.run(cmd, check=True)

    payload = json.loads(Path(args.output).read_text(encoding="utf-8"))
    average = float(payload.get("average_score", 0.0)) if isinstance(payload, dict) else 0.0
    false_assertions = 0
    for item in _items(payload):
        reasoning = item.get("reasoning") if isinstance(item.get("reasoning"), dict) else {}
        score = float(item.get("score") or 0.0)
        false_assertions += int(bool(reasoning.get("false_assertion")))
        if score < 1.0 or reasoning.get("false_assertion"):
            print(
                f"{item.get('id')}: score={score:g} reasoning="
                f"{json.dumps(reasoning, sort_keys=True)}"
            )

    print(f"average_score={average:.3f} false_assertions={false_assertions}")
    if average < args.min_avg:
        print(f"average score below threshold: {average:.3f} < {args.min_avg:.3f}", file=sys.stderr)
        return 1
    if false_assertions:
        print(f"false assertions above threshold: {false_assertions}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
