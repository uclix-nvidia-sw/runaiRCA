"""Export backend incidents into eval fixture skeletons.

The `expected` family is intentionally `TODO_LABEL`: a human should label it
before the line is moved into fixtures.jsonl or fixtures_holdout.jsonl.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from typing import Any

SECRET_RE = re.compile(
    r"(?i)(token|password|secret|api[_-]?key|authorization)([=:]\s*)[^\s,;]+"
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export RCA incidents as eval fixture skeletons.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--view", default="active", choices=("active", "archived", "trash"))
    parser.add_argument("--output", default="-", help="output JSONL path, or - for stdout")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    listing = _get_json(
        f"{base}/api/v1/incidents?{urllib.parse.urlencode({'limit': args.limit, 'view': args.view})}"
    )
    items = listing.get("data") if isinstance(listing, dict) else []
    lines = []
    for incident in items if isinstance(items, list) else []:
        incident_id = str(incident.get("incident_id") or "")
        if not incident_id:
            continue
        detail = _get_json(f"{base}/api/v1/incidents/{urllib.parse.quote(incident_id)}")
        data = detail.get("data") if isinstance(detail, dict) else {}
        fixture = _fixture_from_detail(data if isinstance(data, dict) else {})
        if fixture:
            lines.append(json.dumps(fixture, ensure_ascii=False, sort_keys=True))

    body = "\n".join(lines)
    if args.output == "-":
        print(body)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(body + ("\n" if body else ""))
    return 0


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - operator-supplied URL
        return json.loads(response.read().decode("utf-8"))


def _fixture_from_detail(detail: dict[str, Any]) -> dict[str, Any] | None:
    incident_id = str(detail.get("incident_id") or "")
    alerts = detail.get("alerts")
    if not incident_id or not isinstance(alerts, list) or not alerts:
        return None
    latest = alerts[0] if isinstance(alerts[0], dict) else {}
    labels = latest.get("labels") if isinstance(latest.get("labels"), dict) else {}
    annotations = latest.get("annotations") if isinstance(latest.get("annotations"), dict) else {}
    evidence = {
        "kubernetes": _mask(
            " ".join(
                str(part)
                for part in (
                    latest.get("analysis_summary"),
                    latest.get("analysis_detail"),
                    annotations.get("summary") if isinstance(annotations, dict) else "",
                )
                if part
            )
        )
    }
    return {
        "id": incident_id,
        "expected": "TODO_LABEL",
        "occurrence_count": int(latest.get("occurrence_count") or 0),
        "blast_radius_workloads": 0,
        "evidence": evidence,
        "labels": _mask_map(labels),
    }


def _mask_map(value: dict[str, Any]) -> dict[str, str]:
    return {str(key): _mask(str(item)) for key, item in value.items()}


def _mask(value: str) -> str:
    return SECRET_RE.sub(r"\1\2<redacted>", value)


if __name__ == "__main__":
    raise SystemExit(main())
