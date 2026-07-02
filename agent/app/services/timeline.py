"""Merge timestamped signals across collectors into one time-ordered list.

Lets the synthesis narrate "T0 …, T0+2m …": we pull the events that carry a
timestamp out of each collector's details (kubernetes warning events, loki log
lines, system node log lines, change-detection events) and sort them by time.

Defensive by design — collectors vary in shape and timestamp format, and the
no-LLM test suite feeds sample CollectorResults, so every accessor tolerates
missing/odd values and simply skips what it cannot parse. Never raises.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.collectors.base import CollectorResult

# Leading timestamp on a raw kernel/host log line, e.g.
# "2026-07-02T10:15:03Z ...", "Jul  2 10:15:03 ...", or "[ 1234.56] ...".
_ISO_PREFIX = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_SYSLOG_PREFIX = re.compile(r"^\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def build_timeline(results: list[CollectorResult]) -> list[dict]:
    """Return timestamped signals across all collectors, oldest first.

    Each entry: {"timestamp": iso-or-raw str, "source": collector, "kind": str,
    "message": str}. Entries whose timestamp we cannot parse are kept but sort
    last (stable) so nothing is silently dropped.
    """
    entries: list[dict] = []
    for result in results or []:
        try:
            entries.extend(_from_result(result))
        except Exception:  # noqa: BLE001 - a bad collector shape never breaks the timeline
            continue
    entries.sort(key=lambda e: (_sort_key(e.get("timestamp")), e.get("source", "")))
    return entries


def to_markdown(timeline: list[dict], *, limit: int = 30) -> str:
    if not timeline:
        return "- No timestamped signals were correlated across collectors."
    lines = []
    for entry in timeline[:limit]:
        ts = entry.get("timestamp") or "unknown-time"
        lines.append(
            f"- `{ts}` **{entry.get('source', '?')}** "
            f"({entry.get('kind', 'event')}): {entry.get('message', '')}"
        )
    if len(timeline) > limit:
        lines.append(f"- … and {len(timeline) - limit} more signal(s)")
    return "\n".join(lines)


def _from_result(result: CollectorResult) -> list[dict]:
    agent = result.agent
    details = result.details or {}
    if agent == "change":
        return _from_change(details)
    if agent == "kubernetes":
        return _from_kubernetes(details)
    if agent == "loki":
        return _from_loki(details)
    if agent == "system":
        return _from_system(details)
    return []


def _from_change(details: dict) -> list[dict]:
    out = []
    for change in _list(details.get("changes")):
        change = _dict(change)
        out.append(
            {
                "timestamp": _str(change.get("timestamp")),
                "source": "change",
                "kind": str(change.get("kind") or "change"),
                "message": _str(change.get("summary")),
            }
        )
    return out


def _from_kubernetes(details: dict) -> list[dict]:
    out = []
    for event in _list(details.get("warning_events")):
        event = _dict(event)
        ts = event.get("lastTimestamp") or event.get("eventTime")
        reason = event.get("reason") or "Event"
        message = event.get("message") or ""
        obj = event.get("object")
        out.append(
            {
                "timestamp": _str(ts),
                "source": "kubernetes",
                "kind": str(reason),
                "message": f"{obj + ': ' if obj else ''}{message}".strip(),
            }
        )
    return out


def _from_loki(details: dict) -> list[dict]:
    out = []
    for query in _list(details.get("queries")):
        query = _dict(query)
        name = query.get("name") or "loki"
        for stream in _list(query.get("sample")):
            for pair in _list(_dict(stream).get("values")):
                if not isinstance(pair, list) or len(pair) < 2:
                    continue
                out.append(
                    {
                        "timestamp": _loki_ns_to_iso(pair[0]),
                        "source": "loki",
                        "kind": str(name),
                        "message": _str(pair[1])[:300],
                    }
                )
    return out


def _from_system(details: dict) -> list[dict]:
    out = []
    for source in _list(details.get("sources")):
        source = _dict(source)
        label = source.get("source") or "system"
        for line in _list(source.get("errors")):
            line = _str(line)
            out.append(
                {
                    "timestamp": _timestamp_from_line(line),
                    "source": "system",
                    "kind": str(label),
                    "message": line[:300],
                }
            )
    return out


def _loki_ns_to_iso(value: object) -> str:
    """Loki stream timestamps are unix-nanosecond strings; keep raw on failure."""
    try:
        seconds = int(str(value)) / 1e9
        return datetime.fromtimestamp(seconds, tz=UTC).isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        return _str(value)


def _timestamp_from_line(line: str) -> str:
    match = _ISO_PREFIX.match(line) or _SYSLOG_PREFIX.match(line)
    return match.group(1) if match else ""


def _sort_key(ts: object) -> tuple[int, float, str]:
    """Sort parsed times chronologically; unparseable/empty go last (stable)."""
    text = _str(ts)
    if not text:
        return (1, 0.0, "")
    parsed = _parse(text)
    if parsed is None:
        return (1, 0.0, text)
    return (0, parsed.timestamp(), text)


def _parse(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        # Syslog "Jul  2 10:15:03" (no year) — assume current year, UTC.
        try:
            parsed = datetime.strptime(text, "%b %d %H:%M:%S").replace(
                year=datetime.now(UTC).year
            )
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))
