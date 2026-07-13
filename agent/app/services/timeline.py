"""Merge timestamped signals across collectors into one time-ordered list.

Lets the synthesis narrate "T0 …, T0+2m …": we pull the events that carry a
timestamp out of each collector's details (kubernetes warning events, Loki log
lines, Prometheus samples, Postgres audit rows, system node log lines, and
change-detection events) and sort them by time.

Defensive by design — collectors vary in shape and timestamp format, and the
no-LLM test suite feeds sample CollectorResults, so every accessor tolerates
missing/odd values and simply skips what it cannot parse. Never raises.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.collectors.base import CollectorResult
from app.masking import Masker, build_masker

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
    masker = build_masker(())
    for result in results or []:
        if result.status not in ("ok", "partial"):
            continue
        try:
            entries.extend(_sanitize_entry(entry, masker) for entry in _from_result(result))
        except Exception:  # noqa: BLE001 - a bad collector shape never breaks the timeline
            continue
    entries.sort(key=lambda e: (_sort_key(e.get("timestamp")), e.get("source", "")))
    return entries


def to_markdown(timeline: list[dict], *, limit: int = 30) -> str:
    if not timeline:
        return "- No timestamped signals were correlated across collectors."
    lines = []
    masker = build_masker(())
    for entry in timeline[:limit]:
        ts = _clean_timestamp(entry.get("timestamp") or "unknown-time", masker)
        lines.append(
            f"- `{ts}` **{_clean(entry.get('source', '?'), masker, limit=80)}** "
            f"({_clean(entry.get('kind', 'event'), masker, limit=120)}): "
            f"{_clean(entry.get('message', ''), masker, limit=300)}"
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
    if agent == "prometheus":
        return _from_prometheus(details)
    if agent == "postgres":
        return _from_postgres(details)
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
        # Native Loki responses retain streams/values. grafana-mcp instead
        # commonly returns a flat [{timestamp, line, labels}] list; keep both
        # contracts on the causal timeline instead of treating successful MCP
        # log collection as timestamp-less context.
        for entry in _list(query.get("sample_entries")):
            entry = _dict(entry)
            line = _str(entry.get("line") or entry.get("message"))
            if not line:
                continue
            out.append(
                {
                    "timestamp": _timestamp_to_iso(entry.get("timestamp")),
                    "source": "loki",
                    "kind": str(name),
                    "message": line[:300],
                }
            )
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


def _from_prometheus(details: dict) -> list[dict]:
    """Project bounded metric samples into causal evidence.

    Prometheus range results are already compacted by the collector. Keeping
    returned samples makes an explicit zero/false visible beside events and
    logs, rather than leaving synthesis to infer it from extrema alone.
    """
    out = []
    for query in _list(details.get("queries")):
        query = _dict(query)
        name = str(query.get("name") or "prometheus")
        for series in _list(query.get("sample")):
            series = _dict(series)
            labels = _prometheus_labels(series.get("metric"))
            suffix = f" {{{labels}}}" if labels else ""
            for timestamp, value in _prometheus_pairs(series):
                out.append(
                    {
                        "timestamp": _timestamp_to_iso(timestamp),
                        "source": "prometheus",
                        "kind": name,
                        "message": f"{name}{suffix} = {value}",
                    }
                )
    return out


def _from_postgres(details: dict) -> list[dict]:
    """Add incident-window audit rows without exposing SQL or arbitrary schema."""
    out = []
    history = _dict(details.get("incident_history"))
    for table in _list(history.get("tables")):
        table = _dict(table)
        schema = _str(table.get("schema"))
        name = _str(table.get("table"))
        kind = f"audit.{schema + '.' if schema else ''}{name or 'history'}"
        for row in _list(table.get("rows")):
            row = _dict(row)
            timestamp = row.get("event_time")
            if not timestamp:
                continue
            fields = [
                f"{key}={_str(value)}"
                for key, value in sorted(row.items())
                if key != "event_time" and value not in (None, "")
            ]
            out.append(
                {
                    "timestamp": _timestamp_to_iso(timestamp),
                    "source": "postgres",
                    "kind": kind,
                    "message": "; ".join(fields)[:300] or "audit history record",
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


def _timestamp_to_iso(value: object) -> str:
    """Normalize Prometheus seconds and Loki nanoseconds while retaining RFC3339."""
    text = _str(value)
    try:
        numeric = float(text)
    except (TypeError, ValueError):
        return text
    # Loki uses nanoseconds, while Prometheus range samples use seconds.
    seconds = numeric / 1e9 if abs(numeric) >= 1e12 else numeric
    try:
        return datetime.fromtimestamp(seconds, tz=UTC).isoformat()
    except (ValueError, OSError, OverflowError):
        return text


def _prometheus_pairs(series: dict) -> list[tuple[object, object]]:
    values = series.get("values")
    if not isinstance(values, list):
        value = series.get("value")
        values = [value] if isinstance(value, list) else []
    return [
        (pair[0], pair[1])
        for pair in values
        if isinstance(pair, list) and len(pair) >= 2
    ]


def _prometheus_labels(raw: object) -> str:
    labels = _dict(raw)
    allowed = ("namespace", "pod", "container", "node", "condition", "phase", "project", "queue")
    return ", ".join(f"{key}={_str(labels[key])}" for key in allowed if labels.get(key))


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


def _sanitize_entry(entry: dict, masker: Masker) -> dict:
    return {
        "timestamp": _clean_timestamp(entry.get("timestamp"), masker),
        "source": _clean(entry.get("source"), masker, limit=80),
        "kind": _clean(entry.get("kind"), masker, limit=120),
        "message": _clean(entry.get("message"), masker, limit=300),
    }


def _clean_timestamp(value: object, masker: Masker) -> str:
    text = masker.mask_text(_str(value)).replace("\n", " ").replace("\r", " ")
    if len(text) <= 120:
        return text
    return text[:119].rstrip() + "…"


def _clean(value: object, masker: Masker, *, limit: int) -> str:
    text = " ".join(masker.mask_text(_str(value)).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


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
