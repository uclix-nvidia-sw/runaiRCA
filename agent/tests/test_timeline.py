from __future__ import annotations

from app.collectors.base import CollectorResult
from app.services.timeline import build_timeline, to_markdown


def test_empty_and_unknown_agents_yield_nothing() -> None:
    assert build_timeline([]) == []
    assert build_timeline([CollectorResult(agent="runai", status="ok", summary="")]) == []


def test_merges_and_orders_across_collectors() -> None:
    results = [
        CollectorResult(
            agent="change", status="ok", summary="",
            details={"changes": [
                {"timestamp": "2026-07-02T10:00:00Z", "kind": "PodCreated",
                 "summary": "Pod x created"},
            ]},
        ),
        CollectorResult(
            agent="kubernetes", status="ok", summary="",
            details={"warning_events": [
                {"lastTimestamp": "2026-07-02T10:02:00Z", "reason": "OOMKilling",
                 "message": "out of memory", "object": "x"},
            ]},
        ),
        CollectorResult(
            agent="loki", status="ok", summary="",
            details={"queries": [
                {"name": "error_logs", "sample": [
                    {"values": [["1782986460000000000", "CUDA error"]]},  # 2026-07-02 10:01:00Z
                ]},
            ]},
        ),
        CollectorResult(
            agent="system", status="ok", summary="",
            details={"sources": [
                {"source": "dmesg", "errors": ["2026-07-02T10:03:00Z NVRM: Xid 79"]},
            ]},
        ),
    ]
    timeline = build_timeline(results)
    order = [(e["source"], e["kind"]) for e in timeline]
    assert order == [
        ("change", "PodCreated"),
        ("loki", "error_logs"),
        ("kubernetes", "OOMKilling"),
        ("system", "dmesg"),
    ]
    assert timeline[1]["timestamp"].startswith("2026-07-02T10:01:00")  # loki ns -> iso


def test_unparseable_timestamps_sort_last_not_dropped() -> None:
    results = [
        CollectorResult(
            agent="system", status="ok", summary="",
            details={"sources": [{"source": "syslog", "errors": ["no timestamp here"]}]},
        ),
        CollectorResult(
            agent="change", status="ok", summary="",
            details={"changes": [
                {"timestamp": "2026-07-02T09:00:00Z", "kind": "X", "summary": "s"},
            ]},
        ),
    ]
    timeline = build_timeline(results)
    assert len(timeline) == 2
    assert timeline[0]["source"] == "change"
    assert timeline[-1]["message"] == "no timestamp here"  # kept, sorts last


def test_syslog_prefix_parsed() -> None:
    result = CollectorResult(
        agent="system", status="ok", summary="",
        details={"sources": [{"source": "journal", "errors": ["Jul  2 10:15:03 kernel: oom"]}]},
    )
    [entry] = build_timeline([result])
    assert entry["timestamp"] == "Jul  2 10:15:03"


def test_to_markdown_truncates() -> None:
    timeline = [
        {"timestamp": f"t{i}", "source": "s", "kind": "k", "message": "m"}
        for i in range(40)
    ]
    md = to_markdown(timeline, limit=5)
    assert "and 35 more" in md
    assert to_markdown([]).startswith("- No timestamped")


def test_bad_details_never_raises() -> None:
    # details not a dict / wrong-typed inner values must degrade, not throw.
    r = CollectorResult(agent="loki", status="ok", summary="", details={"queries": "nope"})
    assert build_timeline([r]) == []


def test_unavailable_collector_details_are_not_timeline_evidence() -> None:
    results = [
        CollectorResult(
            agent="kubernetes",
            status="unavailable",
            summary="kubectl failed",
            details={
                "warning_events": [
                    {
                        "lastTimestamp": "2026-07-02T10:02:00Z",
                        "reason": "Evicted",
                        "message": "DiskPressure",
                    },
                ],
            },
        ),
        CollectorResult(
            agent="loki",
            status="unavailable",
            summary="loki failed",
            details={
                "queries": [
                    {
                        "name": "errors",
                        "sample": [{"values": [["1782986460000000000", "CUDA error"]]}],
                    },
                ],
            },
        ),
    ]
    assert build_timeline(results) == []


def test_timeline_masks_sensitive_messages_at_capture() -> None:
    results = [
        CollectorResult(
            agent="loki",
            status="ok",
            summary="",
            details={
                "queries": [
                    {
                        "name": "errors",
                        "sample": [
                            {
                                "values": [
                                    [
                                        "1782986460000000000",
                                        "panic api_key=timeline-secret-12345",
                                    ]
                                ]
                            }
                        ],
                    }
                ]
            },
        )
    ]

    timeline = build_timeline(results)
    serialized = str(timeline)

    assert "timeline-secret-12345" not in serialized
    assert "[MASKED]" in serialized
    assert timeline[0]["message"] == "panic api_key=[MASKED]"


def test_timeline_markdown_masks_and_folds_raw_entries() -> None:
    md = to_markdown(
        [
            {
                "timestamp": "2026-07-02T10:00:00Z",
                "source": "loki",
                "kind": "errors",
                "message": "panic password=timeline-md-secret-12345\n## injected",
            }
        ]
    )

    assert "timeline-md-secret-12345" not in md
    assert "[MASKED]" in md
    assert "\n## injected" not in md
    assert "## injected" in md
