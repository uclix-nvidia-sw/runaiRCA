"""xid_catalog.yaml shape checks — no live TypeDB.

Guards the generated data file: it must parse, carry the expected fields, keep
the well-known GPU-failure XIDs, and resolve action text for the buckets those
XIDs reference. The exact codes below were verified against the parsed xlsx.
"""

from __future__ import annotations

from pathlib import Path

import yaml

CATALOG = Path(__file__).resolve().parents[1] / "knowledge" / "xid_catalog.yaml"

# Well-known GPU hardware faults, verified present in the parsed catalog.
KNOWN_XIDS = {
    31: "GPU memory page fault",          # MMU / page fault
    48: "Double Bit ECC Error",           # double-bit ECC
    74: "NVLINK Error",                    # NVLink
    79: "GPU has fallen off the bus",      # fell off the bus
    95: "Uncontained memory error",        # uncontained ECC
}


def _load() -> dict:
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8"))


def test_parses_and_has_shape() -> None:
    data = _load()
    assert isinstance(data, dict)
    xids = data["xids"]
    buckets = data["resolution_buckets"]
    assert isinstance(xids, list) and len(xids) > 50
    assert isinstance(buckets, dict) and buckets

    for x in xids:
        assert isinstance(x["code"], int)
        assert x["mnemonic"] and isinstance(x["mnemonic"], str)
        assert x["description"] and x["description"].lower() != "unused"
        assert x["severity"] in {"fatal", "non-fatal"}
        assert isinstance(x["gpu_models"], list)
        assert all(m in {"A100", "H100", "B100", "GB200"} for m in x["gpu_models"])
        assert "immediate_action" in x and "investigatory_action" in x


def test_known_gpu_failure_xids_present() -> None:
    by_code = {x["code"]: x for x in _load()["xids"]}
    for code, desc_substr in KNOWN_XIDS.items():
        assert code in by_code, f"missing well-known XID {code}"
        assert desc_substr.lower() in by_code[code]["description"].lower()

    # "GPU has fallen off the bus" must be fatal and apply to the data-center GPUs.
    x79 = by_code[79]
    assert x79["severity"] == "fatal"
    assert {"A100", "H100"} <= set(x79["gpu_models"])


def test_leads_to_causal_edges() -> None:
    by_code = {x["code"]: x for x in _load()["xids"]}

    for code, x in by_code.items():
        edges = x.get("leads_to")
        if edges is None:
            continue
        assert isinstance(edges, list) and edges
        assert all(isinstance(e, int) for e in edges)
        assert code not in edges, f"XID {code} leads_to itself"
        assert len(edges) == len(set(edges)), f"XID {code} leads_to has duplicates"

    # sheet1 "Xid 154 linkage": these faults escalate to XID 154.
    for code in (48, 79, 95, 144):
        assert 154 in by_code[code]["leads_to"], f"XID {code} must lead to 154"
    # sheet2 "Xid 144-150 Decode": NVLink faults lead to ECC/app-crash XIDs.
    assert {45, 48, 94, 95} <= set(by_code[144]["leads_to"])
    assert 48 in by_code[146]["leads_to"]
    # linkage_note carries the raw sheet1 text.
    assert "driver" in by_code[48]["linkage_note"].lower()


def test_resolution_buckets_resolve_action_text() -> None:
    data = _load()
    buckets = data["resolution_buckets"]
    # A concrete class resolves to human-readable guidance.
    assert "support" in buckets["CONTACT_SUPPORT"].lower()

    # Every XID's immediate action names a bucket that either resolves to text
    # or is itself the guidance (freeform actions aren't in the buckets map).
    for x in data["xids"]:
        bucket = x["immediate_action"]
        if not bucket:
            continue
        resolved = buckets.get(bucket, bucket)
        assert isinstance(resolved, str) and resolved.strip()
