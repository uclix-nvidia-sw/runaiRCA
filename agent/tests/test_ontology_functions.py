from __future__ import annotations

from pathlib import Path

# The TypeQL itself is validated against a live TypeDB 3.11.5 (see functions.tql
# header) — not in CI. This guard just keeps the file present and well-formed so an
# accidental edit that drops a function or the `define` block is caught.


def test_functions_tql_defines_the_expected_functions() -> None:
    text = Path("ontology/functions.tql").read_text(encoding="utf-8")
    assert "define" in text
    for name in ("fixes_for_xid", "xids_for_gpu_model", "fixes_for_family"):
        assert f"fun {name}(" in text
        assert "return {" in text
