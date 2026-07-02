"""Static guardrail for the TypeDB loaders, which have NO live-DB test coverage.

Every loader's `_exists(tx, match)` helper wraps the match as
`match {match} select $x;` — so the match snippet MUST bind `$x`. A copied
helper that bound `$s` instead shipped and crashed the schema-load Job on the
first live TypeDB run ([REP18] The variable 'x' was not available). This test
walks every `_exists(...)` call in every loader with the AST and fails offline
on the same class of mistake.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ONTOLOGY = Path(__file__).parents[1] / "ontology"
LOADERS = sorted(ONTOLOGY.glob("load_*.py")) + [ONTOLOGY / "ingest.py"]


def _literal_text(node: ast.AST) -> str:
    """Concatenated literal fragments of a string/f-string/concat expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_literal_text(v) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _literal_text(node.left) + _literal_text(node.right)
    return ""


def _exists_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_exists"
            and len(node.args) >= 2
        ):
            yield node


@pytest.mark.parametrize("path", LOADERS, ids=lambda p: p.name)
def test_every_exists_match_binds_dollar_x(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    checked = 0
    for call in _exists_calls(tree):
        text = _literal_text(call.args[1])
        if not text:
            continue  # non-literal match (built elsewhere) — out of scope
        checked += 1
        assert "$x" in text, (
            f"{path.name}:{call.lineno}: _exists() match does not bind $x — the "
            f"helper runs `match ... select $x;`, so this fails on a live TypeDB "
            f"with [REP18]. Match text: {text!r}"
        )
    if path.name.startswith("load_") and path.name not in (
        "load_schema.py",
        "load_functions.py",
    ):
        assert checked > 0, f"{path.name}: expected _exists() calls to check"