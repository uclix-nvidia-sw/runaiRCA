"""Mirror the executable Kubernetes troubleshooting runbook into TypeDB.

The YAML remains the version-controlled authoring source. Runtime analysis reads
the TypeDB projection first and uses the YAML walker only when TypeDB is disabled
or unavailable.

    ENABLE_TYPEDB=true TYPEDB_ADDRESS=localhost:1729 \
        python -m ontology.load_troubleshooting

The loader replaces one named runbook atomically, so removed YAML nodes/edges do
not linger as stale graph facts.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from app.config import load_settings
from app.ontology.typedb_client import escape_typeql as esc
from app.ontology.typedb_client import open_driver
from app.services.decision_tree import load_tree
from ontology.load_knowledge import FAMILIES

RUNBOOK_NAME = "k8s-senior-troubleshooting"
TREE_FILE = Path(
    os.getenv("K8S_TROUBLESHOOTING_TREE_FILE", "knowledge/k8s_troubleshooting_tree.yaml")
)


def _exists(tx: Any, match: str) -> bool:
    return bool(list(tx.query(f"match {match} select $x;").resolve().as_concept_rows()))


def _condition(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _document(path: Path = TREE_FILE) -> dict[str, Any] | None:
    tree = load_tree(path)
    if tree is None:
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return None
    return raw


def _delete_existing(tx: Any, runbook: str) -> None:
    name = esc(runbook)
    # Delete step-owned relations before their players. Every transition's prior
    # step belongs to this runbook, so the first query covers all of its edges.
    for relation, role in (
        ("diagnostic_transition", "prior"),
        ("diagnostic_outcome", "step"),
        ("diagnostic_recommendation", "step"),
    ):
        tx.query(
            f'match $s isa diagnostic_step, has runbook_name "{name}"; '
            f'$x isa {relation}({role}: $s); delete $x;'
        ).resolve()
    for relation in ("runbook_entry", "runbook_contains"):
        tx.query(
            f'match $r isa runbook, has name "{name}"; '
            f'$x isa {relation}(runbook: $r); delete $x;'
        ).resolve()
    tx.query(
        f'match $x isa diagnostic_step, has runbook_name "{name}"; delete $x;'
    ).resolve()
    tx.query(f'match $x isa runbook, has name "{name}"; delete $x;').resolve()


def _insert_runbook(tx: Any, raw: dict[str, Any]) -> None:
    tx.query(
        f'insert $x isa runbook, has name "{esc(RUNBOOK_NAME)}", '
        f'has summary "{esc("Executable senior-SRE Kubernetes diagnostic graph")}";'
    ).resolve()
    for source in raw.get("sources") or []:
        tx.query(
            f'match $x isa runbook, has name "{esc(RUNBOOK_NAME)}"; '
            f'insert $x has source_url "{esc(str(source))}";'
        ).resolve()
    for principle in raw.get("principles") or []:
        tx.query(
            f'match $x isa runbook, has name "{esc(RUNBOOK_NAME)}"; '
            f'insert $x has principle "{esc(str(principle))}";'
        ).resolve()


def _insert_step(tx: Any, node: dict[str, Any]) -> None:
    step_id = str(node["id"])
    values = {
        "question": node.get("question") or "",
        "verification": node.get("verify") or "",
        "interpretation": node.get("interpretation") or "",
        "avoidance": node.get("avoid") or "",
        "match_expression": _condition(node.get("match")),
    }
    attrs = ", ".join(f'has {key} "{esc(str(value))}"' for key, value in values.items())
    tx.query(
        f'insert $x isa diagnostic_step, has diagnostic_id "{esc(step_id)}", '
        f'has runbook_name "{esc(RUNBOOK_NAME)}", {attrs};'
    ).resolve()
    for probe in _probe_templates(node.get("probes")):
        tx.query(
            f'match $s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
            f'insert $s has probe_template "{esc(json.dumps(probe, sort_keys=True))}";'
        ).resolve()
    tx.query(
        f'match $r isa runbook, has name "{esc(RUNBOOK_NAME)}"; '
        f'$s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
        f"insert (runbook: $r, step: $s) isa runbook_contains;"
    ).resolve()


def _probe_templates(value: object) -> list[dict[str, object]]:
    """Validate portable probe metadata without allowing executable commands."""
    if value is None:
        return []
    raw = value if isinstance(value, list) else [value]
    output: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("diagnostic probe must be a mapping")
        tool = str(item.get("tool") or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,80}", tool):
            raise ValueError(f"invalid diagnostic probe tool: {tool!r}")
        arguments = item.get("arguments_template") or {}
        if not isinstance(arguments, dict):
            raise ValueError("diagnostic probe arguments_template must be a mapping")
        output.append(
            {
                "tool": tool,
                "arguments_template": arguments,
                "incident_time_window": str(item.get("incident_time_window") or "incident"),
                "expected_result_shape": str(item.get("expected_result_shape") or ""),
                "supports_when": [str(v) for v in item.get("supports_when") or [] if str(v)],
                "refutes_when": [str(v) for v in item.get("refutes_when") or [] if str(v)],
                # Only explicit signal tokens are machine-evaluated. The prose
                # fields above remain LLM/operator guidance and cannot make a
                # probe pass itself.
                "support_signal_any": [
                    str(v) for v in item.get("support_signal_any") or [] if str(v)
                ],
                "refute_signal_any": [
                    str(v) for v in item.get("refute_signal_any") or [] if str(v)
                ],
                "source_group": str(item.get("source_group") or ""),
            }
        )
    return output


def _ensure_cause(tx: Any, family: str) -> None:
    if family not in FAMILIES:
        raise ValueError(f"unknown root-cause family: {family}")
    if not _exists(tx, f'$x isa {family}, has subtype "{esc(family)}";'):
        tx.query(f'insert $x isa {family}, has subtype "{esc(family)}";').resolve()


def _ensure_action(tx: Any, statement: str) -> None:
    if not _exists(tx, f'$x isa action, has statement "{esc(statement)}";'):
        tx.query(f'insert $x isa action, has statement "{esc(statement)}";').resolve()


def _insert_outcome(tx: Any, node: dict[str, Any]) -> int:
    conclusion = node.get("conclusion")
    if not isinstance(conclusion, dict):
        return 0
    step_id = str(node["id"])
    family = str(conclusion.get("family") or "")
    summary = str(conclusion.get("summary") or "")
    confidence = str(conclusion.get("confidence") or "")
    _ensure_cause(tx, family)
    tx.query(
        f'match $s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
        f'$c isa {family}, has subtype "{esc(family)}"; '
        f'insert $x isa diagnostic_outcome(step: $s, cause: $c), '
        f'has summary "{esc(summary)}", has confidence "{esc(confidence)}";'
    ).resolve()
    disconfirm = conclusion.get("disconfirm") or []
    if not isinstance(disconfirm, list):
        disconfirm = [disconfirm]
    for item in disconfirm:
        text = str(item).strip()
        if not text:
            continue
        tx.query(
            f'match $s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
            f'$c isa {family}, has subtype "{esc(family)}"; '
            f'$x isa diagnostic_outcome(step: $s, cause: $c); '
            f'insert $x has disconfirm "{esc(text)}";'
        ).resolve()
    actions = [str(item).strip() for item in conclusion.get("next_steps") or []]
    for index, statement in enumerate(action for action in actions if action):
        _ensure_action(tx, statement)
        tx.query(
            f'match $s isa diagnostic_step, has diagnostic_id "{esc(step_id)}"; '
            f'$a isa action, has statement "{esc(statement)}"; '
            f"insert (step: $s, remedy: $a) isa diagnostic_recommendation, "
            f"has sequence_index {index};"
        ).resolve()
    return len([action for action in actions if action])


def _insert_transitions(tx: Any, nodes: list[dict[str, Any]]) -> int:
    count = 0
    for node in nodes:
        prior = str(node["id"])
        for priority, branch in enumerate(node.get("branches") or []):
            if not isinstance(branch, dict):
                continue
            next_id = str(branch.get("next") or "")
            tx.query(
                f'match $p isa diagnostic_step, has diagnostic_id "{esc(prior)}"; '
                f'$n isa diagnostic_step, has diagnostic_id "{esc(next_id)}"; '
                f"insert (prior: $p, next: $n) isa diagnostic_transition, "
                f'has match_expression "{esc(_condition(branch.get("match")))}", '
                f"has transition_priority {priority};"
            ).resolve()
            count += 1
    return count


def _load(tx: Any, raw: dict[str, Any]) -> tuple[int, int, int]:
    nodes = [node for node in raw.get("nodes") or [] if isinstance(node, dict)]
    _delete_existing(tx, RUNBOOK_NAME)
    _insert_runbook(tx, raw)
    for node in nodes:
        _insert_step(tx, node)
    root = str(raw.get("root") or "")
    tx.query(
        f'match $r isa runbook, has name "{esc(RUNBOOK_NAME)}"; '
        f'$s isa diagnostic_step, has diagnostic_id "{esc(root)}"; '
        f"insert (runbook: $r, step: $s) isa runbook_entry;"
    ).resolve()
    edges = _insert_transitions(tx, nodes)
    actions = sum(_insert_outcome(tx, node) for node in nodes)
    return len(nodes), edges, actions


def main() -> int:
    raw = _document(TREE_FILE)
    if raw is None:
        print(f"invalid troubleshooting tree: {TREE_FILE}", file=sys.stderr)
        return 1
    settings = load_settings()
    try:
        from typedb.driver import TransactionType
    except ImportError:
        print("typedb-driver is not installed. `pip install typedb-driver`.", file=sys.stderr)
        return 2

    with open_driver(settings) as driver:
        with driver.transaction(settings.typedb_database, TransactionType.WRITE) as tx:
            nodes, edges, actions = _load(tx, raw)
            tx.commit()
    print(f"loaded diagnostic runbook: {nodes} steps, {edges} transitions, {actions} actions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
