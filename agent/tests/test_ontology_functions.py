from __future__ import annotations

from pathlib import Path

from ontology.load_functions import _function_definitions

# The TypeQL itself is validated against a live TypeDB 3.11.5 (see functions.tql
# header) — not in CI. This guard just keeps the file present and well-formed so an
# accidental edit that drops a function or the `define` block is caught.


def test_functions_tql_defines_the_expected_functions() -> None:
    text = Path("ontology/functions.tql").read_text(encoding="utf-8")
    assert "define" in text
    for name in (
        "fixes_for_xid",
        "trigger_for_xid",
        "xids_for_gpu_model",
        "fixes_for_family",
        "root_xids_for",
        "causes_for_symptom",
        "dependencies_for_component",
        "verified_actions_for_family",
        "approved_case_card",
        "diagnostic_steps_for_runbook",
        "entry_steps_for_runbook",
        "next_diagnostic_steps",
        "diagnostic_outcomes_for",
        "diagnostic_actions_for",
        "diagnostic_disconfirmations_for",
        "diagnostic_steps_for_family",
        "diagnostic_transitions_for_runbook",
        "diagnostic_outcomes_for_runbook",
        "diagnostic_actions_for_runbook",
        "diagnostic_disconfirmations_for_runbook",
    ):
        assert f"fun {name}(" in text
        assert "return {" in text


def test_function_definitions_are_independently_upgradeable() -> None:
    text = Path("ontology/functions.tql").read_text(encoding="utf-8")
    definitions = _function_definitions(text)

    assert len(definitions) >= 10
    assert all(definition.startswith("define\n\nfun ") for definition in definitions)
    assert any("fun causes_for_symptom(" in definition for definition in definitions)
