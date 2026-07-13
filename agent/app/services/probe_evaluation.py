"""Conservative evaluation of declarative ontology probes.

Probe prose (``supports_when`` / ``refutes_when``) is guidance for operators
and LLMs.  This module evaluates only explicitly authored signal tokens, never
tries to infer a pass/fail result from that prose.  A missing or ambiguous
signal remains inconclusive instead of becoming synthetic support.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from app.collectors.base import NO_EVIDENCE
from app.knowledge import _keyword_negated

ProbeVerdict = Literal["supports", "refutes", "inconclusive", "unavailable"]


@dataclass(frozen=True, slots=True)
class ProbeAssessment:
    probe_id: str
    tool: str
    verdict: ProbeVerdict
    support_signals: tuple[str, ...] = ()
    refute_signals: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "tool": self.tool,
            "verdict": self.verdict,
            "support_signals": list(self.support_signals),
            "refute_signals": list(self.refute_signals),
        }


def evaluate_probe(probe: dict[str, Any], outcome: dict[str, Any]) -> ProbeAssessment:
    """Evaluate explicit probe signals against returned observation text.

    Refutation wins when both sides match: a mixed result is a contradiction,
    not confirmation.  Queries, commands, and template text are deliberately
    excluded from the haystack, so authored probe text can never satisfy itself.
    """
    probe_id = str(probe.get("id") or probe.get("probe_id") or probe.get("tool") or "probe")
    tool = str(probe.get("tool") or "")
    status = str(outcome.get("status") or "").strip().lower()
    polarity = str(outcome.get("polarity") or "").strip().lower()
    coverage = str(outcome.get("coverage") or "").strip().lower()
    if (
        outcome.get("error")
        or status in {"unavailable", "error", "failed", "timeout"}
        or polarity == "unavailable"
    ):
        return ProbeAssessment(probe_id, tool, "unavailable")
    # An unknown result may describe a failed/partial retrieval in its summary.
    # It must never become support merely because that summary repeats a signal.
    if polarity == "unknown":
        return ProbeAssessment(probe_id, tool, "inconclusive")
    # Empty scope can be informative only when an authored probe explicitly
    # declares absence as a refuter. Existing probes do not do that, so retain
    # their conservative inconclusive behavior.
    if polarity == "absent" and coverage != "scoped":
        return ProbeAssessment(probe_id, tool, "inconclusive")
    result = outcome.get("result")
    if result is None or (isinstance(result, dict) and not result):
        summary = str(outcome.get("summary") or "")
        if summary.startswith(NO_EVIDENCE):
            return ProbeAssessment(probe_id, tool, "inconclusive")
    text = _observed_text(result)
    if not text:
        text = str(outcome.get("summary") or "")
    support = _matching_signals(text, probe.get("support_signal_any"))
    refute = _matching_signals(text, probe.get("refute_signal_any"))
    if refute:
        return ProbeAssessment(probe_id, tool, "refutes", support, refute)
    if support:
        return ProbeAssessment(probe_id, tool, "supports", support, refute)
    return ProbeAssessment(probe_id, tool, "inconclusive")


def _matching_signals(text: str, configured: object) -> tuple[str, ...]:
    if not isinstance(configured, list):
        return ()
    lowered = text.lower()
    matches: list[str] = []
    for raw in configured:
        signal = " ".join(str(raw or "").split())[:160]
        if not signal:
            continue
        for hit in re.finditer(re.escape(signal.lower()), lowered):
            if not _keyword_negated(lowered, hit.start(), hit.end()):
                matches.append(signal)
                break
    return tuple(dict.fromkeys(matches))


def _observed_text(value: Any) -> str:
    leaves: list[str] = []

    def walk(item: Any, key: str = "") -> None:
        if len(leaves) >= 200:
            return
        if isinstance(item, str):
            # Retrieval instructions are not observations.
            if key.lower() not in {"query", "command", "path", "url", "logql", "promql"}:
                leaves.append(item)
        elif isinstance(item, dict):
            for child_key, child in item.items():
                walk(child, str(child_key))
        elif isinstance(item, (list, tuple)):
            for child in item:
                walk(child, key)

    walk(value)
    return "\n".join(leaves)
