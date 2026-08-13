from __future__ import annotations

import re
from pathlib import Path

from app.collectors.base import CollectorResult, artifact
from app.knowledge import (
    load_failure_modes,
    load_runai_known_issues,
    match_failure_mode_symptoms,
    match_runai_known_issues,
)
from app.schemas import Alert, AlertAnalysisRequest
from app.services.pipeline import (
    ReportKnowledge,
    _known_issue_cause_lines,
    _numbered_actions,
    _observed_text,
)
from app.services.root_cause_ranking import RankedCause

CATALOG = "knowledge/runai_known_issues.yaml"
SCHEMA = "ontology/schema.tql"


def _schema_families() -> set[str]:
    text = Path(SCHEMA).read_text(encoding="utf-8")
    return set(re.findall(r"entity (\w+) sub root_cause", text))


def test_load_shape_and_families_valid() -> None:
    catalog = load_runai_known_issues(CATALOG)
    assert catalog  # non-empty
    families = _schema_families()
    for entry in catalog:
        assert entry["family"] in families, f"{entry['issue']}: family not in schema"
        assert entry["keywords"], f"{entry['issue']}: no keywords"
        assert entry["actions"], f"{entry['issue']}: no actions"


def test_load_carries_refs_citations() -> None:
    """refs (source/KB citations, e.g. "NVIDIA Case 01074073") are authored on
    every entry but were dropped at the loader (2026-08 audit item #2a). An
    entry may legitimately author an empty list — only the KEY must survive."""
    catalog = load_runai_known_issues(CATALOG)
    by_issue = {entry["issue"]: entry for entry in catalog}
    assert all("refs" in entry for entry in catalog)
    assert by_issue["Distributed Training Locked hostPath Policy Rejected In UI"]["refs"] == [
        "NVIDIA Case 01074073"
    ]
    assert by_issue["Distributed Training Backoff And Restart Policy Semantics"]["refs"] == [
        "NVIDIA Case 01064819",
        "NVIDIA Case 01065900",
    ]
    # Authored as `refs: []` in the YAML — an honest empty list, not missing.
    assert by_issue["Scheduler Reclaim Panic On Large GPU Job"]["refs"] == []


def test_match_recognises_signature() -> None:
    catalog = load_runai_known_issues(CATALOG)
    hits = match_runai_known_issues(
        catalog, "Error: the administrator prohibited modifying item 'project-data'"
    )
    assert [h["issue"] for h in hits] == [
        "Distributed Training Locked hostPath Policy Rejected In UI"
    ]
    assert any("2.23.60" in a for a in hits[0]["actions"])  # carries the fixed version


def test_cause_line_grounds_headline_with_version() -> None:
    # The report's Root Cause headline should name the specific known issue and its
    # fixed version, not just the coarse family.
    catalog = load_runai_known_issues(CATALOG)
    lines = _known_issue_cause_lines(catalog, "the administrator prohibited modifying item", "en")
    assert lines
    assert "Locked hostPath Policy" in lines[0]
    assert "fixed in 2.23.60" in lines[0]
    assert _known_issue_cause_lines(catalog, "nothing relevant here", "en") == []


def test_cause_line_renders_the_issue_citation() -> None:
    """The other half of the chain the pin above used to describe.

    `refs` reaches every matched issue dict, and the report renders it, so an
    operator told "this is a known issue" can also see WHICH one. Citation IDs
    are rendered in both languages -- they are identifiers, not prose, like the
    affected/fixed version parenthetical beside them."""
    catalog = load_runai_known_issues(CATALOG)
    lines = _known_issue_cause_lines(catalog, "the administrator prohibited modifying item", "en")
    assert lines
    assert "01074073" in lines[0]


def test_known_issue_signature_in_drilldown_result_is_observed() -> None:
    catalog = load_runai_known_issues(CATALOG)
    result = CollectorResult(agent="postgres", status="ok", summary="db drilldown ok")
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="1 row(s)",
            result={"rows": [{"log": "reclaim/reclaim.go:91 runtime/panic.go:785"}]},
        )
    )
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})
    )
    hits = match_runai_known_issues(catalog, _observed_text([result], request))
    assert [h["issue"] for h in hits] == ["Scheduler Reclaim Panic On Large GPU Job"]


def test_unavailable_artifact_signature_is_not_observed_evidence() -> None:
    catalog = load_runai_known_issues(CATALOG)
    result = CollectorResult(agent="postgres", status="ok", summary="db drilldown failed")
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="unavailable",
            confidence="low",
            summary="failed query mentioned reclaim/reclaim.go:91 runtime/panic.go:785",
            result={"error": "reclaim/reclaim.go:91 runtime/panic.go:785"},
        )
    )
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})
    )

    assert match_runai_known_issues(catalog, _observed_text([result], request)) == []


def test_unavailable_collector_summary_is_not_observed_evidence() -> None:
    catalog = load_runai_known_issues(CATALOG)
    result = CollectorResult(
        agent="postgres",
        status="unavailable",
        summary=(
            "failed before evidence; error mentioned reclaim/reclaim.go:91 "
            "runtime/panic.go:785"
        ),
    )
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "SchedulerCrash"})
    )

    assert match_runai_known_issues(catalog, _observed_text([result], request)) == []


def test_known_issue_signature_in_schema_or_doc_example_is_ignored() -> None:
    catalog = load_runai_known_issues(CATALOG)
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "SchemaDiscovery"})
    )
    result = CollectorResult(agent="postgres", status="ok", summary="db schema discovery")
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="schema rows",
            result={
                "schema": {
                    "columns": [
                        "created_by",
                        "cache_max_store_size_mb",
                        "runai_pod_info_unique",
                    ]
                },
                "rows": [{"message": "docs example: administrator prohibited modifying item"}],
            },
        )
    )
    assert match_runai_known_issues(catalog, _observed_text([result], request)) == []


def test_observed_artifact_keys_are_not_signature_evidence() -> None:
    catalog = load_runai_known_issues(CATALOG)
    failure_modes = load_failure_modes("knowledge/failure_modes.yaml")
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "SchemaDiscovery"})
    )
    result = CollectorResult(agent="postgres", status="ok", summary="metadata only")
    result.artifacts.append(
        artifact(
            agent="postgres",
            source="postgres",
            type="drilldown_query",
            status="ok",
            confidence="medium",
            summary="schema rows",
            result={
                "reclaim.go": False,
                "reclaim": False,
                "runai_pod_info_unique": None,
                "rows": [{"status": "healthy"}],
            },
        )
    )
    observed = _observed_text([result], request)

    assert match_runai_known_issues(catalog, observed) == []
    assert match_failure_mode_symptoms(failure_modes, observed) == []


def test_no_false_match() -> None:
    catalog = load_runai_known_issues(CATALOG)
    assert match_runai_known_issues(catalog, "a perfectly healthy cluster log line") == []


def test_match_titles_finds_a_question_pasting_the_full_issue_title() -> None:
    # rung b of the chat-adhoc knowledge ladder: an operator's question may
    # quote a known issue's TITLE instead of any of its error-string keywords
    # -- match_titles is the question-only escape hatch for that.
    catalog = [
        {
            "issue": "Distributed Training Locked hostPath Policy Rejected In UI",
            "family": "runai_scheduling_quota",
            "keywords": ["administrator prohibited modifying", "masterspec.storage.hostpath"],
            "reason": "The UI enforces a locked hostPath policy for the master.",
            "actions": ["Use the CLI or API to submit the job instead."],
            "affected_version": "",
            "fixed_version": "",
            "refs": [],
        }
    ]
    question = "Distributed Training Locked hostPath Policy Rejected In UI 이거 왜 이러는거야?"

    # Evidence-path guard: the default keyword-only match must NOT see a title.
    assert match_runai_known_issues(catalog, question) == []

    hits = match_runai_known_issues(catalog, question, match_titles=True)
    assert [h["issue"] for h in hits] == [
        "Distributed Training Locked hostPath Policy Rejected In UI"
    ]
    assert (
        "distributed training locked hostpath policy rejected in ui" in hits[0]["matched_keywords"]
    )


def test_match_titles_does_not_change_a_keyword_hit() -> None:
    # No duplicate entries/keywords when a run already matched by keyword.
    catalog = load_runai_known_issues(CATALOG)
    text = "Error: the administrator prohibited modifying item 'project-data'"
    without_titles = match_runai_known_issues(catalog, text)
    with_titles = match_runai_known_issues(catalog, text, match_titles=True)
    assert with_titles == without_titles


def test_include_fixed_is_the_single_choke_point_for_version_suppression() -> None:
    # pipeline._suppress_fixed_known_issues annotates (never drops) an entry
    # already fixed in the running Run:ai version; the matcher is where that
    # annotation actually stops it from surfacing -- by default, everywhere.
    catalog = [
        {
            "issue": "bug fixed already",
            "family": "runai_scheduling_quota",
            "keywords": ["some rare error string"],
            "actions": [],
            "_fixed_in_running": True,
            "_running_version": "2.23.71",
            "fixed_version": "2.23.60",
        }
    ]
    text = "log line containing some rare error string"

    # Evidence-path guard: identical to the old filter's observable behavior.
    assert match_runai_known_issues(catalog, text) == []
    assert match_runai_known_issues(catalog, text, fuzzy_query=text) == []

    # Question path opts in explicitly.
    hits = match_runai_known_issues(catalog, text, include_fixed=True)
    assert [h["issue"] for h in hits] == ["bug fixed already"]
    assert hits[0]["_fixed_in_running"] is True
    assert hits[0]["_running_version"] == "2.23.71"


def test_include_fixed_does_not_affect_unannotated_entries() -> None:
    # An entry with no _fixed_in_running marker (running version was unknown,
    # or it isn't fixed yet) matches identically regardless of include_fixed.
    catalog = load_runai_known_issues(CATALOG)
    text = "Error: the administrator prohibited modifying item 'project-data'"
    assert match_runai_known_issues(catalog, text) == match_runai_known_issues(
        catalog, text, include_fixed=True
    )


def test_missing_file_is_empty() -> None:
    assert load_runai_known_issues("/nope/does-not-exist.yaml") == []


def test_numbered_actions_surfaces_known_issue_regardless_of_ranked_family() -> None:
    # Ranker points at node pressure, but the evidence carries a platform_version_bug
    # signature — its remediation must still surface (ranking-independent).
    catalog = load_runai_known_issues(CATALOG)
    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, annotations={}, fingerprint="fp")
    )
    actions = _numbered_actions(
                  None,
                  None,
                  [RankedCause(family="node_kubelet_pressure", confidence="low", score=1.0)],
                  "runai-scheduler reclaim/reclaim.go:91 attempting to reclaim ... runtime/panic.go:785",
                  [],
                  request,
                  knowledge=ReportKnowledge(failure_modes={}, known_issues=catalog),
              )
    joined = " ".join(actions)
    assert "2.23" in joined and "upgrade" in joined.lower()


def test_playbook_leads_with_known_issue_not_full_dump() -> None:
    # A known-issue-headlined incident (e.g. workloads-manager cache growth) has no
    # failure_modes symptoms for its family — the playbook used to dump the entire
    # troubleshooting_cases.md. It must list the matched known issue precisely.
    from app.services.pipeline import _playbook_lines
    from app.services.root_cause_ranking import RankedCause

    catalog = load_runai_known_issues(CATALOG)
    lines = _playbook_lines(
                [RankedCause(family="expected_known_behavior", confidence="medium", score=8.0)],
                "pod runai-backend-workloads-manager-xyz memory usage 91%",
                knowledge=ReportKnowledge(failure_modes={}, cases="FULL CASE LIBRARY DUMP", known_issues=catalog),
            )
    joined = "\n".join(lines)
    assert "Workloads Manager Memory Grows To Cache Cap" in joined
    assert "known issue" in joined
    assert "FULL CASE LIBRARY DUMP" not in joined
