"""What the operator says they already tried must change the answer."""

from app.plan import InvestigationPlan
from app.schemas import Alert, AlertAnalysisRequest
from app.services.pipeline import ReportKnowledge, _matches_attempted_action, _numbered_actions


def test_matches_a_recommendation_that_restates_the_attempt():
    attempted = ["Increased the container memory limit for thanos-receive"]
    assert _matches_attempted_action(
        "Compare the container's resources.limits.memory with its working set and raise the limit",
        attempted,
    )


def test_does_not_match_on_incidental_shared_words():
    attempted = ["Increased the container memory limit"]
    assert not _matches_attempted_action("Check the node kernel logs for XID errors", attempted)
    assert not _matches_attempted_action("Restart the scheduler", attempted)
    # No claim at all must never mark anything.
    assert not _matches_attempted_action("Increase the memory limit", [])


def test_numbered_actions_mark_rather_than_drop_the_attempted_step():
    """Dropping it would hide that the fix may simply not have taken effect."""

    request = AlertAnalysisRequest(
        alert=Alert(status="firing", labels={"alertname": "X"}, annotations={}, fingerprint="fp")
    )
    plan = InvestigationPlan(attempted_actions=["Increased the container memory limit"])
    actions = _numbered_actions(
                  plan,
                  None,
                  None,
                  "",
                  [],
                  request,
                  self_check_next="Raise the container memory limit above the observed working set",
                  knowledge=ReportKnowledge(failure_modes={}, language="en"),
              )
    assert actions, "the self-check action must still be listed"
    assert "already doing this" in actions[0]
    assert "Raise the container memory limit" in actions[0]
