from __future__ import annotations

from app.schemas import FeedbackHintContext
from app.services.feedback_priors import derive_priors


def _hint(sentiment: str = "", text: str = "", weight: float = 1.0) -> FeedbackHintContext:
    return FeedbackHintContext(sentiment=sentiment, text=text, weight=weight)


def test_downvote_mentioning_control_plane_downweights_family():
    priors = derive_priors([_hint("down", "the control plane was fine, not the cause")])
    assert priors["runai_control_plane_error"] < 1.0


def test_upvote_upweights_family():
    priors = derive_priors([_hint("up", "yes it was node disk pressure")])
    assert priors["node_kubelet_pressure"] > 1.0


def test_image_pull_feedback_targets_image_pull_family():
    priors = derive_priors([_hint("up", "image pull registry auth was the cause")])
    assert priors["image_pull_error"] > 1.0
    assert "workload_startup_error" not in priors


def test_positive_feedback_ignores_negated_family_mentions():
    priors = derive_priors(
        [_hint("up", "control plane was fine; not quota; image pull auth was the cause")]
    )
    assert priors["image_pull_error"] > 1.0
    assert "runai_control_plane_error" not in priors
    assert "runai_scheduling_quota" not in priors


def test_negative_feedback_downweights_rejected_family_not_correct_alternative():
    priors = derive_priors([_hint("down", "not quota; image pull auth was the cause")])
    assert priors["runai_scheduling_quota"] < 1.0
    assert "image_pull_error" not in priors


def test_empty_hints_returns_empty():
    assert derive_priors([]) == {}
    assert derive_priors(None) == {}


def test_hint_without_known_family_ignored():
    assert derive_priors([_hint("down", "this was completely unrelated to anything")]) == {}


def test_neutral_sentiment_ignored():
    assert derive_priors([_hint("meh", "control plane error")]) == {}


def test_malformed_hints_ignored():
    # dicts with missing/garbage fields, None entries, wrong types — none should raise.
    hints = [
        None,
        {"sentiment": "down"},  # no text
        {"sentiment": "down", "text": "control plane", "weight": "bad"},
        object(),
    ]
    priors = derive_priors(hints)
    # only the third hint is usable; its bad weight defaults to 1.0
    assert priors["runai_control_plane_error"] < 1.0


def test_accumulated_feedback_clamped():
    hints = [_hint("down", "control plane", weight=10.0) for _ in range(20)]
    priors = derive_priors(hints)
    assert priors["runai_control_plane_error"] >= 0.5  # clamp floor holds


def test_dict_hints_supported():
    priors = derive_priors([{"sentiment": "up", "text": "gpu hardware xid error", "weight": 1}])
    assert priors["gpu_hardware_error"] > 1.0


def _dt(days_ago: float, ref):
    from datetime import timedelta

    return (ref - timedelta(days=days_ago)).isoformat()


def test_recent_feedback_outweighs_stale_feedback():
    from datetime import datetime, timezone

    ref = datetime(2024, 1, 1, tzinfo=timezone.utc)
    fresh = derive_priors(
        [FeedbackHintContext(sentiment="up", text="gpu hardware xid", created_at=_dt(0, ref))],
        now=ref,
    )
    stale = derive_priors(
        [FeedbackHintContext(sentiment="up", text="gpu hardware xid", created_at=_dt(120, ref))],
        now=ref,
    )
    # Both up-weight, but a 120-day-old hint nudges far less than a fresh one.
    assert fresh["gpu_hardware_error"] > stale["gpu_hardware_error"] > 1.0


def test_missing_created_at_no_decay_backward_compatible():
    from datetime import datetime, timezone

    ref = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with_ts = derive_priors(
        [FeedbackHintContext(sentiment="up", text="gpu hardware xid", created_at=_dt(0, ref))],
        now=ref,
    )
    without_ts = derive_priors([_hint("up", "gpu hardware xid")], now=ref)
    # A fresh (age 0) hint and a timestamp-less hint both decay to 1.0.
    assert with_ts == without_ts


def test_future_timestamp_treated_as_fresh():
    from datetime import datetime, timezone

    ref = datetime(2024, 1, 1, tzinfo=timezone.utc)
    priors = derive_priors(
        [FeedbackHintContext(sentiment="up", text="gpu hardware xid", created_at=_dt(-5, ref))],
        now=ref,
    )
    assert priors["gpu_hardware_error"] > 1.0


def test_relevance_weight_scales_nudge():
    # weight carries source-incident similarity; higher similarity -> bigger nudge.
    high = derive_priors([_hint("up", "gpu hardware xid", weight=1.0)])
    low = derive_priors([_hint("up", "gpu hardware xid", weight=0.2)])
    assert high["gpu_hardware_error"] > low["gpu_hardware_error"] > 1.0


def test_garbage_created_at_ignored():
    priors = derive_priors(
        [FeedbackHintContext(sentiment="up", text="gpu hardware xid", created_at="not-a-date")]
    )
    assert priors["gpu_hardware_error"] > 1.0


if __name__ == "__main__":
    test_downvote_mentioning_control_plane_downweights_family()
    test_upvote_upweights_family()
    test_image_pull_feedback_targets_image_pull_family()
    test_positive_feedback_ignores_negated_family_mentions()
    test_negative_feedback_downweights_rejected_family_not_correct_alternative()
    test_empty_hints_returns_empty()
    test_hint_without_known_family_ignored()
    test_neutral_sentiment_ignored()
    test_malformed_hints_ignored()
    test_accumulated_feedback_clamped()
    test_dict_hints_supported()
    test_recent_feedback_outweighs_stale_feedback()
    test_missing_created_at_no_decay_backward_compatible()
    test_future_timestamp_treated_as_fresh()
    test_relevance_weight_scales_nudge()
    test_garbage_created_at_ignored()
    print("ok")
