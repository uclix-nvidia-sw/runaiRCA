from __future__ import annotations

from app.schemas import FeedbackHintContext
from app.services.feedback_priors import derive_priors


def _hint(sentiment: str = "", text: str = "", weight: float = 1.0) -> FeedbackHintContext:
    return FeedbackHintContext(sentiment=sentiment, text=text, weight=weight)


def test_downvote_mentioning_control_plane_downweights_family():
    priors = derive_priors([_hint("down", "the control plane was fine, not the cause")])
    assert priors["control_plane_error"] < 1.0


def test_upvote_upweights_family():
    priors = derive_priors([_hint("up", "yes it was node disk pressure")])
    assert priors["node_kubelet_pressure"] > 1.0


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
    assert priors["control_plane_error"] < 1.0


def test_accumulated_feedback_clamped():
    hints = [_hint("down", "control plane", weight=10.0) for _ in range(20)]
    priors = derive_priors(hints)
    assert priors["control_plane_error"] >= 0.5  # clamp floor holds


def test_dict_hints_supported():
    priors = derive_priors([{"sentiment": "up", "text": "gpu hardware xid error", "weight": 1}])
    assert priors["gpu_hardware_error"] > 1.0


if __name__ == "__main__":
    test_downvote_mentioning_control_plane_downweights_family()
    test_upvote_upweights_family()
    test_empty_hints_returns_empty()
    test_hint_without_known_family_ignored()
    test_neutral_sentiment_ignored()
    test_malformed_hints_ignored()
    test_accumulated_feedback_clamped()
    test_dict_hints_supported()
    print("ok")
