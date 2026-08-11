"""Three i18n handovers, same files as the eight defects above:

1. ``_short_sentence``/``_safe_line`` truncated with a naive char-index slice
   that could cut mid-word (real output: "...ResourceQu…입니다."). Now uses
   ``textwrap.shorten`` (stdlib word-boundary truncation), the same fix
   already landed in general_guidance.py's ``_safe``.
2. ``_runtime_failure_mode_provenance`` always emitted an English template and
   read ``symptom.get("symptom")`` instead of the localized name.
3. ``_translate_report_lines_ko`` covered ``state.detail`` only; a Korean
   report's ``state.warnings`` shipped English verbatim (a real run: 9/9
   warnings stayed English).
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from app.mcp_client import mcp_fallback_warning
from app.services.pipeline import (
    _runtime_failure_mode_provenance,
    _safe_line,
    _short_sentence,
    _translate_warnings_ko,
)
from app.services.root_cause_ranking import RankedCause
from tests.test_orchestrator import make_settings

_LONG_TEXT = "ResourceQuota exceeded for namespace runai-test1 while provisioning GPUs"


# --- 1: word-boundary truncation ----------------------------------------------


def test_short_sentence_does_not_chop_a_word_mid_token() -> None:
    naive = _LONG_TEXT[: 30 - 1].rstrip() + "…"
    assert naive.endswith("na…"), "the naive slice this replaced chopped 'namespace'"

    result = _short_sentence(_LONG_TEXT, limit=30)

    assert len(result) <= 30
    assert result.endswith("…")
    assert "na…" not in result
    source_words = set(_LONG_TEXT.split())
    for word in result[:-1].split():
        assert word in source_words, f"{word!r} is not a whole word from the source"


def test_safe_line_does_not_chop_a_word_mid_token() -> None:
    result = _safe_line(_LONG_TEXT, limit=30)

    assert len(result) <= 30
    assert result.endswith("…")
    assert "na…" not in result, "the naive slice this replaced chopped 'namespace'"
    source_words = set(_LONG_TEXT.split())
    for word in result[:-1].split():
        assert word in source_words, f"{word!r} is not a whole word from the source"


def test_short_sentence_empty_input_keeps_its_fallback_sentence() -> None:
    assert _short_sentence("", limit=30) == (
        "The agent has not received enough alert context to name a root cause."
    )


def test_short_sentence_short_text_is_unchanged() -> None:
    assert _short_sentence("short text", limit=280) == "short text"


# --- 2: localized runtime provenance -------------------------------------------


def test_runtime_failure_mode_provenance_localizes_to_korean() -> None:
    matches = [(
        "gpu_hardware_error",
        {
            "symptom": "GPU Fallen Off The Bus",
            "symptom_ko": "GPU가 버스에서 이탈함",
            "runtime_package_id": "pkg-1",
            "runtime_status": "confirmed",
        },
    )]
    candidates = [RankedCause("gpu_hardware_error", "high", 9.0)]

    en = _runtime_failure_mode_provenance(matches, candidates, "en")
    ko = _runtime_failure_mode_provenance(matches, candidates, "ko")

    assert "Runtime knowledge provenance" in en
    assert "GPU Fallen Off The Bus" in en
    assert "런타임 지식 출처" in ko
    assert "GPU가 버스에서 이탈함" in ko
    assert "GPU Fallen Off The Bus" not in ko, "the English symptom name must not leak into Korean"


def test_runtime_failure_mode_provenance_defaults_to_english() -> None:
    matches = [(
        "gpu_hardware_error",
        {
            "symptom": "GPU Fallen Off The Bus",
            "runtime_package_id": "pkg-1",
            "runtime_status": "confirmed",
        },
    )]
    candidates = [RankedCause("gpu_hardware_error", "high", 9.0)]

    assert _runtime_failure_mode_provenance(matches, candidates) == (
        "Runtime knowledge provenance: package pkg-1; family gpu_hardware_error; "
        "matched symptom GPU Fallen Off The Bus; status confirmed"
    )


# --- 3: warnings enter the Korean translation pass -----------------------------


@pytest.mark.asyncio
async def test_translate_warnings_ko_localizes_english_lines(monkeypatch) -> None:
    settings = replace(make_settings(), language="ko")
    warnings = [
        "RCA harness quality score below threshold",
        "이미 한국어인 경고입니다",
        "Loki reachability failed",
    ]

    async def fake_complete_with_error(*_args, **kwargs):
        pending = json.loads(kwargs["user"])
        translated = {key: f"[번역] {value}" for key, value in pending.items()}
        return json.dumps(translated, ensure_ascii=False), None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )

    translated, missing = await _translate_warnings_ko(settings, warnings)

    assert missing == 0
    assert translated[0] == "[번역] RCA harness quality score below threshold"
    assert translated[1] == "이미 한국어인 경고입니다", "an already-Korean line is never sent"
    assert translated[2] == "[번역] Loki reachability failed"


@pytest.mark.asyncio
async def test_translate_warnings_ko_keeps_original_text_on_failure(monkeypatch) -> None:
    async def fake_complete_with_error(*_args, **_kwargs):
        return None, "connection refused"

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )
    settings = replace(make_settings(), language="ko")

    translated, missing = await _translate_warnings_ko(settings, ["Loki reachability failed"])

    assert missing == 1
    assert translated == ["Loki reachability failed"]


@pytest.mark.asyncio
async def test_translate_warnings_ko_empty_list_is_a_noop() -> None:
    settings = replace(make_settings(), language="ko")

    assert await _translate_warnings_ko(settings, []) == ([], 0)


@pytest.mark.asyncio
async def test_translate_warnings_ko_carries_the_mcp_source(monkeypatch) -> None:
    """Both languages must show WHICH datasource fell back. The English label
    mcp_fallback_warning() builds now carries "(source)"; confirm the Korean
    rendering the localization pass produces still carries it through."""
    settings = replace(make_settings(), language="ko")
    warning = mcp_fallback_warning(RuntimeError("self-signed certificate"), source="Kubernetes")
    assert "(Kubernetes)" in warning  # the English input this test localizes

    async def fake_complete_with_error(*_args, **kwargs):
        pending = json.loads(kwargs["user"])
        translated = {key: f"[번역] {value}" for key, value in pending.items()}
        return json.dumps(translated, ensure_ascii=False), None

    monkeypatch.setattr(
        "app.services.pipeline.complete_with_error", fake_complete_with_error
    )

    translated, missing = await _translate_warnings_ko(settings, [warning])

    assert missing == 0
    assert "(Kubernetes)" in translated[0]
