

def test_translation_rejects_japanese_kana_leak() -> None:
    # Owner report 2026-07-28: some reports shipped Korean lines with Japanese
    # mixed in. A kana character in the translated line (absent from the
    # source) rejects the translation, so the line stays English instead.
    from app.services.pipeline import _valid_line_translation

    assert not _valid_line_translation("Check the pod events.", "Podのイベントを確認하세요.")
    assert not _valid_line_translation("Check the pod events.", "Pod 이벤트를 확인してください.")
    assert _valid_line_translation("Check the pod events.", "Pod 이벤트를 확인하세요.")
