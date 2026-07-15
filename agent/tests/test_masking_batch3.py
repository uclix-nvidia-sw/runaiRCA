from app.masking import MASK_TOKEN, build_masker


def test_batch3_text_redaction_keeps_diagnostic_words_and_masks_credentials() -> None:
    masker = build_masker(())
    assert masker.mask_text("failed to get token: connection refused") == "failed to get token: connection refused"
    assert "token: " + MASK_TOKEN in masker.mask_text("token: c0nnEct10nXYZsecret")


def test_batch3_sha256_digest_is_not_treated_as_base64() -> None:
    masker = build_masker(())
    digest = "a" * 64
    assert f"sha256:{digest}" in masker.mask_text(f"image@sha256:{digest}")
    assert MASK_TOKEN in masker.mask_text("blob " + "Q" * 64)
