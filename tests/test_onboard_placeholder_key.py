"""`.env` placeholder guard: if `.env` still holds the shipped example value
(`sk-ant-xxxx…`) the operator gets a CLEAR 'replace the placeholder' message and a
fresh paste prompt -- not a confusing 'rejected (401 invalid x-api-key)'. The
placeholder is also never sent to the live API verifier. Universal: shape-based
detection only (repeated filler chars / template words), never a real key's bytes.
"""
import step0_onboard as s

VALID = "sk-ant-" + "A1b2C3d4" * 13   # format-valid shape, not a real key


# ── _is_placeholder_key ──────────────────────────────────────────────────────
def test_example_all_x_placeholder_detected():
    assert s._is_placeholder_key("sk-ant-" + "x" * 40) is True


def test_short_xxxx_placeholder_detected():
    assert s._is_placeholder_key("sk-ant-xxxxxxxxxxxx") is True


def test_template_words_detected():
    assert s._is_placeholder_key("sk-ant-your-key-here") is True
    assert s._is_placeholder_key("sk-ant-REPLACE-ME-please") is True
    assert s._is_placeholder_key("sk-ant-CHANGEME0000") is True


def test_real_shape_key_not_flagged():
    assert s._is_placeholder_key(VALID) is False


def test_realistic_api03_key_not_flagged():
    assert s._is_placeholder_key("sk-ant-api03-" + "9aZ_x2Qb" * 12) is False


def test_empty_or_none_not_flagged():
    assert s._is_placeholder_key("") is False
    assert s._is_placeholder_key(None) is False


# ── integration: a placeholder is NOT verified online; it prompts instead ─────
def test_placeholder_prompts_and_is_never_sent_to_verifier(monkeypatch):
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_ENV_PLACEHOLDER_GUARD", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-" + "x" * 40)  # placeholder configured
    seen = []

    def _verify(k):
        seen.append(k)
        return "ok"

    keys = iter([VALID])  # what the operator pastes at the prompt
    ok = s._ensure_api_key(getpass_fn=lambda _p: next(keys), verifier=_verify)
    assert ok is True
    # the placeholder must never have been sent to the API verifier
    assert ("sk-ant-" + "x" * 40) not in seen
    # only the real pasted key was verified
    assert seen == [VALID]


def test_guard_off_falls_back_to_verify_path(monkeypatch):
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_ENV_PLACEHOLDER_GUARD", "0")  # disabled
    placeholder = "sk-ant-" + "x" * 40
    monkeypatch.setenv("ANTHROPIC_API_KEY", placeholder)
    seen = []

    def _verify(k):
        seen.append(k)
        # the placeholder is rejected by the API; a real pasted key is accepted
        return "rejected" if k == placeholder else "ok"

    keys = iter([VALID])
    ok = s._ensure_api_key(getpass_fn=lambda _p: next(keys), verifier=_verify)
    assert ok is True
    # with the guard OFF, the placeholder IS sent to verify (old behavior)
    assert placeholder in seen
