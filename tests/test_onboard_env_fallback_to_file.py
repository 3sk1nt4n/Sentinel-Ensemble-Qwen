"""A stale / invalid ANTHROPIC_API_KEY in the environment must NOT block a valid key
the operator put in API_KEY.txt (or .env). When the env key is rejected (401) or is a
placeholder, onboarding falls back to a VERIFYING file key before prompting -- so the
file the operator just edited actually works, even with an old export still in the shell.

Universal / shape-based; fake keys + stub verifiers only (never touches a real file).
"""
import os
import step0_onboard as s

VALID = "sk-ant-" + "A1b2C3d4" * 13     # the good key in the file
BADENV = "sk-ant-" + "B2c3D4e5" * 13    # a different, rejected key in the environment
PLACE = "sk-ant-" + "x" * 40


def _verify(k):
    return "ok" if k == VALID else "rejected"


def test_rejected_env_falls_back_to_file_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", BADENV)          # stale export, will 401
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    monkeypatch.setattr(s, "_find_key_in_files",
                        lambda **kw: (VALID, "your API_KEY.txt file", False))
    prompted = []
    ok = s._ensure_api_key(getpass_fn=lambda _p: prompted.append("X") or "",
                           verifier=_verify)
    assert ok is True
    assert "X" not in prompted                                # used the file key, no prompt
    assert os.environ["ANTHROPIC_API_KEY"] == VALID


def test_placeholder_env_falls_back_to_file_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", PLACE)            # placeholder in env
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    monkeypatch.setattr(s, "_find_key_in_files",
                        lambda **kw: (VALID, "your API_KEY.txt file", False))
    ok = s._ensure_api_key(getpass_fn=lambda _p: "", verifier=_verify)
    assert ok is True
    assert os.environ["ANTHROPIC_API_KEY"] == VALID


def test_rejected_env_no_valid_file_still_prompts(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", BADENV)
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    monkeypatch.setattr(s, "_find_key_in_files", lambda **kw: (None, None, False))
    pasted = iter([VALID])
    prompted = []
    ok = s._ensure_api_key(
        getpass_fn=lambda _p: (prompted.append("X"), next(pasted))[1], verifier=_verify)
    assert ok is True and "X" in prompted                     # fell through to the prompt


def test_file_key_also_rejected_does_not_loop(monkeypatch):
    # env bad AND file bad -> must still reach the prompt (no false success, no infinite verify)
    monkeypatch.setenv("ANTHROPIC_API_KEY", BADENV)
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    monkeypatch.setattr(s, "_find_key_in_files",
                        lambda **kw: (BADENV, "your API_KEY.txt file", False))
    pasted = iter([VALID])
    prompted = []
    ok = s._ensure_api_key(
        getpass_fn=lambda _p: (prompted.append("X"), next(pasted))[1], verifier=_verify)
    assert ok is True and "X" in prompted
