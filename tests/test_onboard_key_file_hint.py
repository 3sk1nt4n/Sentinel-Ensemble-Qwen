"""Key-entry discoverability: when no usable key is configured, the onboard step
must tell the operator/judge (a) they can just paste at the prompt -- nothing to
find or edit -- and (b) the EXACT path of the optional `.env` file plus that it is
a hidden dot-file (Ctrl+H to reveal). This kills the "I can't find where to put my
key" confusion without forcing anyone to hunt for a hidden file.

Universal: the hint names a path derived from the repo location only; it carries
no case/dataset content and is shape-free. Kill-switch SIFT_KEY_FILE_HINT=0.
"""
import os
import step0_onboard as s

VALID = "sk-ant-" + "A1b2C3d4" * 13   # format-valid shape, not a real key
KEY_PATH = os.path.join(s._REPO, "API_KEY.txt")   # the VISIBLE file (no hidden dot)


def _run(monkeypatch, capsys, *, key_in_env=None, hint="1"):
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_KEY_FILE_HINT", hint)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    if key_in_env is None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    else:
        monkeypatch.setenv("ANTHROPIC_API_KEY", key_in_env)
    pasted = iter([VALID])
    ok = s._ensure_api_key(getpass_fn=lambda _p: next(pasted, ""),
                           verifier=lambda _k: "ok")
    return ok, capsys.readouterr().out


# ── the hint shows when there is no usable key ───────────────────────────────
def test_no_key_prints_visible_file_path(monkeypatch, capsys):
    ok, out = _run(monkeypatch, capsys, key_in_env=None, hint="1")
    assert ok is True
    assert KEY_PATH in out                 # the exact VISIBLE file path
    # it must NOT scare the judge into thinking a file is required
    assert "prompt" in out.lower() and "save" in out.lower()


# ── the kill-switch silences it ──────────────────────────────────────────────
def test_kill_switch_off_suppresses_hint(monkeypatch, capsys):
    ok, out = _run(monkeypatch, capsys, key_in_env=None, hint="0")
    assert ok is True
    assert "API_KEY.txt" not in out


# ── a frictionless skip (valid key already present) must NOT show the hint ────
def test_valid_existing_key_skips_hint(monkeypatch, capsys):
    ok, out = _run(monkeypatch, capsys, key_in_env=VALID, hint="1")
    assert ok is True
    assert "skipping the paste step" in out         # took the frictionless path
    assert "API_KEY.txt" not in out


# ── the hint never contains a real key's bytes (it's pure guidance) ──────────
def test_hint_carries_no_secret(monkeypatch, capsys):
    _, out = _run(monkeypatch, capsys, key_in_env=None, hint="1")
    assert VALID not in out                 # the pasted key is never echoed
