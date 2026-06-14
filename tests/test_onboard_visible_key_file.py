"""Visible API_KEY.txt: a junior / customer / judge must NOT have to find a hidden
`.env` dot-file. A plainly-named `API_KEY.txt` sits in the repo root; they open it,
paste the key on its own line, save. Onboarding reads it.

Precedence (this is the answer to "what if there's a .env backup too?"):
    environment variable  >  .env  >  API_KEY.txt
A REAL key always wins over a placeholder found anywhere, so a leftover `.env`
placeholder never blocks a real key in `API_KEY.txt`.

Universal: shape-based key extraction only, no case/dataset content, key never echoed.
"""
import os
import step0_onboard as s

VALID = "sk-ant-" + "A1b2C3d4" * 13      # format-valid shape, not a real key
VALID2 = "sk-ant-" + "Z9y8X7w6" * 13
PLACE = "sk-ant-" + "x" * 40             # the shipped placeholder shape


# ── _scan_text_for_anthropic_key: bare token OR KEY=value, comments skipped ───
def test_scan_bare_token_line(tmp_path):
    p = tmp_path / "API_KEY.txt"
    p.write_text("# paste your key below\n%s\n" % VALID)
    assert s._scan_text_for_anthropic_key(str(p)) == VALID


def test_scan_key_equals_value(tmp_path):
    p = tmp_path / "API_KEY.txt"
    p.write_text('ANTHROPIC_API_KEY="%s"\n' % VALID)
    assert s._scan_text_for_anthropic_key(str(p)) == VALID


def test_scan_skips_comment_only(tmp_path):
    p = tmp_path / "API_KEY.txt"
    p.write_text("# example: %s (in a comment, must be ignored)\n" % VALID)
    assert s._scan_text_for_anthropic_key(str(p)) is None


def test_scan_missing_file_is_none(tmp_path):
    assert s._scan_text_for_anthropic_key(str(tmp_path / "nope.txt")) is None


# ── _find_key_in_files precedence ─────────────────────────────────────────────
def test_real_env_beats_real_txt(tmp_path):
    env = tmp_path / ".env"; env.write_text("ANTHROPIC_API_KEY=%s\n" % VALID)
    txt = tmp_path / "API_KEY.txt"; txt.write_text("%s\n" % VALID2)
    key, src, is_ph = s._find_key_in_files(env_paths=[str(env)], txt_paths=[str(txt)])
    assert key == VALID and is_ph is False and ".env" in src


def test_real_txt_used_when_env_is_placeholder(tmp_path):
    # the important one: a stale .env placeholder must NOT block a real API_KEY.txt
    env = tmp_path / ".env"; env.write_text("ANTHROPIC_API_KEY=%s\n" % PLACE)
    txt = tmp_path / "API_KEY.txt"; txt.write_text("%s\n" % VALID2)
    key, src, is_ph = s._find_key_in_files(env_paths=[str(env)], txt_paths=[str(txt)])
    assert key == VALID2 and is_ph is False and "API_KEY.txt" in src


def test_placeholder_returned_when_no_real_key(tmp_path):
    env = tmp_path / ".env"; env.write_text("ANTHROPIC_API_KEY=%s\n" % PLACE)
    key, src, is_ph = s._find_key_in_files(env_paths=[str(env)], txt_paths=[])
    assert is_ph is True and s._is_placeholder_key(key)


def test_none_when_no_files(tmp_path):
    key, src, is_ph = s._find_key_in_files(
        env_paths=[str(tmp_path / ".env")], txt_paths=[str(tmp_path / "API_KEY.txt")])
    assert key is None and src is None and is_ph is False


# ── integration: a real key in a VISIBLE API_KEY.txt skips the paste prompt ────
def test_visible_file_real_key_skips_prompt(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SIFT_FORCE_KEY_PROMPT", raising=False)
    monkeypatch.setenv("SIFT_FORCE_COLOR", "0")
    monkeypatch.setattr(s, "_find_key_in_files",
                        lambda **kw: (VALID, "your API_KEY.txt file", False))
    called = []
    ok = s._ensure_api_key(getpass_fn=lambda _p: called.append("PROMPTED") or "",
                           verifier=lambda k: "ok")
    assert ok is True
    assert "PROMPTED" not in called          # the visible file was enough; no prompt


# ── auto-create never litters the real repo during tests ──────────────────────
def test_autocreate_skipped_under_pytest():
    assert os.environ.get("PYTEST_CURRENT_TEST")          # pytest sets this
    before = os.path.exists(os.path.join(s._REPO, "API_KEY.txt"))
    s._ensure_visible_key_file()
    after = os.path.exists(os.path.join(s._REPO, "API_KEY.txt"))
    assert before == after                                # no create/delete in tests


# ── API_KEY.txt must be gitignored (a real key must never be committed) ───────
def test_visible_key_file_gitignored():
    with open(os.path.join(s._REPO, ".gitignore")) as fh:
        assert "API_KEY.txt" in fh.read()
