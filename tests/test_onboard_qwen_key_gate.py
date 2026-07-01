"""Qwen-mode key gate: with SIFT_LLM_PROVIDER=qwen the launcher's API-key step
must accept a DashScope key (DASHSCOPE_API_KEY / QWEN_API_KEY), reject an
Anthropic-shaped key with a clear hint, and leave Anthropic-mode behavior
byte-identical. Regression guard for the launch-blocking bug where the key gate
demanded an Anthropic key on a Qwen-only install. Universal, no secrets."""
import os

import step0_onboard as s

# Format-valid shapes, not real keys.
QWEN_KEY = "sk-ws-AB.CDEFGH.ijkl." + "Mn0PqRsT" * 8
ANT_KEY = "sk-ant-" + "A1b2C3d4" * 13


def _set_qwen(monkeypatch):
    monkeypatch.setenv("SIFT_LLM_PROVIDER", "qwen")


# ── provider resolution ────────────────────────────────────────────────────────
def test_qwen_mode_follows_provider_env(monkeypatch):
    monkeypatch.delenv("SIFT_LLM_PROVIDER", raising=False)
    assert s._qwen_mode() is False
    assert s._key_env_name() == "ANTHROPIC_API_KEY"
    _set_qwen(monkeypatch)
    assert s._qwen_mode() is True
    assert s._key_env_name() == "DASHSCOPE_API_KEY"


# ── format validation ──────────────────────────────────────────────────────────
def test_qwen_mode_accepts_dashscope_key_format(monkeypatch):
    _set_qwen(monkeypatch)
    ok, why = s.validate_api_key(QWEN_KEY)
    assert ok, why


def test_qwen_mode_rejects_anthropic_key_with_hint(monkeypatch):
    _set_qwen(monkeypatch)
    ok, why = s.validate_api_key(ANT_KEY)
    assert not ok
    assert "anthropic" in why.lower()


def test_qwen_mode_allows_dots_in_key(monkeypatch):
    _set_qwen(monkeypatch)
    ok, _ = s.validate_api_key("sk-ws-H.ABCDEF.j5uh." + "x1Y2" * 10)
    assert ok


def test_anthropic_mode_unchanged(monkeypatch):
    monkeypatch.delenv("SIFT_LLM_PROVIDER", raising=False)
    ok, _ = s.validate_api_key(ANT_KEY)
    assert ok
    ok, why = s.validate_api_key(QWEN_KEY)
    assert not ok
    assert "sk-ant-" in why


# ── placeholder detection ──────────────────────────────────────────────────────
def test_qwen_env_example_placeholder_is_detected():
    assert s._is_placeholder_key("sk-your-dashscope-key-here") is True


def test_real_shaped_qwen_key_is_not_placeholder():
    assert s._is_placeholder_key(QWEN_KEY) is False


# ── env / file resolution ──────────────────────────────────────────────────────
def test_env_file_yields_dashscope_key_in_qwen_mode(tmp_path, monkeypatch):
    _set_qwen(monkeypatch)
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    envf = tmp_path / ".env"
    envf.write_text(
        "# comment\nANTHROPIC_API_KEY=%s\nDASHSCOPE_API_KEY=%s\n" % (ANT_KEY, QWEN_KEY)
    )
    assert s._load_env_file_api_key(path=str(envf)) is True
    assert os.environ.get("DASHSCOPE_API_KEY") == QWEN_KEY


def test_env_file_qwen_api_key_alias_accepted(tmp_path, monkeypatch):
    _set_qwen(monkeypatch)
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    envf = tmp_path / ".env"
    envf.write_text("QWEN_API_KEY=%s\n" % QWEN_KEY)
    assert s._load_env_file_api_key(path=str(envf)) is True
    assert os.environ.get("DASHSCOPE_API_KEY") == QWEN_KEY


def test_scan_text_finds_bare_qwen_token_not_anthropic(tmp_path, monkeypatch):
    _set_qwen(monkeypatch)
    f = tmp_path / "API_KEY.txt"
    f.write_text("# header\n%s\n%s\n" % (ANT_KEY, QWEN_KEY))
    tok = s._scan_text_for_anthropic_key(str(f))
    assert tok == QWEN_KEY


def test_scan_text_anthropic_mode_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv("SIFT_LLM_PROVIDER", raising=False)
    f = tmp_path / "API_KEY.txt"
    f.write_text("%s\n" % ANT_KEY)
    assert s._scan_text_for_anthropic_key(str(f)) == ANT_KEY


# ── the gate end-to-end (no network: PYTEST_CURRENT_TEST short-circuits verify) ─
def test_ensure_api_key_uses_env_dashscope_key(monkeypatch, capsys):
    _set_qwen(monkeypatch)
    monkeypatch.setenv("DASHSCOPE_API_KEY", QWEN_KEY)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert s._ensure_api_key(getpass_fn=lambda _p: "") is True


def test_ensure_api_key_honors_qwen_alias(monkeypatch):
    _set_qwen(monkeypatch)
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.setenv("QWEN_API_KEY", QWEN_KEY)
    assert s._ensure_api_key(getpass_fn=lambda _p: "") is True
    assert os.environ.get("DASHSCOPE_API_KEY") == QWEN_KEY


def test_ensure_api_key_pasted_qwen_key_accepted(monkeypatch):
    _set_qwen(monkeypatch)
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    monkeypatch.setenv("SIFT_KEY_FILE_HINT", "0")
    assert s._ensure_api_key(getpass_fn=lambda _p: QWEN_KEY) is True
    assert os.environ.get("DASHSCOPE_API_KEY") == QWEN_KEY


def test_ensure_api_key_never_touches_anthropic_env_in_qwen_mode(monkeypatch):
    _set_qwen(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-stale-should-be-ignored")
    monkeypatch.setenv("DASHSCOPE_API_KEY", QWEN_KEY)
    assert s._ensure_api_key(getpass_fn=lambda _p: "") is True
    # the stale Anthropic key must not have been consulted or overwritten
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-stale-should-be-ignored"


# ── verify_api_key_live classification (injected transport, no network) ───────
def test_verify_live_qwen_injected_factory_still_works(monkeypatch):
    _set_qwen(monkeypatch)

    class _Models:
        @staticmethod
        def list():
            return []

    class _Client:
        models = _Models()

    assert s.verify_api_key_live(QWEN_KEY, _client_factory=lambda k: _Client()) == "ok"


# ── menu naming (cosmetic but judge-facing) ────────────────────────────────────
def test_model_display_names_qwen_models():
    assert "Qwen3.7-Max" in s._model_display("qwen3.7-max")
    assert s._model_display("qwen-plus") == "Qwen-Plus"
