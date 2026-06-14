"""Live API-key guardrail: a key that passes the FORMAT gate but the API rejects (HTTP
401 invalid x-api-key) must be caught at the prompt, not after launching. The live
check fails OPEN -- a network problem never blocks a launch. Universal, no secrets.
"""
import os

import step0_onboard as s

VALID = "sk-ant-" + "A1b2C3d4" * 13          # format-valid shape, not a real key


# ── verify_api_key_live classification (injected client, no network) ──────────
class _Client:
    def __init__(self, exc=None):
        self._exc = exc

    class _Models:
        def __init__(self, exc):
            self._exc = exc

        def list(self):
            if self._exc:
                raise self._exc
            return ["model-a"]

    @property
    def models(self):
        return self._Models(self._exc)


def test_live_ok_when_api_accepts():
    assert s.verify_api_key_live(VALID, _client_factory=lambda k: _Client()) == "ok"


def test_live_rejected_on_auth_error():
    exc = Exception("authentication_error: invalid x-api-key")
    assert s.verify_api_key_live(VALID, _client_factory=lambda k: _Client(exc)) == "rejected"


def test_live_unverified_on_network_error():
    exc = Exception("Connection timed out")
    assert s.verify_api_key_live(VALID, _client_factory=lambda k: _Client(exc)) == "unverified"


def test_live_unverified_when_client_factory_raises():
    def boom(_k):
        raise RuntimeError("no sdk")
    assert s.verify_api_key_live(VALID, _client_factory=boom) == "unverified"


# ── _ensure_api_key uses the verifier ────────────────────────────────────────
def _gp(seq):
    it = iter(seq)
    return lambda _p: next(it)


def test_rejected_pasted_key_reprompts_then_accepts(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    statuses = iter(["rejected", "ok"])
    ok = s._ensure_api_key(getpass_fn=_gp([VALID, VALID]),
                           verifier=lambda k: next(statuses))
    assert ok is True                                  # second key accepted after reprompt
    assert os.environ.get("ANTHROPIC_API_KEY") == VALID


def test_all_rejected_fails_no_launch(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ok = s._ensure_api_key(getpass_fn=lambda _p: VALID,
                           verifier=lambda k: "rejected", max_tries=2)
    assert ok is False


def test_unverified_fails_open_and_proceeds(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ok = s._ensure_api_key(getpass_fn=lambda _p: VALID, verifier=lambda k: "unverified")
    assert ok is True


def test_ok_proceeds(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ok = s._ensure_api_key(getpass_fn=lambda _p: VALID, verifier=lambda k: "ok")
    assert ok is True


def test_reused_stale_key_rejected_then_fresh_paste_accepts(monkeypatch):
    # A configured (env) key that the API rejects must NOT auto-skip -- it falls through
    # to a fresh paste, which is then accepted.
    monkeypatch.setenv("ANTHROPIC_API_KEY", VALID)
    statuses = iter(["rejected", "ok"])   # configured key rejected; pasted key ok
    ok = s._ensure_api_key(getpass_fn=_gp([VALID]), verifier=lambda k: next(statuses))
    assert ok is True


# ── auto-skip when a key is already configured (env / .env) ───────────────────
def test_configured_valid_key_auto_skips_without_prompting(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", VALID)

    def _no_prompt(_p):
        raise AssertionError("must not prompt when a valid key is already configured")

    assert s._ensure_api_key(getpass_fn=_no_prompt, verifier=lambda k: "ok") is True


def test_configured_unverified_key_fails_open_and_skips(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", VALID)

    def _no_prompt(_p):
        raise AssertionError("must not prompt; fail open on a network-unverified key")

    assert s._ensure_api_key(getpass_fn=_no_prompt, verifier=lambda k: "unverified") is True


def test_force_prompt_disables_auto_skip(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", VALID)
    monkeypatch.setenv("SIFT_FORCE_KEY_PROMPT", "1")
    # forced to show the step; Enter reuses the existing (verified) key
    assert s._ensure_api_key(getpass_fn=lambda _p: "", verifier=lambda k: "ok") is True


# ── .env file support (parse only ANTHROPIC_API_KEY, no shell execution) ──────
def test_env_file_api_key_is_loaded(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = tmp_path / ".env"
    p.write_text('# comment\nOTHER=1\nANTHROPIC_API_KEY="%s"\n' % VALID)
    assert s._load_env_file_api_key(path=str(p)) is True
    assert os.environ.get("ANTHROPIC_API_KEY") == VALID


def test_env_file_does_not_override_existing(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-existing")
    p = tmp_path / ".env"
    p.write_text("ANTHROPIC_API_KEY=%s\n" % VALID)
    assert s._load_env_file_api_key(path=str(p)) is False
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-ant-existing"
