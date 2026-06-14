"""run_strings wall time is bounded by SIFT_STRINGS_TIMEOUT (default 120s) so an
operator can cap the historic slow tool's share of the pipeline budget."""
import subprocess
import sift_sentinel.tools.generic as g


def _capture_timeout(monkeypatch, tmp_path, env=None):
    f = tmp_path / "img.bin"; f.write_text("hello world string here")
    seen = {}
    def _fake_run(cmd, **kw):
        seen["timeout"] = kw.get("timeout")
        class R: stdout = "hello\nworld\n"
        return R()
    monkeypatch.setattr(subprocess, "run", _fake_run)
    if env is not None:
        monkeypatch.setenv("SIFT_STRINGS_TIMEOUT", env)
    else:
        monkeypatch.delenv("SIFT_STRINGS_TIMEOUT", raising=False)
    g.run_strings(str(f))
    return seen["timeout"]


def test_default_timeout_is_120(monkeypatch, tmp_path):
    assert _capture_timeout(monkeypatch, tmp_path) == 120


def test_env_overrides_timeout(monkeypatch, tmp_path):
    assert _capture_timeout(monkeypatch, tmp_path, env="45") == 45


def test_invalid_env_falls_back_to_120(monkeypatch, tmp_path):
    assert _capture_timeout(monkeypatch, tmp_path, env="bad") == 120
