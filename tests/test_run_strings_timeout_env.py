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


# ── Partial-output salvage on timeout (data-completeness, dataset-agnostic) ──
def test_strings_timeout_salvages_partial_output(tmp_path, monkeypatch):
    """On TimeoutExpired, the strings already emitted before the kill must be
    KEPT (not dropped to zero) and the result flagged partial. Universal: no
    case content, just 'use what was produced within the wall-clock bound'."""
    import subprocess
    from unittest import mock
    from sift_sentinel.tools import generic

    monkeypatch.delenv("SIFT_STRINGS_TIMEOUT", raising=False)
    f = tmp_path / "mem.img"
    f.write_bytes(b"x" * 1000)
    te = subprocess.TimeoutExpired(cmd=["strings"], timeout=120,
                                   output="alpha\nbeta\ngamma\n")
    with mock.patch("subprocess.run", side_effect=te):
        r = generic.run_strings(str(f))
    assert r["record_count"] == 3          # salvaged, not zeroed
    assert r.get("partial") is True
    assert "error" not in r                # partial data is not a hard error


def test_strings_timeout_salvage_respects_cap(tmp_path, monkeypatch):
    import subprocess
    from unittest import mock
    from sift_sentinel.tools import generic

    monkeypatch.delenv("SIFT_STRINGS_TIMEOUT", raising=False)
    monkeypatch.setenv("SIFT_STRINGS_MAX", "2")
    f = tmp_path / "mem.img"
    f.write_bytes(b"x" * 1000)
    te = subprocess.TimeoutExpired(cmd=["strings"], timeout=120,
                                   output="a\nb\nc\nd\ne\n")
    with mock.patch("subprocess.run", side_effect=te):
        r = generic.run_strings(str(f))
    assert r["record_count"] == 2          # cap still enforced on salvage
