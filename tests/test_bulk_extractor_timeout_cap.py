"""run_bulk_extractor must not gate the whole pipeline for 10 minutes.

On the acme run bulk_extractor consumed its full 600 s timeout and returned
0 records -- ~48% of the entire runtime -- because Step 6 waits for the
slowest tool. The carve timeout is now bounded by SIFT_BULK_EXTRACTOR_TIMEOUT
(default 180 s, was a hardcoded 600), operator-overridable. extract_network_iocs
already covers the network-IOC value cheaply, so the cap loses little.
Universal: a time bound, no case data.
"""
from __future__ import annotations

import subprocess

import sift_sentinel.tools.generic as generic


class _Captured(Exception):
    pass


def _capture_timeout(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["timeout"] = kw.get("timeout")
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    monkeypatch.setattr(generic.subprocess, "run", fake_run)
    monkeypatch.setattr(generic.os.path, "exists", lambda p: True)
    monkeypatch.setattr(generic.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(generic.os.path, "isdir", lambda p: False)
    img = tmp_path / "img.raw"
    img.write_bytes(b"x")
    out = generic.run_bulk_extractor(str(img), output_dir=str(tmp_path / "bo"))
    return seen.get("timeout"), out


def test_default_timeout_is_capped_at_180(monkeypatch, tmp_path):
    monkeypatch.delenv("SIFT_BULK_EXTRACTOR_TIMEOUT", raising=False)
    t, out = _capture_timeout(monkeypatch, tmp_path)
    assert t == 180, t
    assert out["record_count"] == 0
    assert "180" in out.get("error", "")


def test_operator_can_override_higher(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_BULK_EXTRACTOR_TIMEOUT", "600")
    t, _ = _capture_timeout(monkeypatch, tmp_path)
    assert t == 600


def test_operator_can_override_lower(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_BULK_EXTRACTOR_TIMEOUT", "60")
    t, _ = _capture_timeout(monkeypatch, tmp_path)
    assert t == 60


def test_bad_value_falls_back_to_default(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_BULK_EXTRACTOR_TIMEOUT", "not-a-number")
    t, _ = _capture_timeout(monkeypatch, tmp_path)
    assert t == 180


def test_strings_timeout_already_env_bounded(monkeypatch, tmp_path):
    # run_strings was already bounded by SIFT_STRINGS_TIMEOUT -- guard it stays so
    seen = {}

    def fake_run(cmd, **kw):
        seen["timeout"] = kw.get("timeout")
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    monkeypatch.setattr(generic.subprocess, "run", fake_run)
    monkeypatch.setattr(generic.os.path, "exists", lambda p: True)
    monkeypatch.setenv("SIFT_STRINGS_TIMEOUT", "45")
    img = tmp_path / "img.raw"
    img.write_bytes(b"x")
    out = generic.run_strings(str(img))
    assert seen.get("timeout") == 45
    assert out["record_count"] == 0
