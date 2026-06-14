"""Step-zero storage guard rail: clear accumulated run output (each run leaves a
~600MB /tmp/sift-sentinel-run-* dir) before starting, and report stale mounts /
free space as a PASS gate. The dir-selection is pure and tested here; the actual
rm/umount is a best-effort wrapper that never breaks onboarding. Universal:
keyed on the SIFT run-dir prefix only, no case data.
"""

import os
import sys
import time

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

import step0_onboard as s  # noqa: E402


def test_stale_run_dirs_selects_old_prefixed_dirs(tmp_path):
    old = tmp_path / "sift-sentinel-run-111"
    old.mkdir()
    new = tmp_path / "sift-sentinel-run-222"
    new.mkdir()
    other = tmp_path / "not-ours"
    other.mkdir()
    # age the 'old' dir past the min_age guard; keep 'new' recent.
    past = time.time() - 600
    os.utime(old, (past, past))
    found = s._stale_run_dirs(str(tmp_path), min_age_s=60)
    assert str(old) in found
    assert str(new) not in found        # too recent (within guard) -> not cleaned
    assert str(other) not in found      # wrong prefix -> never touched


def test_stale_run_dirs_empty_when_none(tmp_path):
    assert s._stale_run_dirs(str(tmp_path), min_age_s=60) == []


def test_preflight_never_raises(monkeypatch, tmp_path):
    # Even on a bogus root / no perms, the gate must be a no-op, never raise.
    monkeypatch.setenv("SIFT_STORAGE_PREFLIGHT", "1")
    s._storage_preflight(run_root=str(tmp_path), mnt_root=str(tmp_path / "nope"))


def test_preflight_kill_switch(monkeypatch, tmp_path):
    monkeypatch.setenv("SIFT_STORAGE_PREFLIGHT", "0")
    d = tmp_path / "sift-sentinel-run-999"
    d.mkdir()
    past = time.time() - 600
    os.utime(d, (past, past))
    s._storage_preflight(run_root=str(tmp_path), mnt_root=str(tmp_path))
    assert d.exists()                   # kill-switch -> nothing cleaned
