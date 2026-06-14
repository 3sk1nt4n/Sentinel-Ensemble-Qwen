"""cleanup() must reset ALL per-case probe state, including the EWF mount cache,
so a reused RealProbes re-probes cleanly on the next onboarding attempt.

Bug (live): pressing B (back) at the depth menu -- or A=onboard-another -- runs
probes.cleanup() and loops back to the path prompt, reusing the SAME RealProbes.
cleanup() unmounted the EWF fuse mount and cleared _mounts/_ex_root, but left
self._ewf mapping the disk path to the now-unmounted ".../ewf1". The next
onboard returned that stale target from the _ewf cache, fsstat failed on it, and
the disk was classified "unrecognized" -> "No memory or disk images found". The
section just kept restarting.

Fix: cleanup() also clears self._ewf. Universal, no case data. Verifies the
re-probe contract: after cleanup every per-case cache is empty/None.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

import sift_sentinel.onboard.engine as eng  # noqa: E402


def test_cleanup_clears_ewf_and_all_per_case_state(monkeypatch):
    # never actually run sudo umount/dmsetup/losetup in the unit test
    monkeypatch.setattr(eng.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    rp = eng.RealProbes()
    # simulate state left by a first onboarding that EWF-mounted a disk + extracted
    rp._ewf = {"/ev/host-cdrive.E01": "/tmp/sift-ewf-abc/ewf1"}
    rp._mounts = ["/tmp/sift-ewf-abc", "/mnt/c"]
    rp._ex_root = "/tmp/sift-onboard-ex-xyz"
    rp._tmpdirs = []                       # empty -> rmtree is a no-op
    rp._loops = []
    rp._dm = []

    rp.cleanup()

    assert rp._ewf == {}, "stale EWF mount cache survived cleanup -> disk vanishes on re-onboard"
    assert rp._mounts == []
    assert rp._ex_root is None
    assert rp._loops == [] and rp._dm == []


def test_cleanup_is_idempotent(monkeypatch):
    monkeypatch.setattr(eng.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    rp = eng.RealProbes()
    rp.cleanup()
    rp.cleanup()                           # second call must not raise
    assert rp._ewf == {} and rp._mounts == [] and rp._ex_root is None
