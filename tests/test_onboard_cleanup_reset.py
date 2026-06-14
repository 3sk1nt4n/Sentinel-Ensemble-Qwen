"""engine.cleanup() must fully reset extraction tracking so the SAME engine can
re-extract on the next case (the per-run cleanup that stops a multi-case session
from filling /tmp). Without the reset, a stale _ex_root points at the just-removed
dir and the next extract fails. Universal: no case data, no sudo (empty mounts)."""
import os
import tempfile

from sift_sentinel.onboard.engine import RealProbes


def _engine_with_scratch():
    e = RealProbes.__new__(RealProbes)
    e._mounts, e._dm, e._loops = [], [], []   # empty -> cleanup runs no sudo
    d = tempfile.mkdtemp(prefix="sift-onboard-ex-test-")
    with open(os.path.join(d, "big"), "w") as fh:
        fh.write("x" * 1000)
    e._tmpdirs = [d]
    e._ex_root = d
    return e, d


def test_cleanup_removes_scratch_and_resets_extraction_root():
    e, d = _engine_with_scratch()
    e.cleanup()
    assert e._ex_root is None          # reset -> next extract creates a fresh root
    assert e._tmpdirs == []            # tracking cleared
    assert not os.path.exists(d)       # scratch actually freed


def test_cleanup_is_idempotent():
    e, d = _engine_with_scratch()
    e.cleanup()
    e.cleanup()                        # second call must not raise
    assert e._ex_root is None and e._tmpdirs == []
