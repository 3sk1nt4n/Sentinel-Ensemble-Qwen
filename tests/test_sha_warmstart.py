"""Warm-SHA wait helper: waits for an in-flight hash, never 2x-waits a failed one."""
import os

from sift_sentinel.onboard.sha_warmstart import inprogress_marker, await_precomputed_file


def test_file_already_present_returns_immediately(tmp_path):
    pf = tmp_path / "presha.json"
    pf.write_text("{}")
    calls = []
    assert await_precomputed_file(str(pf), sleep=lambda s: calls.append(s)) is True
    assert calls == []                                  # no waiting


def test_no_marker_no_file_returns_false_immediately(tmp_path):
    pf = tmp_path / "presha.json"
    calls = []
    assert await_precomputed_file(str(pf), sleep=lambda s: calls.append(s)) is False
    assert calls == []                                  # no warm hash -> no wait


def test_waits_then_file_appears(tmp_path):
    pf = tmp_path / "presha.json"
    open(inprogress_marker(str(pf)), "w").close()       # warm hash in flight
    # the injected sleep publishes the file on the 2nd tick (simulates the warm thread)
    state = {"n": 0}

    def _sleep(_s):
        state["n"] += 1
        if state["n"] == 2:
            pf.write_text("{}")
            os.remove(inprogress_marker(str(pf)))

    assert await_precomputed_file(str(pf), sleep=_sleep) is True
    assert state["n"] == 2


def test_marker_removed_without_file_means_failed_warm_hash(tmp_path):
    pf = tmp_path / "presha.json"
    open(inprogress_marker(str(pf)), "w").close()
    # warm hash FAILS: marker removed, file never written -> stop fast, cold-hash
    def _sleep(_s):
        os.remove(inprogress_marker(str(pf)))
    assert await_precomputed_file(str(pf), sleep=_sleep) is False


def test_bounded_by_max_wait_when_marker_stuck(tmp_path):
    pf = tmp_path / "presha.json"
    open(inprogress_marker(str(pf)), "w").close()       # marker never removed
    clock = {"t": 0.0}
    ticks = []
    assert await_precomputed_file(
        str(pf), max_wait=2.0,
        sleep=lambda s: (ticks.append(s), clock.__setitem__("t", clock["t"] + s)),
        now=lambda: clock["t"],
    ) is False
    assert sum(ticks) <= 2.5                              # never hangs
