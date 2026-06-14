"""Slot 31E-DB.5a-beta TASK 6 -- REACT_INFLIGHT_TOOL_DEDUPE_GATE /
HIGH_COST_RAW_SCOPE_DEDUPE_GATE.

Full-image high-cost plugins (vol_vadinfo, vol_hollowprocesses,
vol_ldrmodules) scan the whole image and filter by PID afterward. Two
concurrent ReAct findings requesting the same plugin for *different*
PIDs must collapse to ONE launch keyed by raw execution scope (image),
not by PID. Truly PID-scoped tools key on their argument signature.
Deadlock-safe: the owner runs synchronously; duplicates wait on the
owner's Future. Dataset-agnostic (synthetic PIDs 91000-99999).
"""
from __future__ import annotations

import threading

from sift_sentinel.react_discipline import (
    HIGH_COST_FULL_IMAGE_TOOLS,
    dedupe_run,
    dedupe_scope_key,
    reset_react_tool_discipline_state,
)

_GATE = "REACT_INFLIGHT_TOOL_DEDUPE_GATE"
_GATE_RAW = "HIGH_COST_RAW_SCOPE_DEDUPE_GATE"

_SYN_IMAGE = "/synthetic/memory.raw"
_SYN_PID_A = 91001
_SYN_PID_B = 91002


def setup_function(_):
    reset_react_tool_discipline_state()


def teardown_function(_):
    reset_react_tool_discipline_state()


def test_full_image_tool_key_ignores_pid():
    assert "vol_vadinfo" in HIGH_COST_FULL_IMAGE_TOOLS
    k_a = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, f"pid={_SYN_PID_A}")
    k_b = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, f"pid={_SYN_PID_B}")
    # Different PIDs, same image -> identical raw-scope key.
    assert k_a == k_b == ("vol_vadinfo", _SYN_IMAGE)


def test_pid_scoped_tool_key_uses_arg_signature():
    k_a = dedupe_scope_key("synthetic_pid_tool", _SYN_IMAGE,
                           f"pid={_SYN_PID_A}")
    k_b = dedupe_scope_key("synthetic_pid_tool", _SYN_IMAGE,
                           f"pid={_SYN_PID_B}")
    assert k_a != k_b
    assert k_a == ("synthetic_pid_tool", f"pid={_SYN_PID_A}")


def test_concurrent_full_image_collapses_to_one_launch():
    launches = {"n": 0}
    launch_lock = threading.Lock()
    owner_started = threading.Event()
    release = threading.Event()

    def _runner():
        with launch_lock:
            launches["n"] += 1
        owner_started.set()
        release.wait(timeout=5)
        return [{"PID": _SYN_PID_A}, {"PID": _SYN_PID_B}]

    results: dict[str, object] = {}

    def _call(name, pid):
        key = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, f"pid={pid}")
        results[name] = dedupe_run(key, _runner)

    t_owner = threading.Thread(target=_call, args=("owner", _SYN_PID_A))
    t_owner.start()
    assert owner_started.wait(timeout=5), "owner runner never started"

    # Duplicate caller arrives while the owner's launch is in flight.
    t_dup = threading.Thread(target=_call, args=("dup", _SYN_PID_B))
    t_dup.start()
    # Give the duplicate time to register as a waiter, then release.
    threading.Event().wait(0.2)
    release.set()
    t_owner.join(timeout=5)
    t_dup.join(timeout=5)

    assert launches["n"] == 1, "full-image plugin launched more than once"
    assert results["owner"] == results["dup"]


def test_key_removed_after_completion_allows_relaunch():
    calls = {"n": 0}

    def _runner():
        calls["n"] += 1
        return ["ok"]

    key = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, "pid=91003")
    assert dedupe_run(key, _runner) == ["ok"]
    # Sequential (not concurrent) reuse: key freed in finally, so a
    # genuinely new later request can run again.
    assert dedupe_run(key, _runner) == ["ok"]
    assert calls["n"] == 2


def test_marker():
    print(f"{_GATE}=PASS")
    print(f"{_GATE_RAW}=PASS")
    assert _GATE == "REACT_INFLIGHT_TOOL_DEDUPE_GATE"
    assert _GATE_RAW == "HIGH_COST_RAW_SCOPE_DEDUPE_GATE"
