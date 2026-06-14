"""Slot 31E-DB.5d GROUP C TASK C1 -- HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT.

Observed bug: vol_vadinfo was in-flight for one PID; a second finding
for a different PID hit the budget check first and got
tool_budget_exhausted instead of waiting for the shared full-image
result. The fixed dispatch evaluates, atomically under one lock:
in-flight wait (no counter increment) BEFORE budget. The budget still
blocks a genuinely new launch once nothing is in flight.
Dataset-agnostic: synthetic image path, PIDs 91000-99999.
"""
from __future__ import annotations

import threading

from sift_sentinel.react_discipline import (
    HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE,
    dedupe_scope_key,
    high_cost_dispatch,
    register_launch,
    reset_react_tool_discipline_state,
)

_SYN_IMAGE = "/synthetic/memory.raw"


def setup_function(_):
    reset_react_tool_discipline_state()


def teardown_function(_):
    reset_react_tool_discipline_state()


def test_inflight_wait_wins_over_budget_for_different_pid():
    """vol_vadinfo budget == 1. Owner launches for PID A; a concurrent
    different-PID caller must WAIT on the owner, not be told the budget
    is exhausted."""
    owner_started = threading.Event()
    release = threading.Event()
    launches = {"n": 0}
    lk = threading.Lock()

    def _runner():
        with lk:
            launches["n"] += 1
        owner_started.set()
        release.wait(timeout=5)
        return [{"PID": 91001}, {"PID": 91002}]

    results: dict[str, object] = {}

    def _call(name, pid):
        key = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, f"pid={pid}")
        results[name] = high_cost_dispatch("vol_vadinfo", key, _runner)

    t_owner = threading.Thread(target=_call, args=("owner", 91001))
    t_owner.start()
    assert owner_started.wait(timeout=5), "owner never started"

    t_dup = threading.Thread(target=_call, args=("dup", 91002))
    t_dup.start()
    threading.Event().wait(0.2)  # let the dup register as a waiter
    release.set()
    t_owner.join(timeout=5)
    t_dup.join(timeout=5)

    assert launches["n"] == 1, "full-image plugin launched more than once"
    # The duplicate got the shared result, NOT tool_budget_exhausted.
    assert results["dup"] == results["owner"]
    assert not (isinstance(results["dup"], dict)
                and results["dup"].get("failure_mode")
                == "tool_budget_exhausted")


def test_budget_still_blocks_a_genuinely_new_launch():
    """Once nothing is in flight and the budget is spent, a new scope
    is correctly refused."""
    k1 = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, "pid=91003")
    assert high_cost_dispatch("vol_vadinfo", k1, lambda: ["ok"]) == ["ok"]
    # Budget for vol_vadinfo is 1 and the first launch consumed it.
    k2 = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, "pid=91004")
    res = high_cost_dispatch("vol_vadinfo", k2, lambda: ["should-not-run"])
    assert isinstance(res, dict)
    assert res["failure_mode"] == "tool_budget_exhausted"


def test_waiter_does_not_increment_counter():
    """A waiter must not consume budget. After one in-flight launch
    that two callers share, exactly one budget unit is spent, so a
    later different tool launch is unaffected and ldrmodules (budget 2)
    still allows its full quota."""
    owner_started = threading.Event()
    release = threading.Event()

    def _runner():
        owner_started.set()
        release.wait(timeout=5)
        return ["shared"]

    out: dict[str, object] = {}

    def _call(name, pid):
        key = dedupe_scope_key("vol_vadinfo", _SYN_IMAGE, f"pid={pid}")
        out[name] = high_cost_dispatch("vol_vadinfo", key, _runner)

    a = threading.Thread(target=_call, args=("a", 91005))
    a.start()
    assert owner_started.wait(timeout=5)
    b = threading.Thread(target=_call, args=("b", 91006))
    b.start()
    threading.Event().wait(0.2)
    release.set()
    a.join(timeout=5)
    b.join(timeout=5)
    assert out["a"] == out["b"] == ["shared"]

    # ldrmodules budget is 2 and was never touched -> both allowed.
    assert register_launch("vol_ldrmodules") is None
    assert register_launch("vol_ldrmodules") is None
    assert register_launch("vol_ldrmodules") is not None


def test_sequential_relaunch_after_completion_respects_budget():
    k = dedupe_scope_key("vol_ldrmodules", _SYN_IMAGE, "pid=91007")
    assert high_cost_dispatch("vol_ldrmodules", k, lambda: ["r1"]) == ["r1"]
    k2 = dedupe_scope_key("vol_ldrmodules", _SYN_IMAGE, "pid=91008")
    assert high_cost_dispatch("vol_ldrmodules", k2, lambda: ["r2"]) == ["r2"]
    # ldrmodules budget == 2 -> a third genuinely new launch is refused.
    k3 = dedupe_scope_key("vol_ldrmodules", _SYN_IMAGE, "pid=91009")
    res = high_cost_dispatch("vol_ldrmodules", k3, lambda: ["r3"])
    assert isinstance(res, dict)
    assert res["failure_mode"] == "tool_budget_exhausted"


def test_marker():
    print(f"{HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE}=PASS")
    assert (HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE
            == "HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE")
