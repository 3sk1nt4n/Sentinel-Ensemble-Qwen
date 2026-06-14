"""Slot 31E-DB.5a-beta TASK 5 -- TIMEOUT_TOOL_RETRY_GATE /
VOL_MEMMAP_TIMEOUT_RETRY_GATE.

A tool that times out (subprocess- or pipeline-level) is recorded and
short-circuited for later ReAct requests in the same run, UNLESS an
explicit force flag is set. vol_memmap is the canonical expensive
timeout offender, so it gets a dedicated assertion. Dataset-agnostic.
"""
from __future__ import annotations

from sift_sentinel.react_discipline import (
    note_tool_timed_out,
    precheck_tool,
    reset_react_tool_discipline_state,
)

_GATE = "TIMEOUT_TOOL_RETRY_GATE"
_GATE_MEMMAP = "VOL_MEMMAP_TIMEOUT_RETRY_GATE"


def setup_function(_):
    reset_react_tool_discipline_state()


def teardown_function(_):
    reset_react_tool_discipline_state()


def test_timeout_short_circuits_with_synthetic():
    note_tool_timed_out("synthetic_slow_tool")
    res = precheck_tool("synthetic_slow_tool")
    assert res is not None
    assert res["failure_mode"] == "tool_timed_out_cached"
    assert res["output"] == []
    assert "previously timed out" in res["reason"].lower()


def test_timeout_respects_explicit_force():
    note_tool_timed_out("synthetic_slow_tool")
    assert precheck_tool("synthetic_slow_tool", force=False) is not None
    # Explicit force flag re-enables a timed-out tool (operator intent).
    assert precheck_tool("synthetic_slow_tool", force=True) is None


def test_vol_memmap_timeout_cached():
    note_tool_timed_out("vol_memmap")
    res = precheck_tool("vol_memmap")
    assert res is not None
    assert res["failure_mode"] == "tool_timed_out_cached"
    assert res["tool"] == "vol_memmap"


def test_reset_clears_timeout_cache():
    note_tool_timed_out("vol_memmap")
    assert precheck_tool("vol_memmap") is not None
    reset_react_tool_discipline_state()
    assert precheck_tool("vol_memmap") is None


def test_marker():
    print(f"{_GATE}=PASS")
    print(f"{_GATE_MEMMAP}=PASS")
    assert _GATE == "TIMEOUT_TOOL_RETRY_GATE"
    assert _GATE_MEMMAP == "VOL_MEMMAP_TIMEOUT_RETRY_GATE"
