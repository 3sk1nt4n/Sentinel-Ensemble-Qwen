"""Slot 31E-DB.5a-beta TASK 4 -- UNAVAILABLE_TOOL_RETRY_GATE.

A tool that is unavailable on this evidence must be recorded once and
short-circuited for every later ReAct request in the same run, instead
of being re-attempted per finding. Dataset-agnostic synthetic fixtures
only (synthetic tool identifiers, no real PIDs/paths/hashes).
"""
from __future__ import annotations

from sift_sentinel.react_discipline import (
    note_tool_unavailable,
    precheck_tool,
    reset_react_tool_discipline_state,
)

_GATE = "UNAVAILABLE_TOOL_RETRY_GATE"

_FIXTURE_TOOL = "synthetic_unavailable_tool"


def setup_function(_):
    reset_react_tool_discipline_state()


def teardown_function(_):
    reset_react_tool_discipline_state()


def test_precheck_clean_before_mark():
    assert precheck_tool(_FIXTURE_TOOL) is None


def test_unavailable_short_circuits_with_synthetic():
    note_tool_unavailable(_FIXTURE_TOOL)
    res = precheck_tool(_FIXTURE_TOOL)
    assert res is not None
    assert res["failure_mode"] == "tool_unavailable_cached"
    assert res["tool"] == _FIXTURE_TOOL
    assert res["output"] == []
    assert "previously unavailable" in res["reason"].lower()


def test_unavailable_blocks_even_with_force():
    # Unavailable is absolute: a force flag does NOT revive a dead tool.
    note_tool_unavailable(_FIXTURE_TOOL)
    assert precheck_tool(_FIXTURE_TOOL, force=True) is not None


def test_reset_clears_unavailable_cache():
    note_tool_unavailable(_FIXTURE_TOOL)
    assert precheck_tool(_FIXTURE_TOOL) is not None
    reset_react_tool_discipline_state()
    assert precheck_tool(_FIXTURE_TOOL) is None


def test_other_tools_unaffected():
    note_tool_unavailable(_FIXTURE_TOOL)
    assert precheck_tool("synthetic_other_tool") is None


def test_marker():
    print(f"{_GATE}=PASS")
    assert _GATE == "UNAVAILABLE_TOOL_RETRY_GATE"
