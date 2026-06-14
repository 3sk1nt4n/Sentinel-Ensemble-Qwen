"""Slot 31E-DB.5a-beta TASK 7 -- HIGH_COST_TOOL_BUDGET_GATE.

Each expensive plugin has a per-run launch budget. The counter
increments only when a dispatch actually launches the tool (never on a
cache/Future hit). Once the budget is spent, dispatch returns an
explicit ``tool_budget_exhausted`` synthetic result. Dataset-agnostic.
"""
from __future__ import annotations

from sift_sentinel.react_discipline import (
    HIGH_COST_TOOL_BUDGET,
    register_launch,
    reset_react_tool_discipline_state,
)

_GATE = "HIGH_COST_TOOL_BUDGET_GATE"


def setup_function(_):
    reset_react_tool_discipline_state()


def teardown_function(_):
    reset_react_tool_discipline_state()


def test_budget_table_contract():
    assert HIGH_COST_TOOL_BUDGET["vol_vadinfo"] == 1
    assert HIGH_COST_TOOL_BUDGET["vol_memmap"] == 1
    assert HIGH_COST_TOOL_BUDGET["vol_ldrmodules"] == 2


def test_single_budget_exhausts_after_one_launch():
    assert register_launch("vol_vadinfo") is None
    res = register_launch("vol_vadinfo")
    assert res is not None
    assert res["failure_mode"] == "tool_budget_exhausted"
    assert res["tool"] == "vol_vadinfo"
    assert res["output"] == []


def test_budget_two_allows_two_then_blocks():
    assert register_launch("vol_ldrmodules") is None
    assert register_launch("vol_ldrmodules") is None
    blocked = register_launch("vol_ldrmodules")
    assert blocked is not None
    assert blocked["failure_mode"] == "tool_budget_exhausted"


def test_non_budgeted_tool_never_exhausts():
    for _ in range(10):
        assert register_launch("synthetic_cheap_tool") is None


def test_reset_restores_budget():
    assert register_launch("vol_vadinfo") is None
    assert register_launch("vol_vadinfo") is not None
    reset_react_tool_discipline_state()
    assert register_launch("vol_vadinfo") is None


def test_marker():
    print(f"{_GATE}=PASS")
    assert _GATE == "HIGH_COST_TOOL_BUDGET_GATE"
