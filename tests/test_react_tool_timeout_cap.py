"""ReAct heavy-tool wall-clock cap (operator opt-in). SIFT_REACT_TOOL_TIMEOUT,
when set, bounds a SLOW Vol3 tool to the cap so a 70s full-image scan in the
ReAct loop can't blow the budget; a fast tool is untouched; default-unset is a
no-op. Universal: keyed on the timeout value, no tool/case list.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.tools import common as c  # noqa: E402


def test_default_unset_is_no_op(monkeypatch):
    monkeypatch.delenv("SIFT_REACT_TOOL_TIMEOUT", raising=False)
    slow = next(iter(c.VOL_TIMEOUTS))
    assert c._effective_vol_timeout(slow) == c.VOL_TIMEOUTS[slow]
    assert c._effective_vol_timeout("vol_unknown_tool") == c.VOL_TIMEOUT_DEFAULT


def test_cap_bounds_slow_tool(monkeypatch):
    monkeypatch.setenv("SIFT_REACT_TOOL_TIMEOUT", "35")
    # default tool timeout is 90 -> capped to 35
    assert c._effective_vol_timeout("vol_unknown_tool") == 35


def test_cap_does_not_extend_fast_tool(monkeypatch):
    # a tool whose normal timeout is already below the cap is untouched (min()).
    monkeypatch.setenv("SIFT_REACT_TOOL_TIMEOUT", "300")
    assert c._effective_vol_timeout("vol_unknown_tool") == c.VOL_TIMEOUT_DEFAULT


def test_garbage_cap_ignored(monkeypatch):
    monkeypatch.setenv("SIFT_REACT_TOOL_TIMEOUT", "not-a-number")
    assert c._effective_vol_timeout("vol_unknown_tool") == c.VOL_TIMEOUT_DEFAULT
    monkeypatch.setenv("SIFT_REACT_TOOL_TIMEOUT", "0")
    assert c._effective_vol_timeout("vol_unknown_tool") == c.VOL_TIMEOUT_DEFAULT
