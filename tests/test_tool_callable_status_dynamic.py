"""Callability probe must understand the dynamic-resolution architecture.

Live defect: a zero-record EZ tool (run_recmd) was explained with the reason
"run_recmd is registered but not callable" - false. 158 of 186 registry
tools store (None, category) because they are resolved at RUNTIME (the
generic Vol3 runner, the EZ-tools dispatch map, the Sleuth Kit runner), not
as an inline function. A None function slot is the NORM, not breakage.

_tool_callable_status must therefore treat a registered tool as callable even
when its registry function is None - registration implies runtime dispatch in
this architecture. Only a genuinely-absent tool is 'not registered'.
Universal: keyed on registry presence, not a tool-name list.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.runtime.high_value_tool_args import (  # noqa: E402
    _tool_callable_status,
    _accepted_args_for_tool,
)


def test_none_fn_ez_tool_is_callable_not_broken():
    ok, reason = _tool_callable_status("run_recmd")
    assert ok is True, reason
    assert "not callable" not in reason


def test_none_fn_vol_tool_is_callable():
    ok, reason = _tool_callable_status("vol_psxview")
    assert ok is True, reason


def test_none_fn_sleuthkit_tool_is_callable():
    ok, reason = _tool_callable_status("sleuthkit_tsk_recover")
    assert ok is True, reason


def test_genuinely_absent_tool_is_not_registered():
    ok, reason = _tool_callable_status("totally_fake_tool_xyz_999")
    assert ok is False
    assert "not registered" in reason


def test_accepted_args_safe_for_none_fn_tool():
    # the arg-resolution path must not crash on a None function -> empty set
    # (passthrough), the same as before, so dispatch kwargs are honored.
    assert _accepted_args_for_tool("run_recmd") == set()
