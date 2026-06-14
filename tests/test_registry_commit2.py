"""Commit 2 Zimmerman/EZ Tools registry expansion tests.

Asserts 13 new EZ Tools wrappers registered with correct schema.
"""
from __future__ import annotations

from sift_sentinel.coordinator import _TOOL_REGISTRY


EZ_TOOLS = {
    "run_mftecmd", "run_recmd", "run_evtxecmd",
    "run_amcacheparser", "run_appcompatcacheparser",
    "run_sbecmd", "run_jlecmd", "run_lecmd", "run_rbcmd",
    "run_wxtcmd", "run_evtx_dump", "run_vshadowmount", "run_pffexport",
}


def test_registry_has_120_or_more_tools():
    # Floor assertion — grows with Commit 3a (Linux/Mac Vol3) onward.
    assert len(_TOOL_REGISTRY) >= 120, (
        f"Expected >=120 tools after Commit 2, got {len(_TOOL_REGISTRY)}"
    )


def test_all_13_ez_tools_registered():
    missing = EZ_TOOLS - set(_TOOL_REGISTRY.keys())
    assert not missing, f"Missing EZ Tools: {missing}"


def test_all_ez_tools_have_ez_tools_arg_type():
    for tool in EZ_TOOLS:
        entry = _TOOL_REGISTRY[tool]
        assert entry[1] == "ez_tools", (
            f"{tool} has arg_type {entry[1]!r}, expected 'ez_tools'"
        )


def test_all_ez_tools_have_capability_declarations():
    from sift_sentinel.tools.capabilities import get_capability
    missing = [t for t in EZ_TOOLS if get_capability(t) is None]
    assert not missing, f"Missing capabilities: {missing}"


def test_all_ez_tool_wrappers_exist_in_generic():
    from sift_sentinel.tools import generic
    missing = [t for t in EZ_TOOLS if not hasattr(generic, t)]
    assert not missing, f"Missing wrapper functions in generic.py: {missing}"
