"""Commit 26: Regression guards for MCP server subprocess tool_health
initialization.

Prevents regression of the tool_health tracker missing from MCP subprocess
scope, which silently broke 14 tools with arg_type vol_generic or ez_tools
in Run 12 on base-file.
"""
from __future__ import annotations


def test_L26_1_server_module_inits_tool_health():
    """Property: src/server.py module load must call new_tool_health()
    so tool dispatch via run_tool() doesn't raise RuntimeError."""
    import sys
    # Force fresh import
    if 'server' in sys.modules:
        del sys.modules['server']
    sys.path.insert(0, 'src')
    import server  # noqa: F401

    from sift_sentinel.coordinator import get_tool_health
    # If server didn't init tracker, this raises RuntimeError
    health = get_tool_health()
    assert health is not None, "tool_health tracker not initialized by server.py"


def test_L26_2_server_source_calls_new_tool_health():
    """Structural: src/server.py source must contain new_tool_health()
    call near module top (not inside a function)."""
    from pathlib import Path
    server_src = Path('src/server.py').read_text()
    assert 'new_tool_health()' in server_src, (
        "src/server.py must call new_tool_health() at module load. "
        "See Commit 26 rationale."
    )


def test_L26_3_vol_generic_tool_dispatchable_via_run_tool():
    """Behavioral: run_tool() dispatch for a vol_generic arg_type tool
    must not raise RuntimeError about tool_health."""
    import sys
    sys.path.insert(0, 'src')
    from sift_sentinel.coordinator import new_tool_health, run_tool, _TOOL_REGISTRY

    # Pre-init tracker to simulate fresh subprocess boot
    new_tool_health()

    # Pick any vol_generic tool
    vg_tools = [n for n, (fn, at) in _TOOL_REGISTRY.items() if at == 'vol_generic']
    assert vg_tools, "no vol_generic tools in registry (test invalid)"
    target = vg_tools[0]

    # Call run_tool with dummy args; it may fail for other reasons
    # (no image, etc.) but MUST NOT raise RuntimeError about tool_health.
    try:
        result = run_tool(target, image_path='/nonexistent.img', disk_path='')
        # Any dict return is acceptable - the failure_mode may be runtime_error
        # for missing file, but that's not our concern. Just not RuntimeError.
        assert isinstance(result, dict), f"expected dict, got {type(result)}"
    except RuntimeError as e:
        if 'new_tool_health' in str(e):
            raise AssertionError(
                f"run_tool raised tool_health RuntimeError - Commit 26 regression: {e}"
            )
        # Other RuntimeErrors are fine (e.g. missing volatility3)
