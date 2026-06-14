"""C32 V3 side-test: real-data dispatch verification.

Property-based per slot 28. Invokes call_mcp_tool against real MCP
subprocess with nonexistent tool names (guaranteed to fail fast at
registry lookup before any LLM dispatch). Asserts parent-side tracker
increments correctly. No hardcoded counts.

Skipif pattern protects against environments where MCP server.py is
unavailable.

Note: tracker init is handled by the autouse fixture in
tests/test_tools/conftest.py (Rule 5 parity). This file lives in
tests/ root, so it calls new_tool_health() explicitly in each test.
"""
from __future__ import annotations

import os

import pytest


def _mcp_server_available() -> bool:
    """MCP server.py must be importable for real-dispatch tests."""
    try:
        import sift_sentinel
        server_path = os.path.join(
            os.path.dirname(sift_sentinel.__file__),
            "..", "server.py",
        )
        return os.path.exists(server_path)
    except Exception:
        return False


@pytest.mark.skipif(
    not _mcp_server_available(),
    reason="MCP server.py not available in this environment",
)
def test_real_mcp_dispatch_populates_parent_tracker():
    """Property: after a real MCP tool dispatch, parent tracker reports
    at least 1 attempted. Nonexistent tool name used to avoid any LLM
    dispatch - registry lookup fails fast and returns error envelope."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import new_tool_health, get_tool_health
    new_tool_health()
    try:
        call_mcp_tool("tool_nonexistent_c32_probe", {})
    except Exception:
        pass
    h = get_tool_health().summary()
    assert h["attempted"] >= 1, (
        f"parent tracker did not record attempt: {h}"
    )


@pytest.mark.skipif(
    not _mcp_server_available(),
    reason="MCP server.py not available",
)
def test_real_mcp_dispatch_sum_invariant():
    """Property: succeeded + failed == attempted after any number of
    dispatches. Tracker accounting invariant, no hardcoded counts."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import new_tool_health, get_tool_health
    new_tool_health()
    for tool_name in [
        "tool_nonexistent_a",
        "tool_nonexistent_b",
        "tool_nonexistent_c",
    ]:
        try:
            call_mcp_tool(tool_name, {})
        except Exception:
            pass
    h = get_tool_health().summary()
    assert h["attempted"] == h["succeeded"] + h["failed"], (
        f"tracker accounting broken: {h}"
    )


@pytest.mark.skipif(
    not _mcp_server_available(),
    reason="MCP server.py not available",
)
def test_real_mcp_failure_envelope_marks_failed():
    """Property: nonexistent tool returns failure envelope AND tracker
    reports at least 1 failed. Real subprocess, real envelope, real
    tracker update."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import new_tool_health, get_tool_health
    new_tool_health()
    result = call_mcp_tool("tool_does_not_exist_in_registry_c32_probe", {})
    assert result.get("error") or result.get("failure_mode"), (
        f"expected failure envelope for nonexistent tool, got: {result}"
    )
    h = get_tool_health().summary()
    assert h["failed"] >= 1, f"tracker did not record failure: {h}"
