"""Commit 32: tool_health tracking inside call_mcp_tool.

L32-1 structural: call_mcp_tool body contains tracker wiring
L32-2 behavioral: successful MCP response increments attempted + succeeded
L32-3 behavioral: failure_mode response increments attempted + failed
L32-4 behavioral: error envelope increments attempted + failed
L32-5 behavioral: exception path increments attempted + failed (exception mode)

Summary shape contract (verified Q129):
  {"attempted": int, "succeeded": int, "failed": int,
   "failures": {tool_name: {"error": str, "failure_mode": str}}}

Note L32-2 asserts exact equality on the result dict. Future
response-processing changes to call_mcp_tool would require updating
this test. Intentional tight coupling to current envelope contract.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _fresh_tracker():
    """Each test gets a fresh tool_health tracker."""
    from sift_sentinel.coordinator import new_tool_health
    new_tool_health()


def test_L32_1_call_mcp_tool_body_wires_tracker():
    """Structural: call_mcp_tool source contains mark_* tracker calls."""
    import inspect
    from sift_sentinel import mcp_client
    src = inspect.getsource(mcp_client.call_mcp_tool)
    assert "from sift_sentinel.coordinator import get_tool_health" in src
    assert "mark_attempt" in src, "tracker wiring missing"
    assert "mark_success" in src, "success mark missing"
    assert "mark_failure" in src, "failure mark missing"


def test_L32_2_successful_response_marks_attempt_and_success():
    """Behavioral: clean MCP response increments attempted + succeeded.
    Exact-equality assertion on result intentional; see module docstring."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import get_tool_health
    ok_response = {"output": [{"x": 1}], "record_count": 1}
    async def _ok(*a, **kw):
        return ok_response
    with patch("sift_sentinel.mcp_client._call_tool", side_effect=_ok):
        result = call_mcp_tool("tool_x", {"arg": "val"})
    assert result == ok_response
    h = get_tool_health().summary()
    assert h["attempted"] == 1
    assert h["succeeded"] == 1
    assert h["failed"] == 0


def test_L32_3_failure_mode_response_marks_failure():
    """Behavioral: response with failure_mode key increments failed."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import get_tool_health
    fail_response = {
        "output": [],
        "record_count": 0,
        "failure_mode": "invalid_json_response",
    }
    async def _fail(*a, **kw):
        return fail_response
    with patch("sift_sentinel.mcp_client._call_tool", side_effect=_fail):
        call_mcp_tool("tool_y", {})
    h = get_tool_health().summary()
    assert h["attempted"] == 1
    assert h["succeeded"] == 0
    assert h["failed"] == 1
    assert "tool_y" in h["failures"]
    assert h["failures"]["tool_y"]["failure_mode"] == "invalid_json_response"


def test_L32_4_error_envelope_marks_failure():
    """Behavioral: response with error key (no failure_mode) marks failed."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import get_tool_health
    err_response = {
        "output": [],
        "record_count": 0,
        "error": "stdio EOF",
    }
    async def _err(*a, **kw):
        return err_response
    with patch("sift_sentinel.mcp_client._call_tool", side_effect=_err):
        call_mcp_tool("tool_z", {})
    h = get_tool_health().summary()
    assert h["attempted"] == 1
    assert h["failed"] == 1
    assert "tool_z" in h["failures"]


def test_L32_5_exception_path_marks_failure():
    """Behavioral: asyncio.run raising Exception marks failed with exception mode."""
    from sift_sentinel.mcp_client import call_mcp_tool
    from sift_sentinel.coordinator import get_tool_health
    async def raise_runtime(*a, **kw):
        raise RuntimeError("connection lost")
    with patch("sift_sentinel.mcp_client._call_tool", side_effect=raise_runtime):
        result = call_mcp_tool("tool_w", {})
    assert "error" in result
    h = get_tool_health().summary()
    assert h["attempted"] == 1
    assert h["failed"] == 1
    assert h["failures"]["tool_w"]["failure_mode"] == "exception"
