"""Commit 29: Regression guards for MCP invalid-JSON defensive retry.

Ensures:
  - _call_tool signature accepts _is_retry flag (structural)
  - Invalid JSON on first call triggers one retry with _is_retry=True
  - Invalid JSON on retry returns envelope with retry_attempted=True (no infinite loop)
"""
from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch


def test_L29_1_call_tool_signature_has_is_retry_param():
    """Structural: async def _call_tool must accept _is_retry kwarg
    with default False."""
    from sift_sentinel.mcp_client import _call_tool
    sig = inspect.signature(_call_tool)
    params = sig.parameters
    assert '_is_retry' in params, (
        "_call_tool must accept _is_retry parameter for C29 retry semantics"
    )
    default = params['_is_retry'].default
    assert default is False, (
        f"_is_retry must default to False, got {default!r}"
    )


def test_L29_2_invalid_json_triggers_single_retry():
    """Behavioral: first invalid-JSON response triggers exactly one retry.
    Second invalid-JSON returns failure envelope with retry_attempted=True.
    Must not recurse infinitely."""
    import asyncio
    from sift_sentinel import mcp_client

    bad_block = MagicMock()
    bad_block.text = "not valid json {{{"
    bad_result = MagicMock()
    bad_result.content = [bad_block]

    call_count = {"n": 0}

    class MockSession:
        async def initialize(self):
            pass

        async def call_tool(self, tool_name, arguments):
            call_count["n"] += 1
            return bad_result

    class MockCtx:
        def __init__(self, session):
            self.session = session

        async def __aenter__(self):
            return self.session

        async def __aexit__(self, *a):
            pass

    class MockStdioCtx:
        async def __aenter__(self):
            return (MagicMock(), MagicMock())

        async def __aexit__(self, *a):
            pass

    async def run_test():
        with patch('mcp.client.stdio.stdio_client',
                   return_value=MockStdioCtx()), \
             patch('mcp.ClientSession',
                   return_value=MockCtx(MockSession())), \
             patch('sift_sentinel.mcp_client.asyncio.sleep',
                   new=AsyncMock(return_value=None)):
            result = await mcp_client._call_tool(
                "tool_vol_mftscan", {"image_path": "/fake"},
            )
            return result

    result = asyncio.run(run_test())

    assert call_count["n"] == 2, (
        f"Expected 2 calls (initial + 1 retry), got {call_count['n']}"
    )
    assert result["failure_mode"] == "invalid_json_response"
    assert result.get("retry_attempted") is True, (
        "Second failure must be flagged with retry_attempted=True"
    )


def test_L29_3_retry_false_on_explicit_retry_call():
    """Behavioral: calling _call_tool with _is_retry=True skips retry logic.
    Prevents infinite recursion if retry itself produces invalid JSON."""
    import asyncio
    from sift_sentinel import mcp_client

    bad_block = MagicMock()
    bad_block.text = "invalid"
    bad_result = MagicMock()
    bad_result.content = [bad_block]

    call_count = {"n": 0}

    class MockSession:
        async def initialize(self):
            pass

        async def call_tool(self, tool_name, arguments):
            call_count["n"] += 1
            return bad_result

    class MockCtx:
        def __init__(self, session):
            self.session = session

        async def __aenter__(self):
            return self.session

        async def __aexit__(self, *a):
            pass

    class MockStdioCtx:
        async def __aenter__(self):
            return (MagicMock(), MagicMock())

        async def __aexit__(self, *a):
            pass

    async def run_test():
        with patch('mcp.client.stdio.stdio_client',
                   return_value=MockStdioCtx()), \
             patch('mcp.ClientSession',
                   return_value=MockCtx(MockSession())), \
             patch('sift_sentinel.mcp_client.asyncio.sleep',
                   new=AsyncMock(return_value=None)):
            result = await mcp_client._call_tool(
                "tool_vol_test", {"image_path": "/fake"},
                _is_retry=True,
            )
            return result

    result = asyncio.run(run_test())

    assert call_count["n"] == 1, (
        f"Expected 1 call with _is_retry=True (no retry), got {call_count['n']}"
    )
    assert result["failure_mode"] == "invalid_json_response"
    assert result.get("retry_attempted") is True
