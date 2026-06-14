"""Tests for the MCP client synchronous wrapper."""

from unittest.mock import patch

from sift_sentinel.mcp_client import call_mcp_tool


class TestCallMcpTool:
    """Tests for call_mcp_tool synchronous wrapper."""

    @patch("sift_sentinel.mcp_client._call_tool")
    def test_returns_result_on_success(self, mock_call):
        expected = {"tool_name": "test", "output": [{"a": 1}], "record_count": 1}

        async def _succeed(*a, **kw):
            return expected

        mock_call.side_effect = _succeed
        result = call_mcp_tool("test_tool", {"key": "val"})
        assert result == expected
        mock_call.assert_called_once_with("test_tool", {"key": "val"})

    @patch("sift_sentinel.mcp_client._call_tool")
    def test_returns_error_dict_on_exception(self, mock_call):
        async def _fail(*a, **kw):
            raise RuntimeError("connection refused")

        mock_call.side_effect = _fail
        result = call_mcp_tool("bad_tool", {})
        assert "error" in result
        assert "connection refused" in result["error"]
        assert result.get("output") == []
        assert result.get("record_count") == 0

    @patch("sift_sentinel.mcp_client._call_tool")
    def test_passes_tool_name_and_args_to_async(self, mock_call):
        async def _succeed(*a, **kw):
            return {"output": [], "record_count": 0}

        mock_call.side_effect = _succeed
        call_mcp_tool("tool_vol_pstree", {"image_path": "/evidence/mem.img"})
        mock_call.assert_called_once_with(
            "tool_vol_pstree", {"image_path": "/evidence/mem.img"}
        )
