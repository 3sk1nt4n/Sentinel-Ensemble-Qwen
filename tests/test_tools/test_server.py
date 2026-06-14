"""
Tests for MCP server: verify tools are registered and callable.
"""
from server import mcp
import server

class TestServerRegistration:
    def test_server_has_name(self):
        assert mcp.name == "sift-sentinel"

    def test_memory_tool_functions_exist(self):
        """All 5 memory tool wrapper functions must exist in server module."""
        expected = [
            "tool_vol_pstree",
            "tool_vol_netscan",
            "tool_vol_malfind",
            "tool_vol_cmdline",
            "tool_vol_dlllist",
        ]
        for name in expected:
            assert hasattr(server, name), f"Missing function: {name}"
            assert callable(getattr(server, name)), f"Not callable: {name}"

    def test_disk_tool_functions_exist(self):
        """Both disk tool wrapper functions must exist in server module."""
        expected = [
            "tool_get_amcache",
            "tool_extract_mft_timeline",
        ]
        for name in expected:
            assert hasattr(server, name), f"Missing function: {name}"
            assert callable(getattr(server, name)), f"Not callable: {name}"

    def test_at_least_7_tools(self):
        """At least 7 tool functions registered."""
        tool_funcs = [name for name in dir(server) if name.startswith("tool_")]
        assert len(tool_funcs) >= 7, f"Only {len(tool_funcs)} tools: {tool_funcs}"
