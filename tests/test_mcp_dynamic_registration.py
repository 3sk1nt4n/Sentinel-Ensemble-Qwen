"""Regression: MCP dynamic registration exposes all 178 registry tools
plus 9 hardcoded orphan tools for a total of 187 MCP-surface tools.
"""
import inspect
import sys

import pytest

import sift_sentinel.coordinator  # populates _TOOL_REGISTRY (V-gate)


@pytest.fixture(scope="module")
def server_module():
    if "server" in sys.modules:
        del sys.modules["server"]
    import server
    return server


def test_registered_count_equals_172(server_module):
    from sift_sentinel.coordinator import _TOOL_REGISTRY
    assert server_module._REGISTERED_COUNT == len(_TOOL_REGISTRY)
    assert server_module._REGISTERED_COUNT == 178


def test_no_failed_registrations(server_module):
    assert server_module._FAILED_REGISTRATIONS == [], (
        f"Registration failures: {server_module._FAILED_REGISTRATIONS}"
    )


def test_all_172_registry_tools_exposed_via_mcp(server_module):
    from sift_sentinel.coordinator import _TOOL_REGISTRY
    tm = server_module.mcp._tool_manager
    registered_names = set(tm._tools.keys())
    for reg_name in _TOOL_REGISTRY:
        mcp_name = f"tool_{reg_name}"
        assert mcp_name in registered_names, f"{mcp_name} not in MCP _tool_manager"
        assert hasattr(server_module, mcp_name), f"hasattr({mcp_name}) failed"


def test_exactly_181_tools_exposed(server_module):
    tm = server_module.mcp._tool_manager
    assert len(tm._tools) == 187, f"expected 187, got {len(tm._tools)}"


def test_hasattr_tool_parse_prefetch_preserved(server_module):
    assert hasattr(server_module, "tool_parse_prefetch")
    assert callable(getattr(server_module, "tool_parse_prefetch"))


def test_multi_arg_signature_preserved_for_vol_cmdline(server_module):
    fn = getattr(server_module, "tool_vol_cmdline")
    sig = inspect.signature(fn)
    params = sig.parameters
    assert "image_path" in params
    assert "pid" in params
    assert params["pid"].default is None


def test_curated_docstring_applied_to_vol_pstree(server_module):
    fn = getattr(server_module, "tool_vol_pstree")
    doc = fn.__doc__ or ""
    assert "Hunt Evil" in doc or "parent-child" in doc, (
        f"curated docstring not applied, got first 200 chars: {doc[:200]}"
    )


def test_vol_generic_dispatcher_closure(server_module, monkeypatch):
    captured = {}

    def fake_run_tool(tool_name, image_path, disk_path="", **kw):
        captured["tool_name"] = tool_name
        captured["image_path"] = image_path
        return {"tool_name": tool_name, "output": [], "record_count": 0}

    monkeypatch.setattr(sift_sentinel.coordinator, "run_tool", fake_run_tool)

    fn = getattr(server_module, "tool_vol_ldrmodules")
    result = fn("/fake/mem.img")

    assert captured["tool_name"] == "vol_ldrmodules"
    assert captured["image_path"] == "/fake/mem.img"
    assert result["tool_name"] == "vol_ldrmodules"


def test_all_9_orphans_still_hardcoded(server_module):
    orphans = [
        "tool_parse_shellbags",
        "tool_run_log2timeline",
        "tool_run_regripper",
        "tool_get_investigation_categories",
        "tool_get_tools_for_category",
        "tool_recommend_tools",
        "tool_run_volatility",
        "tool_list_volatility_plugins",
        "tool_run_sleuthkit",
    ]
    for name in orphans:
        assert hasattr(server_module, name), f"orphan {name} missing"
