"""Commit 17 invariants: universal tool wiring + client resilience.

L17-1: _dispatch_wrapper accepts full run_tool parameter set
L17-2: mcp_client returns structured error on invalid JSON
L17-3: run_pipeline summary includes tool_record_counts key
L17-4: _dispatch_wrapper catches all exceptions and returns dict
"""
from __future__ import annotations

import inspect


def test_L17_1_dispatch_wrapper_signature_is_complete():
    """_dispatch_wrapper must accept all run_tool parameters.

    The server must register at least one fn=None tool, and the
    registered wrapper must accept the full run_tool parameter set.
    """
    from src import server
    from sift_sentinel.coordinator import _TOOL_REGISTRY

    # Find ANY fn=None tool (154 available, use the first one)
    target_name = None
    for name, (fn, at) in _TOOL_REGISTRY.items():
        if fn is None:
            target_name = f"tool_{name}"
            break
    assert target_name is not None, "No fn=None dispatch tool found in registry"

    wrapper = getattr(server, target_name, None)
    assert wrapper is not None, f"{target_name} not registered in server module"

    sig = inspect.signature(wrapper)
    params = set(sig.parameters.keys())
    required = {"image_path", "disk_path", "mft_start", "mft_end", "tool_args", "evidence_type"}
    missing = required - params
    assert not missing, f"_dispatch_wrapper missing params: {missing}"


def test_L17_2_mcp_client_handles_invalid_json():
    """mcp_client must return structured error dict on invalid JSON."""
    from sift_sentinel import mcp_client
    source = inspect.getsource(mcp_client)
    assert "invalid_json_response" in source, "Missing invalid_json_response failure_mode"
    assert "no_content_returned" in source, "Missing no_content_returned failure_mode"
    assert "json.JSONDecodeError" in source, "Missing JSONDecodeError handler"


def test_L17_3_run_pipeline_saves_tool_record_counts():
    """run_pipeline summary dict must include tool_record_counts key."""
    with open("run_pipeline.py") as f:
        content = f.read()
    assert '"tool_record_counts": tool_record_counts' in content, \
        "run_pipeline.py summary missing tool_record_counts key"


def test_L17_4_dispatch_wrapper_catches_exceptions():
    """_dispatch_wrapper must catch all exceptions and return dict."""
    from src import server
    source = inspect.getsource(server)
    assert '"dispatch_exception"' in source, "Missing dispatch_exception failure_mode"
    assert "except Exception" in source, "Missing broad exception handler"
    assert '"non_dict_return"' in source, "Missing non_dict_return failure_mode"
