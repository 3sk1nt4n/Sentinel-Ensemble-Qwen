"""Slot 31I-alpha backward compat: a synthetic Inv1 response with
exactly 20 registered tools still validates and survives the
coerce/guardrail/safety-net pipeline at 20 (no padding, no truncation).
"""

import sift_sentinel.coordinator as c


def _twenty_registered():
    mem = [t for t in c._TOOL_REGISTRY
           if t.startswith("vol_") and c._is_registered(t)
           and t not in c.BOOTSTRAP_TOOLS][:14]
    disk = [t for t in sorted(c.DISK_TOOLS)
            if c._is_registered(t)][:6]
    tools = mem + disk
    assert len(tools) == 20
    return tools


def test_legacy_20_tool_response_is_valid():
    resp = {"selected_tools": _twenty_registered(),
            "reasoning": "legacy synthetic"}
    assert c._valid_inv1_response(resp) is True


def test_legacy_20_passes_pipeline_unchanged():
    tools = _twenty_registered()
    coerced = c._coerce_selected_tools(tools, bootstrap_ran=False)
    filtered = c._guardrail_filter_tools(coerced, bootstrap_ran=False)
    final = c.safety_net_tools(filtered)
    assert len(final) == 20
    assert set(final) == set(tools)


def test_legacy_20_has_memory_and_disk():
    final = c.safety_net_tools(_twenty_registered())
    assert any(t.startswith("vol_") for t in final)
    assert any(t in c.DISK_TOOLS for t in final)
