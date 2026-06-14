"""Slot 31I-alpha: Inv1 selection band is 20-35 with deterministic
floor padding and priority truncation. Ceiling raised 33 -> 35 to give
headroom for the floored evil-class detectors (hollowprocesses,
rdp_artifacts, tsk_recover, userassist, privileges).
"""

import sift_sentinel.coordinator as c


def test_constants_are_20_and_35():
    assert c.MIN_SELECTED_TOOLS == 20
    assert c.MAX_SELECTED_TOOLS == 35


def test_thin_selection_padded_to_minimum_with_registered_tools():
    result = c.safety_net_tools(["vol_malfind", "get_amcache"])
    assert len(result) >= c.MIN_SELECTED_TOOLS
    assert all(c._is_registered(t) for t in result)
    assert len(result) == len(set(result))  # no duplicates


def test_over_selection_truncated_to_maximum():
    selected = list(c._TOOL_REGISTRY)[:50]
    result = c.safety_net_tools(selected)
    assert len(result) <= c.MAX_SELECTED_TOOLS


def test_truncation_prefers_mandatory_and_core_memory():
    # Lead with low-priority tools, then core memory + a safety-net
    # tool; after truncation the high-priority ones must survive.
    low = [t for t in c._TOOL_REGISTRY
           if c._selection_priority_rank(t) == 4][:40]
    selected = low + ["vol_malfind", "vol_psscan"]
    result = c.safety_net_tools(selected)
    assert len(result) <= c.MAX_SELECTED_TOOLS
    assert "vol_malfind" in result
    assert "vol_psscan" in result


def test_memory_and_disk_balance_enforced():
    only_disk = ["get_amcache", "parse_event_logs",
                 "extract_mft_timeline"]
    result = c.safety_net_tools(only_disk)
    assert any(t.startswith("vol_") for t in result)
    only_mem = ["vol_psscan", "vol_malfind", "vol_cmdline"]
    result2 = c.safety_net_tools(only_mem)
    assert any(t in c.DISK_TOOLS for t in result2)


def test_duplicates_removed():
    result = c.safety_net_tools(["vol_malfind", "vol_malfind",
                                 "get_amcache", "get_amcache"])
    assert len(result) == len(set(result))
