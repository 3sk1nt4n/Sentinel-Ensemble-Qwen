"""Slot 31I-beta: registry-driven high-value tool semantics.

Registry-driven: each high-value tool is checked ONLY if it is actually
registered. Absent optional tools are not failures (no invented names).
Complements the synthetic 31I-alpha test_high_value_tool_semantics.py.
"""

import pytest

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tool_semantics import get_tool_semantics

# tool name -> a bucket that MUST be present if the tool is registered.
_EXPECTED = {
    "parse_event_logs": "evtx",
    "run_evtxecmd": "evtx",
    "run_evtx_dump": "evtx",
    "run_appcompatcacheparser": "execution_artifacts",
    "parse_wmi_subscription": "persistence",
    "extract_network_iocs": "network_ioc",
    "decode_base64_strings": "base64_decode",
    "run_yara": "malware_triage",
    "get_amcache": "execution_artifacts",
    "extract_mft_timeline": "disk_timeline",
}


@pytest.mark.parametrize("tool,bucket", sorted(_EXPECTED.items()))
def test_registered_high_value_tool_has_expected_bucket(tool, bucket):
    if tool not in c._TOOL_REGISTRY:
        pytest.skip(f"optional tool {tool} not registered in this build")
    sem = get_tool_semantics(
        tool, c._TOOL_REGISTRY[tool], get_capability(tool),
    )
    assert bucket in sem["buckets"], (
        f"{tool}: expected {bucket} in {sem['buckets']}"
    )
    assert sem["buckets"] != ("uncategorized",)


def test_every_high_value_present_tool_is_non_uncategorized():
    present = [t for t in _EXPECTED if t in c._TOOL_REGISTRY]
    assert present, "expected at least one high-value tool registered"
    for tool in present:
        sem = get_tool_semantics(
            tool, c._TOOL_REGISTRY[tool], get_capability(tool),
        )
        assert sem["buckets"] != ("uncategorized",), tool
        assert sem["detects"]
