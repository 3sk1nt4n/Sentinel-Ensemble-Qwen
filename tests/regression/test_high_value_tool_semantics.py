"""Slot 31I-alpha: high-value tools resolve to meaningful buckets.

Synthetic tool names exercising each high-value forensic family. No
real tool name is required to exist; assertions are on the classifier
behavior, not on a fixed catalog.
"""

from sift_sentinel.tool_semantics import get_tool_semantics

# (synthetic name, expected bucket that MUST appear)
_CASES = [
    ("vol_pstree", "memory_process"),
    ("vol_netscan", "memory_network"),
    ("vol_malfind", "memory_injection"),
    ("vol_ldrmodules", "memory_modules"),
    ("vol_handles", "memory_handles"),
    ("vol_svcscan", "memory_services"),
    ("vol_ssdt", "memory_kernel"),
    ("vol_reg_hivelist", "memory_registry"),
    ("get_amcache", "execution_artifacts"),
    ("extract_mft_timeline", "disk_timeline"),
    ("parse_event_logs", "evtx"),
    ("parse_scheduled_tasks_disk", "persistence"),
    ("parse_powershell_transcripts", "powershell_decode"),
    ("extract_network_iocs", "network_ioc"),
    ("run_yara", "malware_triage"),
    ("run_memprocfs", "memprocfs"),
    ("sleuthkit_tsk_recover", "file_carving"),
    ("sleuthkit_fls", "sleuthkit"),
    ("run_ssdeep", "hash_artifact"),
    ("vol_hashdump", "credential_artifact"),
]


def test_high_value_tools_not_uncategorized():
    for name, _expected in _CASES:
        sem = get_tool_semantics(name, (None, "memory"))
        assert sem["buckets"] != ("uncategorized",), name


def test_high_value_tools_resolve_expected_bucket():
    for name, expected in _CASES:
        sem = get_tool_semantics(name, (None, "memory"))
        assert expected in sem["buckets"], (
            f"{name}: expected {expected} in {sem['buckets']}"
        )


def test_cost_maps_from_runtime_class():
    fast = get_tool_semantics(
        "vol_pstree", (None, "memory"), {"runtime_class": "fast"})
    slow = get_tool_semantics(
        "vol_filescan", (None, "memory"), {"runtime_class": "slow"})
    assert fast["cost"] == "low"
    assert slow["cost"] == "high"
