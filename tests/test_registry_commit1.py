"""Commit 1 registry expansion tests.

Asserts sleuthkit 3→14 + 6 SIFT-native = 17 new tools registered.
"""
from __future__ import annotations

from sift_sentinel.coordinator import _TOOL_REGISTRY


def test_registry_has_107_or_more_tools():
    # After Commit 2 this grows to 120+; assertion stays at 107 floor
    # so Commit 1 coverage is preserved without blocking future growth.
    assert len(_TOOL_REGISTRY) >= 107, (
        f"Expected >=107 tools, got {len(_TOOL_REGISTRY)}"
    )


def test_all_14_sleuthkit_commands_registered():
    expected = {
        "sleuthkit_fls", "sleuthkit_icat", "sleuthkit_mmls",
        "sleuthkit_blkstat", "sleuthkit_fsstat", "sleuthkit_ifind",
        "sleuthkit_ffind", "sleuthkit_mactime", "sleuthkit_sorter",
        "sleuthkit_sigfind", "sleuthkit_img_stat", "sleuthkit_img_cat",
        "sleuthkit_tsk_recover", "sleuthkit_tsk_loaddb",
    }
    missing = expected - set(_TOOL_REGISTRY.keys())
    assert not missing, f"Missing Sleuthkit tools: {missing}"


def test_all_6_sift_native_tools_registered():
    expected = {
        "run_yara", "run_bulk_extractor", "run_exiftool",
        "run_ssdeep", "run_foremost", "run_strings",
    }
    missing = expected - set(_TOOL_REGISTRY.keys())
    assert not missing, f"Missing SIFT-native tools: {missing}"


def test_all_new_tools_have_capability_declarations():
    from sift_sentinel.tools.capabilities import get_capability
    new_tools = {
        "sleuthkit_icat", "sleuthkit_blkstat", "sleuthkit_ifind",
        "sleuthkit_ffind", "sleuthkit_mactime", "sleuthkit_sorter",
        "sleuthkit_sigfind", "sleuthkit_img_stat", "sleuthkit_img_cat",
        "sleuthkit_tsk_recover", "sleuthkit_tsk_loaddb",
        "run_yara", "run_bulk_extractor", "run_exiftool",
        "run_ssdeep", "run_foremost", "run_strings",
    }
    missing = [t for t in new_tools if get_capability(t) is None]
    assert not missing, f"Missing capabilities: {missing}"
