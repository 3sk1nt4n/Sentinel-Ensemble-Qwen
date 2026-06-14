"""Commit 3b-pre hygiene tests.

Proves:
  1. ALLOWED in run_sleuthkit derives from _SLEUTHKIT_COMMANDS (single source)
  2. required_args field exists on capability entries
  3. (Runtime, env-gated) Each sleuthkit tool returns ok OR clean
     missing_required_args -- no runtime_error leakage from usage strings
"""
from __future__ import annotations

import os
import pytest

from sift_sentinel.coordinator import _SLEUTHKIT_COMMANDS
from sift_sentinel.tools.capabilities import get_capability


REQUIRED_ARGS_EXPECTED = {
    "sleuthkit_icat": ("inode",),
    "sleuthkit_ifind": ("block_or_name",),
    "sleuthkit_ffind": ("inode",),
    "sleuthkit_blkstat": ("block_addr",),
    "sleuthkit_mactime": ("body_file",),
    "sleuthkit_sigfind": ("hex_sig",),
    "sleuthkit_tsk_recover": ("output_dir",),
}


def test_allowlist_single_source():
    """ALLOWED inside run_sleuthkit must derive from _SLEUTHKIT_COMMANDS."""
    from sift_sentinel.tools.generic import run_sleuthkit
    assert "_SLEUTHKIT_COMMANDS" in run_sleuthkit.__code__.co_names, (
        "run_sleuthkit must import _SLEUTHKIT_COMMANDS, not define ALLOWED locally"
    )


def test_required_args_declared_for_7_tools():
    for tool, expected in REQUIRED_ARGS_EXPECTED.items():
        cap = get_capability(tool)
        assert cap is not None, f"{tool} has no capability entry"
        got = tuple(cap.get("required_args", ()))
        assert got == expected, (
            f"{tool} required_args={got!r}, expected {expected!r}"
        )


def test_args_free_tools_have_empty_required_args():
    args_free = {"sleuthkit_fls", "sleuthkit_fsstat", "sleuthkit_mmls",
                 "sleuthkit_img_stat", "sleuthkit_sorter", "sleuthkit_tsk_loaddb",
                 "sleuthkit_img_cat"}
    for tool in args_free:
        cap = get_capability(tool)
        assert cap is not None, f"{tool} has no capability entry"
        got = tuple(cap.get("required_args", ()))
        assert got == (), f"{tool} should have required_args=(), got {got!r}"


@pytest.mark.skipif(
    not os.environ.get("SIFT_TEST_IMAGE")
    or not os.path.exists(os.environ.get("SIFT_TEST_IMAGE", "")),
    reason="SIFT_TEST_IMAGE not set or path missing",
)
def test_sleuthkit_dispatch_categorizes_cleanly():
    """Every sleuthkit tool returns ok OR missing_required_args -- no leakage."""
    from sift_sentinel.coordinator import run_tool, new_tool_health

    # Rule 5: tracker must be initialized before run_tool() invocation
    new_tool_health()

    img = os.environ["SIFT_TEST_IMAGE"]
    results = {}
    for cmd in _SLEUTHKIT_COMMANDS:
        if cmd == "img_cat":
            continue  # OOM risk without block range; tracked separately
        tool_name = f"sleuthkit_{cmd}"
        r = run_tool(tool_name, image_path=img, disk_path=img)
        fm = r.get("failure_mode")
        results[cmd] = fm
        assert fm in (None, "missing_required_args"), (
            f"{tool_name} leaked failure_mode={fm!r}; expected None or missing_required_args"
        )
    print(f"CATEGORIZATION: {results}")
