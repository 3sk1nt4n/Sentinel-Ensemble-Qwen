from __future__ import annotations

from sift_sentinel.analysis.react_os_tool_compat import (
    resolve_vol_plugin,
    validate_log_text,
)

def test_windows_rewrites_linux_pslist_to_windows_pslist():
    d = resolve_vol_plugin(
        tool_name="vol_pslist",
        plugin_name="linux.pslist.PsList",
        evidence_os="windows",
    )
    assert d["action"] == "replace"
    assert d["plugin"] == "windows.pslist.PsList"

def test_windows_allows_windows_plugin():
    d = resolve_vol_plugin(
        tool_name="vol_pstree",
        plugin_name="windows.pstree.PsTree",
        evidence_os="windows",
    )
    assert d["action"] == "allow"

def test_gate_detects_prior_wrong_os_log_pattern():
    result = validate_log_text(
        "Evidence: memory=/x/mem.img, disk=/x/disk.E01, disk_mount=/tmp/mount/ntfs\n"
        "NtSystemRoot C:\\Windows\n"
        "LIVE VOL: Running vol_pslist (linux.pslist.PsList) on /x/mem.img\n"
    )
    assert result["status"] == "fail"
    assert result["wrong_os_hits"] == 1

def test_unknown_os_does_not_fake_rewrite():
    d = resolve_vol_plugin(
        tool_name="vol_pslist",
        plugin_name="linux.pslist.PsList",
        evidence_os="unknown",
    )
    assert d["action"] == "allow"
