"""Commit 5: applicable_when dispatcher gating tests."""
from __future__ import annotations

import pytest

from sift_sentinel.coordinator import run_tool, new_tool_health
from sift_sentinel.tools.capabilities import get_capability


def test_mac_branch_in_auto_capability():
    """auto_capability must support os_family='mac' without raising."""
    from sift_sentinel.tools.capabilities import auto_capability
    cap = auto_capability("test_tool", os_family="mac")
    # INTENTIONAL CHANGE (disk-only live-run fix): auto_capability covers
    # dynamically-discovered Vol3 plugins, which run on a memory image by
    # construction -- memory_evidence added so disk-only runs omit them.
    assert cap["applicable_when"] == ["mac_evidence", "memory_evidence"]
    assert "windows_evidence" in cap["not_applicable_when"]


def test_mac_plugins_now_have_applicable_when():
    """All 13 previously-empty Mac plugins now have applicable_when populated."""
    expected_mac = [
        "vol_checksysctl", "vol_checktraptable", "vol_dmesg",
        "vol_ifconfig", "vol_kauthlisteners", "vol_kauthscopes",
        "vol_kevents", "vol_listfiles", "vol_mount",
        "vol_procmaps", "vol_socketfilters",
        "vol_trustedbsd", "vol_vfsevents",
    ]
    missing = []
    for name in expected_mac:
        cap = get_capability(name)
        if not cap:
            missing.append(f"{name} (no capability)")
            continue
        aw = cap.get("applicable_when", [])
        if "mac_evidence" not in aw:
            missing.append(f"{name} aw={aw}")
    assert not missing, f"Mac plugins missing mac_evidence: {missing}"


def test_gate_returns_not_applicable_on_mismatch():
    """Invoking a Mac plugin against Windows evidence returns not_applicable."""
    new_tool_health()
    result = run_tool(
        "vol_dmesg",
        image_path="/fake/windows.img",
        disk_path="/fake/windows.img",
        evidence_type="windows_evidence",
    )
    assert result.get("failure_mode") == "not_applicable", (
        f"Expected not_applicable, got {result.get('failure_mode')}: "
        f"{result.get('error')}"
    )


def test_gate_skipped_when_evidence_type_unset():
    """Backward compat: if evidence_type not passed, gate skips."""
    new_tool_health()
    # This should NOT return not_applicable -- should proceed normally
    result = run_tool(
        "sleuthkit_fls",
        image_path="/nonexistent/path.E01",
        disk_path="/nonexistent/path.E01",
        # No evidence_type passed
    )
    # We expect some failure (file doesn't exist) but NOT not_applicable
    assert result.get("failure_mode") != "not_applicable"


def test_gate_allows_matching_evidence_type():
    """Windows plugin with windows_evidence passes gate (reaches inner dispatch)."""
    new_tool_health()
    # vol_pstree is windows_evidence; passing windows_evidence should not gate
    result = run_tool(
        "vol_pstree",
        image_path="/nonexistent/memory.img",
        disk_path="/nonexistent/memory.img",
        evidence_type="windows_evidence",
    )
    # Gate passes; inner will fail due to missing file, but NOT not_applicable
    assert result.get("failure_mode") != "not_applicable"


def test_applicable_when_field_populated_for_all_172():
    """After Commit 5, every registered tool has applicable_when populated."""
    from sift_sentinel.coordinator import _TOOL_REGISTRY
    empty = []
    for k in _TOOL_REGISTRY:
        cap = get_capability(k)
        if cap and not cap.get("applicable_when"):
            empty.append(k)
    assert not empty, f"Empty applicable_when: {empty}"
