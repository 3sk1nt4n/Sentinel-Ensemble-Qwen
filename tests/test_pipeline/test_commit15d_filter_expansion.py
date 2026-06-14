"""Commit 15d: 16 additional Linux/Mac plugins added to _NON_WINDOWS_TOOLS."""
from sift_sentinel.coordinator import _NON_WINDOWS_TOOLS, _TOOL_REGISTRY, _TOOL_CATEGORY


def test_non_windows_tools_count_is_47():
    """Post-Commit-15d filter has exactly 47 entries."""
    assert len(_NON_WINDOWS_TOOLS) == 47, (
        f"expected 47, got {len(_NON_WINDOWS_TOOLS)}"
    )


def test_all_filter_entries_exist_in_registry():
    """No phantom entries (every filtered tool must be real registered tool)."""
    orphans = _NON_WINDOWS_TOOLS - set(_TOOL_REGISTRY.keys())
    assert not orphans, f"orphaned filter entries: {orphans}"


def test_new_linux_rootkit_check_plugins_filtered():
    """Commit 15d additions for Linux rootkit checks."""
    for tool in ("vol_checkafinfo", "vol_checkcreds", "vol_checkidt",
                 "vol_checkmodules", "vol_checksyscall"):
        assert tool in _NON_WINDOWS_TOOLS, f"{tool} missing from filter"


def test_new_linux_tracing_plugins_filtered():
    """Commit 15d additions for Linux tracing subsystem."""
    for tool in ("vol_ftrace", "vol_perfevents", "vol_tracepoints",
                 "vol_fbdev"):
        assert tool in _NON_WINDOWS_TOOLS, f"{tool} missing from filter"


def test_new_mac_plugins_filtered():
    """Commit 15d additions for Mac kernel APIs."""
    for tool in ("vol_kauthlisteners", "vol_kauthscopes", "vol_checksysctl",
                 "vol_checktraptable", "vol_procmaps"):
        assert tool in _NON_WINDOWS_TOOLS, f"{tool} missing from filter"


def test_filter_and_categorization_disjoint():
    """No tool is both filtered AND categorized (architectural invariant)."""
    overlap = _NON_WINDOWS_TOOLS & set(_TOOL_CATEGORY.keys())
    assert not overlap, f"tools both filtered and categorized: {overlap}"


def test_original_15b_entries_preserved():
    """All 31 original Commit 15b entries still in filter."""
    original_15b = {
        "vol_bash", "vol_boottime", "vol_capabilities", "vol_dmesg",
        "vol_ebpf", "vol_elfs", "vol_ifconfig", "vol_iomem", "vol_ip",
        "vol_kallsyms", "vol_kevents", "vol_kmsg", "vol_kthreads",
        "vol_lsmod", "vol_lsof", "vol_modxview", "vol_mount",
        "vol_mountinfo", "vol_netfilter", "vol_pagecache",
        "vol_pidhashtable", "vol_proc", "vol_psaux", "vol_pscallstack",
        "vol_ptrace", "vol_sockstat", "vol_trustedbsd", "vol_vfsevents",
        "vol_vmaregexscan", "vol_vmayarascan", "vol_vmcoreinfo",
    }
    assert original_15b.issubset(_NON_WINDOWS_TOOLS), (
        f"missing from filter: {original_15b - _NON_WINDOWS_TOOLS}"
    )


def test_windows_tools_not_in_filter():
    """Known Windows plugins must NOT be in _NON_WINDOWS_TOOLS."""
    for tool in ("vol_pslist", "vol_psscan", "vol_netscan", "vol_svcscan",
                 "vol_malfind", "vol_hollowprocesses", "vol_filescan",
                 "vol_mftscan", "vol_orphankernelthreads"):
        assert tool not in _NON_WINDOWS_TOOLS, (
            f"{tool} is Windows, should NOT be filtered"
        )


def test_filter_reduces_inv1_selectable_pool():
    """Filter reduces selectable pool to expected Windows count."""
    from sift_sentinel.coordinator import BOOTSTRAP_TOOLS
    selectable = (set(_TOOL_REGISTRY)
                  - set(BOOTSTRAP_TOOLS)
                  - _NON_WINDOWS_TOOLS)
    # 178 - 2 - 47 = 129 (F8-B: parse_wmi_subscription added)
    assert len(selectable) == 129, (
        f"expected 129 Windows selectable, got {len(selectable)}"
    )
