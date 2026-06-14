"""Commit 15c: 79-tool Windows categorization verification."""
from collections import Counter

from sift_sentinel.coordinator import (
    _NON_WINDOWS_TOOLS,
    _TOOL_CATEGORY,
    _TOOL_REGISTRY,
)


def test_category_count_is_102():
    """Post-F8-B total must be exactly 108 (parse_wmi_subscription added)."""
    assert len(_TOOL_CATEGORY) == 108, (
        f"expected 108 categorized, got {len(_TOOL_CATEGORY)}"
    )


def test_all_7_categories_have_minimum_4_tools():
    """Every category must have at least 4 tools."""
    counts = Counter(_TOOL_CATEGORY.values())
    for cat in ("process_analysis", "malware_detection", "network_analysis",
                "persistence", "execution_history", "filesystem_analysis",
                "registry_analysis"):
        assert counts[cat] >= 4, f"{cat} has only {counts[cat]} tools"


def test_distribution_targets():
    """Lock exact counts at 15c ship. Any future recategorization requires
    explicit test update. Intentional: prevents silent drift in Inv1 category
    balance between commits.
    """
    counts = Counter(_TOOL_CATEGORY.values())
    assert counts["process_analysis"] == 22
    assert counts["malware_detection"] == 22
    assert counts["network_analysis"] == 4
    assert counts["persistence"] == 13
    assert counts["filesystem_analysis"] == 21
    assert counts["registry_analysis"] == 9
    assert counts["execution_history"] == 17


def test_all_categorized_tools_exist_in_registry():
    """No phantom entries."""
    orphans = set(_TOOL_CATEGORY.keys()) - set(_TOOL_REGISTRY.keys())
    assert not orphans, f"orphans: {orphans}"


def test_no_non_windows_tools_categorized():
    """Linux/Mac tools must NOT be in _TOOL_CATEGORY (filtered by 15b)."""
    leaked = set(_TOOL_CATEGORY.keys()) & _NON_WINDOWS_TOOLS
    assert not leaked, f"Linux/Mac tools categorized: {leaked}"


def test_no_duplicate_entries():
    """Each tool appears exactly once."""
    keys = list(_TOOL_CATEGORY.keys())
    assert len(keys) == len(set(keys))


def test_dfir_corrections_applied():
    """Thread-injection + anti-forensics in malware, PST extraction in filesystem."""
    assert _TOOL_CATEGORY["vol_processghosting"] == "malware_detection"
    assert _TOOL_CATEGORY["vol_suspendedthreads"] == "malware_detection"
    assert _TOOL_CATEGORY["vol_suspiciousthreads"] == "malware_detection"
    # Anti-forensics volume/cert scanners belong in malware, not persistence
    assert _TOOL_CATEGORY["vol_truecrypt"] == "malware_detection"
    assert _TOOL_CATEGORY["vol_certificates"] == "malware_detection"
    # pffexport is PST extraction = filesystem, not execution
    assert _TOOL_CATEGORY["run_pffexport"] == "filesystem_analysis"


def test_high_value_tools_correctly_placed():
    """Spot-check key forensic tools."""
    assert _TOOL_CATEGORY["run_mftecmd"] == "filesystem_analysis"
    assert _TOOL_CATEGORY["run_recmd"] == "registry_analysis"
    assert _TOOL_CATEGORY["run_evtxecmd"] == "execution_history"
    assert _TOOL_CATEGORY["run_amcacheparser"] == "execution_history"
    assert _TOOL_CATEGORY["run_yara"] == "malware_detection"
    assert _TOOL_CATEGORY["run_bulk_extractor"] == "network_analysis"
    assert _TOOL_CATEGORY["sleuthkit_fls"] == "filesystem_analysis"
    assert _TOOL_CATEGORY["vol_amcache"] == "execution_history"
    assert _TOOL_CATEGORY["vol_userassist"] == "execution_history"


def test_cross_cutting_utilities_not_categorized():
    """General forensic helpers stay uncategorized."""
    for tool in ("run_foremost", "run_strings", "run_ssdeep", "run_exiftool"):
        assert tool not in _TOOL_CATEGORY, f"{tool} should NOT be categorized"


def test_commit11_mandate_has_real_pool():
    """5-of-7 mandate from Commit 11 now has diverse pool."""
    assert len(_TOOL_CATEGORY) > 100
