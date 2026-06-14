"""Commit 16: Tool availability invariant suite (Layers 1-5).

Layer 1: Registration integrity
Layer 2: Filter soundness
Layer 3: Categorization coverage
Layer 4: Prompt visibility
Layer 5: Dispatch routing
"""
import re
import tempfile
from pathlib import Path

from sift_sentinel.coordinator import (
    APPROVED_UNCATEGORIZED,
    BOOTSTRAP_TOOLS,
    MANDATORY_TOOLS,
    _DEGRADED_BROKEN_TOOLS,
    _NON_WINDOWS_TOOLS,
    _TOOL_CATEGORY,
    _TOOL_REGISTRY,
    build_inv1_prompt,
)

VALID_CATEGORIES = frozenset({
    "process_analysis", "malware_detection", "network_analysis",
    "persistence", "filesystem_analysis", "registry_analysis",
    "execution_history",
})


def _minimal_bootstrap() -> dict:
    return {n: {"tool_name": n, "output": [], "record_count": 0}
            for n in MANDATORY_TOOLS}


def _tool_in_text(tool: str, text: str) -> bool:
    return re.search(r"\b" + re.escape(tool) + r"\b", text) is not None


# ------------------------------------------------------------------
# Layer 1: Registration integrity
# ------------------------------------------------------------------

def test_L1_registry_size_stable():
    """Registry has 178 tools post-F8-B. Assert exact count as drift anchor."""
    assert len(_TOOL_REGISTRY) == 178


def test_L1_registry_no_duplicate_names():
    """Every tool name appears exactly once."""
    keys = list(_TOOL_REGISTRY.keys())
    assert len(keys) == len(set(keys))


def test_L1_every_tool_has_arg_type():
    """Every registry entry has a non-None arg_type string."""
    for name, meta in _TOOL_REGISTRY.items():
        arg_type = meta[1] if isinstance(meta, tuple) else meta.get("arg_type")
        assert arg_type, f"{name} has no arg_type"
        assert isinstance(arg_type, str), f"{name} arg_type not str"


# ------------------------------------------------------------------
# Layer 2: Filter soundness
# ------------------------------------------------------------------

def test_L2_non_windows_filter_is_frozenset():
    assert isinstance(_NON_WINDOWS_TOOLS, frozenset)


def test_L2_degraded_filter_is_empty_frozenset():
    assert isinstance(_DEGRADED_BROKEN_TOOLS, frozenset)
    assert _DEGRADED_BROKEN_TOOLS == frozenset()


def test_L2_filters_disjoint_from_each_other():
    """DEGRADED and NON_WINDOWS must not overlap - they target different
    code paths (filter-at-selectable vs runtime-block-on-degraded)."""
    overlap = _NON_WINDOWS_TOOLS & _DEGRADED_BROKEN_TOOLS
    assert not overlap, f"filter overlap: {overlap}"


def test_L2_filters_disjoint_from_bootstrap():
    """Bootstrap tools are pre-selected, never filtered."""
    assert not (_NON_WINDOWS_TOOLS & set(BOOTSTRAP_TOOLS))
    assert not (_DEGRADED_BROKEN_TOOLS & set(BOOTSTRAP_TOOLS))


def test_L2_all_filter_entries_registered():
    """No phantom filter entries."""
    assert not (_NON_WINDOWS_TOOLS - set(_TOOL_REGISTRY))
    assert not (_DEGRADED_BROKEN_TOOLS - set(_TOOL_REGISTRY))


# ------------------------------------------------------------------
# Layer 3: Categorization coverage
# ------------------------------------------------------------------

def test_L3_every_categorized_tool_in_registry():
    """No orphan categorizations."""
    orphans = set(_TOOL_CATEGORY) - set(_TOOL_REGISTRY)
    assert not orphans, f"orphans: {orphans}"


def test_L3_every_category_value_is_valid():
    """Every category assignment is one of the 7 canonical categories."""
    invalid = {t: c for t, c in _TOOL_CATEGORY.items() if c not in VALID_CATEGORIES}
    assert not invalid, f"invalid categories: {invalid}"


def test_L3_categories_not_in_non_windows():
    """Categorized tools are Windows-scope (no Linux/Mac leaks)."""
    leaked = set(_TOOL_CATEGORY) & _NON_WINDOWS_TOOLS
    assert not leaked, f"Linux/Mac in category: {leaked}"


def test_L3_approved_uncategorized_is_frozenset_of_23():
    assert isinstance(APPROVED_UNCATEGORIZED, frozenset)
    assert len(APPROVED_UNCATEGORIZED) == 23


def test_L3_approved_uncategorized_all_in_registry():
    """No phantom approved-uncategorized entries."""
    orphans = APPROVED_UNCATEGORIZED - set(_TOOL_REGISTRY)
    assert not orphans, f"orphans: {orphans}"


def test_L3_approved_uncategorized_disjoint_from_category():
    """Tool is either categorized or explicitly approved uncategorized, not both."""
    overlap = APPROVED_UNCATEGORIZED & set(_TOOL_CATEGORY)
    assert not overlap, f"both categorized and approved uncat: {overlap}"


def test_L3_approved_uncategorized_disjoint_from_non_windows():
    """Approved uncategorized are Windows tools; not Linux/Mac."""
    overlap = APPROVED_UNCATEGORIZED & _NON_WINDOWS_TOOLS
    assert not overlap, f"approved uncat overlaps non_windows: {overlap}"


def test_L3_every_windows_non_bootstrap_tool_covered():
    """THE CORE INVARIANT: every Windows non-bootstrap tool is either
    categorized OR in APPROVED_UNCATEGORIZED. No uncovered Windows tools."""
    windows = set(_TOOL_REGISTRY) - set(BOOTSTRAP_TOOLS) - _NON_WINDOWS_TOOLS
    categorized = set(_TOOL_CATEGORY) - set(BOOTSTRAP_TOOLS)
    approved = APPROVED_UNCATEGORIZED
    uncovered = windows - categorized - approved
    assert not uncovered, (
        f"uncovered Windows tools (must be categorized or approved uncat): "
        f"{sorted(uncovered)}"
    )


def test_L3_every_category_has_minimum_tools():
    """Each of the 7 categories has at least 4 tools total.

    Bootstrap tools count toward the total because _TOOL_CATEGORY
    carries metadata-level category signal even for pre-selected tools.
    This matches the Commit 15c minimum-4 invariant semantic.
    """
    from collections import Counter
    counts = Counter(_TOOL_CATEGORY.values())
    for cat in VALID_CATEGORIES:
        assert counts[cat] >= 4, f"{cat} has only {counts[cat]} tools"


# ------------------------------------------------------------------
# Layer 4: Prompt visibility
# ------------------------------------------------------------------

def test_L4_inv1_catalog_renders_every_selectable_tool(tmp_path):
    """Every Windows non-bootstrap tool appears in Inv1 catalog.

    P0-D: vol_mftscan is quarantined from the Inv1 catalog (MCP dispatch
    signature bug) so it is excluded here. Unquarantine by removing from
    the subtracted set once MCP arg validation is fixed.
    """
    _QUARANTINED = {"vol_mftscan"}
    windows = (set(_TOOL_REGISTRY) - set(BOOTSTRAP_TOOLS)
               - _NON_WINDOWS_TOOLS - _QUARANTINED)
    prompt = build_inv1_prompt(_minimal_bootstrap(), tmp_path).read_text()
    missing = [t for t in windows if not _tool_in_text(t, prompt)]
    assert not missing, (
        f"Windows tools missing from Inv1 prompt: {sorted(missing)[:10]}"
    )


def test_L4_inv1_catalog_excludes_non_windows_tools(tmp_path):
    """No Linux/Mac leaks in Inv1 prompt."""
    prompt = build_inv1_prompt(_minimal_bootstrap(), tmp_path).read_text()
    leaked = [t for t in _NON_WINDOWS_TOOLS if _tool_in_text(t, prompt)]
    assert not leaked, f"Linux/Mac leaked into Inv1: {sorted(leaked)[:5]}"


def test_L4_inv1_all_seven_categories_rendered(tmp_path):
    """All 7 category headers appear in Inv1 catalog."""
    prompt = build_inv1_prompt(_minimal_bootstrap(), tmp_path).read_text()
    for cat in VALID_CATEGORIES:
        assert cat.upper() in prompt, f"{cat} category header missing"


def test_degraded_prompt_signal_has_no_tool_blacklist(tmp_path):
    assert _DEGRADED_BROKEN_TOOLS == frozenset()

    prompt = build_inv1_prompt({}, tmp_path, degraded_profile=True).read_text()
    assert "<degraded_memory_signal>" in prompt
    assert "</degraded_memory_signal>" in prompt
    assert "<degraded_profile>" not in prompt

    import re as _re

    match = _re.search(
        r"<degraded_memory_signal>(.*?)</degraded_memory_signal>",
        prompt,
        _re.DOTALL,
    )
    assert match

    signal = match.group(1)
    tool_names = _re.findall(
        r"\b(?:vol_|run_|parse_|get_|extract_|sleuthkit_)\w+\b",
        signal,
    )
    assert tool_names == []


# ------------------------------------------------------------------
# Layer 5: Dispatch routing (mocked)
# ------------------------------------------------------------------

def test_L5_run_tool_is_callable():
    """run_tool dispatch entry exists and is callable."""
    from sift_sentinel.coordinator import run_tool
    assert callable(run_tool)


def test_L5_every_registered_tool_has_dispatchable_arg_type():
    """Every tool has a valid arg_type that maps to a known dispatch category."""
    KNOWN_ARG_TYPES = frozenset({
        "disk", "disk_mft", "ez_tools", "memory", "sift_native",
        "sleuthkit", "standalone", "vol_generic",
    })
    invalid = {}
    for name, meta in _TOOL_REGISTRY.items():
        arg_type = meta[1] if isinstance(meta, tuple) else meta.get("arg_type")
        if arg_type not in KNOWN_ARG_TYPES:
            invalid[name] = arg_type
    assert not invalid, f"invalid arg_types: {invalid}"
