"""Commit 15b: Non-Windows vol plugin filter in Inv1 and ReAct prompts."""
import re
from pathlib import Path

from sift_sentinel.coordinator import (
    _NON_WINDOWS_TOOLS,
    _TOOL_REGISTRY,
    MANDATORY_TOOLS,
    build_inv1_prompt,
)


def _tool_in_text(tool: str, text: str) -> bool:
    """Word-boundary match so vol_proc does not false-positive on vol_procmaps.

    The catalog lists tools comma-separated on one line, so a naive
    substring check would match prefix-overlapping tool names (e.g.
    vol_proc inside vol_procmaps, vol_processghosting). Use \\b word
    boundaries to require the exact identifier.
    """
    return re.search(r"\b" + re.escape(tool) + r"\b", text) is not None


def _minimal_bootstrap() -> dict[str, dict]:
    return {
        name: {"tool_name": name, "output": [], "record_count": 0}
        for name in MANDATORY_TOOLS
    }


def _extract_catalog(text: str) -> str:
    """Extract the tool catalog section from a build_inv1_prompt output.

    Uses 'Return JSON:' as the catalog end marker because inter-category
    blank lines would cause a naive '\\n\\n' search to truncate to the
    first category block only, silently hiding leaks in later categories.
    """
    catalog_start = text.find("Available tools")
    catalog_end = text.find("Return JSON:", catalog_start)
    assert catalog_start >= 0 and catalog_end > catalog_start, (
        "catalog markers not found in prompt"
    )
    return text[catalog_start:catalog_end]


def test_non_windows_tools_all_exist_in_registry():
    """Every non-Windows tool must be a real registered tool (no orphans)."""
    orphans = _NON_WINDOWS_TOOLS - set(_TOOL_REGISTRY.keys())
    assert not orphans, f"orphaned non-Windows entries: {orphans}"


def test_non_windows_tools_known_linux_plugins():
    """Spot-check that specific known Linux plugins are in the set."""
    for tool in ("vol_bash", "vol_lsmod", "vol_proc", "vol_kthreads",
                 "vol_ebpf", "vol_dmesg", "vol_ifconfig", "vol_ip",
                 "vol_mount", "vol_ptrace"):
        assert tool in _NON_WINDOWS_TOOLS, f"{tool} missing from _NON_WINDOWS_TOOLS"


def test_non_windows_tools_known_mac_plugins():
    """Spot-check that specific known Mac plugins are in the set."""
    for tool in ("vol_trustedbsd", "vol_kevents"):
        assert tool in _NON_WINDOWS_TOOLS, f"{tool} missing from _NON_WINDOWS_TOOLS"


def test_non_windows_set_does_not_include_windows_plugins():
    """Known Windows plugins must NOT be in _NON_WINDOWS_TOOLS."""
    for tool in ("vol_pslist", "vol_psscan", "vol_netscan", "vol_svcscan",
                 "vol_malfind", "vol_hollowprocesses", "vol_vadregexscan",
                 "vol_vadyarascan", "vol_filescan", "vol_mftscan"):
        assert tool not in _NON_WINDOWS_TOOLS, (
            f"{tool} is Windows-intended, should NOT be in _NON_WINDOWS_TOOLS"
        )


def test_inv1_catalog_excludes_all_non_windows_tools(tmp_path):
    """Full Inv1 catalog must contain ZERO non-Windows tools across all categories."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    catalog = _extract_catalog(text)
    leaked = sorted(t for t in _NON_WINDOWS_TOOLS if _tool_in_text(t, catalog))
    assert not leaked, f"non-Windows tools leaked into Inv1 catalog: {leaked}"


def test_inv1_prompt_does_not_mention_specific_non_windows_tools(tmp_path):
    """Spot-check specific non-Windows tools absent from entire prompt."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    for tool in ("vol_bash", "vol_lsmod", "vol_pscallstack",
                 "vol_modxview", "vol_trustedbsd"):
        assert not _tool_in_text(tool, text), f"{tool} leaked into Inv1 prompt"


def test_inv1_preserves_windows_tools(tmp_path):
    """build_inv1_prompt must still include Windows tools in catalog."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    for tool in ("vol_pslist", "vol_malfind", "vol_svcscan", "vol_filescan"):
        assert _tool_in_text(tool, text), f"Windows tool {tool} missing from Inv1 catalog"


def test_degraded_profile_also_filters_non_windows(tmp_path):
    """On DEGRADED profile, non-Windows filter still applies to catalog.

    The prompt may include a generic degraded-memory signal, but the catalog
    must still exclude non-Windows tools.
    """
    prompt_path = build_inv1_prompt(
        _minimal_bootstrap(), tmp_path, degraded_profile=True,
    )
    text = prompt_path.read_text()
    catalog = _extract_catalog(text)
    leaked = sorted(t for t in _NON_WINDOWS_TOOLS if _tool_in_text(t, catalog))
    assert not leaked, f"DEGRADED catalog leaked non-Windows tools: {leaked}"
    assert "<degraded_memory_signal>" in text
    assert "<degraded_profile>" not in text
