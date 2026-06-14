"""Commit 15a: Priority guidance lists all 7 categories with urgency bullets."""
from pathlib import Path

from sift_sentinel.coordinator import MANDATORY_TOOLS, build_inv1_prompt


def _minimal_bootstrap() -> dict[str, dict]:
    return {
        name: {"tool_name": name, "output": [], "record_count": 0}
        for name in MANDATORY_TOOLS
    }


def test_priority_guidance_has_filesystem_analysis_bullet(tmp_path):
    """Priority guidance must explicitly nudge toward filesystem_analysis."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "Add filesystem_analysis" in text
    assert "MFT timeline" in text


def test_priority_guidance_has_registry_analysis_bullet(tmp_path):
    """Priority guidance must explicitly nudge toward registry_analysis."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "Add registry_analysis" in text
    assert "autoruns" in text


def test_priority_guidance_ordering_disk_between_persistence_and_execution(tmp_path):
    """filesystem and registry bullets must appear between persistence and execution_history."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    persistence_pos = text.find("Add persistence tools")
    filesystem_pos = text.find("Add filesystem_analysis")
    registry_pos = text.find("Add registry_analysis")
    execution_pos = text.find("Add execution_history")
    assert persistence_pos < filesystem_pos < registry_pos < execution_pos, (
        f"ordering broken: persistence={persistence_pos}, fs={filesystem_pos}, "
        f"reg={registry_pos}, exec={execution_pos}"
    )


def test_priority_guidance_covers_all_seven_categories(tmp_path):
    """All 7 categories must have a priority guidance bullet."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    block_start = text.find("Priority guidance:")
    block_end = text.find("Available tools", block_start)
    block = text[block_start:block_end]
    for category in [
        "process_analysis",
        "network_analysis",
        "malware_detection",
        "persistence",
        "filesystem_analysis",
        "registry_analysis",
        "execution_history",
    ]:
        assert category in block, f"{category} missing from priority guidance"


def test_priority_guidance_preserves_thorough_span_closer(tmp_path):
    """The 'Thorough investigations span multiple categories' closer must remain."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "Thorough investigations span multiple categories" in text
