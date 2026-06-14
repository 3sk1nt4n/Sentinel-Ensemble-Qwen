"""Commit 11: Inv1 prompt breadth and category mandate (N16 fix)."""
from pathlib import Path

from sift_sentinel.coordinator import build_inv1_prompt, MANDATORY_TOOLS


def _minimal_bootstrap() -> dict[str, dict]:
    """Minimal bootstrap matching pattern from test_coordinator.py:1205."""
    return {
        name: {"tool_name": name, "output": [], "record_count": 0}
        for name in MANDATORY_TOOLS
    }


def test_inv1_prompt_requests_wider_breadth_15_to_20(tmp_path):
    """Commit 11: instruction must demand 15-20 tools, not 6-10."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "15-20 tools" in text
    assert "6-10 tools" not in text


def test_inv1_prompt_names_seven_categories(tmp_path):
    """Category mandate must explicitly name all 7 investigative categories."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    for cat in (
        "process_analysis", "malware_detection", "network_analysis",
        "persistence", "execution_history", "filesystem_analysis",
        "registry_analysis",
    ):
        assert cat in text, f"category missing: {cat}"


def test_inv1_prompt_requires_5_of_7_coverage(tmp_path):
    """Prompt must state the 5-of-7 coverage requirement."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "at least 5 of these" in text
    assert "7 categories" in text


def test_inv1_prompt_preserves_cross_domain_guidance(tmp_path):
    """Existing Include BOTH memory/disk guidance must survive edit."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "BOTH memory tools AND disk tools" in text


def test_inv1_prompt_preserves_json_response_schema(tmp_path):
    """Return JSON schema instruction must remain intact post-edit."""
    prompt_path = build_inv1_prompt(_minimal_bootstrap(), tmp_path)
    text = prompt_path.read_text()
    assert "selected_tools" in text
    assert "reasoning" in text
