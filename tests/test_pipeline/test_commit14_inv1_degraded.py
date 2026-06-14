"""Evidence-speaks tests for degraded-memory Inv1 prompt behavior.

The prompt may communicate memory state, but it must not encode a
hardcoded tool blacklist, plugin blacklist, or per-dataset skip sheet.
"""

from __future__ import annotations

import re

from sift_sentinel.coordinator import LOW_YIELD_TOOLS, build_inv1_prompt


def test_degraded_prompt_uses_generic_signal(tmp_path):
    prompt = build_inv1_prompt({}, tmp_path, degraded_profile=True).read_text()

    assert "<degraded_memory_signal>" in prompt
    assert "</degraded_memory_signal>" in prompt
    assert "<degraded_profile>" not in prompt
    assert "negative-yield observation" in prompt
    assert "Let the evidence speak" in prompt


def test_degraded_signal_has_no_tool_names(tmp_path):
    prompt = build_inv1_prompt({}, tmp_path, degraded_profile=True).read_text()

    match = re.search(
        r"<degraded_memory_signal>(.*?)</degraded_memory_signal>",
        prompt,
        re.DOTALL,
    )
    assert match, "degraded_memory_signal block missing"

    signal = match.group(1)
    tool_names = re.findall(
        r"\b(?:vol_|run_|parse_|get_|extract_|sleuthkit_)\w+\b",
        signal,
    )

    assert tool_names == []


def test_degraded_prompt_has_no_old_skip_sheet_phrases(tmp_path):
    prompt = build_inv1_prompt({}, tmp_path, degraded_profile=True).read_text()

    banned_phrases = [
        "AVOID " + "these " + "known-" + "broken",
        "PREFER " + "disk-based categories",
        "MORE " + "reliable than memory",
    ]

    for phrase in banned_phrases:
        assert phrase not in prompt


def test_degraded_false_has_no_degraded_section(tmp_path):
    prompt = build_inv1_prompt({}, tmp_path, degraded_profile=False).read_text()

    assert "<degraded_memory_signal>" not in prompt
    assert "<degraded_profile>" not in prompt


def test_low_yield_tools_registry_is_empty_policy():
    assert LOW_YIELD_TOOLS == {}


def test_inv1_prompt_backward_compat_default_matches_explicit_false(tmp_path):
    a = build_inv1_prompt({}, tmp_path / "a")
    b = build_inv1_prompt({}, tmp_path / "b", degraded_profile=False)

    assert a.read_text() == b.read_text()


def test_inv1_prompt_preserves_breadth_guidance_in_both_modes(tmp_path):
    for degraded in (False, True):
        prompt = build_inv1_prompt(
            {},
            tmp_path / f"d{int(degraded)}",
            degraded_profile=degraded,
        ).read_text()

        assert "15-20 tools" in prompt


def test_inv1_prompt_preserves_category_mandate_in_both_modes(tmp_path):
    for degraded in (False, True):
        prompt = build_inv1_prompt(
            {},
            tmp_path / f"c{int(degraded)}",
            degraded_profile=degraded,
        ).read_text()

        assert "5 " in prompt
        assert "categories" in prompt
