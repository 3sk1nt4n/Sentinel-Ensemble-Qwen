"""Commit 13: em-dash sanitization for Inv4 report output (N13 fix)."""
from pathlib import Path

from sift_sentinel.coordinator import (
    _REPORT_UNICODE_REPLACEMENTS,
    _coerce_report,
    _sanitize_report_text,
    build_inv4_prompt,
)


def test_sanitize_replaces_em_dash():
    """U+2014 must become double hyphen."""
    result = _sanitize_report_text("foo \u2014 bar")
    assert result == "foo -- bar"
    assert "\u2014" not in result


def test_sanitize_replaces_en_dash():
    """U+2013 must become single hyphen."""
    result = _sanitize_report_text("range 2023\u20132024")
    assert result == "range 2023-2024"
    assert "\u2013" not in result


def test_sanitize_replaces_rightwards_arrow():
    """U+2192 must become ->"""
    result = _sanitize_report_text("flow A \u2192 B")
    assert result == "flow A -> B"
    assert "\u2192" not in result


def test_sanitize_replaces_multiplication_sign():
    """U+00D7 must become letter x."""
    result = _sanitize_report_text("size 3\u00d74")
    assert result == "size 3x4"
    assert "\u00d7" not in result


def test_sanitize_is_idempotent_on_clean_text():
    """Running sanitizer twice must give same result."""
    clean = "already clean ASCII text"
    assert _sanitize_report_text(clean) == clean
    assert _sanitize_report_text(_sanitize_report_text(clean)) == clean


def test_sanitize_handles_empty_string():
    """Empty string must pass through unchanged."""
    assert _sanitize_report_text("") == ""


def test_replacements_map_has_expected_entries():
    """The module-level replacement map must cover all 4 known polluters."""
    assert _REPORT_UNICODE_REPLACEMENTS["\u2014"] == "--"
    assert _REPORT_UNICODE_REPLACEMENTS["\u2013"] == "-"
    assert _REPORT_UNICODE_REPLACEMENTS["\u2192"] == "->"
    assert _REPORT_UNICODE_REPLACEMENTS["\u00d7"] == "x"
    assert len(_REPORT_UNICODE_REPLACEMENTS) == 4


def test_coerce_report_applies_sanitizer_on_live_path():
    """_coerce_report must strip em-dashes from AI string output."""
    polluted = "# Incident Report\n\nFinding \u2014 critical \u2013 review\nFlow A \u2192 B\n"
    result = _coerce_report(polluted)
    assert "\u2014" not in result
    assert "\u2013" not in result
    assert "\u2192" not in result
    assert "--" in result
    assert "->" in result


def test_coerce_report_applies_sanitizer_on_fallback_path():
    """_coerce_report with non-string input returns sanitized fallback template."""
    result = _coerce_report(None)
    assert isinstance(result, str)
    # Fallback template is ASCII-clean already, so no content change, but
    # still must be run through sanitizer safely.
    assert "\u2014" not in result
    assert "INCOMPLETE" in result


def test_inv4_prompt_has_ascii_only_instruction(tmp_path):
    """Inv4 prompt header must instruct AI to use ASCII only."""
    prompt_path = build_inv4_prompt(
        [{"finding_id": "F001", "severity": "MEDIUM"}],
        tmp_path,
    )
    text = prompt_path.read_text()
    header = text.split("## Findings")[0]
    assert "standard ASCII characters only" in header
    assert "em-dash" in header
    assert "en-dash" in header
