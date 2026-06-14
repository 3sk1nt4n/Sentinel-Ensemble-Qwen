from sift_sentinel.reporting.deterministic_confirmed_section import (
    render_confirmed_findings_section,
    replace_confirmed_findings_section,
)


def _finding(fid, title):
    return {
        "finding_id": fid,
        "title": title,
        "severity": "CRITICAL",
        "confidence_level": "HIGH",
        "source_tools": ["tool_alpha", "tool_beta"],
        "claims": [
            {"type": "pid", "pid": 1234, "process": "example.exe"},
            {"type": "hash", "sha1": "a" * 40},
        ],
        "verified_claims_count": 2,
        "claims_count": 2,
    }


def test_render_one_heading_per_confirmed_finding():
    section, audit = render_confirmed_findings_section(
        [_finding("F001", "First"), _finding("F002", "Second")]
    )

    assert audit["gate"] == "PASS"
    assert audit["expected_count"] == 2
    assert audit["heading_count"] == 2
    assert audit["missing_ids"] == []
    assert "### F001: First" in section
    assert "### F002: Second" in section


def test_replace_existing_confirmed_section_removes_llm_grouped_content():
    report = """# Report

## Executive Summary

Narrative.

## Confirmed Findings

### Grouped Memory Injection

Old grouped content.

## Requires Analyst Review

Review text.
"""
    new_report, chars = replace_confirmed_findings_section(
        report,
        [_finding("F010", "Atomic A"), _finding("F011", "Atomic B")],
    )

    assert chars > 0
    assert "Grouped Memory Injection" not in new_report
    assert "### F010: Atomic A" in new_report
    assert "### F011: Atomic B" in new_report
    assert "## Requires Analyst Review" in new_report


def test_insert_confirmed_section_when_missing():
    report = "# Report\n\n## Executive Summary\n\nNarrative.\n"
    new_report, _chars = replace_confirmed_findings_section(
        report,
        [_finding("F100", "Inserted")],
    )

    assert "## Confirmed Malicious Atomic Findings" in new_report
    assert "### F100: Inserted" in new_report


def test_accepts_bucket_dict_as_source():
    section, audit = render_confirmed_findings_section(
        {"confirmed_malicious_atomic": [_finding("F200", "Bucketed")]}
    )

    assert audit["gate"] == "PASS"
    assert audit["expected_ids"] == ["F200"]
    assert "### F200: Bucketed" in section


def test_accepts_legacy_group_shapes_and_deduplicates():
    section, audit = render_confirmed_findings_section(
        [
            {"findings": [_finding("F300", "Grouped"), _finding("F300", "Grouped duplicate")]},
            {"items": [_finding("F301", "Grouped two")]},
        ]
    )

    assert audit["gate"] == "PASS"
    assert audit["expected_ids"] == ["F300", "F301"]
    assert section.count("### F300:") == 1
    assert section.count("### F301:") == 1
