from sift_sentinel.validation.report_gates import (
    check_confirmed_section_render_coverage,
)


def _buckets(*ids):
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": fid, "title": f"title {fid}"}
            for fid in ids
        ],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "suspicious_needs_review": [],
        "synthesis_narrative": [],
    }


def test_confirmed_gate_ignores_later_confirmed_subsections():
    report = """# Report

## Confirmed Malicious Atomic Findings

### F001: first finding

Evidence for F001.

### F002: second finding

Evidence for F002.

## MITRE ATT&CK Mapping

### Confirmed Malicious Findings

This later narrative subsection is not the primary confirmed section.
"""

    # Legacy audit shape may say FAIL because it counted unrelated headings.
    # The post-run gate must validate the final persisted report text itself.
    truth = {
        "confirmed_section_render": {
            "schema_version": "confirmed_section_render_v1",
            "gate": "FAIL",
            "expected_count": 2,
            "missing_count": 0,
            "missing_finding_ids": [],
            "heading_count": 2,
        }
    }

    assert check_confirmed_section_render_coverage(
        report,
        _buckets("F001", "F002"),
        truth,
    ) == []


def test_confirmed_gate_requires_top_level_primary_section():
    report = """# Report

### Confirmed Malicious Atomic Findings

### F001: first finding

## MITRE ATT&CK Mapping
"""

    truth = {
        "confirmed_section_render": {
            "schema_version": "confirmed_section_render_v2",
            "gate": "PASS",
            "expected_count": 1,
            "missing_count": 0,
            "missing_finding_ids": [],
            "heading_count": 1,
        }
    }

    violations = check_confirmed_section_render_coverage(
        report,
        _buckets("F001"),
        truth,
    )

    assert any(v.startswith("confirmed_section_heading_count:") for v in violations)
    assert "confirmed_section_missing" in violations
