"""
SIFT Sentinel -- B3/B4 schema warning banner tests.

Unit-tests apply_schema_warning_banner helper. No run_pipeline.py
coupling, no validate_report invocation. Tests only the logic added
by the B3/B4 fix: prepend schema errors as banner, preserve report.
"""

from __future__ import annotations

from sift_sentinel.reporting.fallback import apply_schema_warning_banner


def test_b4_banner_prepended_when_errors_present():
    """Errors list produces a markdown blockquote banner above the report."""
    report = "# Incident Report\n\nFull analysis here.\n"
    errors = [
        "Finding F009: missing required field 'finding_id'",
        "Finding F009: empty tool_call_ids list",
    ]

    result = apply_schema_warning_banner(report, errors)

    assert result.startswith("> **SCHEMA VALIDATION WARNINGS:**")
    assert "> - Finding F009: missing required field 'finding_id'" in result
    assert "> - Finding F009: empty tool_call_ids list" in result
    assert "# Incident Report" in result
    assert "Full analysis here." in result
    assert len(result) > len(report)


def test_b4_empty_errors_returns_report_unchanged():
    """No errors means no banner; report passes through byte-identical."""
    report = "# Incident Report\n\nClean report.\n"

    result = apply_schema_warning_banner(report, [])

    assert result == report


def test_b4_banner_does_not_truncate_long_report():
    """22k-char report (RD-02 scenario) survives banner with content intact."""
    body = "Analysis paragraph. " * 1200
    report = f"# Incident Report\n\n{body}"
    errors = ["Finding findings[10]: missing required field 'finding_id'"]

    result = apply_schema_warning_banner(report, errors)

    assert body in result
    assert len(result) > 24000
    assert result.startswith("> **SCHEMA VALIDATION WARNINGS:**")
