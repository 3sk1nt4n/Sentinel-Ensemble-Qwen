"""Tests for CC#15 Finding N display helper.

Judges read terminal and HTML reports. "F001" looks like a technical
code; "Finding 1" is cleaner. Internal JSON/state/validator/test keys
still use "F001" -- this helper is display-only.
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.reporting import display_finding_id


class TestDisplayFindingId:
    def test_display_finding_id_basic(self):
        assert display_finding_id("F001") == "Finding 1"

    def test_display_finding_id_with_total(self):
        # P0-E: total arg accepted but no longer rendered (dropped to avoid
        # false-precision bug when finding_id gaps diverge from list length).
        assert display_finding_id("F003", total=7) == "Finding 3"

    def test_display_finding_id_strips_leading_zeros(self):
        assert display_finding_id("F010") == "Finding 10"
        assert display_finding_id("F099") == "Finding 99"

    def test_display_finding_id_preserves_malformed(self):
        """Unexpected input (e.g. upstream schema drift) passes through."""
        assert display_finding_id("X999") == "X999"
        assert display_finding_id("Fxyz") == "Fxyz"

    def test_display_finding_id_empty_input(self):
        assert display_finding_id("") == ""
        assert display_finding_id(None) == ""  # type: ignore[arg-type]

    def test_display_finding_id_zero_total_omits_of_clause(self):
        """total=0 is falsy; treat as no total (don't print 'of 0')."""
        assert display_finding_id("F001", total=0) == "Finding 1"

    def test_display_finding_id_large_index(self):
        # P0-E: total arg ignored; see test_display_finding_id_with_total.
        assert display_finding_id("F123", total=200) == "Finding 123"


class TestDisplayAppliedInReports:
    """The helper must be wired into the user-facing render sites.

    Internal state/logs/validator still use F001. These tests assert the
    helper is imported wherever judge-facing text is composed.
    """

    def test_imported_in_run_pipeline(self):
        src = Path("run_pipeline.py").read_text()
        assert "display_finding_id" in src, (
            "run_pipeline.py must use display_finding_id for "
            "dashboard/self-assessment/walkthrough output"
        )

    def test_imported_in_console(self):
        src = Path("src/sift_sentinel/console.py").read_text()
        assert "display_finding_id" in src, (
            "console.py list/show commands must render Finding N"
        )

    def test_imported_in_generate_report(self):
        src = Path("src/sift_sentinel/generate_report.py").read_text()
        assert "display_finding_id" in src, (
            "HTML report cards must render Finding N"
        )
