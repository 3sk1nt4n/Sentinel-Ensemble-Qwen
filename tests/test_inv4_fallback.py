"""Tests for CC#16 Fix 2 -- Inv4 structured fallback report.

When the Inv4 API call fails, the pipeline falls back to a pure-Python
renderer (sift_sentinel.reporting.fallback.render_fallback_report) that
produces a publishable markdown report from the already-validated
findings. These tests guard the renderer against regressions in field
handling and markdown structure.
"""
from __future__ import annotations

from sift_sentinel.reporting.fallback import render_fallback_report


class TestEmptyFindings:
    def test_empty_list_produces_valid_report(self):
        report = render_fallback_report([])
        assert "# SIFT Sentinel Incident Report" in report
        assert "**Validated findings:** 0" in report
        assert "## Findings" in report
        assert "## Limitations" in report

    def test_empty_list_has_no_finding_sections(self):
        report = render_fallback_report([])
        assert "### F" not in report


class TestSingleFinding:
    def test_full_finding_renders_all_fields(self):
        finding = {
            "finding_id": "F001",
            "title": "WMI-spawned PowerShell",
            "severity": "CRITICAL",
            "timestamp": "2018-08-30T16:43:36+00:00",
            "evidence_type": "memory",
            "source_tools": ["vol_pstree", "vol_cmdline"],
            "description": "WmiPrvSE spawned powershell.exe with null cmdline.",
            "raw_excerpt": "PID 2876 -> PID 9002",
        }
        report = render_fallback_report([finding])
        assert "### F001 -- WMI-spawned PowerShell (CRITICAL)" in report
        assert "**Timestamp:** 2018-08-30T16:43:36+00:00" in report
        assert "**Evidence type:** memory" in report
        assert "**Source tools:** vol_pstree, vol_cmdline" in report
        assert "WmiPrvSE spawned powershell.exe with null cmdline." in report
        assert "PID 2876 -> PID 9002" in report
        assert "**Validated findings:** 1" in report

    def test_artifact_used_when_title_missing(self):
        finding = {
            "finding_id": "F002",
            "artifact": "Cobalt Strike beacon",
            "source_tools": ["vol_malfind"],
        }
        report = render_fallback_report([finding])
        assert "### F002 -- Cobalt Strike beacon (UNKNOWN)" in report

    def test_confidence_level_used_when_severity_missing(self):
        finding = {
            "finding_id": "F003",
            "title": "Suspicious process",
            "confidence_level": "HIGH",
        }
        report = render_fallback_report([finding])
        assert "(HIGH)" in report


class TestDefensiveFieldHandling:
    def test_missing_optional_fields_do_not_crash(self):
        finding = {"finding_id": "F004"}
        report = render_fallback_report([finding])
        assert "### F004 -- (no description available) (UNKNOWN)" in report

    def test_none_values_for_strings_do_not_crash(self):
        finding = {
            "finding_id": "F005",
            "title": None,
            "description": None,
            "timestamp": None,
        }
        report = render_fallback_report([finding])
        assert isinstance(report, str)
        assert "### F005" in report
        assert "**Timestamp:** None" not in report

    def test_none_source_tools_does_not_crash(self):
        finding = {
            "finding_id": "F006",
            "title": "Anomaly",
            "source_tools": None,
        }
        report = render_fallback_report([finding])
        assert "### F006 -- Anomaly" in report
        assert "**Source tools:**" not in report

    def test_empty_source_tools_list_omits_line(self):
        finding = {
            "finding_id": "F007",
            "title": "Test",
            "source_tools": [],
        }
        report = render_fallback_report([finding])
        assert "### F007" in report
        assert "**Source tools:**" not in report

    def test_missing_finding_id_renders_question_mark(self):
        finding = {"title": "No ID"}
        report = render_fallback_report([finding])
        assert "### ? -- No ID" in report


class TestMultipleFindings:
    def test_ten_findings_all_rendered_in_order(self):
        findings = [
            {"finding_id": f"F{i:03d}", "title": f"Finding {i}", "severity": "HIGH"}
            for i in range(1, 11)
        ]
        report = render_fallback_report(findings)
        assert "**Validated findings:** 10" in report
        for i in range(1, 11):
            assert f"### F{i:03d} -- Finding {i} (HIGH)" in report
        assert report.index("F001") < report.index("F010")


class TestRawExcerptFormatting:
    def test_multi_line_raw_excerpt_wrapped_in_fenced_block(self):
        finding = {
            "finding_id": "F008",
            "title": "Multi-line",
            "raw_excerpt": "line 1\nline 2\nline 3",
        }
        report = render_fallback_report([finding])
        assert "line 1\nline 2\nline 3" in report
        assert "````" in report

    def test_single_line_raw_excerpt_wrapped_in_fenced_block(self):
        finding = {
            "finding_id": "F009",
            "title": "Single-line",
            "raw_excerpt": "pid 1234",
        }
        report = render_fallback_report([finding])
        assert "pid 1234" in report
        assert "````" in report


class TestStructuralInvariants:
    def test_report_starts_with_h1_heading(self):
        report = render_fallback_report([])
        assert report.startswith("# SIFT Sentinel Incident Report")

    def test_report_contains_limitations_section(self):
        report = render_fallback_report([{"finding_id": "F001"}])
        assert "## Limitations" in report
        assert "deterministic" in report.lower()

    def test_report_is_string_not_none(self):
        result = render_fallback_report([])
        assert isinstance(result, str)
        assert len(result) > 100
