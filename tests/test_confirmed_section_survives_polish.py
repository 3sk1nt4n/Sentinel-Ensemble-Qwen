"""The confirmed-malicious section must survive report polish AND satisfy the
post-run coverage gate.

Root cause of the live POSTRUN_REPORT_VALIDATION_GATE=FAIL (exit 1 on a SUCCESSFUL
run): polish_report DROPPED the '## Confirmed Malicious Atomic Findings' section
(it sat in _REMOVE_SECTIONS) while postrun_report_checks REQUIRED it -- every run
with confirmed findings failed, and the customer report silently lost its most
important section. Fix = keep the section in polish + make the confirmed-heading
gate regexes tolerant of polish's '## N.' numbering. Universal: section-title
structure only, no case data.
"""
import re

from sift_sentinel.reporting.report_polish import polish_report
from sift_sentinel.validation.report_gates import check_confirmed_section_render_coverage

_HEAD_NUMBERED = re.compile(
    r"^##\s+(?:\d+\.\s+)?Confirmed Malicious(?: Atomic)? Findings", re.M)


def _report():
    return ("# Forensic Incident Report\n\n## Executive Summary\noverview\n\n"
            "## Confirmed Malicious Atomic Findings\n\n"
            "- F044 sdelete (hash 7bcd...)\n- F052 exfil egress\n\n"
            "## Suspicious Findings\ns\n\n## Recommendations\nr\n")


def test_polish_keeps_the_confirmed_section():
    out = polish_report(_report())
    assert _HEAD_NUMBERED.search(out), "polish dropped the confirmed-malicious section"
    assert "F044" in out and "F052" in out  # the findings themselves survive


def test_postrun_gate_matches_the_polished_confirmed_section():
    out = polish_report(_report())
    buckets = {"confirmed_malicious_atomic": [{"finding_id": "F044"}, {"finding_id": "F052"}]}
    rt = {"confirmed_section_render": {"gate": "PASS", "expected_count": 2}}
    violations = check_confirmed_section_render_coverage(out, buckets, rt)
    bad = [v for v in violations if "confirmed_section_missing" in v or "heading_count" in v]
    assert not bad, bad


def test_gate_still_matches_an_unnumbered_heading():
    # the in-run gate runs on the UNPOLISHED report (no '## N.') -> must still match
    buckets = {"confirmed_malicious_atomic": [{"finding_id": "F044"}]}
    rt = {"confirmed_section_render": {"gate": "PASS", "expected_count": 1}}
    md = "# R\n\n## Confirmed Malicious Atomic Findings\n\n- F044 x\n"
    bad = [v for v in check_confirmed_section_render_coverage(md, buckets, rt)
           if "confirmed_section_missing" in v or "heading_count" in v]
    assert not bad, bad
