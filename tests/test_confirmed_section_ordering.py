"""When the AI report has no confirmed-section heading, the deterministic
confirmed block must be inserted AFTER the Executive Summary -- so the report
leads with the summary, then the confirmed findings. Previously it landed right
after the title `#`, pushing it ABOVE the Executive Summary. Universal/structural:
keys only on the generic '## Executive Summary' heading, no case data."""
from sift_sentinel.reporting.deterministic_confirmed_section import (
    replace_confirmed_findings_section,
)


def _finding(fid, title):
    return {
        "finding_id": fid,
        "title": title,
        "severity": "CRITICAL",
        "claims": [{"type": "path", "value": "C:\\Windows\\Temp\\x.exe"}],
        "description": "%s executed from Temp" % title,
    }


def test_confirmed_section_inserted_after_executive_summary():
    report = (
        "# Forensic Incident Report\n\n"
        "## Executive Summary\n\nNarrative of what happened.\n\n"
        "## Suspicious Activity\n\nReview items.\n"
    )
    new_report, chars = replace_confirmed_findings_section(report, [_finding("F1", "Atomic A")])
    assert chars > 0
    i_exec = new_report.find("## Executive Summary")
    i_conf = new_report.lower().find("confirmed malicious")
    i_susp = new_report.find("## Suspicious Activity")
    assert i_exec != -1 and i_conf != -1 and i_susp != -1
    # order: Exec Summary -> Confirmed -> Suspicious
    assert i_exec < i_conf < i_susp


def test_no_executive_summary_falls_back_to_after_title():
    report = "# Forensic Incident Report\n\n## Suspicious Activity\n\nReview items.\n"
    new_report, _ = replace_confirmed_findings_section(report, [_finding("F1", "Atomic A")])
    i_title = new_report.find("# Forensic Incident Report")
    i_conf = new_report.lower().find("confirmed malicious")
    i_susp = new_report.find("## Suspicious Activity")
    assert i_title < i_conf < i_susp


def test_existing_confirmed_section_replaced_in_place():
    # in-place replacement keeps its position (unchanged behavior)
    report = (
        "# Report\n\n## Executive Summary\n\nNarrative.\n\n"
        "## Confirmed Findings\n\nOld grouped content.\n\n## Other\n\nx.\n"
    )
    new_report, chars = replace_confirmed_findings_section(report, [_finding("F1", "Atomic A")])
    assert chars > 0
    assert "Old grouped content" not in new_report
    i_exec = new_report.find("## Executive Summary")
    i_conf = new_report.lower().find("confirmed malicious")
    assert i_exec < i_conf
