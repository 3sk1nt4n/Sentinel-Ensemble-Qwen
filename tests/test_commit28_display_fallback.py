"""Commit 28: regression guards for display fallback and claim schema.

L28-1 structural: finding_title exists and is exported
L28-2 behavioral: artifact present -> artifact returned
L28-3 behavioral: artifact absent, original_draft.artifact present -> orig (P2)
L28-4 behavioral: artifact+original absent, summary present -> summary
L28-5 behavioral: all content absent/invalid -> sentinel returned
L28-6 C27 follow-up: _claim_spans renders foreign_addr:foreign_port
"""
from __future__ import annotations

from sift_sentinel.reporting import finding_title
from sift_sentinel.reporting.display import finding_title as direct_import


def test_L28_1_finding_title_exists_and_exported():
    """Structural: finding_title importable from package and direct module."""
    assert callable(finding_title), "finding_title not exported from reporting"
    assert callable(direct_import), "finding_title not exported from display module"
    assert finding_title is direct_import, "package export and module export differ"


def test_L28_2_artifact_present_returned():
    """Behavioral: finding with artifact returns artifact."""
    expected = "PID 9007 powershell.exe C2 to 1.2.3.4"
    f = {"artifact": expected}
    assert finding_title(f) == expected


def test_L28_3_artifact_absent_original_draft_returned():
    """Behavioral: SC-rewritten finding falls back to original_draft.artifact.
    P2 priority: pre-SC content preferred over post-SC summary."""
    expected = "ngentask.exe PID 7092 beaconing to 192.0.2.140:8080"
    f = {
        "summary": "Suspicious process short form",
        "original_draft": {"artifact": expected},
    }
    result = finding_title(f)
    assert result == expected, (
        f"P2 priority violated: expected pre-SC content, got {result!r}"
    )


def test_L28_4_artifact_and_original_absent_summary_returned():
    """Behavioral: no artifact and no original_draft -> summary."""
    f = {"summary": "Short post-SC description"}
    assert finding_title(f) == "Short post-SC description"


def test_L28_5_all_absent_sentinel_returned():
    """Behavioral: nothing populated -> sentinel string, not blank."""
    assert finding_title({}) == "(no description available)"
    assert finding_title({"artifact": ""}) == "(no description available)"
    assert finding_title({"artifact": "   "}) == "(no description available)"
    assert finding_title(None) == "(no description available)"
    assert finding_title([]) == "(no description available)"
    assert finding_title("not a dict") == "(no description available)"


def test_L28_6_claim_spans_connection_uses_canonical_keys():
    """C27 follow-up: _claim_spans renders foreign_addr + foreign_port."""
    from sift_sentinel.generate_report import _claim_spans
    claims = [{
        "type": "connection",
        "pid": 3164,
        "process": "powershell.exe",
        "foreign_addr": "192.0.2.140",
        "foreign_port": 8080,
    }]
    html = _claim_spans(claims)
    assert "192.0.2.140" in html, f"foreign_addr not rendered: {html!r}"
    assert "8080" in html, f"foreign_port not rendered: {html!r}"
    assert "?:?" not in html, (
        f"C27 follow-up regression legacy keys still read: {html!r}"
    )
