from __future__ import annotations

from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def test_public_summary_counts_present_without_legacy_columns():
    text = render_customer_findings_table(
        {
            "finding_disposition_buckets": {
                "confirmed_malicious_atomic": [{"id": "F100", "title": "Confirmed"}],
                "suspicious_needs_review": [{"id": "F101", "title": "Review"}],
                "inconclusive_unresolved": [{"id": "F102", "title": "Inconclusive"}],
                "benign_or_false_positive": [{"id": "F103", "title": "Benign"}],
                "synthesis_narrative": [{"id": "F104", "title": "Narrative"}],
            }
        }
    )

    assert "Confirmed malicious findings: 1" in text
    assert "Suspicious findings needing analyst review: 1" in text
    assert "Self-correction / inconclusive findings: 1" in text
    assert "False positives / benign findings: 1" in text
    assert "Narrative / context findings: 1" in text

    assert "Severity" not in text
    assert "Confidence" not in text
    assert "State:" not in text


def test_public_summary_counts_do_not_duplicate_v6_line():
    text = render_customer_findings_table(
        {
            "finding_disposition_buckets": {
                "confirmed_malicious_atomic": [],
                "suspicious_needs_review": [],
                "inconclusive_unresolved": [],
                "benign_or_false_positive": [],
                "synthesis_narrative": [],
            }
        }
    )

    assert text.count("Confirmed malicious findings:") == 1
    assert text.count("Suspicious findings needing analyst review:") == 1
