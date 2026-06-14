from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def test_customer_table_public_output_has_no_internal_state_or_legacy_columns():
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {
                "id": "F001",
                "title": "Generic review finding",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 100,
                        "process": "generic.exe",
                        "status": "MATCH",
                        "source_tool": "vol_pstree",
                    }
                ],
                "source_tools": ["vol_pstree"],
            }
        ],
        "benign_or_false_positive": [
            {
                "id": "F002",
                "title": "Generic benign finding",
                "react_verdict": "confirmed_benign",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 200,
                        "process": "benign.exe",
                        "status": "MATCH",
                        "source_tool": "vol_cmdline",
                    }
                ],
                "source_tools": ["vol_cmdline"],
            }
        ],
    }

    text = render_customer_findings_table(
        {"finding_disposition_buckets": buckets, "state": "/tmp/internal-state"}
    )

    assert "State:" not in text
    assert "Severity" not in text
    assert "Confidence" not in text
    assert "## Actionable / Needs Review" in text
    assert "## Benign / False Positive" in text
    assert text.index("## Actionable / Needs Review") < text.index("## Benign / False Positive")
