from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def test_explicit_buckets_win_over_latest_tmp_state():
    buckets = {
        "confirmed_malicious_atomic": [
            {"id": "T001", "title": "Explicit actionable", "claims": [{"type": "pid", "pid": 1, "process": "a.exe"}]}
        ],
        "suspicious_needs_review": [
            {"id": "T002", "title": "Explicit benign", "react_verdict": "confirmed_benign", "claims": [{"type": "pid", "pid": 2, "process": "b.exe"}]}
        ],
        "inconclusive_unresolved": [
            {"id": "T003", "title": "Explicit SC", "self_correction_status": "dropped_honest", "claims": [{"type": "pid", "pid": 3, "process": "c.exe"}]}
        ],
        "synthesis_narrative": [
            {"id": "T004", "title": "Summary: explicit narrative", "claims": [{"type": "raw"}]}
        ],
        "benign_or_false_positive": [],
    }

    text = render_customer_findings_table({"finding_disposition_buckets": buckets})

    assert "T001" in text
    assert "T002" in text
    assert "T003" in text
    assert "T004" in text
    assert "Severity" not in text
    assert "Confidence" not in text
    assert "State:" not in text

    assert text.index("## Actionable / Needs Review") < text.index("T001")
    assert text.index("## Self-Correction / Inconclusive") < text.index("T003")
    assert text.index("## Narrative / Context") < text.index("T004")
    assert text.index("## Benign / False Positive") < text.index("T002")
    assert text.index("T001") < text.index("T003") < text.index("T004") < text.index("T002")
