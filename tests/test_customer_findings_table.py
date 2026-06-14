from sift_sentinel.reporting.customer_findings_table import build_customer_findings_table


def _finding(fid, title, status=None, react_fp=False):
    f = {
        "finding_id": fid,
        "title": title,
        "claims": [{"type": "pid", "pid": 1234, "process": "example.exe"}],
        "source_tools": ["vol_pstree"],
        "react_conclusion": {
            "is_false_positive": react_fp,
            "verdict": "confirmed_benign" if react_fp else "confirmed_malicious",
        },
    }
    if status:
        f["fp_fidelity"] = {
            "status": status,
            "visible_fp": status == "visible_fp_verified",
            "blockers": ["protected_windows_process_non_rfc1918_network"]
            if status == "fp_withheld_needs_review"
            else [],
        }
    return f


def test_customer_table_has_no_visible_severity_confidence_disposition_columns():
    buckets = {
        "confirmed_malicious_atomic": [_finding("F001", "Observed suspicious process")],
        "benign_or_false_positive": [
            _finding("F002", "False alarm cleared", "visible_fp_verified", True)
        ],
    }

    text = build_customer_findings_table(buckets)

    header_area = text.split("╠", 1)[0]
    assert "Severity" not in header_area
    assert "Confidence" not in header_area
    assert "Disposition" not in header_area

    assert "What AI Observed" in header_area
    assert "IOC / Artifacts" in header_area
    assert "Tools Hit" in header_area
    assert "Details Explain" in header_area


def test_bottom_fp_section_uses_fp_fidelity_not_raw_react_fp():
    buckets = {
        "benign_or_false_positive": [
            _finding("F002", "Visible clear", "visible_fp_verified", True),
        ],
        "suspicious_needs_review": [
            _finding("F003", "Withheld clear", "fp_withheld_needs_review", True),
        ],
    }

    text = build_customer_findings_table(buckets)
    bottom = text.split("FALSE ALARMS THE AI CAUGHT", 1)[1]

    assert "F002" in bottom
    assert "F003" not in bottom


def test_withheld_fp_is_still_in_main_table_but_not_bottom_fp_list():
    buckets = {
        "suspicious_needs_review": [
            _finding("F003", "Withheld clear", "fp_withheld_needs_review", True),
        ],
    }

    text = build_customer_findings_table(buckets)

    assert "F003" in text
    assert "Needs analyst review" in text

    bottom = text.split("FALSE ALARMS THE AI CAUGHT", 1)[1]
    assert "F003" not in bottom


def test_self_correction_badge_in_details_only():
    f = _finding("F004", "Corrected finding")
    f["self_correction"] = {"applied": True, "status": "corrected"}

    buckets = {"confirmed_malicious_atomic": [f]}
    text = build_customer_findings_table(buckets)

    assert "AI self-correction" in text
    assert "Severity" not in text.split("╠", 1)[0]
