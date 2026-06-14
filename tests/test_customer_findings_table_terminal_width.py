from sift_sentinel.reporting.customer_findings_table import build_customer_findings_table


def test_customer_table_is_closed_box_and_terminal_safe():
    buckets = {
        "confirmed_malicious_atomic": [
            {
                "finding_id": "F_VISIBLE",
                "title": (
                    "Very long customer-facing finding title that must wrap "
                    "inside the table and never spill beyond the border"
                ),
                "artifact": (
                    r"C:\Very\Long\Path\That\Should\Wrap\Inside\The\Cell\artifact.exe "
                    "hash:abcdef0123456789abcdef0123456789abcdef01"
                ),
                "source_tools": [
                    "vol_malfind",
                    "vol_netscan",
                    "run_appcompatcacheparser",
                    "get_amcache",
                ],
                "description": (
                    "This is a deliberately long explanation written for a junior analyst "
                    "and a customer. It must wrap cleanly and keep every row boxed."
                ),
                "claims": [
                    {"type": "pid", "pid": 1234, "process": "example.exe"},
                    {"type": "connection", "pid": 1234, "foreign_addr": "203.0.113.7"},
                ],
            }
        ],
        "benign_or_false_positive": [
            {
                "finding_id": "F_FP_OK",
                "title": "A false alarm the AI correctly cleared",
                "fp_fidelity": {"status": "visible_fp_verified"},
                "react_conclusion": {"is_false_positive": True},
                "description": "The AI investigated and cleared this without exposing score columns.",
                "source_tools": ["vol_netscan"],
            }
        ],
    }

    table = build_customer_findings_table(buckets)
    lines = [line for line in table.splitlines() if line]

    widths = {len(line) for line in lines}
    assert len(widths) == 1, sorted(widths)
    assert max(widths) <= 120

    assert "Severity" not in table
    assert "Confidence" not in table
    assert "Disposition" not in table
    assert "FALSE ALARMS THE AI CAUGHT" in table
    assert "F_FP_OK" in table
