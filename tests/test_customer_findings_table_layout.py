from sift_sentinel.reporting.customer_findings_table import build_customer_findings_table


def _box_lines(text):
    return [
        line for line in text.splitlines()
        if line and line[0] in "╔╠╟╚║┌│└"
    ]


def test_customer_table_all_box_lines_have_consistent_width():
    long_token = "X" * 180
    buckets = {
        "confirmed_malicious_atomic": [
            {
                "finding_id": "FX001",
                "title": long_token,
                "artifact": long_token,
                "description": long_token,
                "source_tools": [long_token],
                "claims": [{"type": "artifact", "value": long_token}],
            }
        ],
        "benign_or_false_positive": [],
    }

    table = build_customer_findings_table(buckets, evidence_label="layout", run_date="test")
    lengths = {len(line) for line in _box_lines(table)}

    assert len(lengths) == 1


def test_customer_table_hard_wraps_unbroken_tokens_inside_cells():
    long_token = "Y" * 220
    table = build_customer_findings_table({
        "confirmed_malicious_atomic": [
            {
                "finding_id": "FX002",
                "title": "Long artifact",
                "artifact": long_token,
                "description": long_token,
                "source_tools": [long_token],
                "claims": [{"type": "artifact", "value": long_token}],
            }
        ]
    })

    assert long_token not in table
    assert len({len(line) for line in _box_lines(table)}) == 1


def test_customer_table_bottom_fp_band_uses_only_visible_fp_status():
    buckets = {
        "benign_or_false_positive": [
            {
                "finding_id": "F_VISIBLE",
                "title": "Visible false alarm",
                "fp_fidelity": {"status": "visible_fp_verified"},
                "react_conclusion": {"is_false_positive": True},
                "description": "AI cleared this.",
            },
            {
                "finding_id": "F_WITHHELD",
                "title": "Withheld false alarm",
                "fp_fidelity": {"status": "fp_withheld_needs_review"},
                "react_conclusion": {"is_false_positive": True},
                "description": "Review required.",
            },
        ]
    }

    table = build_customer_findings_table(buckets)
    bottom = table.split("FALSE ALARMS THE AI CAUGHT", 1)[1]

    assert "F_VISIBLE" in bottom
    assert "F_WITHHELD" not in bottom


def test_customer_table_has_no_score_or_routing_headers():
    table = build_customer_findings_table({
        "confirmed_malicious_atomic": [
            {"finding_id": "FX003", "title": "Neutral row", "description": "Details"}
        ]
    })

    header_area = table.split("╠", 1)[0]
    forbidden = ["Severity", "Confidence", "Disposition"]

    for word in forbidden:
        assert word not in header_area
