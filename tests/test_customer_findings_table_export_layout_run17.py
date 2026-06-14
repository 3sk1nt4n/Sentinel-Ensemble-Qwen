from sift_sentinel.reporting.customer_findings_table import (
    print_customer_findings_table,
    render_customer_findings_table,
)


def _sample_buckets():
    return {
        "suspicious_needs_review": [
            {
                "id": "F001",
                "title": "Generic suspicious process relationship",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 1234,
                        "process": "generic.exe",
                        "status": "MATCH",
                        "source_tool": "vol_pstree",
                    }
                ],
                "source_tools": ["vol_pstree"],
                "severity": "CRITICAL_SHOULD_NOT_RENDER",
                "confidence": "HIGH_SHOULD_NOT_RENDER",
            }
        ],
        "inconclusive_unresolved": [
            {
                "id": "F003",
                "title": "Generic unsupported path hypothesis",
                "status": "dropped_honest",
                "claims": [],
            }
        ],
        "benign_or_false_positive": [
            {
                "id": "F002",
                "title": "Generic benign tool behavior",
                "claims": [
                    {
                        "type": "pid",
                        "pid": 5678,
                        "process": "benign.exe",
                        "status": "MATCH",
                        "source_tool": "vol_cmdline",
                    }
                ],
                "source_tools": ["vol_cmdline"],
            }
        ],
    }


def test_customer_table_exports_print_function():
    assert callable(print_customer_findings_table)


def test_customer_table_has_no_severity_or_confidence_columns():
    text = render_customer_findings_table(
        {"finding_disposition_buckets": _sample_buckets()}
    )
    assert "Severity" not in text
    assert "Confidence" not in text
    assert "CRITICAL_SHOULD_NOT_RENDER" not in text
    assert "HIGH_SHOULD_NOT_RENDER" not in text
    assert "Tools Hit" in text
    assert "IOCs / Artifacts" in text


def test_customer_table_orders_fp_at_bottom_after_sc():
    text = render_customer_findings_table(
        {"finding_disposition_buckets": _sample_buckets()}
    )
    assert text.index("F001") < text.index("F003") < text.index("F002")
    assert text.index("Self-Correction / Inconclusive") < text.index("Benign / False Positive")


def test_customer_table_print_function_prints_and_returns(capsys):
    returned = print_customer_findings_table(
        {"finding_disposition_buckets": _sample_buckets()}
    )
    printed = capsys.readouterr().out
    assert returned == printed
    assert "SIFT Sentinel Customer Findings" in printed
    assert "Severity" not in printed
    assert "Confidence" not in printed


def test_customer_table_safe_on_unexpected_input(capsys):
    returned = print_customer_findings_table(object())
    printed = capsys.readouterr().out
    assert returned == printed
    assert "SIFT Sentinel Customer Findings" in printed
    assert "Severity" not in printed
    assert "Confidence" not in printed
