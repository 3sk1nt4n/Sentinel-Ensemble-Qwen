
"""Regression for compact live summary import compatibility.

Synthetic only. Dataset-agnostic. No case facts.
"""

from sift_sentinel.reporting.live_console import (
    print_compact_pipeline_summary,
    render_compact_findings_table,
)


def test_print_compact_pipeline_summary_alias_prints_table(capsys):
    findings = [
        {
            "finding_id": "F001",
            "title": "Synthetic validator-backed finding",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "claims": [{"type": "pid", "pid": 1234, "process": "demo.exe"}],
            "source_tools": ["vol_pstree"],
            "validation_status": "MATCH",
        }
    ]
    buckets = {"suspicious_needs_review": [{"finding_id": "F001"}]}

    table = print_compact_pipeline_summary(
        {"status": "completed"},
        findings_final=findings,
        disposition_buckets=buckets,
    )
    out = capsys.readouterr().out

    assert table in out
    assert "Findings#" in table
    assert "F001" in table
    assert "Synthetic validator-backed finding" in table
    assert "suspicious needs review" in table


def test_render_compact_findings_table_still_available():
    table = render_compact_findings_table([])
    assert "No findings to display" in table
