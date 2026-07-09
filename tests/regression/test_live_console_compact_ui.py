from sift_sentinel.reporting.live_console import render_compact_findings_table


def _sample_findings():
    return [
        {
            "finding_id": "F001",
            "title": "Synthetic suspicious execution chain",
            "severity": "HIGH",
            "confidence_level": "MEDIUM",
            "claims": [{"type": "pid"}, {"type": "hash"}],
            "source_tools": ["vol_pstree", "get_amcache"],
            "validator_fact_refs": [{"fact_type": "process_fact"}, {"fact_type": "file_execution_fact"}],
            "evidence_type": "memory+disk",
            "validation_status": "MATCH",
        },
        {
            "finding_id": "F002",
            "artifact": "Synthetic benign false positive",
            "severity": "LOW",
            "confidence_level": "LOW",
            "claims": [{"type": "pid"}],
            "source_tools": ["vol_netscan"],
            "validator_fact_refs": [{"fact_type": "network_connection_fact"}],
            "validation_status": "MATCH",
        },
    ]


def test_compact_table_has_numeric_left_column_and_requested_columns():
    rendered = render_compact_findings_table(_sample_findings(), max_rows=2)

    assert "│ # " in rendered
    assert "│ 1 " in rendered
    assert "│ 2 " in rendered
    assert "Findings#" in rendered
    assert "Findings Name" in rendered
    assert "Severity" in rendered
    assert "Confidence" in rendered
    assert "Details" in rendered
    assert "Tools Hit" in rendered


def test_compact_table_does_not_render_verbose_live_report_sections():
    rendered = render_compact_findings_table(_sample_findings(), max_rows=2)

    forbidden_visible_blocks = [
        "SENTINEL QWEN ENSEMBLE -- Autonomous DFIR Agent",
        "Pipeline Execution Report",
        "SUBMISSION SUMMARY",
        "ZEROFAKE PROTOCOL",
        "DETAILED ANALYSIS REPORT",
        "STEP-BY-STEP WALKTHROUGH",
        "WHAT THIS MEANS",
        "API COST BREAKDOWN",
    ]
    for marker in forbidden_visible_blocks:
        assert marker not in rendered


def test_compact_table_details_explain_severity_confidence_inputs():
    rendered = render_compact_findings_table(
        _sample_findings(),
        disposition_buckets={
            "confirmed_malicious_atomic": [_sample_findings()[0]],
            "benign_or_false_positive": [_sample_findings()[1]],
        },
        max_rows=2,
    )

    normalized = " ".join(rendered.split())

    assert "routed=confirmed malicious atomic" in normalized
    # The table renderer wraps Details across visual rows, so words may be
    # separated by box-drawing borders. Assert the semantic pieces instead.
    assert "2 validated" in normalized
    assert "claims" in normalized
    assert "2 tools" in normalized
    assert "2 typed refs" in normalized
    assert "validation=MATCH" in normalized
    assert "vol_pstree, get_amcache" in normalized


def test_compact_table_compatibility_kwargs():
    rendered = render_compact_findings_table(findings_final=_sample_findings(), rows=1)

    assert "│ 1 " in rendered
    assert "F001" in rendered
    assert "F002" not in rendered
