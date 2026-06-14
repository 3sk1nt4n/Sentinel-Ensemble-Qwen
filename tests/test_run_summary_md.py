"""Markdown run-summary report -- universal, no case values."""
from sift_sentinel.reporting.run_summary_md import render_run_summary_md


def _summary():
    return {
        "status": "completed", "elapsed_s": 408, "tools_count": 33,
        "tool_record_counts": {"vol_malfind": 8, "vol_ssdt": 3, "get_amcache": 40},
        "contributing_tools": ["vol_malfind", "get_amcache"],
        "tool_health": {"failed": 0},
        "token_usage": {"total_input": 1027570, "total_output": 66166},
        "react_stats": {"calls": 57, "distinct": 8, "new": ["vol_x"], "findings": 16},
        "sc_unresolved_holdout": [{"finding_id": "F1"}, {"finding_id": "F2"}],
    }


def _buckets():
    return {
        "confirmed_malicious_atomic": [{"finding_id": "F1"}] * 5,
        "suspicious_needs_review": [{"finding_id": "F2"}] * 4,
        "inconclusive_unresolved": [{"finding_id": "F3"}] * 3,
        "benign_or_false_positive": [{"finding_id": "F4"}] * 6,
    }


def test_renders_all_run_details():
    md = render_run_summary_md(
        _summary(), _buckets(), image_path="/evidence/base-rd01/mem.img",
        disk_path="/mnt/disk", state_dir="/tmp/run-1", report_path="/tmp/run-1/report.md",
        return_code=1)
    for must in ("Run Summary", "Confirmed malicious", "| 5 |", "ReAct AI-Cross-Check",
                 "57", "Tokens in", "1,027,570", "Est. cost", "Artifacts",
                 "/tmp/run-1/report.md", "Return code", "memory + disk"):
        assert must in md, must


def test_data_only_listed():
    md = render_run_summary_md(_summary(), _buckets())
    # vol_ssdt produced 3 records but is not in contributing_tools -> data-only
    assert "vol_ssdt" in md and "Data-only" in md


def test_total_observations_sums_buckets_plus_holdout():
    md = render_run_summary_md(_summary(), _buckets())
    # 5+4+3+6 buckets + 2 holdout = 20
    assert "**20**" in md


def test_never_raises_on_empty():
    md = render_run_summary_md({}, {})
    assert "Run Summary" in md  # still produces a document
