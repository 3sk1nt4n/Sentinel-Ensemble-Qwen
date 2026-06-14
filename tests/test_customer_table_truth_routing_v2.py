import json
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table

def _write_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    findings = [
        {
            "id": "F003",
            "title": "Memory injection detected in FrameworkService",
            "claims": [{"type": "pid", "pid": 1472, "process": "FrameworkServi"}],
            "source_tools": ["vol_malfind", "vol_pstree", "get_amcache"],
        },
        {
            "id": "F013",
            "title": "Memory injection detected in FrameworkService",
            "claims": [{"type": "pid", "pid": 1472, "process": "FrameworkServi"}],
            "source_tools": ["vol_malfind", "vol_pstree"],
        },
        {
            "id": "F053",
            "title": "Summary: Multi-tactic attack pattern with memory injection",
            "claims": [{"type": "pid", "pid": 1472, "process": "FrameworkServi"}],
            "source_tools": ["vol_malfind", "get_amcache"],
            "kind": "synthesis_narrative",
        },
        {
            "id": "F054",
            "title": "Unexpected process ancestry: csrss.exe parented by spoolsv.exe",
            "claims": [
                {"type": "pid", "pid": 440, "process": "csrss.exe"},
                {"type": "pid", "pid": 432, "process": "spoolsv.exe"},
            ],
            "source_tools": ["vol_pstree"],
        },
        {
            "id": "F007",
            "title": "Unsupported temp executable path hypothesis",
            "claims": [],
            "source_tools": ["run_appcompatcacheparser", "get_amcache"],
        },
    ]
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": ["F003", "F054"],
        "inconclusive_unresolved": ["F007"],
        "benign_or_false_positive": ["F013"],
        "synthesis_narrative": ["F053"],
    }
    all_outputs = {
        "vol_malfind": {"status": "ok", "records": [{"x": 1}]},
        "vol_pstree": {"status": "ok", "records": [{"x": 1}]},
        "run_appcompatcacheparser": {"status": "ok", "records": [{"x": 1}]},
        "get_amcache": {"status": "not_applicable", "records": []},
    }
    (state / "findings_final.json").write_text(json.dumps(findings))
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))
    (state / "all_outputs.json").write_text(json.dumps(all_outputs))
    return state

def _section(text, name):
    start = text.index(f"## {name}")
    rest = text[start:]
    next_pos = rest.find("\n## ", 5)
    return rest if next_pos == -1 else rest[:next_pos]

def test_customer_table_no_severity_confidence_and_correct_order(tmp_path):
    state = _write_state(tmp_path)
    text = render_customer_findings_table(state_dir=str(state))

    assert "Severity" not in text
    assert "Confidence" not in text
    assert "## Actionable / Needs Review" in text
    assert "## Self-Correction / Inconclusive" in text
    assert "## Benign / False Positive" in text

    action = _section(text, "Actionable / Needs Review")
    inconclusive = _section(text, "Self-Correction / Inconclusive")
    fp = _section(text, "Benign / False Positive")

    assert "F054" in action
    assert "F003" not in action          # same PID as FP row
    assert "F053" not in action          # synthesis not actionable when no confirmed malicious atomic
    assert "F053" in inconclusive
    assert "F003" in inconclusive
    assert "F013" in fp

def test_customer_table_filters_zero_or_not_applicable_tools(tmp_path):
    state = _write_state(tmp_path)
    text = render_customer_findings_table(state_dir=str(state))
    assert "get_amcache" not in text
    assert "vol_malfind" in text
