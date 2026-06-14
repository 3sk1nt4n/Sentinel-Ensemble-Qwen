import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    build_bucket_faithful_customer_findings_table,
)


def _f(fid, title):
    return {
        "finding_id": fid,
        "title": title,
        "source_tools": ["vol_pstree"],
        "claims": [{"type": "process_exists", "pid": 123, "process": "x.exe"}],
    }


def test_bucket_faithful_table_keeps_suspicious_in_actionable_section():
    buckets = {
        "confirmed_malicious_atomic": [_f("F001", "confirmed")],
        "suspicious_needs_review": [_f("F039", "needs review")],
        "inconclusive_unresolved": [_f("F002", "inconclusive")],
        "benign_or_false_positive": [_f("F005", "benign")],
    }

    text = build_bucket_faithful_customer_findings_table(buckets)

    actionable = text.split("## Actionable / Needs Review", 1)[1].split("## Self-Correction / Inconclusive", 1)[0]
    inconclusive = text.split("## Self-Correction / Inconclusive", 1)[1].split("## Narrative / Context", 1)[0]
    benign = text.split("## Benign / False Positive", 1)[1]

    assert "F039" in actionable
    assert "F039" not in inconclusive
    assert "F005" in benign
    assert "Confidence" not in text
    assert "Severity" not in text


def test_customer_table_bucket_section_gate_repair_rewrites_stale_table(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    buckets = {
        "suspicious_needs_review": [_f("F039", "needs review")],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
        "confirmed_malicious_atomic": [],
    }
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))
    (state / "customer_findings_table.md").write_text(
        "SIFT Sentinel Customer Findings\n\n"
        "## Actionable / Needs Review\n"
        "| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |\n"
        "|---:|---|---|---|---|---|\n"
        "| — | — | No items | — | — | — |\n\n"
        "## Self-Correction / Inconclusive\n"
        "| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |\n"
        "|---:|---|---|---|---|---|\n"
        "| 1 | F039 | needs review | - | vol_pstree | INCONCLUSIVE |\n"
    )

    r = subprocess.run(
        [sys.executable, "scripts/check_customer_table_bucket_section_gate.py", str(state), "--repair"],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CUSTOMER_TABLE_BUCKET_SECTION_GATE=PASS" in r.stdout
    text = (state / "customer_findings_table.md").read_text()
    actionable = text.split("## Actionable / Needs Review", 1)[1].split("## Self-Correction / Inconclusive", 1)[0]
    assert "F039" in actionable
