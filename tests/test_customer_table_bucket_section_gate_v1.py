import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    write_customer_findings_table,
)


def _finding(fid, title, tools=None, claims=None):
    return {
        "finding_id": fid,
        "title": title,
        "source_tools": tools or [],
        "claims": claims or [],
    }


def test_bucket_faithful_table_has_exact_sections_and_no_confidence_severity(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    buckets = {
        "confirmed_malicious_atomic": [
            _finding("F001", "confirmed", ["vol_malfind"], [{"type": "pid", "pid": 1, "process": "a.exe"}])
        ],
        "suspicious_needs_review": [
            _finding("F002", "review", ["vol_pstree"], [{"type": "child_process", "pid": 2}])
        ],
        "inconclusive_unresolved": [
            _finding("F003", "inconclusive", ["vol_netscan"], [{"type": "pid", "pid": 3}])
        ],
        "synthesis_narrative": [
            _finding("F004", "context", ["vol_cmdline"], [{"type": "raw"}])
        ],
        "benign_or_false_positive": [
            _finding("F005", "benign", ["vol_cmdline"], [{"type": "pid", "pid": 5}])
        ],
    }
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))
    table = write_customer_findings_table(state).read_text()

    assert "Confidence" not in table
    assert "Severity" not in table
    assert "| 1 | F001 |" in table
    assert "| 2 | F002 |" in table
    assert "| 3 | F003 |" in table
    assert "| 4 | F004 |" in table
    assert "| 5 | F005 |" in table

    r = subprocess.run(
        [sys.executable, "scripts/check_customer_table_bucket_section_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CUSTOMER_TABLE_BUCKET_SECTION_GATE=PASS" in r.stdout


def test_bucket_section_gate_fails_when_row_in_wrong_section(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    buckets = {
        "suspicious_needs_review": [_finding("F039", "review", ["vol_malfind"])],
        "inconclusive_unresolved": [],
        "benign_or_false_positive": [],
    }
    (state / "finding_disposition_buckets.json").write_text(json.dumps(buckets))
    (state / "customer_findings_table.md").write_text(
        """Sentinel Qwen Ensemble Customer Findings

## Actionable / Needs Review
| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |
|---:|---|---|---|---|---|
| - | - | No items | - | - | - |

## Self-Correction / Inconclusive
| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |
|---:|---|---|---|---|---|
| 1 | F039 | wrong section | - | vol_malfind | INCONCLUSIVE |

## Narrative / Context
| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |
|---:|---|---|---|---|---|
| - | - | No items | - | - | - |

## Benign / False Positive
| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |
|---:|---|---|---|---|---|
| - | - | No items | - | - | - |
"""
    )
    r = subprocess.run(
        [sys.executable, "scripts/check_customer_table_bucket_section_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "missing ids ['F039']" in r.stdout
