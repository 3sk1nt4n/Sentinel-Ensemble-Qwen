from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_state(state: Path) -> None:
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]}
    }))
    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": []
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {"id": "F001", "title": "Synthetic needs review", "source_tools": ["producer_tool"]}
        ],
        "inconclusive_unresolved": [
            {"id": "F002", "title": "Synthetic inconclusive"}
        ],
        "benign_or_false_positive": [
            {"id": "F003", "title": "Synthetic benign"}
        ],
        "synthesis_narrative": [],
    }))


def test_fresh_run_completion_gate_passes_and_writes_table(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "run.log"
    log.write_text("STEP 1: STARTING ANALYSIS\nSTEP 16: ANALYSIS COMPLETE in 1.0s\n")

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log), "--write-table"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    assert "FRESH_RUN_COMPLETION_GATE=PASS" in proc.stdout
    assert (state / "customer_findings_table.md").exists()
    text = (state / "customer_findings_table.md").read_text()
    assert "Sentinel Qwen Ensemble Customer Findings" in text
    assert "Severity" not in text
    assert "Confidence" not in text


def test_fresh_run_completion_gate_fails_without_step16(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "run.log"
    log.write_text("STEP 13C: REPORT TRUTH VALIDATION\n")

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout
    assert "FRESH_RUN_COMPLETION_GATE=FAIL" in proc.stdout
    assert "missing_STEP_16" in proc.stdout


def test_fresh_run_completion_gate_fails_on_none_state_crash(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "run.log"
    log.write_text(
        "STEP 13C: REPORT TRUTH VALIDATION\n"
        "TOOL_HIT_INTEGRITY_PRE_REPORT_GATE=FAIL\n"
        "TypeError: argument should be a str or an os.PathLike object where __fspath__ returns a str, not 'NoneType'\n"
    )

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout
    assert "FRESH_RUN_COMPLETION_GATE=FAIL" in proc.stdout
    assert "none_state_crash" in proc.stdout
    assert "pre_report_gate_fail" in proc.stdout
