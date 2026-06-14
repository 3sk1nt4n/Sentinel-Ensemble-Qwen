from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _write_state(state: Path) -> None:
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]}
    }))
    (state / "evidence_db.json").write_text(json.dumps({"typed_facts": []}))
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


def test_gate_does_not_write_customer_table_for_incomplete_state(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    log = tmp_path / "run.log"
    log.write_text(f"state={state}\nSTEP 16: ANALYSIS COMPLETE in 1.0s\n")

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log), "--write-table"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout
    assert "FRESH_RUN_COMPLETION_GATE=FAIL" in proc.stdout
    assert "missing_state_files" in proc.stdout
    assert "customer_table_not_written_incomplete_state" in proc.stdout
    assert not (state / "customer_findings_table.md").exists()


def test_gate_writes_customer_table_only_for_complete_state(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "run.log"
    log.write_text(f"state={state}\nSTEP 16: ANALYSIS COMPLETE in 1.0s\n")

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


def test_gate_flags_far_state_log_mismatch(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "old_run.log"
    log.write_text("STEP 16: ANALYSIS COMPLETE in 1.0s\n")

    old = 1_700_000_000
    os.utime(log, (old, old))

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env={**os.environ, "SIFT_STATE_LOG_MAX_AGE_DELTA_S": "1"},
    )

    assert proc.returncode == 1, proc.stdout
    assert "state_log_mismatch" in proc.stdout


def test_gate_fails_wrong_os_plugin_even_if_step16_present(tmp_path: Path):
    state = tmp_path / "state"
    _write_state(state)
    log = tmp_path / "run.log"
    log.write_text(
        f"state={state}\n"
        "STEP 16: ANALYSIS COMPLETE in 1.0s\n"
        "LIVE VOL: Running vol_pslist (linux.pslist.PsList) on sample-memory.img\n"
    )

    proc = subprocess.run(
        [sys.executable, "scripts/check_fresh_run_completion_gate.py", str(state), str(log)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout
    assert "wrong_os_volatility_plugin" in proc.stdout
