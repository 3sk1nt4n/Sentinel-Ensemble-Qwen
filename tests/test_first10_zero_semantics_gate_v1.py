from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run_gate(state: Path, log: Path | None = None):
    cmd = [sys.executable, "scripts/check_first10_zero_semantics_gate.py", str(state)]
    if log:
        cmd.append(str(log))
    return subprocess.run(cmd, text=True, capture_output=True)


def test_gate_passes_not_applicable_zero_without_finding_ref(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_prefetch": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "parse_prefetch": {
            "status": "not_applicable",
            "reason": "Windows/Prefetch directory absent on mount",
        }
    }))
    log = tmp_path / "run.log"
    log.write_text("SELECTED: parse_prefetch\nCOLLECTED: parse_prefetch -- 0 records\n")
    r = run_gate(state, log)
    assert r.returncode == 0
    assert "FIRST10_ZERO_SEMANTICS_GATE=PASS" in r.stdout


def test_gate_fails_zero_without_reason(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_amcache": []}))
    log = tmp_path / "run.log"
    log.write_text("SELECTED: vol_amcache\nCOLLECTED: vol_amcache -- 0 records\n")
    r = run_gate(state, log)
    assert r.returncode == 1
    assert "zero records without zero-record reason" in r.stdout
    assert "FIRST10_ZERO_SEMANTICS_GATE=FAIL" in r.stdout


def test_gate_fails_no_image_path_zero(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_amcache": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "vol_amcache": {
            "status": "error",
            "reason": "Vol3 plugin error: vol_amcache: no image path provided (Vol3 requires -f <path>)",
        }
    }))
    r = run_gate(state)
    assert r.returncode == 1
    assert "hard-fail zero reason" in r.stdout


def test_gate_fails_zero_tool_referenced_by_finding(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_powershell_transcripts": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "parse_powershell_transcripts": {
            "status": "not_applicable",
            "reason": "No PowerShell transcript/history artifacts found under mounted filesystem",
        }
    }))
    (state / "findings_final.json").write_text(json.dumps({
        "findings": [
            {
                "title": "synthetic",
                "source_tools": ["parse_powershell_transcripts"],
            }
        ]
    }))
    r = run_gate(state)
    assert r.returncode == 1
    assert "zero/nonproducer tool referenced by findings" in r.stdout


def test_gate_fails_mft_window_zero_without_fallback(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"extract_mft_timeline": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "extract_mft_timeline": {
            "status": "ok_no_records",
            "reason": "MFT timeline window query returned no in-range entries",
        }
    }))
    log = tmp_path / "run.log"
    log.write_text("MFT timeline window query returned no in-range entries\n")
    r = run_gate(state, log)
    assert r.returncode == 1
    assert "MFT window false-zero" in r.stdout
