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


def test_structured_zero_reason_metadata_keys_are_not_tools(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_prefetch": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "schema_version": 2,
        "gate": "PASS",
        "selected_count": 1,
        "output_source": {"source": "all_outputs"},
        "missing_reason_tools": [],
        "zero_record_tools": [
            {
                "tool": "parse_prefetch",
                "record_count": 0,
                "status": "not_applicable",
                "reason": "Windows/Prefetch directory absent on mount",
            }
        ],
    }))
    r = run_gate(state)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "`gate`" not in r.stdout
    assert "`schema_version`" not in r.stdout
    assert "`zero_record_tools`" not in r.stdout
    assert "FIRST10_ZERO_SEMANTICS_GATE=PASS" in r.stdout


def test_raw_inv2_zero_tool_ref_is_warning_not_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_powershell_transcripts": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "zero_record_tools": [
            {
                "tool": "parse_powershell_transcripts",
                "record_count": 0,
                "status": "not_applicable",
                "reason": "No PowerShell transcript/history artifacts found under mounted filesystem",
            }
        ]
    }))
    (state / "inv2_response.json").write_text(json.dumps({
        "findings": [{"source_tools": ["parse_powershell_transcripts"]}]
    }))
    r = run_gate(state)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "raw Inv2 draft refs" in r.stdout
    assert "FIRST10_ZERO_SEMANTICS_GATE=PASS" in r.stdout


def test_final_zero_tool_ref_is_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_powershell_transcripts": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "zero_record_tools": [
            {
                "tool": "parse_powershell_transcripts",
                "record_count": 0,
                "status": "not_applicable",
                "reason": "No PowerShell transcript/history artifacts found under mounted filesystem",
            }
        ]
    }))
    (state / "findings_final.json").write_text(json.dumps({
        "findings": [{"source_tools": ["parse_powershell_transcripts"]}]
    }))
    r = run_gate(state)
    assert r.returncode == 1
    assert "referenced by final/public findings" in r.stdout


def test_no_image_path_zero_is_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_amcache": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "zero_record_tools": [
            {
                "tool": "vol_amcache",
                "record_count": 0,
                "status": "error",
                "reason": "Vol3 plugin error: vol_amcache: no image path provided (Vol3 requires -f <path>)",
            }
        ]
    }))
    r = run_gate(state)
    assert r.returncode == 1
    assert "hard-fail zero reason" in r.stdout


def test_mft_window_zero_without_fallback_is_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"extract_mft_timeline": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "zero_record_tools": [
            {
                "tool": "extract_mft_timeline",
                "record_count": 0,
                "status": "ok_no_records",
                "reason": "MFT timeline window query returned no in-range entries",
            }
        ]
    }))
    log = tmp_path / "run.log"
    log.write_text("MFT timeline window query returned no in-range entries\n")
    r = run_gate(state, log)
    assert r.returncode == 1
    assert "MFT window false-zero" in r.stdout


def test_mft_window_zero_with_fallback_marker_can_pass(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"extract_mft_timeline": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "zero_record_tools": [
            {
                "tool": "extract_mft_timeline",
                "record_count": 0,
                "status": "ok_no_records",
                "reason": "MFT window fallback returned 0 records after whole-volume fallback",
            }
        ]
    }))
    log = tmp_path / "run.log"
    log.write_text(
        "MFT timeline window query returned no in-range entries\n"
        "MFT_WINDOW_FALLBACK_APPLIED primary_records=0 fallback_records=0\n"
    )
    r = run_gate(state, log)
    assert r.returncode == 0, r.stdout + r.stderr


def test_db_producer_with_zero_shallow_records_passes(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_event_logs": []}))
    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {"fact_type": "event_log_fact", "source_tool": "parse_event_logs"}
        ]
    }))
    r = run_gate(state)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS_DB_PRODUCER" in r.stdout
