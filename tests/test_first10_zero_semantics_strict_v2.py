import json
import subprocess
import sys
from pathlib import Path


def test_first10_gate_fails_selected_parse_event_logs_error(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_event_logs": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "parse_event_logs": {"status": "error", "reason": "Connection closed"}
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({}))
    (state / "evidence_db.json").write_text(json.dumps({}))
    log = tmp_path / "run.log"
    log.write_text("SELECTED: parse_event_logs\nCOLLECTED: parse_event_logs -- 0 records\n")

    r = subprocess.run(
        [sys.executable, "scripts/check_first10_zero_semantics_gate.py", str(state), str(log)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "parse_event_logs: hard-error zero reason" in r.stdout
    assert "FIRST10_ZERO_SEMANTICS_GATE=FAIL" in r.stdout


def test_first10_gate_fails_zero_tool_final_reference(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_rdp_artifacts": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "parse_rdp_artifacts": {"status": "not_applicable", "reason": "No RDP artifacts"}
    }))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({
        "suspicious_needs_review": [{
            "finding_id": "F001",
            "source_tools": ["parse_rdp_artifacts"],
            "claims": [],
        }]
    }))
    (state / "evidence_db.json").write_text(json.dumps({}))

    r = subprocess.run(
        [sys.executable, "scripts/check_first10_zero_semantics_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "zero/nonproducer tool referenced by findings" in r.stdout
