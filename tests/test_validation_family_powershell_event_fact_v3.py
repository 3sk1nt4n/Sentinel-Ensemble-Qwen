from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

def _write_state(path: Path, *, include_extra_family: bool = False) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "tool_outputs").mkdir(exist_ok=True)

    (path / "all_outputs.json").write_text(json.dumps({
        "parse_event_logs": {
            "status": "ok",
            "records": [{"event_id": 1}, {"event_id": 2}],
        },
    }))

    facts = [
        {
            "fact_id": "event_log_fact-1",
            "fact_type": "event_log_fact",
            "source_tool": "parse_event_logs",
            "raw_excerpt": "{}",
        },
        {
            "fact_id": "powershell_command_fact-1",
            "fact_type": "powershell_command_fact",
            "source_tool": "parse_event_logs",
            "raw_excerpt": "{}",
        },
    ]

    if include_extra_family:
        facts.append({
            "fact_id": "unexpected_fact-1",
            "fact_type": "unexpected_fact",
            "source_tool": "parse_event_logs",
            "raw_excerpt": "{}",
        })

    (path / "evidence_db.json").write_text(json.dumps({
        "version": 1,
        "typed_facts": facts,
    }))

    return path

def test_parse_event_logs_powershell_command_fact_is_registered(tmp_path: Path):
    state = _write_state(tmp_path / "state")
    proc = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in proc.stdout
    assert "powershell_command_fact" in proc.stdout
    assert "FAIL_UNREGISTERED_FACT_FAMILY" not in proc.stdout

def test_unregistered_family_still_fails(tmp_path: Path):
    state = _write_state(tmp_path / "state", include_extra_family=True)
    proc = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert proc.returncode == 1
    assert "VALIDATION_FAMILY_WIRING_GATE=FAIL" in proc.stdout
    assert "unexpected_fact" in proc.stdout
