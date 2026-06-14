import json
import subprocess
import sys
from pathlib import Path


def run_gate(state: Path):
    return subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        capture_output=True,
    )


def test_validation_gate_reads_top_level_facts_list(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_cmdline": [{"pid": 1}]}))
    (state / "evidence_db.json").write_text(json.dumps({
        "facts": [
            {
                "fact_id": "fact-1",
                "fact_type": "process_cmdline_fact",
                "source_tool": "vol_cmdline",
                "pid": 1,
            }
        ]
    }))

    r = run_gate(state)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in r.stdout
    assert "process_cmdline_fact:1" in r.stdout


def test_validation_gate_reads_nested_by_tool_facts_without_source_tool(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_handles": [{"pid": 2}]}))
    (state / "evidence_db.json").write_text(json.dumps({
        "by_tool": {
            "vol_handles": [
                {
                    "fact_id": "h-1",
                    "fact_type": "handle_fact",
                    "pid": 2,
                },
                {
                    "fact_id": "u-1",
                    "fact_type": "user_account_fact",
                    "user": "bobby",
                },
            ]
        }
    }))

    r = run_gate(state)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in r.stdout
    assert "handle_fact:1" in r.stdout
    assert "user_account_fact:1" in r.stdout


def test_validation_gate_still_fails_unregistered_family_for_registered_tool(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_cmdline": [{"pid": 1}]}))
    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {
                "fact_id": "bad-1",
                "fact_type": "surprise_fact",
                "source_tool": "vol_cmdline",
            }
        ]
    }))

    r = run_gate(state)

    assert r.returncode == 1
    assert "FAIL_UNREGISTERED_FACT_FAMILY" in r.stdout
    assert "surprise_fact" in r.stdout


def test_validation_gate_fails_records_with_no_evidencedb_family(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_cmdline": [{"pid": 1}]}))
    (state / "evidence_db.json").write_text(json.dumps({}))

    r = run_gate(state)

    assert r.returncode == 1
    assert "FAIL_MISSING_EVIDENCEDB_FAMILY" in r.stdout
