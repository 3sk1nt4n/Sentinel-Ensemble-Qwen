import json
import subprocess
import sys
from pathlib import Path


def _write_state(tmp_path: Path, missing_db_for: str | None = None) -> Path:
    state = tmp_path / "state"
    tool_outputs = state / "tool_outputs"
    tool_outputs.mkdir(parents=True)

    tools = {
        "decode_base64_strings": "decoded_string_fact",
        "extract_network_iocs": "network_ioc_fact",
        "parse_event_logs": "event_log_fact",
        "parse_scheduled_tasks_disk": "scheduled_task_fact",
        "parse_wmi_subscription": "wmi_subscription_fact",
        "run_jlecmd": "jumplist_fact",
        "run_lecmd": "lnk_execution_fact",
        "vol_cmdline": "process_cmdline_fact",
        "vol_dlllist": "dll_load_fact",
        "vol_filescan": "filesystem_listing_fact",
        "vol_getsids": "sid_fact",
        "vol_handles": "handle_fact",
        "vol_privileges": "privilege_fact",
        "vol_reg_hivelist": "registry_hive_fact",
        "vol_sessions": "session_fact",
        "vol_ssdt": "ssdt_integrity_fact",
        "vol_svcscan": "service_fact",
    }

    all_outputs = {}
    facts = []
    for tool, family in tools.items():
        all_outputs[tool] = {"status": "ok", "records": [{"id": tool}]}
        (tool_outputs / f"{tool}.json").write_text(json.dumps(all_outputs[tool]))
        if tool != missing_db_for:
            facts.append({"tool": tool, "fact_type": family, "value": tool})

    (state / "all_outputs.json").write_text(json.dumps(all_outputs))
    (state / "evidence_db.json").write_text(json.dumps({"facts": facts}))
    (state / "finding_disposition_buckets.json").write_text(json.dumps({}))
    return state


def test_validation_family_wiring_gate_passes_synthetic_full_state(tmp_path):
    state = _write_state(tmp_path)
    proc = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in proc.stdout
    assert "PASS_CONTEXT_OR_HEALTH_DB_WIRED" in proc.stdout
    assert "PASS_VALIDATION_FAMILY_WIRED" in proc.stdout


def test_validation_family_wiring_gate_fails_missing_evidence_db_fact(tmp_path):
    state = _write_state(tmp_path, missing_db_for="run_lecmd")
    proc = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.returncode != 0
    assert "VALIDATION_FAMILY_WIRING_GATE=FAIL" in proc.stdout
    assert "run_lecmd" in proc.stdout
