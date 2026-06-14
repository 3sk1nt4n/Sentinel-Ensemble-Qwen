import json
import subprocess
import sys
from pathlib import Path


def test_validation_family_gate_allows_registered_user_account_context_family(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({
        "vol_cmdline": [{"pid": 1, "process": "x.exe"}],
        "vol_handles": [{"pid": 1, "handle": "Token"}],
    }))
    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {"fact_type": "process_cmdline_fact", "source_tool": "vol_cmdline"},
            {"fact_type": "user_account_fact", "source_tool": "vol_cmdline", "user": "alice"},
            {"fact_type": "handle_fact", "source_tool": "vol_handles"},
            {"fact_type": "user_account_fact", "source_tool": "vol_handles", "user": "alice"},
        ]
    }))

    r = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in r.stdout
    assert "FAIL_UNREGISTERED_FACT_FAMILY" not in r.stdout
    assert "user_account_fact" in r.stdout
