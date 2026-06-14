import json
import subprocess
import sys
from pathlib import Path


def test_health_only_evidencedb_family_uses_context_health_verdict(tmp_path):
    state = tmp_path / "state"
    state.mkdir()

    (state / "all_outputs.json").write_text(json.dumps({
        "vol_ssdt": [{"index": 1, "symbol": "NtCreateFile"}]
    }))

    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {
                "fact_id": "ssdt-1",
                "fact_type": "ssdt_integrity_fact",
                "source_tool": "vol_ssdt",
            }
        ]
    }))

    r = subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        capture_output=True,
    )

    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in r.stdout
    assert "PASS_CONTEXT_OR_HEALTH_DB_WIRED" in r.stdout
