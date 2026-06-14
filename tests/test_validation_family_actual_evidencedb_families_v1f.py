import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry


def run_gate(state: Path):
    return subprocess.run(
        [sys.executable, "scripts/check_validation_family_wiring_gate.py", str(state)],
        text=True,
        capture_output=True,
    )


def test_registry_registers_actual_evidencedb_fact_families():
    reg = get_validation_family_registry()

    for family in [
        "memory_injection_fact",
        "network_connection_fact",
        "process_relationship_fact",
        "user_account_fact",
    ]:
        assert family in reg
        spec = reg[family]
        assert spec["family"] == family
        assert spec["fact_type"] == family
        assert spec["producer_tools"]
        assert spec["candidate_policy"]
        assert spec["validator_policy"]
        assert spec["claim_types"]
        assert spec["required_fields_any"]


def test_gate_accepts_actual_families_from_acme_style_memory_tools(tmp_path):
    state = tmp_path / "state"
    state.mkdir()

    (state / "all_outputs.json").write_text(json.dumps({
        "vol_malfind": [{"pid": 1}],
        "vol_netscan": [{"pid": 1}],
        "vol_pstree": [{"pid": 1, "ppid": 0}],
        "vol_psscan": [{"pid": 1, "ppid": 0}],
    }))

    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {"fact_id": "mi-1", "fact_type": "memory_injection_fact", "source_tool": "vol_malfind"},
            {"fact_id": "nc-1", "fact_type": "network_connection_fact", "source_tool": "vol_netscan"},
            {"fact_id": "pf-1", "fact_type": "process_fact", "source_tool": "vol_pstree"},
            {"fact_id": "pr-1", "fact_type": "process_relationship_fact", "source_tool": "vol_pstree"},
            {"fact_id": "pf-2", "fact_type": "process_fact", "source_tool": "vol_psscan"},
            {"fact_id": "pr-2", "fact_type": "process_relationship_fact", "source_tool": "vol_psscan"},
        ]
    }))

    r = run_gate(state)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VALIDATION_FAMILY_WIRING_GATE=PASS" in r.stdout
    assert "FAIL_UNREGISTERED_FACT_FAMILY" not in r.stdout


def test_gate_still_fails_strict_producer_without_evidencedb_family(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_malfind": [{"pid": 1}]}))
    (state / "evidence_db.json").write_text(json.dumps({"typed_facts": []}))

    r = run_gate(state)
    assert r.returncode == 1
    assert "FAIL_MISSING_EVIDENCEDB_FAMILY" in r.stdout
