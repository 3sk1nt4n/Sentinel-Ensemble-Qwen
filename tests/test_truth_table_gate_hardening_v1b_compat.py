import json
import subprocess
import sys


def test_user_account_fact_complete_shape():
    from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry

    spec = get_validation_family_registry()["user_account_fact"]
    assert spec["family"] == "user_account_fact"
    assert spec["fact_type"] == "user_account_fact"
    assert spec["producer_tools"]
    assert spec["candidate_policy"]
    assert spec["validator_notes"]
    assert "context_only" in spec["roles"]


def test_first10_legacy_message_compat_for_hard_fail(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_amcache": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "vol_amcache": {
            "status": "error",
            "reason": "Vol3 plugin error: vol_amcache: no image path provided (Vol3 requires -f <path>)",
        }
    }))

    r = subprocess.run(
        [sys.executable, "scripts/check_first10_zero_semantics_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "hard-fail zero reason" in r.stdout


def test_first10_pass_db_producer_marker(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"parse_event_logs": []}))
    (state / "evidence_db.json").write_text(json.dumps({
        "typed_facts": [
            {"fact_type": "event_log_fact", "source_tool": "parse_event_logs"}
        ]
    }))

    r = subprocess.run(
        [sys.executable, "scripts/check_first10_zero_semantics_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0
    assert "PASS_DB_PRODUCER" in r.stdout
