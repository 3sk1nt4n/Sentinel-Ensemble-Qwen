import json
import subprocess
import sys


def test_mft_gate_fails_resolver_not_applicable(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"extract_mft_timeline": []}))
    (state / "zero_record_reasons.json").write_text(json.dumps({
        "extract_mft_timeline": {
            "status": "not_applicable",
            "reason": "no compatible resolver arguments for current tool signature",
        }
    }))
    r = subprocess.run(
        [sys.executable, "scripts/check_mft_window_fallback_gate.py", str(state)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "resolver/signature bug" in r.stdout
