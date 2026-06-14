from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_mft_window_gate_passes_source_only():
    r = subprocess.run(
        [sys.executable, "scripts/check_mft_window_fallback_gate.py"],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0
    assert "MFT_WINDOW_FALLBACK_GATE=PASS" in r.stdout


def test_mft_window_gate_fails_old_window_zero_log(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"extract_mft_timeline": []}))
    log = tmp_path / "run.log"
    log.write_text("MFT timeline window query returned no in-range entries")
    r = subprocess.run(
        [sys.executable, "scripts/check_mft_window_fallback_gate.py", str(state), str(log)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "MFT_WINDOW_FALLBACK_GATE=FAIL" in r.stdout
