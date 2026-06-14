from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_gate_fails_on_no_image_path_log(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({}))
    log = tmp_path / "run.log"
    log.write_text("vol_amcache: no image path provided (Vol3 requires -f <path>)")
    r = subprocess.run(
        [sys.executable, "scripts/check_volatility_arg_contract_gate.py", str(state), str(log)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 1
    assert "VOLATILITY_ARG_CONTRACT_GATE=FAIL" in r.stdout


def test_gate_passes_clean_state_and_log(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(json.dumps({"vol_pstree": [{"PID": 4}]}))
    log = tmp_path / "run.log"
    log.write_text("LIVE VOL: Running vol_pstree (windows.pstree.PsTree) on /tmp/memory.img")
    r = subprocess.run(
        [sys.executable, "scripts/check_volatility_arg_contract_gate.py", str(state), str(log)],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0
    assert "VOLATILITY_ARG_CONTRACT_GATE=PASS" in r.stdout
