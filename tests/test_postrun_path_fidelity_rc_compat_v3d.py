from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_postrun_path_fidelity_legacy_wrapper_returns_2_on_stale_mount(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(
        json.dumps({"evidence_path": "/mnt/windows_mount/Windows/System32"})
    )

    proc = subprocess.run(
        [sys.executable, "scripts/postrun_path_fidelity_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 2, proc.stdout
    assert "PATH_FIDELITY_GATE=FAIL" in proc.stdout


def test_postrun_path_fidelity_legacy_wrapper_returns_0_on_clean_state(tmp_path: Path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "all_outputs.json").write_text(
        json.dumps({"evidence_path": "/tmp/sift-isolated-mount-unit/ntfs/Windows"})
    )

    proc = subprocess.run(
        [sys.executable, "scripts/postrun_path_fidelity_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    assert "PATH_FIDELITY_GATE=PASS" in proc.stdout
