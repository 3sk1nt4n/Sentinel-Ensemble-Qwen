from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _stale() -> str:
    return "/" + "mnt" + "/" + "windows_mount"


def test_postrun_path_fidelity_repair_removes_legacy_refs(tmp_path: Path):
    state = tmp_path
    (state / "tool_outputs").mkdir()
    (state / "all_outputs.json").write_text(json.dumps({
        "parse_powershell_transcripts": {
            "status": "not_applicable",
            "evidence_path": _stale(),
            "records": [],
        }
    }))
    (state / "tool_outputs" / "parse_powershell_transcripts.json").write_text(json.dumps({
        "status": "not_applicable",
        "evidence_path": _stale(),
        "searched_roots": [_stale()],
        "records": [],
    }))

    fail = subprocess.run(
        [sys.executable, "scripts/postrun_path_fidelity_gate.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert fail.returncode != 0
    assert "PATH_FIDELITY_GATE=FAIL" in fail.stdout

    fixed = subprocess.run(
        [sys.executable, "scripts/postrun_path_fidelity_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert fixed.returncode == 0, fixed.stdout
    assert "PATH_FIDELITY_GATE=PASS" in fixed.stdout

    assert _stale() not in (state / "all_outputs.json").read_text()
    assert _stale() not in (state / "tool_outputs" / "parse_powershell_transcripts.json").read_text()
