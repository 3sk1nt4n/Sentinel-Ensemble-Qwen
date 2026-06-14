from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sift_sentinel.analysis.path_fidelity import (
    count_legacy_mount_refs,
    legacy_mount_literal,
    normalize_legacy_mount_paths,
)


def test_normalizer_replaces_stale_with_active_mount(tmp_path: Path):
    active = tmp_path / "ntfs"
    (active / "Windows").mkdir(parents=True)

    stale = legacy_mount_literal()
    obj = {
        "status": "not_applicable",
        "evidence_path": stale,
        "searched_roots": [stale, stale + "/Users"],
    }

    out = normalize_legacy_mount_paths(obj, active_mount=str(active))
    dumped = json.dumps(out)

    assert stale not in dumped
    assert str(active) in dumped
    assert count_legacy_mount_refs(out) == 0


def test_normalizer_removes_stale_when_mount_unknown():
    stale = legacy_mount_literal()
    obj = {
        "status": "not_applicable",
        "evidence_path": stale,
        "searched_roots": [stale, stale + "/Users"],
    }

    out = normalize_legacy_mount_paths(obj, active_mount=None)
    dumped = json.dumps(out)

    assert stale not in dumped
    assert out["evidence_path"] is None
    assert out["searched_roots"] == []


def test_state_gate_repairs_tool_output(tmp_path: Path):
    state = tmp_path
    tool_dir = state / "tool_outputs"
    tool_dir.mkdir()

    stale = legacy_mount_literal()
    (state / "all_outputs.json").write_text(json.dumps({
        "parse_powershell_transcripts": {
            "status": "not_applicable",
            "records": [],
            "evidence_path": stale,
        }
    }))
    (tool_dir / "parse_powershell_transcripts.json").write_text(json.dumps({
        "status": "not_applicable",
        "records": [],
        "evidence_path": stale,
        "searched_roots": [stale],
    }))

    proc = subprocess.run(
        [sys.executable, "scripts/check_path_fidelity_gate.py", str(state), "--repair"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    assert "PATH_FIDELITY_GATE=PASS" in proc.stdout
    assert stale not in (state / "all_outputs.json").read_text()
    assert stale not in (tool_dir / "parse_powershell_transcripts.json").read_text()
