from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_min_state(tmp_path: Path, stale: bool) -> Path:
    state = tmp_path / ("bad_state" if stale else "good_state")
    tool_outputs = state / "tool_outputs"
    tool_outputs.mkdir(parents=True)

    evidence_path = "/mnt/windows_mount" if stale else str(tmp_path / "isolated" / "ntfs")

    (state / "all_outputs.json").write_text(
        json.dumps(
            {
                "vol_pstree": {
                    "status": "ok",
                    "records": [{"PID": 100, "ImageFileName": "generic.exe"}],
                },
                "parse_powershell_transcripts": {
                    "status": "not_applicable",
                    "records": [],
                    "evidence_path": evidence_path,
                },
            }
        )
    )
    (tool_outputs / "vol_pstree.json").write_text(
        json.dumps({"status": "ok", "records": [{"PID": 100, "ImageFileName": "generic.exe"}]})
    )
    (tool_outputs / "parse_powershell_transcripts.json").write_text(
        json.dumps({"status": "not_applicable", "records": [], "evidence_path": evidence_path})
    )
    (state / "evidence_db.json").write_text(json.dumps({"facts": []}))
    (state / "findings_final.json").write_text(
        json.dumps(
            [
                {
                    "id": "F001",
                    "title": "generic finding",
                    "source_tools": ["vol_pstree"],
                    "claim_tools": ["vol_pstree"],
                    "claims": [{"type": "pid", "pid": 100, "process": "generic.exe"}],
                }
            ]
        )
    )
    (state / "finding_disposition_buckets.json").write_text(
        json.dumps(
            {
                "suspicious_needs_review": [
                    {
                        "id": "F001",
                        "title": "generic finding",
                        "source_tools": ["vol_pstree"],
                        "claim_tools": ["vol_pstree"],
                        "claims": [{"type": "pid", "pid": 100, "process": "generic.exe"}],
                    }
                ],
                "benign_or_false_positive": [],
                "inconclusive_unresolved": [],
                "confirmed_malicious_atomic": [],
                "synthesis_narrative": [],
            }
        )
    )
    return state


def test_output_truth_wrapper_fails_when_path_fidelity_fails(tmp_path):
    state = _write_min_state(tmp_path, stale=True)
    result = subprocess.run(
        [sys.executable, "scripts/check_output_truth_gates.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert result.returncode != 0
    assert "PATH_FIDELITY_GATE=FAIL" in result.stdout
    assert "OUTPUT_TRUTH_GATES=FAIL" in result.stdout


def test_output_truth_wrapper_passes_when_all_gates_pass(tmp_path):
    state = _write_min_state(tmp_path, stale=False)
    result = subprocess.run(
        [sys.executable, "scripts/check_output_truth_gates.py", str(state)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout
    assert "PATH_FIDELITY_GATE=PASS" in result.stdout
    assert "TOOL_HIT_INTEGRITY_GATE=PASS" in result.stdout
    assert "CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE=PASS" in result.stdout
    assert "TOOL_CONTRIBUTION_GATE=PASS" in result.stdout
    assert "OUTPUT_TRUTH_GATES=PASS" in result.stdout
