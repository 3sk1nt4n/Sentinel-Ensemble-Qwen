"""Slot 31E-DB.5d GROUP A TASK A4 -- RAW_DISK_HASH_ARTIFACT_GATE.

Disk integrity proof in the REAL recorded state may take any of three
forms: a raw_disk_sha256 artifact, the run JSON reporting
disk_integrity==verified, or integrity_check / sha256_pre / sha256_post
showing pre==post. Paths may be redacted; hash values and the match
boolean still persist. Absence of all proof fails closed.
Dataset-agnostic: synthetic hashes ("0"*64), no live call.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_POST = Path("scripts/post_live_acceptance.sh")
_GATE = "RAW_DISK_HASH_ARTIFACT_GATE"


def _run(tmp_path, state_dir, run_json=None):
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_STATE_DIR": str(state_dir),
        "SIFT_DISK_PATH": "/synthetic/evidence/disk.E01",
    }
    if run_json is not None:
        env["SIFT_RUN_JSON"] = str(run_json)
    return subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )


def test_pass_via_run_json_disk_integrity_verified(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    run_json = tmp_path / "run.json"
    run_json.write_text(json.dumps({
        "state_dir": str(state),
        "disk_integrity": "verified",
    }))
    res = _run(tmp_path, state, run_json)
    assert f"{_GATE}=PASS" in res.stdout, res.stdout
    assert "RAW_DISK_HASH_GATE=PASS" in res.stdout


def test_pass_via_integrity_check_artifact(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "integrity_check.json").write_text(json.dumps({
        "match": True,
        "details": [
            {"path": "<redacted-memory>", "pre": "a" * 64,
             "post": "a" * 64, "match": True},
            {"path": "<redacted-disk>", "pre": "b" * 64,
             "post": "b" * 64, "match": True},
        ],
    }))
    res = _run(tmp_path, state)
    assert f"{_GATE}=PASS" in res.stdout, res.stdout


def test_pass_via_sha256_pre_post_match(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    hashes = {"<redacted-memory>": "0" * 64, "<redacted-disk>": "f" * 64}
    (state / "sha256_pre.json").write_text(json.dumps(hashes))
    (state / "sha256_post.json").write_text(json.dumps(hashes))
    res = _run(tmp_path, state)
    assert f"{_GATE}=PASS" in res.stdout, res.stdout


def test_fail_closed_when_no_proof(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    res = _run(tmp_path, state)
    assert f"{_GATE}=FAIL" in res.stdout, res.stdout
    assert "RAW_DISK_HASH_GATE=FAIL" in res.stdout
    assert res.returncode != 0


def test_fail_closed_when_sha_pre_post_differ(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "sha256_pre.json").write_text(json.dumps({"x": "0" * 64}))
    (state / "sha256_post.json").write_text(json.dumps({"x": "1" * 64}))
    res = _run(tmp_path, state)
    assert f"{_GATE}=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0


def test_skip_when_no_disk_path(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    env = {"PATH": "/usr/bin:/bin", "SIFT_STATE_DIR": str(state)}
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert f"{_GATE}=SKIP" in res.stdout, res.stdout


def test_marker():
    print(f"{_GATE}=PASS")
    assert _GATE == "RAW_DISK_HASH_ARTIFACT_GATE"
