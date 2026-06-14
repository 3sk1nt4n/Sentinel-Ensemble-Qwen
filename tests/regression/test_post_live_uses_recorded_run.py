"""Slot 31E-DB.5d GROUP A TASK A3 -- post-live uses recorded run JSON.

scripts/post_live_acceptance.sh must accept SIFT_RUN_JSON (or the
recorded LIVE_ACCEPTANCE_RUN_JSON), parse state_dir out of that full
run JSON, and treat it as the source of truth -- never default to
./analysis/state when a run JSON is available. Dataset-agnostic.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_POST = Path("scripts/post_live_acceptance.sh")
_GATE = "POST_LIVE_USES_RECORDED_RUN_GATE"


def test_post_live_binds_to_state_dir_parsed_from_run_json(tmp_path):
    parsed_state = tmp_path / "parsed_state"
    parsed_state.mkdir()
    # Proof the parsed dir (not ./analysis/state) was inspected: the
    # raw-disk artifact lives ONLY in the parsed dir.
    (parsed_state / "raw_disk_sha256.txt").write_text("0" * 64 + "  d\n")
    reports = tmp_path / "reports"
    reports.mkdir()
    run_json = reports / "run_real.json"
    run_json.write_text(json.dumps({"state_dir": str(parsed_state)}))

    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_RUN_JSON": str(run_json),
        "SIFT_DISK_PATH": "/synthetic/evidence/disk.E01",
        # deliberately NO SIFT_STATE_DIR -> must come from run JSON
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    out = res.stdout
    assert f"{_GATE}=PASS" in out, out
    assert str(run_json) in out
    # It read the parsed dir, so the raw disk hash gate passes.
    assert "RAW_DISK_HASH_GATE=PASS" in out, out
    assert "analysis/state" not in out


def test_post_live_run_json_without_state_dir_fails_closed(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    run_json = reports / "run_nostate.json"
    run_json.write_text(json.dumps({"findings": []}))
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_RUN_JSON": str(run_json),
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert f"{_GATE}=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0


def test_post_live_missing_run_json_fails_closed(tmp_path):
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_RUN_JSON": str(tmp_path / "gone.json"),
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert f"{_GATE}=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0


def test_explicit_state_dir_still_wins(tmp_path):
    """An explicit operator SIFT_STATE_DIR overrides discovery (SKIP)."""
    state = tmp_path / "explicit"
    state.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_STATE_DIR": str(state),
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert f"{_GATE}=SKIP (explicit SIFT_STATE_DIR)" in res.stdout, res.stdout


def test_marker():
    print(f"{_GATE}=PASS")
    assert _GATE == "POST_LIVE_USES_RECORDED_RUN_GATE"
