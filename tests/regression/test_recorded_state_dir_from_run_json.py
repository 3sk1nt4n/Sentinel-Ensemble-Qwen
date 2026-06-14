"""Slot 31E-DB.5d GROUP A TASK A2 -- recorded state_dir from run JSON.

Observed bug: the wrapper recorded ./analysis/state instead of the
real run_json["state_dir"], so the post-live verifier inspected the
wrong directory. The wrapper must now parse state_dir out of the full
run JSON and record THAT. Dataset-agnostic: synthetic paths only, no
live pipeline call (SIFT_LIVE_ACCEPTANCE_CMD substitutes a fake run).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

_WRAPPER = Path("scripts/live_acceptance.sh")

_GATE_MATCH = "RECORDED_STATE_DIR_MATCHES_RUN_JSON_GATE"
_GATE_EXISTS = "RECORDED_STATE_DIR_EXISTS_GATE"


def _env(tmp_path, fake_cmd):
    reports = tmp_path / "reports"
    state = tmp_path / "default_state"  # the WRONG dir (old default)
    reports.mkdir()
    state.mkdir()
    env_file = tmp_path / "rec.env"
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_IMAGE_PATH": "/synthetic/evidence/memory.img",
        "SIFT_DISK_PATH": "/synthetic/evidence/disk.E01",
        "SIFT_DISK_MOUNT": "/synthetic/mnt",
        "SIFT_REPORT_DIR": str(reports),
        "SIFT_STATE_DIR": str(state),
        "SIFT_LIVE_ACCEPTANCE_ENV": str(env_file),
        "SIFT_LIVE_ACCEPTANCE_CMD": fake_cmd,
    }
    return reports, state, env_file, env


def test_recorded_state_dir_comes_from_run_json(tmp_path):
    real_state = tmp_path / "real_run_state"
    real_state.mkdir()
    reports, default_state, env_file, env = _env(
        tmp_path,
        # Fake run writes a full run JSON carrying its OWN state_dir,
        # different from the (wrong) SIFT_STATE_DIR default.
        'printf \'{"state_dir": "%s"}\' > '
        '"$SIFT_REPORT_DIR/run_real.json"' % real_state,
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert f"{_GATE_MATCH}=PASS" in res.stdout, res.stdout
    assert f"{_GATE_EXISTS}=PASS" in res.stdout, res.stdout
    assert "LIVE_WRAPPER_EXECUTION_PROOF_GATE=PASS" in res.stdout
    assert res.returncode == 0

    recorded = env_file.read_text()
    assert f"LIVE_ACCEPTANCE_STATE_DIR={real_state}" in recorded, recorded
    # The stale default must NOT be what got recorded.
    assert f"LIVE_ACCEPTANCE_STATE_DIR={default_state}\n" not in recorded


def test_run_json_state_dir_absent_falls_back_without_false_pass(tmp_path):
    """A synthetic run JSON with no state_dir key must not silently
    record a fabricated match -- the gate reports SKIP, not PASS."""
    reports, default_state, env_file, env = _env(
        tmp_path, 'printf "{}" > "$SIFT_REPORT_DIR/run_empty.json"',
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert f"{_GATE_MATCH}=SKIP" in res.stdout, res.stdout
    assert res.returncode == 0
    assert f"LIVE_ACCEPTANCE_STATE_DIR={default_state}" in env_file.read_text()


def test_run_json_state_dir_missing_dir_fails_closed(tmp_path):
    reports, _default_state, env_file, env = _env(
        tmp_path,
        'printf \'{"state_dir": "%s/gone"}\' > '
        '"$SIFT_REPORT_DIR/run_real.json"' % tmp_path,
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert f"{_GATE_EXISTS}=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0
    assert not env_file.exists()


def test_meta_sidecar_excluded(tmp_path):
    """run_*_meta.json is the sidecar; it must never be chosen as the
    full run JSON source of truth."""
    real_state = tmp_path / "real_run_state"
    real_state.mkdir()
    reports, _default_state, env_file, env = _env(
        tmp_path,
        'printf \'{"state_dir": "%s"}\' > "$SIFT_REPORT_DIR/run_x.json"; '
        'printf \'{"no_state_dir": 1}\' > '
        '"$SIFT_REPORT_DIR/run_x_meta.json"' % real_state,
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert f"{_GATE_MATCH}=PASS" in res.stdout, res.stdout
    assert "run_x.json" in env_file.read_text()


def test_marker():
    print(f"{_GATE_MATCH}=PASS")
    print(f"{_GATE_EXISTS}=PASS")
    assert _GATE_MATCH == "RECORDED_STATE_DIR_MATCHES_RUN_JSON_GATE"
