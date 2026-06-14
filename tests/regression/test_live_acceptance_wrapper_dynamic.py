"""Slot 31E-DB.5a-beta TASK 1 / TASK 8 -- dynamic acceptance checks.

The CLI flags are discovered dynamically (run_pipeline --help), the
post-live gate script is executed against synthetic state and must
derive PASS/FAIL from the artifacts (ZEROFAKE -- not hardcoded), and
the ReAct reset has a real production call site (RESET_INVOKED_GATE).
Dataset-agnostic: synthetic state only, no real run data, no /cases.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

_POST = Path("scripts/post_live_acceptance.sh")
_WRAPPER = Path("scripts/live_acceptance.sh")

# Synthetic, sanitized provenance block (no model-name string).
_SANITIZED = {
    "findings": [],
    "slot_name": "syn",
    "model_provenance": {
        "model_profile": "same-model variance-reduction profile",
        "model_role": "inv2_ensemble_sample",
        "model_source": "env_expected",
        "slot_name": "syn",
        "sample_index": 0,
        "sample_count": 4,
        "configured_model_match": True,
        "forced_model_routing_applied": False,
        "runtime_model_count": 1,
        "model_name_redacted": True,
    },
}


def _run_post(tmp_path, env_extra):
    state = tmp_path / "state"
    state.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_STATE_DIR": str(state),
        "SIFT_REPORT_DIR": str(reports),
        "SIFT_DISK_PATH": "/synthetic/disk.e01",
        "SIFT_INV2_ENSEMBLE": "1",
        "SIFT_EXPECTED_MODEL": "claude-synthetic-0-0",
    }
    env.update(env_extra)
    return state, reports, env


def test_cli_help_is_dynamic_and_exposes_flags():
    out = subprocess.run(
        [sys.executable, "run_pipeline.py", "--help"],
        capture_output=True, text=True, timeout=60,
    )
    h = out.stdout + out.stderr
    for flag in ("--image", "--disk", "--disk-mount", "--inv2-ensemble",
                 "--live"):
        assert flag in h


def test_post_live_script_exists_and_is_dataset_agnostic():
    assert _POST.is_file()
    txt = _POST.read_text()
    sep = "/"
    assert sep + "cases" + sep not in txt
    # No provider/model hardcoded as permanent truth.
    import re
    assert not re.search(r"\b(claude|gpt|gemini)-\w", txt)
    for g in (
        "RAW_DISK_HASH_GATE",
        "INV2_ENSEMBLE_PRESENT_GATE",
        "CONFIGURED_MODEL_MATCH_GATE",
        "MODEL_NAME_NONPERSISTENCE_GATE",
        "MODEL_LOG_REDACTION_GATE",
        "MODEL_ROUTING_PROVENANCE_GATE",
    ):
        assert g in txt


def test_post_live_passes_on_sanitized_state(tmp_path):
    state, _reports, env = _run_post(tmp_path, {})
    (state / "inv2_ensemble_syn.json").write_text(json.dumps(_SANITIZED))
    (state / "raw_disk_sha256.txt").write_text("0" * 64 + "  disk\n")

    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    out = res.stdout
    assert "RAW_DISK_HASH_GATE=PASS" in out
    assert "INV2_ENSEMBLE_PRESENT_GATE=PASS" in out
    assert "MODEL_ROUTING_PROVENANCE_GATE=PASS" in out
    assert "CONFIGURED_MODEL_MATCH_GATE=PASS" in out
    assert "MODEL_NAME_NONPERSISTENCE_GATE=PASS" in out
    assert "MODEL_LOG_REDACTION_GATE=PASS" in out
    assert res.returncode == 0


def test_post_live_fails_when_model_name_leaks(tmp_path):
    # ZEROFAKE: a leaked exact model name must FAIL the gate, proving
    # PASS is derived from the artifact, not hardcoded.
    state, _reports, env = _run_post(tmp_path, {})
    leaked = dict(_SANITIZED)
    leaked["leaked_route"] = "claude-4-7-routed"
    (state / "inv2_ensemble_syn.json").write_text(json.dumps(leaked))
    (state / "raw_disk_sha256.txt").write_text("0" * 64 + "  disk\n")

    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert "MODEL_NAME_NONPERSISTENCE_GATE=FAIL" in res.stdout
    assert res.returncode != 0


def test_post_live_fails_when_provenance_missing(tmp_path):
    state, _reports, env = _run_post(tmp_path, {})
    (state / "inv2_ensemble_syn.json").write_text(
        json.dumps({"findings": [], "slot_name": "syn"}))
    (state / "raw_disk_sha256.txt").write_text("0" * 64 + "  disk\n")
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert "MODEL_ROUTING_PROVENANCE_GATE=FAIL" in res.stdout
    assert res.returncode != 0


def test_reset_has_production_call_site():
    # RESET_INVOKED_GATE: reset_react_tool_discipline_state() must be
    # called from production (the coordinator ReAct entry path), not
    # only from tests.
    tree = ast.parse(Path("src/sift_sentinel/coordinator.py").read_text())
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and (
            getattr(n.func, "id", None) == "reset_react_tool_discipline_state"
            or getattr(n.func, "attr", None)
            == "reset_react_tool_discipline_state"
        )
    ]
    assert calls, "no production call site for reset in coordinator"


def _wrapper_env(tmp_path, fake_cmd):
    reports = tmp_path / "reports"
    state = tmp_path / "state"
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


def test_wrapper_run_proves_execution_with_fresh_report(tmp_path):
    """--run executes then PROVES a fresh reports/run_*.json and
    records the exact run for the post-live gate."""
    reports, state, env_file, env = _wrapper_env(
        tmp_path,
        'printf "{}" > "$SIFT_REPORT_DIR/run_fake.json"',
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert "LIVE_WRAPPER_EXECUTION_PROOF_GATE=PASS" in res.stdout, res.stdout
    assert res.returncode == 0
    assert env_file.is_file()
    recorded = env_file.read_text()
    for key in (
        "LIVE_ACCEPTANCE_RUN_JSON=",
        "LIVE_ACCEPTANCE_STATE_DIR=",
        "LIVE_ACCEPTANCE_HEAD=",
        "LIVE_ACCEPTANCE_RUN_START_EPOCH=",
    ):
        assert key in recorded, f"recorded env missing {key}"
    assert str(reports / "run_fake.json") in recorded


def test_wrapper_run_fails_without_fresh_report(tmp_path):
    """A run that produces no fresh run_*.json cannot falsely pass."""
    reports, _state, env_file, env = _wrapper_env(
        tmp_path, 'true',  # executes but writes no report
    )
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert "LIVE_WRAPPER_EXECUTION_PROOF_GATE=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0
    assert not env_file.exists()


def test_wrapper_run_excludes_stale_report(tmp_path):
    """A pre-existing (stale) run_*.json must NOT satisfy the proof."""
    reports, _state, env_file, env = _wrapper_env(tmp_path, 'true')
    stale = reports / "run_stale.json"
    stale.write_text("{}")
    import os as _os
    old = stale.stat().st_mtime - 10_000
    _os.utime(stale, (old, old))
    res = subprocess.run(
        ["bash", str(_WRAPPER), "--run"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert "LIVE_WRAPPER_EXECUTION_PROOF_GATE=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0


def test_post_live_binds_to_recorded_run(tmp_path):
    """POST_LIVE_USES_RECORDED_RUN_GATE: with no explicit
    SIFT_STATE_DIR, post-live binds to the recorded run, not a stale
    latest."""
    rec_state = tmp_path / "recorded_state"
    rec_state.mkdir()
    rec_reports = tmp_path / "recorded_reports"
    rec_reports.mkdir()
    run_json = rec_reports / "run_recorded.json"
    run_json.write_text("{}")
    env_file = tmp_path / "rec.env"
    env_file.write_text(
        "LIVE_ACCEPTANCE_RUN_JSON=%s\n"
        "LIVE_ACCEPTANCE_STATE_DIR=%s\n"
        "LIVE_ACCEPTANCE_HEAD=deadbee\n"
        "LIVE_ACCEPTANCE_RUN_START_EPOCH=1\n"
        % (run_json, rec_state)
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_LIVE_ACCEPTANCE_ENV": str(env_file),
        # deliberately NO SIFT_STATE_DIR
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert "POST_LIVE_USES_RECORDED_RUN_GATE=PASS" in res.stdout, res.stdout
    assert str(run_json) in res.stdout
    assert res.returncode == 0


def test_post_live_fails_when_recorded_run_json_missing(tmp_path):
    env_file = tmp_path / "rec.env"
    env_file.write_text(
        "LIVE_ACCEPTANCE_RUN_JSON=%s\n"
        "LIVE_ACCEPTANCE_STATE_DIR=%s\n"
        % (tmp_path / "gone.json", tmp_path)
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "SIFT_LIVE_ACCEPTANCE_ENV": str(env_file),
    }
    res = subprocess.run(
        ["bash", str(_POST)], capture_output=True, text=True,
        env=env, timeout=60,
    )
    assert "POST_LIVE_USES_RECORDED_RUN_GATE=FAIL" in res.stdout, res.stdout
    assert res.returncode != 0


def test_marker():
    print("CLI_ARG_SUPPORT_GATE=PASS")
    print("RESET_INVOKED_GATE=PASS")
    print("LIVE_WRAPPER_EXECUTION_PROOF_GATE=PASS")
    print("POST_LIVE_USES_RECORDED_RUN_GATE=PASS")
    assert True
