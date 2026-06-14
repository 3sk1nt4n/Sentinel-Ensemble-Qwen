from __future__ import annotations

from pathlib import Path

from sift_sentinel.analysis.run_state_contract import (
    REQUIRED_COMPLETED_STATE_FILES,
    extract_state_paths_from_log_text,
    state_has_completed_files,
    validate_state_log_pair,
)


def _complete_state(root: Path) -> Path:
    root.mkdir()
    for name in REQUIRED_COMPLETED_STATE_FILES:
        (root / name).write_text("{}")
    return root


def test_completed_state_detection(tmp_path):
    state = _complete_state(tmp_path / "sift-sentinel-run-good")
    ok, missing = state_has_completed_files(state)
    assert ok
    assert missing == []


def test_incomplete_state_detection(tmp_path):
    state = tmp_path / "sift-sentinel-run-bad"
    state.mkdir()
    (state / "all_outputs.json").write_text("{}")
    ok, missing = state_has_completed_files(state)
    assert not ok
    assert "evidence_db.json" in missing
    assert "finding_disposition_buckets.json" in missing


def test_extract_state_paths_from_log_text():
    txt = "STATE: /tmp/sift-sentinel-run-abc_123 | LOG: logs/x/run.log"
    assert extract_state_paths_from_log_text(txt) == ["/tmp/sift-sentinel-run-abc_123"]


def test_state_log_pair_rejects_mismatch(tmp_path):
    state = _complete_state(tmp_path / "sift-sentinel-run-one")
    other = _complete_state(tmp_path / "sift-sentinel-run-two")
    log = tmp_path / "run.log"
    log.write_text(f"STEP 16: ANALYSIS COMPLETE in 10s\nSTATE: {other}\n")
    res = validate_state_log_pair(state, log, require_completed_state=True, require_step16=True)
    assert not res["ok"]
    assert "state_log_mismatch" in res["failures"]


def test_state_log_pair_accepts_exact_completed_pair(tmp_path):
    state = _complete_state(tmp_path / "sift-sentinel-run-one")
    log = tmp_path / "run.log"
    log.write_text(f"STEP 16: ANALYSIS COMPLETE in 10s\nSTATE: {state}\n")
    res = validate_state_log_pair(state, log, require_completed_state=True, require_step16=True)
    assert res["ok"]
