from __future__ import annotations

import json
from pathlib import Path

from sift_sentinel.analysis.state_dir_resolver import resolve_state_dir, set_active_state_dir
from sift_sentinel.analysis.tool_hit_integrity import enforce_latest_state_tool_hit_integrity

def _minimal_state(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    (p / "all_outputs.json").write_text(json.dumps({
        "producer_tool": {"status": "ok", "records": [{"x": 1}]},
    }))
    (p / "finding_disposition_buckets.json").write_text(json.dumps({
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }))
    (p / "tool_outputs").mkdir(exist_ok=True)
    return p

def test_resolver_prefers_explicit_state(tmp_path: Path):
    state = _minimal_state(tmp_path / "state")
    assert resolve_state_dir(str(state)) == str(state)

def test_set_active_state_env_then_enforce_latest_no_none_crash(tmp_path: Path, monkeypatch):
    state = _minimal_state(tmp_path / "state")
    monkeypatch.setenv("SIFT_ACTIVE_STATE_DIR", str(state))
    set_active_state_dir(state)
    result = enforce_latest_state_tool_hit_integrity(repair=True, fail=False)
    assert result.get("status") == "pass"

def test_enforce_latest_with_explicit_state_no_none_crash(tmp_path: Path):
    state = _minimal_state(tmp_path / "state")
    result = enforce_latest_state_tool_hit_integrity(state_dir=str(state), repair=True, fail=False)
    assert result.get("status") == "pass"
