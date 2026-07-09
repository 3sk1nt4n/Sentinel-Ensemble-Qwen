"""31AH regression: inv2_ensemble_stats includes explicit members[] array.

V3 triple-side:
  A=static     - ensemble.py has the patch and stats literal includes members
  B=runtime    - merge_ensemble_findings importable
  C=behavioral - synthetic per_model exercises all schema paths

DATASET-AGNOSTIC ABSOLUTE: all per_model inputs synthesized at runtime; no
hardcoded IDs/PIDs/paths/IPs/hashes/fixtures.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENSEMBLE_PY = REPO_ROOT / "src" / "sift_sentinel" / "ensemble.py"


def _runtime_forbidden_tokens() -> list[str]:
    parts = [
        ("r", "d", "-", "01"),
        ("r", "d", "0", "1"),
        ("/", "c", "ases", "/evidence"),
        ("/", "m", "nt", "/rd01"),
        ("s", "ansf", "or", "ensics"),
    ]
    return ["".join(p) for p in parts]


def test_31ah_static_patch_present_in_ensemble_py():
    src = ENSEMBLE_PY.read_text(encoding="utf-8")
    assert src.count("31AH: explicit members[] audit array") == 1
    assert '"members": members_audit,' in src
    assert '"completed_member_count": sum(' in src
    assert '"requested_member_count": len(members_audit)' in src
    ast.parse(src)


def test_31ah_no_forbidden_tokens_in_patch_block():
    src = ENSEMBLE_PY.read_text(encoding="utf-8")
    marker = "31AH: explicit members[] audit array"
    assert marker in src
    start = src.index(marker)
    block = src[max(0, start - 100):start + 1500]
    leaked = [tok for tok in _runtime_forbidden_tokens() if tok in block]
    assert not leaked, f"31AH region leaked forbidden tokens: {leaked}"


def test_31ah_runtime_importable():
    from sift_sentinel.ensemble import merge_ensemble_findings
    assert callable(merge_ensemble_findings)


def _synth_finding(fid: str, ts: str, art: str, tool: str) -> dict:
    return {
        "finding_id": fid,
        "title": f"synthetic_{fid}",
        "artifact": art,
        "timestamp": ts,
        "source_tools": [tool],
    }


def test_31ah_behavioral_members_schema_complete():
    from sift_sentinel.ensemble import merge_ensemble_findings
    per_model = {
        "member_00_synthA": {
            "member_index": 0,
            "actual_model": "synthetic-model-a",
            "original_model": "synthetic-model-a",
            "status": "completed",
            "findings": [_synth_finding("a1", "2026-01-01T00:00", "art_a", "tx")],
        },
        "member_01_synthB": {
            "member_index": 1,
            "actual_model": "synthetic-model-b",
            "findings": [_synth_finding("b1", "2026-01-02T00:00", "art_b", "ty")],
        },
    }
    _, stats = merge_ensemble_findings(per_model)
    assert "members" in stats
    members = stats["members"]
    assert isinstance(members, list)
    assert len(members) == 2
    required = {"member_id", "member_index", "model", "finding_count", "status"}
    for m in members:
        assert required.issubset(m.keys()), f"missing keys in {m}"


def test_31ah_behavioral_zero_findings_status_no_findings():
    from sift_sentinel.ensemble import merge_ensemble_findings
    per_model = {
        "member_00_empty": {
            "member_index": 0,
            "actual_model": "synthetic-model-x",
            "findings": [],
        },
    }
    _, stats = merge_ensemble_findings(per_model)
    m = stats["members"][0]
    assert m["finding_count"] == 0
    assert m["status"] == "no_findings"
    assert stats["completed_member_count"] == 0
    assert stats["requested_member_count"] == 1


def test_31ah_behavioral_model_fallback_chain():
    from sift_sentinel.ensemble import merge_ensemble_findings
    # Only original_model present (no actual_model)
    per_model = {
        "member_00_orig_only": {
            "member_index": 0,
            "original_model": "synthetic-model-orig",
            "status": "completed",
            "findings": [_synth_finding("o1", "2026-01-01T00:00", "art_o", "tk")],
        },
        # No model keys at all
        "member_01_no_model": {
            "member_index": 1,
            "findings": [_synth_finding("n1", "2026-01-02T00:00", "art_n", "tl")],
        },
    }
    _, stats = merge_ensemble_findings(per_model)
    by_id = {m["member_id"]: m for m in stats["members"]}
    assert by_id["member_00_orig_only"]["model"] == "synthetic-model-orig"
    assert by_id["member_01_no_model"]["model"] is None  # no key present, must be None not crash


def test_31ah_behavioral_empty_per_model_returns_empty_members():
    from sift_sentinel.ensemble import merge_ensemble_findings
    merged, stats = merge_ensemble_findings({})
    assert merged == []
    assert stats["members"] == []
    assert stats["requested_member_count"] == 0
    assert stats["completed_member_count"] == 0


def test_31ah_behavioral_existing_stats_keys_preserved():
    """Backward compat: existing keys must remain present."""
    from sift_sentinel.ensemble import merge_ensemble_findings
    per_model = {
        "member_00": {"member_index": 0, "findings": [
            _synth_finding("z1", "2026-01-01T00:00", "art_z", "tk")
        ]},
    }
    _, stats = merge_ensemble_findings(per_model)
    expected_keys = {
        "total_findings", "unique_findings", "cross_validated",
        "cross_validated_3plus", "per_model_counts", "raw_total_findings",
        "merged_survivor_count", "dropped_by_merge_count", "dropped_by_merge",
        "merge_algorithm",
    }
    assert expected_keys.issubset(stats.keys()), (
        f"31AH broke backward compat - missing: {expected_keys - set(stats.keys())}"
    )
