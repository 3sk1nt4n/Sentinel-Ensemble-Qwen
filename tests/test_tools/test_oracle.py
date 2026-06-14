"""Unit tests for ToolOracle.

Covers 4 tiers + feature flag + reason strings + dataset-agnostic
enforcement + batch ranking.
"""
from __future__ import annotations

import os
import pathlib
from unittest import mock

from sift_sentinel.tools.oracle import (
    Tier,
    TierRanked,
    ToolOracle,
    is_enabled,
)


def test_1_preferred_tier_when_artifact_type_unrepresented():
    oracle = ToolOracle(
        profile_healthy=True,
        already_selected={"tool_a"},
        registered_tools={"tool_a", "tool_b"},
        artifact_map={"tool_a": "M", "tool_b": "D"},
    )
    v = oracle.verdict("tool_b")
    assert v.tier == Tier.PREFERRED
    assert "artifact D not yet represented" in v.reason


def test_2_penalized_tier_when_profile_degraded_memory_tool():
    oracle = ToolOracle(
        profile_healthy=False,
        profile_reasons=["KeNumberProcessors=0"],
        registered_tools={"tool_mem"},
        artifact_map={"tool_mem": "M"},
    )
    v = oracle.verdict("tool_mem")
    assert v.tier == Tier.EXCLUDED
    assert "DEGRADED" in v.reason
    assert "KeNumberProcessors=0" in v.reason


def test_3_penalized_tier_when_prior_empty_record():
    oracle = ToolOracle(
        profile_healthy=True,
        investigation_history=[
            {"tool": "tool_x", "result_count": 0, "turn": 0},
        ],
        registered_tools={"tool_x"},
    )
    v = oracle.verdict("tool_x")
    assert v.tier == Tier.PENALIZED
    assert "prior turn returned 0 records" in v.reason


def test_4_reason_string_explains_tier_assignment():
    oracle = ToolOracle(profile_healthy=True, registered_tools={"any_tool"})
    v = oracle.verdict("any_tool")
    assert isinstance(v.reason, str)
    assert len(v.reason) > 0


def test_5_legacy_behavior_when_no_history_provided():
    oracle = ToolOracle(profile_healthy=True, registered_tools={"any_tool"})
    v = oracle.verdict("any_tool")
    assert v.tier == Tier.AVAILABLE
    assert v.score == 0.0


def test_6_rank_returns_all_candidates_categorized():
    oracle = ToolOracle(
        profile_healthy=True,
        investigation_history=[{"tool": "tool_zero", "result_count": 0}],
        already_selected=set(),
        registered_tools={"tool_preferred", "tool_zero", "tool_plain"},
        artifact_map={"tool_preferred": "D", "tool_plain": "T"},
    )
    ranked = oracle.rank(["tool_preferred", "tool_zero", "tool_plain", "tool_unknown"])
    assert len(ranked) == 4
    assert ranked[0].tier == Tier.PREFERRED
    assert ranked[-1].tier == Tier.EXCLUDED
    assert ranked[-1].tool == "tool_unknown"


def test_7_dataset_agnostic_no_tool_names_hardcoded_in_scores():
    """Source must not reference specific tool names or dataset codes."""
    source_path = pathlib.Path(__file__).resolve().parents[2] / "src" / "sift_sentinel" / "tools" / "oracle.py"
    source = source_path.read_text()
    forbidden = [
        "vol_pstree", "vol_malfind", "vol_psscan", "vol_netscan",
        "get_amcache", "parse_event_logs", "extract_mft_timeline",
        "CRIMSON", "OSPREY", "RD" "-01", "RD" "-02", "BASE-",
    ]
    for token in forbidden:
        assert token not in source, f"oracle.py must not reference {token!r}"


def test_8_feature_flag_off_by_default():
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SIFT_USE_ORACLE", None)
        assert is_enabled() is False
    with mock.patch.dict(os.environ, {"SIFT_USE_ORACLE": "1"}):
        assert is_enabled() is True


def test_9_excluded_for_unregistered_tool():
    oracle = ToolOracle(profile_healthy=True, registered_tools={"known"})
    v = oracle.verdict("unknown")
    assert v.tier == Tier.EXCLUDED
    assert "not in tool registry" in v.reason


def test_10_rank_sort_is_stable_within_tier_by_score_then_name():
    oracle = ToolOracle(
        profile_healthy=True,
        already_selected=set(),
        registered_tools={"alpha", "bravo", "charlie"},
        artifact_map={"alpha": "A", "bravo": "B", "charlie": "C"},
    )
    ranked = oracle.rank(["charlie", "alpha", "bravo"])
    assert [r.tool for r in ranked] == ["alpha", "bravo", "charlie"]
