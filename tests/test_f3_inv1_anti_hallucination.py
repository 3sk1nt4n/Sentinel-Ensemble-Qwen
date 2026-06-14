"""
F3 regression tests: Inv1 anti-hallucination rule.

Property-based tests (slot 28):
  - No hardcoded evidence data
  - Assertions on prompt text structure, not Run-N specifics
  - Dataset-agnostic: rule must fire in both bootstrap-on and
    bootstrap-off paths
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sift_sentinel.coordinator import build_inv1_prompt


@pytest.fixture
def tmpdir_path(tmp_path):
    return tmp_path


class TestAntiHallucinationRulePresent:
    def test_rule_present_when_bootstrap_empty(self, tmpdir_path):
        # Bootstrap off: empty dict
        prompt_path = build_inv1_prompt({}, tmpdir_path)
        text = prompt_path.read_text()
        assert "CRITICAL HONESTY RULE" in text, (
            "anti-hallucination rule missing when bootstrap skipped"
        )
        assert "not actually seen" in text.lower()

    def test_rule_present_when_bootstrap_has_data(self, tmpdir_path):
        # Bootstrap on: non-empty summary
        bootstrap = {
            "vol_pstree": {"records": 12, "sample": "...fake data..."},
            "vol_netscan": {"records": 3, "sample": "..."},
        }
        prompt_path = build_inv1_prompt(bootstrap, tmpdir_path)
        text = prompt_path.read_text()
        assert "CRITICAL HONESTY RULE" in text, (
            "anti-hallucination rule missing when bootstrap provided"
        )

    def test_rule_forbids_phantom_reasoning(self, tmpdir_path):
        prompt_path = build_inv1_prompt({}, tmpdir_path)
        text = prompt_path.read_text().lower()
        # Rule must explicitly name the failure modes
        assert "would have shown" in text or "likely contains" in text, (
            "rule must forbid speculating about unseen tool outputs"
        )

    def test_rule_in_degraded_profile_path(self, tmpdir_path):
        # Degraded profile path also must include rule
        prompt_path = build_inv1_prompt(
            {}, tmpdir_path, degraded_profile=True,
        )
        text = prompt_path.read_text()
        assert "CRITICAL HONESTY RULE" in text


class TestRulePlacement:
    def test_rule_precedes_return_json(self, tmpdir_path):
        prompt_path = build_inv1_prompt({}, tmpdir_path)
        text = prompt_path.read_text()
        idx_rule = text.find("CRITICAL HONESTY RULE")
        idx_return = text.find("Return JSON:")
        assert idx_rule != -1 and idx_return != -1
        assert idx_rule < idx_return, (
            "rule must come before output format instructions"
        )

    def test_rule_after_tool_catalog(self, tmpdir_path):
        prompt_path = build_inv1_prompt({}, tmpdir_path)
        text = prompt_path.read_text()
        idx_catalog = text.find("Available tools")
        idx_rule = text.find("CRITICAL HONESTY RULE")
        assert idx_catalog < idx_rule, (
            "rule should come after tool listing, before return format"
        )
