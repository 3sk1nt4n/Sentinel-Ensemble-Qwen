"""Fix A tests: Inv2 prompt must require disk-tool citation.

Run 7 regressed to 0 HIGH findings because Inv2 stopped citing disk
tools (get_amcache, parse_event_logs, extract_mft_timeline) on
execution/lateral/file-drop findings. Cross-domain upgrade requires
at least one memory + one disk citation, so memory-only findings stay
MEDIUM even for confirmed malware.

These tests lock the citation rules into all three Inv2 composer paths.
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.coordinator import build_inv2_prompt
from sift_sentinel.prompts import (
    INV2_CITATION_RULES,
    render_citation_rules,
)
from sift_sentinel.tools.common import build_ollama_inv2_prompt


class TestCitationRulesContent:
    def test_inv2_prompt_requires_amcache_for_execution(self):
        """Execution findings must cite get_amcache even on empty results."""
        rules = render_citation_rules()
        assert "get_amcache" in rules
        assert "Execution" in rules
        assert "empty amcache" in rules.lower() or "amcache" in rules.lower()

    def test_inv2_prompt_requires_event_logs_for_lateral(self):
        rules = render_citation_rules()
        assert "parse_event_logs" in rules
        assert "Lateral movement" in rules or "lateral" in rules.lower()
        assert "credential" in rules.lower()

    def test_inv2_prompt_requires_mft_for_file_drops(self):
        rules = render_citation_rules()
        assert "extract_mft_timeline" in rules
        assert "File drops" in rules or "temp-path" in rules.lower()

    def test_citation_rules_explain_probative_absence(self):
        """Empty disk-tool results must be explicitly called out as probative."""
        rules = render_citation_rules()
        # "probative" or "probative evidence" or equivalent language
        assert "probative" in rules.lower()

    def test_citation_rules_mention_cross_domain_upgrade(self):
        rules = render_citation_rules()
        assert "cross-domain" in rules.lower()
        assert "HIGH" in rules


class TestCitationRulesInClaudeInv2Prompt:
    def test_coordinator_build_inv2_includes_citation_rules(self, tmp_path):
        """coordinator.build_inv2_prompt embeds the citation block."""
        prompt_path = build_inv2_prompt({}, token_budget=1000, state_dir=tmp_path)
        text = Path(prompt_path).read_text()
        assert "MANDATORY SOURCE-TOOL CITATION" in text
        assert "get_amcache" in text
        assert "parse_event_logs" in text
        assert "extract_mft_timeline" in text


class TestCitationRulesInOllamaInv2Prompt:
    def test_ollama_build_inv2_includes_citation_rules(self):
        text = build_ollama_inv2_prompt({})
        assert "MANDATORY SOURCE-TOOL CITATION" in text
        assert "get_amcache" in text


class TestCitationRulesInLiveInv2Prompt:
    def test_live_inv2_template_imports_citation_rules(self):
        """run_pipeline.py LIVE Inv2 prompt uses render_citation_rules."""
        src = Path("run_pipeline.py").read_text()
        assert "render_citation_rules" in src
        assert "render_citation_rules()" in src


class TestCitationRulesAppliedBeforeToolOutputs:
    """Rules must appear BEFORE the tool output blob so the model sees them
    while building findings, not as a footnote."""

    def test_citation_rules_before_tool_data_in_coordinator(self, tmp_path):
        all_outputs = {
            "vol_pstree": {"output": [{"ImageFileName": "demo.exe", "PID": 1}]},
        }
        prompt_path = build_inv2_prompt(all_outputs, token_budget=2000, state_dir=tmp_path)
        text = Path(prompt_path).read_text()
        citation_idx = text.find("MANDATORY SOURCE-TOOL CITATION")
        assert citation_idx > 0, "Citation rules missing from Claude Inv2 prompt"


class TestCitationRulesModuleExports:
    def test_rules_constant_and_helper_both_present(self):
        assert "get_amcache" in INV2_CITATION_RULES
        assert render_citation_rules() == INV2_CITATION_RULES
