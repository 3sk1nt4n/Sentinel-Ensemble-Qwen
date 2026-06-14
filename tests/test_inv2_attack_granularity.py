"""Fix B tests: Inv2 prompt must enforce one-finding-per-tactic.

Run 5 had 8 findings including a dedicated PWDumpX credential-theft
finding (F004, upgraded to HIGH) and a dedicated C2 finding (F006).
Run 7 had 7 findings where F007 "Full attack chain from WMI execution
to persistent backdoor" consolidated credential theft + lateral
movement + C2 into one summary -- PWDumpX/PsExec appears nowhere as a
dedicated finding in Run 7.

These tests lock the granularity guidance so future prompt refactors
can't silently re-introduce the summary-only pattern.
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.coordinator import build_inv2_prompt
from sift_sentinel.prompts import (
    INV2_ATTACK_GRANULARITY,
    render_attack_granularity,
)
from sift_sentinel.tools.common import build_ollama_inv2_prompt


class TestAttackGranularityContent:
    def test_inv2_prompt_mentions_att_ck_tactics(self):
        rules = render_attack_granularity()
        assert "ATT&CK" in rules or "MITRE" in rules
        assert "TA0002" in rules  # Execution
        assert "TA0006" in rules  # Credential Access
        assert "TA0008" in rules  # Lateral Movement
        assert "TA0011" in rules  # Command and Control

    def test_inv2_prompt_requires_credential_access_separately(self):
        rules = render_attack_granularity()
        assert "Credential Access" in rules
        # Must name the credential-theft tools so the model recognises them
        assert "PWDumpX" in rules or "PsExec" in rules or "Mimikatz" in rules

    def test_inv2_prompt_requires_lateral_movement_separately(self):
        rules = render_attack_granularity()
        assert "Lateral Movement" in rules
        assert (
            "PsExec" in rules
            or "SMB" in rules
            or "WinRM" in rules
            or "WMI-remote" in rules
        )

    def test_inv2_prompt_warns_against_attack_chain_consolidation(self):
        """Must explicitly forbid replacing tactic findings with a summary."""
        rules = render_attack_granularity()
        lower = rules.lower()
        assert "consolidate" in lower or "replace" in lower
        assert "summary" in lower or "attack chain" in lower
        assert (
            "do not" in lower
            or "do NOT" in rules
            or "never" in lower
            or "Never" in rules
        )

    def test_inv2_prompt_sets_expected_finding_count(self):
        rules = render_attack_granularity()
        lower = rules.lower()
        # Either explicit 6-10 range or "fewer than 4" under-producing warning
        assert "6-10" in rules or "fewer than 4" in lower or "under-producing" in lower

    def test_inv2_prompt_requires_execution_tactic(self):
        rules = render_attack_granularity()
        assert "Execution" in rules
        assert "TA0002" in rules


class TestAttackGranularityInClaudeInv2Prompt:
    def test_coordinator_build_inv2_includes_granularity_block(self, tmp_path):
        prompt_path = build_inv2_prompt({}, token_budget=1000, state_dir=tmp_path)
        text = Path(prompt_path).read_text()
        assert "FINDING GRANULARITY" in text
        assert "TA0006" in text  # Credential Access required verbatim


class TestAttackGranularityInOllamaInv2Prompt:
    def test_ollama_build_inv2_includes_granularity_block(self):
        text = build_ollama_inv2_prompt({})
        assert "FINDING GRANULARITY" in text
        assert "TA0008" in text


class TestAttackGranularityInLiveInv2Prompt:
    def test_live_inv2_template_imports_granularity_helper(self):
        src = Path("run_pipeline.py").read_text()
        assert "render_attack_granularity" in src
        assert "render_attack_granularity()" in src


class TestAttackGranularityModuleExports:
    def test_constant_and_helper_consistent(self):
        assert "TA0006" in INV2_ATTACK_GRANULARITY
        assert render_attack_granularity() == INV2_ATTACK_GRANULARITY
