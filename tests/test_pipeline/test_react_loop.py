"""Tests for Step 11 ReAct reasoning loop."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sift_sentinel.coordinator import (
    INVESTIGATION_TOOLS,
    _build_react_prompt,
    step_11_investigate,
)


@pytest.fixture(autouse=True)
def dry_run_mode(monkeypatch):
    """Force tests to use sample data path."""
    monkeypatch.setenv("SIFT_DRY_RUN", "1")


@pytest.fixture
def single_finding():
    """One finding with a PID claim."""
    return [
        {
            "finding_id": "F-100",
            "artifact": "evil.exe",
            "claims": [
                {"type": "pid", "pid": 100, "process": "evil.exe"},
            ],
            "source_tools": ["vol_pstree"],
            "confidence_level": "HIGH",
            "deterministic_check": "passed",
        },
    ]


# ── Test 1: conclude on turn 0 ─────────────────────────────────────────


class TestReActConcludeTurn0:
    def test_conclude_immediately(self, tmp_path, single_finding):
        """AI concludes on first turn: 0 tool calls, conclusion saved."""
        invoke = MagicMock(return_value={
            "action": "conclude",
            "conclusion": "confirmed malicious",
            "evidence_summary": "malfind + netscan",
        })
        result = step_11_investigate(
            single_finding, tmp_path, False, invoke,
        )
        assert len(result["investigations"]) == 1
        inv = result["investigations"][0]
        assert inv["tool_chain"] == []
        assert inv["turns"] == 0
        assert inv["conclusion"] == "confirmed malicious"
        assert invoke.call_count == 1


# ── Test 2: tool then conclude ──────────────────────────────────────────


class TestReActToolThenConclude:
    def test_one_tool_then_conclude(self, tmp_path, single_finding):
        """Turn 0: tool request. Turn 1: conclude. 1 tool in chain."""
        responses = [
            {"action": "tool", "tool": "vol_handles", "pid": 100,
             "reasoning": "check handles"},
            {"action": "conclude", "conclusion": "done",
             "evidence_summary": "handles confirmed"},
        ]
        invoke = MagicMock(side_effect=responses)
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = step_11_investigate(
                single_finding, tmp_path, False, invoke,
            )
        inv = result["investigations"][0]
        assert inv["tool_chain"] == ["vol_handles"]
        assert inv["turns"] == 1  # 1 tool call recorded
        assert inv["conclusion"] == "done"
        assert invoke.call_count == 2


# ── Test 3: max turns cap ──────────────────────────────────────────────


class TestReActMaxTurnsCap:
    def test_capped_at_5_turns(self, tmp_path, single_finding):
        """AI always requests tools -- capped at 5 turns."""
        invoke = MagicMock(return_value={
            "action": "tool", "tool": "vol_handles", "pid": 100,
            "reasoning": "still looking",
        })
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = step_11_investigate(
                single_finding, tmp_path, False, invoke,
            )
        inv = result["investigations"][0]
        assert inv["turns"] == 5
        # CC#17d-2: cap conclusion now preserves AI's final reasoning.
        # Verify both: (a) cap fired (conclusion mentions cap/reached),
        # (b) AI reasoning is preserved (conclusion includes "reasoning"
        # marker from the new format "Final AI reasoning: ...").
        conclusion_lower = inv["conclusion"].lower()
        assert "cap" in conclusion_lower, (
            f"conclusion should indicate cap fired, got: {inv['conclusion']!r}"
        )
        assert "reasoning" in conclusion_lower or "still looking" in conclusion_lower, (
            f"conclusion should preserve AI's final reasoning, got: {inv['conclusion']!r}"
        )
        assert invoke.call_count == 5


# ── Test 4: invalid tool guardrail ──────────────────────────────────────


class TestReActInvalidToolGuardrail:
    def test_invalid_tool_aborts(self, tmp_path, single_finding):
        """Agent requests invalid tool -> loop ends, guardrail noted."""
        invoke = MagicMock(return_value={
            "action": "tool", "tool": "fake_tool", "pid": 100,
            "reasoning": "trying fake",
        })
        result = step_11_investigate(
            single_finding, tmp_path, False, invoke,
        )
        inv = result["investigations"][0]
        assert "guardrail" in inv["conclusion"].lower()
        assert "fake_tool" in inv["conclusion"]
        assert inv["tool_chain"] == []
        assert invoke.call_count == 1


# ── Test 5: dry run skips ───────────────────────────────────────────────


class TestReActDryRunSkips:
    def test_dry_run_no_invoke(self, tmp_path, single_finding):
        """dry_run=True: empty result, no invoke calls."""
        invoke = MagicMock()
        result = step_11_investigate(
            single_finding, tmp_path, True, invoke,
        )
        invoke.assert_not_called()
        assert result == {"investigations": [], "threads": []}


# ── Test 6: prompt contains previous results ───────────────────────────


class TestReActPromptHasPreviousResults:
    def test_previous_results_in_prompt(self):
        """Prompt with 2 previous results includes Turn 0 and Turn 1."""
        finding = {
            "finding_id": "F-100",
            "claims": [{"type": "pid", "pid": 100, "process": "test.exe"}],
        }
        previous = [
            {"turn": 0, "tool": "vol_handles", "pid": 100,
             "reasoning": "checking handles", "result_count": 5,
             "result_sample": [{"PID": 100, "Name": "pipe"}]},
            {"turn": 1, "tool": "vol_netscan", "pid": 100,
             "reasoning": "checking network", "result_count": 2,
             "result_sample": [{"PID": 100, "LocalAddr": "0.0.0.0"}]},
        ]
        prompt = _build_react_prompt(finding, previous, turn=2)
        assert "Turn 0:" in prompt
        assert "Turn 1:" in prompt
        assert "vol_handles" in prompt
        assert "vol_netscan" in prompt
        assert "previous_investigation_results" in prompt


# ── Test 7: prompt contains escalation rules ───────────────────────────


class TestReActPromptHasEscalation:
    def test_escalation_rules_present(self):
        """Prompt always includes escalation_rules block."""
        finding = {
            "finding_id": "F-100",
            "claims": [{"type": "pid", "pid": 100, "process": "test.exe"}],
        }
        prompt = _build_react_prompt(finding, [], turn=0)
        assert "<escalation_rules>" in prompt
        assert "ROOTKIT ESCALATION" in prompt
        assert "vol_ldrmodules" in prompt


# ── Test 8: prompt includes tool failures ──────────────────────────────


class TestReActPromptHasFailures:
    def test_tool_failures_in_prompt(self):
        """When tool_failures provided, prompt includes failure block."""
        finding = {
            "finding_id": "F-100",
            "claims": [{"type": "pid", "pid": 100, "process": "test.exe"}],
        }
        failures = [
            {"tool": "vol_pstree", "status": "empty", "reason": "no data"},
        ]
        prompt = _build_react_prompt(
            finding, [], turn=0, tool_failures=failures,
        )
        assert "<tool_failures>" in prompt
        assert "vol_pstree" in prompt

    def test_no_failures_no_block(self):
        """Without tool_failures, no failure block in prompt."""
        finding = {
            "finding_id": "F-100",
            "claims": [{"type": "pid", "pid": 100, "process": "test.exe"}],
        }
        prompt = _build_react_prompt(finding, [], turn=0)
        assert "<tool_failures>" not in prompt
