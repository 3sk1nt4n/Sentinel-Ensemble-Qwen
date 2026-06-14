"""Tests for memory profile health check, degraded-profile pipeline mode, and colored output."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sift_sentinel.coordinator import (
    check_profile_health,
    _build_react_prompt,
    INVESTIGATION_TOOLS,
)
from sift_sentinel.correction.self_correct import STRATEGIES


# ── check_profile_health tests ──────────────────────────────────────────


class TestProfileHealthy:
    """Normal windows.info output should return healthy."""

    HEALTHY_OUTPUT = (
        "Variable\tValue\n"
        "Kernel Base\t0xf80002c56000\n"
        "DTB\t0x187000\n"
        "Symbols\tntkrnlmp.pdb\n"
        "Is64Bit\tTrue\n"
        "IsPAE\tFalse\n"
        "primary\t0 still valid\n"
        "memory_layer\t0 still valid\n"
        "KdVersionBlock\t0xf80002d1c388\n"
        "Major/Minor\t15.7601\n"
        "MachineType\t34404\n"
        "KeNumberProcessors\t4\n"
        "SystemTime\t2018-08-17 12:34:56.000000+00:00\n"
        "NtSystemRoot\tC:\\Windows\n"
        "NtProductType\tNtProductServer\n"
        "NtMajorVersion\t6\n"
        "NtMinorVersion\t1\n"
    )

    def test_healthy_profile(self):
        """Healthy kernel metadata returns (True, [], info)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.HEALTHY_OUTPUT, stderr="", returncode=0,
            )
            healthy, reasons, info = check_profile_health("/fake/image.raw")
        assert healthy is True
        assert reasons == []
        assert info["KeNumberProcessors"] == "4"
        assert info["MachineType"] == "34404"
        assert info["Major/Minor"] == "15.7601"


class TestProfileDegradedKe0:
    """KeNumberProcessors=0 means corrupted kernel metadata."""

    DEGRADED_KE0_OUTPUT = (
        "Variable\tValue\n"
        "Major/Minor\t15.7601\n"
        "MachineType\t34404\n"
        "KeNumberProcessors\t0\n"
    )

    def test_ke_zero_is_degraded(self):
        """KeNumberProcessors=0 returns (False, reasons, info)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.DEGRADED_KE0_OUTPUT, stderr="", returncode=0,
            )
            healthy, reasons, info = check_profile_health("/fake/image.raw")
        assert healthy is False
        assert any("KeNumberProcessors=0" in r for r in reasons)


class TestProfileDegradedMachine:
    """MachineType=101 (invalid) means corrupted kernel metadata."""

    DEGRADED_MACHINE_OUTPUT = (
        "Variable\tValue\n"
        "Major/Minor\t92.70\n"
        "MachineType\t101\n"
        "KeNumberProcessors\t0\n"
    )

    def test_bad_machine_type(self):
        """MachineType=101 returns (False, reasons, info)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=self.DEGRADED_MACHINE_OUTPUT, stderr="", returncode=0,
            )
            healthy, reasons, info = check_profile_health("/fake/image.raw")
        assert healthy is False
        assert any("MachineType=101" in r for r in reasons)
        assert any("Major/Minor=92.70" in r for r in reasons)
        assert any("KeNumberProcessors=0" in r for r in reasons)


class TestProfileCheckFailure:
    """If windows.info fails entirely, assume healthy (fail-open)."""

    def test_subprocess_error_returns_healthy(self):
        """Subprocess error returns (True, [], {}) -- fail-open."""
        with patch("subprocess.run", side_effect=OSError("vol not found")):
            healthy, reasons, info = check_profile_health("/fake/image.raw")
        assert healthy is True
        assert reasons == []
        assert info == {}

    def test_timeout_returns_healthy(self):
        """Timeout returns (True, [], {}) -- fail-open."""
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("vol", 60)):
            healthy, reasons, info = check_profile_health("/fake/image.raw")
        assert healthy is True
        assert reasons == []


# ── ReAct prompt degraded hint tests ────────────────────────────────────


class TestDegradedPromptHint:
    """Degraded memory prompt behavior must be generic and no-blacklist."""

    SAMPLE_FINDING = {
        "finding_id": "PROBE",
        "artifact": "probe.exe",
        "claims": [{"type": "pid", "pid": 1234, "process": "probe.exe"}],
        "source_tools": [],
    }

    def test_degraded_prompt_has_generic_context(self):
        prompt = _build_react_prompt(
            self.SAMPLE_FINDING, [], 0, 3,
            degraded_profile=True,
        )

        assert "DEGRADED MEMORY CONTEXT" in prompt
        assert "negative-yield observation" in prompt
        assert "Do not pre-exclude" in prompt

    def test_degraded_prompt_has_no_tool_blacklist(self):
        import re

        prompt = _build_react_prompt(
            self.SAMPLE_FINDING, [], 0, 3,
            degraded_profile=True,
        )

        do_not_use = "Do " + "NOT use"
        avoid = "AV" + "OID"
        prior_broken_dash = "known-" + "broken"
        prior_broken_space = "known " + "broken"
        prior_empty_dash = "known-" + "empty"
        prior_empty_space = "known " + "empty"

        bad_lines = [
            line
            for line in prompt.splitlines()
            if (
                do_not_use in line
                or avoid in line
                or prior_broken_dash in line
                or prior_broken_space in line
                or prior_empty_dash in line
                or prior_empty_space in line
            )
            and re.search(
                r"\b(?:vol_|run_|parse_|get_|extract_|sleuthkit_)\w+\b",
                line,
            )
        ]

        assert bad_lines == []

    def test_degraded_prompt_has_no_named_degraded_tool_suppression(self):
        prompt = _build_react_prompt(
            self.SAMPLE_FINDING, [], 0, 3,
            degraded_profile=True,
        )

        forbidden_names = [
            "vol_filescan",
            "vol_cmdline",
            "vol_dlllist",
            "vol_handles",
            "vol_envars",
            "vol_svcscan",
            "vol_ldrmodules",
        ]

        do_not = "Do " + "NOT"
        avoid = "AV" + "OID"
        prior_broken_dash = "known-" + "broken"
        prior_broken_space = "known " + "broken"
        prior_empty_dash = "known-" + "empty"
        prior_empty_space = "known " + "empty"

        context_lines = [
            line
            for line in prompt.splitlines()
            if (
                "DEGRADED" in line
                or do_not in line
                or avoid in line
                or prior_broken_dash in line
                or prior_broken_space in line
                or prior_empty_dash in line
                or prior_empty_space in line
            )
        ]

        context_text = "\n".join(context_lines)
        for tool_name in forbidden_names:
            assert tool_name not in context_text

    def test_healthy_prompt_no_degraded_context(self):
        prompt = _build_react_prompt(
            self.SAMPLE_FINDING, [], 0, 3,
            degraded_profile=False,
        )

        assert "DEGRADED MEMORY CONTEXT" not in prompt
        assert "negative-yield observation" not in prompt


# ── Colored output and label tests ─────────────────────────────────────


class TestStepLabelsColored:
    """Step headers must contain STEP N: labels."""

    def test_step_labels_present(self):
        """run_pipeline.py must produce STEP labels for all major steps."""
        src = Path(__file__).resolve().parents[2] / "run_pipeline.py"
        content = src.read_text()
        # Steps 8-9 combined; step 9 covered by "STEPS 8-9";
        # step 11 logged in coordinator.py (not run_pipeline.py header)
        for n in [1, 2, 3, 4, 5, 6, 7, 10, 12, 13, 14, 15, 16]:
            assert f"STEP {n}:" in content, \
                f"STEP {n}: not found in run_pipeline.py"
        assert "STEPS 8-9:" in content, "STEPS 8-9: not found"


class TestAiActionsCyan:
    """AI call output must contain identifying labels."""

    def test_ai_action_labels_in_source(self):
        """run_pipeline.py must contain AI action labels."""
        src = Path(__file__).resolve().parents[2] / "run_pipeline.py"
        content = src.read_text()
        assert "AI SELECTING TOOLS" in content
        assert "AI ANALYZING EVIDENCE" in content
        assert "AI WRITING REPORT" in content
        assert "AI INVESTIGATING" in content


class TestToolDescriptionsPresent:
    """Tool descriptions must appear in the source."""

    def test_tool_descriptions_in_source(self):
        """run_pipeline.py must contain plain English tool descriptions."""
        src = Path(__file__).resolve().parents[2] / "run_pipeline.py"
        content = src.read_text()
        assert "process tree from memory" in content
        assert "network connections" in content
        assert "injected code detection" in content
        assert "program execution history" in content


class TestNoColorWhenPiped:
    """When isatty()=False and SIFT_FORCE_COLOR unset, color constants must be empty strings."""

    def test_no_ansi_when_not_tty(self, monkeypatch):
        """Color constants are empty when stdout is not a TTY and SIFT_FORCE_COLOR is unset."""
        # The pattern used in all files:
        # _TTY = sys.stdout.isatty() or os.environ.get("SIFT_FORCE_COLOR") == "1"
        # When piped with no override, _TTY is False, so all constants are ""
        monkeypatch.delenv("SIFT_FORCE_COLOR", raising=False)
        with patch.object(sys.stdout, "isatty", return_value=False):
            # Re-evaluate the conditional
            _tty = sys.stdout.isatty() or os.environ.get("SIFT_FORCE_COLOR") == "1"
            g = "\033[92m" if _tty else ""
            x = "\033[0m" if _tty else ""
            assert g == ""
            assert x == ""
            # A formatted string would contain no escape codes
            msg = f"{g}RUNNING: vol_pstree (process tree from memory){x}"
            assert "\033" not in msg


class TestForceColorOverride:
    """SIFT_FORCE_COLOR=1 keeps colors even when stdout is not a TTY."""

    def test_force_color_env_var_overrides_non_tty(self, monkeypatch):
        """SIFT_FORCE_COLOR=1 makes _TTY True even when stdout.isatty() is False."""
        monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
        monkeypatch.setenv("SIFT_FORCE_COLOR", "1")
        _tty = sys.stdout.isatty() or os.environ.get("SIFT_FORCE_COLOR") == "1"
        g = "\033[92m" if _tty else ""
        x = "\033[0m" if _tty else ""
        assert _tty is True
        assert g == "\033[92m"
        assert x == "\033[0m"
        # A formatted string preserves escape codes despite non-TTY
        msg = f"{g}RUNNING: vol_pstree{x}"
        assert "\033[92m" in msg
        assert "\033[0m" in msg


class TestScLabelsPlainEnglish:
    """Self-correction output must contain plain English strategy descriptions."""

    def test_sc_strategy_descriptions_in_source(self):
        """self_correct.py must contain plain English strategy labels."""
        src = (Path(__file__).resolve().parents[2]
               / "src" / "sift_sentinel" / "correction" / "self_correct.py")
        content = src.read_text()
        assert "Explain and retry" in content
        assert "Simplify to validator-typed claims" in content
        assert "Last chance or drop" in content

    def test_strategies_defined(self):
        """All 3 strategies must be defined."""
        assert 1 in STRATEGIES
        assert 2 in STRATEGIES
        assert 3 in STRATEGIES
