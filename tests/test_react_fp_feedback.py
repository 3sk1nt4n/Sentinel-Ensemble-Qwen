"""Fix C tests: ReAct FALSE POSITIVE conclusion feeds severity.

Run 5 Step 11 investigated OUTLOOK, concluded
    "FALSE POSITIVE - OUTLOOK.EXE malfind hits are benign Office
     memory allocation patterns"
and OUTLOOK ended at LOW severity -- because Inv2 had already labelled
it LOW upstream. Luck, not system.

Run 7 Step 11 hit the max-turn cap on OUTLOOK without ever calling
action=conclude, so no FP marker was ever produced. The finding stayed
MEDIUM CONFIRMED.

These tests lock three things:
  1. conclude action with FP markers writes ``react_conclusion`` onto
     the finding dict
  2. calibrator reads ``react_conclusion.is_false_positive`` and forces
     severity LOW
  3. this overrides otherwise-HIGH signals
"""
from __future__ import annotations

import logging

from sift_sentinel.analysis.confidence import (
    _is_false_positive,
    calibrate_confidence,
)


class TestReactFpDetection:
    def test_react_fp_conclusion_forces_low(self):
        """Cross-domain HIGH signal + ReAct FP -> LOW."""
        finding = {
            "finding_id": "F001",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "HIGH",
            "claims": [
                {"source_tool": "vol_pstree"},
                {"source_tool": "get_amcache"},
            ],
            "react_conclusion": {
                "text": (
                    "FALSE POSITIVE - OUTLOOK.EXE malfind hits are "
                    "benign Office memory allocation patterns"
                ),
                "is_false_positive": True,
            },
        }
        assert calibrate_confidence(finding, "full") == "LOW"

    def test_react_conclude_without_fp_markers_keeps_normal_scoring(self):
        """action=conclude with non-FP text does NOT demote severity."""
        finding = {
            "finding_id": "F002",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "MEDIUM",
            "claims": [
                {"source_tool": "vol_cmdline"},
                {"source_tool": "get_amcache"},
            ],
            "react_conclusion": {
                "text": "insufficient evidence to determine maliciousness",
                "is_false_positive": False,
            },
        }
        # Cross-domain (memory+disk) triggers HIGH, FP flag is False
        assert calibrate_confidence(finding, "full") == "HIGH"

    def test_no_react_conclusion_uses_normal_scoring(self):
        """Findings without a react_conclusion scored normally."""
        finding = {
            "finding_id": "F003",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "MEDIUM",
            "claims": [],
        }
        assert calibrate_confidence(finding, "full") == "HIGH"

    def test_react_fp_supersedes_high(self):
        """HIGH with every cross-domain + 3+ types signal + ReAct FP -> LOW."""
        finding = {
            "finding_id": "F004",
            "source_tools": [
                "vol_pstree", "vol_netscan", "get_amcache",
                "parse_event_logs", "extract_mft_timeline",
            ],
            "confidence_level": "HIGH",
            "claims": [
                {"source_tool": "vol_pstree"},
                {"source_tool": "get_amcache"},
                {"source_tool": "parse_event_logs"},
            ],
            "react_conclusion": {
                "text": "BENIGN: McAfee updater tiny RWX is normal",
                "is_false_positive": True,
            },
        }
        assert calibrate_confidence(finding, "full") == "LOW"

    def test_is_false_positive_honors_react_marker(self):
        """_is_false_positive must return True when only react_conclusion set."""
        finding = {
            "react_conclusion": {
                "text": "LEGITIMATE forensic tool",
                "is_false_positive": True,
            },
        }
        assert _is_false_positive(finding) is True

    def test_is_false_positive_false_when_only_conclusion_text_no_flag(self):
        """Flag governs, not the text: if is_false_positive=False, not FP."""
        finding = {
            "react_conclusion": {
                "text": "unclear verdict",
                "is_false_positive": False,
            },
        }
        assert _is_false_positive(finding) is False


class TestReactFpLogging:
    def test_calibrator_logs_react_fp_reason(self, caplog):
        """Log line must identify the ReAct FP path so operators can trace it."""
        finding = {
            "finding_id": "F100",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "HIGH",
            "react_conclusion": {
                "text": (
                    "FALSE POSITIVE: F-Response is a legitimate forensic "
                    "acquisition tool, not malware"
                ),
                "is_false_positive": True,
            },
        }
        with caplog.at_level(
            logging.INFO, logger="sift_sentinel.analysis.confidence"
        ):
            calibrate_confidence(finding, "full")
        assert any(
            "FORCED LOW by ReAct FP" in r.message for r in caplog.records
        )


class TestCoordinatorReactHandlerWiring:
    def test_coordinator_sets_react_conclusion_on_finding(self):
        """coordinator.py must persist the conclude payload onto finding.

        BUG 2B updated contract: FP detection uses strict regex patterns
        instead of naive substring match. Test asserts the new contract.
        """
        from pathlib import Path
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        # react_conclusion persistence still required
        assert 'finding["react_conclusion"]' in src, (
            "react_conclusion dict not persisted onto finding"
        )
        # BUG 2B: fp_patterns (regex tuple) replaces fp_markers (substring)
        assert "fp_patterns" in src, (
            "fp_patterns regex tuple missing (BUG 2B regression). "
            "The old fp_markers substring check was broken -- matched "
            "'legitimate' in 'masquerading as legitimate'."
        )
        # Verify the regex patterns anchor on assertion verbs (is/are/appears)
        assert r"\b(?:is|are|appears?" in src, (
            "FP regex must require assertion verb (is/are/appears) before "
            "benign/legitimate, not bare substring. BUG 2B regression."
        )

    def test_coordinator_marker_check_is_case_insensitive(self):
        """Markers matched case-insensitively.

        BUG 2B updated contract: re.IGNORECASE replaces .upper() text
        normalization. Both achieve case-insensitivity; regex is more
        precise.
        """
        from pathlib import Path
        src = Path("src/sift_sentinel/coordinator.py").read_text()
        # BUG 2B: re.IGNORECASE flag replaces .upper() on input
        assert "re.IGNORECASE" in src, (
            "re.IGNORECASE flag missing -- FP regex must be case-"
            "insensitive (BUG 2B regression)"
        )
