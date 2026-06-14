"""Tests for CC#15 claim_tools extraction and severity upgrade.

Before CC#15: every finding had ``claim_tools=[]`` because the calibrator
only read ``finding.source_tools`` and ``investigation_claims[].source_tools``.
Per-claim ``source_tool`` (singular, from Claude/GPT) and ``source_tools``
(plural, from Gemini) were ignored, so no finding ever reached HIGH in
the v2.2 runs even when claims cited 3 distinct tools spanning memory+disk.
"""
from __future__ import annotations

from sift_sentinel.analysis.confidence import (
    _extract_claim_tools,
    calibrate_confidence,
)


class TestClaimToolsExtraction:
    def test_claim_tools_extracted_from_claims_list(self):
        """Both 'source_tool' (singular) and 'source_tools' (plural) are honored."""
        finding = {
            "finding_id": "F001",
            "claims": [
                {"text": "null cmdline", "source_tool": "vol_cmdline"},
                {"text": "WmiPrvSE parent", "source_tool": "vol_pstree"},
                {"text": "amcache entry", "source_tool": "get_amcache"},
            ],
        }
        assert _extract_claim_tools(finding) == [
            "vol_cmdline", "vol_pstree", "get_amcache",
        ]

    def test_claim_tools_deduped_preserving_order(self):
        finding = {
            "claims": [
                {"source_tool": "vol_pstree"},
                {"source_tool": "vol_cmdline"},
                {"source_tool": "vol_pstree"},  # dupe
                {"source_tool": "get_amcache"},
            ],
        }
        assert _extract_claim_tools(finding) == [
            "vol_pstree", "vol_cmdline", "get_amcache",
        ]

    def test_claim_tools_plural_field(self):
        """Gemini shape: source_tools as a list."""
        finding = {
            "claims": [
                {"source_tools": ["vol_pstree", "vol_cmdline"]},
                {"source_tools": ["get_amcache"]},
            ],
        }
        assert _extract_claim_tools(finding) == [
            "vol_pstree", "vol_cmdline", "get_amcache",
        ]

    def test_claim_tools_includes_investigation_claims(self):
        """Step 11b enrichment claims also contribute."""
        finding = {
            "claims": [{"source_tool": "vol_pstree"}],
            "investigation_claims": [
                {"source_tools": ["get_amcache"]},
            ],
        }
        assert "vol_pstree" in _extract_claim_tools(finding)
        assert "get_amcache" in _extract_claim_tools(finding)

    def test_claim_tools_empty_when_no_provenance(self):
        finding = {"claims": [{"type": "pid", "pid": 1234}]}
        assert _extract_claim_tools(finding) == []


class TestSeverityFromClaimTools:
    def test_high_severity_requires_cross_domain(self):
        """memory+disk spread via claim_tools -> HIGH."""
        finding = {
            "finding_id": "F001",
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
            "claims": [
                {"source_tool": "vol_cmdline"},
                {"source_tool": "get_amcache"},
            ],
        }
        assert calibrate_confidence(finding, "full") == "HIGH"

    def test_medium_severity_same_domain(self):
        """2 memory tools via claim_tools -> MEDIUM (no cross-domain)."""
        finding = {
            "finding_id": "F002",
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
            "claims": [
                {"source_tool": "vol_cmdline"},
                {"source_tool": "vol_malfind"},
            ],
        }
        assert calibrate_confidence(finding, "full") == "MEDIUM"

    def test_low_severity_single_tool(self):
        """Single-tool finding with no claims -> MEDIUM ceiling, honors LOW input."""
        finding = {
            "finding_id": "F003",
            "source_tools": ["vol_pstree"],
            "confidence_level": "LOW",
            "claims": [],
        }
        assert calibrate_confidence(finding, "full") == "LOW"

    def test_fp_marker_forces_low(self):
        """is_false_positive=True forces LOW regardless of corroboration."""
        finding = {
            "finding_id": "F004",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "HIGH",
            "claims": [
                {"source_tool": "vol_cmdline"},
                {"source_tool": "get_amcache"},
            ],
            "is_false_positive": True,
        }
        assert calibrate_confidence(finding, "full") == "LOW"

    def test_known_good_marker_does_not_force_low(self):
        """known_good is display/context only, not a confidence gate."""
        from sift_sentinel.analysis.confidence import calibrate_confidence

        finding = {
            "confidence_level": "HIGH",
            "source_tools": ["vol_pstree", "get_amcache"],
            "claim_tools": ["vol_pstree", "get_amcache"],
            "claims": [
                {"type": "pid", "pid": 1234, "process": "sample.exe"},
            ],
            "known_good": True,
        }

        result = calibrate_confidence(
            finding,
            tool_records={"vol_pstree": 1, "get_amcache": 1},
        )

        assert result == "HIGH"

    def test_claim_tools_persisted_on_finding(self):
        """Calibrate should populate finding['claim_tools'] for downstream use."""
        finding = {
            "finding_id": "F006",
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
            "claims": [
                {"source_tool": "vol_cmdline"},
                {"source_tool": "get_amcache"},
            ],
        }
        calibrate_confidence(finding, "full")
        assert finding["claim_tools"] == ["vol_cmdline", "get_amcache"]

    def test_claim_tools_only_no_finding_source_tools(self):
        """Finding with empty source_tools but rich claim_tools still calibrates."""
        finding = {
            "finding_id": "F007",
            "source_tools": [],
            "confidence_level": "MEDIUM",
            "claims": [
                {"source_tool": "vol_pstree"},
                {"source_tool": "vol_cmdline"},
                {"source_tool": "get_amcache"},
            ],
        }
        # claim_tools span memory + disk -> HIGH
        assert calibrate_confidence(finding, "full") == "HIGH"
