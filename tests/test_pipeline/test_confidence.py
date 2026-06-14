"""Tests for confidence calibration cross-domain upgrade (memory + disk -> HIGH)."""
from __future__ import annotations

import logging

from sift_sentinel.analysis.confidence import calibrate_confidence
from sift_sentinel.coordinator import step_13_calibrate


class TestCrossDomainUpgrade:
    def test_confidence_memory_plus_disk_is_high(self):
        """vol_pstree (memory) + get_amcache (disk) -> upgraded to HIGH."""
        finding = {
            "finding_id": "F003",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "MEDIUM",
        }
        result = calibrate_confidence(finding, "full")
        assert result == "HIGH"

    def test_confidence_memory_only_stays_medium(self):
        """vol_pstree only (memory) -> stays MEDIUM, no upgrade."""
        finding = {
            "finding_id": "F010",
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
        }
        result = calibrate_confidence(finding, "full")
        assert result == "MEDIUM"

    def test_confidence_low_stays_low_single_source(self):
        """Single source LOW finding -> stays LOW."""
        finding = {
            "finding_id": "F020",
            "source_tools": ["vol_malfind"],
            "confidence_level": "LOW",
        }
        result = calibrate_confidence(finding, "full")
        assert result == "LOW"

    def test_confidence_upgrade_logs(self, caplog):
        """Verify logger.info called with 'upgraded' on cross-domain upgrade."""
        finding = {
            "finding_id": "F004",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "MEDIUM",
        }
        with caplog.at_level(logging.INFO, logger="sift_sentinel.analysis.confidence"):
            calibrate_confidence(finding, "full")
        assert any("upgraded" in r.message for r in caplog.records)

    def test_step13_upgrades_in_place(self):
        """step_13_calibrate applies cross-domain upgrade to findings list."""
        findings = [
            {
                "finding_id": "F003",
                "source_tools": ["vol_pstree", "get_amcache"],
                "confidence_level": "MEDIUM",
            },
            {
                "finding_id": "F005",
                "source_tools": ["vol_cmdline"],
                "confidence_level": "MEDIUM",
            },
        ]
        result = step_13_calibrate(findings, "full")
        assert result[0]["confidence_level"] == "HIGH"
        assert result[1]["confidence_level"] == "MEDIUM"

    def test_investigation_claims_contribute(self):
        """investigation_claims source_tools counted for domain check."""
        finding = {
            "finding_id": "F006",
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
            "investigation_claims": [
                {"source_tools": ["get_amcache"]},
            ],
        }
        result = calibrate_confidence(finding, "full")
        assert result == "HIGH"

    def test_already_high_no_double_upgrade(self):
        """Already HIGH with 3+ types stays HIGH (no regression)."""
        finding = {
            "finding_id": "F007",
            "source_tools": ["vol_pstree", "vol_netscan", "get_amcache"],
            "confidence_level": "HIGH",
        }
        result = calibrate_confidence(finding, "full")
        assert result == "HIGH"

    def test_ssdt_degraded_memory_plus_disk(self):
        """SSDT degraded: memory ceiling capped, but cross-domain still upgrades."""
        finding = {
            "finding_id": "F008",
            "source_tools": ["vol_pstree", "get_amcache"],
            "confidence_level": "MEDIUM",
        }
        # SSDT degraded caps memory-dependent ceiling to MEDIUM,
        # but cross-domain upgrade overrides since disk corroborates
        result = calibrate_confidence(finding, "degraded")
        assert result == "HIGH"
