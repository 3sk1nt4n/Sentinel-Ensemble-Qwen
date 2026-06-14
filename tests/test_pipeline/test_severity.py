"""Tests for severity rating (assign_severity)."""
from __future__ import annotations

from sift_sentinel.analysis.confidence import assign_severity


class TestSeverityCredentialTools:
    def test_pwdump_is_critical(self):
        finding = {"artifact": "pwdumsample_payload.exe executed", "description": ""}
        assert assign_severity(finding) == "CRITICAL"

    def test_mimikatz_is_critical(self):
        finding = {"artifact": "mimikatz.exe", "description": "credential theft"}
        assert assign_severity(finding) == "CRITICAL"

    def test_procdump_lsass_is_critical(self):
        finding = {"artifact": "procdump", "description": "dumped lsass memory"}
        assert assign_severity(finding) == "CRITICAL"

    def test_lateral_movement_is_critical(self):
        finding = {"artifact": "", "description": "lateral movement via psexec"}
        assert assign_severity(finding) == "CRITICAL"


class TestSeverityInjection:
    def test_malfind_is_high(self):
        finding = {"artifact": "malfind hit in svchost", "description": ""}
        assert assign_severity(finding) == "HIGH"

    def test_injected_is_high(self):
        finding = {"artifact": "", "description": "injected code in explorer"}
        assert assign_severity(finding) == "HIGH"

    def test_hollowed_is_high(self):
        finding = {"artifact": "hollowed process", "description": ""}
        assert assign_severity(finding) == "HIGH"

    def test_beacon_is_high(self):
        finding = {"artifact": "beacon callback", "description": ""}
        assert assign_severity(finding) == "HIGH"


class TestSeverityListeningPort:
    def test_listening_is_medium(self):
        finding = {"artifact": "", "description": "port 4444 listening"}
        assert assign_severity(finding) == "MEDIUM"

    def test_established_is_medium(self):
        finding = {"artifact": "", "description": "established connection"}
        assert assign_severity(finding) == "MEDIUM"

    def test_suspicious_is_medium(self):
        finding = {"artifact": "suspicious service", "description": ""}
        assert assign_severity(finding) == "MEDIUM"


class TestSeverityGeneric:
    def test_generic_finding_is_low(self):
        finding = {"artifact": "svchost.exe", "description": "normal service"}
        assert assign_severity(finding) == "LOW"

    def test_empty_finding_is_low(self):
        finding = {}
        assert assign_severity(finding) == "LOW"

    def test_missing_fields_is_low(self):
        finding = {"artifact": "explorer.exe"}
        assert assign_severity(finding) == "LOW"


class TestSeverityCaseInsensitive:
    def test_pwdump_upper(self):
        finding = {"artifact": "PWDumpX.exe", "description": ""}
        assert assign_severity(finding) == "CRITICAL"

    def test_pwdump_lower(self):
        finding = {"artifact": "pwdump", "description": ""}
        assert assign_severity(finding) == "CRITICAL"

    def test_mimikatz_mixed(self):
        finding = {"artifact": "MimiKATZ", "description": ""}
        assert assign_severity(finding) == "CRITICAL"

    def test_malfind_upper(self):
        finding = {"artifact": "MALFIND hit", "description": ""}
        assert assign_severity(finding) == "HIGH"
