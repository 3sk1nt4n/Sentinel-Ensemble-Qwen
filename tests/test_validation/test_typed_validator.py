"""Slot 31E-DB.2 -- typed EvidenceDB claim validation.

Covers:
  A. Typed facts validate process / relationship / connection /
     memory-injection / registry / scheduled-task / event-log claims;
     unsupported claim type falls back to reference_set.
  B. Negative: wrong PID / wrong parent / wrong hash / string-only near
     match do NOT validate.
  D. Backward compatibility: with no evidence_db the validator is
     byte-identical to the reference_set-only path.
"""

import pytest

from sift_sentinel.analysis.evidence_db import build_typed_evidence_db
from sift_sentinel.validation.validator import validate_finding


# RFC5737 documentation address -- NOT a real IOC.
_DOC_IP = "203.0.113.50"


@pytest.fixture
def tool_outputs():
    return {
        "vol_pstree": {"output": [
            {"PID": 800, "ImageFileName": "services.exe", "PPID": 4,
             "Path": r"C:\Windows\System32\services.exe",
             "CreateTime": "2026-01-02 03:04:00"},
            {"PID": 1000, "ImageFileName": "explorer.exe", "PPID": 800,
             "Path": r"C:\Windows\explorer.exe",
             "CreateTime": "2026-01-02 03:05:00"},
            {"PID": 1337, "ImageFileName": "evil.exe", "PPID": 1000,
             "Path": r"C:\Temp\evil.exe",
             "CreateTime": "2026-01-02 03:06:00"},
        ]},
        "vol_netscan": {"output": [
            {"PID": 1337, "Proto": "TCP",
             "LocalAddr": "10.0.0.5", "LocalPort": 50544,
             "ForeignAddr": _DOC_IP, "ForeignPort": 4444,
             "State": "ESTABLISHED", "Owner": "evil.exe"},
        ]},
        "vol_malfind": {"output": [
            {"PID": 2222, "Process": "inject.exe",
             "Protection": "PAGE_EXECUTE_READWRITE",
             "Start VPN": "0x1000", "Tag": "VadS"},
        ]},
        "parse_registry_persistence": {"records": [
            {"registry_path":
             r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
             "value_name": "", "value_data": r"C:\Temp\evil.exe",
             "persistence_type": "run_key", "hive_type": "SOFTWARE"},
        ]},
        "parse_scheduled_tasks_disk": {"records": [
            {"task_name": "EvilTask", "task_path": r"\EvilTask",
             "actions": [{"execute": r"C:\Temp\evil.exe"}],
             "enabled": True, "hidden": True, "author": "attacker"},
        ]},
        "parse_event_logs": {"output": [
            {"EventID": 4624, "Provider": "Security-Auditing",
             "Channel": "Security",
             "TimeCreated": "2026-01-02 03:06:30", "Message": "logon"},
        ]},
        "vol_svcscan": {"output": [
            {"Name": "EvilSvc", "Binary": r"C:\Temp\evil.exe",
             "State": "RUNNING", "Start": "AUTO_START"},
        ]},
        "get_amcache": {"output": {"entries": [
            {"path": r"C:\Temp\evil.exe",
             "sha1": "a" * 40, "first_run": "2026-01-02 03:06:10"},
        ]}},
        "extract_network_iocs": {"records": [
            {"type": "ip", "value": _DOC_IP, "classification": "c2"},
        ]},
    }


@pytest.fixture
def evidence_db(tool_outputs):
    return build_typed_evidence_db(tool_outputs, reference_set={})


@pytest.fixture
def ref_set():
    """Minimal hand-built reference set for fallback assertions."""
    return {
        "hashes": {},
        "pid_to_process": {1337: ["evil.exe"]},
        "pid_to_parent_pid": {1337: 1000},
        "hidden_pids": set(),
        "timestamps_per_artifact": {
            "evil.exe": ["2026-01-02 03:06:00"],
        },
        "connections": {},
        "paths": {},
    }


# ── A. Typed validation ──────────────────────────────────────────────────

class TestTypedPositive:
    def _one(self, claim):
        return {"finding_id": "F1", "claims": [claim]}

    def test_process_fact_validates_pid(self, evidence_db):
        r = validate_finding(
            self._one({"type": "pid", "pid": 1337, "process": "evil.exe"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert r["checks"][0]["source"] == "typed_evidence_db"
        assert r["typed_evidence_db_used"] is True
        assert r["typed_fact_matches"] == 1

    def test_relationship_fact_validates_parent_child(self, evidence_db):
        r = validate_finding(
            self._one({"type": "child_process",
                       "parent_pid": 1000, "child_pid": 1337}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert r["checks"][0]["source"] == "typed_evidence_db"

    def test_network_fact_validates_ip_port(self, evidence_db):
        r = validate_finding(
            self._one({"type": "connection", "pid": 1337,
                       "process": "evil.exe",
                       "foreign_addr": _DOC_IP, "foreign_port": 4444}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert r["typed_fact_matches"] == 1

    def test_memory_injection_fact_validates_rwx_claim(self, evidence_db):
        # PID 2222 exists ONLY as a malfind/RWX fact (no process_fact).
        r = validate_finding(
            self._one({"type": "pid", "pid": 2222,
                       "process": "inject.exe"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert r["checks"][0]["source"] == "typed_evidence_db"

    def test_registry_fact_validates_registry_claim(self, evidence_db):
        r = validate_finding(
            self._one({"type": "path", "value":
                       r"HKLM\Software\Microsoft\Windows"
                       r"\CurrentVersion\Run"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert "registry" in r["checks"][0]["detail"]

    def test_scheduled_task_fact_validates_task_claim(self, evidence_db):
        r = validate_finding(
            self._one({"type": "artifact", "value": "EvilTask"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert "scheduled task" in r["checks"][0]["detail"]

    def test_event_log_fact_validates_event_claim(self, evidence_db):
        r = validate_finding(
            self._one({"type": "raw", "value": "4624"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert "event log" in r["checks"][0]["detail"]

    def test_unsupported_claim_falls_back_to_reference_set(
            self, evidence_db, ref_set):
        r = validate_finding(
            self._one({"type": "timestamp", "artifact": "evil.exe",
                       "timestamp": "2026-01-02 03:06:00"}),
            ref_set, evidence_db=evidence_db)
        assert r["status"] == "MATCH"
        assert r["checks"][0]["source"] == "reference_set"
        assert r["unsupported_claim_type_count"] == 1
        assert r["reference_set_fallback_matches"] == 1
        assert r["typed_fact_matches"] == 0


# ── B. Negative validation ───────────────────────────────────────────────

class TestTypedNegative:
    def _one(self, claim):
        return {"finding_id": "FN", "claims": [claim]}

    def test_wrong_pid_does_not_validate(self, evidence_db):
        r = validate_finding(
            self._one({"type": "pid", "pid": 1337,
                       "process": "notepad.exe"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MISMATCH"
        assert r["typed_fact_matches"] == 0

    def test_wrong_parent_pid_does_not_validate(self, evidence_db):
        r = validate_finding(
            self._one({"type": "child_process",
                       "parent_pid": 4242, "child_pid": 1337}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MISMATCH"

    def test_wrong_hash_path_does_not_validate(self, evidence_db):
        r = validate_finding(
            self._one({"type": "hash", "sha1": "a" * 40,
                       "filename": "legit.exe"}),
            {}, evidence_db=evidence_db)
        assert r["status"] == "MISMATCH"

    def test_string_only_near_match_does_not_validate(self, evidence_db):
        # "evil" is a substring of evil.exe but is NOT a normalized-field
        # equality on any typed fact -> must not promote.
        r = validate_finding(
            self._one({"type": "raw", "value": "evil"}),
            {}, evidence_db=evidence_db)
        assert r["status"] != "MATCH"
        assert r["typed_fact_matches"] == 0


# ── D. Backward compatibility (no evidence_db) ───────────────────────────

class TestBackwardCompatibility:
    def test_none_evidence_db_uses_reference_set(self, ref_set):
        finding = {"finding_id": "BC", "claims": [
            {"type": "pid", "pid": 1337, "process": "evil.exe"}]}
        r = validate_finding(finding, ref_set)
        assert r["status"] == "MATCH"
        assert r["typed_evidence_db_used"] is False
        assert r["reference_set_fallback_matches"] == 1
        assert r["checks"][0]["source"] == "reference_set"

    def test_empty_evidence_db_falls_back(self, ref_set):
        finding = {"finding_id": "BC2", "claims": [
            {"type": "pid", "pid": 1337, "process": "evil.exe"}]}
        r = validate_finding(finding, ref_set, evidence_db={})
        assert r["status"] == "MATCH"
        assert r["typed_evidence_db_used"] is False
        assert r["checks"][0]["source"] == "reference_set"

    def test_step_10_validate_telemetry_logged(self, ref_set, caplog):
        import logging
        from sift_sentinel.coordinator import step_10_validate
        findings = [{"finding_id": "S10", "claims": [
            {"type": "pid", "pid": 1337, "process": "evil.exe"}]}]
        with caplog.at_level(logging.INFO):
            passed, blocked = step_10_validate(findings, ref_set)
        assert len(passed) == 1
        assert any("typed-validator telemetry" in m
                   for m in caplog.messages)
