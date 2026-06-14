"""Tests for validator.py -- finding validation against paired reference set."""

import pytest

from sift_sentinel.validation.validator import validate_finding


@pytest.fixture
def reference_set():
    """Standard paired reference set for testing."""
    return {
        "hashes": {
            "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30": "payload.exe",
            "d4e1f2a3b5c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2": "ransom.exe",
        },
        "pid_to_process": {
            4012: ["svchost.exe"],
            9005: ["payload.exe"],
        },
        "timestamps_per_artifact": {
            "payload.exe": ["2024-11-14 02:31:07", "2024-11-14 02:31:22"],
            "ransom.exe": ["2024-11-14 04:47:13"],
        },
        "connections": {
            "9005:192.0.2.111:443->192.0.2.129:443": "payload.exe",
        },
        "paths": {
            "payload.exe": [r"C:\Windows\Temp\payload.exe"],
            "ransom.exe": [r"C:\Users\Public\ransom.exe"],
        },
    }


# ── Hash checks ──────────────────────────────────────────────────────────

class TestHashValidation:
    def test_correct_sha1_correct_filename_match(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"
        assert result["checks"][0]["result"] == "MATCH"

    def test_correct_sha1_wrong_filename_cross_contamination(self, reference_set):
        finding = {
            "artifact": "ransom.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "ransom.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"
        assert "payload.exe" in result["checks"][0]["detail"]

    def test_invented_sha1_fabrication(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "0000000000000000000000000000000000000000",
                 "filename": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"
        assert "not found" in result["checks"][0]["detail"].lower()

    def test_hash_case_insensitive(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "A3F2C8D1E5B94F7260E8D3A1C9B47F52D6E81A30",
                 "filename": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"


# ── PID checks ───────────────────────────────────────────────────────────

class TestPidValidation:
    def test_correct_pid_correct_process(self, reference_set):
        finding = {
            "artifact": "svchost.exe",
            "claims": [{"type": "pid", "pid": 4012, "process": "svchost.exe"}],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_correct_pid_wrong_process_cross_contamination(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [{"type": "pid", "pid": 4012, "process": "payload.exe"}],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"
        assert "svchost.exe" in result["checks"][0]["detail"]

    def test_truncated_process_name_matches(self, reference_set):
        """Netscan truncates names at 15 chars: 'svchost.ex' matches 'svchost.exe'."""
        reference_set["pid_to_process"][9999] = ["vendorx_srv.ex"]
        finding = {
            "artifact": "VENDORX_SRV.EXE",
            "claims": [
                {"type": "pid", "pid": 9999, "process": "VENDORX_SRV.EXE"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_truncated_ref_matches_full_claim(self, reference_set):
        """Reference has truncated name, claim has full name."""
        reference_set["pid_to_process"][8888] = ["longprocess.ex"]
        finding = {
            "artifact": "longprocess.exe",
            "claims": [
                {"type": "pid", "pid": 8888, "process": "longprocess.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_short_prefix_no_false_match(self, reference_set):
        """Short prefix 'svc' must NOT match 'svchost.exe' (too short)."""
        reference_set["pid_to_process"][7777] = ["svchost.exe"]
        finding = {
            "artifact": "svc.exe",
            "claims": [
                {"type": "pid", "pid": 7777, "process": "svc.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_invented_pid(self, reference_set):
        finding = {
            "artifact": "unknown.exe",
            "claims": [{"type": "pid", "pid": 99999, "process": "unknown.exe"}],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"
        assert "not found" in result["checks"][0]["detail"].lower()

    def test_pid_reuse_accepted(self):
        """PID with 2 different process names -- both should be accepted."""
        ref = {
            "hashes": {},
            "pid_to_process": {448: ["NETSTAT.EXE", "cmd.exe"]},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        # Claim for the second process (cmd.exe) should MATCH
        finding = {
            "artifact": "cmd.exe",
            "claims": [{"type": "pid", "pid": 448, "process": "cmd.exe"}],
        }
        result = validate_finding(finding, ref)
        assert result["status"] == "MATCH"
        # Claim for the first process (NETSTAT.EXE) should also MATCH
        finding2 = {
            "artifact": "NETSTAT.EXE",
            "claims": [{"type": "pid", "pid": 448, "process": "NETSTAT.EXE"}],
        }
        result2 = validate_finding(finding2, ref)
        assert result2["status"] == "MATCH"

    def test_pid_reuse_logged(self):
        """PID reuse with unknown third process still accepted with reuse note."""
        ref = {
            "hashes": {},
            "pid_to_process": {448: ["NETSTAT.EXE", "cmd.exe"]},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        # Claim for a process NOT in the list -- reuse detected, accept
        finding = {
            "artifact": "explorer.exe",
            "claims": [{"type": "pid", "pid": 448, "process": "explorer.exe"}],
        }
        result = validate_finding(finding, ref)
        assert result["status"] == "MATCH"
        assert "reuse detected" in result["checks"][0]["detail"].lower()

    def test_pid_single_mismatch_rejected(self):
        """PID with 1 process name, wrong claim -- still rejected."""
        ref = {
            "hashes": {},
            "pid_to_process": {500: ["svchost.exe"]},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        finding = {
            "artifact": "evil.exe",
            "claims": [{"type": "pid", "pid": 500, "process": "evil.exe"}],
        }
        result = validate_finding(finding, ref)
        assert result["status"] == "MISMATCH"
        assert "cross-contamination" in result["checks"][0]["detail"].lower()


# ── Timestamp checks ─────────────────────────────────────────────────────

class TestTimestampValidation:
    def test_matching_timestamp(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "2024-11-14 02:31:07",
                 "artifact": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_timestamp_z_suffix_normalization(self, reference_set):
        """'14:22:07Z' vs '14:22:07' should MATCH after normalization."""
        reference_set["timestamps_per_artifact"]["test.exe"] = ["14:22:07"]
        finding = {
            "artifact": "test.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "14:22:07Z",
                 "artifact": "test.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_timestamp_tz_offset_normalization(self, reference_set):
        """'+00:00' stripped for comparison."""
        reference_set["timestamps_per_artifact"]["sys.exe"] = [
            "2018-08-30 13:52:22",
        ]
        finding = {
            "artifact": "sys.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "2018-08-30T13:52:22+00:00",
                 "artifact": "sys.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_timestamp_wrong_artifact(self, reference_set):
        finding = {
            "artifact": "ransom.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "2024-11-14 02:31:07",
                 "artifact": "ransom.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_different_tz_offsets_do_not_match(self, reference_set):
        """Timestamps with different TZ offsets must not validate as MATCH."""
        reference_set["timestamps_per_artifact"]["sys.exe"] = [
            "2018-08-30 13:52:22",  # stored as UTC
        ]
        # -05:00 means 18:52:22 UTC -- different absolute time
        finding = {
            "artifact": "sys.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "2018-08-30T13:52:22-05:00",
                 "artifact": "sys.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_invented_timestamp(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "timestamp",
                 "timestamp": "2099-01-01 00:00:00",
                 "artifact": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"


# ── Connection checks ────────────────────────────────────────────────────

class TestConnectionValidation:
    def test_matching_connection(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "192.0.2.129",
                 "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_wrong_process_for_connection(self, reference_set):
        finding = {
            "artifact": "svchost.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "192.0.2.129",
                 "process": "svchost.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_prefix_collision_no_false_match(self, reference_set):
        """192.0.2.122 must NOT match cached connection to 192.0.2.129."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "192.0.2.122",
                 "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_local_addr_collision_no_false_match(self, reference_set):
        """Claim for IP appearing in local_addr side must NOT match."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "192.0.2.111",
                 "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_exact_foreign_addr_match(self, reference_set):
        """Exact foreign_addr with correct PID returns MATCH."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "192.0.2.129",
                 "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_pid_multiple_connections_correct_and_wrong(self, reference_set):
        """PID with multiple connections: correct foreign_addr matches, wrong doesn't."""
        reference_set["connections"][
            "9005:192.0.2.111:8080->10.0.0.5:80"
        ] = "payload.exe"
        finding_ok = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "10.0.0.5",
                 "process": "payload.exe"},
            ],
        }
        assert validate_finding(finding_ok, reference_set)["status"] == "MATCH"

        finding_bad = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "10.0.0.99",
                 "process": "payload.exe"},
            ],
        }
        assert validate_finding(finding_bad, reference_set)["status"] == "MISMATCH"

    def test_truncated_connection_process_matches(self, reference_set):
        """Connection owner truncated at 15 chars still matches full process name."""
        reference_set["connections"][
            "5555:192.0.2.111:80->10.0.0.1:443"
        ] = "vendorx_srv.ex"
        finding = {
            "artifact": "VENDORX_SRV.EXE",
            "claims": [
                {"type": "connection", "pid": 5555,
                 "foreign_addr": "10.0.0.1",
                 "process": "VENDORX_SRV.EXE"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_invented_connection(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "connection", "pid": 9005,
                 "foreign_addr": "10.10.10.10",
                 "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"


# ── Multiple claims ──────────────────────────────────────────────────────

class TestMultipleClaims:
    def test_all_claims_match(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "payload.exe"},
                {"type": "pid", "pid": 9005, "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"
        assert len(result["checks"]) == 2

    def test_one_mismatch_blocks_entire_finding(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "payload.exe"},
                {"type": "pid", "pid": 4012, "process": "payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_no_claims_unresolved(self, reference_set):
        finding = {"artifact": "payload.exe", "claims": []}
        result = validate_finding(finding, reference_set)
        assert result["status"] == "UNRESOLVED"

    def test_missing_claims_key_unresolved(self, reference_set):
        finding = {"artifact": "payload.exe"}
        result = validate_finding(finding, reference_set)
        assert result["status"] == "UNRESOLVED"

    def test_unknown_claim_type_blocks(self, reference_set):
        """Unknown claim types make entire finding UNRESOLVED, not silently skipped."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "payload.exe"},
                {"type": "alien_claim", "foo": "bar"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "UNRESOLVED"
        assert "alien_claim" in result["detail"]

    def test_only_unknown_types_unresolved(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [{"type": "alien_claim", "foo": "bar"}],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "UNRESOLVED"


# ── Passthrough types (path, raw, artifact) ──────────────────────────────

class TestPassthroughTypes:
    def test_validator_accepts_path_type(self, reference_set):
        """'path' claim type must not cause UNRESOLVED -- it's valid for prefetch/amcache."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "pid", "pid": 9005, "process": "payload.exe"},
                {"type": "path", "value": r"C:\Windows\Temp\payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"
        assert "unrecognized" not in result.get("detail", "")

    def test_path_only_is_unresolved(self, reference_set):
        """Finding with ONLY path claims has no checkable claims -> UNRESOLVED."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "path", "value": r"C:\Windows\Temp\payload.exe"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "UNRESOLVED"
        assert "no recognized" in result["detail"]

    def test_raw_type_accepted(self, reference_set):
        """'raw' claim type (from string claim conversion) must not block."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "pid", "pid": 9005, "process": "payload.exe"},
                {"type": "raw", "value": "sqlsvc.exe ran malware"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_artifact_type_accepted(self, reference_set):
        """'artifact' claim type must not block."""
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "pid", "pid": 9005, "process": "payload.exe"},
                {"type": "artifact", "name": "prefetch"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"


# ── Edge cases ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_reference_set(self):
        ref = {
            "hashes": {}, "pid_to_process": {},
            "timestamps_per_artifact": {},
            "connections": {}, "paths": {},
        }
        finding = {
            "artifact": "payload.exe",
            "claims": [
                {"type": "hash", "sha1": "abc", "filename": "payload.exe"},
            ],
        }
        result = validate_finding(finding, ref)
        assert result["status"] == "MISMATCH"

    def test_filename_case_insensitive_hash(self, reference_set):
        """Filename comparison in hash check is case-insensitive."""
        finding = {
            "artifact": "PAYLOAD.EXE",
            "claims": [
                {"type": "hash",
                 "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                 "filename": "PAYLOAD.EXE"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_process_name_case_insensitive_pid(self, reference_set):
        finding = {
            "artifact": "SVCHOST.EXE",
            "claims": [
                {"type": "pid", "pid": 4012, "process": "SVCHOST.EXE"},
            ],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"


# ── Null / None field safety ─────────────────────────────────────────────


class TestNullFieldSafety:
    """Claims with None values must not crash the validator."""

    def test_hash_none_filename(self, reference_set):
        finding = {
            "artifact": "test",
            "claims": [{
                "type": "hash",
                "sha1": "a3f2c8d1e5b94f7260e8d3a1c9b47f52d6e81a30",
                "filename": None,
            }],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_hash_none_sha1(self, reference_set):
        finding = {
            "artifact": "test",
            "claims": [{"type": "hash", "sha1": None, "filename": "test"}],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_pid_none_process(self, reference_set):
        finding = {
            "artifact": "test",
            "claims": [{"type": "pid", "pid": 4012, "process": None}],
        }
        result = validate_finding(finding, reference_set)
        # Empty process vs "svchost.exe" => MISMATCH
        assert result["status"] == "MISMATCH"

    def test_connection_none_foreign_addr(self, reference_set):
        finding = {
            "artifact": "test",
            "claims": [{
                "type": "connection", "pid": 9005,
                "foreign_addr": None, "process": "payload.exe",
            }],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"

    def test_timestamp_none_artifact(self, reference_set):
        finding = {
            "artifact": "test",
            "claims": [{
                "type": "timestamp",
                "timestamp": "2024-11-14 02:31:07",
                "artifact": None,
            }],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MISMATCH"


# ── Case-insensitive timestamp artifacts ──────────────────────────────────


class TestTimestampCaseInsensitive:
    def test_uppercase_artifact_matches(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [{
                "type": "timestamp",
                "timestamp": "2024-11-14 02:31:07",
                "artifact": "PAYLOAD.EXE",
            }],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"

    def test_mixed_case_artifact_matches(self, reference_set):
        finding = {
            "artifact": "payload.exe",
            "claims": [{
                "type": "timestamp",
                "timestamp": "2024-11-14 02:31:07",
                "artifact": "Payload.exe",
            }],
        }
        result = validate_finding(finding, reference_set)
        assert result["status"] == "MATCH"
