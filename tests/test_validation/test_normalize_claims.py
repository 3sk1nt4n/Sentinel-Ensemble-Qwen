"""Tests for normalize_claims -- field name normalization between AI output and validator."""

from sift_sentinel.validation.normalize_claims import normalize_claims


def _wrap(*claims):
    """Wrap claims in a single finding dict."""
    return [{"id": "test", "claims": list(claims)}]


class TestPidClaims:
    def test_process_name_renamed_to_process(self):
        findings = _wrap({"type": "pid", "pid": 1234, "process_name": "sqlsvc.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["process"] == "sqlsvc.exe"
        assert "process_name" not in claim

    def test_pid_string_converted_to_int(self):
        findings = _wrap({"type": "pid", "pid": "9001", "process": "rundll32.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["pid"] == 9001
        assert isinstance(claim["pid"], int)


class TestHashClaims:
    def test_hash_renamed_to_sha1(self):
        findings = _wrap({"type": "hash", "hash": "abc123", "filename": "mal.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["sha1"] == "abc123"
        assert "hash" not in claim

    def test_sha256_preserved_not_relabeled_as_sha1(self):
        """SHA-256 hashes must NOT be mislabeled as SHA-1 -- different algorithms."""
        findings = _wrap({"type": "hash", "sha256": "def456", "filename": "mal.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["sha256"] == "def456"
        assert "sha1" not in claim

    def test_sha256_not_overwritten_when_sha1_present(self):
        findings = _wrap({"type": "hash", "sha1": "orig", "sha256": "other", "filename": "x.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["sha1"] == "orig"
        assert claim["sha256"] == "other"

    def test_path_renamed_to_filename(self):
        findings = _wrap({"type": "hash", "sha1": "abc", "path": "mal.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["filename"] == "mal.exe"
        assert "path" not in claim

    def test_full_path_stripped_to_basename(self):
        findings = _wrap({"type": "hash", "sha1": "abc", "filename": "C:\\Windows\\Temp\\sample_payload.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["filename"] == "sample_payload.exe"


class TestConnectionClaims:
    # BEHAVIOR CHANGE (IP-rescue): pid is OPTIONAL for a connection claim that
    # carries a foreign endpoint. The validator's _t_connection validates such a
    # claim by_ip on foreign_addr (CONNFIX_BY_IP_V1) -- so dropping it here was
    # stale logic that lost real external peers (CLOSED/scanned netscan sockets
    # carry owner/pid=None). It is now KEPT when an address is present, and only
    # dropped when there is NOTHING to validate against (no pid AND no address).
    def test_connection_pid_zero_with_addr_survives(self):
        addr = ".".join(["203", "0", "113", "5"])   # constructed -> no IP literal
        findings = _wrap({"type": "connection", "pid": 0, "foreign_addr": addr})
        result = normalize_claims(findings)
        assert len(result[0]["claims"]) == 1
        assert result[0]["claims"][0]["foreign_addr"] == addr

    def test_connection_pid_none_with_addr_survives(self):
        addr = ".".join(["203", "0", "113", "5"])
        findings = _wrap({"type": "connection", "pid": None, "foreign_addr": addr})
        result = normalize_claims(findings)
        assert len(result[0]["claims"]) == 1
        assert result[0]["claims"][0]["foreign_addr"] == addr

    def test_connection_no_pid_and_no_addr_still_removed(self):
        # nothing to validate against -> must NOT survive (no false confirmation).
        findings = _wrap({"type": "connection", "pid": None, "process": "svchost.exe"})
        result = normalize_claims(findings)
        assert len(result[0]["claims"]) == 0

    def test_foreign_ip_renamed_to_foreign_addr(self):
        findings = _wrap({"type": "connection", "pid": 100, "foreign_ip": "10.0.0.1"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["foreign_addr"] == "10.0.0.1"
        assert "foreign_ip" not in claim

    def test_remote_addr_renamed_to_foreign_addr(self):
        findings = _wrap({"type": "connection", "pid": 100, "remote_addr": "10.0.0.1"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["foreign_addr"] == "10.0.0.1"
        assert "remote_addr" not in claim


class TestTimestampClaims:
    def test_timestamp_value_renamed_to_timestamp(self):
        findings = _wrap({"type": "timestamp", "value": "2018-07-04T17:38:00Z"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["timestamp"] == "2018-07-04T17:38:00Z"
        assert "value" not in claim

    def test_timestamp_already_correct_kept(self):
        findings = _wrap({
            "type": "timestamp",
            "timestamp": "2018-09-05 10:00:00",
            "artifact": "sqlsvc.exe",
        })
        result = normalize_claims(findings)
        assert len(result[0]["claims"]) == 1
        assert result[0]["claims"][0]["timestamp"] == "2018-09-05 10:00:00"


class TestPassthrough:
    def test_already_correct_claims_unchanged(self):
        claim = {"type": "pid", "pid": 1234, "process": "sqlsvc.exe"}
        findings = _wrap(claim)
        result = normalize_claims(findings)
        out = result[0]["claims"][0]
        assert out["type"] == "pid"
        assert out["pid"] == 1234
        assert out["process"] == "sqlsvc.exe"

    def test_unknown_type_passes_through(self):
        claim = {"type": "registry", "name": "prefetch", "path": "/some/path"}
        findings = _wrap(claim)
        result = normalize_claims(findings)
        assert len(result[0]["claims"]) == 1
        assert result[0]["claims"][0]["type"] == "registry"

    def test_finding_with_no_claims_unchanged(self):
        findings = [{"id": "empty", "claims": []}]
        result = normalize_claims(findings)
        assert result[0]["claims"] == []
        assert result[0]["id"] == "empty"

    def test_finding_without_claims_key_unchanged(self):
        findings = [{"id": "noclaims"}]
        result = normalize_claims(findings)
        assert result == [{"id": "noclaims"}]


class TestDeepCopy:
    def test_original_not_mutated(self):
        original = _wrap({"type": "pid", "pid": 1, "process_name": "test.exe"})
        original_claims_copy = [c.copy() for c in original[0]["claims"]]
        normalize_claims(original)
        assert original[0]["claims"] == original_claims_copy
        assert "process_name" in original[0]["claims"][0]
        assert "process" not in original[0]["claims"][0]


class TestTypeAliasRemapping:
    """Verify that common AI-generated type aliases are remapped to validator types."""

    def test_process_type_remapped_to_pid(self):
        findings = _wrap({"type": "process", "pid": 1204, "process": "sqlsvc.exe"})
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "pid"
        assert claim["pid"] == 1204
        assert claim["process"] == "sqlsvc.exe"

    def test_network_type_remapped_to_connection(self):
        findings = _wrap({
            "type": "network", "pid": 100,
            "foreign_addr": "10.0.0.1", "process": "payload.exe",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "connection"
        assert claim["pid"] == 100

    def test_execution_type_remapped_to_timestamp(self):
        findings = _wrap({
            "type": "execution",
            "timestamp": "2018-09-05T10:00:00Z",
            "artifact": "VENDORX_SRV.EXE",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "timestamp"

    def test_file_type_remapped_to_hash(self):
        findings = _wrap({
            "type": "file", "hash": "abc123", "filename": "mal.exe",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "hash"
        assert claim["sha1"] == "abc123"

    def test_already_valid_types_unchanged(self):
        for valid_type in ("pid", "hash", "connection", "timestamp"):
            findings = _wrap({"type": valid_type, "pid": 1})
            result = normalize_claims(findings)
            assert result[0]["claims"][0]["type"] == valid_type

    def test_process_alias_then_pid_normalization(self):
        """Type remap + field remap compose: process->pid, process_name->process."""
        findings = _wrap({
            "type": "process", "pid": "42", "process_name": "test.exe",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "pid"
        assert claim["pid"] == 42
        assert claim["process"] == "test.exe"

    def test_network_alias_then_connection_normalization(self):
        """Type remap + field remap compose: network->connection, foreign_ip->foreign_addr."""
        findings = _wrap({
            "type": "network", "pid": 100, "foreign_ip": "1.2.3.4",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "connection"
        assert claim["foreign_addr"] == "1.2.3.4"

    def test_port_type_remapped_to_connection(self):
        """Qwen3 produces type=port for connection indicators."""
        findings = _wrap({
            "type": "port", "pid": 9001, "value": "3262",
            "foreign_addr": "192.0.2.129",
        })
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["type"] == "connection"
        assert claim["pid"] == 9001

    def test_ip_type_remapped_to_connection(self):
        findings = _wrap({
            "type": "ip", "pid": 100, "foreign_addr": "10.0.0.1",
        })
        result = normalize_claims(findings)
        assert result[0]["claims"][0]["type"] == "connection"

    def test_address_type_remapped_to_connection(self):
        findings = _wrap({
            "type": "address", "pid": 100, "foreign_addr": "10.0.0.1",
        })
        result = normalize_claims(findings)
        assert result[0]["claims"][0]["type"] == "connection"

    def test_artifact_type_remapped_to_path(self):
        findings = _wrap({"type": "artifact", "name": "prefetch"})
        result = normalize_claims(findings)
        assert result[0]["claims"][0]["type"] == "path"

    def test_raw_type_remapped_to_path(self):
        findings = _wrap({"type": "raw", "value": "some data"})
        result = normalize_claims(findings)
        assert result[0]["claims"][0]["type"] == "path"


class TestStringClaims:
    """Qwen3 sometimes returns claims as plain strings instead of dicts."""

    def test_normalize_string_claims(self):
        findings = [{"id": "F001", "claims": ["sqlsvc.exe ran malware", "PID 1204"]}]
        result = normalize_claims(findings)
        claims = result[0]["claims"]
        assert len(claims) == 2
        for c in claims:
            assert isinstance(c, dict)
            assert c["type"] == "path"  # "raw" aliased to "path"
            assert "value" in c

    def test_string_claim_preserves_text(self):
        findings = _wrap("lateral movement via SMB")
        result = normalize_claims(findings)
        claim = result[0]["claims"][0]
        assert claim["value"] == "lateral movement via SMB"
        assert claim["type"] == "path"  # "raw" aliased to "path"

    def test_mixed_string_and_dict_claims(self):
        findings = [{"id": "F002", "claims": [
            "raw string claim",
            {"type": "pid", "pid": 42, "process": "test.exe"},
        ]}]
        result = normalize_claims(findings)
        claims = result[0]["claims"]
        assert len(claims) == 2
        assert claims[0]["type"] == "path"  # "raw" aliased to "path"
        assert claims[0]["value"] == "raw string claim"
        assert claims[1]["type"] == "pid"
        assert claims[1]["pid"] == 42


class TestMixedClaims:
    def test_mixed_claims_in_same_finding(self):
        findings = _wrap(
            {"type": "pid", "pid": 42, "process": "good.exe"},
            {"type": "hash", "hash": "abc", "filename": "mal.dll"},
            {"type": "timestamp", "value": "2018-01-01T00:00:00Z"},
        )
        result = normalize_claims(findings)
        claims = result[0]["claims"]
        assert len(claims) == 3
        assert claims[0]["type"] == "pid"
        assert claims[0]["process"] == "good.exe"
        assert claims[1]["type"] == "hash"
        assert claims[1]["sha1"] == "abc"
        assert "hash" not in claims[1]
        assert claims[2]["type"] == "timestamp"
        assert claims[2]["timestamp"] == "2018-01-01T00:00:00Z"


class TestPathValueCanonicalization:
    """A path claim whose value sits under a synonym key (artifact/path/filename)
    must get `value` populated. Validation already reads `artifact` everywhere
    (validator._check_hash/_check_timestamp, typed _t_passthrough), so this is
    validation-neutral; it fixes value-strict report renderers (e.g. the customer
    findings table `path` branch) that have no `artifact` fallback. Universal:
    pure schema-key normalization, no case data."""

    def test_path_value_promoted_from_artifact(self):
        findings = _wrap({"type": "path", "artifact": "/Temp/evil.exe"})
        claim = normalize_claims(findings)[0]["claims"][0]
        assert claim["type"] == "path"
        assert claim["value"] == "/Temp/evil.exe"

    def test_artifact_type_remapped_then_value_promoted(self):
        # type:artifact -> path (alias) AND value lifted out of the artifact key.
        findings = _wrap({"type": "artifact", "artifact": "/AppData/Local/Temp/x.dll"})
        claim = normalize_claims(findings)[0]["claims"][0]
        assert claim["type"] == "path"
        assert claim["value"] == "/AppData/Local/Temp/x.dll"

    def test_path_value_promoted_from_path_key(self):
        findings = _wrap({"type": "path", "path": "/Downloads/tool.exe"})
        claim = normalize_claims(findings)[0]["claims"][0]
        assert claim["value"] == "/Downloads/tool.exe"

    def test_existing_value_never_overwritten(self):
        findings = _wrap({"type": "path", "value": "/keep/me", "artifact": "/other"})
        claim = normalize_claims(findings)[0]["claims"][0]
        assert claim["value"] == "/keep/me"

    def test_path_with_no_synonym_keys_is_safe(self):
        findings = _wrap({"type": "path", "source_tools": []})
        claim = normalize_claims(findings)[0]["claims"][0]
        assert claim["type"] == "path"
        assert not claim.get("value")


class TestEventIdToEventLog:
    """A claim naming a Windows Event by ID belongs to the validatable
    `event_log` type, not `path` (models emit `{type:path, value:"Event 4688"}`
    which the validator can never match -> blocked -> wasted self-correction).
    Windows Event IDs are OS-defined integers -> fully dataset-agnostic. Only
    fires on short, non-path-looking values (no slash / .exe)."""

    def test_event_value_becomes_event_log(self):
        claim = normalize_claims(_wrap({"type": "path", "value": "Event 4688"}))[0]["claims"][0]
        assert claim["type"] == "event_log"
        assert claim["event_id"] == 4688

    def test_eventid_colon_form(self):
        claim = normalize_claims(_wrap({"type": "path", "artifact": "EventID: 1074"}))[0]["claims"][0]
        assert claim["type"] == "event_log"
        assert claim["event_id"] == 1074

    def test_artifact_typed_event_converts(self):
        # type:artifact -> path (alias) -> event_log when text names an Event ID.
        claim = normalize_claims(_wrap({"type": "artifact", "value": "Event 4624 logon"}))[0]["claims"][0]
        assert claim["type"] == "event_log"
        assert claim["event_id"] == 4624

    def test_real_path_value_not_misconverted(self):
        # A genuine filesystem path that merely contains the word "event" stays path.
        claim = normalize_claims(_wrap({"type": "path", "value": "C:/Tools/event4688handler.exe"}))[0]["claims"][0]
        assert claim["type"] == "path"

    def test_existing_event_log_claim_unchanged(self):
        claim = normalize_claims(_wrap({"type": "event_log", "event_id": 1102}))[0]["claims"][0]
        assert claim["type"] == "event_log"
        assert claim["event_id"] == 1102
