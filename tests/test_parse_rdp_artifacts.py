"""Targeted unit tests for parse_rdp_artifacts (F7-A).

Covers closed-vocabulary contracts, EVTX event normalization against
mocked event dicts, Default.rdp / *.rdp profile parsing, registry MRU
and Servers value normalization with synthetic values, malformed-input
resilience, recovery_hints extraction, bounded-record behavior, and
dataset-agnostic safety. F7-A is parser + tests only -- no registry,
pipeline, or report integration is exercised here.
"""
from __future__ import annotations

import inspect
import textwrap
from pathlib import Path

import pytest

from sift_sentinel.tools.parse_rdp_artifacts import (
    RDP_CHANNEL_KINDS,
    RDP_EXTRACTION_METHODS,
    RDP_RECORD_REQUIRED_FIELDS,
    RDP_RECORD_TYPES,
    RDP_RECOVERY_HINT_REQUIRED_FIELDS,
    RDP_RECOVERY_HINT_STATUSES,
    RDP_RECOVERY_HINT_TYPES,
    RDP_SOURCE_KINDS,
    RDP_STATUSES,
    RDP_SUB_SOURCE_KEYS,
    RDP_SUB_SOURCE_STATUSES,
    find_rdp_recovery_hints,
    normalize_evtx_event,
    normalize_registry_value,
    normalize_registry_values,
    parse_rdp_artifacts,
    parse_rdp_profile_text,
)


# ── expected closed vocabularies (locked F7-A contract, BRAIN V3) ──────
#
# These mirror the BRAIN-approved schema:
#
#   - record types: 6 values covering the three EVTX session flows,
#     the two Terminal Server Client registry key groups, and the
#     .rdp profile file.
#   - source_kind: 3 values. The channel name (for EVTX) and the
#     specific registry key path (for hives) live in per-record fields,
#     NOT in source_kind.
#   - channel_kind: internal discriminator passed to normalize_evtx_event.

_EXPECTED_STATUSES = frozenset({
    "no_rdp_artifacts_found",
    "rdp_references_found",
    "rdp_artifacts_parsed",
    "rdp_artifacts_parsed_with_references",
})

_EXPECTED_RECORD_TYPES = frozenset({
    "rdp_session_inbound",
    "rdp_auth_event",
    "rdp_session_outbound",
    "rdp_mru_entry",
    "rdp_server_entry",
    "rdp_default_profile",
})

_EXPECTED_SOURCE_KINDS = frozenset({
    "evtx_file",
    "registry_hive",
    "rdp_profile_file",
})

_EXPECTED_CHANNEL_KINDS = frozenset({
    "local_session_manager",
    "remote_connection_manager",
    "rdp_client_operational",
})

_EXPECTED_EXTRACTION_METHODS = frozenset({
    "evtx_xml_event_record",
    "registry_value",
    "registry_subkey_values",
    "rdp_profile_directive",
})

_EXPECTED_SUB_SOURCE_STATUSES = frozenset({
    "ok",
    "not_found",
    "library_unavailable",
    "parse_error",
    "not_requested",
})

_EXPECTED_HINT_TYPES = frozenset({
    "rdp_artifact_path_reference",
    "rdp_binary_reference",
})

_EXPECTED_HINT_STATUSES = frozenset({
    "path_reference_only",
    "binary_reference_only",
})

_EXPECTED_RECORD_REQUIRED_FIELDS = (
    "type",
    "source_kind",
    "extraction_method",
    "source_file",
    "record_id",
    "raw_excerpt",
    "user",
    "host_or_target",
    "timestamp",
)

_EXPECTED_HINT_REQUIRED_FIELDS = (
    "type",
    "status",
    "path",
    "binary",
    "source_tool",
    "source_file",
    "raw_excerpt",
    "reason",
)

_EXPECTED_SUB_SOURCE_KEYS = (
    "evtx_local_session_manager",
    "evtx_remote_connection_manager",
    "evtx_rdp_client",
    "registry_mru",
    "registry_servers",
    "rdp_profile",
)


# ── closed-vocabulary constant tests ───────────────────────────────────


class TestClosedVocabularyConstants:
    """Pin the locked F7-A contract -- no drift without a schema bump."""

    def test_status_vocab_locked(self):
        assert RDP_STATUSES == _EXPECTED_STATUSES

    def test_record_type_vocab_locked(self):
        assert RDP_RECORD_TYPES == _EXPECTED_RECORD_TYPES

    def test_source_kind_vocab_locked(self):
        assert RDP_SOURCE_KINDS == _EXPECTED_SOURCE_KINDS

    def test_extraction_method_vocab_locked(self):
        assert RDP_EXTRACTION_METHODS == _EXPECTED_EXTRACTION_METHODS

    def test_sub_source_status_vocab_locked(self):
        assert RDP_SUB_SOURCE_STATUSES == _EXPECTED_SUB_SOURCE_STATUSES

    def test_recovery_hint_type_vocab_locked(self):
        assert RDP_RECOVERY_HINT_TYPES == _EXPECTED_HINT_TYPES

    def test_recovery_hint_status_vocab_locked(self):
        assert RDP_RECOVERY_HINT_STATUSES == _EXPECTED_HINT_STATUSES

    def test_record_required_fields_locked(self):
        assert (
            RDP_RECORD_REQUIRED_FIELDS == _EXPECTED_RECORD_REQUIRED_FIELDS
        )

    def test_hint_required_fields_locked(self):
        assert (
            RDP_RECOVERY_HINT_REQUIRED_FIELDS
            == _EXPECTED_HINT_REQUIRED_FIELDS
        )

    def test_sub_source_keys_locked(self):
        assert tuple(RDP_SUB_SOURCE_KEYS) == _EXPECTED_SUB_SOURCE_KEYS

    def test_channel_kinds_vocab_locked(self):
        assert RDP_CHANNEL_KINDS == _EXPECTED_CHANNEL_KINDS


# ── normalize_evtx_event (mocked events) ───────────────────────────────


class TestNormalizeEvtxEvent:
    def test_returns_none_for_non_dict(self):
        for bad in (None, "str", 42, [], ()):
            assert normalize_evtx_event(
                bad, "local_session_manager", "x.evtx",
            ) is None

    def test_returns_none_for_unrecognized_channel_kind(self):
        event = {
            "EventID": 21,
            "TimeCreated": "2024-01-01T12:00:00.000Z",
            "EventData": {"User": "DOMAIN\\alice"},
        }
        assert normalize_evtx_event(
            event, "not_a_channel_kind", "x.evtx",
        ) is None
        # The old long source_kind strings are no longer valid channel
        # kinds and must return None.
        assert normalize_evtx_event(
            event, "evtx_terminalservices_localsessionmanager", "x.evtx",
        ) is None
        assert normalize_evtx_event(
            event, "registry_hive", "x.evtx",
        ) is None

    def test_lsm_event_21_normalizes(self):
        event = {
            "EventID": 21,
            "TimeCreated": "2024-03-15T09:00:00.000Z",
            "Provider": (
                "Microsoft-Windows-TerminalServices-"
                "LocalSessionManager"
            ),
            "Computer": "HOST-Z",
            "EventRecordID": 4242,
            "EventData": {
                "User": "EXAMPLECORP\\alice",
                "SessionID": "2",
                "Source Network Address": "10.20.30.40",
            },
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "/mnt/x/Windows/System32/winevt/Logs/"
            "Microsoft-Windows-TerminalServices-LocalSessionManager"
            "%4Operational.evtx",
        )
        assert rec is not None
        assert rec["type"] == "rdp_session_inbound"
        assert rec["source_kind"] == "evtx_file"
        assert rec["extraction_method"] == "evtx_xml_event_record"
        assert rec["event_id"] == 21
        # Channel name is the Microsoft canonical channel -- NOT the
        # source_kind value.
        assert (
            "TerminalServices-LocalSessionManager" in rec["channel"]
        )
        assert rec["user"] == "EXAMPLECORP\\alice"
        assert rec["host_or_target"] == "10.20.30.40"
        assert rec["timestamp"] == "2024-03-15T09:00:00.000Z"
        assert "4242" in rec["record_id"]
        assert rec["raw_excerpt"]
        for f in _EXPECTED_RECORD_REQUIRED_FIELDS:
            assert f in rec, f"missing required field: {f}"

    @pytest.mark.parametrize("eid", [21, 22, 23, 24, 25, 39, 40])
    def test_lsm_all_whitelisted_eids_normalize(self, eid):
        event = {
            "EventID": eid,
            "TimeCreated": "2024-01-01T00:00:00Z",
            "EventData": {"User": "u"},
            "EventRecordID": eid,
        }
        rec = normalize_evtx_event(
            event, "local_session_manager", "lsm.evtx",
        )
        assert rec is not None
        assert rec["type"] == "rdp_session_inbound"
        assert rec["event_id"] == eid

    def test_lsm_non_whitelisted_eid_returns_none(self):
        # Events outside the LSM whitelist -- must be dropped.
        for eid in (1, 1024, 4624, 4776, 7036):
            event = {
                "EventID": eid,
                "EventData": {},
                "EventRecordID": 1,
            }
            rec = normalize_evtx_event(
                event, "local_session_manager", "lsm.evtx",
            )
            assert rec is None, f"EID {eid} must be dropped for LSM"

    def test_rcm_event_1149_normalizes(self):
        event = {
            "EventID": 1149,
            "TimeCreated": "2024-03-15T09:05:00.000Z",
            "EventRecordID": 9,
            "EventData": {
                "User": "bob",
                "Domain": "EXAMPLECORP",
                "Source Network Address": "192.0.2.55",
            },
        }
        rec = normalize_evtx_event(
            event,
            "remote_connection_manager",
            "rcm.evtx",
        )
        assert rec is not None
        assert rec["type"] == "rdp_auth_event"
        assert rec["source_kind"] == "evtx_file"
        assert rec["user"] == "bob"
        assert rec["host_or_target"] == "192.0.2.55"
        assert rec["event_id"] == 1149

    def test_rcm_non_1149_returns_none(self):
        """RCM channel whitelist is strict: only EID 1149."""
        for eid in (261, 1147, 1148, 21):
            event = {"EventID": eid, "EventData": {}, "EventRecordID": 1}
            rec = normalize_evtx_event(
                event, "remote_connection_manager", "rcm.evtx",
            )
            assert rec is None, f"RCM EID {eid} must be dropped"

    def test_rdpclient_event_1024_normalizes_outbound_target(self):
        event = {
            "EventID": 1024,
            "TimeCreated": "2024-03-15T09:10:00.000Z",
            "EventRecordID": 77,
            "EventData": {"ConnectionName": "target-host-1.example.local"},
        }
        rec = normalize_evtx_event(
            event, "rdp_client_operational", "rdpclient.evtx",
        )
        assert rec is not None
        assert rec["type"] == "rdp_session_outbound"
        assert rec["source_kind"] == "evtx_file"
        assert rec["host_or_target"] == "target-host-1.example.local"
        # No User EventData -> user stays None (verbatim only).
        assert rec["user"] is None

    @pytest.mark.parametrize(
        "eid",
        [1024, 1025, 1026, 1027, 1028, 1029, 1102, 1103, 1105],
    )
    def test_rdpclient_whitelisted_eids_normalize(self, eid):
        event = {
            "EventID": eid,
            "TimeCreated": "2024-01-01T00:00:00Z",
            "EventData": {"ConnectionName": "target"},
            "EventRecordID": eid,
        }
        rec = normalize_evtx_event(
            event, "rdp_client_operational", "c.evtx",
        )
        assert rec is not None
        assert rec["type"] == "rdp_session_outbound"

    def test_rdpclient_non_whitelisted_eid_returns_none(self):
        for eid in (21, 4624, 7036):
            event = {"EventID": eid, "EventData": {}, "EventRecordID": 1}
            rec = normalize_evtx_event(
                event, "rdp_client_operational", "c.evtx",
            )
            assert rec is None, f"RDPClient EID {eid} must be dropped"

    def test_event_without_eventrecordid_generates_stable_id(self):
        event = {
            "EventID": 21,
            "TimeCreated": "2024-01-01T00:00:00.000Z",
            "EventData": {"User": "x"},
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        # Stable composite id contains channel_kind + event_id + ts.
        assert "local_session_manager" in rec["record_id"]
        assert "21" in rec["record_id"]

    def test_event_with_explicit_record_id_uses_it(self):
        event = {
            "EventID": 21,
            "TimeCreated": "2024-01-01T00:00:00.000Z",
            "EventData": {},
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
            record_id="custom-id-42",
        )
        assert rec["record_id"] == "custom-id-42"

    def test_event_with_missing_timestamp_still_builds_record(self):
        event = {
            "EventID": 21,
            "EventData": {"User": "x"},
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        assert rec["timestamp"] is None

    def test_event_with_empty_eventdata_fills_none(self):
        event = {
            "EventID": 21,
            "TimeCreated": "2024-01-01T00:00:00.000Z",
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        assert rec["user"] is None
        assert rec["host_or_target"] is None

    def test_event_with_raw_xml_preserves_excerpt(self):
        xml = (
            "<Event><System><EventID>21</EventID></System>"
            "<EventData><Data Name='User'>alice</Data></EventData></Event>"
        )
        event = {
            "EventID": 21,
            "TimeCreated": "2024-01-01T00:00:00.000Z",
            "EventData": {"User": "alice"},
            "raw_xml": xml,
        }
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        assert "EventID" in rec["raw_excerpt"]

    def test_all_channels_produce_closed_vocab_records(self):
        # Per-channel valid EID + matching channel_kind.
        cases = [
            ("local_session_manager", 21, "rdp_session_inbound"),
            ("remote_connection_manager", 1149, "rdp_auth_event"),
            ("rdp_client_operational", 1024, "rdp_session_outbound"),
        ]
        for channel_kind, eid, expected_type in cases:
            event = {
                "EventID": eid,
                "TimeCreated": "2024-01-01T00:00:00.000Z",
                "EventData": {},
            }
            rec = normalize_evtx_event(event, channel_kind, "x.evtx")
            assert rec is not None
            assert rec["source_kind"] == "evtx_file"
            assert rec["source_kind"] in _EXPECTED_SOURCE_KINDS
            assert rec["type"] == expected_type
            assert rec["type"] in _EXPECTED_RECORD_TYPES
            assert rec["extraction_method"] in _EXPECTED_EXTRACTION_METHODS

    def test_record_channel_carries_microsoft_channel_name(self):
        event = {"EventID": 21, "EventData": {}, "EventRecordID": 1}
        rec = normalize_evtx_event(
            event, "local_session_manager", "x.evtx",
        )
        assert rec is not None
        assert rec["channel"] == (
            "Microsoft-Windows-TerminalServices-"
            "LocalSessionManager/Operational"
        )

    def test_channel_override_from_event_dict_takes_precedence(self):
        event = {
            "EventID": 21,
            "EventData": {},
            "EventRecordID": 1,
            "Channel": "Custom-Channel-Name",
        }
        rec = normalize_evtx_event(
            event, "local_session_manager", "x.evtx",
        )
        assert rec is not None
        assert rec["channel"] == "Custom-Channel-Name"

    def test_no_confidence_field_on_record(self):
        event = {"EventID": 21, "EventData": {"User": "x"}}
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        assert "confidence" not in rec

    def test_no_findings_field_on_record(self):
        event = {"EventID": 21, "EventData": {"User": "x"}}
        rec = normalize_evtx_event(
            event,
            "local_session_manager",
            "x.evtx",
        )
        assert rec is not None
        assert "findings" not in rec
        assert "finding" not in rec


# ── parse_rdp_profile_text (Default.rdp / *.rdp) ───────────────────────


class TestRdpProfileParsing:
    def test_none_for_non_string(self):
        for bad in (None, 42, [], {}):
            assert parse_rdp_profile_text(bad, "x.rdp") is None

    def test_none_for_empty(self):
        assert parse_rdp_profile_text("", "x.rdp") is None

    def test_none_for_text_without_directives(self):
        assert parse_rdp_profile_text(
            "just some random text\nwith no directives\n",
            "x.rdp",
        ) is None

    def test_parses_full_address_and_username(self):
        text = textwrap.dedent(
            """\
            screen mode id:i:2
            use multimon:i:0
            desktopwidth:i:1920
            full address:s:server.example.local
            username:s:DOMAIN\\alice
            """
        )
        rec = parse_rdp_profile_text(text, "/x/Default.rdp")
        assert rec is not None
        assert rec["type"] == "rdp_default_profile"
        assert rec["source_kind"] == "rdp_profile_file"
        assert rec["extraction_method"] == "rdp_profile_directive"
        assert rec["host_or_target"] == "server.example.local"
        assert rec["user"] == "DOMAIN\\alice"
        assert rec["timestamp"] is None
        for f in _EXPECTED_RECORD_REQUIRED_FIELDS:
            assert f in rec

    def test_falls_back_to_alternate_full_address(self):
        text = textwrap.dedent(
            """\
            alternate full address:s:alt.example.local
            desktopwidth:i:1920
            """
        )
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        assert rec["host_or_target"] == "alt.example.local"

    def test_host_or_target_left_none_when_no_host_directive(self):
        text = "desktopwidth:i:1920\nscreen mode id:i:2\n"
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        assert rec["host_or_target"] is None

    def test_profile_directives_dict_present(self):
        text = textwrap.dedent(
            """\
            full address:s:srv.example.local
            desktopwidth:i:1920
            """
        )
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        dirs = rec["profile_directives"]
        assert dirs["full address"] == "srv.example.local"
        assert dirs["desktopwidth"] == "1920"

    def test_record_is_json_shaped(self):
        """All required fields present, no disallowed fields."""
        text = "full address:s:srv.example.local\n"
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        assert rec["type"] in _EXPECTED_RECORD_TYPES
        assert rec["source_kind"] in _EXPECTED_SOURCE_KINDS
        assert rec["extraction_method"] in _EXPECTED_EXTRACTION_METHODS
        assert "confidence" not in rec
        assert "findings" not in rec

    def test_duplicate_directive_keeps_first(self):
        text = (
            "full address:s:first.example.local\n"
            "full address:s:second.example.local\n"
        )
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        assert rec["host_or_target"] == "first.example.local"

    def test_malformed_lines_dont_crash(self):
        text = (
            "full address:s:srv.example.local\n"
            "not a directive\n"
            ":::\n"
            "\n"
            "garbage\n"
        )
        rec = parse_rdp_profile_text(text, "x.rdp")
        assert rec is not None
        assert rec["host_or_target"] == "srv.example.local"


# ── registry MRU / Servers normalization ───────────────────────────────


class TestRegistryNormalization:
    # ── classification ────────────────────────────────────────────────

    def test_mru_key_classified(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "target-host.example.local",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["type"] == "rdp_mru_entry"
        # Coarse source_kind -- the specific key suffix is in
        # registry_key_path, not in source_kind.
        assert rec["source_kind"] == "registry_hive"
        assert rec["extraction_method"] == "registry_value"

    def test_servers_key_classified(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Servers\\"
                "target-host.example.local"
            ),
            "value_name": "UsernameHint",
            "value_data": "DOMAIN\\alice",
            "subkey_name": "target-host.example.local",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["type"] == "rdp_server_entry"
        assert rec["source_kind"] == "registry_hive"
        assert rec["extraction_method"] == "registry_subkey_values"

    def test_non_rdp_key_returns_none(self):
        entry = {
            "key_path": "Software\\Microsoft\\Windows\\CurrentVersion",
            "value_name": "ProgramFilesDir",
            "value_data": r"C:\Program Files",
        }
        assert normalize_registry_value(entry) is None

    def test_hkcu_prefixed_key_accepted(self):
        entry = {
            "key_path": (
                "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "target.example",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["type"] == "rdp_mru_entry"

    def test_hkey_current_user_prefix_accepted(self):
        entry = {
            "key_path": (
                "HKEY_CURRENT_USER\\Software\\Microsoft\\"
                "Terminal Server Client\\Default"
            ),
            "value_name": "MRU2",
            "value_data": "another.example",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["type"] == "rdp_mru_entry"

    def test_hku_with_sid_root_accepted(self):
        entry = {
            "key_path": (
                "HKEY_USERS\\S-1-5-21-111-222-333-1001\\Software\\"
                "Microsoft\\Terminal Server Client\\Servers\\"
                "srv.example"
            ),
            "value_name": "UsernameHint",
            "value_data": "alice",
            "subkey_name": "srv.example",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["type"] == "rdp_server_entry"

    # ── verbatim-field extraction ─────────────────────────────────────

    def test_mru_host_or_target_from_value_data(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "target.example",
        }
        rec = normalize_registry_value(entry)
        assert rec["host_or_target"] == "target.example"
        assert rec["user"] is None

    def test_servers_host_or_target_from_subkey_name(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Servers\\"
                "srv.example"
            ),
            "value_name": "UsernameHint",
            "value_data": "alice",
            "subkey_name": "srv.example",
        }
        rec = normalize_registry_value(entry)
        assert rec["host_or_target"] == "srv.example"
        assert rec["user"] == "alice"

    def test_servers_non_username_hint_leaves_user_none(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Servers\\"
                "srv.example"
            ),
            "value_name": "CertHash",
            "value_data": "abc123",
            "subkey_name": "srv.example",
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["user"] is None
        assert rec["host_or_target"] == "srv.example"

    def test_record_contains_required_fields(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "x.example",
        }
        rec = normalize_registry_value(entry)
        for f in _EXPECTED_RECORD_REQUIRED_FIELDS:
            assert f in rec, f"missing required field: {f}"

    def test_non_dict_entry_returns_none(self):
        for bad in (None, "str", 42, [], ()):
            assert normalize_registry_value(bad) is None

    def test_entry_without_key_path_returns_none(self):
        assert normalize_registry_value({"value_name": "X"}) is None

    def test_value_data_coerced_to_string(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": 12345,
        }
        rec = normalize_registry_value(entry)
        assert rec is not None
        assert rec["host_or_target"] == "12345"

    def test_timestamp_passthrough_when_string(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "x.example",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        rec = normalize_registry_value(entry)
        assert rec["timestamp"] == "2024-01-01T00:00:00Z"

    def test_timestamp_none_when_missing(self):
        entry = {
            "key_path": (
                "Software\\Microsoft\\Terminal Server Client\\Default"
            ),
            "value_name": "MRU0",
            "value_data": "x.example",
        }
        rec = normalize_registry_value(entry)
        assert rec["timestamp"] is None

    # ── batch normalization ───────────────────────────────────────────

    def test_normalize_list_drops_non_rdp_keys(self):
        entries = [
            {
                "key_path": (
                    "Software\\Microsoft\\Terminal Server Client\\Default"
                ),
                "value_name": "MRU0",
                "value_data": "x.example",
            },
            {
                "key_path": "Software\\Microsoft\\Windows\\CurrentVersion",
                "value_name": "X",
                "value_data": "Y",
            },
            {
                "key_path": (
                    "Software\\Microsoft\\Terminal Server Client\\Servers\\"
                    "x.example"
                ),
                "value_name": "UsernameHint",
                "value_data": "alice",
                "subkey_name": "x.example",
            },
        ]
        recs = normalize_registry_values(entries)
        assert len(recs) == 2
        assert {r["type"] for r in recs} == {
            "rdp_mru_entry",
            "rdp_server_entry",
        }

    def test_normalize_list_none_returns_empty(self):
        assert normalize_registry_values(None) == []

    def test_normalize_list_non_list_returns_empty(self):
        assert normalize_registry_values({}) == []  # type: ignore[arg-type]
        assert normalize_registry_values("str") == []  # type: ignore[arg-type]


# ── recovery_hints extraction ──────────────────────────────────────────


class TestRecoveryHints:
    def test_none_input_returns_empty(self):
        assert find_rdp_recovery_hints(None) == []

    def test_non_dict_input_returns_empty(self):
        for bad in ("str", 42, [], (), 1.5):
            assert find_rdp_recovery_hints(bad) == []  # type: ignore[arg-type]

    def test_empty_dict_returns_empty(self):
        assert find_rdp_recovery_hints({}) == []

    def test_malformed_envelopes_tolerated(self):
        for bad in (
            {"x": None},
            {"x": "str"},
            {"x": 42},
            {"x": {"output": "not a list"}},
            {"x": {"output": None}},
            {"x": {}},
        ):
            assert find_rdp_recovery_hints(bad) == []

    def test_non_dict_records_tolerated(self):
        env = {"output": [
            None, "str", 42, ["list"],
            {"Name": (
                r"\Windows\System32\winevt\Logs\\"
                r"Microsoft-Windows-TerminalServices-"
                r"LocalSessionManager%4Operational.evtx"
            )},
        ]}
        hints = find_rdp_recovery_hints({"vol_filescan": env})
        assert len(hints) == 1
        assert hints[0]["type"] == "rdp_artifact_path_reference"

    def test_terminalservices_evtx_path_hint(self):
        env = {"output": [{
            "Name": (
                r"\Windows\System32\winevt\Logs\\"
                r"Microsoft-Windows-TerminalServices-"
                r"LocalSessionManager%4Operational.evtx"
            ),
            "Offset": 1,
        }]}
        hints = find_rdp_recovery_hints({"vol_filescan": env})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "rdp_artifact_path_reference"
        assert h["status"] == "path_reference_only"
        assert "TerminalServices-LocalSessionManager" in h["path"]
        assert h["path"].endswith(".evtx")
        assert h["binary"] is None
        assert h["source_tool"] == "vol_filescan"
        assert h["source_file"] == "tool_outputs/vol_filescan.json"
        for f in _EXPECTED_HINT_REQUIRED_FIELDS:
            assert f in h

    def test_default_rdp_path_hint(self):
        env = {"output": [{
            "Name": r"\Users\bob\Documents\Default.rdp",
        }]}
        hints = find_rdp_recovery_hints({"vol_filescan": env})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "rdp_artifact_path_reference"
        assert h["path"].endswith(".rdp")
        assert h["path"].startswith("/Users/")

    def test_rdp_binary_reference_mstsc(self):
        env = {"output": [{
            "ImageFileName": "mstsc.exe",
            "PID": 1234,
        }]}
        hints = find_rdp_recovery_hints({"vol_pslist": env})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "rdp_binary_reference"
        assert h["status"] == "binary_reference_only"
        assert h["binary"] == "mstsc.exe"
        assert h["path"] is None

    def test_rdp_binary_reference_termsrv(self):
        env = {"output": [{"Message": "loaded termsrv.dll"}]}
        hints = find_rdp_recovery_hints({"vol_ldrmodules": env})
        assert len(hints) == 1
        assert hints[0]["binary"] == "termsrv.dll"

    def test_rdp_binary_reference_rdpdr(self):
        env = {"output": [{"Message": "driver rdpdr.sys loaded"}]}
        hints = find_rdp_recovery_hints({"vol_modules": env})
        assert len(hints) == 1
        assert hints[0]["binary"] == "rdpdr.sys"

    def test_rdp_binary_reference_tsclient(self):
        env = {"output": [{
            "CommandLine": r"dir \\tsclient\c\Users",
        }]}
        hints = find_rdp_recovery_hints({"vol_cmdline": env})
        assert len(hints) == 1
        assert hints[0]["binary"] == "tsclient"

    def test_path_hint_normalizes_device_prefix(self):
        env = {"output": [{
            "Name": (
                r"\Device\HarddiskVolume2\Windows\System32\winevt\Logs\\"
                r"Microsoft-Windows-TerminalServices-"
                r"RemoteConnectionManager%4Operational.evtx"
            ),
        }]}
        hints = find_rdp_recovery_hints({"vol_handles": env})
        assert len(hints) == 1
        p = hints[0]["path"]
        assert "Device" not in p
        assert "HarddiskVolume" not in p
        assert p.endswith(".evtx")

    def test_path_and_binary_same_record_path_wins(self):
        """When a single record field mentions both a path and a binary,
        only the path hint is emitted (binary hints are fallback)."""
        env = {"output": [{
            "Message": (
                "Loaded mstsc.exe and accessed "
                r"\Windows\System32\winevt\Logs\\"
                r"Microsoft-Windows-TerminalServices-RDPClient"
                r"%4Operational.evtx"
            ),
        }]}
        hints = find_rdp_recovery_hints({"vol_pslist": env})
        types = {h["type"] for h in hints}
        assert "rdp_artifact_path_reference" in types
        assert "rdp_binary_reference" not in types

    def test_duplicate_path_hints_deduped(self):
        path = (
            r"\Windows\System32\winevt\Logs\\"
            r"Microsoft-Windows-TerminalServices-"
            r"LocalSessionManager%4Operational.evtx"
        )
        env = {"output": [
            {"Name": path, "Offset": 1},
            {"Name": path, "Offset": 2},
            {"Name": path, "Offset": 3},
        ]}
        hints = find_rdp_recovery_hints({"vol_filescan": env})
        assert len(hints) == 1

    def test_distinct_tools_yield_separate_hints(self):
        path = (
            r"\Windows\System32\winevt\Logs\\"
            r"Microsoft-Windows-TerminalServices-"
            r"LocalSessionManager%4Operational.evtx"
        )
        envelopes = {
            "vol_filescan": {"output": [{"Name": path}]},
            "vol_handles": {"output": [{"Name": path}]},
        }
        hints = find_rdp_recovery_hints(envelopes)
        assert sorted({h["source_tool"] for h in hints}) == [
            "vol_filescan", "vol_handles",
        ]

    def test_deterministic_ordering(self):
        envelopes = {
            "z_tool": {"output": [
                {"Name": r"\Users\u\Documents\B.rdp"},
            ]},
            "a_tool": {"output": [
                {"Name": r"\Users\u\Documents\A.rdp"},
            ]},
        }
        a = find_rdp_recovery_hints(envelopes)
        b = find_rdp_recovery_hints(envelopes)
        assert a == b

    def test_hints_use_closed_type_vocab(self):
        envelopes = {
            "vol_filescan": {"output": [
                {"Name": r"\Users\u\Documents\Default.rdp"},
            ]},
            "vol_pslist": {"output": [
                {"ImageFileName": "mstsc.exe"},
            ]},
        }
        hints = find_rdp_recovery_hints(envelopes)
        assert len(hints) >= 2
        for h in hints:
            assert h["type"] in _EXPECTED_HINT_TYPES
            assert h["status"] in _EXPECTED_HINT_STATUSES
            for f in _EXPECTED_HINT_REQUIRED_FIELDS:
                assert f in h


# ── top-level signature (accepted F7 design) ───────────────────────────


class TestTopLevelSignature:
    """The top-level entry must match the BRAIN-accepted signature
    exactly -- keyword parameter names, defaults, and ordering are part
    of the public API contract.
    """

    def test_parameter_names_and_defaults(self):
        sig = inspect.signature(parse_rdp_artifacts)
        expected = [
            ("mount_path", None),
            ("disk_image_path", None),
            ("staging_dir", None),
            ("tool_outputs", None),
            ("max_events_per_channel", 5000),
            ("max_records_per_source", 2000),
            ("max_rdp_files_per_user", 25),
            ("timeout_seconds_per_sub", 60),
            ("include_eventlogs", True),
            ("include_registry", True),
            ("include_default_rdp", True),
        ]
        actual = [(n, p.default) for n, p in sig.parameters.items()]
        assert actual == expected, (
            f"signature mismatch.\nexpected: {expected}\nactual: {actual}"
        )


# ── top-level envelope / disk walk ─────────────────────────────────────


class TestEnvelopeShape:
    def test_missing_mount_envelope(self, tmp_path):
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path / "nope"),
        )
        assert result["tool"] == "parse_rdp_artifacts"
        assert result["tool_name"] == "parse_rdp_artifacts"
        assert result["record_count"] == 0
        assert result["records"] == []
        assert result["output"] == []
        assert result["candidate_files"] == []
        assert result["searched_paths"] == []
        assert result["status"] == "no_rdp_artifacts_found"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["recovery_hints"] == []
        # Reason mentions no candidate files were found.
        assert "no RDP candidate files" in result["reason"]
        for key in (
            "tool", "tool_name", "evidence_path", "record_count",
            "records", "output", "candidate_files", "searched_paths",
            "sub_source_status", "status", "reason", "errors",
            "recovery_hints",
        ):
            assert key in result, f"missing envelope key: {key}"

    def test_sub_source_status_keys_stable(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert set(result["sub_source_status"].keys()) == set(
            _EXPECTED_SUB_SOURCE_KEYS
        )
        for v in result["sub_source_status"].values():
            assert v in _EXPECTED_SUB_SOURCE_STATUSES

    def test_registry_sub_sources_library_unavailable_when_lib_missing(
        self, tmp_path,
    ):
        """With include_registry=True and python-registry not installed,
        the two registry sub-sources honestly report
        ``library_unavailable`` -- not a crash, not a fake record."""
        try:
            import Registry  # noqa: F401
            pytest.skip("python-registry installed; lib-missing path N/A")
        except ImportError:
            pass
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        ss = result["sub_source_status"]
        assert ss["registry_mru"] == "library_unavailable"
        assert ss["registry_servers"] == "library_unavailable"

    def test_status_rdp_references_found_hints_only(self, tmp_path):
        env = {"output": [{"Name": r"\Users\u\Documents\Default.rdp"}]}
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={"vol_filescan": env},
        )
        assert result["status"] == "rdp_references_found"
        assert result["records"] == []
        assert result["recovery_hints"]

    def test_status_rdp_artifacts_parsed_with_references(self, tmp_path):
        # Put a real .rdp profile on disk -> records.
        user = tmp_path / "Users" / "alice" / "Documents"
        user.mkdir(parents=True)
        (user / "Default.rdp").write_text(
            "full address:s:target.example\n", encoding="utf-8",
        )
        env = {"output": [{"Name": r"\Users\u\Documents\Default.rdp"}]}
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={"vol_filescan": env},
        )
        assert result["status"] == "rdp_artifacts_parsed_with_references"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"]
        assert result["recovery_hints"]

    def test_recovery_hints_never_merged_into_records(self, tmp_path):
        env = {"output": [{"Name": r"\Users\u\Documents\Default.rdp"}]}
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={"vol_filescan": env},
        )
        assert result["records"] == []
        assert result["output"] == []
        assert result["recovery_hints"]  # and yet hints exist


# ── include_* flag gating ──────────────────────────────────────────────


class TestIncludeFlags:
    def test_include_eventlogs_false_marks_evtx_not_requested(
        self, tmp_path,
    ):
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            include_eventlogs=False,
        )
        ss = result["sub_source_status"]
        for sk in (
            "evtx_local_session_manager",
            "evtx_remote_connection_manager",
            "evtx_rdp_client",
        ):
            assert ss[sk] == "not_requested"

    def test_include_registry_false_marks_registry_not_requested(
        self, tmp_path,
    ):
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            include_registry=False,
        )
        ss = result["sub_source_status"]
        assert ss["registry_mru"] == "not_requested"
        assert ss["registry_servers"] == "not_requested"

    def test_include_default_rdp_false_marks_profile_not_requested(
        self, tmp_path,
    ):
        user = tmp_path / "Users" / "alice" / "Documents"
        user.mkdir(parents=True)
        (user / "Default.rdp").write_text(
            "full address:s:x.example\n", encoding="utf-8",
        )
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            include_default_rdp=False,
        )
        assert result["sub_source_status"]["rdp_profile"] == (
            "not_requested"
        )
        # And no rdp_default_profile records are emitted.
        assert all(
            r["type"] != "rdp_default_profile" for r in result["records"]
        )

    def test_all_includes_false_yields_empty_envelope(self, tmp_path):
        user = tmp_path / "Users" / "alice" / "Documents"
        user.mkdir(parents=True)
        (user / "Default.rdp").write_text(
            "full address:s:x.example\n", encoding="utf-8",
        )
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            include_eventlogs=False,
            include_registry=False,
            include_default_rdp=False,
        )
        assert result["records"] == []
        assert result["status"] == "no_rdp_artifacts_found"
        for v in result["sub_source_status"].values():
            assert v == "not_requested"


# ── disk walk: .rdp profiles ───────────────────────────────────────────


def _make_user_dir(tmp_path: Path, name: str = "alice") -> Path:
    user = tmp_path / "Users" / name
    (user / "Documents").mkdir(parents=True)
    (user / "Desktop").mkdir(parents=True)
    (user / "Downloads").mkdir(parents=True)
    return user


class TestDiskRdpProfileWalk:
    def test_default_rdp_parsed_from_disk(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        (user / "Documents" / "Default.rdp").write_text(
            "full address:s:srv.example.local\n"
            "username:s:alice\n",
            encoding="utf-8",
        )
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert result["status"] in (
            "rdp_artifacts_parsed",
            "rdp_artifacts_parsed_with_references",
        )
        assert result["record_count"] == 1
        rec = result["records"][0]
        assert rec["type"] == "rdp_default_profile"
        assert rec["source_kind"] == "rdp_profile_file"
        assert rec["host_or_target"] == "srv.example.local"
        assert rec["user"] == "alice"
        assert result["sub_source_status"]["rdp_profile"] == "ok"

    def test_custom_rdp_profile_parsed(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        (user / "Desktop" / "customer-gateway.rdp").write_text(
            "gatewayhostname:s:gateway.example\n"
            "username:s:DOMAIN\\alice\n",
            encoding="utf-8",
        )
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert any(
            r["type"] == "rdp_default_profile"
            and r["host_or_target"] == "gateway.example"
            for r in result["records"]
        )

    def test_empty_rdp_file_not_recorded(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        (user / "Documents" / "Default.rdp").write_text("", encoding="utf-8")
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert result["record_count"] == 0

    def test_directive_only_file_does_not_crash(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        (user / "Documents" / "noise.rdp").write_text(
            "absolutely not a directive line\n",
            encoding="utf-8",
        )
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert all(
            r.get("source_file", "").find("noise.rdp") < 0
            for r in result["records"]
        )

    def test_max_records_per_source_bounds_candidates(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        for i in range(15):
            (user / "Documents" / f"p{i:03d}.rdp").write_text(
                f"full address:s:target-{i}.example\n",
                encoding="utf-8",
            )
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            max_records_per_source=5,
        )
        assert len(result["candidate_files"]) <= 5
        assert result["record_count"] <= 5

    def test_max_records_per_source_bounds_records(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        for i in range(10):
            (user / "Documents" / f"p{i:03d}.rdp").write_text(
                f"full address:s:target-{i}.example\n",
                encoding="utf-8",
            )
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            max_records_per_source=3,
        )
        assert result["record_count"] <= 3

    def test_deterministic_disk_walk(self, tmp_path):
        user = _make_user_dir(tmp_path, "alice")
        (user / "Documents" / "A.rdp").write_text(
            "full address:s:a.example\n", encoding="utf-8",
        )
        (user / "Documents" / "B.rdp").write_text(
            "full address:s:b.example\n", encoding="utf-8",
        )
        a = parse_rdp_artifacts(mount_path=str(tmp_path))
        b = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert a["records"] == b["records"]
        assert a["candidate_files"] == b["candidate_files"]
        assert a["searched_paths"] == b["searched_paths"]
        assert a["status"] == b["status"]


# ── disk_image_path (E01) graceful behavior ────────────────────────────


class TestDiskImagePath:
    def test_missing_e01_returns_graceful_envelope(self, tmp_path):
        missing = tmp_path / "does-not-exist.E01"
        result = parse_rdp_artifacts(disk_image_path=str(missing))
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"] == []
        assert result["evidence_path"] == str(missing)
        # EVTX + profile sub-sources show "not_found" because the image
        # file was missing (not a library/parse problem).
        ss = result["sub_source_status"]
        for sk in (
            "evtx_local_session_manager",
            "evtx_remote_connection_manager",
            "evtx_rdp_client",
            "rdp_profile",
        ):
            assert ss[sk] == "not_found", (sk, ss[sk])
        assert any("E01 image not found" in e for e in result["errors"])

    def test_invalid_e01_file_returns_parse_error(self, tmp_path):
        """A file that exists but isn't a valid E01 must return cleanly
        with a parse-error status -- no crash, no fake records."""
        try:
            import pyewf  # noqa: F401
            import pytsk3  # noqa: F401
        except ImportError:
            pytest.skip("pyewf/pytsk3 not installed; can't exercise path")
        not_an_e01 = tmp_path / "fake.E01"
        not_an_e01.write_bytes(b"not an e01 file " * 10)
        result = parse_rdp_artifacts(
            disk_image_path=str(not_an_e01),
            staging_dir=str(tmp_path / "staging"),
        )
        assert result["records"] == []
        assert result["status"] in _EXPECTED_STATUSES
        ss = result["sub_source_status"]
        # Either open_error (pyewf couldn't open it) or fs_error (pyewf
        # opened but no NTFS located). Both map to parse_error on the
        # envelope. What we care about: NOT "ok" and NOT a crash.
        for sk in (
            "evtx_local_session_manager",
            "evtx_remote_connection_manager",
            "evtx_rdp_client",
            "rdp_profile",
        ):
            assert ss[sk] in {"parse_error", "not_found"}, (sk, ss[sk])

    def test_disk_image_path_accepts_staging_dir(self, tmp_path):
        missing = tmp_path / "does-not-exist.E01"
        staging = tmp_path / "staging"
        # Should not crash even though E01 is missing.
        result = parse_rdp_artifacts(
            disk_image_path=str(missing),
            staging_dir=str(staging),
        )
        assert result["tool"] == "parse_rdp_artifacts"

    def test_no_fake_records_when_e01_unavailable(self, tmp_path):
        result = parse_rdp_artifacts(
            disk_image_path=str(tmp_path / "nope.E01"),
        )
        assert result["records"] == []
        assert result["output"] == []
        assert result["record_count"] == 0


# ── counts + reason (envelope explanations) ────────────────────────────


class TestCountsDict:
    """BRAIN V3 contract: ``counts`` is always a dict, never None, and
    always carries per-type / per-source_kind breakdowns even when all
    counts are zero."""

    def test_counts_always_present_and_is_dict(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert "counts" in result
        assert isinstance(result["counts"], dict)
        assert result["counts"] is not None

    def test_counts_has_required_keys(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        counts = result["counts"]
        for key in (
            "records",
            "records_by_type",
            "records_by_source_kind",
            "recovery_hints",
            "recovery_hints_by_type",
            "candidate_files",
            "searched_paths",
            "errors",
        ):
            assert key in counts, f"missing counts key: {key}"
        # Scalars are ints, breakdowns are dicts
        assert isinstance(counts["records"], int)
        assert isinstance(counts["records_by_type"], dict)
        assert isinstance(counts["records_by_source_kind"], dict)

    def test_counts_by_type_covers_closed_vocab(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        counts = result["counts"]
        assert set(counts["records_by_type"].keys()) == _EXPECTED_RECORD_TYPES
        assert (
            set(counts["records_by_source_kind"].keys())
            == _EXPECTED_SOURCE_KINDS
        )
        assert (
            set(counts["recovery_hints_by_type"].keys())
            == _EXPECTED_HINT_TYPES
        )

    def test_counts_reflect_actual_records(self, tmp_path):
        user = tmp_path / "Users" / "alice" / "Documents"
        user.mkdir(parents=True)
        (user / "Default.rdp").write_text(
            "full address:s:x.example\n", encoding="utf-8",
        )
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        counts = result["counts"]
        assert counts["records"] == result["record_count"]
        assert counts["records_by_type"]["rdp_default_profile"] == 1
        assert counts["records_by_source_kind"]["rdp_profile_file"] == 1
        # Other buckets remain zero.
        assert counts["records_by_type"]["rdp_session_inbound"] == 0


class TestReasonExplainsRecoveryHints:
    """BRAIN V3: when recovery_hints is 0, the reason text must say
    *why* -- either tool_outputs wasn't provided, or it was provided
    but contained no RDP references. No silent zero."""

    def test_reason_explains_when_no_tool_outputs(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert result["recovery_hints"] == []
        assert "no tool_outputs provided" in result["reason"]

    def test_reason_explains_when_tool_outputs_empty(self, tmp_path):
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={},
        )
        assert result["recovery_hints"] == []
        # Empty dict counts as "not provided" in our semantics.
        assert "no tool_outputs provided" in result["reason"]

    def test_reason_explains_when_tool_outputs_have_no_rdp(self, tmp_path):
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={"vol_pslist": {"output": [
                {"ImageFileName": "explorer.exe"},
                {"ImageFileName": "svchost.exe"},
            ]}},
        )
        assert result["recovery_hints"] == []
        assert "no RDP artifact references" in result["reason"]

    def test_reason_counts_hints_when_present(self, tmp_path):
        env = {"output": [{"Name": r"\Users\u\Documents\Default.rdp"}]}
        result = parse_rdp_artifacts(
            mount_path=str(tmp_path),
            tool_outputs={"vol_filescan": env},
        )
        assert result["recovery_hints"]
        assert "RDP reference(s)" in result["reason"]


# ── envelope + signature sanity ────────────────────────────────────────


class TestEnvelopeMeta:
    def test_signature_callable_with_no_args(self):
        sig = inspect.signature(parse_rdp_artifacts)
        for p in sig.parameters.values():
            assert (
                p.default is not inspect.Parameter.empty
                or p.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                )
            ), f"parameter {p.name!r} has no default"

    def test_envelope_has_no_findings_key(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert "findings" not in result
        assert "finding" not in result

    def test_envelope_has_no_confidence_key(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert "confidence" not in result

    def test_output_mirrors_records(self, tmp_path):
        user = tmp_path / "Users" / "alice" / "Documents"
        user.mkdir(parents=True)
        (user / "Default.rdp").write_text(
            "full address:s:x.example\n", encoding="utf-8",
        )
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert result["output"] == result["records"]
        assert result["record_count"] == len(result["records"])

    def test_evidence_path_reported_for_mount(self, tmp_path):
        result = parse_rdp_artifacts(mount_path=str(tmp_path))
        assert result["evidence_path"] == str(tmp_path)

    def test_evidence_path_reported_for_disk_image(self, tmp_path):
        img = tmp_path / "img.E01"
        result = parse_rdp_artifacts(disk_image_path=str(img))
        assert result["evidence_path"] == str(img)


# ── dataset-agnostic guardrail ─────────────────────────────────────────


class TestDatasetAgnostic:
    def test_no_dataset_specific_tokens_in_module(self):
        """Production module must not embed scenario-specific tokens,
        case-specific users, IPs, hostnames, or IOC fragments.

        Uses the same word-boundary regex guard as
        ``tests/test_agnostic_contract.py`` so substrings inside legitimate
        identifiers (e.g. ``continue`` containing ``conti``) don't false-
        positive.
        """
        import re

        import sift_sentinel.tools.parse_rdp_artifacts as mod
        source = Path(mod.__file__).read_text()
        forbidden = (
            # Scenario host identifiers
            "TEST-HOST-01", "TEST_HOST_01", "TEST-HOST-02",
            "CRIMSON", "OSPREY", "Stark Research",
            # Specific users / IPs / domains from the case
            "sqlsvc", "tuser-r",
            "192.0.2.129", "192.0.2.111", "192.0.2.112",
            "192.0.2.113",
            "evil-c2.example.invalid",
            # Specific IOC-style tokens from the evidence set
            "3IlbDbjb", "5cHlvR59", "ehp5JHmP", "umt1XQWc",
            "yAXjPaXf", "ykLVQpA_",
        )
        for token in forbidden:
            pattern = re.compile(
                r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])"
            )
            assert pattern.search(source) is None, (
                f"dataset token leaked into parser: {token!r}"
            )

    def test_only_generic_rdp_binary_tokens_referenced(self):
        """The only RDP binary names hardcoded in the parser are the
        canonical Windows ones. Verifies the binary hint pipeline is not
        scenario-priming.
        """
        import sift_sentinel.tools.parse_rdp_artifacts as mod
        source = Path(mod.__file__).read_text().lower()
        # Must reference these generic tokens.
        for token in ("mstsc.exe", "termsrv.dll", "rdpdr.sys", "tsclient"):
            assert token in source, (
                f"expected generic RDP token missing: {token!r}"
            )


# ── record invariants across all emit paths ────────────────────────────


class TestRecordInvariants:
    def _all_record_paths(self, tmp_path):
        """Produce at least one record from every emit path.

        Each channel_kind is exercised with a per-channel valid EventID
        per the approved F7 EID whitelist.
        """
        records: list[dict] = []
        # EVTX normalize (mocked). Use a per-channel valid EID so the
        # whitelist check passes.
        evtx_cases = (
            ("local_session_manager", 21),
            ("remote_connection_manager", 1149),
            ("rdp_client_operational", 1024),
        )
        for channel_kind, eid in evtx_cases:
            rec = normalize_evtx_event(
                {
                    "EventID": eid,
                    "TimeCreated": "2024-01-01T00:00:00.000Z",
                    "EventData": {
                        "User": "u",
                        "Source Network Address": "10.0.0.1",
                        "ConnectionName": "target.example",
                    },
                    "EventRecordID": 1,
                },
                channel_kind, "/x.evtx",
            )
            assert rec is not None
            records.append(rec)
        # Registry MRU + Servers
        records.extend(normalize_registry_values([
            {
                "key_path": (
                    "Software\\Microsoft\\Terminal Server Client\\Default"
                ),
                "value_name": "MRU0",
                "value_data": "x.example",
            },
            {
                "key_path": (
                    "Software\\Microsoft\\Terminal Server Client\\"
                    "Servers\\x.example"
                ),
                "value_name": "UsernameHint",
                "value_data": "alice",
                "subkey_name": "x.example",
            },
        ]))
        # .rdp profile
        prof = parse_rdp_profile_text(
            "full address:s:x.example\nusername:s:alice\n",
            "/x/Default.rdp",
        )
        assert prof is not None
        records.append(prof)
        return records

    def test_all_records_carry_required_fields(self, tmp_path):
        records = self._all_record_paths(tmp_path)
        for rec in records:
            for f in _EXPECTED_RECORD_REQUIRED_FIELDS:
                assert f in rec, (
                    f"{rec['type']} missing required field: {f}"
                )

    def test_all_records_use_closed_vocab(self, tmp_path):
        records = self._all_record_paths(tmp_path)
        for rec in records:
            assert rec["type"] in _EXPECTED_RECORD_TYPES
            assert rec["source_kind"] in _EXPECTED_SOURCE_KINDS
            assert rec["extraction_method"] in (
                _EXPECTED_EXTRACTION_METHODS
            )

    def test_no_confidence_or_findings_on_any_record(self, tmp_path):
        records = self._all_record_paths(tmp_path)
        for rec in records:
            assert "confidence" not in rec
            assert "findings" not in rec
            assert "finding" not in rec

    def test_record_id_non_empty_for_all_records(self, tmp_path):
        records = self._all_record_paths(tmp_path)
        for rec in records:
            assert isinstance(rec["record_id"], str)
            assert rec["record_id"]

    def test_record_ids_unique_across_paths(self, tmp_path):
        records = self._all_record_paths(tmp_path)
        ids = [r["record_id"] for r in records]
        # record_ids should be unique across these constructed records.
        assert len(set(ids)) == len(ids)


# ── F7-B: registry / capability / MCP exposure ─────────────────────────


class TestRdpRegistryExposure:
    """Registration surfaces for parse_rdp_artifacts.

    Mirrors TestRegistryExposure in test_parse_powershell_transcripts.py.
    The parser itself is dataset-agnostic; these tests only assert that
    the registration wiring exposes it to the same coordinator / Inv1 /
    Inv3 / confidence / console / MCP surfaces as other disk tools.
    """

    def test_registered_in_tool_registry(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        assert "parse_rdp_artifacts" in _TOOL_REGISTRY
        fn, arg_type = _TOOL_REGISTRY["parse_rdp_artifacts"]
        assert callable(fn)
        assert arg_type == "standalone"

    def test_capability_declared(self):
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("parse_rdp_artifacts")
        assert cap is not None
        assert "windows_evidence" in cap["applicable_when"]
        assert "disk_evidence" in cap["applicable_when"]
        assert "linux_evidence" in cap["not_applicable_when"]
        assert cap["runtime_class"] in {"fast", "medium", "slow", "background"}
        assert cap["produces"] == ["rdp_artifact_records"]

    def test_categorized_under_valid_category(self):
        """RDP must sit under an existing VALID_CATEGORIES value.
        Commit 16 invariants forbid new category strings in this task.
        """
        from sift_sentinel.coordinator import _TOOL_CATEGORY
        # Mirrors the canonical 7-category set in test_commit16_invariants.
        VALID = {
            "process_analysis", "malware_detection", "network_analysis",
            "persistence", "filesystem_analysis", "registry_analysis",
            "execution_history",
        }
        cat = _TOOL_CATEGORY.get("parse_rdp_artifacts")
        assert cat in VALID, (
            f"parse_rdp_artifacts category {cat!r} not in {sorted(VALID)}"
        )

    def test_appears_in_inv1_prompt(self, tmp_path):
        from sift_sentinel.coordinator import (
            BOOTSTRAP_TOOLS, build_inv1_prompt,
        )
        bootstrap = {
            n: {"tool_name": n, "output": [], "record_count": 0}
            for n in BOOTSTRAP_TOOLS
        }
        prompt = build_inv1_prompt(bootstrap, tmp_path).read_text()
        assert "parse_rdp_artifacts" in prompt

    def test_appears_in_inv3_oneshot_prompt(self, tmp_path):
        from sift_sentinel.coordinator import _build_inv3_oneshot_prompt
        prompt = _build_inv3_oneshot_prompt([], tmp_path).read_text()
        assert "parse_rdp_artifacts" in prompt

    def test_listed_in_investigation_tools(self):
        from sift_sentinel.coordinator import INVESTIGATION_TOOLS
        assert "parse_rdp_artifacts" in INVESTIGATION_TOOLS

    def test_listed_in_disk_tools(self):
        from sift_sentinel.coordinator import DISK_TOOLS as COORD_DISK_TOOLS
        from sift_sentinel.analysis.confidence import (
            DISK_TOOLS as CONF_DISK_TOOLS,
        )
        from sift_sentinel.console import DISK_TOOLS as CONSOLE_DISK_TOOLS
        assert "parse_rdp_artifacts" in COORD_DISK_TOOLS
        assert "parse_rdp_artifacts" in CONF_DISK_TOOLS
        assert "parse_rdp_artifacts" in CONSOLE_DISK_TOOLS

    def test_artifact_type_classified_as_event_log(self):
        from sift_sentinel.analysis.confidence import TOOL_TO_ARTIFACT_TYPE
        # "E" = event-log-class artifact; RDP is evtx-dominated.
        assert TOOL_TO_ARTIFACT_TYPE.get("parse_rdp_artifacts") == "E"

    def test_listed_in_tool_catalog_surface(self):
        """tool_catalog TOOL_CATALOG exposes the tool to MCP clients
        via get_tools_for_category. Mirrors the PS precedent of
        appearing under the filesystem_analysis tools group."""
        from sift_sentinel.tools.tool_catalog import TOOL_CATALOG
        fs_tools = TOOL_CATALOG["filesystem_analysis"]["tools"]
        assert "parse_rdp_artifacts" in fs_tools
        desc = fs_tools["parse_rdp_artifacts"]
        assert isinstance(desc, str) and desc.strip()

    def test_tool_catalog_description_makes_no_attack_claim(self):
        """Description must describe the artifacts the tool returns,
        not attribute a technique (e.g. 'initial access',
        'lateral movement') to the evidence. F7-B honesty rule."""
        from sift_sentinel.tools.tool_catalog import TOOL_CATALOG
        desc = TOOL_CATALOG["filesystem_analysis"]["tools"][
            "parse_rdp_artifacts"
        ].lower()
        banned = [
            "initial access", "lateral movement", "attacker",
            "compromise", "malicious", "session reconstruction",
        ]
        for word in banned:
            assert word not in desc, (
                f"tool_catalog description for parse_rdp_artifacts must "
                f"not contain {word!r}: {desc!r}"
            )

    def test_mcp_server_exposes_tool(self):
        """MCP dynamic registration exposes parse_rdp_artifacts as
        tool_parse_rdp_artifacts without any edit to src/server.py."""
        import sys
        if "server" in sys.modules:
            del sys.modules["server"]
        sys.path.insert(0, "src")
        import server
        assert hasattr(server, "tool_parse_rdp_artifacts")
        assert callable(getattr(server, "tool_parse_rdp_artifacts"))
        assert "tool_parse_rdp_artifacts" in \
            server.mcp._tool_manager._tools

    def test_signature_accepts_standalone_call(self):
        """The 'standalone' arg_type contract requires the function to
        be callable with no positional args. All RDP kwargs are optional.
        """
        from sift_sentinel.tools.parse_rdp_artifacts import parse_rdp_artifacts
        sig = inspect.signature(parse_rdp_artifacts)
        for p in sig.parameters.values():
            assert (
                p.default is not inspect.Parameter.empty
                or p.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                )
            ), f"parse_rdp_artifacts parameter {p.name!r} has no default"

    def test_bootstrap_excludes_rdp(self):
        """Bootstrap is the pre-AI fixed prefix. RDP must be AI-selected."""
        from sift_sentinel.coordinator import BOOTSTRAP_TOOLS
        assert "parse_rdp_artifacts" not in BOOTSTRAP_TOOLS

    def test_counts_bumped_after_registration(self):
        """F7-B adds exactly one registered+categorized tool. Guards
        against accidental multi-register or missing register.
        """
        from sift_sentinel.coordinator import (
            _TOOL_CATEGORY,
            _TOOL_REGISTRY,
            BOOTSTRAP_TOOLS,
            _NON_WINDOWS_TOOLS,
        )
        assert "parse_rdp_artifacts" in _TOOL_REGISTRY
        assert "parse_rdp_artifacts" in _TOOL_CATEGORY
        selectable = (set(_TOOL_REGISTRY) - set(BOOTSTRAP_TOOLS)
                      - _NON_WINDOWS_TOOLS)
        assert "parse_rdp_artifacts" in selectable
