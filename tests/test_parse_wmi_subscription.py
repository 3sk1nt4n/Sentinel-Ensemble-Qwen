"""Targeted unit tests for parse_wmi_subscription (F8-A).

Covers closed-vocabulary contracts, ASCII + UTF-16LE anchor scanning
with synthetic in-memory buffers, per-record-type property extraction
(__EventFilter, CommandLineEventConsumer, ActiveScriptEventConsumer,
__FilterToConsumerBinding), anchor-only fallback, duplicate
suppression, corrupt/missing-source graceful status handling,
recovery_hints extraction from tool_outputs, top-level envelope
signature, record invariants, bounded raw_excerpt, and dataset-
agnostic source scan.

F8-A is parser + tests only -- no registry, capabilities, MCP server,
coordinator, or report integration is exercised here. Those come in a
later F8-B wiring task.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from sift_sentinel.tools.parse_wmi_subscription import (
    WMI_ANCHOR_CLASSES,
    WMI_EXTRACTION_METHODS,
    WMI_RECORD_REQUIRED_FIELDS,
    WMI_RECORD_TYPES,
    WMI_RECOVERY_HINT_REQUIRED_FIELDS,
    WMI_RECOVERY_HINT_STATUSES,
    WMI_RECOVERY_HINT_TYPES,
    WMI_SOURCE_KINDS,
    WMI_STATUSES,
    WMI_SUB_SOURCE_KEYS,
    WMI_SUB_SOURCE_STATUSES,
    find_wmi_recovery_hints,
    parse_wmi_from_bytes,
    parse_wmi_subscription,
)


# ── expected closed vocabularies (locked F8-A contract) ────────────────

_EXPECTED_STATUSES = frozenset({
    "no_wmi_artifacts_found",
    "wmi_references_found",
    "wmi_artifacts_parsed",
    "wmi_artifacts_parsed_with_references",
})

_EXPECTED_RECORD_TYPES = frozenset({
    "wmi_event_filter",
    "wmi_command_line_consumer",
    "wmi_active_script_consumer",
    "wmi_nt_event_log_consumer",
    "wmi_log_file_consumer",
    "wmi_smtp_consumer",
    "wmi_filter_to_consumer_binding",
})

_EXPECTED_SOURCE_KINDS = frozenset({
    "wmi_repository_file",
    "memory_image",
})

_EXPECTED_EXTRACTION_METHODS = frozenset({
    "objects_data_anchor_window",
    "memory_mof_literal",
    "memory_anchor_only",
})

_EXPECTED_SUB_SOURCE_STATUSES = frozenset({
    "ok",
    "not_found",
    "library_unavailable",
    "parse_error",
    "not_requested",
})

_EXPECTED_SUB_SOURCE_KEYS = (
    "objects_data",
    "memory_strings",
)

_EXPECTED_HINT_TYPES = frozenset({
    "wmi_repository_path_reference",
    "wmi_binary_reference",
})

_EXPECTED_HINT_STATUSES = frozenset({
    "path_reference_only",
    "binary_reference_only",
})

_EXPECTED_ANCHOR_CLASSES = frozenset({
    "__EventFilter",
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "NTEventLogEventConsumer",
    "LogFileEventConsumer",
    "SMTPEventConsumer",
    "__FilterToConsumerBinding",
})

_EXPECTED_RECORD_REQUIRED_FIELDS = (
    "type",
    "source_kind",
    "extraction_method",
    "source_file",
    "record_id",
    "raw_excerpt",
    "anchor_class",
    "offset",
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


# ── helpers ────────────────────────────────────────────────────────────

def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def _pad(length: int, byte: int = 0x00) -> bytes:
    return bytes([byte]) * length


# ── closed-vocab constant tests ────────────────────────────────────────


class TestClosedVocabularyConstants:
    """Pin the locked F8-A contract -- no drift without a schema bump."""

    def test_status_vocab_locked(self):
        assert WMI_STATUSES == _EXPECTED_STATUSES

    def test_record_type_vocab_locked(self):
        assert WMI_RECORD_TYPES == _EXPECTED_RECORD_TYPES

    def test_source_kind_vocab_locked(self):
        assert WMI_SOURCE_KINDS == _EXPECTED_SOURCE_KINDS

    def test_extraction_method_vocab_locked(self):
        assert WMI_EXTRACTION_METHODS == _EXPECTED_EXTRACTION_METHODS

    def test_sub_source_status_vocab_locked(self):
        assert WMI_SUB_SOURCE_STATUSES == _EXPECTED_SUB_SOURCE_STATUSES

    def test_sub_source_keys_locked(self):
        assert tuple(WMI_SUB_SOURCE_KEYS) == _EXPECTED_SUB_SOURCE_KEYS

    def test_hint_type_vocab_locked(self):
        assert WMI_RECOVERY_HINT_TYPES == _EXPECTED_HINT_TYPES

    def test_hint_status_vocab_locked(self):
        assert WMI_RECOVERY_HINT_STATUSES == _EXPECTED_HINT_STATUSES

    def test_anchor_classes_locked(self):
        assert WMI_ANCHOR_CLASSES == _EXPECTED_ANCHOR_CLASSES

    def test_record_required_fields_locked(self):
        assert (
            WMI_RECORD_REQUIRED_FIELDS
            == _EXPECTED_RECORD_REQUIRED_FIELDS
        )

    def test_hint_required_fields_locked(self):
        assert (
            WMI_RECOVERY_HINT_REQUIRED_FIELDS
            == _EXPECTED_HINT_REQUIRED_FIELDS
        )


# ── ASCII property extraction (synthetic) ──────────────────────────────


class TestAsciiEventFilterExtraction:
    def test_event_filter_name_query_extracted(self):
        buf = (
            b"\x00" * 32
            + b'garbage __EventFilter garbage\n'
            + b'Name="FilterAlpha" '
            + b'Query="SELECT * FROM __InstanceCreationEvent" '
            + b'QueryLanguage="WQL" '
            + b'EventNamespace="root\\\\cimv2"\n'
            + b"\x00" * 32
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        types = {r["type"] for r in records}
        assert "wmi_event_filter" in types
        rec = next(r for r in records if r["type"] == "wmi_event_filter")
        assert rec["extracted_name"] == "FilterAlpha"
        assert "SELECT" in (rec["extracted_query"] or "")
        assert rec["extracted_query_language"] == "WQL"
        assert "cimv2" in (rec["extracted_event_namespace"] or "")
        assert rec["extraction_method"] == "objects_data_anchor_window"
        assert rec["anchor_class"] == "__EventFilter"
        assert rec["offset"] >= 0

    def test_event_filter_does_not_match_substring(self):
        # "Name" occurs inside "HostName" -- must not match.
        buf = (
            b"__EventFilter padding "
            b'HostName="not-the-name" end'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        # no Name= hit -> no record emitted (anchor_only disabled for
        # repository source).
        assert records == []


class TestAsciiCommandLineConsumerExtraction:
    def test_name_and_template_extracted(self):
        buf = (
            b"\x00" * 32
            + b'ref:CommandLineEventConsumer\n'
            + b'Name="ConsumerBeta" '
            + b'CommandLineTemplate="notepad.exe /arg" '
            + b'ExecutablePath="C:\\Windows\\System32\\notepad.exe" '
            + b'WorkingDirectory="C:\\"\n'
            + b"\x00" * 32
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_command_line_consumer"
        )
        assert rec["extracted_name"] == "ConsumerBeta"
        assert rec["extracted_command_template"] == "notepad.exe /arg"
        assert "notepad.exe" in rec["extracted_executable_path"]
        assert rec["extracted_working_directory"] == "C:\\"

    def test_properties_restricted_to_record_type(self):
        """Query is not a property of CommandLineEventConsumer, so even
        if the regex matches somewhere, it must not surface on the
        record. The record schema pins the allowed fields."""
        buf = (
            b'CommandLineEventConsumer '
            b'Name="C" CommandLineTemplate="x"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_command_line_consumer"
        )
        assert "extracted_query" not in rec
        assert "extracted_script_text" not in rec


class TestAsciiActiveScriptConsumerExtraction:
    def test_script_engine_filename_text_extracted(self):
        buf = (
            b'ActiveScriptEventConsumer '
            b'Name="ScriptGamma" '
            b'ScriptingEngine="JScript" '
            b'ScriptFilename="C:\\payload.js" '
            b'ScriptText="WScript.Echo(123)"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_active_script_consumer"
        )
        assert rec["extracted_name"] == "ScriptGamma"
        assert rec["extracted_script_engine"] == "JScript"
        assert rec["extracted_script_filename"] == "C:\\payload.js"
        assert rec["extracted_script_text"] == "WScript.Echo(123)"


class TestFilterToConsumerBindingExtraction:
    def test_explicit_filter_and_consumer_equality(self):
        # Explicit MOF-style Filter=/Consumer= equalities within window.
        buf = (
            b'__FilterToConsumerBinding padding '
            b'Filter="filter-ref-A" '
            b'Consumer="consumer-ref-B"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_filter_to_consumer_binding"
        )
        assert rec["extracted_filter_ref"] == "filter-ref-A"
        assert rec["extracted_consumer_ref"] == "consumer-ref-B"

    def test_backfill_from_class_name_references(self):
        # No Filter=/Consumer= equality, only the raw MOF-reference
        # strings as they appear inside a binding's string properties.
        buf = (
            b'__FilterToConsumerBinding padding '
            b'__EventFilter.Name="FilterAlpha" and '
            b'CommandLineEventConsumer.Name="ConsumerBeta"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_filter_to_consumer_binding"
        )
        assert rec["extracted_filter_ref"] == (
            '__EventFilter.Name="FilterAlpha"'
        )
        assert rec["extracted_consumer_ref"] == (
            'CommandLineEventConsumer.Name="ConsumerBeta"'
        )


# ── UTF-16LE property extraction ───────────────────────────────────────


class TestUtf16LeExtraction:
    def test_event_filter_utf16le_window(self):
        body = (
            '__EventFilter padding '
            'Name="UtfFilter" '
            'Query="SELECT * FROM __InstanceCreationEvent" '
            'QueryLanguage="WQL"\n'
        )
        buf = _pad(32) + _utf16le(body) + _pad(32)
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        assert any(
            r["type"] == "wmi_event_filter"
            and r["extracted_name"] == "UtfFilter"
            for r in records
        ), f"no utf16le event-filter record in {records!r}"

    def test_command_line_consumer_utf16le(self):
        body = (
            'CommandLineEventConsumer '
            'Name="UtfConsumer" '
            'CommandLineTemplate="cmd.exe /c whoami"\n'
        )
        buf = _utf16le(body)
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_command_line_consumer"
        )
        assert rec["extracted_name"] == "UtfConsumer"
        assert rec["extracted_command_template"] == (
            "cmd.exe /c whoami"
        )


# ── anchor-only fixture ────────────────────────────────────────────────


class TestAnchorOnlyFixture:
    def test_repository_source_drops_anchor_only(self):
        # Anchor token isolated with no Name/Template/etc. For repository
        # source we drop -- OBJECTS.DATA has too many class-definition
        # regions where the anchor appears without meaningful adjacent
        # context.
        buf = b"\x00" * 256 + b"ActiveScriptEventConsumer" + b"\x00" * 256
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        assert records == []

    def test_memory_source_emits_anchor_only_when_enabled(self):
        buf = b"\x00" * 256 + b"ActiveScriptEventConsumer" + b"\x00" * 256
        records = parse_wmi_from_bytes(
            buf, source_kind="memory_image",
            source_file="memory:test.img",
            emit_anchor_only=True,
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_active_script_consumer"
        )
        assert rec["extraction_method"] == "memory_anchor_only"
        assert rec["extracted_name"] is None

    def test_memory_source_mof_literal_when_value_present(self):
        buf = (
            b'ActiveScriptEventConsumer="ScriptFromMemory" '
            b'Name="ScriptFromMemory"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="memory_image",
            source_file="memory:test.img",
            emit_anchor_only=False,
        )
        rec = next(
            r for r in records
            if r["type"] == "wmi_active_script_consumer"
        )
        assert rec["extraction_method"] == "memory_mof_literal"
        assert rec["extracted_name"] == "ScriptFromMemory"


# ── duplicate suppression ──────────────────────────────────────────────


class TestDuplicateSuppression:
    def test_two_identical_adjacent_anchors_collapse(self):
        body = (
            b'__EventFilter Name="DupFilter" Query="SELECT X FROM Y"\n'
            b'__EventFilter Name="DupFilter" Query="SELECT X FROM Y"\n'
        )
        records = parse_wmi_from_bytes(
            body, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        filter_records = [
            r for r in records if r["type"] == "wmi_event_filter"
        ]
        assert len(filter_records) == 1, (
            f"expected 1 dedup'd record, got {filter_records!r}"
        )

    def test_distant_duplicate_anchors_are_not_collapsed(self):
        # Same anchor + same name but separated by more than the dedup
        # bucket must survive as two records.
        body_a = b'__EventFilter Name="SameName" Query="SELECT X FROM Y"\n'
        body_b = b'__EventFilter Name="SameName" Query="SELECT X FROM Y"\n'
        padding = b"\x00" * (8 * 1024)   # > 4096 bucket
        buf = body_a + padding + body_b
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        filter_records = [
            r for r in records if r["type"] == "wmi_event_filter"
        ]
        assert len(filter_records) == 2


# ── record invariants ──────────────────────────────────────────────────


class TestRecordInvariants:
    def _all_record_paths(self) -> list[dict]:
        records: list[dict] = []
        # Filter (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'__EventFilter Name="F1" Query="SELECT X FROM Y"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # CommandLineEventConsumer (UTF-16LE)
        records.extend(parse_wmi_from_bytes(
            _utf16le(
                'CommandLineEventConsumer Name="C1" '
                'CommandLineTemplate="cmd.exe"'
            ),
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # ActiveScriptEventConsumer (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'ActiveScriptEventConsumer Name="S1" '
            b'ScriptingEngine="VBScript" '
            b'ScriptText="x"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # NTEventLogEventConsumer (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'NTEventLogEventConsumer Name="N1"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # LogFileEventConsumer (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'LogFileEventConsumer Name="L1" ExecutablePath="x.log"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # SMTPEventConsumer (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'SMTPEventConsumer Name="M1"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # FilterToConsumerBinding (ASCII)
        records.extend(parse_wmi_from_bytes(
            b'__FilterToConsumerBinding Filter="f" Consumer="c"',
            source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        ))
        # Memory anchor-only
        records.extend(parse_wmi_from_bytes(
            b"\x00" * 64 + b"CommandLineEventConsumer" + b"\x00" * 64,
            source_kind="memory_image",
            source_file="memory:test.img",
            emit_anchor_only=True,
        ))
        return records

    def test_every_record_type_has_a_sample(self):
        records = self._all_record_paths()
        seen = {r["type"] for r in records}
        assert seen == _EXPECTED_RECORD_TYPES

    def test_all_records_carry_required_fields(self):
        records = self._all_record_paths()
        for rec in records:
            for f in _EXPECTED_RECORD_REQUIRED_FIELDS:
                assert f in rec, (
                    f"{rec['type']} missing required field: {f}"
                )

    def test_all_records_use_closed_vocab(self):
        records = self._all_record_paths()
        for rec in records:
            assert rec["type"] in _EXPECTED_RECORD_TYPES
            assert rec["source_kind"] in _EXPECTED_SOURCE_KINDS
            assert rec["extraction_method"] in (
                _EXPECTED_EXTRACTION_METHODS
            )
            assert rec["anchor_class"] in _EXPECTED_ANCHOR_CLASSES

    def test_no_confidence_or_findings_on_any_record(self):
        records = self._all_record_paths()
        for rec in records:
            assert "confidence" not in rec
            assert "findings" not in rec
            assert "finding" not in rec
            assert "severity" not in rec
            assert "suspicious" not in rec
            assert "verdict" not in rec

    def test_record_id_non_empty_for_all_records(self):
        records = self._all_record_paths()
        for rec in records:
            assert isinstance(rec["record_id"], str)
            assert rec["record_id"]

    def test_record_offset_is_int(self):
        records = self._all_record_paths()
        for rec in records:
            assert isinstance(rec["offset"], int)
            assert rec["offset"] >= 0


# ── bounded raw_excerpt ────────────────────────────────────────────────


class TestBoundedRawExcerpt:
    def test_raw_excerpt_capped_at_256_bytes(self):
        long_value = "A" * 2000
        buf = (
            b'__EventFilter Name="Long" '
            b'Query="' + long_value.encode("ascii") + b'"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records if r["type"] == "wmi_event_filter"
        )
        assert len(rec["raw_excerpt"]) <= 256

    def test_raw_excerpt_is_single_line(self):
        buf = (
            b'__EventFilter\nName="X"\nQuery="SELECT Y FROM Z"\n'
        )
        records = parse_wmi_from_bytes(
            buf, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        rec = next(
            r for r in records if r["type"] == "wmi_event_filter"
        )
        assert "\n" not in rec["raw_excerpt"]
        assert "\r" not in rec["raw_excerpt"]


# ── top-level envelope ─────────────────────────────────────────────────


class TestTopLevelEntry:
    def test_no_inputs_returns_no_artifacts_found(self):
        env = parse_wmi_subscription()
        assert env["status"] == "no_wmi_artifacts_found"
        assert env["records"] == []
        assert env["record_count"] == 0
        assert env["sub_source_status"]["objects_data"] == "not_requested"
        assert env["sub_source_status"]["memory_strings"] == (
            "not_requested"
        )
        assert env["recovery_hints"] == []

    def test_envelope_has_all_top_level_keys(self):
        env = parse_wmi_subscription()
        for key in (
            "tool", "tool_name", "evidence_path", "record_count",
            "records", "output", "candidate_files", "searched_paths",
            "sub_source_status", "counts", "status", "reason",
            "errors", "recovery_hints",
        ):
            assert key in env, f"missing top-level key: {key!r}"

    def test_output_alias_matches_records(self):
        env = parse_wmi_subscription()
        assert env["output"] is env["records"]

    def test_objects_data_path_direct(self, tmp_path):
        obj = tmp_path / "OBJECTS.DATA"
        obj.write_bytes(
            b"\x00" * 64
            + b'__EventFilter Name="FromFile" '
            + b'Query="SELECT X FROM Y"\n'
            + b"\x00" * 64
        )
        env = parse_wmi_subscription(
            objects_data_path=str(obj),
        )
        assert env["sub_source_status"]["objects_data"] == "ok"
        assert env["status"] == "wmi_artifacts_parsed"
        assert env["record_count"] >= 1
        names = {
            r.get("extracted_name") for r in env["records"]
            if r.get("type") == "wmi_event_filter"
        }
        assert "FromFile" in names

    def test_objects_data_via_mount_path(self, tmp_path):
        mount = tmp_path / "mount"
        repo = mount / "Windows" / "System32" / "wbem" / "Repository"
        repo.mkdir(parents=True)
        obj = repo / "OBJECTS.DATA"
        obj.write_bytes(
            b'__EventFilter Name="FromMount" '
            b'Query="SELECT X FROM Y"\n'
        )
        env = parse_wmi_subscription(
            mount_path=str(mount),
        )
        assert env["sub_source_status"]["objects_data"] == "ok"
        assert env["record_count"] >= 1
        # source_file should be the canonical relative tail
        rec = env["records"][0]
        assert rec["source_file"].startswith(
            "Windows/System32/wbem/Repository/"
        )

    def test_memory_image_direct(self, tmp_path):
        mem = tmp_path / "mem.img"
        body = _utf16le(
            'CommandLineEventConsumer="FromMemory"\n'
            'Name="FromMemory"\n'
        )
        mem.write_bytes(b"\x00" * 64 + body + b"\x00" * 64)
        env = parse_wmi_subscription(
            memory_image_path=str(mem),
            include_repository=False,
        )
        assert env["sub_source_status"]["memory_strings"] == "ok"
        assert env["sub_source_status"]["objects_data"] == (
            "not_requested"
        )
        assert env["status"] == "wmi_artifacts_parsed"
        rec = next(
            r for r in env["records"]
            if r["type"] == "wmi_command_line_consumer"
        )
        assert rec["extracted_name"] == "FromMemory"
        assert rec["source_file"] == f"memory:{mem.name}"

    def test_status_references_found_when_only_hints(self):
        tool_outputs = {
            "vol_filescan": {
                "evidence_path": "/some/image.img",
                "records": [
                    {"Name": (
                        "\\Windows\\System32\\wbem\\Repository\\"
                        "OBJECTS.DATA"
                    )},
                ],
            },
        }
        env = parse_wmi_subscription(tool_outputs=tool_outputs)
        assert env["status"] == "wmi_references_found"
        assert env["record_count"] == 0
        assert env["counts"]["recovery_hints"] >= 1

    def test_status_parsed_with_references(self, tmp_path):
        obj = tmp_path / "OBJECTS.DATA"
        obj.write_bytes(
            b'__EventFilter Name="X" Query="SELECT X FROM Y"\n'
        )
        tool_outputs = {
            "vol_handles": {
                "records": [
                    {"Name": "/.../Windows/System32/wbem/Repository/"
                             "INDEX.BTR"},
                ],
            },
        }
        env = parse_wmi_subscription(
            objects_data_path=str(obj),
            tool_outputs=tool_outputs,
        )
        assert env["status"] == "wmi_artifacts_parsed_with_references"
        assert env["record_count"] >= 1
        assert env["counts"]["recovery_hints"] >= 1


# ── corrupt / missing source handling ──────────────────────────────────


class TestMissingOrCorruptSource:
    def test_missing_objects_data_path(self):
        env = parse_wmi_subscription(
            objects_data_path="/nonexistent/OBJECTS.DATA",
        )
        assert env["sub_source_status"]["objects_data"] == "not_found"
        assert env["status"] == "no_wmi_artifacts_found"
        assert env["records"] == []

    def test_missing_mount_path(self):
        env = parse_wmi_subscription(
            mount_path="/nonexistent/mount",
        )
        assert env["sub_source_status"]["objects_data"] == "not_found"
        assert env["status"] == "no_wmi_artifacts_found"

    def test_mount_without_wbem_dir_reports_not_found(self, tmp_path):
        env = parse_wmi_subscription(mount_path=str(tmp_path))
        assert env["sub_source_status"]["objects_data"] == "not_found"

    def test_empty_objects_data_file(self, tmp_path):
        obj = tmp_path / "OBJECTS.DATA"
        obj.write_bytes(b"")
        env = parse_wmi_subscription(objects_data_path=str(obj))
        assert env["sub_source_status"]["objects_data"] == "ok"
        assert env["status"] == "no_wmi_artifacts_found"

    def test_random_bytes_no_anchors(self, tmp_path):
        obj = tmp_path / "OBJECTS.DATA"
        # Deterministic "random": no anchor class token present.
        obj.write_bytes(
            bytes((i * 7 + 31) & 0xff for i in range(8192))
        )
        env = parse_wmi_subscription(objects_data_path=str(obj))
        assert env["sub_source_status"]["objects_data"] == "ok"
        assert env["status"] == "no_wmi_artifacts_found"
        assert env["records"] == []

    def test_missing_memory_image_reports_not_found(self):
        env = parse_wmi_subscription(
            include_repository=False,
            memory_image_path="/nonexistent/mem.img",
        )
        assert env["sub_source_status"]["memory_strings"] == "not_found"
        assert env["records"] == []

    def test_include_flags_respected(self):
        env = parse_wmi_subscription(
            include_repository=False,
            include_memory_strings=False,
        )
        assert env["sub_source_status"]["objects_data"] == (
            "not_requested"
        )
        assert env["sub_source_status"]["memory_strings"] == (
            "not_requested"
        )


# ── recovery_hints ─────────────────────────────────────────────────────


class TestRecoveryHints:
    def test_repo_path_hint_from_tool_output(self):
        tool_outputs = {
            "vol_filescan": {
                "evidence_path": "/tmp/img.img",
                "records": [
                    {"Name": (
                        "\\Device\\HarddiskVolume2\\Windows\\System32\\"
                        "wbem\\Repository\\OBJECTS.DATA"
                    )},
                ],
            },
        }
        hints = find_wmi_recovery_hints(tool_outputs)
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "wmi_repository_path_reference"
        assert h["status"] == "path_reference_only"
        assert "Repository" in h["path"]
        assert h["source_tool"] == "vol_filescan"
        for f in _EXPECTED_HINT_REQUIRED_FIELDS:
            assert f in h

    def test_binary_hint_from_tool_output(self):
        tool_outputs = {
            "vol_pslist": {
                "records": [
                    {"ImageFileName": "wmiprvse.exe"},
                ],
            },
        }
        hints = find_wmi_recovery_hints(tool_outputs)
        types = {h["type"] for h in hints}
        assert "wmi_binary_reference" in types
        bin_hint = next(
            h for h in hints
            if h["type"] == "wmi_binary_reference"
        )
        assert bin_hint["binary"] == "wmiprvse.exe"
        assert bin_hint["status"] == "binary_reference_only"

    def test_no_false_positive_on_unrelated_binary(self):
        tool_outputs = {
            "vol_pslist": {
                "records": [
                    {"ImageFileName": "notepad.exe"},
                ],
            },
        }
        hints = find_wmi_recovery_hints(tool_outputs)
        assert hints == []

    def test_duplicates_suppressed_across_tools(self):
        tool_outputs = {
            "vol_pslist": {
                "records": [{"ImageFileName": "wmiprvse.exe"}],
            },
            "vol_pstree": {
                "records": [{"ImageFileName": "wmiprvse.exe"}],
            },
        }
        hints = find_wmi_recovery_hints(tool_outputs)
        # Different source_tool => different hint per tool.
        assert len(hints) == 2
        assert {h["source_tool"] for h in hints} == (
            {"vol_pslist", "vol_pstree"}
        )

    def test_hints_have_closed_vocab_type_and_status(self):
        tool_outputs = {
            "vol_filescan": {
                "records": [
                    {"Name": "/Windows/System32/wbem/Repository/"
                             "OBJECTS.DATA"},
                    {"ImageFileName": "wmiprvse.exe"},
                ],
            },
        }
        hints = find_wmi_recovery_hints(tool_outputs)
        assert hints
        for h in hints:
            assert h["type"] in _EXPECTED_HINT_TYPES
            assert h["status"] in _EXPECTED_HINT_STATUSES

    def test_none_or_empty_tool_outputs_returns_empty(self):
        assert find_wmi_recovery_hints(None) == []
        assert find_wmi_recovery_hints({}) == []
        assert find_wmi_recovery_hints(
            {"bad_tool": "not a dict"}
        ) == []


# ── API input-type safety ──────────────────────────────────────────────


class TestApiInputSafety:
    def test_parse_wmi_from_bytes_rejects_non_bytes(self):
        with pytest.raises(TypeError):
            parse_wmi_from_bytes("a string, not bytes")  # type: ignore

    def test_parse_wmi_from_bytes_rejects_bad_source_kind(self):
        with pytest.raises(ValueError):
            parse_wmi_from_bytes(
                b"", source_kind="garbage_source",
            )

    def test_parse_wmi_from_bytes_accepts_bytearray(self):
        ba = bytearray(
            b'__EventFilter Name="BAF" Query="SELECT X FROM Y"'
        )
        records = parse_wmi_from_bytes(
            ba, source_kind="wmi_repository_file",
            source_file="OBJECTS.DATA",
        )
        assert any(
            r.get("extracted_name") == "BAF" for r in records
        )


# ── dataset-agnostic source scan ───────────────────────────────────────


class TestDatasetAgnostic:
    def test_no_dataset_specific_tokens_in_module(self):
        """Production module must not embed scenario-specific tokens,
        case-specific users, IPs, hostnames, or IOC fragments.

        Uses word-boundary regex so substrings inside legitimate
        identifiers don't false-positive.
        """
        import sift_sentinel.tools.parse_wmi_subscription as mod
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
            # Specific WMI subscription names from the case -- the
            # parser must never hardcode any of these.
            "EvilConsumer", "EvilFilter",
            # Specific IOC-style tokens from the evidence set
            "3IlbDbjb", "5cHlvR59", "ehp5JHmP", "umt1XQWc",
            "yAXjPaXf", "ykLVQpA_",
        )
        for token in forbidden:
            pattern = re.compile(
                r"(?<![A-Za-z0-9_])"
                + re.escape(token)
                + r"(?![A-Za-z0-9_])"
            )
            assert pattern.search(source) is None, (
                f"dataset token leaked into parser: {token!r}"
            )

    def test_only_generic_wmi_tokens_referenced(self):
        """The only WMI binary names hardcoded in the parser are the
        canonical Windows ones. Verifies the binary hint pipeline is
        not scenario-priming."""
        import sift_sentinel.tools.parse_wmi_subscription as mod
        source = Path(mod.__file__).read_text().lower()
        for token in (
            "wmiprvse.exe", "wmiadasample_payload.exe", "mofcomsample_payload.exe",
            "wbemtest.exe", "scrcons.exe",
        ):
            assert token in source, (
                f"expected generic WMI token missing: {token!r}"
            )

    def test_anchor_classes_are_stock_microsoft_names(self):
        """Anchor class tokens must all be stock Microsoft WMI class
        names. None are scenario-specific.
        """
        for anchor in WMI_ANCHOR_CLASSES:
            assert anchor in _EXPECTED_ANCHOR_CLASSES, (
                f"non-stock anchor class leaked: {anchor!r}"
            )


# ── miscellaneous sanity ───────────────────────────────────────────────


class TestMiscellaneousSanity:
    def test_counts_dict_always_has_all_record_types(self):
        env = parse_wmi_subscription()
        counts = env["counts"]
        assert set(counts["records_by_type"].keys()) == (
            _EXPECTED_RECORD_TYPES
        )
        assert set(counts["records_by_source_kind"].keys()) == (
            _EXPECTED_SOURCE_KINDS
        )
        assert set(counts["recovery_hints_by_type"].keys()) == (
            _EXPECTED_HINT_TYPES
        )

    def test_reason_is_non_empty_string(self):
        env = parse_wmi_subscription()
        assert isinstance(env["reason"], str)
        assert env["reason"].strip()

    def test_records_are_sorted_deterministically(self, tmp_path):
        obj = tmp_path / "OBJECTS.DATA"
        # Two filters at different offsets -> sort by offset.
        obj.write_bytes(
            b'__EventFilter Name="Zeta" Query="SELECT X FROM Y"\n'
            + b"\x00" * (8 * 1024)
            + b'__EventFilter Name="Alpha" Query="SELECT X FROM Y"\n'
        )
        env = parse_wmi_subscription(objects_data_path=str(obj))
        filter_records = [
            r for r in env["records"]
            if r["type"] == "wmi_event_filter"
        ]
        # Offsets strictly ascending.
        offsets = [r["offset"] for r in filter_records]
        assert offsets == sorted(offsets)


# ── F8-B: registration / capability / MCP exposure ─────────────────────


class TestWmiRegistryExposure:
    """Registration surfaces for parse_wmi_subscription.

    Mirrors TestRdpRegistryExposure. The parser itself is dataset-
    agnostic; these tests only assert that the registration wiring
    exposes it to the same coordinator / Inv1 / confidence / console
    / MCP surfaces as other disk tools. BRAIN explicitly disallowed
    editing the Inv3 one-shot legacy prompt text, so no corresponding
    ``test_appears_in_inv3_oneshot_prompt`` exists here.
    """

    def test_registered_in_tool_registry(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        assert "parse_wmi_subscription" in _TOOL_REGISTRY
        fn, arg_type = _TOOL_REGISTRY["parse_wmi_subscription"]
        assert callable(fn)
        assert arg_type == "standalone"

    def test_capability_declared(self):
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("parse_wmi_subscription")
        assert cap is not None
        assert "windows_evidence" in cap["applicable_when"]
        assert "disk_evidence" in cap["applicable_when"]
        assert "linux_evidence" in cap["not_applicable_when"]
        assert cap["runtime_class"] in {
            "fast", "medium", "slow", "background",
        }
        assert cap["produces"] == ["wmi_subscription_records"]

    def test_categorized_as_persistence(self):
        """BRAIN decision: parse_wmi_subscription sits under the
        persistence category (WMI event subscriptions are a persistence
        mechanism in the MITRE sense, but the tool itself classifies
        nothing -- the category is a tool-taxonomy label, not an
        attacker-intent tag)."""
        from sift_sentinel.coordinator import _TOOL_CATEGORY
        VALID = {
            "process_analysis", "malware_detection", "network_analysis",
            "persistence", "filesystem_analysis", "registry_analysis",
            "execution_history",
        }
        cat = _TOOL_CATEGORY.get("parse_wmi_subscription")
        assert cat in VALID, (
            f"parse_wmi_subscription category {cat!r} not in "
            f"{sorted(VALID)}"
        )
        assert cat == "persistence"

    def test_appears_in_inv1_prompt(self, tmp_path):
        """Inv1 prompt is built from build_tool_catalog_advertisement,
        which renders tools grouped by _TOOL_CATEGORY automatically.
        Registering the tool + adding a category entry is enough; no
        hand-edit to prompt text is required or performed.
        """
        from sift_sentinel.coordinator import (
            BOOTSTRAP_TOOLS, build_inv1_prompt,
        )
        bootstrap = {
            n: {"tool_name": n, "output": [], "record_count": 0}
            for n in BOOTSTRAP_TOOLS
        }
        prompt = build_inv1_prompt(bootstrap, tmp_path).read_text()
        assert "parse_wmi_subscription" in prompt

    def test_listed_in_investigation_tools(self):
        from sift_sentinel.coordinator import INVESTIGATION_TOOLS
        assert "parse_wmi_subscription" in INVESTIGATION_TOOLS

    def test_listed_in_disk_tools_everywhere(self):
        from sift_sentinel.coordinator import (
            DISK_TOOLS as COORD_DISK_TOOLS,
        )
        from sift_sentinel.analysis.confidence import (
            DISK_TOOLS as CONF_DISK_TOOLS,
        )
        from sift_sentinel.console import DISK_TOOLS as CONSOLE_DISK_TOOLS
        assert "parse_wmi_subscription" in COORD_DISK_TOOLS
        assert "parse_wmi_subscription" in CONF_DISK_TOOLS
        assert "parse_wmi_subscription" in CONSOLE_DISK_TOOLS

    def test_artifact_type_classified_as_event_log(self):
        """BRAIN decision: artifact type "E" (event-log-class).
        WMI subscriptions are persistence metadata but the records
        are log-shaped evidence rows (one anchor hit = one row),
        consistent with parse_powershell_transcripts and
        parse_rdp_artifacts which are also "E".
        """
        from sift_sentinel.analysis.confidence import (
            TOOL_TO_ARTIFACT_TYPE,
        )
        assert TOOL_TO_ARTIFACT_TYPE.get("parse_wmi_subscription") == (
            "E"
        )

    def test_listed_in_tool_catalog_surface(self):
        """TOOL_CATALOG exposes the tool to MCP clients via
        get_tools_for_category. Placed under the persistence group to
        match the _TOOL_CATEGORY assignment.
        """
        from sift_sentinel.tools.tool_catalog import TOOL_CATALOG
        pers_tools = TOOL_CATALOG["persistence"]["tools"]
        assert "parse_wmi_subscription" in pers_tools
        desc = pers_tools["parse_wmi_subscription"]
        assert isinstance(desc, str) and desc.strip()

    def test_tool_catalog_description_makes_no_attack_claim(self):
        """Description must describe the artifacts the tool returns,
        not attribute a technique to the evidence. Mirrors F7-B
        honesty rule.
        """
        from sift_sentinel.tools.tool_catalog import TOOL_CATALOG
        desc = TOOL_CATALOG["persistence"]["tools"][
            "parse_wmi_subscription"
        ].lower()
        banned = [
            "initial access", "lateral movement", "attacker",
            "compromise", "malicious",
            # WMI-specific: the tool must not claim to reconstruct
            # the binding graph or classify subscription intent.
            "binding graph", "reconstruction",
        ]
        for word in banned:
            assert word not in desc, (
                f"tool_catalog description for "
                f"parse_wmi_subscription must not contain "
                f"{word!r}: {desc!r}"
            )

    def test_mcp_server_exposes_tool(self):
        """MCP dynamic registration exposes parse_wmi_subscription as
        tool_parse_wmi_subscription without any edit to src/server.py.
        """
        import sys
        if "server" in sys.modules:
            del sys.modules["server"]
        sys.path.insert(0, "src")
        import server
        assert hasattr(server, "tool_parse_wmi_subscription")
        assert callable(
            getattr(server, "tool_parse_wmi_subscription")
        )
        assert "tool_parse_wmi_subscription" in (
            server.mcp._tool_manager._tools
        )

    def test_signature_accepts_standalone_call(self):
        """The 'standalone' arg_type contract requires the function to
        be callable with no positional args. All kwargs must have
        defaults.
        """
        import inspect
        from sift_sentinel.tools.parse_wmi_subscription import (
            parse_wmi_subscription,
        )
        sig = inspect.signature(parse_wmi_subscription)
        for p in sig.parameters.values():
            assert (
                p.default is not inspect.Parameter.empty
                or p.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                )
            ), (
                f"parse_wmi_subscription parameter {p.name!r} "
                f"has no default"
            )

    def test_bootstrap_excludes_wmi(self):
        """Bootstrap is the pre-AI fixed prefix. WMI must be
        AI-selected (BRAIN: Bootstrap=NO)."""
        from sift_sentinel.coordinator import BOOTSTRAP_TOOLS
        assert "parse_wmi_subscription" not in BOOTSTRAP_TOOLS

    def test_ai_selectable_and_not_in_non_windows_filter(self):
        """BRAIN: AI-selectable=YES. The tool must survive the
        Windows-only filter and land in the selectable pool shown
        to the AI at Inv1.
        """
        from sift_sentinel.coordinator import (
            _TOOL_CATEGORY,
            _TOOL_REGISTRY,
            BOOTSTRAP_TOOLS,
            _NON_WINDOWS_TOOLS,
        )
        assert "parse_wmi_subscription" in _TOOL_REGISTRY
        assert "parse_wmi_subscription" in _TOOL_CATEGORY
        assert "parse_wmi_subscription" not in _NON_WINDOWS_TOOLS
        selectable = (
            set(_TOOL_REGISTRY) - set(BOOTSTRAP_TOOLS)
            - _NON_WINDOWS_TOOLS
        )
        assert "parse_wmi_subscription" in selectable
