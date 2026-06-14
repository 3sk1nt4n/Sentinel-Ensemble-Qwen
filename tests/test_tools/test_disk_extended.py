"""
Tests for disk_extended tools: parse_event_logs, parse_shellbags, parse_prefetch.
Tests use real filesystem structures or mock the EVTX library.
"""

import inspect
import json
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from sift_sentinel.tools.disk_extended import parse_event_logs, parse_prefetch, parse_shellbags


# ── Helpers ───────────────────────────────────────────────────────────

SAMPLE_EVTX_RECORDS = [
    {
        "EventID": 4624,
        "TimeCreated": "2018-09-05T17:38:22.000Z",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WINDOWS2012R2",
        "Message": "An account was successfully logged on",
    },
    {
        "EventID": 7036,
        "TimeCreated": "2018-09-05T18:01:10.000Z",
        "Provider": "Service Control Manager",
        "Channel": "System",
        "Computer": "WINDOWS2012R2",
        "Message": "Windows Modules Installer | running",
    },
    {
        "EventID": 104,
        "TimeCreated": "2018-03-14T20:48:48.223Z",
        "Provider": "Microsoft-Windows-Eventlog",
        "Channel": "System",
        "Computer": "WINDOWS2012R2",
        "Message": "The System log file was cleared",
    },
]


def _build_evtx_xml(rec: dict) -> str:
    """Build a minimal EVTX-style XML string from a record dict."""
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<EventID>{rec.get("EventID", 0)}</EventID>'
        f'<TimeCreated SystemTime="{rec.get("TimeCreated", "")}"/>'
        f'<Provider Name="{rec.get("Provider", "")}"/>'
        f'<Channel>{rec.get("Channel", "")}</Channel>'
        f'<Computer>{rec.get("Computer", "")}</Computer>'
        "</System>"
        "<EventData>"
        f'<Data>{rec.get("Message", "")}</Data>'
        "</EventData>"
        "</Event>"
    )


def _make_mock_evtx(records: list[dict]):
    """Return (mock_module, cleanup) that patches Evtx.Evtx for parse_event_logs."""
    mock_records = []
    for rec in records:
        mr = MagicMock()
        mr.xml.return_value = _build_evtx_xml(rec)
        mock_records.append(mr)

    mock_log = MagicMock()
    mock_log.__enter__ = MagicMock(return_value=mock_log)
    mock_log.__exit__ = MagicMock(return_value=False)
    mock_log.records.return_value = mock_records

    mock_evtx_mod = MagicMock()
    mock_evtx_mod.Evtx.return_value = mock_log

    mock_parent = MagicMock()
    mock_parent.Evtx = mock_evtx_mod

    return mock_parent, mock_evtx_mod


def _setup_evtx_env(tmp_path, records, filenames=None):
    """Create evtx directory + mock module. Returns (disk_mount, ctx_manager)."""
    evtx_dir = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    evtx_dir.mkdir(parents=True)
    for fname in (filenames or ["Test.evtx"]):
        (evtx_dir / fname).write_bytes(b"\x00")

    mock_parent, mock_evtx_mod = _make_mock_evtx(records)
    ctx = patch.dict(sys.modules, {
        "Evtx": mock_parent,
        "Evtx.Evtx": mock_evtx_mod,
    })
    return str(tmp_path), ctx


# ── parse_event_logs ──────────────────────────────────────────────────

class TestParseEventLogs:
    def test_returns_records(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, SAMPLE_EVTX_RECORDS)
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        assert "output" in result
        assert "record_count" in result
        assert result["record_count"] == 3
        assert isinstance(result["output"], list)
        # Sorted by TimeCreated descending: 7036 (18:01) before 4624 (17:38)
        assert result["output"][0]["EventID"] == 7036

    def test_record_fields(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, SAMPLE_EVTX_RECORDS)
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        rec = result["output"][0]
        for field in ("EventID", "TimeCreated", "Provider",
                      "Channel", "Computer", "Message"):
            assert field in rec, f"Missing field: {field}"

    def test_no_mount_returns_not_applicable(self, monkeypatch):
        # FIX B (#1) INTENTIONAL CHANGE (was test_no_mount_returns_error): an
        # absent Windows event-log tree is a CAPABILITY-ABSENCE, not a tool
        # failure. parse_event_logs now returns a not_applicable envelope with a
        # reason -- aligned with its sibling disk tools (get_amcache /
        # parse_prefetch / parse_registry_persistence) -- so the report's
        # applicability section explains it and the model never treats a
        # missing-evidence outcome as a finding. Kill switch SIFT_EVTX_NA_NODISK=0
        # restores the legacy error envelope (covered in
        # test_eventlogs_nodisk_not_applicable.py).
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        monkeypatch.delenv("SIFT_EVTX_NA_NODISK", raising=False)
        result = parse_event_logs(disk_mount="/nonexistent/mount")
        assert result["record_count"] == 0
        assert result.get("status") == "not_applicable"
        assert result.get("reason")  # explains WHY (Windows tree absent)
        assert isinstance(result["output"], list)
        assert len(result["output"]) == 0

    def test_record_count_matches_output(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, SAMPLE_EVTX_RECORDS)
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        assert result["record_count"] == len(result["output"])

    def test_empty_evtx_dir_returns_zero(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, [], filenames=[])
        # No .evtx files -> no records
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        assert result["record_count"] == 0
        assert result["output"] == []

    def test_sorted_by_timestamp_descending(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, SAMPLE_EVTX_RECORDS)
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        timestamps = [r["TimeCreated"] for r in result["output"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_max_records_truncates(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        records = [
            {"EventID": i, "TimeCreated": f"2018-09-05T{i:02d}:00:00.000Z",
             "Provider": "test", "Channel": "System",
             "Computer": "PC", "Message": ""}
            for i in range(10)
        ]
        mount, ctx = _setup_evtx_env(tmp_path, records)
        with ctx:
            result = parse_event_logs(disk_mount=mount, max_records=3)
        assert result["record_count"] == 3
        assert len(result["output"]) == 3
        # Most recent first (hour 09, 08, 07)
        assert result["output"][0]["EventID"] == 9
        assert result["output"][1]["EventID"] == 8
        assert result["output"][2]["EventID"] == 7

    def test_max_records_default_is_None_resolved_via_env(self):
        # 31W honesty: the signature default has been `None` since the
        # env-var-resolved default (SIFT_EVENT_LOG_MAX_RECORDS=50000) was
        # introduced. The stale `== 5000` assertion never matched code
        # behavior. Assert current contract: signature default is None and
        # internally resolves via env (verified by code path, not value).
        sig = inspect.signature(parse_event_logs)
        assert sig.parameters["max_records"].default is None


# ── parse_shellbags ───────────────────────────────────────────────────

class TestParseShellbags:
    def _write_csv(self, tmp_path, records):
        """Write records as CSV and return path."""
        if not records:
            csv_file = tmp_path / "shellbags.csv"
            csv_file.write_text("col\n")
            return str(csv_file)
        keys = list(records[0].keys())
        lines = [",".join(keys)]
        for r in records:
            lines.append(",".join(str(r.get(k, "")) for k in keys))
        csv_file = tmp_path / "shellbags.csv"
        csv_file.write_text("\n".join(lines) + "\n")
        return str(csv_file)

    def test_returns_records(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_path = self._write_csv(tmp_path, [
            {"AbsolutePath": "Desktop", "ShellType": "Root Folder",
             "Value": "Desktop", "CreatedOn": "2018-03-14 20:30:00",
             "ModifiedOn": "2018-09-05 17:00:00",
             "AccessedOn": "2018-09-05 17:00:00", "MFTEntry": "123"},
            {"AbsolutePath": "Documents", "ShellType": "Directory",
             "Value": "Documents", "CreatedOn": "2018-03-14 20:31:00",
             "ModifiedOn": "2018-09-04 10:00:00",
             "AccessedOn": "2018-09-05 16:00:00", "MFTEntry": "456"},
        ])
        result = parse_shellbags(csv_path=csv_path)
        assert "output" in result
        assert "record_count" in result
        assert result["record_count"] == 2
        assert isinstance(result["output"], list)

    def test_preserves_fields(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_path = self._write_csv(tmp_path, [
            {"AbsolutePath": "Desktop", "ShellType": "Root Folder",
             "Value": "Desktop", "CreatedOn": "2018-03-14 20:30:00",
             "ModifiedOn": "2018-09-05 17:00:00",
             "AccessedOn": "2018-09-05 17:00:00", "MFTEntry": "123"},
        ])
        result = parse_shellbags(csv_path=csv_path)
        rec = result["output"][0]
        assert rec["AbsolutePath"] == "Desktop"
        assert rec["ShellType"] == "Root Folder"

    def test_csv_not_found_returns_error(self, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        result = parse_shellbags(csv_path="/nonexistent/shellbags.csv")
        assert result["record_count"] == 0
        assert "error" in result
        assert result["output"] == []

    def test_csv_path_is_directory_returns_error(self, tmp_path, monkeypatch):
        """SBECmd sometimes creates directories named .csv; handle gracefully."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        dir_path = tmp_path / "fake.csv"
        dir_path.mkdir()
        result = parse_shellbags(csv_path=str(dir_path))
        assert result["record_count"] == 0
        assert "error" in result

    def test_reading_actual_csv(self, tmp_path, monkeypatch):
        """Read a CSV file and verify output structure."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_file = tmp_path / "shellbags_test.csv"
        csv_file.write_text(
            "AbsolutePath,ShellType,Value,CreatedOn,ModifiedOn,AccessedOn,MFTEntry\n"
            "Desktop,Root Folder,Desktop,2018-03-14 20:30:00,2018-09-05 17:00:00,2018-09-05 17:00:00,123\n"
            "Documents,Directory,Documents,2018-03-14 20:31:00,2018-09-04 10:00:00,2018-09-05 16:00:00,456\n"
        )
        result = parse_shellbags(csv_path=str(csv_file))
        assert "output" in result
        assert "record_count" in result
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] == 2

    def test_record_count_matches_output(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_path = self._write_csv(tmp_path, [
            {"Name": "Desktop", "Value": "folder"},
            {"Name": "Documents", "Value": "folder"},
        ])
        result = parse_shellbags(csv_path=csv_path)
        assert result["record_count"] == len(result["output"])

    def test_live_csv_returns_records(self, tmp_path, monkeypatch):
        """Live CSV parsing returns correct records."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_file = tmp_path / "test_shellbags.csv"
        csv_file.write_text("Name,Value\nDesktop,folder\n")
        result = parse_shellbags(csv_path=str(csv_file))
        assert result["record_count"] == 1


# ── parse_prefetch ───────────────────────────────────────────────────


class TestParsePrefetch:
    def test_parse_prefetch_returns_list(self, tmp_path, monkeypatch):
        """Temp .pf files return valid output structure."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "CMD.EXE-12345678.pf").write_bytes(b"\x00")
        (prefetch_dir / "POWERSHELL.EXE-AABBCCDD.pf").write_bytes(b"\x00")
        result = parse_prefetch(disk_mount=str(tmp_path))
        assert "output" in result
        assert "record_count" in result
        assert result["record_count"] == 2
        assert isinstance(result["output"], list)
        rec = result["output"][0]
        for field in ("executable_name", "run_count", "last_run_times",
                      "path", "files_accessed"):
            assert field in rec, f"Missing field: {field}"

    def test_parse_prefetch_missing_dir_returns_empty(self, tmp_path, monkeypatch):
        """No Prefetch directory -> empty result."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        result = parse_prefetch(disk_mount=str(tmp_path / "nonexistent"))
        assert result["output"] == []
        assert result["record_count"] == 0

    def test_parse_prefetch_no_pf_files_returns_empty(self, tmp_path, monkeypatch):
        """Prefetch directory exists but has no .pf files."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        result = parse_prefetch(disk_mount=str(tmp_path))
        assert result["output"] == []
        assert result["record_count"] == 0

    def test_parse_prefetch_bad_file_skipped(self, tmp_path, monkeypatch):
        """Corrupt .pf file is skipped without crashing."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        bad_pf = prefetch_dir / "CORRUPT-AABBCCDD.pf"
        bad_pf.write_bytes(b"\x00" * 16)
        result = parse_prefetch(disk_mount=str(tmp_path))
        # Corrupt file skipped, no crash
        assert isinstance(result["output"], list)
        assert result["record_count"] == len(result["output"])

    def test_prefetch_live_parses_filenames(self, tmp_path, monkeypatch):
        """Create temp .pf files and verify executable names extracted."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "PSEXEC.EXE-AD70946C.pf").write_bytes(b"\x00")
        (prefetch_dir / "CMD.EXE-12345678.pf").write_bytes(b"\x00")
        (prefetch_dir / "POWERSHELL.EXE-AABBCCDD.pf").write_bytes(b"\x00")
        result = parse_prefetch(disk_mount=str(tmp_path))
        assert result["record_count"] == 3
        names = [r["executable_name"] for r in result["output"]]
        assert "PSEXEC.EXE" in names
        assert "CMD.EXE" in names
        assert "POWERSHELL.EXE" in names

    def test_prefetch_handles_no_dash(self, tmp_path, monkeypatch):
        """Filename without hash dash returns full stem as executable."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "UNKNOWN.pf").write_bytes(b"\x00")
        result = parse_prefetch(disk_mount=str(tmp_path))
        assert result["record_count"] == 1
        assert result["output"][0]["executable_name"] == "UNKNOWN"

    def test_prefetch_path_included(self, tmp_path, monkeypatch):
        """Each record includes the full path to the .pf file."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        prefetch_dir = tmp_path / "Windows" / "Prefetch"
        prefetch_dir.mkdir(parents=True)
        (prefetch_dir / "CALC.EXE-11111111.pf").write_bytes(b"\x00")
        result = parse_prefetch(disk_mount=str(tmp_path))
        assert result["output"][0]["path"].endswith("CALC.EXE-11111111.pf")

    def test_no_windowsprefetch_import(self):
        """Codebase must not import windowsprefetch anywhere.

        AST-walk worktree's src/ + run_pipeline.py for Import and
        ImportFrom nodes referencing windowsprefetch. Catches the
        actual antipattern (unwanted dependency) rather than text matches.
        """
        import ast as _ast
        from pathlib import Path as _Path

        repo_root = _Path(__file__).resolve().parents[2]
        scan_paths = [repo_root / "run_pipeline.py"]
        scan_paths.extend((repo_root / "src").rglob("*.py"))

        offenders = []
        for path in scan_paths:
            try:
                module = _ast.parse(path.read_text(errors="ignore"))
            except SyntaxError:
                continue
            for node in _ast.walk(module):
                if isinstance(node, _ast.Import):
                    for alias in node.names:
                        if "windowsprefetch" in alias.name:
                            offenders.append(
                                f"{path.relative_to(repo_root)}:{node.lineno}: import {alias.name}"
                            )
                elif isinstance(node, _ast.ImportFrom):
                    if node.module and "windowsprefetch" in node.module:
                        offenders.append(
                            f"{path.relative_to(repo_root)}:{node.lineno}: from {node.module} import ..."
                        )

        assert offenders == [], (
            "windowsprefetch still imported:\n" + "\n".join(offenders)
        )

    def test_prefetch_registered_as_mcp_tool(self):
        """parse_prefetch is registered as an MCP tool in server."""
        import server
        assert hasattr(server, "tool_parse_prefetch")
        assert callable(getattr(server, "tool_parse_prefetch"))


# ── Output shape (both tools) ────────────────────────────────────────

class TestOutputShape:
    def test_event_logs_has_required_keys(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        mount, ctx = _setup_evtx_env(tmp_path, SAMPLE_EVTX_RECORDS)
        with ctx:
            result = parse_event_logs(disk_mount=mount)
        assert "output" in result
        assert "record_count" in result

    def test_shellbags_no_default_path(self):
        """parse_shellbags() with no csv_path returns error, not crash."""
        result = parse_shellbags()
        assert result["output"] == []
        assert result["record_count"] == 0
        assert "no shellbags path provided" in result["error"]

    def test_shellbags_has_required_keys(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("Name,Value\nDesktop,folder\n")
        result = parse_shellbags(csv_path=str(csv_file))
        assert "output" in result
        assert "record_count" in result


# ── Live-mode evtx timeout tests ────────────────────────────────────

class TestEvtxTimeout:
    def test_corrupt_file_skipped_via_timeout(self, tmp_path, monkeypatch):
        """A .evtx file that hangs is skipped after timeout."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)

        evtx_dir = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        # Write a corrupt evtx file (invalid header causes hang or error)
        corrupt = evtx_dir / "Corrupt.evtx"
        corrupt.write_bytes(b"\x00" * 4096)

        result = parse_event_logs(disk_mount=str(tmp_path), max_records=100)
        # Should not hang; corrupt file skipped
        assert isinstance(result["output"], list)
        assert result["record_count"] == len(result["output"])

    def test_max_records_truncates_live(self, tmp_path, monkeypatch):
        """max_records truncates output from mock EVTX parsing."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        records = [
            {"EventID": i, "TimeCreated": f"2018-09-05T{i:02d}:00:00.000Z",
             "Provider": "test", "Channel": "System",
             "Computer": "PC", "Message": "msg"}
            for i in range(20)
        ]
        mount, ctx = _setup_evtx_env(tmp_path, records)
        with ctx:
            result = parse_event_logs(disk_mount=mount, max_records=5)
        assert result["record_count"] == 5


# ── No "not implemented" in disk tools ───────────────────────────────

class TestNoNotImplemented:
    def test_no_not_implemented_in_disk(self):
        """No disk tool should contain 'not implemented' in source."""
        from sift_sentinel.tools import disk
        src = inspect.getsource(disk)
        assert "not implemented" not in src.lower(), \
            "disk.py still has 'not implemented'"

    def test_no_not_implemented_in_disk_extended(self):
        """No disk_extended tool should contain 'not implemented' in source."""
        from sift_sentinel.tools import disk_extended
        src = inspect.getsource(disk_extended)
        assert "not implemented" not in src.lower(), \
            "disk_extended.py still has 'not implemented'"
