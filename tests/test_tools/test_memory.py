"""
Tests for memory tools: vol_pstree, vol_netscan, vol_malfind, vol_cmdline, vol_dlllist.
Each tool calls run_volatility (mocked in conftest) and returns typed output.
"""

import pytest
from unittest.mock import patch

from sift_sentinel.tools.memory import (
    vol_pstree,
    vol_netscan,
    vol_malfind,
    vol_cmdline,
    vol_dlllist,
)

DUMMY_IMAGE = "/evidence/synthetic-memory.img"


# ── Envelope shape (common to all tools) ───────────────────────────────

def _check_envelope(result: dict, tool_name: str):
    """Every tool must return the standard envelope."""
    assert result["tool_name"] == tool_name
    assert isinstance(result["execution_time_ms"], int)
    assert result["execution_time_ms"] >= 0
    assert isinstance(result["evidence_path"], str)
    assert isinstance(result["record_count"], int)
    assert result["record_count"] > 0
    assert "output" in result


# ── vol_pstree ─────────────────────────────────────────────────────────

class TestVolPstree:
    def test_returns_envelope(self):
        result = vol_pstree(DUMMY_IMAGE)
        _check_envelope(result, "vol_pstree")

    def test_flattens_tree(self):
        """pstree returns nested __children; tool must flatten to list."""
        result = vol_pstree(DUMMY_IMAGE)
        procs = result["output"]
        assert isinstance(procs, list)
        assert len(procs) >= 4  # System + smss + csrss + svchost

    def test_process_fields(self):
        """Each flattened process has required fields from TESTED list."""
        result = vol_pstree(DUMMY_IMAGE)
        proc = result["output"][0]
        for field in ["PID", "PPID", "ImageFileName", "CreateTime"]:
            assert field in proc, f"Missing field: {field}"

    def test_system_is_pid_4(self):
        """System process must be PID 4, PPID 0."""
        result = vol_pstree(DUMMY_IMAGE)
        system = [p for p in result["output"] if p["ImageFileName"] == "System"]
        assert len(system) == 1
        assert system[0]["PID"] == 4
        assert system[0]["PPID"] == 0

    def test_record_count_matches_output(self):
        result = vol_pstree(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])

    def test_children_stripped(self):
        """__children must not appear in flattened output."""
        result = vol_pstree(DUMMY_IMAGE)
        for proc in result["output"]:
            assert "__children" not in proc


# ── vol_netscan ────────────────────────────────────────────────────────

class TestVolNetscan:
    def test_returns_envelope(self):
        result = vol_netscan(DUMMY_IMAGE)
        _check_envelope(result, "vol_netscan")

    def test_flat_list(self):
        result = vol_netscan(DUMMY_IMAGE)
        conns = result["output"]
        assert isinstance(conns, list)
        assert len(conns) >= 2

    def test_connection_fields(self):
        result = vol_netscan(DUMMY_IMAGE)
        conn = result["output"][0]
        for field in ["PID", "LocalAddr", "LocalPort", "ForeignAddr",
                      "ForeignPort", "State", "Proto"]:
            assert field in conn, f"Missing field: {field}"

    def test_record_count_matches(self):
        result = vol_netscan(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_malfind ────────────────────────────────────────────────────────

class TestVolMalfind:
    def test_returns_envelope(self):
        result = vol_malfind(DUMMY_IMAGE)
        _check_envelope(result, "vol_malfind")

    def test_flat_list(self):
        result = vol_malfind(DUMMY_IMAGE)
        injections = result["output"]
        assert isinstance(injections, list)
        assert len(injections) >= 2

    def test_injection_fields(self):
        result = vol_malfind(DUMMY_IMAGE)
        inj = result["output"][0]
        for field in ["PID", "Process", "Protection", "Start VPN",
                      "End VPN", "Hexdump", "Tag"]:
            assert field in inj, f"Missing field: {field}"

    def test_record_count_matches(self):
        result = vol_malfind(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_cmdline ────────────────────────────────────────────────────────

class TestVolCmdline:
    def test_returns_envelope(self):
        result = vol_cmdline(DUMMY_IMAGE)
        _check_envelope(result, "vol_cmdline")

    def test_flat_list(self):
        result = vol_cmdline(DUMMY_IMAGE)
        cmds = result["output"]
        assert isinstance(cmds, list)
        assert len(cmds) >= 2

    def test_cmdline_fields(self):
        result = vol_cmdline(DUMMY_IMAGE)
        cmd = result["output"][0]
        for field in ["PID", "Process", "Args"]:
            assert field in cmd, f"Missing field: {field}"

    def test_pid_filter(self):
        """When pid is given, only that process is returned."""
        result = vol_cmdline(DUMMY_IMAGE, pid=4)
        cmds = result["output"]
        assert len(cmds) >= 1
        assert all(c["PID"] == 4 for c in cmds)

    def test_record_count_matches(self):
        result = vol_cmdline(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_dlllist ────────────────────────────────────────────────────────

class TestVolDlllist:
    def test_returns_envelope(self):
        result = vol_dlllist(DUMMY_IMAGE)
        _check_envelope(result, "vol_dlllist")

    def test_flat_list(self):
        result = vol_dlllist(DUMMY_IMAGE)
        dlls = result["output"]
        assert isinstance(dlls, list)
        assert len(dlls) >= 2

    def test_dll_fields(self):
        result = vol_dlllist(DUMMY_IMAGE)
        dll = result["output"][0]
        for field in ["PID", "Process", "Name", "Path", "Base", "Size"]:
            assert field in dll, f"Missing field: {field}"

    def test_pid_filter(self):
        result = vol_dlllist(DUMMY_IMAGE, pid=388)
        dlls = result["output"]
        assert len(dlls) >= 1
        assert all(d["PID"] == 388 for d in dlls)

    def test_record_count_matches(self):
        result = vol_dlllist(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── Error handling ─────────────────────────────────────────────────────

class TestErrorHandling:
    def test_pstree_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_pstree("")

    def test_netscan_relative_path(self):
        with pytest.raises(FileNotFoundError):
            vol_netscan("relative/image.img")

    def test_malfind_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_malfind("/tmp/image.txt")

    def test_cmdline_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_cmdline("")

    def test_dlllist_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_dlllist("/tmp/image.doc")


# ── Uppercase extension handling ─────────────────────────────────────────


class TestUppercaseExtensions:
    """Uppercase .RAW, .DMP etc must be accepted."""

    def test_uppercase_raw_accepted(self):
        result = vol_pstree("/evidence/synthetic-memory.RAW")
        assert result["tool_name"] == "vol_pstree"

    def test_uppercase_dmp_accepted(self):
        result = vol_cmdline("/evidence/synthetic-memory.DMP")
        assert result["tool_name"] == "vol_cmdline"

    def test_mixed_case_accepted(self):
        result = vol_netscan("/evidence/synthetic-memory.Raw")
        assert result["tool_name"] == "vol_netscan"


# ── Missing PID rows ────────────────────────────────────────────────────


class TestMissingPIDRows:
    """PID filter must not crash if a row lacks the PID key."""

    def test_cmdline_missing_pid_row_no_crash(self):
        bad_data = [
            {"PID": 4, "Process": "System", "Args": ""},
            {"Process": "broken", "Args": "no pid"},  # missing PID
            {"PID": 100, "Process": "test.exe", "Args": "-f"},
        ]
        with patch("sift_sentinel.tools.memory.run_volatility",
                    return_value=bad_data):
            result = vol_cmdline("/evidence/synthetic-memory.img", pid=100)
        output = result["output"]
        assert len(output) == 1
        assert output[0]["Process"] == "test.exe"

    def test_dlllist_missing_pid_row_no_crash(self):
        bad_data = [
            {"PID": 4, "Process": "System", "Name": "ntdll.dll"},
            {"Process": "broken", "Name": "bad.dll"},  # missing PID
        ]
        with patch("sift_sentinel.tools.memory.run_volatility",
                    return_value=bad_data):
            result = vol_dlllist("/evidence/synthetic-memory.img", pid=4)
        output = result["output"]
        assert len(output) == 1


# ── RuntimeError graceful handling ────────────────────────────────────

class TestRuntimeErrorHandling:
    def test_pstree_returns_empty_on_vol_failure(self):
        with patch("sift_sentinel.tools.memory.run_volatility",
                    side_effect=RuntimeError("vol failed")):
            result = vol_pstree("/evidence/synthetic-memory.img")
        assert result["record_count"] == 0
        assert result["output"] == []

    def test_netscan_returns_empty_on_vol_failure(self):
        with patch("sift_sentinel.tools.memory.run_volatility",
                    side_effect=RuntimeError("vol failed")):
            result = vol_netscan("/evidence/synthetic-memory.img")
        assert result["record_count"] == 0
        assert result["output"] == []
