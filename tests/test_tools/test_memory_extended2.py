"""
Tests for memory_extended2 tools: vol_svcscan, vol_sessions, vol_ssdt,
vol_filescan, vol_reg_hivelist.
Each tool calls run_volatility (mocked in conftest) and returns typed output.
"""

import pytest

from sift_sentinel.tools.memory_extended2 import (
    vol_svcscan,
    vol_sessions,
    vol_ssdt,
    vol_filescan,
    vol_reg_hivelist,
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


# ── vol_svcscan ───────────────────────────────────────────────────────

class TestVolSvcscan:
    def test_returns_envelope(self):
        result = vol_svcscan(DUMMY_IMAGE)
        _check_envelope(result, "vol_svcscan")

    def test_output_keys(self):
        result = vol_svcscan(DUMMY_IMAGE)
        assert "output" in result
        assert "record_count" in result

    def test_record_count_matches(self):
        result = vol_svcscan(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] >= 2

    def test_service_fields(self):
        result = vol_svcscan(DUMMY_IMAGE)
        svc = result["output"][0]
        for field in ["Binary", "Display", "Name", "Offset",
                      "PID", "Start", "State", "Type"]:
            assert field in svc, f"Missing field: {field}"

    def test_no_children_key(self):
        result = vol_svcscan(DUMMY_IMAGE)
        for svc in result["output"]:
            assert "__children" not in svc



# ── vol_sessions ──────────────────────────────────────────────────────

class TestVolSessions:
    def test_returns_envelope(self):
        result = vol_sessions(DUMMY_IMAGE)
        _check_envelope(result, "vol_sessions")

    def test_output_keys(self):
        result = vol_sessions(DUMMY_IMAGE)
        assert "output" in result
        assert "record_count" in result

    def test_record_count_matches(self):
        result = vol_sessions(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] >= 2

    def test_session_fields(self):
        result = vol_sessions(DUMMY_IMAGE)
        sess = result["output"][0]
        for field in ["Create Time", "Process", "Process ID",
                      "Session ID", "Session Type", "User Name"]:
            assert field in sess, f"Missing field: {field}"

    def test_no_children_key(self):
        result = vol_sessions(DUMMY_IMAGE)
        for sess in result["output"]:
            assert "__children" not in sess



# ── vol_ssdt ──────────────────────────────────────────────────────────

class TestVolSsdt:
    def test_returns_envelope(self):
        result = vol_ssdt(DUMMY_IMAGE)
        _check_envelope(result, "vol_ssdt")

    def test_output_keys(self):
        result = vol_ssdt(DUMMY_IMAGE)
        assert "output" in result
        assert "record_count" in result

    def test_record_count_matches(self):
        result = vol_ssdt(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] >= 2

    def test_ssdt_fields(self):
        result = vol_ssdt(DUMMY_IMAGE)
        entry = result["output"][0]
        for field in ["Address", "Index", "Module", "Symbol"]:
            assert field in entry, f"Missing field: {field}"

    def test_no_children_key(self):
        result = vol_ssdt(DUMMY_IMAGE)
        for entry in result["output"]:
            assert "__children" not in entry



# ── vol_filescan ──────────────────────────────────────────────────────

class TestVolFilescan:
    def test_returns_envelope(self):
        result = vol_filescan(DUMMY_IMAGE)
        _check_envelope(result, "vol_filescan")

    def test_output_keys(self):
        result = vol_filescan(DUMMY_IMAGE)
        assert "output" in result
        assert "record_count" in result

    def test_record_count_matches(self):
        result = vol_filescan(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] >= 2

    def test_filescan_fields(self):
        result = vol_filescan(DUMMY_IMAGE)
        entry = result["output"][0]
        for field in ["Name", "Offset"]:
            assert field in entry, f"Missing field: {field}"

    def test_no_children_key(self):
        result = vol_filescan(DUMMY_IMAGE)
        for entry in result["output"]:
            assert "__children" not in entry



# ── vol_reg_hivelist ──────────────────────────────────────────────────

class TestVolRegHivelist:
    def test_returns_envelope(self):
        result = vol_reg_hivelist(DUMMY_IMAGE)
        _check_envelope(result, "vol_reg_hivelist")

    def test_output_keys(self):
        result = vol_reg_hivelist(DUMMY_IMAGE)
        assert "output" in result
        assert "record_count" in result

    def test_record_count_matches(self):
        result = vol_reg_hivelist(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])
        assert result["record_count"] >= 2

    def test_hivelist_fields(self):
        result = vol_reg_hivelist(DUMMY_IMAGE)
        entry = result["output"][0]
        for field in ["File output", "FileFullPath", "Offset"]:
            assert field in entry, f"Missing field: {field}"

    def test_no_children_key(self):
        result = vol_reg_hivelist(DUMMY_IMAGE)
        for entry in result["output"]:
            assert "__children" not in entry



# ── Error handling ─────────────────────────────────────────────────────

class TestErrorHandling:
    def test_svcscan_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_svcscan("")

    def test_sessions_relative_path(self):
        with pytest.raises(FileNotFoundError):
            vol_sessions("relative/image.img")

    def test_ssdt_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_ssdt("/tmp/image.txt")

    def test_filescan_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_filescan("")

    def test_hivelist_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_reg_hivelist("/tmp/image.doc")
