"""
Tests for memory_extended tools: vol_psscan, vol_handles, vol_envars,
vol_getsids, vol_privileges.
Each tool calls run_volatility (mocked in conftest) and returns typed output.
"""

import pytest

from sift_sentinel.tools.memory_extended import (
    vol_psscan,
    vol_handles,
    vol_envars,
    vol_getsids,
    vol_privileges,
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


# ── vol_psscan ─────────────────────────────────────────────────────────

class TestVolPsscan:
    def test_returns_envelope(self):
        result = vol_psscan(DUMMY_IMAGE)
        _check_envelope(result, "vol_psscan")

    def test_flat_list(self):
        result = vol_psscan(DUMMY_IMAGE)
        procs = result["output"]
        assert isinstance(procs, list)
        assert len(procs) >= 2

    def test_process_fields(self):
        result = vol_psscan(DUMMY_IMAGE)
        proc = result["output"][0]
        for field in ["PID", "PPID", "ImageFileName", "Offset(V)",
                      "CreateTime", "ExitTime"]:
            assert field in proc, f"Missing field: {field}"

    def test_no_children_key(self):
        """__children must be stripped from output records."""
        result = vol_psscan(DUMMY_IMAGE)
        for proc in result["output"]:
            assert "__children" not in proc

    def test_record_count_matches(self):
        result = vol_psscan(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_handles ────────────────────────────────────────────────────────

class TestVolHandles:
    def test_returns_envelope(self):
        result = vol_handles(DUMMY_IMAGE)
        _check_envelope(result, "vol_handles")

    def test_flat_list(self):
        result = vol_handles(DUMMY_IMAGE)
        handles = result["output"]
        assert isinstance(handles, list)
        assert len(handles) >= 2

    def test_handle_fields(self):
        result = vol_handles(DUMMY_IMAGE)
        handle = result["output"][0]
        for field in ["PID", "Process", "Offset", "HandleValue",
                      "Type", "GrantedAccess", "Name"]:
            assert field in handle, f"Missing field: {field}"

    def test_pid_filter(self):
        result = vol_handles(DUMMY_IMAGE, pid=4)
        handles = result["output"]
        assert len(handles) >= 1
        assert all(h["PID"] == 4 for h in handles)

    def test_record_count_matches(self):
        result = vol_handles(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_envars ─────────────────────────────────────────────────────────

class TestVolEnvars:
    def test_returns_envelope(self):
        result = vol_envars(DUMMY_IMAGE)
        _check_envelope(result, "vol_envars")

    def test_flat_list(self):
        result = vol_envars(DUMMY_IMAGE)
        envs = result["output"]
        assert isinstance(envs, list)
        assert len(envs) >= 2

    def test_envar_fields(self):
        result = vol_envars(DUMMY_IMAGE)
        env = result["output"][0]
        for field in ["PID", "Process", "Block", "Variable", "Value"]:
            assert field in env, f"Missing field: {field}"

    def test_pid_filter(self):
        result = vol_envars(DUMMY_IMAGE, pid=2360)
        envs = result["output"]
        assert len(envs) >= 1
        assert all(e["PID"] == 2360 for e in envs)

    def test_record_count_matches(self):
        result = vol_envars(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_getsids ────────────────────────────────────────────────────────

class TestVolGetsids:
    def test_returns_envelope(self):
        result = vol_getsids(DUMMY_IMAGE)
        _check_envelope(result, "vol_getsids")

    def test_flat_list(self):
        result = vol_getsids(DUMMY_IMAGE)
        sids = result["output"]
        assert isinstance(sids, list)
        assert len(sids) >= 2

    def test_sid_fields(self):
        result = vol_getsids(DUMMY_IMAGE)
        sid = result["output"][0]
        for field in ["PID", "Process", "SID", "Name"]:
            assert field in sid, f"Missing field: {field}"

    def test_pid_filter(self):
        result = vol_getsids(DUMMY_IMAGE, pid=4)
        sids = result["output"]
        assert len(sids) >= 1
        assert all(s["PID"] == 4 for s in sids)

    def test_record_count_matches(self):
        result = vol_getsids(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── vol_privileges ─────────────────────────────────────────────────────

class TestVolPrivileges:
    def test_returns_envelope(self):
        result = vol_privileges(DUMMY_IMAGE)
        _check_envelope(result, "vol_privileges")

    def test_flat_list(self):
        result = vol_privileges(DUMMY_IMAGE)
        privs = result["output"]
        assert isinstance(privs, list)
        assert len(privs) >= 2

    def test_privilege_fields(self):
        result = vol_privileges(DUMMY_IMAGE)
        priv = result["output"][0]
        for field in ["PID", "Process", "Value", "Privilege",
                      "Attributes", "Description"]:
            assert field in priv, f"Missing field: {field}"

    def test_pid_filter(self):
        result = vol_privileges(DUMMY_IMAGE, pid=4)
        privs = result["output"]
        assert len(privs) >= 1
        assert all(p["PID"] == 4 for p in privs)

    def test_record_count_matches(self):
        result = vol_privileges(DUMMY_IMAGE)
        assert result["record_count"] == len(result["output"])


# ── Error handling ─────────────────────────────────────────────────────

class TestErrorHandling:
    def test_psscan_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_psscan("")

    def test_handles_relative_path(self):
        with pytest.raises(FileNotFoundError):
            vol_handles("relative/image.img")

    def test_envars_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_envars("/tmp/image.txt")

    def test_getsids_empty_path(self):
        with pytest.raises(FileNotFoundError):
            vol_getsids("")

    def test_privileges_bad_extension(self):
        with pytest.raises(FileNotFoundError):
            vol_privileges("/tmp/image.doc")
