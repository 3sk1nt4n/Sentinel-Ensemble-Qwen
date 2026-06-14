"""Live VM tool verification against real evidence.

Runs each implemented tool against actual evidence on this SIFT workstation.
Skips entirely if evidence files are absent.
Run with: pytest -m live tests/test_pipeline/test_live_tools.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sift_sentinel.tools.memory import (
    vol_cmdline,
    vol_dlllist,
    vol_malfind,
    vol_netscan,
    vol_pstree,
)
from sift_sentinel.tools.disk import (
    extract_mft_timeline,
    get_amcache,
)

MEMORY_IMAGE = "/synthetic/evidence/memory.img"
DISK_MOUNT = "/mnt/windows_mount"

_skip_no_memory = pytest.mark.skipif(
    not Path(MEMORY_IMAGE).exists(),
    reason=f"Memory image not found: {MEMORY_IMAGE}",
)
_skip_no_disk = pytest.mark.skipif(
    not Path(DISK_MOUNT).exists(),
    reason=f"Disk mount not found: {DISK_MOUNT}",
)

# All tests in this module are live tests
pytestmark = pytest.mark.live


def _check_envelope(result: dict, expected_tool: str) -> None:
    """Verify the standard envelope keys are present and typed correctly."""
    assert result["tool_name"] == expected_tool
    assert isinstance(result["execution_time_ms"], int)
    assert result["execution_time_ms"] >= 0
    assert isinstance(result["record_count"], int)
    assert "output" in result


# ── 1. vol_pstree ──────────────────────────────────────────────────────

@_skip_no_memory
class TestVolPstree:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = vol_pstree(MEMORY_IMAGE)

    def test_envelope(self):
        _check_envelope(self.result, "vol_pstree")

    def test_record_count_positive(self):
        assert self.result["record_count"] > 0

    def test_output_is_list(self):
        assert isinstance(self.result["output"], list)
        assert len(self.result["output"]) > 0

    def test_process_entry_has_pid_and_name(self):
        entry = self.result["output"][0]
        assert "PID" in entry
        assert "ImageFileName" in entry


# ── 2. vol_netscan ─────────────────────────────────────────────────────

@_skip_no_memory
class TestVolNetscan:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = vol_netscan(MEMORY_IMAGE)

    def test_envelope(self):
        _check_envelope(self.result, "vol_netscan")

    def test_record_count_positive(self):
        assert self.result["record_count"] > 0

    def test_has_foreign_addr(self):
        entries = self.result["output"]
        assert isinstance(entries, list)
        has_foreign = any("ForeignAddr" in e for e in entries)
        assert has_foreign, "No entry with ForeignAddr key found"


# ── 3. vol_malfind ─────────────────────────────────────────────────────

@_skip_no_memory
class TestVolMalfind:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = vol_malfind(MEMORY_IMAGE)

    def test_envelope(self):
        _check_envelope(self.result, "vol_malfind")

    def test_output_is_list(self):
        assert isinstance(self.result["output"], list)


# ── 4. vol_cmdline ─────────────────────────────────────────────────────

@_skip_no_memory
class TestVolCmdline:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = vol_cmdline(MEMORY_IMAGE)

    def test_envelope(self):
        _check_envelope(self.result, "vol_cmdline")

    def test_record_count_positive(self):
        assert self.result["record_count"] > 0


# ── 5. vol_dlllist ─────────────────────────────────────────────────────

@_skip_no_memory
class TestVolDlllist:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = vol_dlllist(MEMORY_IMAGE)

    def test_envelope(self):
        _check_envelope(self.result, "vol_dlllist")

    def test_record_count_positive(self):
        assert self.result["record_count"] > 0


# ── 6. get_amcache ─────────────────────────────────────────────────────

@_skip_no_disk
class TestGetAmcache:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = get_amcache(DISK_MOUNT)

    def test_envelope(self):
        _check_envelope(self.result, "get_amcache")

    def test_output_is_dict_with_entries(self):
        output = self.result["output"]
        assert isinstance(output, dict)
        assert "entries" in output
        assert isinstance(output["entries"], list)


# ── 7. extract_mft_timeline ───────────────────────────────────────────

@_skip_no_disk
class TestExtractMftTimeline:

    @pytest.fixture(autouse=True)
    def run_tool(self):
        self.result = extract_mft_timeline(DISK_MOUNT, "2018-09-04", "2018-09-07")

    def test_envelope(self):
        _check_envelope(self.result, "extract_mft_timeline")

    def test_output_is_dict_with_events(self):
        output = self.result["output"]
        assert isinstance(output, dict)
        assert "events" in output
        assert isinstance(output["events"], list)


# ── 8. Field-name drift test removed ─────────────────────────────────
# Cached memory data deleted. Memory tools always run Volatility live.
