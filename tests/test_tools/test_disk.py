"""
Tests for disk tools: get_amcache and extract_mft_timeline.
Each tool reads from disk and returns typed output matching the standard JSON envelope schema (see ARCHITECTURE.md).
Tests mock the parsing functions to avoid needing a real disk mount.
"""

import os
from unittest.mock import patch

import pytest

from sift_sentinel.tools.disk import (
    get_amcache,
    extract_mft_timeline,
    _parse_amcache_live,
    _build_mft_from_find,
)

DUMMY_DISK = "/evidence/synthetic-disk.e01"

ATTACK_START = "2018-09-04"
ATTACK_END = "2018-09-07"

# Mock amcache entries for unit tests
_MOCK_AMCACHE = [
    {"path": f"c:\\windows\\system32\\prog{i}.exe",
     "sha1": f"{i:0>40x}", "first_run": f"2018-09-0{4 + i % 4}",
     "publisher": None, "file_size": 1000 + i}
    for i in range(35)
] + [
    {"path": "c:\\windows\\psexesvc.exe",
     "sha1": "a" * 40, "first_run": "2018-09-04",
     "publisher": None, "file_size": 50000},
]

# Mock MFT events for unit tests
_MOCK_MFT_EVENTS = [
    {"path": f"/Windows/file{i}.exe", "filename": f"file{i}.exe",
     "si_created": "", "fn_created": "",
     "si_modified": f"2018-09-0{4 + i % 4}T{10 + i:02d}:00:00.000000Z",
     "fn_modified": "", "action": "exists", "file_size": None,
     "si_lt_fn": False, "usec_zeros": False}
    for i in range(150)
]


# ── Envelope shape ─────────────────────────────────────────────────────

def _check_envelope(result: dict, tool_name: str):
    assert result["tool_name"] == tool_name
    assert isinstance(result["execution_time_ms"], int)
    assert result["execution_time_ms"] >= 0
    assert isinstance(result["evidence_path"], str)
    assert isinstance(result["record_count"], int)
    assert result["record_count"] > 0
    assert "output" in result


# ── get_amcache ────────────────────────────────────────────────────────

class TestGetAmcache:
    @pytest.fixture(autouse=True)
    def _mock_parser(self, monkeypatch):
        monkeypatch.setattr(
            "sift_sentinel.tools.disk._parse_amcache_live",
            lambda disk_mount: list(_MOCK_AMCACHE),
        )

    def test_returns_envelope(self):
        result = get_amcache(DUMMY_DISK)
        _check_envelope(result, "get_amcache")

    def test_output_has_entries(self):
        result = get_amcache(DUMMY_DISK)
        entries = result["output"]["entries"]
        assert isinstance(entries, list)
        assert len(entries) >= 30

    def test_entry_has_required_fields(self):
        result = get_amcache(DUMMY_DISK)
        entry = result["output"]["entries"][0]
        for field in ["path", "sha1", "first_run"]:
            assert field in entry, f"Missing field: {field}"

    def test_sha1_format(self):
        result = get_amcache(DUMMY_DISK)
        for entry in result["output"]["entries"]:
            sha1 = entry["sha1"]
            assert len(sha1) == 40, f"Bad SHA1 length: {sha1}"
            assert all(c in "0123456789abcdef" for c in sha1), f"Non-hex SHA1: {sha1}"

    def test_psexesvc_present(self):
        result = get_amcache(DUMMY_DISK)
        paths = [e["path"].lower() for e in result["output"]["entries"]]
        assert any("psexesvc.exe" in p for p in paths)

    def test_platform_tool_field(self):
        result = get_amcache(DUMMY_DISK)
        assert "platform_tool" in result["output"]
        assert isinstance(result["output"]["platform_tool"], str)

    def test_record_count_matches_entries(self):
        result = get_amcache(DUMMY_DISK)
        assert result["record_count"] == len(result["output"]["entries"])

    def test_optional_fields_present(self):
        result = get_amcache(DUMMY_DISK)
        entry = result["output"]["entries"][0]
        assert "publisher" in entry
        assert "file_size" in entry


# ── extract_mft_timeline ───────────────────────────────────────────────

class TestExtractMftTimeline:
    @pytest.fixture(autouse=True)
    def _mock_parser(self, monkeypatch):
        monkeypatch.setattr(
            "sift_sentinel.tools.disk._build_mft_from_find",
            lambda mount, start, end: list(_MOCK_MFT_EVENTS),
        )

    def test_returns_envelope(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        _check_envelope(result, "extract_mft_timeline")

    def test_output_has_events(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        events = result["output"]["events"]
        assert isinstance(events, list)
        assert len(events) >= 100

    def test_event_has_required_fields(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        event = result["output"]["events"][0]
        for field in ["path", "si_created", "si_modified",
                      "fn_created", "fn_modified", "action"]:
            assert field in event, f"Missing field: {field}"

    def test_timestomp_detection_fields(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        event = result["output"]["events"][0]
        assert "timestomped" in event
        assert "real_created" in event
        assert isinstance(event["timestomped"], bool)

    def test_window_filtering(self):
        """Narrow window returns fewer results than full window."""
        full = extract_mft_timeline(DUMMY_DISK, "2018-09-04", "2018-09-07")
        narrow = extract_mft_timeline(DUMMY_DISK, "2018-09-05", "2018-09-05")
        assert len(narrow["output"]["events"]) < len(full["output"]["events"])

    def test_events_within_window(self):
        result = extract_mft_timeline(DUMMY_DISK, "2018-09-05", "2018-09-05")
        for event in result["output"]["events"]:
            ts_fields = [event.get("si_created", ""), event.get("fn_created", ""),
                         event.get("si_modified", ""), event.get("fn_modified", "")]
            in_window = any(t.startswith("2018-09-05") for t in ts_fields if t)
            assert in_window, f"Event outside window: {event['path']}"

    def test_record_count_matches_events(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        assert result["record_count"] == len(result["output"]["events"])

    def test_si_lt_fn_indicates_timestomp(self):
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        for event in result["output"]["events"]:
            if event.get("si_lt_fn"):
                assert event["timestomped"] is True


# ── Error handling ─────────────────────────────────────────────────────

class TestDiskErrorHandling:
    def test_amcache_empty_path(self, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        with pytest.raises(FileNotFoundError):
            get_amcache("")

    def test_amcache_relative_path(self, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        with pytest.raises(FileNotFoundError):
            get_amcache("relative/disk.e01")

    def test_mft_empty_path(self, monkeypatch):
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        with pytest.raises(FileNotFoundError):
            extract_mft_timeline("", "2018-09-04", "2018-09-07")

    def test_mft_bad_date_format(self):
        with pytest.raises(ValueError):
            extract_mft_timeline(DUMMY_DISK, "not-a-date", "2018-09-07")

    def test_mft_invalid_calendar_start(self):
        with pytest.raises(ValueError, match="Invalid calendar date"):
            extract_mft_timeline(DUMMY_DISK, "2024-99-99", "2024-12-31")

    def test_mft_invalid_calendar_end(self):
        with pytest.raises(ValueError, match="Invalid calendar date"):
            extract_mft_timeline(DUMMY_DISK, "2024-01-01", "2024-02-30")

    def test_mft_start_after_end(self):
        with pytest.raises(ValueError, match="start_date must be <= end_date"):
            extract_mft_timeline(DUMMY_DISK, "2018-09-07", "2018-09-04")

    def test_mft_valid_window(self, monkeypatch):
        monkeypatch.setattr(
            "sift_sentinel.tools.disk._build_mft_from_find",
            lambda mount, start, end: list(_MOCK_MFT_EVENTS),
        )
        result = extract_mft_timeline(DUMMY_DISK, ATTACK_START, ATTACK_END)
        assert result["tool_name"] == "extract_mft_timeline"
        assert len(result["output"]["events"]) > 0

    def test_mft_wide_date_range(self, monkeypatch):
        monkeypatch.setattr(
            "sift_sentinel.tools.disk._build_mft_from_find",
            lambda mount, start, end: list(_MOCK_MFT_EVENTS),
        )
        result = extract_mft_timeline(DUMMY_DISK, "2015-01-01", "2025-12-31")
        assert result["tool_name"] == "extract_mft_timeline"
        assert result["record_count"] >= 0
        assert isinstance(result["output"]["events"], list)

    def test_mft_default_dates(self, monkeypatch):
        monkeypatch.setattr(
            "sift_sentinel.tools.disk._build_mft_from_find",
            lambda mount, start, end: list(_MOCK_MFT_EVENTS),
        )
        result = extract_mft_timeline(DUMMY_DISK)
        assert result["tool_name"] == "extract_mft_timeline"
        assert result["record_count"] >= 0
        assert isinstance(result["output"]["events"], list)


# ── Live-mode tests ──────────────────────────────────────────────────

class TestAmcacheLive:
    def test_no_hive_returns_empty(self, tmp_path):
        """Missing Amcache.hve returns [] without error."""
        result = _parse_amcache_live(str(tmp_path))
        assert result == []

    def test_parses_strings_output(self, tmp_path, monkeypatch):
        """Mock strings to return exe paths + SHA1 FileIds."""
        import subprocess as sp

        sha1_a = "a" * 40
        sha1_b = "b" * 40
        strings_output = (
            f"0000{sha1_a}\n"
            "c:\\windows\\system32\\cmd.exe\n"
            f"0000{sha1_b}\n"
            "c:\\users\\admin\\malware.exe\n"
            "some random string\n"
        )

        # Create the Amcache.hve file so path check passes
        hive_dir = tmp_path / "Windows" / "AppCompat" / "Programs"
        hive_dir.mkdir(parents=True)
        (hive_dir / "Amcache.hve").write_bytes(b"\x00" * 16)

        calls = []

        def mock_run(cmd, **kwargs):
            calls.append(cmd)
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = strings_output
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _parse_amcache_live(str(tmp_path))

        assert len(result) == 2
        assert result[0]["path"] == "c:\\windows\\system32\\cmd.exe"
        assert result[0]["sha1"] == sha1_a
        assert result[1]["path"] == "c:\\users\\admin\\malware.exe"
        assert result[1]["sha1"] == sha1_b

    def test_strings_timeout_returns_empty(self, tmp_path, monkeypatch):
        """If strings times out, returns [] gracefully."""
        import subprocess as sp

        hive_dir = tmp_path / "Windows" / "AppCompat" / "Programs"
        hive_dir.mkdir(parents=True)
        (hive_dir / "Amcache.hve").write_bytes(b"\x00" * 16)

        def mock_run(cmd, **kwargs):
            raise sp.TimeoutExpired(cmd, 30)

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _parse_amcache_live(str(tmp_path))
        assert result == []

    def test_get_amcache_live_calls_parser(self, tmp_path, monkeypatch):
        """In live mode, get_amcache delegates to _parse_amcache_live."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        monkeypatch.setattr(
            "sift_sentinel.tools.disk.DISK_MOUNT_PATH", str(tmp_path),
        )
        # Create a real-looking evidence path for check_disk_path
        evidence = tmp_path / "disk.e01"
        evidence.write_bytes(b"\x00")

        result = get_amcache(str(evidence))
        assert result["tool_name"] == "get_amcache"
        assert result["output"]["entries"] == []
        assert result["record_count"] == 0

    def test_deduplicates_paths(self, tmp_path, monkeypatch):
        """Same path seen twice should produce one entry."""
        import subprocess as sp

        hive_dir = tmp_path / "Windows" / "AppCompat" / "Programs"
        hive_dir.mkdir(parents=True)
        (hive_dir / "Amcache.hve").write_bytes(b"\x00" * 16)

        strings_output = (
            "c:\\windows\\system32\\cmd.exe\n"
            "c:\\windows\\system32\\cmd.exe\n"
        )

        def mock_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = strings_output
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _parse_amcache_live(str(tmp_path))
        assert len(result) == 1


class TestMftLive:
    def test_no_mount_returns_empty(self):
        """Non-existent mount point returns []."""
        result = _build_mft_from_find("/nonexistent/mount", "2018-09-04", "2018-09-07")
        assert result == []

    def test_find_fallback_parses_output(self, tmp_path, monkeypatch):
        """Mock find output produces valid MFT events."""
        import subprocess as sp

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        find_output = (
            f"1536127102.000000 Thu 06 Sep 2018 05:38:22 PM UTC {mount}/Windows/evil.exe\n"
            f"1536100000.000000 Thu 06 Sep 2018 10:06:40 AM UTC {mount}/Windows/normal.dll\n"
        )

        def mock_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = find_output
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _build_mft_from_find(mount, "2018-09-04", "2018-09-07")

        assert len(result) == 2
        assert result[0]["filename"] == "normal.dll"  # sorted by time (earlier)
        assert result[1]["filename"] == "evil.exe"
        # epoch 1536100000 -> 2018-09-04, epoch 1536127102 -> 2018-09-05
        assert result[0]["si_modified"].startswith("2018-09-04")
        assert result[1]["si_modified"].startswith("2018-09-05")
        # FN timestamps not available from find fallback
        assert result[0]["fn_created"] == ""
        assert result[0]["si_lt_fn"] is False

    def test_find_filters_by_window(self, tmp_path, monkeypatch):
        """Events outside [start, end] window are excluded."""
        import subprocess as sp

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        find_output = (
            f"1536127102.000000 Thu 06 Sep 2018 05:38:22 PM UTC {mount}/Windows/in_window.exe\n"
            f"1514764800.000000 Mon 01 Jan 2018 12:00:00 AM UTC {mount}/Windows/out_of_window.dll\n"
        )

        def mock_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = find_output
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _build_mft_from_find(mount, "2018-09-04", "2018-09-07")

        assert len(result) == 1
        assert result[0]["filename"] == "in_window.exe"

    def test_find_timeout_returns_empty(self, tmp_path, monkeypatch):
        """If find times out, return [] gracefully."""
        import subprocess as sp

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        def mock_run(cmd, **kwargs):
            raise sp.TimeoutExpired(cmd, 60)

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = _build_mft_from_find(mount, "2018-09-04", "2018-09-07")
        assert result == []

    def test_extract_mft_live_calls_find(self, tmp_path, monkeypatch):
        """In live mode, extract_mft_timeline delegates to _build_mft_from_find."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)
        monkeypatch.setattr(
            "sift_sentinel.tools.disk.DISK_MOUNT_PATH", str(tmp_path),
        )
        evidence = tmp_path / "disk.e01"
        evidence.write_bytes(b"\x00")

        result = extract_mft_timeline(str(evidence), "2018-09-04", "2018-09-07")
        assert result["tool_name"] == "extract_mft_timeline"
        assert isinstance(result["output"]["events"], list)


# ── Bug-fix regression: disk tools must use provided mount path ────────


class TestDiskMountPathPassthrough:
    """Verify disk tools pass disk_path to internal helpers, not DISK_MOUNT_PATH."""

    def test_mft_uses_provided_mount(self, tmp_path, monkeypatch):
        """extract_mft_timeline must call find on the provided path, not /mnt/windows_mount."""
        import subprocess as sp

        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)

        mount = str(tmp_path / "test_mount")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        captured_cmds: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = ""
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        extract_mft_timeline(mount, "2018-09-04", "2018-09-07")

        assert len(captured_cmds) == 1
        find_cmd = captured_cmds[0]
        assert find_cmd[0] == "find"
        assert os.path.join(mount, "Windows") in find_cmd
        assert "/mnt/windows_mount" not in " ".join(find_cmd)

    def test_amcache_uses_provided_mount(self, tmp_path, monkeypatch):
        """get_amcache must look for Amcache.hve under the provided path, not /mnt/windows_mount."""
        monkeypatch.delenv("SIFT_DRY_RUN", raising=False)

        mount = str(tmp_path / "custom_mount")
        os.makedirs(mount)
        hive_dir = tmp_path / "custom_mount" / "Windows" / "AppCompat" / "Programs"
        hive_dir.mkdir(parents=True)
        (hive_dir / "Amcache.hve").write_bytes(b"\x00" * 16)

        import subprocess as sp

        captured_cmds: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = ""
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        result = get_amcache(mount)

        assert result["tool_name"] == "get_amcache"
        # strings was invoked on the Amcache.hve inside our custom mount
        if captured_cmds:
            for cmd in captured_cmds:
                assert "/mnt/windows_mount" not in " ".join(cmd)

    def test_mft_no_hardcoded_path(self):
        """disk.py must not contain the hardcoded '/mnt/windows_mount' in functional code."""
        import inspect
        source = inspect.getsource(extract_mft_timeline)
        assert "/mnt/windows_mount" not in source
        source2 = inspect.getsource(_build_mft_from_find)
        assert "/mnt/windows_mount" not in source2

    def test_all_disk_tools_accept_mount(self):
        """All 5 disk tools accept a disk_mount/disk_path parameter."""
        import inspect
        from sift_sentinel.tools.disk_extended import (
            parse_event_logs, parse_prefetch, parse_shellbags,
        )

        # disk.py tools: first parameter is disk_path
        for fn in (get_amcache, extract_mft_timeline):
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            assert params[0] in ("disk_path", "disk_mount"), \
                f"{fn.__name__} first param is '{params[0]}', expected disk_path/disk_mount"

        # disk_extended.py tools: first parameter is disk_mount or csv_path
        for fn in (parse_event_logs, parse_prefetch):
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            assert params[0] in ("disk_path", "disk_mount"), \
                f"{fn.__name__} first param is '{params[0]}', expected disk_path/disk_mount"

        # parse_shellbags uses csv_path (different pattern, correct by design)
        sig = inspect.signature(parse_shellbags)
        assert "csv_path" in sig.parameters


# ── MFT scope / timeout / cap tests ──────────────────────────────────

class TestMftScopeAndCap:
    """Verify MFT find targets Windows/+Users/, uses 120s timeout, caps at 5000."""

    def test_mft_targets_windows_users(self, tmp_path, monkeypatch):
        """find command targets Windows/ and Users/ dirs, not mount root."""
        import subprocess as sp

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)
        os.makedirs(os.path.join(mount, "Users"), exist_ok=True)

        captured_cmds: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = ""
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        _build_mft_from_find(mount, "2018-09-04", "2018-09-07")

        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]
        assert cmd[0] == "find"
        # Should contain Windows/ and Users/ paths, NOT the bare mount root
        cmd_str = " ".join(cmd)
        assert os.path.join(mount, "Windows") in cmd_str
        assert os.path.join(mount, "Users") in cmd_str
        assert "-maxdepth" in cmd
        assert "5" in cmd

    def test_mft_timeout_120(self, tmp_path, monkeypatch):
        """Timeout must be 120 seconds, not 60."""
        import subprocess as sp

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        captured_kwargs: list[dict] = []

        def mock_run(cmd, **kwargs):
            captured_kwargs.append(kwargs)
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = ""
            r.stderr = ""
            return r

        monkeypatch.setattr("sift_sentinel.tools.disk.subprocess.run", mock_run)
        _build_mft_from_find(mount, "2018-09-04", "2018-09-07")

        assert len(captured_kwargs) == 1
        assert captured_kwargs[0]["timeout"] == 120

    def test_mft_cap_5000(self, tmp_path, monkeypatch):
        """MFT records honor dynamic SIFT_MFT_TIMELINE_MAX."""
        import importlib
        import os
        import subprocess as sp
        import sift_sentinel.tools.disk as disk_mod

        monkeypatch.setenv("SIFT_MFT_TIMELINE_MAX", "5000")
        disk_mod = importlib.reload(disk_mod)

        mount = str(tmp_path / "mnt")
        os.makedirs(os.path.join(mount, "Windows"), exist_ok=True)

        lines = []
        for i in range(6000):
            epoch = 1536100000.0 + i
            lines.append(f"{epoch} Thu 06 Sep 2018 10:00:00 AM UTC {mount}/Windows/f{i}.exe")
        find_output = "\n".join(lines) + "\n"

        def mock_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, 0)
            r.stdout = find_output
            r.stderr = ""
            return r

        monkeypatch.setattr(disk_mod.subprocess, "run", mock_run)
        result = disk_mod._build_mft_from_find(mount, "2018-09-04", "2018-09-07")

        assert len(result) == 5000
        assert len(result) <= int(os.environ["SIFT_MFT_TIMELINE_MAX"])



    def test_mft_missing_dirs_empty(self, tmp_path):
        """No Windows/ or Users/ under mount -> returns []."""
        mount = str(tmp_path / "mnt")
        os.makedirs(mount)  # empty mount, no Windows/ or Users/
        result = _build_mft_from_find(mount, "2018-09-04", "2018-09-07")
        assert result == []
