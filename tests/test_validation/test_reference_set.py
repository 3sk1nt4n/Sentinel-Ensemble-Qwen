"""Tests for reference_set.py -- paired value extraction from tool outputs."""

import pytest

from sift_sentinel.validation.reference_set import (
    build_reference_set,
    dkom_check,
    normalize_timestamp,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _envelope(tool_name, output):
    """Minimal tool output envelope for testing."""
    if isinstance(output, list):
        rc = len(output)
    elif isinstance(output, dict):
        for v in output.values():
            if isinstance(v, list):
                rc = len(v)
                break
        else:
            rc = 0
    else:
        rc = 0
    return {
        "tool_name": tool_name,
        "execution_time_ms": 1,
        "evidence_path": "/evidence/test.mem",
        "record_count": rc,
        "output": output,
    }


# ── normalize_timestamp ──────────────────────────────────────────────────

class TestNormalizeTimestamp:
    def test_strip_trailing_z(self):
        assert normalize_timestamp("14:22:07Z") == "14:22:07"

    def test_strip_tz_offset(self):
        assert normalize_timestamp("2018-08-30T13:52:22+00:00") == "2018-08-30 13:52:22"

    def test_replace_t_separator(self):
        assert normalize_timestamp("2018-08-30T13:52:22") == "2018-08-30 13:52:22"

    def test_strip_fractional_seconds(self):
        assert normalize_timestamp("2013-08-22 13:31:02.9116340") == "2013-08-22 13:31:02"

    def test_already_normalized(self):
        assert normalize_timestamp("2024-11-14 02:31:07") == "2024-11-14 02:31:07"

    def test_time_only(self):
        assert normalize_timestamp("14:22:07") == "14:22:07"

    def test_time_only_with_z(self):
        assert normalize_timestamp("14:22:07Z") == "14:22:07"

    def test_empty_string(self):
        assert normalize_timestamp("") == ""

    def test_none_returns_empty(self):
        assert normalize_timestamp(None) == ""

    def test_different_tz_offsets_not_collapsed(self):
        """UTC+00:00 and UTC-05:00 must produce DIFFERENT normalized values."""
        utc = normalize_timestamp("2018-08-30T13:52:22+00:00")
        est = normalize_timestamp("2018-08-30T13:52:22-05:00")
        assert utc != est
        assert utc == "2018-08-30 13:52:22"
        assert est == "2018-08-30 18:52:22"

    def test_negative_offset_converted_to_utc(self):
        """Negative UTC offset adds hours when converting to UTC."""
        result = normalize_timestamp("2018-09-01T08:00:00-04:00")
        assert result == "2018-09-01 12:00:00"

    def test_positive_offset_converted_to_utc(self):
        """Positive UTC offset subtracts hours when converting to UTC."""
        result = normalize_timestamp("2018-09-01T20:00:00+05:30")
        assert result == "2018-09-01 14:30:00"


# ── build_reference_set ──────────────────────────────────────────────────

class TestBuildReferenceSet:
    def test_empty_input_returns_skeleton(self):
        ref = build_reference_set({})
        assert ref["hashes"] == {}
        assert ref["pid_to_process"] == {}
        assert ref["timestamps_per_artifact"] == {}
        assert ref["connections"] == {}
        assert ref["paths"] == {}

    # ── AmCache ──────────────────────────────────────────────────────────

    def test_amcache_hashes_paired(self):
        out = {
            "get_amcache": _envelope("get_amcache", {
                "entries": [
                    {"path": r"C:\Windows\payload.exe",
                     "sha1": "A3F2C8D1E5", "first_run": "2024-11-14 02:31:07"},
                    {"path": r"C:\Temp\ransom.exe",
                     "sha1": "D4E1F2A3B5", "first_run": "2024-11-14 04:47:13"},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert ref["hashes"]["a3f2c8d1e5"] == "payload.exe"
        assert ref["hashes"]["d4e1f2a3b5"] == "ransom.exe"

    def test_amcache_timestamps(self):
        out = {
            "get_amcache": _envelope("get_amcache", {
                "entries": [
                    {"path": r"C:\payload.exe",
                     "sha1": "aaa", "first_run": "2024-11-14 02:31:07"},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert "2024-11-14 02:31:07" in ref["timestamps_per_artifact"]["payload.exe"]

    def test_amcache_paths(self):
        out = {
            "get_amcache": _envelope("get_amcache", {
                "entries": [
                    {"path": r"C:\Windows\System32\svchost.exe",
                     "sha1": "abc123", "first_run": "2024-01-01"},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert ref["paths"]["svchost.exe"] == [r"C:\Windows\System32\svchost.exe"]

    # ── vol_pstree ───────────────────────────────────────────────────────

    def test_pstree_pid_to_process(self):
        out = {
            "vol_pstree": _envelope("vol_pstree", [
                {"PID": 4, "ImageFileName": "System", "PPID": 0},
                {"PID": 556, "ImageFileName": "svchost.exe", "PPID": 616},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][4] == ["System"]
        assert ref["pid_to_process"][556] == ["svchost.exe"]

    def test_pstree_timestamps(self):
        out = {
            "vol_pstree": _envelope("vol_pstree", [
                {"PID": 4, "ImageFileName": "System", "PPID": 0,
                 "CreateTime": "2018-08-30T13:51:58+00:00"},
            ]),
        }
        ref = build_reference_set(out)
        assert "2018-08-30 13:51:58" in ref["timestamps_per_artifact"]["system"]

    # ── vol_netscan ──────────────────────────────────────────────────────

    def test_netscan_pid_and_connections(self):
        out = {
            "vol_netscan": _envelope("vol_netscan", [
                {"PID": 556, "Owner": "svchost.exe",
                 "LocalAddr": "0.0.0.0", "LocalPort": 49666,
                 "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                 "State": "LISTENING", "Proto": "TCPv4"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][556] == ["svchost.exe"]
        assert len(ref["connections"]) == 1

    # ── vol_malfind ──────────────────────────────────────────────────────

    def test_malfind_pid_to_process(self):
        out = {
            "vol_malfind": _envelope("vol_malfind", [
                {"PID": 9005, "Process": "payload.exe"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][9005] == ["payload.exe"]

    # ── vol_cmdline ──────────────────────────────────────────────────────

    def test_cmdline_pid_to_process(self):
        out = {
            "vol_cmdline": _envelope("vol_cmdline", [
                {"PID": 388, "Process": "smss.exe",
                 "Args": r"\SystemRoot\System32\smss.exe"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][388] == ["smss.exe"]

    # ── vol_dlllist ──────────────────────────────────────────────────────

    def test_dlllist_pid_and_paths(self):
        out = {
            "vol_dlllist": _envelope("vol_dlllist", [
                {"PID": 388, "Process": "smss.exe", "Name": "smss.exe",
                 "Path": r"\SystemRoot\System32\smss.exe",
                 "Base": 140695878762496, "Size": 151552},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][388] == ["smss.exe"]
        assert ref["paths"]["smss.exe"] == [r"\SystemRoot\System32\smss.exe"]

    # ── vol_psscan ───────────────────────────────────────────────────────

    def test_psscan_pid_to_process(self):
        out = {
            "vol_psscan": _envelope("vol_psscan", [
                {"PID": 4, "ImageFileName": "System", "PPID": 0,
                 "CreateTime": "2018-08-30T13:51:58+00:00"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][4] == ["System"]

    # ── extract_mft_timeline ─────────────────────────────────────────────

    def test_mft_timestamps_and_paths(self):
        out = {
            "extract_mft_timeline": _envelope("extract_mft_timeline", {
                "events": [
                    {"path": r"C:\Windows\payload.exe",
                     "filename": "payload.exe",
                     "si_created": "2024-11-14 02:31:07.0000000",
                     "fn_created": "2024-11-14 02:31:07.0000000",
                     "timestomped": False},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert "payload.exe" in ref["timestamps_per_artifact"]
        assert "2024-11-14 02:31:07" in ref["timestamps_per_artifact"]["payload.exe"]
        assert ref["paths"]["payload.exe"] == [r"C:\Windows\payload.exe"]

    # ── parse_prefetch ────────────────────────────────────────────────────

    def test_prefetch_paths(self):
        out = {
            "parse_prefetch": _envelope("parse_prefetch", {
                "entries": [
                    {"executable_name": "VENDORX_SRV.EXE",
                     "path": r"C:\Windows\Temp\VENDORX_SRV.EXE",
                     "last_run_times": ["2018-09-05 10:00:00"],
                     "files_accessed": [
                         r"C:\Windows\Temp\config.dat",
                     ]},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert "vendorx_srv.exe" in ref["paths"]
        assert ref["paths"]["vendorx_srv.exe"] == [
            r"C:\Windows\Temp\VENDORX_SRV.EXE",
        ]

    def test_prefetch_timestamps(self):
        out = {
            "parse_prefetch": _envelope("parse_prefetch", {
                "entries": [
                    {"executable_name": "VENDORX_SRV.EXE",
                     "path": "",
                     "last_run_times": ["2018-09-05 10:00:00"],
                     "files_accessed": []},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert "2018-09-05 10:00:00" in ref["timestamps_per_artifact"]["vendorx_srv.exe"]

    def test_prefetch_files_accessed(self):
        out = {
            "parse_prefetch": _envelope("parse_prefetch", {
                "entries": [
                    {"executable_name": "TEST.EXE",
                     "path": "",
                     "last_run_times": [],
                     "files_accessed": [
                         r"C:\Windows\System32\ntdll.dll",
                     ]},
                ],
            }),
        }
        ref = build_reference_set(out)
        assert "ntdll.dll" in ref["paths"]

    # ── Cross-tool merging ───────────────────────────────────────────────

    def test_pstree_and_netscan_same_pid_merges(self):
        out = {
            "vol_pstree": _envelope("vol_pstree", [
                {"PID": 556, "ImageFileName": "svchost.exe", "PPID": 616},
            ]),
            "vol_netscan": _envelope("vol_netscan", [
                {"PID": 556, "Owner": "svchost.exe",
                 "LocalAddr": "0.0.0.0", "LocalPort": 49666,
                 "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                 "State": "LISTENING", "Proto": "TCPv4"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][556] == ["svchost.exe"]

    def test_pstree_wins_first_writer(self):
        """pstree is processed explicitly first; first entry is authoritative."""
        out = {
            "vol_pstree": _envelope("vol_pstree", [
                {"PID": 100, "ImageFileName": "real.exe", "PPID": 1},
            ]),
            "vol_malfind": _envelope("vol_malfind", [
                {"PID": 100, "Process": "real.exe"},
            ]),
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"][100] == ["real.exe"]

    def test_pstree_wins_when_netscan_inserted_first(self):
        """pstree attribution is first (authoritative) even when netscan dict key comes first."""
        out = {}
        out["vol_netscan"] = _envelope("vol_netscan", [
            {"PID": 500, "Owner": "netscan_name.exe",
             "LocalAddr": "0.0.0.0", "LocalPort": 80,
             "ForeignAddr": "1.2.3.4", "ForeignPort": 0},
        ])
        out["vol_pstree"] = _envelope("vol_pstree", [
            {"PID": 500, "ImageFileName": "pstree_name.exe", "PPID": 1},
        ])
        ref = build_reference_set(out)
        # pstree is processed first, so pstree_name is first (authoritative)
        assert ref["pid_to_process"][500][0] == "pstree_name.exe"
        # netscan name is also stored (PID reuse / aliasing)
        assert "netscan_name.exe" in ref["pid_to_process"][500]

    def test_no_duplicate_timestamps(self):
        out = {
            "vol_pstree": _envelope("vol_pstree", [
                {"PID": 4, "ImageFileName": "System",
                 "CreateTime": "2018-08-30T13:51:58+00:00"},
            ]),
            "vol_psscan": _envelope("vol_psscan", [
                {"PID": 4, "ImageFileName": "System",
                 "CreateTime": "2018-08-30T13:51:58+00:00"},
            ]),
        }
        ref = build_reference_set(out)
        ts_list = ref["timestamps_per_artifact"]["system"]
        assert ts_list.count("2018-08-30 13:51:58") == 1

    # ── Edge: envelope with error key (failed tool) ──────────────────────

    def test_failed_tool_skipped(self):
        """Tool outputs with 'error' key and no 'output' are skipped."""
        out = {
            "vol_pstree": {"tool_name": "vol_pstree",
                           "error": "FileNotFoundError: cache missing"},
        }
        ref = build_reference_set(out)
        assert ref["pid_to_process"] == {}


# ── dkom_check ───────────────────────────────────────────────────────────

class TestDkomCheck:
    def test_no_hidden_processes(self):
        pstree = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 556, "ImageFileName": "svchost.exe"},
        ]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 556, "ImageFileName": "svchost.exe"},
        ]
        assert dkom_check(pstree, psscan) == []

    def test_hidden_exe_detected(self):
        pstree = [{"PID": 4, "ImageFileName": "System"}]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 9999, "ImageFileName": "evil.exe",
             "Offset(V)": 123456},
        ]
        result = dkom_check(pstree, psscan)
        assert len(result) == 1
        assert result[0]["pid"] == 9999
        assert result[0]["finding"] == "DKOM_CANDIDATE"
        assert result[0]["confidence"] == "MEDIUM"

    def test_non_exe_ignored(self):
        """Processes without .exe suffix are not DKOM candidates."""
        pstree = [{"PID": 4, "ImageFileName": "System"}]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 100, "ImageFileName": "MemCompression"},
        ]
        assert dkom_check(pstree, psscan) == []

    def test_exited_process_not_flagged(self):
        """Process with ExitTime should NOT be flagged -- exited, not hidden."""
        pstree = [{"PID": 4, "ImageFileName": "System"}]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 7777, "ImageFileName": "hidden.exe",
             "ExitTime": "2018-09-01T10:00:00+00:00"},
        ]
        result = dkom_check(pstree, psscan)
        assert len(result) == 0, "Exited processes must not be flagged as DKOM"

    def test_null_exit_time_flagged(self):
        """ExitTime: None (live process not in pstree) IS flagged as DKOM."""
        pstree = [{"PID": 4, "ImageFileName": "System"}]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 8888, "ImageFileName": "stealth.exe",
             "ExitTime": None, "Offset(V)": 999},
        ]
        result = dkom_check(pstree, psscan)
        assert len(result) == 1
        assert result[0]["pid"] == 8888

    def test_empty_string_exit_time_flagged(self):
        """ExitTime: '' (empty string, treated as absent) IS flagged as DKOM."""
        pstree = [{"PID": 4, "ImageFileName": "System"}]
        psscan = [
            {"PID": 4, "ImageFileName": "System"},
            {"PID": 9001, "ImageFileName": "rootkit.exe",
             "ExitTime": "", "Offset(V)": 111},
        ]
        result = dkom_check(pstree, psscan)
        assert len(result) == 1
        assert result[0]["pid"] == 9001

    def test_empty_inputs(self):
        assert dkom_check([], []) == []
