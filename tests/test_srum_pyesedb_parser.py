"""TDD (D1b): Linux-native SRUM parser via pyesedb.

SrumECmd is Windows-only (verified on the SIFT box: "Non-Windows platforms not
supported ... Exiting...") so it returns 0 on Linux for EVERY dataset, and the
pipeline masked SRUM as benign ok_no_records. pyesedb reads SRUDB.dat natively
on Linux (verified: 18,516 network-usage rows + 5,993 id-map rows recovered from
the real evidence). These tests lock the pure decode helpers + the pyesedb-first
wiring. Dataset-agnostic: pure ESE/SID/OLE-date decoding, no host/user/path/case
literal. Real-evidence end-to-end proof is a separate side-run (not a committed
test, to keep the suite portable).
"""
import struct

from sift_sentinel.tools import generic as g


def test_format_sid_local_system():
    # Real SruDbIdMapTable IdType=3 blob for S-1-5-18 (from the live SRUDB.dat).
    assert g._srum_format_sid(bytes.fromhex("010100000000000512000000")) == "S-1-5-18"


def test_format_sid_domain_user():
    blob = b"\x01\x05" + (5).to_bytes(6, "big") + struct.pack(
        "<IIIII", 21, 111, 222, 333, 1001)
    assert g._srum_format_sid(blob) == "S-1-5-21-111-222-333-1001"


def test_decode_idmap_blob_app_is_utf16():
    assert g._srum_decode_idmap_blob(0, "!!lsass.exe".encode("utf-16-le")) == "!!lsass.exe"


def test_decode_idmap_blob_user_is_sid():
    assert g._srum_decode_idmap_blob(3, bytes.fromhex("010100000000000512000000")) == "S-1-5-18"


def test_ole_date_to_iso():
    # raw 8 bytes from the live network table -> ~2020 OLE-automation date
    val = struct.unpack("<d", bytes.fromhex("e4388ee3958be540"))[0]
    assert g._srum_ole_to_iso(val).startswith("2020-")


def test_ole_date_invalid_returns_empty():
    assert g._srum_ole_to_iso(0.0) == ""
    assert g._srum_ole_to_iso(None) == ""


def test_run_srumecmd_uses_pyesedb_when_available(monkeypatch, tmp_path):
    f = tmp_path / "SRUDB.dat"
    f.write_bytes(b"\x00")
    rows = [{
        "_srum_table": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        "ApplicationName": "!!chrome.exe",
        "UserSid": "S-1-5-21-1-2-3-1001",
        "TimeStamp": "2020-11-02T08:28:14",
        "BytesSent": 12345, "BytesReceived": 6789012, "SourceFile": str(f),
    }]
    monkeypatch.setattr(g, "_srum_parse_pyesedb", lambda p: rows)
    out = g.run_srumecmd(str(f))
    assert out.get("record_count", 0) == 1
    assert out.get("parser") == "pyesedb"


def test_run_srumecmd_falls_back_when_pyesedb_returns_none(monkeypatch, tmp_path):
    # pyesedb absent / cannot open -> None -> legacy path still runs (no crash).
    f = tmp_path / "SRUDB.dat"
    f.write_bytes(b"\x00")
    monkeypatch.setattr(g, "_srum_parse_pyesedb", lambda p: None)
    out = g.run_srumecmd(str(f))
    assert isinstance(out, dict)
    assert out.get("parser") != "pyesedb"
