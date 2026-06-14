"""Disk-side UserAssist reader: per-user GUI execution history from NTUSER.DAT,
producing the SAME record shape Vol3's userassist plugin emits so the existing
_c_userassist -> userassist_fact compiler is unchanged. Synthetic duck-typed hive
(ROT13 value names + a 72-byte Count blob); universal, no user/program/case literal.
"""
import codecs
from datetime import datetime, timezone

from sift_sentinel.tools.parse_userassist import extract_userassist
from sift_sentinel.analysis.phase2_extractors import _c_userassist


def _rot13(s):
    return codecs.decode(s, "rot_13")


def _count_blob(run_count, dt):
    b = bytearray(72)                       # Win7+ Count value is 72 bytes
    b[4:8] = int(run_count).to_bytes(4, "little")          # run count @ offset 4
    ft = int((dt.timestamp() + 11644473600) * 10_000_000)  # FILETIME @ offset 60
    b[60:68] = ft.to_bytes(8, "little")
    return bytes(b)


class _Val:
    def __init__(self, name, data): self._n = name; self._d = data
    def name(self): return self._n
    def value(self): return self._d


class _Key:
    def __init__(self, name, subkeys=None, values=None):
        self._name = name; self._s = subkeys or []; self._v = values or []
    def name(self): return self._name
    def subkeys(self): return self._s
    def values(self): return self._v
    def subkey(self, n):
        for k in self._s:
            if k.name().lower() == n.lower():
                return k
        raise KeyError(n)


class _Hive:
    def __init__(self, keys): self._k = keys
    def open_key(self, path):
        k = self._k.get(path)
        if k is None:
            raise KeyError(path)
        return k


_UA = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def _ntuser_with_userassist():
    # one launched program (ROT13-encoded name) + a session marker that must be skipped
    prog = _Val(_rot13("Microsoft.Windows.SyntheticApp"),
                _count_blob(7, datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)))
    marker = _Val(_rot13("UEME_CTLSESSION"), b"\x00" * 16)
    count = _Key("Count", values=[prog, marker])
    guid = _Key("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", subkeys=[count])
    ua = _Key("UserAssist", subkeys=[guid])
    return _Hive({_UA: ua})


def test_extracts_rot13_program_count_lastrun_and_skips_session_marker():
    rows = extract_userassist(_ntuser_with_userassist(), user="alice")
    assert len(rows) == 1                                   # session marker skipped
    r = rows[0]
    assert r["Name"] == "Microsoft.Windows.SyntheticApp"    # ROT13-decoded
    assert r["Count"] == 7
    assert r["Last Write Time"].startswith("2020-01-02")    # FILETIME decoded
    assert r["Hive Name"] == r"\Users\alice\NTUSER.DAT"     # compiler extracts user from this
    assert r["source"] == "disk"


def test_records_compile_to_userassist_fact_unchanged():
    rows = extract_userassist(_ntuser_with_userassist(), user="alice")
    facts = [f for _, f, _ in _c_userassist(rows) if f is not None]
    assert len(facts) == 1
    f = facts[0]
    assert f["fact_type"] == "userassist_fact"
    assert f["user"] == "alice"                  # extracted from Hive Name by the compiler
    assert f["run_count"] == 7
    assert f["entry_name"] == "Microsoft.Windows.SyntheticApp"


def test_empty_and_missing_userassist_safe():
    assert extract_userassist(_Hive({}), user="x") == []


def test_runner_not_applicable_when_no_ntuser(tmp_path, monkeypatch):
    # empty mount, no NTUSER hives -> gate-clean not_applicable (no absolute paths)
    monkeypatch.delenv("SIFT_ACTIVE_DISK_MOUNT", raising=False)
    import sift_sentinel.tools.parse_userassist as m
    env = m.parse_userassist(mount_path=str(tmp_path))
    assert env["status"] == "not_applicable" and env["record_count"] == 0
    import json
    assert "/mnt" not in json.dumps(env) and str(tmp_path) not in json.dumps(env)


def test_userassist_fact_family_registered_for_both_producers():
    from sift_sentinel.analysis.validation_family_registry import get_validation_family_registry
    fam = get_validation_family_registry().get("userassist_fact")
    producers = fam["producer_tools"] if isinstance(fam, dict) else fam.producer_tools
    assert "parse_userassist" in producers and "vol_userassist" in producers
