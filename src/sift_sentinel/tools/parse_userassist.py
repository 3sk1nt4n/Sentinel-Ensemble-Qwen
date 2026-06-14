"""UserAssist (per-user GUI program-execution history) from mounted NTUSER.DAT hives.

UserAssist lives in NTUSER\\...\\Explorer\\UserAssist\\{GUID}\\Count as ROT13-encoded
value names plus a binary Count blob (run count + last-run FILETIME). vol_userassist
reads this from the MEMORY image only and frequently returns 0 (only loaded session
hives are visible; the Vol3 parser is flaky); the full per-user history is on DISK.

This disk reader produces the SAME record shape Vol3's userassist plugin emits
("Hive Name" / "Path" / "Name" / "Count" / "Last Write Time" / "Type") so the EXISTING
_c_userassist compiler -> userassist_fact path is byte-for-byte unchanged -- only
source="disk" differs. Strict read-only, mount-only. Universal: keyed on the registry
structure + ROT13, no user/program/case literals.
"""
from __future__ import annotations

import codecs
import os
from datetime import datetime, timezone
from typing import Any

# UserAssist subtree under a per-user NTUSER hive.
_UA_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
# UEME_CTLSESSION is a per-session marker value, not a launched program.
_SESSION_MARKERS = {"UEME_CTLSESSION"}


def _subkeys(key: Any) -> list:
    sk = getattr(key, "subkeys", None)
    sk = sk() if callable(sk) else sk
    return list(sk) if sk else []


def _values(key: Any) -> list:
    v = getattr(key, "values", None)
    v = v() if callable(v) else v
    return list(v) if v else []


def _name(obj: Any) -> str:
    n = getattr(obj, "name", None)
    return str(n() if callable(n) else (n if n is not None else ""))


def _data(value: Any):
    d = getattr(value, "value", None)
    return d() if callable(d) else d


def _open(hive: Any, path: str):
    fn = getattr(hive, "open_key", None) or getattr(hive, "get_key", None)
    if not callable(fn):
        return None
    try:
        return fn(path)
    except Exception:
        return None


def _open_sub(key: Any, name: str):
    """Open a direct subkey by name, duck-typed across registry libs."""
    fn = getattr(key, "subkey", None)
    if callable(fn):
        try:
            return fn(name)
        except Exception:
            return None
    for sub in _subkeys(key):
        if _name(sub).lower() == name.lower():
            return sub
    return None


def _rot13(text: str) -> str:
    try:
        return codecs.decode(str(text), "rot_13")
    except Exception:
        return str(text)


def _filetime_to_iso(ft: int) -> str:
    if not ft:
        return ""
    try:
        secs = ft / 10_000_000 - 11644473600
        if secs <= 0:
            return ""
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def _parse_count_blob(data: Any) -> tuple:
    """(run_count, last_run_iso) from the binary Count value. Win7+ Count is 72 bytes
    (run count @ offset 4, last-run FILETIME @ offset 60); older/XP is 16 bytes (count
    @ offset 4). Robust to length and to a non-bytes value."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
        return None, ""
    b = bytes(data)
    run_count = int.from_bytes(b[4:8], "little")
    last_run = ""
    if len(b) >= 68:
        last_run = _filetime_to_iso(int.from_bytes(b[60:68], "little"))
    return run_count, last_run


def extract_userassist(ntuser_hive: Any, user: str | None = None) -> list[dict]:
    """UserAssist Count entries from one NTUSER hive -> vol-userassist-shaped records.

    Duck-typed: a "hive" exposes ``open_key(path)`` -> key; a key exposes
    ``subkeys()`` / ``values()`` / ``subkey(name)``; a value exposes ``name()`` /
    ``value()``. ROT13-decodes the value name (the launched program); session markers
    are skipped. Universal: no user/program literal.
    """
    out: list[dict] = []
    root = _open(ntuser_hive, _UA_KEY)
    if root is None:
        return out
    hive_name = r"\Users\%s\NTUSER.DAT" % (user or "unknown")
    for guid in _subkeys(root):
        count_key = _open_sub(guid, "Count")
        if count_key is None:
            continue
        gname = _name(guid)
        for v in _values(count_key):
            raw = _name(v)
            name = _rot13(raw).strip()
            if not name or name in _SESSION_MARKERS:
                continue
            run_count, last_run = _parse_count_blob(_data(v))
            out.append({
                "type": "userassist",
                "Type": "UserAssist",
                "Hive Name": hive_name,
                "Path": r"%s\%s\Count\%s" % (_UA_KEY, gname, raw),
                "Name": name,
                "Count": run_count,
                "Last Write Time": last_run,
                "user": (user or "").strip(),
                "source": "disk",
            })
    return out


# ── Live runner: discover NTUSER hives on the active mount, run the extractor ──
from sift_sentinel.tools.parse_registry_persistence import (  # noqa: E402
    _hive_candidates as _reg_hive_candidates,
    _open_registry_hive as _reg_open_hive,
)
from sift_sentinel.tools.parse_usb_devices import _as_extractor_hive  # noqa: E402


def parse_userassist(mount_path: str | None = None,
                     hive_paths: list | None = None,
                     max_hives: int = 50) -> dict:
    """Extract per-user UserAssist execution history from mounted NTUSER hives.

    Resolves the ACTIVE disk mount (SIFT_ACTIVE_DISK_MOUNT) like the other standalone
    disk tools, opens each user's NTUSER.DAT read-only, and runs the pure extractor.
    Records feed the existing _c_userassist -> userassist_fact compiler unchanged.
    Universal: registry structure + ROT13, no case data.
    """
    if mount_path is None and hive_paths is None:
        mount_path = os.environ.get("SIFT_ACTIVE_DISK_MOUNT") or None

    candidates = _reg_hive_candidates(mount_path, hive_paths)
    ntusers = [p for p in candidates
               if p.is_file() and p.name.upper().startswith("NTUSER")]
    if not ntusers:
        return {
            "tool": "parse_userassist",
            "tool_name": "parse_userassist",
            "status": "not_applicable",
            "kind": "not_applicable",
            "reason": "no NTUSER hives on mount",
            "record_count": 0,
            "records": [],
            "searched_hives": sorted({p.name for p in candidates}),
            "errors": [],
        }

    records: list = []
    errors: list = []
    for path in ntusers[:max(0, int(max_hives))]:
        user = path.parent.name
        try:
            hive = _as_extractor_hive(_reg_open_hive(path))
            records += extract_userassist(hive, user)
        except Exception as exc:  # noqa: BLE001 - keep going on a bad hive
            errors.append({"path": f"NTUSER:{user}", "error": f"{type(exc).__name__}: {exc}"})

    return {
        "tool": "parse_userassist",
        "tool_name": "parse_userassist",
        "status": "ok" if records else "ok_no_records",
        "record_count": len(records),
        "records": records,
        "source": "disk",
        "searched_hives": ["NTUSER.DAT(UserAssist)"],
        "errors": errors,
    }


__all__ = ["parse_userassist", "extract_userassist"]
