"""USB / removable-media device facts from the registry (the disk-strong USB story).

USB history is overwhelmingly a DISK/registry discipline -- the high-value artifacts are:
  * USBSTOR  (SYSTEM\\...\\Enum\\USBSTOR) -- device serial + vendor/product = unique
    physical-device identity, and FriendlyName.
  * MountedDevices (SYSTEM\\MountedDevices) -- device -> drive letter / volume GUID.
  * MountPoints2 (NTUSER\\...\\Explorer\\MountPoints2\\<GUID>) -- ties a volume to a USER.

This module is the pure, duck-typed extractor (a "hive" is anything exposing
``open_key(path)`` -> key, and a key exposing ``subkeys()`` and ``values()``), so it is
unit-testable with synthetic hives -- exactly like parse_registry_persistence. The live
mounted-hive / in-memory-hive discovery + wiring to the evidence DB are layered on top.
Universal: keyed on the registry structure, no case data.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

# USBSTOR class subkey shape: "Disk&Ven_<vendor>&Prod_<product>&Rev_<rev>"; the instance
# subkey under it is the device SERIAL (a trailing "&0"/"&1" is an interface suffix).
_USBSTOR_CLASS_RE = re.compile(
    r"(?:Disk&)?Ven_(?P<vendor>[^&]*)&Prod_(?P<product>[^&]*)(?:&Rev_(?P<rev>[^&]*))?",
    re.IGNORECASE)
_DRIVE_LETTER_RE = re.compile(r"^\\DosDevices\\([A-Za-z]):$")


def _subkeys(key: Any) -> list:
    sk = getattr(key, "subkeys", None)
    sk = sk() if callable(sk) else sk
    return list(sk) if sk else []


def _name(obj: Any) -> str:
    n = getattr(obj, "name", None)
    return str(n() if callable(n) else (n if n is not None else "")).strip()


def _values(key: Any) -> list:
    v = getattr(key, "values", None)
    v = v() if callable(v) else v
    return list(v) if v else []


def _value(key: Any, want: str):
    for v in _values(key):
        if _name(v).lower() == want.lower():
            raw = getattr(v, "value", None)
            return raw() if callable(raw) else raw
    return None


def _open(hive: Any, path: str):
    fn = getattr(hive, "open_key", None) or getattr(hive, "get_key", None)
    if not callable(fn):
        return None
    try:
        return fn(path)
    except Exception:
        return None


def extract_usbstor(system_hive: Any, control_set: str = "ControlSet001") -> list[dict]:
    """USB mass-storage devices: serial + vendor/product + FriendlyName.

    A dirty hive (unreplayed transaction logs) can open the USBSTOR key fine
    and then raise ParseException on ITERATION (the child cells are pending
    in the logs). That failure is recorded on the hive's ``parse_errors`` (when
    the adapter provides it) so the runner can attempt log-replay recovery --
    it must never read as "no USB devices"."""
    out: list[dict] = []
    root = _open(system_hive, control_set + r"\Enum\USBSTOR")
    if root is None:
        return out
    try:
        for cls in _subkeys(root):
            cname = _name(cls)
            m = _USBSTOR_CLASS_RE.search(cname)
            vendor = (m.group("vendor") if m else "").replace("_", " ").strip()
            product = (m.group("product") if m else "").replace("_", " ").strip()
            for inst in _subkeys(cls):
                serial = _name(inst)
                out.append({
                    "type": "usb_device",
                    "serial": serial.split("&")[0],          # strip interface suffix
                    "vendor": vendor, "product": product,
                    "friendly_name": str(_value(inst, "FriendlyName") or "").strip(),
                    "registry_path": r"HKLM\SYSTEM\%s\Enum\USBSTOR\%s\%s" % (control_set, cname, serial),
                })
    except Exception as exc:  # noqa: BLE001 - iteration-level dirty-hive failure
        sink = getattr(system_hive, "parse_errors", None)
        if isinstance(sink, list):
            sink.append({
                "path": control_set + r"\Enum\USBSTOR",
                "error": f"{type(exc).__name__}: {exc}",
            })
    return out


def extract_mounted_devices(system_hive: Any) -> list[dict]:
    """Drive-letter -> volume mappings from SYSTEM\\MountedDevices."""
    out: list[dict] = []
    key = _open(system_hive, "MountedDevices")
    if key is None:
        return out
    for v in _values(key):
        m = _DRIVE_LETTER_RE.match(_name(v))
        if m:
            out.append({"type": "mounted_device", "drive_letter": m.group(1).upper() + ":",
                        "registry_path": r"HKLM\SYSTEM\MountedDevices"})
    return out


def extract_mount_points(ntuser_hive: Any, user: str | None = None) -> list[dict]:
    """Per-user mounted volumes (MountPoints2) -- ties a volume GUID to a USER."""
    out: list[dict] = []
    key = _open(ntuser_hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2")
    if key is None:
        return out
    for sub in _subkeys(key):
        guid = _name(sub)
        if guid.startswith("{") or guid.startswith("##"):
            out.append({"type": "mount_point", "volume": guid, "user": (user or "").strip() or None,
                        "registry_path": r"HKCU\...\Explorer\MountPoints2\%s" % guid})
    return out


def _strip_reg_value(data: Any) -> str:
    """Vol3 renders REG_SZ values wrapped in literal double quotes; strip them."""
    s = "" if data is None else str(data)
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.strip()


def _walk_printkey(rows: Any):
    """Depth-first walk of a Vol3 windows.registry.printkey JSON tree (each node may
    carry ``__children``)."""
    stack = list(rows if isinstance(rows, list) else [rows])
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            kids = node.get("__children")
            if isinstance(kids, list):
                stack.extend(kids)


def extract_usbstor_from_printkey(rows: Any, control_set: str = "ControlSet001") -> list[dict]:
    """Parse USBSTOR device identity from a Vol3 ``windows.registry.printkey`` tree
    (the IN-MEMORY SYSTEM hive). Mirrors the disk extractor's output shape so the
    downstream compiler / candidate / validator are identical -- only ``source`` and
    the registry-path provenance differ.

    Robust to the printkey shape: it recursively finds USBSTOR device-class keys
    (``Disk&Ven_X&Prod_Y`` under an ``...Enum\\USBSTOR`` path -- so spurious cross-
    hive key matches without a Ven_/Prod_ class are ignored), then reads each serial
    instance subkey and its FriendlyName value. Universal: registry structure only.
    """
    out: list[dict] = []
    for node in _walk_printkey(rows):
        if node.get("Type") != "Key":
            continue
        cname = str(node.get("Name") or "")
        key_path = str(node.get("Key") or "")
        if "usbstor" not in (key_path + "\\" + cname).lower():
            continue
        m = _USBSTOR_CLASS_RE.search(cname)
        if not m:
            continue
        vendor = (m.group("vendor") or "").replace("_", " ").strip()
        product = (m.group("product") or "").replace("_", " ").strip()
        for inst in (node.get("__children") or []):
            if not isinstance(inst, dict) or inst.get("Type") != "Key":
                continue
            serial = str(inst.get("Name") or "").split("&")[0]
            if not serial:
                continue
            friendly = ""
            for v in (inst.get("__children") or []):
                if isinstance(v, dict) and str(v.get("Name") or "").lower() == "friendlyname":
                    friendly = _strip_reg_value(v.get("Data"))
            out.append({
                "type": "usb_device",
                "serial": serial,
                "vendor": vendor, "product": product,
                "friendly_name": friendly,
                "registry_path": r"HKLM\SYSTEM\%s\Enum\USBSTOR\%s\%s" % (
                    control_set, cname, str(inst.get("Name") or "")),
                "source": "memory",
            })
    return out


def extract_usb_devices(system_hive: Any = None, ntuser_hives: dict | None = None,
                        control_set: str = "ControlSet001") -> list[dict]:
    """All USB/removable records from the available hives. ntuser_hives maps user -> hive."""
    records: list[dict] = []
    if system_hive is not None:
        records += extract_usbstor(system_hive, control_set)
        records += extract_mounted_devices(system_hive)
    for user, hive in (ntuser_hives or {}).items():
        records += extract_mount_points(hive, user)
    return records


# ── Live runner: discover + open hives, run the pure extractor ────────────
# Reuse the proven disk hive discovery + python-registry opener from the
# registry-persistence tool so USB inherits the SAME read-only, mount-only
# semantics (no live registry, no command exec, no writes to the mount). The
# ``hive_paths`` override is the drop-in injection point a future memory-carve
# increment uses to feed already-materialized hives without touching this code.
from sift_sentinel.tools.parse_registry_persistence import (  # noqa: E402
    _hive_candidates as _reg_hive_candidates,
    _open_registry_hive as _reg_open_hive,
)


class _RegistryHiveAdapter:
    """Adapt a python-registry ``Registry`` to the extractor's duck-type.

    python-registry exposes ``reg.open(path)`` (raising on a missing key); the
    pure extractor wants ``hive.open_key(path)`` returning None when absent.

    A missing key and an UNPARSEABLE key are different facts: a hive imaged
    from a live box carries unreplayed transaction logs, and python-registry
    raises ParseException on exactly the keys whose cells are pending in the
    logs. Those are recorded in ``parse_errors`` (classified by exception
    name, so synthetic hives need no library import) so the runner can
    attempt transaction-log replay instead of reporting a clean zero.
    """

    def __init__(self, reg: Any):
        self._reg = reg
        self.parse_errors: list[dict] = []

    def open_key(self, path: str):
        try:
            return self._reg.open(path)
        except Exception as exc:  # noqa: BLE001 - classified below
            if "notfound" not in type(exc).__name__.lower():
                self.parse_errors.append({
                    "path": path,
                    "error": f"{type(exc).__name__}: {exc}",
                })
            return None


def _as_extractor_hive(reg: Any):
    """Synthetic hives pass through untouched; real python-registry gets wrapped."""
    if hasattr(reg, "open_key") or hasattr(reg, "get_key"):
        return reg
    return _RegistryHiveAdapter(reg)


def _usb_envelope(status: str, records: list, searched_paths: list,
                  errors: list, reason: str | None = None) -> dict:
    env = {
        "tool": "parse_usb_devices",
        "tool_name": "parse_usb_devices",
        "status": status,
        "record_count": len(records),
        "records": records,
        "searched_paths": searched_paths,
        "errors": errors,
    }
    if reason:
        env["reason"] = reason
    return env


# ── Dirty-hive recovery: RECmd transaction-log replay fallback ────────────
# python-registry reads the BASE hive only; cells still pending in the
# SYSTEM.LOG1/LOG2 transaction logs raise ParseException on open/iteration.
# Zimmerman's RECmd replays the logs (same engine the run_*ecmd runners use),
# so USBSTOR device identity is recoverable from exactly the hives a live
# acquisition produces. Typed function, fixed argv, bounded timeout, operates
# on a SCRATCH COPY of the hive+logs (the evidence mount stays untouched).

def _parse_recmd_usbstor_json(data: Any, control_set: str) -> list[dict]:
    """Flatten RECmd's recursive --json export of Enum\\USBSTOR into the same
    record shape the pure extractor emits, plus replay provenance."""
    out: list[dict] = []
    for cls in (data or {}).get("SubKeys") or []:
        cname = str(cls.get("KeyName") or "")
        m = _USBSTOR_CLASS_RE.search(cname)
        vendor = (m.group("vendor") if m else "").replace("_", " ").strip()
        product = (m.group("product") if m else "").replace("_", " ").strip()
        for inst in cls.get("SubKeys") or []:
            serial = str(inst.get("KeyName") or "")
            if not serial:
                continue
            friendly = ""
            for v in inst.get("Values") or []:
                if str(v.get("ValueName") or "").lower() == "friendlyname":
                    friendly = str(v.get("ValueData") or "").strip()
                    break
            out.append({
                "type": "usb_device",
                "serial": serial.split("&")[0],
                "vendor": vendor, "product": product,
                "friendly_name": friendly,
                "registry_path": r"HKLM\SYSTEM\%s\Enum\USBSTOR\%s\%s"
                                 % (control_set, cname, serial),
                "last_write": str(inst.get("LastWriteTimestamp") or ""),
                "recovered_via": "registry_transaction_log_replay",
            })
    return out


def _usbstor_via_recmd(system_hive_path, control_set: str = "ControlSet001",
                       timeout_s: int = 120) -> list[dict]:
    """Recover USBSTOR from a dirty SYSTEM hive via RECmd log replay.
    Returns [] when RECmd/dotnet is unavailable or recovery fails -- the
    caller then reports a degraded status instead of a silent empty."""
    import shutil
    import tempfile
    from pathlib import Path

    dll = os.environ.get("SIFT_RECMD_DLL",
                         "/opt/zimmermantools/RECmd/RECmd.dll")
    dotnet = shutil.which("dotnet")
    src = Path(str(system_hive_path))
    if not (dotnet and os.path.isfile(dll) and src.is_file()):
        return []
    tmp = tempfile.mkdtemp(prefix="sift-usb-recmd-")
    try:
        hive_copy = Path(tmp) / src.name
        shutil.copyfile(src, hive_copy)
        for suffix in (".LOG1", ".LOG2", ".LOG"):
            log = src.with_name(src.name + suffix)
            if log.is_file():
                shutil.copyfile(log, Path(tmp) / log.name)
        proc = subprocess.run(
            [dotnet, dll, "-f", str(hive_copy),
             "--kn", control_set + r"\Enum\USBSTOR", "--json", tmp],
            capture_output=True, text=True, timeout=timeout_s,
        )
        if proc.returncode != 0:
            return []
        export = Path(tmp) / "USBSTOR.json"
        if not export.is_file():
            return []
        return _parse_recmd_usbstor_json(
            json.loads(export.read_text(errors="replace")), control_set)
    except Exception:  # noqa: BLE001 - recovery is best-effort; caller degrades
        return []
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)


def _usb_from_memory(image_path: str) -> tuple[list, list]:
    """Carve USBSTOR device identity from the IN-MEMORY SYSTEM hive via ONE Vol3
    ``windows.registry.printkey`` call (the same registry-from-memory mechanism
    vol_userassist uses). The pure parser filters cross-hive key matches, so no
    hive-offset resolution is needed. Strict read-only; bounded by a timeout; any
    failure degrades to ([], [error]) -- never raises into the runner.

    This is the memory half of the USB story: on a memory image (or a memory-mostly
    run with no usable disk mount), the SYSTEM/NTUSER hives live in RAM, not as
    files -- so the disk extractor sees nothing while the device identity is right
    there in memory. Universal: keys on the registry structure, no case data.
    """
    try:
        from sift_sentinel.tools.common import VOL_CMD as _VOL_CMD
        vol_cmd = list(_VOL_CMD)
    except Exception:  # noqa: BLE001
        vol_cmd = ["vol"]
    try:
        timeout_s = int(os.environ.get("SIFT_USB_MEMORY_TIMEOUT", "240") or "240")
    except ValueError:
        timeout_s = 240
    cmd = [*vol_cmd, "-f", image_path, "-r", "json",
           "windows.registry.printkey", "--key",
           "ControlSet001\\Enum\\USBSTOR", "--recurse"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except Exception as exc:  # noqa: BLE001 - timeout / OSError
        return [], [{"path": "memory:printkey", "error": f"{type(exc).__name__}: {exc}"}]
    if proc.returncode != 0:
        return [], [{"path": "memory:printkey",
                     "error": f"vol printkey rc={proc.returncode}"}]
    try:
        rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        return [], [{"path": "memory:printkey", "error": f"json: {exc}"}]
    return extract_usbstor_from_printkey(rows), []


def parse_usb_devices(mount_path: str | None = None,
                      hive_paths: list | None = None,
                      max_hives: int = 50,
                      control_set: str = "ControlSet001",
                      image_path: str | None = None) -> dict:
    """Extract USB / removable-media device history from mounted registry hives.

    Reads mounted hive files only (strict read-only): the SYSTEM hive yields
    USBSTOR device identity + MountedDevices drive letters; each user's NTUSER
    hive yields MountPoints2 volume->USER attribution. ``hive_paths`` overrides
    discovery -- the drop-in point for a future memory-carve increment. Does not
    access a live registry, run commands, classify maliciousness, or write to
    the mount. Universal: keyed on the registry structure, no case data.
    """
    # Resolve the ACTIVE disk mount the same way the other standalone disk tools do
    # (parse_wmi_subscription / parse_powershell_transcripts): the pipeline exports
    # the real onboard mount as SIFT_ACTIVE_DISK_MOUNT, while the config default
    # (/mnt/windows_mount) is usually empty. Without this, USB read the empty default,
    # found no disk hives, and fell back to the memory carve -- returning only what is
    # loaded in RAM instead of the full on-disk USBSTOR history. Disk is preferred;
    # memory remains the fallback when there is genuinely no disk mount.
    if mount_path is None and hive_paths is None:
        mount_path = os.environ.get("SIFT_ACTIVE_DISK_MOUNT") or None

    records: list = []
    errors: list = []
    candidates = _reg_hive_candidates(mount_path, hive_paths)
    existing = [p for p in candidates if p.is_file()]
    if not existing:
        # Disk hives absent -> try the MEMORY carve: on a memory image the SYSTEM
        # hive (USBSTOR) lives in RAM, not as a file, so the device identity is
        # recoverable via Vol3 printkey even when the disk extractor sees nothing.
        img = image_path or os.environ.get("SIFT_MEMORY_IMAGE") or ""
        if img and os.path.isfile(img):
            mem_records, mem_errors = _usb_from_memory(img)
            errors.extend(mem_errors)
            if mem_records:
                return {
                    "tool": "parse_usb_devices",
                    "tool_name": "parse_usb_devices",
                    "status": "ok",
                    "record_count": len(mem_records),
                    "records": mem_records,
                    "searched_hives": ["memory:SYSTEM\\ControlSet001\\Enum\\USBSTOR"],
                    "source": "memory",
                    "errors": errors,
                }
        # No disk hives AND no USB recoverable from memory -> NOT_APPLICABLE
        # (mirrors parse_registry_persistence's clean no-evidence shape). Emit hive
        # BASENAMES only, never absolute mount paths, so a run with NO usable disk
        # mount cannot leave un-repairable legacy-mount references for
        # PATH_FIDELITY_GATE (on a real paired run the active mount IS resolvable,
        # so full paths would be fine; the basename form is gate-safe in every case).
        return {
            "tool": "parse_usb_devices",
            "tool_name": "parse_usb_devices",
            "status": "not_applicable",
            "kind": "not_applicable",
            "reason": "no registry hives on mount and no USB devices recoverable from memory",
            "record_count": 0,
            "records": [],
            "searched_hives": sorted({p.name for p in candidates}),
            "errors": errors,
        }
    searched = [str(p) for p in candidates]

    system_hives: list = []
    ntuser_hives: dict = {}
    for path in existing[:max(0, int(max_hives))]:
        pname = path.name.upper()
        try:
            hive = _as_extractor_hive(_reg_open_hive(path))
        except Exception as exc:  # noqa: BLE001 - keep going on a bad hive
            errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            continue
        if pname == "SYSTEM":
            system_hives.append((path, hive))
        elif pname.startswith("NTUSER"):
            ntuser_hives[path.parent.name] = hive

    usbstor_parse_failed = False
    for sys_path, sysh in system_hives:
        try:
            usb_recs = extract_usbstor(sysh, control_set)
            records += usb_recs
            records += extract_mounted_devices(sysh)
        except Exception as exc:  # noqa: BLE001
            usb_recs = []
            errors.append({"path": "SYSTEM", "error": f"{type(exc).__name__}: {exc}"})
        # Dirty-hive false-negative guard: a parse failure on the USBSTOR key
        # (cells pending in unreplayed SYSTEM.LOG1/LOG2) must not read as "no
        # USB devices". Recover via RECmd transaction-log replay; if recovery
        # is impossible the envelope degrades to an explicit error instead of
        # a fake-clean zero. SIFT_USB_RECMD_FALLBACK=0 disables the replay
        # (the degraded status stays -- honesty is not switchable).
        hive_parse_errors = [e for e in getattr(sysh, "parse_errors", [])
                             if "usbstor" in str(e.get("path", "")).lower()]
        if not usb_recs and hive_parse_errors:
            usbstor_parse_failed = True
            errors.extend(hive_parse_errors)
            if os.environ.get("SIFT_USB_RECMD_FALLBACK", "1") != "0":
                recovered = _usbstor_via_recmd(sys_path, control_set)
                if recovered:
                    records += recovered
                    usbstor_parse_failed = False
                    errors.append({
                        "path": str(sys_path),
                        "note": "USBSTOR recovered via RECmd "
                                "transaction-log replay (dirty hive)",
                    })
    for user, hive in ntuser_hives.items():
        try:
            records += extract_mount_points(hive, user)
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": f"NTUSER:{user}", "error": f"{type(exc).__name__}: {exc}"})

    if usbstor_parse_failed and not records:
        return _usb_envelope(
            "error", records, searched, errors,
            reason="USBSTOR key present but unparseable (dirty hive; "
                   "transaction logs unreplayed) and replay recovery "
                   "unavailable -- device history NOT verified absent")
    return _usb_envelope("ok" if records else "empty", records, searched, errors)


__all__ = ["parse_usb_devices", "extract_usb_devices", "extract_usbstor",
           "extract_mounted_devices", "extract_mount_points"]
