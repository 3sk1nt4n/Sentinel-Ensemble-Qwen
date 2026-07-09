from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# SIFT_REACT_OS_COMPAT_TOOL_SURFACE_V1
#
# Universal policy:
# - ReAct must not run a plugin for the wrong operating system.
# - Tool selection and runtime execution must be evidence-OS aware.
# - If a safe same-OS replacement is known, rewrite.
# - If no safe replacement is known, block the tool as unavailable for this evidence.
# - This module uses current evidence/mount/tool metadata only. No case-specific values.

WINDOWS_PREFIXES = ("windows.",)
LINUX_PREFIXES = ("linux.",)
MAC_PREFIXES = ("mac.", "darwin.")

WINDOWS_TOOL_PLUGINS: dict[str, str] = {
    "vol_pslist": "windows.pslist.PsList",
    "vol_pstree": "windows.pstree.PsTree",
    "vol_psscan": "windows.psscan.PsScan",
    "vol_cmdline": "windows.cmdline.CmdLine",
    "vol_netscan": "windows.netscan.NetScan",
    "vol_malfind": "windows.malfind.Malfind",
    "vol_dlllist": "windows.dlllist.DllList",
    "vol_handles": "windows.handles.Handles",
    "vol_svcscan": "windows.svcscan.SvcScan",
    "vol_svclist": "windows.svclist.SvcList",
    "vol_filescan": "windows.filescan.FileScan",
    "vol_reg_hivelist": "windows.registry.hivelist.HiveList",
    "vol_hivelist": "windows.registry.hivelist.HiveList",
    "vol_privileges": "windows.privileges.Privs",
    "vol_getsids": "windows.getsids.GetSIDs",
    "vol_ssdt": "windows.ssdt.SSDT",
    "vol_sessions": "windows.sessions.Sessions",
    "vol_ldrmodules": "windows.malware.ldrmodules.LdrModules",
    "vol_modscan": "windows.modscan.ModScan",
    "vol_modules": "windows.modules.Modules",
    "vol_skeleton_key_check": "windows.skeleton_key_check.Skeleton_Key_Check",
    "vol_hashdump": "windows.hashdump.Hashdump",
    "vol_cmdscan": "windows.cmdscan.CmdScan",
    "vol_consoles": "windows.consoles.Consoles",
}

LINUX_TOOL_PLUGINS: dict[str, str] = {
    "vol_pslist": "linux.pslist.PsList",
    "vol_pstree": "linux.pstree.PsTree",
    "vol_psscan": "linux.psscan.PsScan",
    "vol_bash": "linux.bash.Bash",
    "vol_lsof": "linux.lsof.Lsof",
    "vol_netstat": "linux.netstat.NetStat",
}

def _as_path(value: Any) -> Path | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in {"none", "null", "unknown", "-", "n/a"}:
        return None
    try:
        return Path(s)
    except Exception:
        return None

def _looks_windows_mount(p: Path | None) -> bool:
    if not p:
        return False
    try:
        return (p / "Windows").is_dir() or (p / "windows").is_dir() or (p / "WINDOWS").is_dir()
    except Exception:
        return False

def _looks_linux_mount(p: Path | None) -> bool:
    if not p:
        return False
    try:
        return (p / "etc").is_dir() and ((p / "bin").exists() or (p / "usr").is_dir())
    except Exception:
        return False

def _normalize_os(value: Any) -> str:
    s = str(value or "").strip().lower()
    if not s:
        return "unknown"
    if s.startswith("win") or "windows" in s or "ntoskrnl" in s or "ntsystemroot" in s:
        return "windows"
    if s.startswith("lin") or "linux" in s:
        return "linux"
    if s in {"mac", "macos", "darwin", "osx"} or "darwin" in s:
        return "macos"
    return "unknown"

def infer_evidence_os(
    *,
    disk_mount: Any = None,
    state_dir: Any = None,
    plugin_name: Any = None,
    raw_text: str | None = None,
) -> str:
    """Infer current evidence OS from explicit env, active mount, state, or observed text."""
    for k in (
        "SIFT_ACTIVE_EVIDENCE_OS",
        "SIFT_EVIDENCE_OS",
        "SIFT_MEMORY_OS",
        "SIFT_TARGET_OS",
        "SIFT_OS",
    ):
        v = _normalize_os(os.environ.get(k))
        if v != "unknown":
            return v

    for k in (
        "SIFT_ACTIVE_DISK_MOUNT",
        "SIFT_DISK_MOUNT",
        "SIFT_DISK_MOUNT_PATH",
        "SIFT_MOUNT_ROOT",
    ):
        p = _as_path(os.environ.get(k))
        if _looks_windows_mount(p):
            return "windows"
        if _looks_linux_mount(p):
            return "linux"

    p = _as_path(disk_mount)
    if _looks_windows_mount(p):
        return "windows"
    if _looks_linux_mount(p):
        return "linux"

    sp = _as_path(state_dir)
    if sp and sp.is_dir():
        for name in ("profile_health.json", "all_outputs.json", "tool_outputs/vol_info.json"):
            fp = sp / name
            if not fp.exists():
                continue
            try:
                txt = fp.read_text(errors="replace")[:250000]
            except Exception:
                continue
            v = _normalize_os(txt)
            if v != "unknown":
                return v

    if raw_text:
        v = _normalize_os(raw_text)
        if v != "unknown":
            return v

    pn = str(plugin_name or "")
    if pn.startswith(WINDOWS_PREFIXES):
        return "windows"
    if pn.startswith(LINUX_PREFIXES):
        return "linux"
    if pn.startswith(MAC_PREFIXES):
        return "macos"
    return "unknown"

def plugin_family(plugin_name: Any) -> str:
    p = str(plugin_name or "").strip()
    if p.startswith(WINDOWS_PREFIXES):
        return "windows"
    if p.startswith(LINUX_PREFIXES):
        return "linux"
    if p.startswith(MAC_PREFIXES):
        return "macos"
    return "unknown"

def resolve_vol_plugin(
    *,
    tool_name: Any,
    plugin_name: Any,
    evidence_os: Any = None,
    disk_mount: Any = None,
    state_dir: Any = None,
) -> dict[str, Any]:
    tool = str(tool_name or "").replace("tool_", "").strip()
    plugin = str(plugin_name or "").strip()
    ev_os = _normalize_os(evidence_os)
    if ev_os == "unknown":
        ev_os = infer_evidence_os(disk_mount=disk_mount, state_dir=state_dir, plugin_name=None)

    fam = plugin_family(plugin)
    if not plugin:
        return {
            "action": "allow",
            "tool": tool,
            "plugin": plugin,
            "evidence_os": ev_os,
            "reason": "no_plugin_name_available",
        }

    if ev_os == "unknown" or fam == "unknown" or fam == ev_os:
        return {
            "action": "allow",
            "tool": tool,
            "plugin": plugin,
            "evidence_os": ev_os,
            "plugin_family": fam,
            "reason": "compatible_or_unknown",
        }

    replacement = None
    if ev_os == "windows":
        replacement = WINDOWS_TOOL_PLUGINS.get(tool)
    elif ev_os == "linux":
        replacement = LINUX_TOOL_PLUGINS.get(tool)

    if replacement:
        return {
            "action": "replace",
            "tool": tool,
            "old_plugin": plugin,
            "plugin": replacement,
            "evidence_os": ev_os,
            "plugin_family": fam,
            "reason": "wrong_os_plugin_rewritten",
        }

    return {
        "action": "block",
        "tool": tool,
        "old_plugin": plugin,
        "plugin": plugin,
        "evidence_os": ev_os,
        "plugin_family": fam,
        "reason": "wrong_os_plugin_no_safe_replacement",
    }

def set_active_evidence_os_from_mount(disk_mount: Any) -> str:
    os_name = infer_evidence_os(disk_mount=disk_mount)
    if os_name != "unknown":
        os.environ["SIFT_ACTIVE_EVIDENCE_OS"] = os_name
    p = _as_path(disk_mount)
    if p:
        os.environ["SIFT_ACTIVE_DISK_MOUNT"] = str(p)
    return os_name

def validate_log_text(text: str) -> dict[str, Any]:
    """Read-only proof: detect wrong-OS plugin execution in run logs."""
    evidence_os = "unknown"

    # Prefer explicit disk_mount evidence if present in the log.
    m = re.search(r"disk_mount=([^,\s]+)", text)
    if m:
        p = _as_path(m.group(1))
        if _looks_windows_mount(p):
            evidence_os = "windows"
        elif _looks_linux_mount(p):
            evidence_os = "linux"

    if evidence_os == "unknown":
        evidence_os = infer_evidence_os(raw_text=text)

    mismatches: list[dict[str, Any]] = []
    rewrites: list[dict[str, Any]] = []
    for m in re.finditer(r"LIVE VOL:\s+Running\s+([A-Za-z0-9_./-]+)\s+\(([^)]+)\)", text):
        tool = m.group(1)
        plugin = m.group(2)
        decision = resolve_vol_plugin(tool_name=tool, plugin_name=plugin, evidence_os=evidence_os)
        if decision["action"] == "block":
            mismatches.append(decision)
        elif decision["action"] == "replace":
            # A log from before the fix is a mismatch; a new log should show rewrite before run.
            mismatches.append(decision)

    return {
        "status": "pass" if not mismatches else "fail",
        "evidence_os": evidence_os,
        "wrong_os_hits": len(mismatches),
        "mismatches": mismatches,
        "rewrites": rewrites,
    }

def _selftest() -> None:
    assert resolve_vol_plugin(
        tool_name="vol_pslist",
        plugin_name="linux.pslist.PsList",
        evidence_os="windows",
    )["plugin"] == "windows.pslist.PsList"

    assert resolve_vol_plugin(
        tool_name="vol_pstree",
        plugin_name="windows.pstree.PsTree",
        evidence_os="windows",
    )["action"] == "allow"

    assert validate_log_text(
        "Evidence: memory=x, disk=y, disk_mount=/not/mounted\n"
        "LIVE VOL: Running vol_pslist (linux.pslist.PsList) on mem.img\n"
        "NtSystemRoot C:\\Windows\n"
    )["status"] == "fail"

if __name__ == "__main__":
    _selftest()
    print("REACT_OS_COMPAT_MODULE_SELFTEST=PASS")
