"""Dataset-agnostic semantic tool-value selection.

Important principle:
- High-value is a stable forensic semantic category.
- Runtime applicability is artifact-dependent.
- A zero-record result on one dataset must never demote a tool globally.
- No answer keys, no case literals, no IOCs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Mapping


# Stable semantic high-value set. These are valuable because of what they prove,
# not because a previous dataset happened to contain their artifacts.
SEMANTIC_HIGH_VALUE_TOOLS = frozenset({
    # Memory/process baseline
    "vol_pstree",
    "vol_psscan",
    "vol_cmdline",
    "vol_netscan",
    "vol_malfind",
    "vol_dlllist",
    "vol_handles",
    "vol_svcscan",
    "vol_filescan",
    "vol_reg_hivelist",
    "vol_privileges",
    "vol_getsids",

    # Disk execution and filesystem history
    "get_amcache",
    "parse_prefetch",
    "extract_mft_timeline",
    "run_mftecmd",
    "sleuthkit_fls",
    "sleuthkit_mactime",
    "run_appcompatcacheparser",
    "run_lecmd",
    "run_jlecmd",

    # Logs, script activity, persistence, remote access
    "parse_event_logs",
    "parse_registry_persistence",
    "parse_scheduled_tasks_disk",
    "parse_powershell_transcripts",
    "parse_rdp_artifacts",
    "parse_wmi_subscription",

    # Resource usage / network / derived evidence
    "run_srumecmd",
    "extract_network_iocs",
    "decode_base64_strings",
})


SEMANTIC_BUCKETS = {
    "process_memory": {
        "vol_pstree", "vol_psscan", "vol_cmdline", "vol_getsids",
    },
    "memory_injection_context": {
        "vol_malfind", "vol_dlllist", "vol_handles", "vol_filescan",
        "vol_privileges",
    },
    "network": {
        "vol_netscan", "extract_network_iocs",
    },
    "disk_execution": {
        "get_amcache", "parse_prefetch", "extract_mft_timeline",
        "run_mftecmd", "run_appcompatcacheparser", "run_lecmd",
        "run_jlecmd", "sleuthkit_fls", "sleuthkit_mactime",
    },
    "logs_script_wmi": {
        "parse_event_logs", "parse_powershell_transcripts",
        "parse_wmi_subscription",
    },
    "persistence": {
        "parse_registry_persistence", "parse_scheduled_tasks_disk",
        "vol_svcscan",
    },
    "remote_access_user": {
        "parse_rdp_artifacts",
    },
    "resource_usage": {
        "run_srumecmd",
    },
    "derived": {
        "decode_base64_strings",
    },
}


_BODYFILE_ENV_KEYS = (
    "SIFT_SLEUTHKIT_BODYFILE",
    "SIFT_MACTIME_BODYFILE",
)


def semantic_bucket(tool_name: str) -> str:
    for bucket, tools in SEMANTIC_BUCKETS.items():
        if tool_name in tools:
            return bucket
    if tool_name.startswith("vol_"):
        return "memory_other"
    return "other"


def is_semantic_high_value(tool_name: str) -> bool:
    return tool_name in SEMANTIC_HIGH_VALUE_TOOLS


def _existing_bodyfile(env: Mapping[str, str] | None = None) -> str:
    env = env or {}
    for key in _BODYFILE_ENV_KEYS:
        raw = str(env.get(key) or "").strip()
        if raw and Path(raw).is_file():
            return raw
    return ""


def _artifact_status_for_tool(
    tool_name: str,
    *,
    disk_mount: str | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Return run-applicability status without changing semantic value."""
    env = env or {}
    root = Path(disk_mount) if disk_mount else None

    if tool_name == "sleuthkit_mactime":
        bodyfile = _existing_bodyfile(env)
        if bodyfile:
            return "applicable", f"bodyfile present: {bodyfile}"
        return (
            "defer_no_artifact",
            "bodyfile absent; generate or set SIFT_SLEUTHKIT_BODYFILE/SIFT_MACTIME_BODYFILE",
        )

    if tool_name == "parse_prefetch":
        if root and (root / "Windows" / "Prefetch").is_dir():
            return "applicable", "Windows/Prefetch present"
        return "not_applicable_this_run", "Windows/Prefetch absent"

    if tool_name == "run_srumecmd":
        candidates = []
        if root:
            candidates = [
                root / "Windows" / "System32" / "sru" / "SRUDB.dat",
                root / "Windows" / "System32" / "SRUDB.dat",
                root / "Windows" / "SRUDB.dat",
            ]
        if any(p.exists() for p in candidates):
            return "applicable", "SRUDB.dat present"
        return "not_applicable_this_run", "SRUDB.dat absent"

    return "applicable_or_tool_handles_na", "no prerequisite gate"


def tool_profile(
    tool_name: str,
    *,
    disk_mount: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, str | bool]:
    status, reason = _artifact_status_for_tool(
        tool_name,
        disk_mount=disk_mount,
        env=env,
    )
    return {
        "tool": tool_name,
        "semantic_high_value": is_semantic_high_value(tool_name),
        "semantic_bucket": semantic_bucket(tool_name),
        "artifact_status": status,
        "artifact_reason": reason,
    }


def rebalance_selected_tools(
    selected: Iterable[str],
    *,
    inv1_supported: Iterable[str] | None = None,
    disk_mount: str | None = None,
    max_selected: int = 30,
    env: Mapping[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Rebalance selected tools using semantic value + artifact availability.

    This does NOT downgrade high-value tools globally. It only defers tools whose
    required runtime artifact is absent. Currently:
    - `sleuthkit_mactime` is high-value, but requires a bodyfile.
    - If no bodyfile exists, defer it and use `run_mftecmd` when supported.
    - Later, once bodyfile generation is implemented, `sleuthkit_mactime` is
      automatically kept again.
    """
    out = list(selected or [])
    supported = set(inv1_supported or out)
    actions: list[str] = []

    if "sleuthkit_mactime" not in out:
        return out, actions

    status, reason = _artifact_status_for_tool(
        "sleuthkit_mactime",
        disk_mount=disk_mount,
        env=env,
    )

    if status == "applicable":
        actions.append(
            "kept sleuthkit_mactime: semantic_high_value=true; "
            f"artifact_status=applicable; reason={reason}"
        )
        return out, actions

    out = [tool for tool in out if tool != "sleuthkit_mactime"]
    actions.append(
        "deferred sleuthkit_mactime: semantic_high_value=true; "
        f"artifact_status={status}; reason={reason}"
    )

    mount_ok = bool(disk_mount and Path(str(disk_mount)).exists())
    can_add_mftecmd = (
        "run_mftecmd" in supported
        and "run_mftecmd" not in out
        and mount_ok
        and len(out) < int(max_selected or 30)
    )
    if can_add_mftecmd:
        out.append("run_mftecmd")
        actions.append(
            "injected run_mftecmd: semantic_high_value=true; "
            "MFT-backed replacement while mactime bodyfile is absent"
        )

    return out, actions
