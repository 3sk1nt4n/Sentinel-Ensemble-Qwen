"""Tool capability declarations (typed-tool integration contract; see ARCHITECTURE.md).

Every tool registered in coordinator._TOOL_REGISTRY MUST have a matching
capability here. get_capability(tool_name) returns the capability dict;
register_capability(tool_name, cap) adds one at runtime (used by dynamic
Vol3 plugin discovery in tools/common.py).

Schema (all five fields required):
  produces:            list[str]  -- evidence types yielded
  applicable_when:     list[str]  -- preconditions
  not_applicable_when: list[str]  -- exclusions (e.g. "linux_evidence")
  failure_modes:       list[str]  -- known failure classes
  runtime_class:       "fast" | "medium" | "slow" | "background"

Rule 6: no dataset observations. Do not reference specific cases,
evidence files, observed counts, or case-specific artifacts here.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

VALID_RUNTIME_CLASSES = frozenset({"fast", "medium", "slow", "background"})
REQUIRED_FIELDS = frozenset({
    "produces", "applicable_when", "not_applicable_when",
    "failure_modes", "runtime_class",
})


def _cap(
    *,
    produces: List[str],
    applicable_when: List[str],
    not_applicable_when: List[str],
    failure_modes: List[str],
    runtime_class: str,
    required_args: tuple = (),
    mitre_techniques: tuple = (),
    kill_chain_phases: tuple = (),
    behavioral_signals: tuple = (),
) -> Dict[str, Any]:
    """Build a capability dict, validating the five required fields."""
    if runtime_class not in VALID_RUNTIME_CLASSES:
        raise ValueError(
            f"runtime_class must be one of {sorted(VALID_RUNTIME_CLASSES)}, "
            f"got {runtime_class!r}"
        )
    for name, value in (
        ("produces", produces),
        ("applicable_when", applicable_when),
        ("not_applicable_when", not_applicable_when),
        ("failure_modes", failure_modes),
    ):
        if not isinstance(value, list):
            raise TypeError(f"{name} must be a list")
    return {
        "produces": list(produces),
        "applicable_when": list(applicable_when),
        "not_applicable_when": list(not_applicable_when),
        "failure_modes": list(failure_modes),
        "runtime_class": runtime_class,
        "required_args": tuple(required_args),
        "mitre_techniques": tuple(mitre_techniques),
        "kill_chain_phases": tuple(kill_chain_phases),
        "behavioral_signals": tuple(behavioral_signals),
    }


def auto_capability(
    tool_name: str,
    os_family: str = "windows",
    runtime_class: str = "medium",
) -> Dict[str, Any]:
    """Return a default capability for a dynamically-discovered plugin.

    Used by tools/common.py when adding Vol3 plugins without explicit
    capability entries. os_family sets applicability; runtime_class
    defaults to "medium" since the true cost is unknown until smoke-run.
    """
    # All dynamically-discovered plugins here are Volatility 3 -- they run on a
    # memory image by construction, so they are memory-required. This is what
    # lets a disk-only run omit them from Inv1/ReAct instead of dispatching
    # them on a None image (live-run lesson: 13 vol_* failures on disk-only).
    if os_family == "windows":
        applicable = ["windows_evidence", "memory_evidence"]
        not_applicable = ["linux_evidence", "mac_evidence"]
    elif os_family == "linux":
        applicable = ["linux_evidence", "memory_evidence"]
        not_applicable = ["windows_evidence", "mac_evidence"]
    elif os_family == "mac":
        applicable = ["mac_evidence", "memory_evidence"]
        not_applicable = ["windows_evidence", "linux_evidence"]
    elif os_family == "any":
        applicable = ["memory_evidence"]
        not_applicable = []
    else:
        raise ValueError(
            f"os_family must be 'windows'|'linux'|'mac'|'any', got {os_family!r}"
        )
    return _cap(
        produces=["records"],
        applicable_when=applicable,
        not_applicable_when=not_applicable,
        failure_modes=["plugin_may_be_unavailable_on_this_profile"],
        runtime_class=runtime_class,
    )


_WIN_MEMORY_EXCLUSIONS = ["linux_evidence"]
_WIN_DISK_EXCLUSIONS = ["linux_evidence"]


def _win_mem_cap(
    produces: List[str],
    runtime_class: str,
    failure_modes: List[str] | None = None,
) -> Dict[str, Any]:
    """Shortcut for a typical Windows memory-plugin capability."""
    return _cap(
        produces=produces,
        # memory_evidence: Vol3 wrappers run on a memory image by construction,
        # so disk-only runs can structurally omit them (source prefilter).
        applicable_when=["windows_evidence", "memory_evidence"],
        not_applicable_when=_WIN_MEMORY_EXCLUSIONS,
        failure_modes=failure_modes or [
            "plugin_may_be_unavailable_on_this_profile",
        ],
        runtime_class=runtime_class,
    )


_TOOL_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    # ── Memory: Vol3 wrappers (arg_type="memory") ──
    "vol_pstree":       _win_mem_cap(["process_tree"],          "fast"),
    "vol_psscan":       _win_mem_cap(["process_scan"],          "fast"),
    "vol_netscan":      _win_mem_cap(["network_connections"],   "fast"),
    "vol_malfind":      _win_mem_cap(["injected_memory_regions"], "medium"),
    "vol_psxview":      _win_mem_cap(["process_cross_view"], "fast"),
    "vol_cmdline":      _win_mem_cap(["command_lines"],         "fast"),
    "vol_dlllist":      _win_mem_cap(["loaded_dlls"],           "slow"),
    "vol_handles":      _win_mem_cap(["process_handles"],       "slow"),
    "vol_envars":       _win_mem_cap(["environment_variables"], "medium"),
    "vol_getsids":      _win_mem_cap(["process_sids"],          "fast"),
    "vol_privileges":   _win_mem_cap(["process_privileges"],    "medium"),
    "vol_svcscan":      _win_mem_cap(["services"],              "medium"),
    "vol_filescan":     _win_mem_cap(["file_objects"],          "slow"),
    "vol_mftscan":      _win_mem_cap(["mft_entries"],           "slow"),
    "vol_reg_hivelist": _win_mem_cap(["registry_hives"],        "fast"),
    # ── Memory: Vol3 plugins routed via vol_generic ──
    "vol_ldrmodules":      _win_mem_cap(["loaded_modules"],          "medium"),
    "vol_hollowprocesses": _win_mem_cap(
        ["hollow_process_candidates"], "medium",
        failure_modes=["plugin_may_yield_zero_on_clean_evidence"],
    ),
    "vol_vadinfo":     _win_mem_cap(["vad_regions"],      "slow"),
    "vol_callbacks":   _win_mem_cap(["kernel_callbacks"], "fast"),
    "vol_modscan":     _win_mem_cap(["kernel_modules"],   "fast"),
    # ── Disk / standalone ──
    "get_amcache": _cap(
        produces=["execution_history_amcache"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=["hive_missing", "hive_unreadable"],
        runtime_class="fast",
    ),
    "extract_mft_timeline": _cap(
        produces=["mft_timeline"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=["mft_unreadable", "timeline_window_too_narrow"],
        runtime_class="medium",
    ),
    "parse_event_logs": _cap(
        produces=["event_log_entries"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=["evtx_corrupt", "no_logs_present"],
        runtime_class="medium",
    ),
    "parse_prefetch": _cap(
        produces=["prefetch_entries"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=["prefetch_disabled", "no_prefetch_files"],
        runtime_class="fast",
    ),
    "parse_powershell_transcripts": _cap(
        produces=["powershell_transcript_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "no_transcripts_found",
            "transcript_unreadable",
            "decode_failed",
        ],
        runtime_class="medium",
    ),
    "parse_rdp_artifacts": _cap(
        produces=["rdp_artifact_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "no_rdp_artifacts_found",
            "evtx_unreadable",
            "registry_hive_unreadable",
            "rdp_file_unreadable",
        ],
        runtime_class="slow",
    ),
    "parse_registry_persistence": _cap(
        produces=["registry_persistence_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "registry_hive_missing",
            "registry_hive_unreadable",
            "registry_parser_unavailable",
            "registry_key_parse_error",
        ],
        runtime_class="medium",
    ),
    "parse_usb_devices": _cap(
        produces=["usb_device_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "registry_hive_missing",
            "registry_hive_unreadable",
            "registry_parser_unavailable",
            "registry_key_parse_error",
        ],
        runtime_class="medium",
    ),
    "parse_userassist": _cap(
        produces=["userassist_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "registry_hive_missing",
            "registry_hive_unreadable",
            "registry_parser_unavailable",
            "registry_key_parse_error",
        ],
        runtime_class="medium",
    ),
    "parse_scheduled_tasks_disk": _cap(
        produces=["scheduled_task_xml_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "tasks_directory_missing",
            "task_xml_unreadable",
            "task_xml_parse_error",
        ],
        runtime_class="medium",
    ),
    "extract_network_iocs": _cap(
        produces=["network_ioc_candidates"],
        applicable_when=["windows_evidence"],
        not_applicable_when=_WIN_MEMORY_EXCLUSIONS,
        failure_modes=[
            "runtime_outputs_missing",
            "no_network_iocs_found",
            "runtime_output_parse_error",
        ],
        runtime_class="fast",
    ),
    "decode_base64_strings": _cap(
        produces=["decoded_encoded_string"],
        applicable_when=["windows_evidence"],
        not_applicable_when=_WIN_MEMORY_EXCLUSIONS,
        failure_modes=[
            "runtime_outputs_missing",
            "no_base64_tokens_found",
            "decode_failed",
        ],
        runtime_class="fast",
    ),
    "parse_wmi_subscription": _cap(
        produces=["wmi_subscription_records"],
        applicable_when=["windows_evidence", "disk_evidence"],
        not_applicable_when=_WIN_DISK_EXCLUSIONS,
        failure_modes=[
            "no_wmi_artifacts_found",
            "objects_data_unreadable",
            "memory_image_unreadable",
        ],
        runtime_class="slow",
    ),
    # ── Sleuthkit (filesystem-level disk tools) ──
    "sleuthkit_fls": _cap(
        produces=["file_listing"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "unsupported_fs"],
        runtime_class="medium",
    ),
    "sleuthkit_mmls": _cap(
        produces=["partition_table"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "no_partition_table"],
        runtime_class="fast",
    ),
    "sleuthkit_icat": _cap(
        produces=["file_contents_by_inode"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "invalid_inode"],
        runtime_class="fast",
        required_args=("inode",),
    ),
    "sleuthkit_blkstat": _cap(
        produces=["block_allocation_status"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "invalid_block"],
        runtime_class="fast",
        required_args=("block_addr",),
    ),
    "sleuthkit_ifind": _cap(
        produces=["inode_for_filename"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "file_not_found"],
        runtime_class="fast",
        required_args=("block_or_name",),
    ),
    "sleuthkit_ffind": _cap(
        produces=["filename_for_inode"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "inode_not_found"],
        runtime_class="fast",
        required_args=("inode",),
    ),
    "sleuthkit_mactime": _cap(
        produces=["mac_timeline"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "empty_timeline"],
        runtime_class="medium",
        required_args=("body_file",),
    ),
    "sleuthkit_sorter": _cap(
        produces=["files_sorted_by_type"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="slow",
    ),
    "sleuthkit_sigfind": _cap(
        produces=["signature_matches"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="medium",
        required_args=("hex_sig",),
    ),
    "sleuthkit_img_stat": _cap(
        produces=["image_metadata"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "unsupported_format"],
        runtime_class="fast",
    ),
    "sleuthkit_img_cat": _cap(
        produces=["raw_image_bytes"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="medium",
    ),
    "sleuthkit_tsk_recover": _cap(
        produces=["recovered_deleted_files"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "no_deleted_files"],
        runtime_class="slow",
        required_args=("output_dir",),
    ),
    "sleuthkit_tsk_loaddb": _cap(
        produces=["sqlite_database_of_image"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "database_error"],
        runtime_class="slow",
    ),
    "run_yara": _cap(
        produces=["yara_matches"],
        applicable_when=["disk_evidence", "memory_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "rules_path_invalid", "no_rules_loaded", "no_matches"],
        runtime_class="medium",
    ),
    "run_bulk_extractor": _cap(
        produces=["extracted_artifacts_ips_emails_urls"],
        applicable_when=["disk_evidence", "memory_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "output_dir_not_writable"],
        runtime_class="slow",
    ),
    "run_exiftool": _cap(
        produces=["file_metadata"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "unsupported_file_type"],
        runtime_class="fast",
    ),
    "run_ssdeep": _cap(
        produces=["fuzzy_hashes"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="fast",
    ),
    "run_foremost": _cap(
        produces=["carved_files"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "output_dir_not_writable"],
        runtime_class="slow",
    ),
    "run_strings": _cap(
        produces=["printable_strings"],
        applicable_when=["disk_evidence", "memory_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="medium",
    ),
    "run_memprocfs": _cap(
        # A18-gamma: capability-attribute promotion. Declares forensic_collector
        # role + memory requirement so the Inv1 classifier promotes it without
        # name-equality special-casing. produces lists per-family A18 semantic
        # outputs (multi-root forensic CSV walk).
        produces=[
            "findevil_indicators",
            "memory_process_baseline",
            "memory_service_baseline",
            "memory_network_state",
            "memory_dns_resolution",
            "memory_persistence",
            "memory_execution_history",
            "memory_module_anomalies",
            "memory_timeline_process",
            "memory_timeline_task",
        ],
        applicable_when=["memory_evidence"],
        not_applicable_when=[],
        failure_modes=[
            "binary_missing",
            "install_dir_missing",
            "vmm_so_missing",
            "ldd_dependency_missing",
            "image_path_not_found",
            "process_died",
            "mount_timeout",
            "forensic_csv_timeout",
            "process_timeout",
        ],
        runtime_class="slow",
    ),
    "run_mftecmd": _cap(
        produces=["mft_timeline"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "invalid_mft"],
        runtime_class="slow",
    ),
    "run_recmd": _cap(
        produces=["registry_parsed_values"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "corrupt_hive"],
        runtime_class="medium",
    ),
    "run_evtxecmd": _cap(
        produces=["event_log_csv"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "corrupt_evtx"],
        runtime_class="slow",
    ),
    "run_amcacheparser": _cap(
        produces=["first_execution_evidence"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "invalid_amcache"],
        runtime_class="medium",
    ),
    "run_appcompatcacheparser": _cap(
        produces=["shimcache_entries"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "corrupt_hive"],
        runtime_class="fast",
    ),
    "run_srumecmd": _cap(
        # 31K-SRUM-SURFACE-RESOLVER: SRUM App Resource Usage / Network Usage.
        # Aggregate telemetry only; not exact process creation or peer-IP proof.
        produces=["srum_application_resource_usage", "srum_network_usage", "srum_user_resource_usage"],
        applicable_when=["disk_evidence"],
        not_applicable_when=["srudb_missing", "binary_missing"],
        failure_modes=["binary_missing", "srudb_missing", "unsupported_database", "output_dir_not_writable"],
        runtime_class="fast",
    ),
    "run_sbecmd": _cap(
        produces=["shellbag_entries"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="medium",
    ),
    "run_jlecmd": _cap(
        produces=["jumplist_entries"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="fast",
    ),
    "run_lecmd": _cap(
        produces=["lnk_file_entries"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="fast",
    ),
    "run_rbcmd": _cap(
        produces=["recycle_bin_entries"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="fast",
    ),
    "run_wxtcmd": _cap(
        produces=["windows_timeline_activity"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing"],
        runtime_class="fast",
    ),
    "run_evtx_dump": _cap(
        produces=["evtx_jsonl"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "corrupt_evtx"],
        runtime_class="medium",
    ),
    "run_vshadowmount": _cap(
        produces=["mounted_shadow_copies"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "requires_privileged_mount"],
        runtime_class="slow",
    ),
    "run_pffexport": _cap(
        produces=["pst_mailbox_contents"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "unsupported_pst_format"],
        runtime_class="slow",
    ),
    "sleuthkit_fsstat": _cap(
        produces=["filesystem_stats"],
        applicable_when=["disk_evidence"],
        not_applicable_when=[],
        failure_modes=["binary_missing", "unsupported_fs"],
        runtime_class="fast",
    ),
}


def get_capability(tool_name: str) -> Dict[str, Any] | None:
    """Return the capability dict for *tool_name*, or None if absent."""
    return _TOOL_CAPABILITIES.get(tool_name)


def register_capability(
    tool_name: str, capability: Dict[str, Any],
) -> None:
    """Register a capability at runtime. Validates all five fields.

    Used by tools/common.py after dynamic Vol3 plugin discovery so that
    newly-exposed plugins still satisfy Rule 2.
    """
    if not isinstance(capability, dict):
        raise TypeError(
            f"capability for {tool_name!r} must be a dict, "
            f"got {type(capability).__name__}"
        )
    missing = REQUIRED_FIELDS - set(capability.keys())
    if missing:
        raise ValueError(
            f"capability for {tool_name!r} missing fields: {sorted(missing)}"
        )
    if capability["runtime_class"] not in VALID_RUNTIME_CLASSES:
        raise ValueError(
            f"capability for {tool_name!r}: invalid runtime_class "
            f"{capability['runtime_class']!r}"
        )
    _TOOL_CAPABILITIES[tool_name] = capability


def all_registered() -> List[str]:
    """Return the list of tool names that have capabilities declared."""
    return sorted(_TOOL_CAPABILITIES.keys())

# 31K-SRUM-SURFACE-RESOLVER: SrumECmd capability registered.

# RUN17_VOL_SSDT_CAPABILITY_V1
#
# Dataset-agnostic Volatility SSDT capability declaration.
# This is a tool-surface declaration only. It does not classify maliciousness
# and does not contain case-specific module names, syscall IDs, PIDs, paths,
# hashes, IPs, users, or answer labels.
try:
    _TOOL_CAPABILITIES.setdefault(
        "vol_ssdt",
        _win_mem_cap(["kernel_ssdt", "ssdt_integrity"], "fast"),
    )
except Exception:
    # Import-time fail-closed: the normal capability map remains authoritative.
    pass

