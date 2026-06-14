"""Stable semantic API for the MCP / Inv1 tool catalog.

Slot 31I-alpha. This module classifies every *real registered* tool into
a locked semantic-bucket vocabulary so the Inv1 prompt can present the
catalog grouped by forensic family (memory/disk/network/registry/...),
and so Inv1 can select 20-30 relevant tools dynamically.

Design properties:
  - dataset-agnostic by construction: classification is derived only
    from the tool name, its registry arg_type, and its declared
    capability. There are no run-specific assumptions and no
    predetermined outputs baked in here.
  - no network / no evidence access. Pure functions over the registry.
  - never advertises a tool that is not in the registry passed in:
    renderers iterate the supplied registry only.

Public API (see ``__all__``):
  SEMANTIC_BUCKETS, DEFAULT_SEMANTIC_BUCKET, get_tool_semantics,
  iter_tool_semantics, normalize_semantic_buckets,
  format_grouped_inv1_tool_catalog, estimate_catalog_tokens
"""

from __future__ import annotations

import math
from typing import Any, Callable, Iterable

__all__ = [
    "SEMANTIC_BUCKETS",
    "DEFAULT_SEMANTIC_BUCKET",
    "get_tool_semantics",
    "iter_tool_semantics",
    "normalize_semantic_buckets",
    "format_grouped_inv1_tool_catalog",
    "estimate_catalog_tokens",
    "EVENT_CODE_FAMILIES",
    "event_code_semantics",
]


# ── Locked semantic bucket vocabulary (Slot 31I TASK 3) ────────────────
# Do not expand this vocabulary in this slot.
SEMANTIC_BUCKETS: frozenset[str] = frozenset({
    "memory_process",
    "memory_process_listing",
    "memory_process_arguments",
    "memory_process_identity",
    "memory_process_resources",
    "memory_process_threads",
    "memory_process_ui",
    "memory_network",
    "memory_injection",
    "memory_modules",
    "memory_handles",
    "memory_services",
    "memory_registry",
    "memory_kernel",
    "disk_filesystem",
    "disk_timeline",
    "disk_artifact",
    "event_logs",
    "evtx",
    "registry",
    "execution_artifacts",
    "persistence",
    "network_ioc",
    "string_analysis",
    "string_decode",
    "base64_decode",
    "powershell_decode",
    "malware_triage",
    "linux_process",
    "linux_auth",
    "linux_persistence",
    "ios_artifacts",
    "memprocfs",
    "sleuthkit",
    "file_carving",
    "hash_artifact",
    "credential_artifact",
    "uncategorized",
})

DEFAULT_SEMANTIC_BUCKET = "uncategorized"


# ── Bucket resolution rules ────────────────────────────────────────────
#
# Ordered (substring-tuple -> bucket) rules. A tool's lowercased name is
# scanned against every rule; all matches are collected in this fixed
# order then de-duplicated, so classification is deterministic and
# render order is stable. Unknown tools fall back to the default bucket.
#
# Order also encodes priority for deterministic truncation consumers:
# memory process/network/injection/kernel rank ahead of disk artifacts,
# which rank ahead of string/IOC/decode buckets.
_BUCKET_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("ssdt", "callback", "checkidt", "_idt", "syscall", "driverirp",
      "etwpatch", "skeletonkey", "keyboardnotifier", "timers", "kpcr",
      "debugregister", "unhooked", "directsystem", "indirectsystem",
      "checkmodules", "checkafinfo", "ftrace", "tracepoint",
      "perfevents", "checktraptable", "checksysctl"), "memory_kernel"),
    (("malfind", "hollow", "ghost", "vadregex", "vadyara", "vadinfo",
      "pebmasquerade", "suspendedthread", "suspiciousthread", "_iat",
      "injection"), "memory_injection"),
    (("modscan", "modules", "moduleextract", "unloadedmodules",
      "hiddenmodules", "drivermodule", "driverscan", "ldrmodules",
      "dlllist", "librarylist", "lsmod", "modxview"), "memory_modules"),
    (("handles", "mutantscan", "mutant"), "memory_handles"),
    (("svcscan", "svcdiff", "svclist", "_service"), "memory_services"),
    (("hashdump", "cachedump", "lsadump", "getservicesids",
      "skeletonkey"), "credential_artifact"),
    (("hivelist", "hivescan", "printkey", "cellroutine",
      "reg_hive"), "memory_registry"),
    (("netscan", "netstat", "sockstat", "socketfilter", "sockets",
      "ifconfig", "netfilter"), "memory_network"),
    # 31AO Turn 1: sub-buckets for memory_process (specific rules first)
    (("getsids", "privileges", "sessions", "envars"),
     "memory_process_identity"),
    (("cmdline", "cmdscan", "consoles"),
     "memory_process_arguments"),
    (("pstree", "psscan", "pslist", "psxview", "psaux", "pscallstack"),
     "memory_process_listing"),
    (("thrdscan", "threads"),
     "memory_process_threads"),
    (("memmap", "joblinks"),
     "memory_process_resources"),
    (("windowstation", "desktops", "deskscan", "pidhashtable",
      "kthreads"), "memory_process_ui"),
    (("pstree", "psscan", "pslist", "psxview", "psaux", "pscallstack",
      "cmdline", "cmdscan", "consoles", "envars", "getsids",
      "privileges", "sessions", "thrdscan", "threads", "memmap",
      "joblinks", "windowstation", "desktops", "deskscan",
      "pidhashtable", "kthreads"), "memory_process"),
    (("mft_timeline", "mftecmd", "mactime", "timeline"), "disk_timeline"),
    (("filescan", "mftscan", "listfiles", "dumpfiles", "fls", "fsstat",
      "mmls", "ifind", "ffind", "blkstat", "img_stat", "img_cat",
      "vshadowmount"), "disk_filesystem"),
    (("foremost", "tsk_recover", "sorter", "sigfind", "carve"),
     "file_carving"),
    (("amcache", "prefetch", "shimcache", "appcompat", "appcompatcache", "userassist", "lecmd", "jlecmd", "lnk", "jumplist", "shortcut",
      "jlecmd", "lecmd", "sbecmd", "rbcmd", "wxtcmd",
      "shellbag", "srum", "srumecmd", "srudb"), "execution_artifacts"),
    (("scheduledtask", "scheduled_tasks", "wmi_subscription",
      "registry_persistence", "autorun"), "persistence"),
    (("evtx", "event_logs", "eventlog"), "evtx"),
    # 31I-alpha-b64: real base64/encoded-string decoder family. Keyed on
    # decoder-specific tokens so plain string dumpers (run_strings) are
    # never mistagged as decoders.
    (("base64",), "base64_decode"),
    (("decode_base64", "encoded_strings", "decode_b64",
      "string_decode"), "string_decode"),
    (("powershell", "base64_strings", "encoded_strings",
      "decode_base64"), "powershell_decode"),
    (("network_ioc", "bulk_extractor", "rdp_artifact",
      "base64_strings", "decode_base64", "srum", "srumecmd", "srudb"), "network_ioc"),
    (("strings", "exiftool"), "string_analysis"),
    (("ssdeep",), "hash_artifact"),
    (("memprocfs",), "memory_process"),  # 31K-REWEIGHT: de-elevated to normal memory bucket (no orphan)
    (("yara", "truecrypt", "certificates", "base64_strings",
      "decode_base64"), "malware_triage"),
    (("recmd", "printkey", "reg_hivelist"), "registry"),
    (("sleuthkit",), "sleuthkit"),
    (("ios", "iphone", "ipad"), "ios_artifacts"),
)

_LINUX_NAME_HINTS: tuple[str, ...] = (
    "vol_bash", "vol_psaux", "vol_pslist", "vol_lsof", "vol_lsmod",
    "vol_ip", "vol_ifconfig", "vol_mount", "vol_proc", "vol_kthreads",
    "vol_pidhashtable", "vol_kallsyms", "vol_ebpf", "vol_netfilter",
    "vol_sockstat", "vol_capabilities", "vol_checkcreds", "vol_ptrace",
    "vol_checkmodules", "vol_checkafinfo", "vol_dmesg", "vol_kmsg",
    "vol_iomem", "vol_elfs", "vol_librarylist", "vol_pagecache",
    "vol_vfsevents", "vol_ttycheck", "vol_pscallstack", "vol_modxview",
)

_MAC_NAME_HINTS: tuple[str, ...] = (
    "vol_kevents", "vol_kauthlisteners", "vol_kauthscopes",
    "vol_trustedbsd", "vol_checksysctl", "vol_checktraptable",
    "vol_procmaps",
)


def normalize_semantic_buckets(value: Any) -> tuple[str, ...]:
    """Coerce *value* into a non-empty tuple of valid bucket names.

    Accepts an iterable of strings, a single string, or anything else.
    Unknown bucket names are dropped; a single string is treated as one
    element; dicts / None / unrecognised inputs collapse to the default.
    The result is always a non-empty tuple whose members all live in
    ``SEMANTIC_BUCKETS`` (never ``str`` or ``dict``).
    """
    if isinstance(value, str):
        candidates: Iterable[Any] = (value,)
    elif isinstance(value, dict) or value is None:
        candidates = ()
    elif isinstance(value, Iterable):
        candidates = value
    else:
        candidates = ()

    seen: list[str] = []
    for item in candidates:
        if not isinstance(item, str):
            continue
        name = item.strip()
        if name in SEMANTIC_BUCKETS and name not in seen:
            seen.append(name)
    if not seen:
        return (DEFAULT_SEMANTIC_BUCKET,)
    return tuple(seen)


def _resolve_buckets(name_l: str) -> tuple[str, ...]:
    """Apply the ordered keyword rules; default to uncategorized."""
    matched: list[str] = []
    for needles, bucket in _BUCKET_RULES:
        if bucket in matched:
            continue
        if any(n in name_l for n in needles):
            matched.append(bucket)
    return tuple(matched) if matched else (DEFAULT_SEMANTIC_BUCKET,)


def _cap_get(capability: Any, key: str) -> Any:
    if isinstance(capability, dict):
        return capability.get(key)
    return None


def _platforms(name: str, capability: Any) -> tuple[str, ...]:
    """Best-effort platform tags (windows/linux/ios/generic).

    Lays groundwork for a later Windows-react namespace gate.
    """
    if any(h in name for h in ("ios", "iphone", "ipad")):
        return ("ios",)
    if name in _LINUX_NAME_HINTS or name in _MAC_NAME_HINTS:
        return ("linux",)
    applicable = _cap_get(capability, "applicable_when") or []
    not_applicable = _cap_get(capability, "not_applicable_when") or []
    if isinstance(applicable, (list, tuple)):
        if "windows_evidence" in applicable:
            return ("windows",)
        if ("linux_evidence" in applicable
                or "mac_evidence" in applicable):
            return ("linux",)
    # Cross-evidence utilities (yara/strings/bulk/ssdeep) declare both
    # disk and memory and exclude no OS -> generic.
    if (isinstance(applicable, (list, tuple))
            and "disk_evidence" in applicable
            and not not_applicable):
        return ("generic",)
    if name.startswith("vol_"):
        return ("windows",)
    if name.startswith(("sleuthkit_", "run_", "parse_", "get_",
                         "extract_")):
        return ("generic",)
    return ("generic",)


def _evidence_domains(
    name: str, arg_type: str, buckets: tuple[str, ...],
) -> tuple[str, ...]:
    domains: list[str] = []
    if any(b.startswith("memory_") for b in buckets) or arg_type in (
        "memory", "vol_generic",
    ):
        domains.append("memory")
    if (any(b in buckets for b in (
        "disk_filesystem", "disk_timeline", "disk_artifact",
        "execution_artifacts", "sleuthkit", "file_carving",
        "registry", "evtx", "event_logs",
    )) or arg_type in (
        "disk", "disk_mft", "standalone", "ez_tools", "sleuthkit",
    )):
        domains.append("disk")
    if any(b in buckets for b in ("memory_network", "network_ioc")):
        domains.append("network")
    if not domains:
        domains.append("generic")
    # de-dupe preserving order
    out: list[str] = []
    for d in domains:
        if d not in out:
            out.append(d)
    return tuple(out)


_RUNTIME_COST = {
    "fast": "low",
    "medium": "medium",
    "slow": "high",
    "background": "high",
}


def _humanize(token: str) -> str:
    return token.replace("_", " ").strip()


def _purpose(name: str, arg_type: str, capability: Any) -> str:
    produces = _cap_get(capability, "produces")
    if isinstance(produces, (list, tuple)) and produces:
        first = str(produces[0])
        return f"yields {_humanize(first)}"
    if arg_type:
        return f"{_humanize(arg_type)} tool"
    return "forensic tool"


# ── Windows abuse event-code families (Slot 31I-beta) ──────────────────
#
# Generic DFIR event-code semantics (SANS Hunt Evil / Windows logging
# baseline), NOT evidence-specific findings. Each family lists the
# canonical channel and well-known Event IDs an analyst hunts for. No
# run-specific assumptions and no predetermined outputs.
EVENT_CODE_FAMILIES: dict[str, dict] = {
    "authentication": {
        "channel": "Security",
        "event_ids": (4624, 4625, 4634, 4647, 4648, 4672,
                      4768, 4769, 4776),
        "summary": "logon / logoff / explicit-credential / Kerberos",
    },
    "account_management": {
        "channel": "Security",
        "event_ids": (4720, 4722, 4724, 4726, 4728, 4732,
                      4738, 4756),
        "summary": "account create / enable / group membership change",
    },
    "process_execution": {
        "channel": "Security",
        "event_ids": (4688, 4689),
        "summary": "process creation / termination",
    },
    "powershell": {
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "event_ids": (4103, 4104, 4105, 4106),
        "summary": "module / script-block logging",
    },
    "service_install": {
        "channel": "System / Security",
        "event_ids": (7045, 7034, 7036, 4697),
        "summary": "new service install / service state change",
    },
    "scheduled_task": {
        "channel": "Security / Microsoft-Windows-TaskScheduler",
        "event_ids": (4698, 4699, 4700, 4702, 106, 140, 141,
                      200, 201),
        "summary": "scheduled task create / update / action run",
    },
    "log_clear": {
        "channel": "Security / System",
        "event_ids": (1102, 104),
        "summary": "audit log cleared (anti-forensics)",
    },
    "rdp_lateral": {
        "channel": "Security / Microsoft-Windows-TerminalServices",
        "event_ids": (4778, 4779, 21, 22, 25, 1149),
        "summary": "remote interactive / RDP session activity",
    },
    "wmi_activity": {
        "channel": "Microsoft-Windows-WMI-Activity/Operational",
        "event_ids": (5857, 5858, 5859, 5860, 5861),
        "summary": "WMI provider load / permanent subscription",
    },
    "defender_av": {
        "channel": "Microsoft-Windows-Windows Defender/Operational",
        "event_ids": (1116, 1117, 5001, 5007),
        "summary": "malware detected / protection state change",
    },
    "file_share_access": {
        "channel": "Security",
        "event_ids": (5140, 5145),
        "summary": "network share / detailed file share access",
    },
    "object_access": {
        "channel": "Security",
        "event_ids": (4656, 4663),
        "summary": "handle requested / object access attempt",
    },
}


def _is_evtx_capable(
    name_l: str, buckets: tuple[str, ...], produces: Any,
) -> bool:
    if "evtx" in buckets or "event_logs" in buckets:
        return True
    if any(tok in name_l for tok in ("evtx", "event_log", "eventlog")):
        return True
    if isinstance(produces, (list, tuple)):
        joined = " ".join(str(p).lower() for p in produces)
        if "evtx" in joined or "event_log" in joined:
            return True
    return False


def event_code_semantics(
    tool_name: str,
    capability: Any = None,
    registry_entry: Any = None,
) -> dict:
    """Return generic Windows event-code semantics for *tool_name*.

    Shape: ``{"event_code_capable": bool, "families": tuple[str,...],
    "event_ids": tuple[int,...]}``. EVTX-capable tools advertise the
    full generic family set; non-EVTX tools return an empty, inert
    descriptor. Dataset-agnostic: families are standard DFIR baselines.
    """
    name_l = str(tool_name).lower()
    produces = _cap_get(capability, "produces")
    # Cheap bucket probe without recursing through get_tool_semantics.
    buckets = normalize_semantic_buckets(_resolve_buckets(name_l))
    if not _is_evtx_capable(name_l, buckets, produces):
        return {
            "event_code_capable": False,
            "families": (),
            "event_ids": (),
        }
    families = tuple(EVENT_CODE_FAMILIES.keys())
    ids: list[int] = []
    for fam in families:
        for eid in EVENT_CODE_FAMILIES[fam]["event_ids"]:
            if eid not in ids:
                ids.append(eid)
    return {
        "event_code_capable": True,
        "families": families,
        "event_ids": tuple(ids),
    }


# Name-keyed detect enrichment (high-value Windows abuse coverage).
# These are detects-level tags only -- the locked SEMANTIC_BUCKETS
# vocabulary is unchanged.
_DETECT_ENRICHMENT: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("appcompatcache", "appcompat", "shimcache"),
     ("execution_artifacts", "appcompatcache")),
    (("wmi_subscription", "wmi_activity", "wmi"),
     ("persistence", "wmi_activity")),
    (("lecmd", "lecd", "lnk", "shortcut"),
     ("execution_artifacts", "shortcut_artifact")),
)


def _enrich_detects(
    name_l: str, base: tuple[str, ...], evtx_caps: dict,
) -> tuple[str, ...]:
    out: list[str] = list(base)

    def _add(tag: str) -> None:
        if tag not in out:
            out.append(tag)

    if evtx_caps.get("event_code_capable"):
        _add("evtx")
        _add("event_code_hunting")
        for fam in evtx_caps.get("families", ()):
            _add(f"event_family:{fam}")
    for needles, tags in _DETECT_ENRICHMENT:
        if any(n in name_l for n in needles):
            for t in tags:
                _add(t)
    return tuple(out)


def get_tool_semantics(
    tool_name: str,
    registry_entry: Any = None,
    capability: Any = None,
) -> dict:
    """Resolve one tool to its semantic descriptor.

    The descriptor schema (all keys always present):
      tool_name        str
      platforms        tuple[str, ...]
      evidence_domains tuple[str, ...]
      buckets          tuple[str, ...]   (non-empty, all in vocabulary)
      detects          tuple[str, ...]
      cost             "low" | "medium" | "high"
      notes            str

    ``registry_entry`` is the ``(callable, arg_type)`` tuple stored in
    the tool registry; ``capability`` is the optional capability dict.
    Both are inputs only -- this function never imports the coordinator,
    keeping it safe to call from the registry-building path.
    """
    name = str(tool_name)
    name_l = name.lower()

    arg_type = ""
    if isinstance(registry_entry, (tuple, list)) and len(registry_entry) >= 2:
        arg_type = str(registry_entry[1] or "")

    buckets = normalize_semantic_buckets(_resolve_buckets(name_l))
    platforms = _platforms(name, capability)
    if platforms == ("linux",):
        buckets = _linux_remap(name_l, buckets)
    evidence_domains = _evidence_domains(name, arg_type, buckets)

    produces = _cap_get(capability, "produces")
    if isinstance(produces, (list, tuple)) and produces:
        detects = tuple(str(p) for p in produces)
    else:
        detects = tuple(buckets)

    # Slot 31I-beta: fold Windows abuse event-code families + high-value
    # detect tags into ``detects`` (schema/key set unchanged).
    _evtx_caps = event_code_semantics(name, capability, registry_entry)
    detects = _enrich_detects(name_l, detects, _evtx_caps)

    runtime_class = _cap_get(capability, "runtime_class")
    cost = _RUNTIME_COST.get(str(runtime_class), "medium")

    notes = _purpose(name, arg_type, capability)

    return {
        "tool_name": name,
        "platforms": tuple(platforms),
        "evidence_domains": tuple(evidence_domains),
        "buckets": tuple(buckets),
        "detects": detects,
        "cost": cost,
        "notes": notes,
    }


_LINUX_AUTH_HINTS = ("capabilit", "checkcreds", "ptrace", "cred",
                     "kauth", "trustedbsd")
_LINUX_PERSIST_HINTS = ("lsmod", "kallsyms", "ebpf", "netfilter",
                        "ftrace", "checkmodules", "tracepoint",
                        "module", "boottime")


def _linux_remap(name_l: str, buckets: tuple[str, ...]) -> tuple[str, ...]:
    """Translate generic buckets to the linux_* family for *nix tools.

    Keeps the LINUX / UNIX catalog section populated instead of dumping
    every *nix plugin into uncategorized. Dataset-agnostic: pure
    name-keyword routing, no run-specific assumptions.
    """
    if any(h in name_l for h in _LINUX_AUTH_HINTS):
        return ("linux_auth",)
    if any(h in name_l for h in _LINUX_PERSIST_HINTS):
        return ("linux_persistence",)
    return ("linux_process",)


def _resolve_capability(capabilities: Any, tool_name: str) -> Any:
    if capabilities is None:
        return None
    if callable(capabilities):
        try:
            return capabilities(tool_name)
        except Exception:
            return None
    if isinstance(capabilities, dict):
        return capabilities.get(tool_name)
    return None


def iter_tool_semantics(
    registry: Any, capabilities: Any = None,
) -> dict:
    """Return ``{tool_name: semantics dict}`` for every registry entry.

    ``registry`` is a mapping of ``tool_name -> (callable, arg_type)``.
    ``capabilities`` may be ``None``, a ``dict``, or a callable
    ``get_capability(name) -> cap | None``.
    """
    result: dict[str, dict] = {}
    if not isinstance(registry, dict):
        return result
    for tool_name in registry:
        entry = registry.get(tool_name)
        cap = _resolve_capability(capabilities, tool_name)
        result[tool_name] = get_tool_semantics(tool_name, entry, cap)
    return result


# ── Grouped Inv1 catalog rendering (Slot 31I TASK 5) ───────────────────
#
# Section header -> ordered buckets that route into it. A tool is
# rendered exactly once, under the FIRST section whose bucket set
# intersects the tool's buckets. Stable and explicit: every section
# header is always emitted even when it has no tools this run.
_CATALOG_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # 31AO Turn 1: sub-sections (specific before catch-all)
    ("MEMORY / PROCESS IDENTITY", ("memory_process_identity",)),
    ("MEMORY / PROCESS LISTING", ("memory_process_listing",)),
    ("MEMORY / PROCESS ARGUMENTS", ("memory_process_arguments",)),
    ("MEMORY / PROCESS RESOURCES", ("memory_process_resources",)),
    ("MEMORY / PROCESS THREADS", ("memory_process_threads",)),
    ("MEMORY / PROCESS UI/KERNEL", ("memory_process_ui",)),
    ("MEMORY / PROCESS", ("memory_process",)),
    ("MEMORY / NETWORK", ("memory_network",)),
    ("MEMORY / INJECTION", ("memory_injection",)),
    ("MEMORY / MODULES", ("memory_modules",)),
    ("MEMORY / HANDLES", ("memory_handles",)),
    ("MEMORY / SERVICES", ("memory_services",)),
    ("MEMORY / KERNEL", ("memory_kernel",)),
    ("DISK / FILESYSTEM", ("disk_filesystem",)),
    ("DISK / TIMELINE", ("disk_timeline",)),
    ("DISK / ARTIFACTS", ("disk_artifact", "execution_artifacts",
                          "hash_artifact", "credential_artifact")),
    ("EVENT LOGS / EVTX", ("event_logs", "evtx")),
    ("REGISTRY / PERSISTENCE", ("registry", "memory_registry",
                                "persistence")),
    ("STRING / DECODE / IOC", ("string_analysis", "string_decode",
                               "base64_decode", "powershell_decode",
                               "network_ioc")),
    ("SLEUTHKIT / FILE RECOVERY", ("sleuthkit", "file_carving")),
    ("LINUX / UNIX", ("linux_process", "linux_auth",
                      "linux_persistence")),
    ("IOS / MOBILE", ("ios_artifacts",)),
    ("GENERIC / UNCATEGORIZED", ("malware_triage",
                                 "uncategorized")),
)


def estimate_catalog_tokens(text: str) -> int:
    """Rough token estimate: ceil(len(text) / 4)."""
    if not text:
        return 0
    return math.ceil(len(str(text)) / 4)


def _section_for(buckets: tuple[str, ...]) -> str:
    for header, sec_buckets in _CATALOG_SECTIONS:
        if any(b in buckets for b in sec_buckets):
            return header
    return "GENERIC / UNCATEGORIZED"


def format_grouped_inv1_tool_catalog(
    registry: Any, capabilities: Any = None,
) -> str:
    """Render the registry as a semantically grouped Inv1 catalog.

    Only tools present in *registry* are advertised -- no fake / future
    capability is injected into the selectable catalog. Each line lists
    name, one-line purpose, platform, evidence domain, buckets, and cost.
    Section headers are always emitted (stable and explicit) even when a
    section has no tools in this run.
    """
    semantics = iter_tool_semantics(registry, capabilities)

    by_section: dict[str, list[str]] = {
        header: [] for header, _ in _CATALOG_SECTIONS
    }
    for tool_name in sorted(semantics):
        sem = semantics[tool_name]
        header = _section_for(sem["buckets"])
        platform = ",".join(sem["platforms"])
        domain = ",".join(sem["evidence_domains"])
        buckets = ", ".join(sem["buckets"])
        # 31AO Turn 2: surface value_tier + when_to_use + rich descriptions
        try:
            from sift_sentinel.tools.tool_catalog import (
                value_tier as _pu_value_tier,
                when_to_use as _pu_when_to_use,
                description_for as _pu_description_for,
            )
            _tier = _pu_value_tier(tool_name)
            _hint = _pu_when_to_use(tool_name)
            _rich_desc = _pu_description_for(tool_name)
        except Exception:
            _tier, _hint, _rich_desc = "MED", "", ""
        _desc_text = _rich_desc if _rich_desc else sem["notes"]
        _tier_part = f" | value={_tier}" if _tier == "HIGH" else ""
        _hint_part = f" | use_when={_hint}" if _hint else ""
        line = (
            f"- {tool_name} — {_desc_text}{_tier_part} | platform={platform} "
            f"| domain={domain} | buckets={buckets} | cost={sem['cost']}{_hint_part}"
        )
        by_section[header].append(line)

    out: list[str] = []
    for header, _ in _CATALOG_SECTIONS:
        out.append(header)
        lines = by_section[header]
        if lines:
            out.extend(lines)
        else:
            out.append("  (no registered tools in this section "
                        "this run)")
        out.append("")
    return "\n".join(out).rstrip()

# --- Slot 31I-beta schema-preserving Windows event-code semantic enrichment v2 ---
# Windows event-code guidance is exposed through existing descriptor fields:
#   - detects: event_id:<id> and windows_event:<family>
#   - notes: concise human-readable guidance
#   - event_code_semantics(): structured helper API
# get_tool_semantics() descriptor keys remain unchanged.

WINDOWS_EVENT_CODE_FAMILIES: dict[str, tuple[int, ...]] = {
    "log_tampering": (1102,),
    "powershell_activity": (4103, 4104),
    "authentication": (4624, 4625, 4740),
    "credential_use": (4648, 4672, 4776),
    "process_execution": (4688,),
    "service_installation": (4697, 7045),
    "scheduled_task": (4698, 4702),
    "account_group_change": (4720, 4728, 4732),
    "share_access_lateral_movement": (5140, 5145),
    "wmi_activity": (5857, 5858, 5860, 5861),
}

WINDOWS_EVENT_IDS: tuple[int, ...] = tuple(
    sorted({
        event_id
        for event_ids in WINDOWS_EVENT_CODE_FAMILIES.values()
        for event_id in event_ids
    })
)

_SLOT31I_BETA_SCHEMA_BASE_GET_TOOL_SEMANTICS = get_tool_semantics

try:
    _SLOT31I_BETA_BASE_EVENT_CODE_SEMANTICS = event_code_semantics
except NameError:
    _SLOT31I_BETA_BASE_EVENT_CODE_SEMANTICS = None


def _slot31i_beta_is_evtx_semantic_tool(tool_name: str, buckets: set[str]) -> bool:
    name = str(tool_name or "").lower()
    return (
        name in {"parse_event_logs", "run_evtxecmd", "run_evtx_dump"}
        or "evtx" in name
        or ("event" in name and "log" in name)
        or "evtx" in buckets
        or "event_logs" in buckets
    )


def event_code_semantics(tool_name: str | None = None, *args, **kwargs) -> dict:
    """Return structured Windows event-code guidance for EVTX-style tooling."""
    base: dict = {}

    if callable(_SLOT31I_BETA_BASE_EVENT_CODE_SEMANTICS):
        try:
            candidate = _SLOT31I_BETA_BASE_EVENT_CODE_SEMANTICS(
                tool_name, *args, **kwargs
            )
        except TypeError:
            try:
                candidate = _SLOT31I_BETA_BASE_EVENT_CODE_SEMANTICS()
            except TypeError:
                candidate = {}

        if isinstance(candidate, dict):
            base.update(candidate)

    name = str(tool_name or "").lower()
    if (
        tool_name is None
        or name in {"parse_event_logs", "run_evtxecmd", "run_evtx_dump"}
        or "evtx" in name
        or ("event" in name and "log" in name)
    ):
        families = {
            family: tuple(event_ids)
            for family, event_ids in WINDOWS_EVENT_CODE_FAMILIES.items()
        }
        base["event_ids"] = WINDOWS_EVENT_IDS
        base["windows_event_ids"] = WINDOWS_EVENT_IDS
        base["event_code_families"] = families
        base["families"] = families

    return base


def get_tool_semantics(tool_name: str, registry_entry=None, capability=None) -> dict:
    """Resolve one tool to its semantic descriptor with descriptor schema unchanged."""
    data = dict(_SLOT31I_BETA_SCHEMA_BASE_GET_TOOL_SEMANTICS(
        tool_name, registry_entry, capability
    ))

    buckets = set(data.get("buckets") or ())
    if _slot31i_beta_is_evtx_semantic_tool(tool_name, buckets):
        buckets.add("evtx")

        detects = list(data.get("detects") or ())
        for family, event_ids in WINDOWS_EVENT_CODE_FAMILIES.items():
            family_tag = f"windows_event:{family}"
            if family_tag not in detects:
                detects.append(family_tag)

            for event_id in event_ids:
                event_tag = f"event_id:{int(event_id)}"
                if event_tag not in detects:
                    detects.append(event_tag)

        notes = str(data.get("notes") or "")
        hint = (
            "Windows event IDs include 4648 credential use, 5140/5145 share "
            "access, 7045 service install, 4103/4104 PowerShell, and 1102 "
            "log clearing."
        )
        if hint not in notes:
            notes = (notes + " " + hint).strip()

        data["buckets"] = tuple(sorted(buckets))
        data["detects"] = tuple(detects)
        data["notes"] = notes

    return data


_slot31i_beta_public_exports = (
    "WINDOWS_EVENT_CODE_FAMILIES",
    "WINDOWS_EVENT_IDS",
    "event_code_semantics",
)

try:
    _slot31i_beta_orig_all = __all__
    _slot31i_beta_merged_all = list(dict.fromkeys(
        list(_slot31i_beta_orig_all) + list(_slot31i_beta_public_exports)
    ))
    __all__ = type(_slot31i_beta_orig_all)(_slot31i_beta_merged_all)
except NameError:
    __all__ = list(_slot31i_beta_public_exports)

# Slot 31J-epsilon: elevate MemProcFS / FindEvil semantics for Inv1 posture.
_SLOT31J_EPSILON_MEMPROCFS_DETECTS = (
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
)

_SLOT31J_EPSILON_MEMPROCFS_PURPOSE = (
    "FindEvil memory triage; yields process baseline, service baseline, "
    "network state, DNS resolution, persistence, execution history, "
    "module anomalies, timeline process, and timeline task (10 fact families)"
)

_SLOT31J_EPSILON_BASE_GET_TOOL_SEMANTICS = get_tool_semantics
_SLOT31J_EPSILON_BASE_FORMAT_GROUPED_INV1_TOOL_CATALOG = format_grouped_inv1_tool_catalog


def get_tool_semantics(tool_name: str, entry=None, cap=None) -> dict:
    """Slot 31J-epsilon: enrich MemProcFS semantics without changing API shape."""
    sem = dict(_SLOT31J_EPSILON_BASE_GET_TOOL_SEMANTICS(tool_name, entry, cap))
    # 31K-REWEIGHT: MemProcFS Inv1 semantic elevation backed out (base semantics only)
    return sem


def _slot31j_epsilon_enrich_catalog_text(catalog: str) -> str:
    enriched: list[str] = []
    for line in catalog.splitlines():
        stripped = line.lstrip()
        prefix = line[: len(line) - len(stripped)]
        if stripped.startswith("- run_memprocfs — "):
            parts = stripped.split(" | ")
            suffix = ""
            if len(parts) > 1:
                suffix_parts = [
                    "cost=medium" if part.startswith("cost=") else part
                    for part in parts[1:]
                ]
                suffix = " | " + " | ".join(suffix_parts)
            line = prefix + f"- run_memprocfs — {_SLOT31J_EPSILON_MEMPROCFS_PURPOSE}{suffix}"
        enriched.append(line)
    return "\n".join(enriched)


def format_grouped_inv1_tool_catalog(registry, get_capability=None) -> str:
    """Slot 31J-epsilon: render MemProcFS as high-value memory triage."""
    return _slot31j_epsilon_enrich_catalog_text(
        _SLOT31J_EPSILON_BASE_FORMAT_GROUPED_INV1_TOOL_CATALOG(
            registry,
            get_capability,
        )
    )

# 31K-LNKJL-APP-SEMANTIC-BUCKETS: LECmd/JLECmd/AppCompatCache route to execution_artifacts semantics.


# 31K-SRUM-SURFACE-RESOLVER-A3: rich SRUM semantic override. Schema-preserving wrapper.
_SLOT31K_SRUM_BASE_GET_TOOL_SEMANTICS = get_tool_semantics

def get_tool_semantics(tool_name: str, entry=None, cap=None) -> dict:
    sem = dict(_SLOT31K_SRUM_BASE_GET_TOOL_SEMANTICS(tool_name, entry, cap))
    name_l = str(tool_name or "").lower()
    if "srum" in name_l or "srudb" in name_l:
        buckets = list(sem.get("buckets") or ())
        for b in ("execution_artifacts", "network_ioc"):
            if b not in buckets:
                buckets.append(b)
        sem["buckets"] = tuple(buckets)

        detects = list(sem.get("detects") or ())
        for d in (
            "srum_application_resource_usage",
            "srum_network_usage",
            "srum_user_resource_usage",
            "aggregate_network_usage_by_application",
            "disk_side_usage_telemetry",
        ):
            if d not in detects:
                detects.append(d)
        sem["detects"] = tuple(detects)

        sem["evidence_domains"] = ("disk", "network")
        sem["cost"] = "low"
        sem["notes"] = (
            "SRUM/App Resource Usage and Network Usage telemetry from SRUDB.dat. "
            "Use to corroborate app/user/resource/network activity and byte-volume context. "
            "Do not treat SRUM alone as process creation proof, command-line proof, "
            "or destination-IP proof."
        )
    return sem

