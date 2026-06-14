"""Tool catalog: organized by DFIR investigation category.
Claude queries by category to find relevant tools without being overwhelmed."""

TOOL_CATALOG = {
    "process_analysis": {
        "description": "Investigate running and hidden processes",
        "tools": {
            "vol_pstree": "Process tree with parent-child relationships",
            "vol_psscan": "Find hidden/unlinked processes (DKOM detection)",
            "vol_cmdline": "Command-line arguments per process",
            "vol_dlllist": "Loaded DLLs per process",
            "vol_handles": "Open file/registry/mutex handles per process",
            "vol_envars": "Environment variables per process",
            "vol_getsids": "Security identifiers (user context) per process",
            "vol_privileges": "Privilege tokens per process (SeDebugPrivilege = suspicious)",
            "vol_psxview": "Cross-view process listing for rootkit-hiding detection",
        },
        "generic_plugins": [
            "windows.pslist.PsList",
            "windows.psxview.PsXView",
            "windows.ldrmodules.LdrModules",
            "windows.vadinfo.VadInfo",
            "windows.vadwalk.VadWalk",
            "windows.threads.Threads",
            "windows.orphan_kernel_threads.Threads",
        ],
    },
    "malware_detection": {
        "description": "Find injected code, rootkits, and suspicious behavior",
        "tools": {
            "vol_malfind": "Injected code detection via VAD anomaly scan",
            "vol_ssdt": "System Service Descriptor Table hooks (rootkit detection)",
        },
        "generic_plugins": [
            "windows.hollowprocesses.HollowProcesses",
            "windows.processghosting.ProcessGhosting",
            "windows.suspicious_threads.SuspiciousThreads",
            "windows.malware.malfind.Malfind",
            "windows.malware.ldrmodules.LdrModules",
            "windows.malware.pebmasquerade.PebMasquerade",
            "windows.malware.skeleton_key_check.Skeleton_Key_Check",
            "windows.malware.svcdiff.SvcDiff",
            "windows.direct_system_calls.DirectSystemCalls",
            "windows.indirect_system_calls.IndirectSystemCalls",
            "windows.etwpatch.EtwPatch",
        ],
    },
    "network_analysis": {
        "description": "Network connections, C2 channels, lateral movement indicators",
        "tools": {
            "vol_netscan": "All network connections by PID",
        },
        "generic_plugins": [
            "windows.netstat.NetStat",
        ],
    },
    "persistence": {
        "description": "Services, scheduled tasks, registry persistence mechanisms",
        "tools": {
            "vol_svcscan": "Windows services from memory",
            "vol_sessions": "Login sessions",
            "parse_wmi_subscription": (
                "WMI event subscription artifacts from the CIMv2 "
                "repository (OBJECTS.DATA) and memory: event filters, "
                "consumers, and filter-to-consumer bindings. Returns "
                "raw per-record evidence only."
            ),
        },
        "generic_plugins": [
            "windows.registry.printkey.PrintKey",
            "windows.registry.userassist.UserAssist",
            "windows.registry.scheduled_tasks.ScheduledTasks",
            "windows.scheduled_tasks.ScheduledTasks",
            "windows.callbacks.Callbacks",
            "windows.driverirp.DriverIrp",
            "windows.driverscan.DriverScan",
            "windows.svclist.SvcList",
            "windows.malware.svcdiff.SvcDiff",
        ],
    },
    "credential_access": {
        "description": "Credential dumping, password extraction, token theft",
        "generic_plugins": [
            "windows.cachedump",
            "windows.hashdump",
            "windows.lsadump",
        ],
    },
    "filesystem_analysis": {
        "description": "File artifacts, MFT timeline, deleted files",
        "tools": {
            "get_amcache": "Execution history with SHA1 hashes",
            "extract_mft_timeline": "MFT timeline with timestomp detection",
            "vol_filescan": "File objects in memory (including deleted)",
            "parse_shellbags": "Folder access history",
            "parse_event_logs": "Windows Event Logs",
            "parse_powershell_transcripts": (
                "PowerShell transcripts: commands, decoded -EncodedCommand, "
                "URLs/IPs/paths, suspicious markers"
            ),
            "parse_rdp_artifacts": (
                "RDP-related artifacts from TerminalServices EVTX "
                "channels, Terminal Server Client registry keys, and "
                "Default.rdp / *.rdp profile files. Returns raw "
                "per-record evidence only."
            ),
        },
        "generic_plugins": [
            "windows.mftscan.MFTScan",
            "windows.mftscan.ADS",
            "windows.mftscan.ResidentData",
            "windows.dumpfiles.DumpFiles",
            "windows.shimcachemem.ShimcacheMem",
        ],
        "sleuthkit": ["fls", "icat", "mmls", "mactime"],
    },
    "registry_analysis": {
        "description": "Registry hives, keys, and forensic artifacts",
        "tools": {
            "vol_reg_hivelist": "Loaded registry hives",
        },
        "generic_plugins": [
            "windows.registry.hivelist.HiveList",
            "windows.registry.hivescan.HiveScan",
            "windows.registry.printkey.PrintKey",
            "windows.registry.certificates.Certificates",
            "windows.registry.getcellroutine.GetCellRoutine",
        ],
    },
    "yara_scanning": {
        "description": "Pattern matching with YARA rules",
        "generic_plugins": [
            "windows.vadyarascan.VadYaraScan",
        ],
        "disk_tools": ["yara"],
    },
}


def get_categories() -> dict:
    """Return all investigation categories with descriptions."""
    return {
        cat: info["description"]
        for cat, info in TOOL_CATALOG.items()
    }


def get_tools_for_category(category: str) -> dict:
    """Return all available tools for a given investigation category."""
    if category not in TOOL_CATALOG:
        return {"error": f"Unknown category: {category}. Available: {list(TOOL_CATALOG.keys())}"}

    cat = TOOL_CATALOG[category]
    result = {
        "category": category,
        "description": cat["description"],
        "specific_tools": cat.get("tools", {}),
        "volatility_plugins": cat.get("generic_plugins", []),
        "sleuthkit_commands": cat.get("sleuthkit", []),
        "disk_tools": cat.get("disk_tools", []),
    }
    total = (len(result["specific_tools"]) + len(result["volatility_plugins"])
             + len(result["sleuthkit_commands"]) + len(result["disk_tools"]))
    result["total_available"] = total
    return result


def recommend_tools(question: str) -> dict:
    """Given an investigation question, recommend relevant categories and tools.
    This is a keyword-based recommender, not AI -- deterministic and fast."""
    question_lower = question.lower()

    KEYWORDS = {
        "process_analysis": ["process", "pid", "parent", "child", "spawn", "execute", "running"],
        "malware_detection": ["malware", "inject", "hollow", "rootkit", "hook", "suspicious", "evil"],
        "network_analysis": ["network", "connection", "c2", "callback", "lateral", "port", "ip", "socket"],
        "persistence": ["persist", "service", "scheduled", "task", "autorun", "startup", "registry run"],
        "credential_access": ["credential", "password", "hash", "dump", "lsass", "sam", "ntds"],
        "filesystem_analysis": ["file", "mft", "timeline", "deleted", "amcache", "prefetch", "shellbag"],
        "registry_analysis": ["registry", "hive", "key", "userassist", "shimcache"],
        "yara_scanning": ["yara", "signature", "pattern", "rule", "scan"],
    }

    matches = {}
    for cat, keywords in KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in question_lower)
        if score > 0:
            matches[cat] = score

    if not matches:
        return {"recommended": list(TOOL_CATALOG.keys()), "reason": "No specific keywords found, showing all categories"}

    ranked = sorted(matches.items(), key=lambda x: -x[1])
    recommended = [cat for cat, score in ranked]

    # Gather tools from top 3 categories
    tools = {}
    for cat in recommended[:3]:
        cat_tools = get_tools_for_category(cat)
        tools[cat] = cat_tools

    return {"recommended_categories": recommended, "tools": tools}

# ─────────────────────────────────────────────────────────────────────
# 31AO Turn 2: tool value tiers + use-case hints (additive metadata).
# Dataset-agnostic — consulted by Inv1 catalog renderer to surface
# distinguishing semantic signals. Empty/missing tools default to
# value_tier="MED" and no hint (no behavioral change from prior runs).
# ─────────────────────────────────────────────────────────────────────

HIGH_VALUE_TOOLS: frozenset[str] = frozenset({
    # Memory: foundation + uniquely-valuable single-purpose tools
    "vol_pstree",        # process tree foundation — ANY memory invx
    "vol_getsids",       # UNIQUE: SID-PID user attribution join
    "vol_cmdline",       # process arguments foundation
    "vol_handles",       # process resources foundation
    "vol_malfind",       # injection detection
    "vol_netscan",       # network IOCs / C2 detection
    "vol_psxview",       # rootkit cross-view detection
    # Disk + parsed evidence
    "parse_event_logs",            # auth/security events (4624/4625/4672)
    "parse_powershell_transcripts", # script execution evidence
    "run_yara",                    # signature-based malware
    "extract_mft_timeline",        # filesystem timeline
    "run_memprocfs",               # FindEvil triage broad coverage
})

# Short, evidence-grounded use-case hints. The hint explains the
# question the tool answers, not the tool's mechanics. Keep under
# 90 chars so the Inv1 catalog stays readable. Dataset-agnostic.
WHEN_TO_USE_HINTS: dict[str, str] = {
    "vol_getsids": (
        "findings cite PIDs without user-owner attribution"
    ),
    "vol_pstree": (
        "any investigation that needs process parent-child relationships"
    ),
    "vol_cmdline": (
        "you need to see how each process was invoked"
    ),
    "vol_handles": (
        "tracking what files/registry/mutexes a process touched"
    ),
    "vol_malfind": (
        "suspected code injection or unknown memory regions"
    ),
    "vol_netscan": (
        "investigating C2 / lateral movement / exfiltration"
    ),
    "vol_privileges": (
        "checking for privilege escalation indicators (SeDebug etc.)"
    ),
    "vol_sessions": (
        "correlating user logon sessions with process activity"
    ),
    "vol_psxview": (
        "detecting rootkit hiding via cross-view process comparison"
    ),
    "parse_event_logs": (
        "credential access / audit trail / authentication forensics"
    ),
    "parse_powershell_transcripts": (
        "investigating PowerShell-based execution evidence"
    ),
    "run_yara": (
        "scanning for known malware family signatures"
    ),
    "extract_mft_timeline": (
        "cross-domain corroboration between memory and filesystem"
    ),
    "run_memprocfs": (
        "broad FindEvil triage when starting any memory investigation"
    ),
    "get_amcache": (
        "execution history evidence (program execution + binary metadata)"
    ),
    "parse_prefetch": (
        "execution history evidence (process run timestamps)"
    ),
    "parse_rdp_artifacts": (
        "lateral movement via RDP investigation"
    ),
    "parse_wmi_subscription": (
        "WMI event subscription persistence investigation"
    ),
    "vol_svcscan": (
        "service-based persistence investigation"
    ),
    "vol_reg_hivelist": (
        "registry hive enumeration before targeted registry queries"
    ),
}

def value_tier(tool_name: str) -> str:
    """Return the value tier for a tool. HIGH if explicitly tagged,
    otherwise MED. Never raises — safe for all tool names."""
    name = str(tool_name or "")
    return "HIGH" if name in HIGH_VALUE_TOOLS else "MED"


def when_to_use(tool_name: str) -> str:
    """Return the use-case hint for a tool, or '' if no hint defined.
    Never raises — safe for all tool names."""
    return WHEN_TO_USE_HINTS.get(str(tool_name or ""), "")

def description_for(tool_name: str) -> str:
    """31AO Turn 2 mini-fix: return rich description for a tool from
    the nested TOOL_CATALOG, or empty string. Walks all category sub-dicts.
    Dataset-agnostic. Never raises."""
    name = str(tool_name or "")
    if not name:
        return ""
    for cat_data in TOOL_CATALOG.values():
        if not isinstance(cat_data, dict):
            continue
        tools = cat_data.get("tools") or {}
        if name in tools:
            return tools[name]
    return ""

