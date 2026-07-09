# SIFT_OS_CAPABILITY_V1: single source of truth for OS-version tool applicability.
# Derives from the NT build number -- second field of Vol3 windows.info
# Major/Minor (e.g. 15.2600 -> 2600). Fixed OS mapping, NOT case data. Used by
# the ReAct OS pre-filter, the bulk/tsk extraction fallbacks, and to retire the
# inert version gate. 'Inapplicable' = structurally cannot run (capability),
# never because a tool returned zero (yield) -- honors the degraded guardrail.

# Minimum NT build for version-gated tools; tools not listed are all-Windows.
_MIN_BUILD = {
    "vol_netscan": 6000,
    "get_amcache": 9200,
    "vol_amcache": 9200,
    "run_srumecmd": 9200,
    "run_jlecmd": 7600,
    "parse_scheduled_tasks_disk": 6000,
}

_OS_NAME = [
    (22000, "Windows 11"),
    (10240, "Windows 10"),
    (9600, "Windows 8.1"),
    (9200, "Windows 8"),
    (7600, "Windows 7"),
    (6000, "Windows Vista"),
    (3790, "Windows XP x64 / Server 2003"),
    (2600, "Windows XP"),
    (2195, "Windows 2000"),
]


def parse_nt_build(major_minor):
    # NT build from Vol3 Major/Minor (15.<build>); None if unparseable.
    try:
        return int(str(major_minor).split(".")[1])
    except (IndexError, ValueError, AttributeError, TypeError):
        return None


def supports(tool, major_minor):
    # True if the tool can run on the evidence OS (unknown build => True).
    build = parse_nt_build(major_minor)
    if build is None:
        return True
    return build >= _MIN_BUILD.get(tool, 0)


def inapplicable_tools(major_minor):
    # Tools structurally inapplicable on the evidence OS build.
    # Empty if build unknown (conservative: filter nothing).
    build = parse_nt_build(major_minor)
    if build is None:
        return set()
    return {t for t, min_b in _MIN_BUILD.items() if build < min_b}


def evidence_os_name(major_minor):
    build = parse_nt_build(major_minor)
    if build is None:
        return ""
    for floor, name in _OS_NAME:
        if build >= floor:
            return name
    return ""


def evidence_os_label(major_minor):
    # One-line ReAct prompt context; empty string if OS unknown.
    build = parse_nt_build(major_minor)
    if build is None:
        return ""
    name = evidence_os_name(major_minor) or "Windows"
    note = " Later-Windows tools omitted (cannot run on this OS)." if inapplicable_tools(major_minor) else ""
    return f"Evidence OS: {name} (NT build {build}).{note}\n\n"



def source_inapplicable_tools(applicable_when_map, has_disk=True, has_memory=True):
    """Tools that cannot run given which evidence SOURCES are present.

    Disk-required = applicable_when needs disk but not memory; memory-required =
    needs memory but not disk. Either-source and source-agnostic tools (e.g.
    windows_evidence-only Volatility plugins) are never dropped. Conservative:
    empty/unknown applicable_when is never dropped. Pure/dependency-free -- the
    caller passes the {tool: applicable_when} map, so this module imports nothing
    from the coordinator (single-source-of-truth rule, no import cycle).
    """
    out = set()
    for tool, aw in (applicable_when_map or {}).items():
        aw = aw or []
        disk_req = ("disk_evidence" in aw) and ("memory_evidence" not in aw)
        mem_req = ("memory_evidence" in aw) and ("disk_evidence" not in aw)
        if disk_req and not has_disk:
            out.add(tool)
        elif mem_req and not has_memory:
            out.add(tool)
    return out
