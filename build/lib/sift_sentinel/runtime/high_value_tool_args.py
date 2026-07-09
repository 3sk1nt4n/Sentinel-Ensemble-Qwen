"""A31-alpha: dynamic Step 6 argument resolver for high-value tools.

The Step 6 dispatcher historically built MCP arguments from coarse keyword
heuristics. That worked for the bootstrap set but fails for several
high-value wrappers because the wrapper signatures use specific argument
names and require concrete artifact paths instead of a disk mount root:

    run_memprocfs(memory_image_path=...)
    run_evtxecmd(evtx_path=<dir of *.evtx>)
    run_mftecmd(mft_path=<$MFT file>)
    run_amcacheparser(hive_path=<Amcache.hve>)
    run_appcompatcacheparser(hive_path=<SYSTEM hive>)
    run_lecmd(lnk_path=<dir containing *.lnk>)
    parse_prefetch(disk_mount=<mount root>)

This module resolves a selected tool name to either an mcp_call envelope
with the correct kwargs and concrete paths, or a structured
not_applicable envelope when the underlying artifact is absent on the
mounted evidence (so the dispatcher returns a deterministic envelope
instead of fabricating output or surfacing a wrapper error).

Path resolution is dataset-agnostic: it walks well-known relative Windows
paths beneath the supplied disk mount with case-insensitive segment
matching. No values are read from prior-run notes or evidence-reference files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

HIGH_VALUE_TOOLS: frozenset[str] = frozenset(
    [
        "decode_base64_strings",
        "extract_mft_timeline",
        "extract_network_iocs",
        "parse_prefetch",
        "parse_rdp_artifacts",
        "parse_registry_persistence",
        "parse_scheduled_tasks_disk",
        "run_amcacheparser",
        "run_appcompatcacheparser",
        "run_srumecmd",  # 31K-SRUM-SURFACE-RESOLVER-A3
        "run_evtxecmd",
        "run_lecmd",
        "run_jlecmd",  # 31K-LNK-WIRE: high-value, resolver added below (drift-coupled)
        "run_mftecmd",  # 31K-REWEIGHT: run_memprocfs removed from HIGH_VALUE_TOOLS
        "sleuthkit_tsk_recover",
        "run_recmd",
    ]
)

_LNK_PROBE_LIMIT = 5000


def _canonical_tool_name(tool_name: str) -> str:
    if not isinstance(tool_name, str):
        return ""
    name = tool_name.strip()
    if name.startswith("tool_"):
        name = name[len("tool_"):]
    return name


def _to_path(candidate: Any) -> Path | None:
    if candidate is None:
        return None
    if isinstance(candidate, Path):
        return candidate
    text = str(candidate).strip()
    if not text:
        return None
    return Path(text)


def _case_insensitive_lookup(root: Path, *parts: str) -> Path:
    """Walk ``parts`` beneath ``root`` with case-insensitive segments.

    Returns the resolved Path. Callers must check ``.exists()`` themselves;
    if a segment cannot be matched, the literal join is returned so that
    error messages remain interpretable.
    """

    current = root
    for part in parts:
        exact = current / part
        if exact.exists():
            current = exact
            continue
        folded = part.casefold()
        match: Path | None = None
        try:
            for child in current.iterdir():
                if child.name.casefold() == folded:
                    match = child
                    break
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            match = None
        current = match if match is not None else exact
    return current


def _has_any_lnk(users_root: Path) -> bool:
    if not users_root.is_dir():
        return False
    seen = 0
    try:
        for path in users_root.rglob("*.lnk"):
            if path.is_file():
                return True
            seen += 1
            if seen >= _LNK_PROBE_LIMIT:
                return False
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
        return False
    return False


def _has_file_with_suffix(root: Path, suffix: str) -> bool:
    """EIO-tolerant recursive probe: does any file under ``root`` end with
    ``suffix`` (case-insensitive)?

    ``Path.rglob`` propagates an ``OSError``/EIO raised by ``scandir`` on a
    corrupt or locked directory of a force-mounted NTFS image, which aborts
    the whole resolver (it runs in a Step-6 worker thread, outside the MCP
    client's try/except, so the escape surfaces as a "future raised" tool
    error and zeroes the artifact family). ``os.walk(onerror=...)`` routes a
    per-directory scandir error to the hook and keeps walking siblings; the
    ``next()`` guard also swallows an ``OSError`` surfacing from the walk
    generator itself under concurrent mount access. A single unreadable
    directory must not zero an artifact-existence probe. The walk
    short-circuits on the first match. Dataset-agnostic by construction:
    reacts only to I/O errors and the suffix.
    """
    import os as _os

    suffix_lower = suffix.lower()
    walker = _os.walk(str(root), onerror=lambda _e: None)
    while True:
        try:
            _dirpath, _dirnames, filenames = next(walker)
        except StopIteration:
            return False
        except OSError:
            # Generator itself raised (rare; concurrent ntfs-3g EIO). End the
            # probe gracefully rather than crash the resolver.
            return False
        for name in filenames:
            if name.lower().endswith(suffix_lower):
                return True


def _mcp_call(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "mcp_call", "tool_name": tool_name, "args": args}


def _not_applicable(tool_name: str, reason: str) -> dict[str, Any]:
    return {"kind": "not_applicable", "tool_name": tool_name, "reason": reason}


def _resolve_memprocfs(image_path: Path | None) -> dict[str, Any]:
    if image_path is None or not str(image_path):
        return _not_applicable(
            "run_memprocfs",
            "memory image path not provided",
        )
    if not image_path.exists():
        return _not_applicable(
            "run_memprocfs",
            f"memory image not found at {image_path}",
        )
    return _mcp_call(
        "run_memprocfs",
        {"memory_image_path": str(image_path)},
    )


def _resolve_evtxecmd(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_evtxecmd",
            "disk mount unavailable; EVTX directory cannot be located",
        )
    logs_dir = _case_insensitive_lookup(
        disk_mount, "Windows", "System32", "winevt", "Logs",
    )
    if logs_dir.is_dir():
        return _mcp_call("run_evtxecmd", {"evtx_path": str(logs_dir)})
    parent = _case_insensitive_lookup(
        disk_mount, "Windows", "System32", "winevt",
    )
    if parent.is_dir():
        return _mcp_call("run_evtxecmd", {"evtx_path": str(parent)})
    return _not_applicable(
        "run_evtxecmd",
        "Windows/System32/winevt/Logs directory not present on mount",
    )


def _resolve_mftecmd(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_mftecmd",
            "disk mount unavailable; $MFT cannot be located",
        )
    mft = _case_insensitive_lookup(disk_mount, "$MFT")
    if mft.is_file():
        return _mcp_call("run_mftecmd", {"mft_path": str(mft)})
    return _not_applicable(
        "run_mftecmd",
        "$MFT not exposed at mount root",
    )


def _resolve_amcacheparser(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_amcacheparser",
            "disk mount unavailable; Amcache.hve cannot be located",
        )
    hive = _case_insensitive_lookup(
        disk_mount, "Windows", "AppCompat", "Programs", "Amcache.hve",
    )
    if hive.is_file():
        return _mcp_call("run_amcacheparser", {"hive_path": str(hive)})
    return _not_applicable(
        "run_amcacheparser",
        "Amcache.hve absent under Windows/AppCompat/Programs",
    )


def _resolve_appcompatcacheparser(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_appcompatcacheparser",
            "disk mount unavailable; SYSTEM hive cannot be located",
        )
    hive = _case_insensitive_lookup(
        disk_mount, "Windows", "System32", "config", "SYSTEM",
    )
    if hive.is_file():
        return _mcp_call(
            "run_appcompatcacheparser",
            {"hive_path": str(hive)},
        )
    return _not_applicable(
        "run_appcompatcacheparser",
        "SYSTEM hive absent under Windows/System32/config",
    )



def _count_lnk_group(root: Path, patterns: tuple[str, ...]) -> int:
    total = 0
    for pattern in patterns:
        try:
            for candidate in root.glob(pattern):
                if candidate.is_dir():
                    total += sum(1 for p in candidate.rglob("*.lnk") if p.is_file())
                elif candidate.is_file() and candidate.suffix.lower() == ".lnk":
                    total += 1
        except Exception:
            continue
    return total


_LECMD_HIGH_VALUE_PATTERNS = (
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent",
    "Users/*/AppData/Roaming/Microsoft/Office/Recent",
    "Users/*/Desktop",
    "Users/Public/Desktop",
)

_LECMD_FALLBACK_PATTERNS = (
    "ProgramData/Microsoft/Windows/Start Menu",
    "Users/*/AppData/Roaming/Microsoft/Windows/Start Menu",
)


def _resolve_srumecmd(disk_mount: Path | None) -> dict[str, Any]:
    """31K-SRUM-SURFACE-RESOLVER-A3: artifact-gated SRUM resolver.

    SRUM is high-value when SRUDB.dat exists. If absent, return an honest
    not_applicable result so Step 6 never silently runs a dead tool.
    """
    import shutil as _shutil

    if disk_mount is None:
        return _not_applicable("run_srumecmd", "disk mount unavailable")

    root = Path(disk_mount)
    candidates = (
        root / "Windows" / "System32" / "sru" / "SRUDB.dat",
        root / "Windows" / "System32" / "SRUDB.dat",
        root / "Windows" / "SRUDB.dat",
    )
    srum_db = next((p for p in candidates if p.exists()), None)
    if srum_db is None:
        return _not_applicable(
            "run_srumecmd",
            "SRUDB.dat not found under Windows/System32/sru",
        )

    if not (
        _shutil.which("SrumECmd")
        or _shutil.which("SrumECmd.exe")
        or _shutil.which("srumecmd")
        or _shutil.which("srumecmd.exe")
    ):
        return _not_applicable("run_srumecmd", "SrumECmd binary not found")

    return _mcp_call("run_srumecmd", {"srum_path": str(srum_db)})


def _resolve_lecmd(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_lecmd",
            "disk mount unavailable; LNK directory cannot be located",
        )
    users = _case_insensitive_lookup(disk_mount, "Users")
    if not users.is_dir():
        return _not_applicable(
            "run_lecmd",
            "Users directory not present on mount",
        )

    high_value_count = _count_lnk_group(disk_mount, _LECMD_HIGH_VALUE_PATTERNS)
    fallback_count = _count_lnk_group(disk_mount, _LECMD_FALLBACK_PATTERNS)
    if high_value_count == 0 and fallback_count == 0:
        return _not_applicable(
            "run_lecmd",
            "no .lnk files found in high-value or fallback locations",
        )

    # generic.run_lecmd performs bounded priority selection; passing Users is
    # safe after the wrapper's own high-value candidate cap.
    return _mcp_call("run_lecmd", {"lnk_path": str(users)})


def _resolve_jlecmd(disk_mount: Path | None) -> dict[str, Any]:
    # 31K-LNK-WIRE: mirror _resolve_lecmd. Jump lists live under each user's
    # AppData/Roaming/Microsoft/Windows/Recent/{Automatic,Custom}Destinations;
    # generic.run_jlecmd walks the Users dir like run_lecmd does for .lnk.
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "run_jlecmd",
            "disk mount unavailable; jump list directory cannot be located",
        )
    users = _case_insensitive_lookup(disk_mount, "Users")
    if not users.is_dir():
        return _not_applicable(
            "run_jlecmd",
            "Users directory not present on mount",
        )
    return _mcp_call("run_jlecmd", {"jumplist_path": str(users)})

def _resolve_prefetch(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable(
            "parse_prefetch",
            "disk mount unavailable; Prefetch directory cannot be located",
        )
    pf = _case_insensitive_lookup(disk_mount, "Windows", "Prefetch")
    if pf.is_dir():
        return _mcp_call("parse_prefetch", {"disk_mount": str(disk_mount)})
    return _not_applicable(
        "parse_prefetch",
        "Windows/Prefetch directory absent on mount",
    )



# --- Slot 31C.3 resolver extensions v3 ---
# ZEROFAKE: no caches, no hardcoded signature whitelists.
# Every callable-status check and every accepted-args query is a fresh
# runtime probe against coord._TOOL_REGISTRY and inspect.signature().
# Tool signature evolution is auto-reflected; no stale-state risk.


def _tool_callable_status(tool_name: str) -> tuple[bool, str]:
    """Fresh probe of coordinator registry on every call. NO CACHE.

    Architecture truth: 158 of 186 registry tools store ``(None, category)``
    because they are resolved at RUNTIME (the generic Vol3 runner, the
    EZ-tools dispatch map, the Sleuth Kit runner) -- a None function slot is
    the NORM, not breakage. So a *registered* tool is callable-via-dispatch
    even when its inline function is None; only a genuinely-absent tool is
    'not registered'. (The old check called 85% of the catalog 'not
    callable', which only ever surfaced as a misleading zero-record reason
    for a runtime-resolved tool that happened to return no rows.)
    Universal: keyed on registry presence, no tool-name list."""
    try:
        import sift_sentinel.coordinator as _coord
        reg = getattr(_coord, "_TOOL_REGISTRY", {})
        entry = reg.get(tool_name)
        if entry is None:
            return False, f"{tool_name} is not registered in coordinator"
        # Registered -> dispatchable at runtime (inline fn may legitimately be
        # None for dynamically-resolved tools). callable() of the inline slot
        # is NOT a callability signal here.
        return True, ""
    except Exception as exc:
        return False, f"{tool_name} callable probe failed: {type(exc).__name__}: {exc}"


def _accepted_args_for_tool(tool_name: str) -> set[str]:
    """Fresh probe of inspect.signature() on every call. NO HARDCODED WHITELIST."""
    callable_ok, _ = _tool_callable_status(tool_name)
    if not callable_ok:
        return set()
    try:
        import inspect as _inspect
        import sift_sentinel.coordinator as _coord
        entry = _coord._TOOL_REGISTRY.get(tool_name)
        fn = entry[0] if isinstance(entry, tuple) and entry else entry
        _sig = _inspect.signature(fn)
        for _p in _sig.parameters.values():
            if _p.kind is _inspect.Parameter.VAR_KEYWORD:
                # A31-MFT-WRAPPER-SIG-FIX: tool accepts arbitrary keywords (a
                # (*args, **kwargs) wrapper masking the real core signature, e.g.
                # extract_mft_timeline's stacked wrappers). Return empty set so
                # _filter_tool_args's existing `if not accepted: return cleaned`
                # passthrough honors the resolver's intended kwargs instead of
                # filtering them to empty -> not_applicable. Dataset-agnostic;
                # no hardcoded whitelist, honors real Python keyword semantics.
                return set()
        return set(_sig.parameters.keys())
    except Exception:
        return set()


def _filter_tool_args(tool_name: str, candidates: dict[str, Any]) -> dict[str, Any]:
    """Drop None values + filter by live tool signature. Probed fresh."""
    cleaned = {k: v for k, v in candidates.items() if v is not None}
    accepted = _accepted_args_for_tool(tool_name)
    if not accepted:
        return cleaned
    return {k: v for k, v in cleaned.items() if k in accepted}


def _resolve_registry_persistence(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable("parse_registry_persistence", "disk mount unavailable; registry hives cannot be located")
    config = _case_insensitive_lookup(disk_mount, "Windows", "System32", "config")
    if not config.is_dir():
        return _not_applicable("parse_registry_persistence", "Windows/System32/config directory absent on mount")
    hive_paths = []
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY"):
        p = _case_insensitive_lookup(config, hive)
        if p.is_file():
            hive_paths.append(str(p))
    if not hive_paths:
        return _not_applicable("parse_registry_persistence", "no registry hives found under Windows/System32/config")
    args = _filter_tool_args("parse_registry_persistence", {"mount_path": str(disk_mount), "hive_paths": hive_paths})
    if not args:
        return _not_applicable("parse_registry_persistence", "no compatible resolver arguments for current tool signature")
    return _mcp_call("parse_registry_persistence", args)


def _resolve_scheduled_tasks_disk(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable("parse_scheduled_tasks_disk", "disk mount unavailable; scheduled tasks cannot be located")
    tasks_root = _case_insensitive_lookup(disk_mount, "Windows", "System32", "Tasks")
    if not tasks_root.is_dir():
        return _not_applicable("parse_scheduled_tasks_disk", "Windows/System32/Tasks directory absent on mount")
    args = _filter_tool_args("parse_scheduled_tasks_disk", {"mount_path": str(disk_mount), "tasks_root": str(tasks_root)})
    if not args:
        return _not_applicable("parse_scheduled_tasks_disk", "no compatible resolver arguments for current tool signature")
    return _mcp_call("parse_scheduled_tasks_disk", args)


def _resolve_rdp_artifacts(disk_mount: Path | None) -> dict[str, Any]:
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable("parse_rdp_artifacts", "disk mount unavailable; RDP evidence cannot be located")
    logs_dir = _case_insensitive_lookup(disk_mount, "Windows", "System32", "winevt", "Logs")
    users_dir = _case_insensitive_lookup(disk_mount, "Users")
    has_terminal_services = False
    if logs_dir.is_dir():
        has_terminal_services = any(
            "terminalservices" in p.name.lower() and p.suffix.lower() == ".evtx"
            for p in logs_dir.glob("*.evtx")
        )
    has_rdp_profile = False
    if users_dir.is_dir():
        # EIO-tolerant probe: a corrupt/locked directory under Users (e.g. an
        # incomplete ContentDeliveryManager cache on a force-mounted image)
        # must not crash the resolver. Path.rglob would propagate the EIO.
        has_rdp_profile = _has_file_with_suffix(users_dir, ".rdp")
    if not has_terminal_services and not has_rdp_profile:
        return _not_applicable("parse_rdp_artifacts", "no TerminalServices EVTX or .rdp profile artifacts found")
    args = _filter_tool_args("parse_rdp_artifacts", {"mount_path": str(disk_mount)})
    if not args:
        return _not_applicable("parse_rdp_artifacts", "no compatible resolver arguments for current tool signature")
    return _mcp_call("parse_rdp_artifacts", args)


def _resolve_extract_mft_timeline(disk_mount: Path | None, disk_path: Path | None = None) -> dict[str, Any]:
    source = disk_path if disk_path is not None else disk_mount
    if source is None:
        return _not_applicable("extract_mft_timeline", "disk_path not provided")
    if source.is_dir():
        mft = _case_insensitive_lookup(source, "$MFT")
        if not mft.is_file():
            return _not_applicable("extract_mft_timeline", "$MFT not exposed at disk_path root")
        args = _filter_tool_args("extract_mft_timeline", {"disk_path": str(source.parent if getattr(source, "name", "") == "$MFT" else source)})
    elif source.is_file():
        args = _filter_tool_args("extract_mft_timeline", {"disk_path": str(source.parent if getattr(source, "name", "") == "$MFT" else source)})
    else:
        return _not_applicable("extract_mft_timeline", f"disk_path not found at {source}")
    if not args:
        return _not_applicable("extract_mft_timeline", "no compatible resolver arguments for current tool signature")
    return _mcp_call("extract_mft_timeline", args)


def _resolve_extract_network_iocs(tool_outputs: Any = None) -> dict[str, Any]:
    if tool_outputs is None:
        return _not_applicable("extract_network_iocs", "derived-after-raw tool; runs in Step 6C phase after raw tool outputs exist")
    if isinstance(tool_outputs, (dict, list, tuple, set, str)) and len(tool_outputs) == 0:
        return _not_applicable("extract_network_iocs", "derived-after-raw tool requires non-empty prior raw tool_outputs")
    args = _filter_tool_args("extract_network_iocs", {"tool_outputs": tool_outputs})
    if not args:
        return _not_applicable("extract_network_iocs", "no compatible resolver arguments for current tool signature")
    return _mcp_call("extract_network_iocs", args)


def _resolve_decode_base64_strings(tool_outputs: Any = None) -> dict[str, Any]:
    if tool_outputs is None:
        return _not_applicable("decode_base64_strings", "derived-after-raw tool; runs in Step 6C phase after raw tool outputs exist")
    if isinstance(tool_outputs, (dict, list, tuple, set, str)) and len(tool_outputs) == 0:
        return _not_applicable("decode_base64_strings", "derived-after-raw tool requires non-empty prior raw tool_outputs")
    args = _filter_tool_args("decode_base64_strings", {"tool_outputs": tool_outputs})
    if not args:
        return _not_applicable("decode_base64_strings", "no compatible resolver arguments for current tool signature")
    return _mcp_call("decode_base64_strings", args)


def _resolve_run_recmd(disk_mount: Path | None) -> dict[str, Any]:
    callable_ok, reason = _tool_callable_status("run_recmd")
    if not callable_ok:
        return _not_applicable("run_recmd", reason)
    if disk_mount is None or not disk_mount.is_dir():
        return _not_applicable("run_recmd", "disk mount unavailable; SYSTEM hive cannot be located")
    hive = _case_insensitive_lookup(disk_mount, "Windows", "System32", "config", "SYSTEM")
    if not hive.is_file():
        return _not_applicable("run_recmd", "SYSTEM hive absent under Windows/System32/config")
    args = _filter_tool_args("run_recmd", {"hive_path": str(hive)})
    if not args:
        return _not_applicable("run_recmd", "no compatible resolver arguments for current tool signature")
    return _mcp_call("run_recmd", args)
def _resolve_sleuthkit_tsk_recover(artifact_path: Path | None) -> dict[str, Any]:
    """Slot 31J-beta: provide a writable output_dir for tsk_recover."""
    # Slot 31J-beta-2 not_applicable guard: don't fabricate dir for absent artifact
    import hashlib
    import os

    if artifact_path is None:
        return _not_applicable(
            "sleuthkit_tsk_recover",
            "disk evidence path not provided",
        )
    if not artifact_path.exists():
        return _not_applicable(
            "sleuthkit_tsk_recover",
            "disk evidence not present at provided path",
        )
    base = Path(
        os.environ.get(
            "SIFT_TSK_RECOVER_OUTPUT_BASE",
            "/tmp/sift-sentinel-tools/tsk_recover_out",
        )
    )
    source = str(artifact_path)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    output_dir = base / digest
    output_dir.mkdir(parents=True, exist_ok=True)
    return _mcp_call("sleuthkit_tsk_recover", {"output_dir": str(output_dir)})


# --- end Slot 31C.3 resolver extensions v3 ---

_RESOLVERS = {
    "run_evtxecmd": ("disk_evtx", _resolve_evtxecmd),
    "run_mftecmd": ("disk_mft", _resolve_mftecmd),
    "run_amcacheparser": ("disk_amcache", _resolve_amcacheparser),
    "run_appcompatcacheparser": ("disk_appcompat", _resolve_appcompatcacheparser),
    "run_srumecmd": ("disk_srum", _resolve_srumecmd),  # 31K-SRUM-SURFACE-RESOLVER-A3
    "run_lecmd": ("disk_lnk", _resolve_lecmd),
    "run_jlecmd": ("disk_jumplist", _resolve_jlecmd),  # 31K-LNK-WIRE
    "parse_prefetch": ("disk_prefetch", _resolve_prefetch),
    "parse_registry_persistence": ("disk_registry", _resolve_registry_persistence),
    "parse_scheduled_tasks_disk": ("disk_tasks", _resolve_scheduled_tasks_disk),
    "parse_rdp_artifacts": ("disk_rdp", _resolve_rdp_artifacts),
    "extract_mft_timeline": ("disk_mft_timeline", _resolve_extract_mft_timeline),
    "extract_network_iocs": ("derived_iocs", _resolve_extract_network_iocs),
    "decode_base64_strings": ("derived_decoded", _resolve_decode_base64_strings),
    "run_recmd": ("disk_registry_recmd", _resolve_run_recmd),
    "sleuthkit_tsk_recover": ("disk_recovery", _resolve_sleuthkit_tsk_recover),
}


def resolve_high_value_tool_invocation(
    tool_name: str,
    *,
    image_path: Any = None,
    disk_mount: Any = None,
    disk_path: Any = None,
    tool_outputs: Any = None,
) -> dict[str, Any] | None:
    """Resolve ``tool_name`` to an mcp_call or not_applicable envelope.

    Returns ``None`` when ``tool_name`` is not part of the high-value set,
    so callers fall back to legacy argument logic.
    """
    canonical = _canonical_tool_name(tool_name)
    if canonical not in _RESOLVERS:
        return None
    image = _to_path(image_path)
    mount = _to_path(disk_mount)
    disk = _to_path(disk_path)
    mount_for_disk_tools = mount
    if mount_for_disk_tools is None and disk is not None and disk.is_dir():
        mount_for_disk_tools = disk
    _, resolver = _RESOLVERS[canonical]
    if canonical in ("extract_network_iocs", "decode_base64_strings"):
        return resolver(tool_outputs)
    if canonical == "extract_mft_timeline":
        return resolver(mount_for_disk_tools, disk)
    if canonical == "sleuthkit_tsk_recover":
        return resolver(disk if disk is not None else mount_for_disk_tools)
    return resolver(mount_for_disk_tools)


def tool_applicability_report(
    *,
    image_path: Any = None,
    disk_mount: Any = None,
    disk_path: Any = None,
    tool_outputs: Any = None,
    tools: Any = None,
) -> dict[str, dict[str, Any]]:
    """Universal applicability probe for the high-value tool set.

    For each tool, reports whether its required evidence is present and, when it
    is NOT, the EXACT reason -- so a no-hit fact family (e.g. srum_usage_fact = 0)
    is explained (disk mount unavailable / artifact file absent / binary not
    installed) instead of being a silent mystery. This is the SRUM disk-side probe
    generalized to every high-value tool.

    It calls the SAME resolver Step 6 dispatch uses
    (``resolve_high_value_tool_invocation``), so the report can never drift from
    real runtime behavior. Dataset-agnostic: no case paths, no prior-run notes.

    Returns ``{tool: {"status": "applicable"|"not_applicable",
                      "reason": str, "resolved": dict|None}}``.
    """
    names = sorted(tools) if tools else sorted(HIGH_VALUE_TOOLS)
    report: dict[str, dict[str, Any]] = {}
    for tool in names:
        env = resolve_high_value_tool_invocation(
            tool,
            image_path=image_path,
            disk_mount=disk_mount,
            disk_path=disk_path,
            tool_outputs=tool_outputs,
        )
        if env is None:
            continue  # not a high-value tool -- nothing to probe here
        if env.get("kind") == "not_applicable":
            report[tool] = {
                "status": "not_applicable",
                "reason": str(env.get("reason") or ""),
                "resolved": None,
            }
        else:  # mcp_call -> evidence resolved, tool will run
            report[tool] = {
                "status": "applicable",
                "reason": "",
                "resolved": env.get("args") or {},
            }
    return report


__all__ = [
    "HIGH_VALUE_TOOLS",
    "resolve_high_value_tool_invocation",
    "tool_applicability_report",
]


# SIFT_MFT_RESOLVER_DISK_MOUNT_COMPAT_V1C
# The decorated exported extract_mft_timeline may expose *args/**kwargs to
# inspect.signature, causing _filter_tool_args to return empty. MFT timeline
# itself accepts disk_path. For resolver correctness, disk_mount is a valid
# disk_path source and must not be rejected by schema introspection noise.
def _sift_resolve_extract_mft_timeline_disk_mount_compat_v1c(
    disk_mount=None,
    disk_path=None,
):
    from pathlib import Path as _Path

    source = disk_mount or disk_path
    if source is None or not str(source).strip():
        return _not_applicable("extract_mft_timeline", "disk_path not provided")

    root = _Path(str(source))
    if root.name == "$MFT":
        root = root.parent

    if not root.exists():
        return _not_applicable("extract_mft_timeline", f"disk_path not found at {root}")

    # Force the actual callable's canonical argument. This is intentionally
    # independent of _filter_tool_args because wrappers may hide disk_path.
    return _mcp_call("extract_mft_timeline", {"disk_path": str(root)})


# Update whichever resolver dictionary this checkout uses.
for _sift_name_v1c, _sift_value_v1c in list(globals().items()):
    if isinstance(_sift_value_v1c, dict) and "extract_mft_timeline" in _sift_value_v1c:
        _old = _sift_value_v1c.get("extract_mft_timeline")
        if isinstance(_old, tuple) and len(_old) >= 2:
            _sift_value_v1c["extract_mft_timeline"] = (
                _old[0],
                _sift_resolve_extract_mft_timeline_disk_mount_compat_v1c,
            )
