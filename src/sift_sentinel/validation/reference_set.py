"""
Sentinel Qwen Ensemble - Paired reference set builder.
Extracts value-to-artifact linkages from tool outputs.
NOT a flat set -- every value is paired with its source artifact.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone


_TZ_RE = re.compile(r"[+-]\d{2}:\d{2}$")
_FRAC_RE = re.compile(r"\.\d+")


def normalize_timestamp(ts: str | None) -> str:
    """Normalize a timestamp for comparison.
    Converts timezone offsets to UTC (not just strips them).
    Strips fractional seconds. Replaces T separator with space."""
    if not ts:
        return ""
    s = ts.strip()
    # Normalize Z to +00:00 for uniform parsing
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = s.replace("T", " ")
    # Try full datetime parsing (handles timezone conversion to UTC)
    for attempt_s in (s, _FRAC_RE.sub("", s)):
        try:
            dt = datetime.fromisoformat(attempt_s)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt.replace(microsecond=0).isoformat(sep=" ")
        except (ValueError, TypeError):
            continue
    # Fallback for time-only or unparseable: strip tz + fractional
    s = _TZ_RE.sub("", s)
    s = _FRAC_RE.sub("", s)
    return s.strip()


def _extract_filename(path: str) -> str:
    """Extract filename from a Windows or Unix path."""
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def build_reference_set(tool_outputs: dict[str, dict]) -> dict:
    """Build paired reference set from all tool outputs.

    Returns:
        hashes:                 {sha1_lower: filename}
        pid_to_process:         {pid_int: process_name}
        timestamps_per_artifact:{artifact: [normalized_ts, ...]}
        connections:            {key_string: process_name}
        paths:                  {filename_lower: [full_paths]}
    """
    ref: dict = {
        "hashes": {},
        "pid_to_process": {},
        "pid_to_parent_pid": {},
        "hidden_pids": set(),
        "timestamps_per_artifact": {},
        "connections": {},
        "paths": {},
    }

    _extractors = {
        "get_amcache": _extract_amcache,
        "vol_pstree": _extract_pstree,
        "vol_netscan": _extract_netscan,
        "vol_malfind": _extract_malfind,
        "vol_cmdline": _extract_cmdline,
        "vol_dlllist": _extract_dlllist,
        "vol_psscan": _extract_psscan,
        "extract_mft_timeline": _extract_mft,
        "parse_prefetch": _extract_prefetch,
        "sleuthkit_tsk_recover": _extract_tsk_recover,
    }

    # Process vol_pstree first -- pstree is authoritative for PID->process.
    # setdefault means first-writer-wins, so pstree must go before netscan/etc.
    if "vol_pstree" in tool_outputs:
        envelope = tool_outputs["vol_pstree"]
        if not ("error" in envelope and "output" not in envelope):
            _extract_pstree(envelope.get("output", []), ref)

    for tool_name, envelope in tool_outputs.items():
        if tool_name == "vol_pstree":
            continue
        if "error" in envelope and "output" not in envelope:
            continue
        extractor = _extractors.get(tool_name)
        if extractor:
            extractor(envelope.get("output", []), ref)

    # BUG 5a: Populate hidden_pids via DKOM detection when both
    # pstree and psscan are available. Hidden = in psscan, not in pstree.
    if "vol_pstree" in tool_outputs and "vol_psscan" in tool_outputs:
        pstree_out = tool_outputs["vol_pstree"].get("output", [])
        psscan_out = tool_outputs["vol_psscan"].get("output", [])
        dkom_candidates = dkom_check(pstree_out, psscan_out)
        for cand in dkom_candidates:
            pid = cand.get("pid")
            if pid is not None:
                ref["hidden_pids"].add(pid)

    return ref


# ── dkom_check ───────────────────────────────────────────────────────────

def dkom_check(
    pstree_output: list[dict],
    psscan_output: list[dict],
) -> list[dict]:
    """DKOM detection: find processes in psscan with no pstree entry.
    Deterministic Python. Not AI. Returns DKOM candidates."""
    pstree_pids = {p["PID"] for p in pstree_output}
    orphaned = []
    for p in psscan_output:
        pid = p.get("PID")
        name = p.get("ImageFileName", "")
        if pid not in pstree_pids and name.endswith(".exe") and not p.get("ExitTime"):
            orphaned.append({
                "pid": pid,
                "name": name,
                "offset": p.get("Offset(V)"),
                "finding": "DKOM_CANDIDATE",
                "confidence": "MEDIUM",
                "note": "process in psscan with no pstree entry"
                        " - EPROCESS unlinked",
            })
    return orphaned


# ── Internal helpers ─────────────────────────────────────────────────────

def _add_pid(ref: dict, pid: int, name: str) -> None:
    """Add PID->process. Stores list to handle PID reuse.

    First entry is authoritative (pstree processed first).
    """
    if pid is not None and name:
        bucket = ref["pid_to_process"].setdefault(pid, [])
        if name not in bucket:
            bucket.append(name)


def _add_timestamp(ref: dict, artifact: str, ts: str) -> None:
    """Add a normalized timestamp for an artifact. Deduplicates.
    Stores keys in lowercase for case-insensitive matching."""
    norm = normalize_timestamp(ts)
    key = (artifact or "").lower()
    if norm and key:
        bucket = ref["timestamps_per_artifact"].setdefault(key, [])
        if norm not in bucket:
            bucket.append(norm)


def _add_path(ref: dict, filename: str, full_path: str) -> None:
    """Add filename->full_path. Case-insensitive key."""
    if filename and full_path:
        key = filename.lower()
        bucket = ref["paths"].setdefault(key, [])
        if full_path not in bucket:
            bucket.append(full_path)


# ── Per-tool extractors ──────────────────────────────────────────────────

def _extract_amcache(output, ref: dict) -> None:
    entries = output if isinstance(output, list) else output.get("entries", [])
    for entry in entries:
        sha1 = (entry.get("sha1") or "").lower()
        path = entry.get("path", "")
        filename = _extract_filename(path)
        if sha1 and filename:
            ref["hashes"][sha1] = filename
        if filename and path:
            _add_path(ref, filename, path)
        first_run = entry.get("first_run", "")
        if first_run and filename:
            _add_timestamp(ref, filename, first_run)


def _extract_pstree(output: list, ref: dict) -> None:
    for proc in output:
        pid = proc.get("PID")
        name = proc.get("ImageFileName", "")
        _add_pid(ref, pid, name)
        # BUG 5a: capture parent-child edges for _check_child_process
        ppid = proc.get("PPID")
        if pid is not None and ppid is not None:
            ref["pid_to_parent_pid"][pid] = ppid
        ct = proc.get("CreateTime", "")
        if ct and name:
            _add_timestamp(ref, name, ct)


def _extract_tsk_recover(output, ref: dict) -> None:
    """SIFT_TSK_HASH_SRC_V1: recovered-file sha256 hashes (universal hash
    source when amcache is unavailable, e.g. pre-Win8). ref["hashes"] is
    hash-type-agnostic {hashkey: filename}; setdefault = first-writer-wins.
    Dataset-agnostic: derives only from per-file sha256/name fields."""
    entries = output if isinstance(output, list) else output.get("entries", [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sha256 = (entry.get("sha256") or "").lower()
        path = entry.get("path") or entry.get("recovered_path") or ""
        filename = entry.get("name") or _extract_filename(path)
        if sha256 and filename:
            ref["hashes"].setdefault(sha256, filename)
        if filename and path:
            _add_path(ref, filename, path)


def _extract_netscan(output: list, ref: dict) -> None:
    for conn in output:
        pid = conn.get("PID")
        owner = conn.get("Owner", "")
        _add_pid(ref, pid, owner)
        local = f"{conn.get('LocalAddr', '')}:{conn.get('LocalPort', '')}"
        foreign = f"{conn.get('ForeignAddr', '')}:{conn.get('ForeignPort', '')}"
        key = f"{pid}:{local}->{foreign}"
        if owner:
            ref["connections"][key] = owner
        ct = conn.get("Created", "")
        if ct and owner:
            _add_timestamp(ref, owner, ct)


def _extract_malfind(output: list, ref: dict) -> None:
    for entry in output:
        _add_pid(ref, entry.get("PID"), entry.get("Process", ""))


def _extract_cmdline(output: list, ref: dict) -> None:
    for entry in output:
        _add_pid(ref, entry.get("PID"), entry.get("Process", ""))


def _extract_dlllist(output: list, ref: dict) -> None:
    for entry in output:
        _add_pid(ref, entry.get("PID"), entry.get("Process", ""))
        dll_name = entry.get("Name", "")
        dll_path = entry.get("Path", "")
        if dll_name and dll_path:
            _add_path(ref, dll_name, dll_path)


def _extract_psscan(output: list, ref: dict) -> None:
    for proc in output:
        pid = proc.get("PID")
        name = proc.get("ImageFileName", "")
        _add_pid(ref, pid, name)
        # BUG 5a: psscan is a secondary PPID source.
        # Only write if pstree didn't already (first-writer-wins).
        ppid = proc.get("PPID")
        if pid is not None and ppid is not None:
            ref["pid_to_parent_pid"].setdefault(pid, ppid)
        ct = proc.get("CreateTime", "")
        if ct and name:
            _add_timestamp(ref, name, ct)


def _extract_prefetch(output, ref: dict) -> None:
    entries = output if isinstance(output, list) else output.get("entries", [])
    for entry in entries:
        exe_name = entry.get("executable_name", "")
        exe_path = entry.get("path", "")
        if exe_name:
            _add_path(ref, exe_name, exe_path or exe_name)
        for ts in entry.get("last_run_times", []):
            if ts and exe_name:
                _add_timestamp(ref, exe_name, ts)
        for accessed in entry.get("files_accessed", []):
            if accessed:
                fname = _extract_filename(accessed)
                if fname:
                    _add_path(ref, fname, accessed)


def _extract_mft(output, ref: dict) -> None:
    events = output if isinstance(output, list) else output.get("events", [])
    for event in events:
        filename = event.get("filename", "")
        path = event.get("path", "")
        if not filename:
            filename = _extract_filename(path)
        for field in ("si_created", "fn_created", "si_modified",
                      "fn_modified", "real_created"):
            ts = event.get(field, "")
            if ts and filename:
                _add_timestamp(ref, filename, ts)
        if filename and path:
            _add_path(ref, filename, path)
