"""Defense layer 10: Process Ancestry Validator (Hunt Evil poster rules)."""

KNOWN_PARENTS = {
    "svchost.exe": ["services.exe"],
    "lsass.exe": ["wininit.exe"],
    "csrss.exe": ["smss.exe"],
    "smss.exe": ["system", "registry", "smss.exe"],
    "services.exe": ["wininit.exe"],
    "wininit.exe": ["smss.exe"],
    "winlogon.exe": ["smss.exe"],
    "taskhostw.exe": ["svchost.exe"],
}

# OS invariant (Hunt Evil): a per-session smss.exe spawns that session's csrss.exe +
# winlogon.exe and then the session smss instance EXITS immediately; its PID is then
# commonly reused (often by svchost.exe). So for a child whose canonical parent is one of
# these transient processes, a NON-canonical parent observed at the SAME create-time second
# is the documented PID-reuse artifact -- not malicious reparenting. Universal across every
# Windows image (no PIDs/IPs/paths/case data).
_TRANSIENT_PARENTS = {"smss.exe"}


def check_ancestry(pstree_records: list[dict]) -> list[dict]:
    """Check process parents against Hunt Evil poster rules.
    pstree_records: flat list of dicts with PID, PPID, ImageFileName keys.
    Returns list of violation dicts."""
    from datetime import datetime, timezone
    import re

    def _ts(v):
        """Parse a CreateTime/ExitTime value to a comparable naive-UTC datetime.
        Returns None on empty/None/unparseable. Defensive: never raises."""
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        s = s.replace("T", " ")
        for attempt in (s, re.sub(r"\.\d+", "", s)):
            try:
                dt = datetime.fromisoformat(attempt)
            except (ValueError, TypeError):
                continue
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        return None

    pid_to_name = {}
    create = {}
    exit = {}
    for proc in pstree_records:
        pid = proc.get("PID")
        name = proc.get("ImageFileName", "")
        if pid is not None:
            pid_to_name[pid] = name
            create[pid] = proc.get("CreateTime")
            exit[pid] = proc.get("ExitTime")

    # SIFT_ANCESTRY_OS_AWARE_V1: derive boot model from the evidence itself.
    # wininit.exe exists on Vista+ (it parents lsass/services); XP/2003 has no
    # wininit and winlogon legitimately parents lsass + services. Reading the
    # process set keeps this universal (XP/7/10/11/degraded) -- no version
    # string, PIDs, or case data.
    _names_present = {(n or "").lower() for n in pid_to_name.values()}
    _xp_boot_model = "wininit.exe" not in _names_present

    violations = []
    for proc in pstree_records:
        name = proc.get("ImageFileName", "").lower()
        expected = KNOWN_PARENTS.get(name)
        if not expected:
            continue
        if _xp_boot_model and name in ("lsass.exe", "services.exe"):
            expected = ["winlogon.exe"]  # SIFT_ANCESTRY_OS_AWARE_V1
        ppid = proc.get("PPID")
        actual_parent = pid_to_name.get(ppid, "UNKNOWN")
        if actual_parent == "UNKNOWN":
            continue  # Parent PID not in process tree; cannot verify
        if actual_parent.lower() not in [e.lower() for e in expected]:
            child_pid = proc.get("PID")
            c_ct = _ts(create.get(child_pid))   # child CreateTime
            p_ct = _ts(create.get(ppid))        # apparent-parent CreateTime
            p_xt = _ts(exit.get(ppid))          # apparent-parent ExitTime
            if c_ct and p_ct and p_ct > c_ct:
                continue  # parent younger than child -> PID reuse, SUPPRESS
            if c_ct and p_xt and p_xt < c_ct:
                continue  # parent exited before child born -> PID reuse, SUPPRESS
            if c_ct and p_ct and p_ct == c_ct and any(e.lower() in _TRANSIENT_PARENTS for e in expected):
                continue  # transient canonical parent (session smss exits, PID reused) at
                # same-second granularity -> PID-reuse artifact, not reparenting. SUPPRESS.
            corroborated = True if (c_ct and p_ct and p_ct < c_ct) else None
            violations.append({
                "pid": proc["PID"],
                "process": proc["ImageFileName"],
                "parent_pid": ppid,
                "actual_parent": actual_parent,
                "expected_parents": expected,
                "child_create_time": create.get(child_pid),
                "parent_create_time": create.get(ppid),
                "corroborated": corroborated,
                "corroboration_reason": (
                    "parent_older_than_child" if corroborated
                    else ("parent_create_time_equal_unverifiable"
                          if (c_ct and p_ct and p_ct == c_ct) else "times_unavailable")
                ),
            })
    return violations
