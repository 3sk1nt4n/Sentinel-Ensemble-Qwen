"""Universal WHO-from-logons + execution-context labeling.

Two structural, dataset-agnostic enrichments that need no username list and no
case data -- they read OS-primitive STRUCTURE (Event-ID grammar, SID class,
process-token shape), so they fire identically on any Windows sample:

  * LOGON WHO -- the human accounts that interactively or remotely logged on,
    read from Security Event 4624. The interesting logon types are 2 (console
    Interactive), 10 (RemoteInteractive / RDP), 7 (Unlock) and 11 (Cached
    Interactive) -- a human at a keyboard or over RDP. The actor is the event's
    TargetUserName; we keep only HUMAN targets (account-SID shape
    ``S-1-5-21-<domain>-<RID>`` with RID >= 1000 or == 500, name not ending in
    ``$``, not a service identity). This answers "who was on the box" even when
    the flagged processes themselves ran as SYSTEM.

  * EXECUTION CONTEXT -- ``vol_getsids`` records each process's token identity as
    ``sid_fact`` whose ``artifact`` is ``[process, account_or_group, sid]``.
    When a process's only token SID is a built-in service identity
    (SYSTEM / LOCAL|NETWORK SERVICE) we label its findings "SYSTEM/service
    context" instead of a blank actor -- honest: the activity was NOT tied to an
    interactive user. When a process token carries a real account SID, that
    account is the WHO (keyed by PROCESS NAME, which fills the gap where the
    compiled sid_fact has no PID).

The 4624 ``Message`` is the EvtxECmd pipe-delimited schema:
  ``SubjectUserSid | SubjectUserName | SubjectDomainName | SubjectLogonId``
  ``| TargetUserSid | TargetUserName | TargetDomainName | TargetLogonId``
  ``| LogonType | LogonProcessName | ...``
so TargetUserSid is field[4], TargetUserName field[5], TargetDomainName
field[6], LogonType field[8] (verified against real Security.evtx output).

Honest blanks: never invents a user, a time, or a logon. Kill-switch
``SIFT_LOGON_ACTOR=0`` disables both enrichments. See also
``analysis.finding_actor_time`` (path-shape / SID actor) which this complements.
"""
from __future__ import annotations

import json
import os
import re

# Reuse the SID-class / account-name discipline from the existing actor module
# so "human account" means the same thing everywhere (DRY, one definition).
from sift_sentinel.analysis.finding_actor_time import (
    _is_user_sid,
    _clean_account_name,
    _ok_user,
    _finding_strings,
)

# Logon types whose TargetUser is a human at the box (console or remote), not a
# service/network/batch logon. Standard Windows Security 4624 LogonType codes.
_HUMAN_LOGON_TYPES = {2, 7, 10, 11}
LOGON_TYPE_NAMES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive (RDP)", 11: "CachedInteractive",
}

# Built-in service identities -> "ran as SYSTEM/service, not a user". Structural
# well-known SIDs, not an account-name list: S-1-5-18 (Local System),
# S-1-5-19 (Local Service), S-1-5-20 (Network Service).
_SERVICE_SIDS = frozenset({"s-1-5-18", "s-1-5-19", "s-1-5-20"})
SERVICE_CONTEXT_LABEL = "SYSTEM/service context"

# A process token reference in free text: "smss.exe", "lsass.exe" ... the .exe
# shape, lower-cased for matching. Structural, no name list.
_EXE_TOKEN_RE = re.compile(r"\b([A-Za-z0-9._-]{1,64}\.exe)\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def _enabled() -> bool:
    return os.environ.get("SIFT_LOGON_ACTOR", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _event_facts(evidence_db) -> list:
    return (((evidence_db or {}).get("typed_facts") or {}).get("event_log_fact")
            or [])


def _sid_facts(evidence_db) -> list:
    return (((evidence_db or {}).get("typed_facts") or {}).get("sid_fact")
            or [])


def _event_id(fact) -> str:
    """The Windows EventID for an event_log_fact, from canonical_entity_id (where
    the compiler puts it) or the raw_excerpt JSON. Tolerant of either shape."""
    if not isinstance(fact, dict):
        return ""
    cid = str(fact.get("canonical_entity_id") or "").strip()
    if cid.isdigit():
        return cid
    raw = fact.get("raw_excerpt")
    if isinstance(raw, str) and raw:
        m = re.search(r'"EventID"\s*:\s*(\d+)', raw)
        if m:
            return m.group(1)
    return ""


def _parsed_message(fact) -> tuple[list, str]:
    """(pipe-split Message fields, TimeCreated) for an event_log_fact whose
    raw_excerpt is the EvtxECmd JSON. ([], "") when not parseable."""
    raw = fact.get("raw_excerpt") if isinstance(fact, dict) else None
    if not isinstance(raw, str) or not raw:
        return [], ""
    try:
        obj = json.loads(raw)
    except Exception:
        return [], ""
    msg = obj.get("Message")
    if not isinstance(msg, str):
        return [], ""
    parts = [p.strip() for p in msg.split("|")]
    return parts, str(obj.get("TimeCreated") or "")


def parse_human_logons(evidence_db) -> list[dict]:
    """Human interactive/remote/unlock logons from Security Event 4624, newest
    intent first. Each entry: ``{user, domain, account, sid, logon_type,
    logon_type_name, time, source_ip}``. Deduplicated on (account, logon_type);
    keeps the earliest time seen and any source IP. Universal -- Event-ID +
    SID-class + LogonType grammar, never an account list. ``[]`` when disabled or
    when no qualifying human logon exists (honest blank)."""
    if not _enabled():
        return []
    out: dict[tuple, dict] = {}
    for f in _event_facts(evidence_db):
        if _event_id(f) != "4624":
            continue
        parts, when = _parsed_message(f)
        if len(parts) < 9:
            continue
        target_sid, target_user, target_dom, logon_type = (
            parts[4], parts[5], parts[6], parts[8])
        try:
            lt = int(str(logon_type).strip())
        except (TypeError, ValueError):
            continue
        if lt not in _HUMAN_LOGON_TYPES:
            continue
        if not _is_user_sid(target_sid):
            continue
        user = _clean_account_name(target_user)
        if not user:                       # machine acct ($) / service / group
            continue
        domain = str(target_dom or "").strip()
        if domain in ("-", ""):
            domain = ""
        # source IP: 4624 carries the client IpAddress later in the message; take
        # the first non-zero IPv4 shape in the tail fields. Best-effort, blank ok.
        src_ip = ""
        for tail in parts[9:]:
            m = _IPV4_RE.search(tail)
            if m and m.group(1) not in ("0.0.0.0", "127.0.0.1"):
                src_ip = m.group(1)
                break
        key = (user.lower(), lt)
        entry = out.get(key)
        if entry is None:
            out[key] = {
                "user": user,
                "domain": domain,
                "account": (domain + "\\" + user) if domain else user,
                "sid": str(target_sid).strip(),
                "logon_type": lt,
                "logon_type_name": LOGON_TYPE_NAMES.get(lt, str(lt)),
                "time": when,
                "source_ip": src_ip,
                "count": 1,
            }
        else:
            entry["count"] += 1
            if src_ip and not entry["source_ip"]:
                entry["source_ip"] = src_ip
            if when and (not entry["time"] or when < entry["time"]):
                entry["time"] = when
    # newest-first by time string (ISO sorts lexically), human types grouped
    return sorted(out.values(),
                  key=lambda e: (e["logon_type"], e["time"]), reverse=False)


def _sid_artifact(fact) -> tuple[str, str, str]:
    """(process_name, account_or_group, sid) from a sid_fact -- the compiled
    ``artifact`` tuple ``[process, name, sid]`` (preferred) or named fields."""
    if not isinstance(fact, dict):
        return "", "", ""
    art = fact.get("artifact")
    if isinstance(art, (list, tuple)) and len(art) >= 3:
        return str(art[0] or ""), str(art[1] or ""), str(art[2] or "")
    return (str(fact.get("process") or ""),
            str(fact.get("resolved_name") or ""),
            str(fact.get("sid") or ""))


def build_process_identity_map(evidence_db) -> dict[str, dict]:
    """process-name (lower) -> ``{"user": <account or "">, "context":
    "user"|"system_service"}`` from ``sid_fact`` (vol_getsids), keyed by PROCESS
    NAME (artifact[0]) so it works where the compiled fact has no PID. A process
    that carries a real account SID is attributed to that user; one whose token
    is only a built-in service SID is "system_service". Universal -- SID class
    only, no name/value list. ``{}`` when disabled."""
    if not _enabled():
        return {}
    by_proc: dict[str, dict] = {}
    for f in _sid_facts(evidence_db):
        proc, name, sid = _sid_artifact(f)
        proc = proc.strip().lower()
        if not proc:
            continue
        slot = by_proc.setdefault(proc, {"user": "", "context": ""})
        if _is_user_sid(sid):
            user = _clean_account_name(name)
            if user and not slot["user"]:
                slot["user"] = user
                slot["context"] = "user"
        elif str(sid).strip().lower() in _SERVICE_SIDS and not slot["context"]:
            slot["context"] = "system_service"
    # a process that never showed a user SID but showed a service SID -> service
    for proc, slot in by_proc.items():
        if not slot["context"]:
            slot["context"] = "system_service" if not slot["user"] else "user"
    return by_proc


def _finding_process_names(finding) -> list[str]:
    """Process names a finding references -- from process/image/name claim fields
    and the ``*.exe`` token shape in any finding string. Lower-cased, structural,
    dataset-agnostic."""
    names: list[str] = []
    seen: set[str] = set()

    def _add(v):
        v = str(v or "").strip().lower()
        # a bare image path -> basename
        if "\\" in v or "/" in v:
            v = re.split(r"[\\/]", v)[-1]
        if v and v.endswith(".exe") and v not in seen:
            seen.add(v)
            names.append(v)

    if isinstance(finding, dict):
        for claim in (finding.get("claims") or []):
            if isinstance(claim, dict):
                for k in ("process", "image", "name", "process_name",
                          "executable"):
                    if claim.get(k):
                        _add(claim.get(k))
        for s in _finding_strings(finding):
            for m in _EXE_TOKEN_RE.finditer(s):
                _add(m.group(1))
    return names


def derive_execution_context(finding, identity_map) -> str:
    """Best WHO/context for a finding from process token identity:

      * a real account name when the finding's process ran as a user, else
      * ``"SYSTEM/service context"`` when every matched process ran as a built-in
        service identity, else
      * ``""`` (no token evidence -- never fabricated).

    Universal; complements ``finding_actor_time.derive_actor``."""
    if not identity_map or not isinstance(finding, dict):
        return ""
    procs = _finding_process_names(finding)
    if not procs:
        return ""
    saw_service = False
    for p in procs:
        slot = identity_map.get(p)
        if not slot:
            continue
        if slot.get("user"):
            return slot["user"]            # a real user wins
        if slot.get("context") == "system_service":
            saw_service = True
    return SERVICE_CONTEXT_LABEL if saw_service else ""


def enrich_findings_with_logon_context(findings, evidence_db) -> tuple[int, int]:
    """Attach WHO / execution-context to findings that still lack an actor, from
    process token identity (``sid_fact`` keyed by PROCESS NAME -- the gap left by
    the PID-keyed :func:`finding_actor_time.resolve_actors_from_sids` when the
    compiled fact has no PID):

      * a real user -> append a ``user_account`` claim (the table's actor logic
        then renders "Who: <user>"),
      * a service-only process -> set ``finding["execution_context"]`` to
        ``"SYSTEM/service context"`` so the WHO cell is honest, not blank.

    Returns ``(n_user, n_service)``. Mutates ``findings`` in place; never
    overwrites an actor that is already present. Universal; ``(0, 0)`` when
    disabled. Import-local to avoid a cycle with finding_actor_time at module load."""
    if not _enabled():
        return 0, 0
    ident = build_process_identity_map(evidence_db)
    if not ident:
        return 0, 0
    from sift_sentinel.analysis.finding_actor_time import derive_actor
    n_user = n_service = 0
    for f in (findings or []):
        if not isinstance(f, dict) or derive_actor(f):
            continue
        ctx = derive_execution_context(f, ident)
        if not ctx:
            continue
        if ctx == SERVICE_CONTEXT_LABEL:
            if not f.get("execution_context"):
                f["execution_context"] = SERVICE_CONTEXT_LABEL
                n_service += 1
        else:
            f.setdefault("claims", []).append({
                "type": "user_account", "value": ctx,
                "source": "vol_getsids:sid_fact(process)"})
            n_user += 1
    return n_user, n_service


# ── 4688 process-creation -> launching user (attributes DISK-execution findings) ──
# resolve_actors_from_sids / enrich_findings_with_logon_context only see live
# processes (vol_getsids token identity). A finding backed purely by Amcache /
# AppCompatCache / MFT has no resident process, so it stays "not attributed" even
# when Security 4688 recorded WHICH user launched that image. This pass closes
# that gap: it maps NewProcessName basename -> SubjectUserName from 4688 and
# attributes any still-blank finding that references the same image. Structural
# (EventID grammar + SID class + .exe path shape); no user/host/case literals.

_SID_SHAPE_RE = re.compile(r"^S-1-\d[-\d]*$", re.IGNORECASE)


def _looks_like_sid(s) -> bool:
    return bool(_SID_SHAPE_RE.match(str(s or "").strip()))


def _looks_like_exe_path(s) -> bool:
    s = str(s or "").strip().lower()
    return ("\\" in s or "/" in s) and s.endswith(".exe")


def _parse_4688(fact) -> tuple[str, str, str]:
    """(SubjectUserSid, SubjectUserName, NewProcessName-basename) from a 4688
    event_log_fact, or ("","",""). Prefers the standard EventData positions
    (SubjectUserSid[0], SubjectUserName[1], NewProcessName[5]) but validates each
    by SHAPE and falls back to a structural scan (first user-SID + adjacent name;
    first full .exe path = NewProcessName). Tolerant of ordering + the raw_excerpt
    length cap. Universal; no case-specific tokens."""
    parts, _ts = _parsed_message(fact)
    if not parts:
        return "", "", ""
    sid = user = proc = ""
    if len(parts) > 5 and _looks_like_sid(parts[0]) and _looks_like_exe_path(parts[5]):
        sid, user, proc = parts[0].strip(), parts[1].strip(), parts[5].strip()
    else:
        for i, p in enumerate(parts):                    # first user SID + adjacent name
            if _looks_like_sid(p):
                sid = p.strip()
                if i + 1 < len(parts):
                    user = parts[i + 1].strip()
                break
        for p in parts:                                  # first full .exe path = NewProcessName
            if _looks_like_exe_path(p):
                proc = p.strip()
                break
    if not proc:
        return "", "", ""
    base = re.split(r"[\\/]", proc)[-1].strip().lower()
    return (sid, user, base) if base.endswith(".exe") else ("", "", "")


def build_launch_user_map_from_4688(evidence_db) -> dict:
    """{process-basename -> launching human user} from Security 4688 New-Process
    events. Only human launchers (``_is_user_sid`` + ``_ok_user``); service SIDs
    (S-1-5-18/19/20) are dropped so we never call SYSTEM a "user". First human
    launcher per image wins (stable). ``{}`` when disabled or none present."""
    if not _enabled():
        return {}
    out: dict[str, str] = {}
    for f in _event_facts(evidence_db):
        if _event_id(f) != "4688":
            continue
        sid, user, base = _parse_4688(f)
        if not base or not _is_user_sid(str(sid).lower()):
            continue
        clean = _clean_account_name(user)
        if clean and _ok_user(clean):
            out.setdefault(base, clean)
    return out


def resolve_actors_from_process_creation(findings, evidence_db) -> int:
    """Attach the launching user (WHO) to still-blank findings by joining their
    process image to Security 4688 SubjectUserName. Additive and guarded by
    ``derive_actor(f)==""`` (never overwrites, never fabricates); returns the count
    enriched. Universal; ``0`` when disabled or no 4688 user data exists."""
    if not _enabled():
        return 0
    launch_user = build_launch_user_map_from_4688(evidence_db)
    if not launch_user:
        return 0
    from sift_sentinel.analysis.finding_actor_time import derive_actor
    enriched = 0
    for f in (findings or []):
        if not isinstance(f, dict) or derive_actor(f):
            continue
        for name in _finding_process_names(f):
            user = launch_user.get(name)
            if user:
                f.setdefault("claims", []).append({
                    "type": "user_account", "value": user,
                    "source": "evt4688:SubjectUserName"})
                enriched += 1
                break
    return enriched


def summarize_logon_context(evidence_db) -> dict:
    """Structured summary for the report's WHO section:
    ``{"human_logons": [...], "logon_count": n, "any_service_only": bool}``.
    ``human_logons`` is the dedup'd list from :func:`parse_human_logons`."""
    logons = parse_human_logons(evidence_db)
    ident = build_process_identity_map(evidence_db)
    any_service = any(s.get("context") == "system_service"
                      and not s.get("user") for s in ident.values())
    return {
        "human_logons": logons,
        "logon_count": len(logons),
        "any_service_only": any_service,
    }


# ── report section: "Accounts & Logon Context" (the WHO section) ─────────────
_LOGON_SECTION_TITLE = "## Accounts & Logon Context"


def build_logon_context_section(evidence_db) -> str:
    """Markdown WHO section: who was on the box (interactive/RDP logons), which
    account owned the live processes, and the context the flagged activity ran
    under. Built purely from 4624 logons + per-process token identity; ``""`` when
    no logon/identity evidence exists (honest blank). Universal -- no name list."""
    if not _enabled():
        return ""
    logons = parse_human_logons(evidence_db)
    ident = build_process_identity_map(evidence_db)
    # account -> owned process names
    owners: dict[str, list[str]] = {}
    service_procs: list[str] = []
    for proc, slot in ident.items():
        if slot.get("user"):
            owners.setdefault(slot["user"], []).append(proc)
        elif slot.get("context") == "system_service":
            service_procs.append(proc)
    if not logons and not owners and not service_procs:
        return ""

    lines = [_LOGON_SECTION_TITLE, ""]
    lines.append(
        "Who was on this system and the security context the flagged activity "
        "ran under, derived from Security Event 4624 logons and per-process "
        "token identity (vol_getsids). Every value traces to a forensic record; "
        "dataset-agnostic (Event-ID + SID class, no account list).")
    lines.append("")

    if logons:
        lines.append("**Interactive / remote logons (a human at the box):**")
        lines.append("")
        lines.append("| User | Logon type | First seen (UTC) | Source IP | Logons |")
        lines.append("|---|---|---|---|---|")
        for e in logons:
            lines.append("| %s | %s | %s | %s | %d |" % (
                e.get("account") or e.get("user") or "-",
                e.get("logon_type_name") or "-",
                e.get("time") or "-",
                e.get("source_ip") or "-",
                int(e.get("count") or 1)))
        lines.append("")

    if owners:
        lines.append("**Account that owned the running processes:**")
        for user in sorted(owners):
            procs = sorted(set(owners[user]))
            sample = ", ".join(procs[:8]) + (" + more" if len(procs) > 8 else "")
            lines.append("- `%s` - %d process(es): %s" % (user, len(procs), sample))
        lines.append("")

    if service_procs:
        sample = ", ".join(sorted(set(service_procs))[:10])
        lines.append(
            "**Execution context:** %d process(es) ran under built-in "
            "SYSTEM / service identities (not tied to an interactive user) - "
            "e.g. %s. Findings on these processes are labelled "
            "\"SYSTEM/service context\" rather than attributed to a person."
            % (len(set(service_procs)), sample))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def insert_logon_context_into_report(report_md, evidence_db) -> tuple[str, int]:
    """Insert (or idempotently replace) the "## Accounts & Logon Context" section
    into a report.md string. Anchors after "## Per-User Attribution", else after
    "## Attack Timeline", else before "## Key Findings"/"## MITRE", else appends.
    Returns ``(new_md, n_chars)``; a no-op ``(report_md, 0)`` when there is no
    logon/identity evidence. Universal; structural anchors only."""
    import re
    if not isinstance(report_md, str):
        report_md = str(report_md or "")
    section = build_logon_context_section(evidence_db)
    if not section:
        return report_md, 0
    # idempotent replace
    existing = re.search(
        r"(^##\s+Accounts & Logon Context\s*$)(.*?)(?=^##\s|\Z)",
        report_md, re.MULTILINE | re.DOTALL)
    if existing:
        new_md = (report_md[:existing.start()] + section.rstrip() + "\n\n"
                  + report_md[existing.end():])
        return new_md, len(section)
    # insert at the highest-priority structural anchor that exists
    for pat in (r"(^##\s+Per-User Attribution\s*$)(.*?)(?=^##\s|\Z)",
                r"(^##\s+Attack Timeline\s*$)(.*?)(?=^##\s|\Z)"):
        m = re.search(pat, report_md, re.MULTILINE | re.DOTALL)
        if m:
            at = m.end()
            return (report_md[:at].rstrip() + "\n\n" + section.rstrip() + "\n\n"
                    + report_md[at:].lstrip()), len(section)
    for pat in (r"^##\s+Key Findings\s*$", r"^##\s+MITRE"):
        m = re.search(pat, report_md, re.MULTILINE)
        if m:
            return (report_md[:m.start()].rstrip() + "\n\n" + section.rstrip()
                    + "\n\n" + report_md[m.start():].lstrip()), len(section)
    return report_md.rstrip() + "\n\n" + section.rstrip() + "\n", len(section)
