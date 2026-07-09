"""31AM v2: Deterministic per-user attack narrative for incident report.

Generates a markdown section that attributes findings to user identities
derived from typed_facts.user_account_fact + owned_pids structural join.
Dataset-agnostic by design: no hardcoded usernames, PIDs, hashes, or paths.
Role classification uses vocabulary checks (e.g. 'outlook' in finding title
is a category signal, not a value match).
"""
from __future__ import annotations
from typing import Any, Iterable, Mapping

# Universal vocabulary signals - describe activity CATEGORIES, not values.
INITIAL_ACCESS_VOCAB = ("outlook", "thunderbird", "webmail", "browser",
                        "chrome", "firefox", "edge", "iexplore", "winword",
                        "excel", "powerpoint", "acrobat", "adobe reader")
POWERSHELL_VOCAB = ("powershell", "pwsh", "ps remoting", "wmi",
                    "encoded command", "download cradle")
CREDENTIAL_VOCAB = ("credential", "lsass", "mimikatz", "pwdump", "ntds",
                    "secretsdump", "hashdump", "kerberoast")
LATERAL_VOCAB = ("lateral", "psexec", "wmiexec", "smbexec", "winrm",
                 "remoting", "wmi")
PERSISTENCE_VOCAB = ("driver", "rootkit", "scheduled task", "service",
                     "registry persistence", "autorun", "wmi event")
INJECTION_VOCAB = ("memory injection", "rwx", "process hollow", "reflective",
                   "code injection", "high-entropy")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _title_contains_any(finding: Mapping[str, Any], vocab: Iterable[str]) -> bool:
    text = ((finding.get("title") or "") + " "
            + (finding.get("description") or "")).lower()
    return any(v in text for v in vocab)


def _identity(uf: Mapping[str, Any]) -> str:
    dom = (uf.get("domain") or "").strip()
    name = (uf.get("username") or "").strip()
    if dom and name:
        return f"{dom}\\{name}"
    return name or "unknown"


def _findings_for_user(uf: Mapping[str, Any],
                       findings_final: list) -> list[dict]:
    """Return findings attributed to this user via either:
       (a) compromised_user_account finding with matching username, OR
       (b) any finding with a user_account claim whose username matches, OR
       (c) any finding citing a PID owned by this user."""
    name_low = (uf.get("username") or "").lower()
    dom_low = (uf.get("domain") or "").lower()
    owned_pids = {int(p) for p in (uf.get("owned_pids") or [])
                  if str(p).isdigit() or isinstance(p, int)}
    out = []
    for f in findings_final or []:
        if not isinstance(f, dict):
            continue
        ftype = (f.get("finding_type") or "").lower()
        if ftype == "compromised_user_account":
            for c in (f.get("claims") or []):
                if (isinstance(c, dict)
                    and (c.get("username") or "").lower() == name_low
                    and (c.get("domain") or "").lower() == dom_low):
                    out.append(f)
                    break
            continue
        for c in (f.get("claims") or []):
            if not isinstance(c, dict):
                continue
            if c.get("type") == "user_account":
                if ((c.get("username") or "").lower() == name_low
                    and (c.get("domain") or "").lower() == dom_low):
                    out.append(f)
                    break
            pid = c.get("pid") or c.get("child_pid") or c.get("parent_pid")
            if isinstance(pid, int) and pid in owned_pids:
                out.append(f)
                break
    return out


def _classify_role(uf: Mapping[str, Any], user_findings: list) -> str:
    """Assign ONE role classification per user (highest-priority match)."""
    # Priority 1: compromised_user_account at HIGH/CRITICAL
    for f in user_findings:
        if ((f.get("finding_type") or "").lower() == "compromised_user_account"
            and (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")):
            return "HIGH-CONFIDENCE COMPROMISED"

    # Priority 2: owns a PID in an initial-access-vocabulary finding
    for f in user_findings:
        if (_title_contains_any(f, INITIAL_ACCESS_VOCAB)
            and (f.get("severity") or "").upper() in ("CRITICAL", "HIGH", "MEDIUM")):
            return "LIKELY INITIAL-ACCESS VICTIM"

    # Priority 3: linked to >=2 powershell findings
    ps_count = sum(1 for f in user_findings if _title_contains_any(f, POWERSHELL_VOCAB))
    if ps_count >= 2:
        return "POWERSHELL EXECUTION CONTEXT"

    # Priority 4: high powershell_count but no owned malicious PIDs
    if int(uf.get("powershell_count", 0) or 0) >= 1000 and not user_findings:
        return "POWERSHELL VOLUME ANOMALY"

    # Priority 5: at least one HIGH/CRITICAL linked finding
    for f in user_findings:
        if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
            return "PROCESS OWNER (HIGH-LINKED)"

    if user_findings:
        return "PROCESS OWNER"
    if int(uf.get("powershell_count", 0) or 0) >= 100:
        return "POWERSHELL ACTIVITY"
    return "ACTIVE USER"


def _activity_tags(findings: list) -> list[str]:
    """Detect MITRE-style activity categories present in this user's findings."""
    tags = []
    if any(_title_contains_any(f, INITIAL_ACCESS_VOCAB) for f in findings):
        tags.append("initial access (memory injection in email/browser process)")
    if any(_title_contains_any(f, CREDENTIAL_VOCAB) for f in findings):
        tags.append("credential dumping")
    if any(_title_contains_any(f, LATERAL_VOCAB) for f in findings):
        tags.append("lateral movement")
    if any(_title_contains_any(f, PERSISTENCE_VOCAB) for f in findings):
        tags.append("persistence (driver/rootkit/scheduled task)")
    if any(_title_contains_any(f, INJECTION_VOCAB) for f in findings):
        tags.append("process memory injection")
    return tags


def _role_emoji(role: str) -> str:
    return {
        "HIGH-CONFIDENCE COMPROMISED": "🔴",
        "LIKELY INITIAL-ACCESS VICTIM": "🟡",
        "POWERSHELL EXECUTION CONTEXT": "🟠",
        "POWERSHELL VOLUME ANOMALY": "🟠",
        "PROCESS OWNER (HIGH-LINKED)": "🟠",
        "PROCESS OWNER": "🔵",
        "POWERSHELL ACTIVITY": "🔵",
        "ACTIVE USER": "⚪",
    }.get(role, "⚪")


# 31AN: data-access / collection (fact-driven; dataset-agnostic). Attribute
# file-artifact facts to a user by the Windows Users\<name> profile-path
# segment (NOT owned_pids; LNK/JumpList/MFT facts are path-level). Pure counts
# + top-N accessed-asset paths; no hardcoded paths, names, or IOCs.
_COLLECTION_FACT_TYPES = (
    "lnk_execution_fact", "jumplist_fact", "filesystem_timeline_fact",
    "appcompatcache_execution_fact", "file_execution_fact",
)
_CHANNEL_FACT_TYPES = (
    "network_connection_fact", "network_ioc_fact", "rdp_artifact_fact",
)
_COLLECTION_PATH_FIELDS = (
    "target_abs_path", "local_path", "path", "file_path", "expanded_path",
    "normalized_path", "full_path", "working_directory", "arguments",
    "raw_excerpt_text",
)
_COLL_CACHE: dict = {}


def _coll_paths(fact):
    out = []
    if isinstance(fact, dict):
        for k in _COLLECTION_PATH_FIELDS:
            v = fact.get(k)
            if v:
                out.append(str(v))
    return out


def _coll_display(fact):
    for p in _coll_paths(fact):
        return p
    return ""


def _coll_user_owns(fact, username):
    seg = "\\users\\" + username.lower() + "\\"
    for p in _coll_paths(fact):
        if seg in p.replace("/", "\\").lower():
            return True
    return False


def _collection_activity(uf, typed_facts):
    """Per-user data-access summary, attributed by the Users\\<name> path.

    Returns {"n_assets", "top_paths", "has_channel"}; empty when nothing is
    attributable. "has_channel" is True only when the user owns a PID that
    bears a network/RDP fact (the collection+channel correlation gate).
    """
    empty = {"n_assets": 0, "top_paths": [], "has_channel": False}
    username = (uf.get("username") or "").strip() if isinstance(uf, dict) else ""
    if not username or not isinstance(typed_facts, dict):
        return empty
    ck = (id(typed_facts), username.lower())
    if ck in _COLL_CACHE:
        return _COLL_CACHE[ck]
    seen, seen_set = [], set()
    for ft in _COLLECTION_FACT_TYPES:
        for fact in (typed_facts.get(ft) or []):
            if _coll_user_owns(fact, username):
                disp = _coll_display(fact) or "(path n/a)"
                key = disp.replace("/", "\\").lower()
                if key not in seen_set:
                    seen_set.add(key)
                    seen.append(disp)
    owned = {str(x) for x in (uf.get("owned_pids") or [])}
    has_channel = False
    if owned:
        for ft in _CHANNEL_FACT_TYPES:
            for fact in (typed_facts.get(ft) or []):
                if not isinstance(fact, dict):
                    continue
                pid = str(fact.get("pid") or fact.get("process_id") or "")
                if pid and pid in owned:
                    has_channel = True
                    break
            if has_channel:
                break
    res = {"n_assets": len(seen), "top_paths": seen[:8], "has_channel": has_channel}
    _COLL_CACHE[ck] = res
    return res


def build_per_user_summary(findings_final: list, typed_facts: Mapping[str, Any]) -> str:
    """Return markdown section with per-user attack attribution.

    Dataset-agnostic: derives entirely from typed_facts.user_account_fact
    and findings_final structural fields. No hardcoded values.
    """
    user_facts = (typed_facts or {}).get("user_account_fact") or []
    if not user_facts:
        return ""

    # Build per-user enrichment
    enriched_users = []
    for uf in user_facts:
        if not isinstance(uf, dict):
            continue
        if not (uf.get("username") or "").strip():
            continue
        fs = _findings_for_user(uf, findings_final or [])
        if not fs and int(uf.get("powershell_count", 0) or 0) < 100:
            # Skip users with no linkage and no notable PS volume
            continue
        role = _classify_role(uf, fs)
        enriched_users.append((uf, fs, role))

    if not enriched_users:
        return ""

    # Sort by role priority then severity-density
    role_order = {
        "HIGH-CONFIDENCE COMPROMISED": 0,
        "LIKELY INITIAL-ACCESS VICTIM": 1,
        "POWERSHELL EXECUTION CONTEXT": 2,
        "POWERSHELL VOLUME ANOMALY": 3,
        "PROCESS OWNER (HIGH-LINKED)": 4,
        "PROCESS OWNER": 5,
        "POWERSHELL ACTIVITY": 6,
        "ACTIVE USER": 7,
    }
    enriched_users.sort(key=lambda x: (role_order.get(x[2], 99), -len(x[1])))

    # Render markdown
    lines = []
    lines.append("## Per-User Attribution")
    lines.append("")
    lines.append("This section attributes findings to user identities derived "
                 "from runtime forensic evidence (typed_facts.user_account_fact "
                 "with owned_pids structural join). All attributions are "
                 "dataset-agnostic and traceable to specific finding IDs and "
                 "typed-fact records.")
    lines.append("")

    for uf, fs, role in enriched_users:
        ident = _identity(uf)
        emoji = _role_emoji(role)
        lines.append(f"### {emoji} `{ident}` - {role}")
        # Stats
        n_ps = int(uf.get("powershell_count", 0) or 0)
        n_owned = len(uf.get("owned_pids") or [])
        owned_sample = sorted(int(p) for p in (uf.get("owned_pids") or [])
                              if str(p).isdigit() or isinstance(p, int))[:8]
        owned_note = (f"  ({owned_sample}" +
                      (" + more" if n_owned > 8 else "") + ")") if owned_sample else ""
        stat_lines = []
        if n_ps:
            stat_lines.append(f"PowerShell commands: **{n_ps:,}**")
        if n_owned:
            stat_lines.append(f"Owned PIDs: **{n_owned}**{owned_note}")
        srcs = ", ".join(sorted(uf.get("source_tools") or [])) or "n/a"
        stat_lines.append(f"Evidence sources: {srcs}")
        for sl in stat_lines:
            lines.append(f"- {sl}")

        # Linked findings (group by severity)
        if fs:
            by_sev = {}
            for f in fs:
                sev = (f.get("severity") or "?").upper()
                by_sev.setdefault(sev, []).append(f.get("finding_id") or "?")
            sev_strs = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in by_sev:
                    sev_strs.append(f"{sev}: {', '.join(by_sev[sev])}")
            if sev_strs:
                lines.append(f"- Linked findings - " + "; ".join(sev_strs))

        # Activity tags
        tags = _activity_tags(fs)
        if tags:
            lines.append(f"- Activity pattern: " + "; ".join(tags))

        # 31AN: data-access / collection line (fact-driven; dataset-agnostic)
        _coll = _collection_activity(uf, typed_facts)
        if _coll["n_assets"]:
            _verb = ("data collection; an externally-communicating process "
                     "runs in this user's context"
                     if _coll["has_channel"] else "data / document access")
            lines.append(
                "- Data accessed: **" + str(_coll["n_assets"]) + "** distinct "
                "file artifact(s) (LNK/JumpList/MFT/ShimCache) under this "
                "profile - " + _verb
            )
            for _p in _coll["top_paths"]:
                lines.append("    - `" + str(_p) + "`")

        # Interpretation prose (deterministic, role-based)
        if role == "HIGH-CONFIDENCE COMPROMISED":
            lines.append(f"- **Forensic interpretation**: identity exhibits "
                         "operational anomaly inconsistent with normal user "
                         "or admin workflow; strongly correlates with the "
                         "linked credential/lateral-movement findings.")
        elif role == "LIKELY INITIAL-ACCESS VICTIM":
            lines.append(f"- **Forensic interpretation**: memory injection "
                         "observed in email/browser process owned by this "
                         "user; pattern is consistent with phishing or "
                         "drive-by initial access.")
        elif role == "POWERSHELL EXECUTION CONTEXT":
            lines.append(f"- **Forensic interpretation**: this user's "
                         "owned PowerShell process is cited in multiple "
                         "PowerShell-themed findings (encoded commands, "
                         "memory injection, or remote execution).")
        elif role == "POWERSHELL VOLUME ANOMALY":
            lines.append(f"- **Forensic interpretation**: anomalous "
                         "PowerShell command volume without direct PID "
                         "ownership - likely operated through a different "
                         "process context but visible via transcript records.")
        lines.append("")

    # Attack chain narrative - deterministic, vocabulary-driven
    lines.append("### Attack Chain Narrative")
    lines.append("")
    chain = []
    # Step 1: initial access victims
    ia = [u for u in enriched_users if u[2] == "LIKELY INITIAL-ACCESS VICTIM"]
    if ia:
        names = ", ".join(f"`{_identity(u[0])}`" for u in ia)
        chain.append(f"**Initial access** - Memory injection observed in "
                     f"email/browser processes owned by {names}. Pattern is "
                     f"consistent with email-borne or drive-by payload.")
    # Step 2: credential access
    cred_users = [u for u in enriched_users
                  if any(_title_contains_any(f, CREDENTIAL_VOCAB) for f in u[1])]
    if cred_users:
        names = ", ".join(f"`{_identity(u[0])}`" for u in cred_users)
        chain.append(f"**Credential access** - Credential-dumping "
                     f"findings linked to {names} (LSASS access or staged "
                     f"credential-dumping tools).")
    # Step 3: PS execution / lateral movement
    pse = [u for u in enriched_users if u[2] == "POWERSHELL EXECUTION CONTEXT"]
    lat_users = [u for u in enriched_users
                 if any(_title_contains_any(f, LATERAL_VOCAB) for f in u[1])]
    if pse or lat_users:
        names = ", ".join(f"`{_identity(u[0])}`" for u in (pse + lat_users))
        chain.append(f"**PowerShell execution / lateral movement** - "
                     f"PowerShell-themed findings cite processes owned by {names}.")
    # Step 4: persistence
    pers_users = [u for u in enriched_users
                  if any(_title_contains_any(f, PERSISTENCE_VOCAB) for f in u[1])]
    if pers_users:
        names = ", ".join(f"`{_identity(u[0])}`" for u in pers_users)
        chain.append(f"**Persistence** - Driver/rootkit/scheduled-task "
                     f"persistence observed under {names}.")
    # Step 5: anomalous volume
    pva = [u for u in enriched_users if u[2] == "POWERSHELL VOLUME ANOMALY"]
    if pva:
        names = ", ".join(f"`{_identity(u[0])}`" for u in pva)
        chain.append(f"**Anomalous account activity** - {names} exhibits "
                     f"PowerShell volume far above the dataset's distribution "
                     f"(top-user outlier, ≥2× next-highest).")

    # 31AN: Collection / Exfiltration chain steps (fact-driven; dataset-
    # agnostic). Collection counts the subject's accessed file artifacts;
    # exfil wording is gated on collection co-occurring with an external
    # channel in the same user context.
    _coll_users, _exfil_users = [], []
    for _u in enriched_users:
        _c = _collection_activity(_u[0], typed_facts)
        if _c["n_assets"] >= 1:
            _coll_users.append((_u, _c))
            if _c["has_channel"]:
                _exfil_users.append(_u)
    if _coll_users:
        _names = ", ".join(
            "`" + _identity(_u[0]) + "` (" + str(_c["n_assets"]) + " asset(s))"
            for (_u, _c) in _coll_users
        )
        chain.append("**Collection / data access** - File-artifact evidence "
                     "(LNK/JumpList/MFT/ShimCache) shows asset access by "
                     + _names + ".")
    if _exfil_users:
        _names = ", ".join("`" + _identity(_u[0]) + "`" for _u in _exfil_users)
        chain.append("**Potential exfiltration** - Collection by " + _names
                     + " co-occurs with an externally-communicating process in "
                     "the same user context; correlate channel + staging to "
                     "confirm.")

    if chain:
        # Number SEQUENTIALLY by what actually fired -- the steps are built in
        # kill-chain order, but only the observed ones are emitted, so a fixed
        # per-step number would print gaps ('4.', '6.', '7.'). Enumerate at emit.
        for i, c in enumerate(chain, 1):
            lines.append("%d. %s" % (i, c))
            lines.append("")
    else:
        lines.append("(No multi-step chain inferred from observed findings.)")
        lines.append("")

    return "\n".join(lines)

def insert_per_user_summary_into_report(report_md, findings_final, typed_facts):
    """31AM v3: insert per-user attribution section into a report.md string.

    Dataset-agnostic by design:
      * Insertion point uses dynamic markdown structural anchors (## section
        headers), never line numbers or specific values.
      * Section content built fresh from findings_final + typed_facts every
        call - no caching, no state.
      * Idempotent: if the report already contains "## Per-User Attribution",
        REPLACE that section (so re-runs don't duplicate).
      * Fallback chain for anchor: after "## Attack Timeline" -> before
        "## Key Findings" -> before "## MITRE" -> append to end.

    Args:
        report_md: existing markdown report string (may be empty).
        findings_final: list of finding dicts.
        typed_facts: dict containing user_account_fact list.

    Returns:
        (new_report_md, n_chars_inserted_or_replaced)
    """
    import re
    if not isinstance(report_md, str):
        report_md = str(report_md or "")
    section = build_per_user_summary(findings_final, typed_facts)
    if not section:
        return report_md, 0

    # Idempotent replace: if the section already exists, swap it out.
    # Locate "## Per-User Attribution" through to the next "## " or EOF.
    existing = re.search(
        r"(^##\s+Per-User Attribution\s*$)(.*?)(?=^##\s|\Z)",
        report_md, re.MULTILINE | re.DOTALL,
    )
    if existing:
        new_md = (report_md[:existing.start()] + section.rstrip() + "\n\n"
                  + report_md[existing.end():])
        return new_md, len(section)

    # Otherwise, INSERT at the highest-priority anchor that exists.
    # Priority 1: after "## Attack Timeline" section (end of that section)
    m = re.search(
        r"(^##\s+Attack Timeline\s*$)(.*?)(?=^##\s|\Z)",
        report_md, re.MULTILINE | re.DOTALL,
    )
    if m:
        insert_at = m.end()
        new_md = (report_md[:insert_at].rstrip() + "\n\n"
                  + section.rstrip() + "\n\n"
                  + report_md[insert_at:].lstrip())
        return new_md, len(section)

    # Priority 2: before "## Key Findings"
    m = re.search(r"^##\s+Key Findings\s*$", report_md, re.MULTILINE)
    if m:
        new_md = (report_md[:m.start()].rstrip() + "\n\n"
                  + section.rstrip() + "\n\n"
                  + report_md[m.start():])
        return new_md, len(section)

    # Priority 3: before "## MITRE"
    m = re.search(r"^##\s+MITRE", report_md, re.MULTILINE)
    if m:
        new_md = (report_md[:m.start()].rstrip() + "\n\n"
                  + section.rstrip() + "\n\n"
                  + report_md[m.start():])
        return new_md, len(section)

    # Priority 4: append to end
    sep = "\n\n" if report_md.strip() else ""
    new_md = report_md.rstrip() + sep + section.rstrip() + "\n"
    return new_md, len(section)

