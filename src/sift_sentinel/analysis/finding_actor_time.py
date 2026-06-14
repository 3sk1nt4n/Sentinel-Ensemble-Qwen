"""Universal WHO + WHEN attribution for findings (customer/junior-friendly).

Every finding gets a best-effort actor (user) and time, derived PURELY from
structure, so it works on ANY Windows disk or memory sample with no prior
knowledge -- no username lists, no hardcoded accounts, no case data, no answer
key:

  WHO  -- the ``\\Users\\<name>\\`` or ``/users/<name>/`` path SHAPE (both
          separators), or an explicit ``user_account`` claim. Whatever name
          occupies that path slot IS the actor -- a structural slot, not a list.
          Non-human profile dirs (Public / Default / All Users) and service
          identities (SYSTEM / LOCAL|NETWORK SERVICE) are excluded structurally.
  WHEN -- a structured timestamp field on the finding's claims, else an
          ISO-8601 date SHAPE (``YYYY-MM-DD[ HH:MM[:SS]]``) found anywhere in
          the finding's evidence text (process create / MFT / event / SRUM /
          prefetch times all surface this way).

Honest blanks: returns ``""`` when nothing is structurally present -- never
invents a user or a time. Dataset-agnostic; fires identically on every sample.
"""
import re

# Windows-style username sanity: alphanumerics + . _ $ - , <= 64 chars.
_USERNAME_OK = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")

# Profile dirs under C:\Users\ that are NOT a human actor, plus service
# identities. Structural exclusions -- not real account names from any dataset.
_REJECT_USERS = frozenset({
    "", "-", "system", "localsystem", "local service", "localservice",
    "network service", "networkservice", "public", "default", "default user",
    "defaultapppool", "all users",
})

# WHO: the segment right after the Users directory, either separator. The
# negative lookbehind keeps "users" a fresh path token (matches at string start,
# after a separator, or after whitespace; never inside a word like "myusers").
_USER_FROM_PATH = re.compile(r"(?<![A-Za-z0-9])users[\\/]([^\\/]+)", re.IGNORECASE)

# WHEN: structured timestamp field names, then a bare ISO date shape in text.
_TS_FIELDS = (
    "timestamp", "time_created", "timecreated", "create_time", "createtime",
    "created", "first_run", "last_run", "lastrun", "execution_time",
    "event_time", "when", "time", "date",
)
_DATE_SHAPE = re.compile(r"(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)")


def _ok_user(u):
    u = (u or "").strip()
    return bool(u) and bool(_USERNAME_OK.match(u)) and u.lower() not in _REJECT_USERS


def _finding_strings(finding):
    """Yield candidate evidence strings from a finding (title/desc/claims/iocs)."""
    if not isinstance(finding, dict):
        return
    for key in ("title", "description", "details", "raw_excerpt", "summary"):
        v = finding.get(key)
        if isinstance(v, str) and v:
            yield v
    for claim in (finding.get("claims") or []):
        if isinstance(claim, dict):
            for v in claim.values():
                if isinstance(v, str) and v:
                    yield v
    for key in ("iocs", "ioc", "artifacts", "indicators"):
        seq = finding.get(key)
        if isinstance(seq, (list, tuple)):
            for v in seq:
                if isinstance(v, str) and v:
                    yield v
        elif isinstance(seq, str) and seq:
            yield seq


def derive_actor(finding):
    """Best WHO (user) for a finding; ``""`` when no human actor is structural."""
    if not isinstance(finding, dict):
        return ""
    # 1. explicit user_account / user / account claim
    for claim in (finding.get("claims") or []):
        if isinstance(claim, dict) and str(claim.get("type", "")).lower() in (
                "user_account", "user", "account"):
            for k in ("username", "user", "account", "value"):
                u = claim.get(k)
                if isinstance(u, str) and _ok_user(u):
                    return u.strip()
    # 2. \Users\<name>\ path SHAPE across every finding string
    for s in _finding_strings(finding):
        m = _USER_FROM_PATH.search(s)
        if m and _ok_user(m.group(1)):
            return m.group(1).strip()
    return ""


# ── WHO from vol_getsids (SID -> user), so service/process findings get an actor ──
# A real user account is the well-known account-SID shape S-1-5-21-<domain>-<RID>
# with RID >= 1000 (domain/local users) or RID 500 (built-in Administrator). Group
# and machine SIDs (S-1-5-32-*, S-1-5-18/19/20, Everyone, ...) are NOT a human actor.
# Pure structure -- no SID value list, no account-name list.
_USER_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$", re.IGNORECASE)
_PID_IN_TEXT_RE = re.compile(r"\bpid[:= ]\s*(\d{1,7})\b", re.IGNORECASE)


def _is_user_sid(sid: str) -> bool:
    m = _USER_SID_RE.match(str(sid or "").strip())
    if not m:
        return False
    rid = int(m.group(1))
    return rid >= 1000 or rid == 500


def _clean_account_name(name: str) -> str:
    """'HOSTA\\jdoe' / 'DOMAIN/jdoe' -> 'jdoe'; validated by _ok_user (rejects
    SYSTEM/service/group identities)."""
    n = str(name or "").strip().replace("/", "\\")
    if "\\" in n:
        n = n.rsplit("\\", 1)[-1]
    return n if _ok_user(n) else ""


def _finding_pids(finding):
    """Every PID a finding references -- from pid/process_id claim fields and from a
    'pid:<n>' shape in any finding string. Structural; dataset-agnostic."""
    pids: set[str] = set()
    for claim in (finding.get("claims") or []):
        if isinstance(claim, dict):
            for k in ("pid", "process_id", "parent_pid", "ppid"):
                v = claim.get(k)
                if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
                    pids.add(str(v))
    for s in _finding_strings(finding):
        for m in _PID_IN_TEXT_RE.finditer(s):
            pids.add(m.group(1))
    return pids


def _sid_and_name(fact) -> tuple:
    """(sid, account_name) from a sid_fact, tolerant of BOTH shapes: named fields
    (sid / resolved_name) when present, else the compiled ``artifact`` tuple
    ``[process, name, sid]`` (build_typed_evidence_db preserves the artifact even
    when top-level compiler fields are dropped)."""
    sid = fact.get("sid")
    name = fact.get("resolved_name")
    if (sid in (None, "") or name in (None, "")):
        art = fact.get("artifact")
        if isinstance(art, (list, tuple)) and len(art) >= 3:
            name = name if name not in (None, "") else art[1]
            sid = sid if sid not in (None, "") else art[2]
    return str(sid or ""), str(name or "")


def build_pid_user_map(evidence_db) -> dict:
    """PID -> human user, from sid_fact (vol_getsids): the account-SID's resolved
    name. Reads the PID from the named field OR the by_pid index (the real compiled
    shape). Universal: SID STRUCTURE only, no value/name list."""
    edb = evidence_db or {}
    facts = (edb.get("typed_facts") or {}).get("sid_fact") or []
    by_id = {f.get("fact_id"): f for f in facts if isinstance(f, dict)}
    # PID -> [sid_facts]: from the by_pid index (real data) and any named pid field.
    pid_to_facts: dict[str, list] = {}
    for pid, fids in ((edb.get("indexes") or {}).get("by_pid") or {}).items():
        for fid in (fids or []):
            f = by_id.get(fid)
            if isinstance(f, dict):
                pid_to_facts.setdefault(str(pid), []).append(f)
    for f in facts:
        if isinstance(f, dict) and f.get("pid") is not None:
            pid_to_facts.setdefault(str(f.get("pid")), []).append(f)

    out: dict[str, str] = {}
    for pid, fs in pid_to_facts.items():
        for f in fs:
            sid, name = _sid_and_name(f)
            if _is_user_sid(sid):
                user = _clean_account_name(name)
                if user:
                    out.setdefault(pid, user)
                    break
    return out


def resolve_actors_from_sids(findings, evidence_db) -> int:
    """Attach a user_account claim (the WHO) to every finding that references a PID
    owned by a real user (per sid_fact) and does not already have an actor. This makes
    vol_getsids' SID->user data actually attribute findings instead of sitting as
    context. Returns the number of findings enriched. Universal; never invents a user."""
    pid_user = build_pid_user_map(evidence_db)
    if not pid_user:
        return 0
    enriched = 0
    for f in (findings or []):
        if not isinstance(f, dict) or derive_actor(f):
            continue
        for pid in _finding_pids(f):
            user = pid_user.get(pid)
            if user:
                f.setdefault("claims", []).append(
                    {"type": "user_account", "value": user, "source": "vol_getsids:sid_fact"})
                enriched += 1
                break
    return enriched


def derive_when(finding):
    """Best WHEN (UTC date/time shape) for a finding; ``""`` when none present."""
    if not isinstance(finding, dict):
        return ""
    # 1. the finding's OWN structured timestamp field (the curated event time --
    #    e.g. a file-execution / process-create / SRUM time set when the finding
    #    was emitted). This is what most findings actually carry.
    for f in _TS_FIELDS:
        v = finding.get(f)
        if isinstance(v, str):
            m = _DATE_SHAPE.search(v)
            if m:
                return m.group(1)
    # 2. structured timestamp field on a claim (the entity's time)
    for claim in (finding.get("claims") or []):
        if isinstance(claim, dict):
            for f in _TS_FIELDS:
                v = claim.get(f)
                if isinstance(v, str):
                    m = _DATE_SHAPE.search(v)
                    if m:
                        return m.group(1)
    # 3. an ISO date shape anywhere in the finding's evidence text
    for s in _finding_strings(finding):
        m = _DATE_SHAPE.search(s)
        if m:
            return m.group(1)
    return ""


def actor_time_label(finding):
    """``"Who: x · When: y UTC"`` label for the finding; ``""`` when neither known.
    When no human actor is derivable but the finding's process ran under a built-in
    service identity, the honest ``execution_context`` label (e.g. "SYSTEM/service
    context", set upstream by analysis.logon_actor) is shown instead of a blank
    WHO. Never fabricates a user."""
    who = derive_actor(finding)
    when = derive_when(finding)
    if not who and isinstance(finding, dict):
        ctx = str(finding.get("execution_context") or "").strip()
        if ctx:
            who = ctx
    parts = []
    if who:
        parts.append("Who: " + who)
    if when:
        parts.append("When: " + when + " UTC")
    return " · ".join(parts)
