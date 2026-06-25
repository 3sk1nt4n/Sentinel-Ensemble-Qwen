from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Step-header palette (magenta + bold), TTY-gated -- matches run_pipeline's
# STEP 1 / STEP 16 headers so the banner title reads as the same brand color.
# SIFT_FORCE_COLOR=1 forces the palette on for captured/redirected output (the
# self-corrected cyan ID + the green +ReAct: tokens are otherwise stripped when
# stdout is not a TTY).
_TTY = sys.stdout.isatty() or os.environ.get("SIFT_FORCE_COLOR") == "1"
_M = "\033[95m" if _TTY else ""
_B = "\033[1m" if _TTY else ""
_C = "\033[96m" if _TTY else ""   # cyan   -- AI self-corrected finding IDs
_G = "\033[92m" if _TTY else ""   # green  -- ReAct-judged finding IDs / benign
_R = "\033[91m" if _TTY else ""   # red    -- CONFIRMED tier
_Y = "\033[93m" if _TTY else ""   # yellow -- NEEDS-REVIEW tier
_D = "\033[90m" if _TTY else ""   # grey   -- inconclusive / unresolved tier
_X = "\033[0m" if _TTY else ""

# Disposition TIER shown per FINDINGS row -- so a correctly DOWNGRADED weak-alone
# signal (e.g. an uncorroborated RWX region) reads as NEEDS-REVIEW, never as a
# confirmed finding. Single-token labels so each stays one colored word (wrap-safe).
# Universal: keyed on the disposition BUCKET, never on a process/case value.
_TIER_LABEL = {
    "confirmed_malicious_atomic": "CONFIRMED",
    "suspicious_needs_review": "NEEDS-REVIEW",
    "inconclusive_unresolved": "INCONCLUSIVE",
    "synthesis_narrative": "CONTEXT",
    "benign_or_false_positive": "BENIGN",
}

# Per-row severity glyph (●) color, keyed on the disposition TIER so severity
# reads at a glance: red=confirmed, amber=needs-review, green=benign, grey=
# inconclusive/unresolved/context, cyan=AI self-corrected. The bullet U+25CF is
# exactly ONE visible column, so it never shifts the box borders (an emoji would
# be two columns and break alignment). Universal: keyed on the bucket, not case
# data.
_GLYPH_COLOR = {
    "CONFIRMED": _R, "NEEDS-REVIEW": _Y, "BENIGN": _G,
    "INCONCLUSIVE": _D, "CONTEXT": _D, "UNRESOLVED": _D, "SELF-CORRECTED": _C,
}


def _severity_glyph(tier: str) -> str:
    """Colored one-column severity bullet for a disposition tier."""
    return _GLYPH_COLOR.get(tier or "", _D) + "●" + _X

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _vlen(s: Any) -> int:
    """Visible length of a string -- ANSI color codes don't count toward width."""
    return len(_ANSI_RE.sub("", str(s)))


def _vljust(s: Any, w: int) -> str:
    s = str(s)
    return s + " " * max(0, w - _vlen(s))

# SIFT_CUSTOMER_TABLE_BUCKET_FAITHFUL_V1E
#
# Contract:
# - The final customer table is a projection of finding_disposition_buckets.json.
# - It never routes rows by confidence, severity, or local heuristics.
# - Confirmed and suspicious findings are action-first.
# - Self-corrected/inconclusive/withheld findings come next.
# - Benign/false-positive findings are visible at the bottom.
# - No confidence or severity columns are emitted.

SECTION_SPECS = [
    ("Findings", ["confirmed_malicious_atomic", "suspicious_needs_review"]),
    ("AI Self-Correction / Inconclusive", ["inconclusive_unresolved"]),
    ("Benign / False Positive", ["benign_or_false_positive"]),
]  # SIFT_FRIENDLY_DETAILS_V1

BUCKET_LABEL = {
    "confirmed_malicious_atomic": "CONFIRMED",
    "suspicious_needs_review": "NEEDS REVIEW",
    "inconclusive_unresolved": "INCONCLUSIVE",
    "synthesis_narrative": "CONTEXT",
    "benign_or_false_positive": "BENIGN / FALSE POSITIVE",
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return {}


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _txt(value: Any, limit: int = 96) -> str:
    s = str(value or "").replace("\n", " ").replace("\r", " ")
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace("|", "\\|")
    if len(s) <= limit:
        return s
    return s[: max(1, limit - 1)].rstrip() + "…"


def _finding_id(f: dict[str, Any]) -> str:
    return str(f.get("finding_id") or f.get("id") or "-").strip() or "-"


def _title(f: dict[str, Any]) -> str:
    raw = f.get("title") or f.get("summary") or f.get("finding") or f.get("description") or _finding_id(f)
    try:
        from sift_sentinel.reporting.display_sanitize import clean_display_text
        raw = clean_display_text(raw)
    except Exception:
        pass
    return _txt(raw, 88)


def _tools(f: dict[str, Any]) -> str:
    vals = []
    for key in ("source_tools", "tools", "tool_hits", "producer_tools"):
        raw = f.get(key)
        if isinstance(raw, list):
            vals.extend(str(x) for x in raw if x)
        elif isinstance(raw, str) and raw.strip():
            vals.append(raw.strip())
    vals = sorted(dict.fromkeys(vals))
    return _txt(", ".join(vals) if vals else "-", 140)


def _claim_count(f: dict[str, Any]) -> int:
    claims = f.get("claims")
    return len(claims) if isinstance(claims, list) else 0


# Universal Windows Event-ID -> plain-English label, so a bare '5140' reads as
# 'event:5140 (network share accessed)' for any reader. OS-primitive knowledge
# (like HTTP 404 -> Not Found), not case data.
_EVENT_ID_LABEL = {
    "104": "event log cleared", "1102": "audit log cleared",
    "4624": "successful logon", "4625": "failed logon", "4634": "logoff",
    "4647": "user-initiated logoff", "4648": "logon with explicit credentials",
    "4672": "special privileges assigned", "4688": "process created",
    "4689": "process exited", "4697": "service installed",
    "7045": "service installed", "7036": "service state change",
    "4698": "scheduled task created", "4699": "scheduled task deleted",
    "4700": "scheduled task enabled", "4702": "scheduled task updated",
    "4720": "user account created", "4722": "account enabled",
    "4724": "password reset attempt", "4725": "account disabled",
    "4726": "account deleted", "4738": "account changed",
    "4728": "added to global security group", "4732": "added to local security group",
    "4756": "added to universal security group",
    "4768": "Kerberos TGT requested", "4769": "Kerberos service ticket requested",
    "4771": "Kerberos pre-auth failed",
    "5140": "network share accessed", "5145": "network share access checked",
    "5156": "network connection allowed", "5158": "local port bound",
    "4663": "object access attempt", "4660": "object deleted",
    "1116": "antimalware threat detected", "1117": "antimalware action taken",
    "400": "PowerShell engine started", "4103": "PowerShell module logged",
    "4104": "PowerShell scriptblock logged",
}


def _sv(x: Any) -> str:
    return str(x).strip()


def _cfirst(c: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = c.get(k)
        if v not in (None, "", []):
            return v
    return None


def _event_label(e: Any) -> str:
    es = _sv(e)
    if not es:
        return ""
    lbl = _EVENT_ID_LABEL.get(es)
    return "event:%s (%s)" % (es, lbl) if lbl else "event:%s" % es


def _classify_bare(v: Any) -> str:
    s = _sv(v)
    if s.isdigit() and s in _EVENT_ID_LABEL:
        return _event_label(s)
    return s


def _entity_bits(c: dict[str, Any]) -> list[str]:
    """Entity-typed IOC labels from one claim -- each value prefixed with its kind
    (user: / service: / task: / event: / port: / key:) so a bare 'jdoe',
    '5140' or 'PSEXESVC' reads clearly for any reader. Universal: keys on claim
    FIELD names + the universal Event-ID map, never a case value."""
    out: list[str] = []
    u = _cfirst(c, "user", "username", "account", "account_name", "target_user", "subject_user")
    if u is not None:
        out.append("user:%s" % _sv(u))
    sv = _cfirst(c, "service_name", "service")
    if sv is not None:
        out.append("service:%s" % _sv(sv))
    tk = _cfirst(c, "task_name", "task")
    if tk is not None:
        out.append("task:%s" % _sv(tk))
    ev = _cfirst(c, "event_id", "event_code", "event")
    if ev is not None:
        lab = _event_label(ev)
        if lab:
            out.append(lab)
    ip = _cfirst(c, "remote_ip", "foreign_addr", "ip", "local_ip")
    pt = _cfirst(c, "remote_port", "dest_port", "port", "local_port")
    if ip is not None and pt is not None:
        out.append("%s:%s" % (_sv(ip), _sv(pt)))
    elif ip is not None:
        out.append(_sv(ip))
    elif pt is not None:
        out.append("port:%s" % _sv(pt))
    dm = _cfirst(c, "domain", "fqdn", "hostname", "host", "url")
    if dm is not None:
        out.append(_sv(dm))
    p = _cfirst(c, "path", "filepath", "image_path")
    if p is not None:
        out.append(_sv(p))
    k = _cfirst(c, "registry_path", "registry_key", "key")
    if k is not None:
        out.append("key:%s" % _sv(k))
    if not out:
        bare = _cfirst(c, "value", "artifact", "indicator")
        if bare is not None:
            out.append(_classify_bare(bare))
    return [b for b in out if b]


def _clip_sentence(value: Any, limit: int = 240) -> str:
    """Clip to <=limit chars on a SENTENCE boundary (else a word boundary) so the
    Details cell never ends mid-word/number. Universal; adds an ellipsis only when
    truncated."""
    s = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(s) <= limit:
        return s
    cut = s[:limit]
    m = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if m >= int(limit * 0.5):
        return cut[:m + 1].strip()
    sp = cut.rfind(" ")
    base = cut[:sp] if sp > 0 else cut
    return base.rstrip(" ,;:") + "\u2026"


def _human_bytes(n: Any) -> str:
    """Bytes -> human figure (decimal units, e.g. 64410159574 -> '64.4 GB')."""
    try:
        v = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if v < 1000:
            return ("%d B" % int(v)) if unit == "B" else ("%.1f %s" % (v, unit))
        v /= 1000.0
    return "%.1f EB" % v


def _format_srum_egress(items: Any) -> str | None:
    """A SRUM usage row (list of CSV cells) -> a readable egress figure, e.g.
    'egress 64.4 GB · appid:1 · 2020-11-16'. Universal: keys on the SHAPE -- a
    large integer (byte count), a date token, an app id -- never on a case value.
    Returns None when the artifact is not SRUM-shaped (then raw rendering applies)."""
    cells = [str(x).strip() for x in (items or []) if str(x).strip()]
    if not cells:
        return None
    blob = " ".join(cells).lower()
    if not any(t in blob for t in ("srudb", "srum", "appid")):
        return None
    nums = [int(t) for t in cells if t.isdigit()]
    big = max(nums) if nums else 0
    date = next((t[:10] for t in cells if re.match(r"\d{4}-\d{2}-\d{2}", t)), "")
    app = next((t for t in cells if t.lower().startswith(("appid:", "app:"))), "")
    parts = []
    if big > 100000:  # > 100 KB -> a real egress figure worth surfacing
        parts.append("egress %s" % _human_bytes(big))
    if app:
        parts.append(app)
    if date:
        parts.append(date)
    return " · ".join(parts) if parts else None


def _ioc_bits(f: dict[str, Any]) -> str:
    bits: list[str] = []
    claims = f.get("claims")
    if isinstance(claims, list):
        for c in claims:
            if not isinstance(c, dict):
                continue
            pid = c.get("pid")
            proc = c.get("process") or c.get("process_name") or c.get("image")
            if pid is not None or proc:
                bits.append(f"pid:{pid} {proc}".strip())
            fn = c.get("filename") or c.get("file") or c.get("name")
            _htag = ""
            for _hk in ("sha256", "sha1", "md5", "hash"):
                _hv = c.get(_hk)
                if _hv and isinstance(_hv, (str, int, float)):
                    _hs = str(_hv)
                    _htag = "%s:%s%s" % (_hk, _hs[:12], "\u2026" if len(_hs) > 12 else "")
                    break
            if fn and _htag:
                bits.append("%s (%s)" % (str(fn), _htag))
            elif fn:
                bits.append(str(fn))
            elif _htag:
                bits.append(_htag)
            # entity-typed labels (user:/service:/event:/port:/key: ...) so bare
            # values read clearly and junior-friendly for everyone.
            bits.extend(_entity_bits(c))
            if len(bits) >= 6:
                break
    # Always surface the finding-level primary artifact (e.g. an admin-share
    # target IP) too, deduped -- so an event/label bit never hides it.
    art = f.get("primary_artifact") or f.get("artifact") or f.get("ioc") or ""
    if isinstance(art, list):
        _srum = _format_srum_egress(art)
        arts = [_srum] if _srum else [str(x) for x in art[:5]]
    else:
        arts = [str(art)] if art else []
    for a in arts:
        a = a.strip()
        if a and not any(a in b for b in bits):
            bits.append(a)
    try:
        from sift_sentinel.reporting.display_sanitize import clean_display_text
        bits = [clean_display_text(b) for b in bits]
    except Exception:
        pass
    return _txt("; ".join(dict.fromkeys(b for b in bits if b)) if bits else "-", 120)


def _sc_badge(f: dict[str, Any]) -> str:
    sc = f.get("self_correction")
    if isinstance(sc, dict):
        status = str(sc.get("status") or "").strip()
        if status:
            return f"; AI self-correction: {status}"
        if sc.get("applied") is True:
            return "; AI self-correction: applied"
    return ""


def _react_text(f: dict[str, Any]) -> str:
    rc = f.get("react_conclusion")
    if isinstance(rc, dict):
        return str(rc.get("text") or rc.get("evidence") or rc.get("conclusion") or "").strip()
    return ""


def _event_when(f: dict[str, Any]) -> str:
    """Best-effort UTC event time/date for the Details cell, derived PURELY from
    finding structure (a timestamp claim field, else an ISO-8601 date shape in
    the evidence text). Returns "" when nothing is structurally present -- never
    invents a time. Universal / dataset-agnostic. See analysis.finding_actor_time.
    """
    try:
        from sift_sentinel.analysis.finding_actor_time import derive_when
        return derive_when(f) or ""
    except Exception:
        return ""


def _event_who(f: dict[str, Any]) -> str:
    """Best-effort actor (user) for the Details cell, derived PURELY from finding
    structure -- a ``\\Users\\<name>\\`` path SHAPE or an explicit user_account claim,
    never a username list, never fabricated (blank for SYSTEM/service context). The
    WHO the WHEN already had a slot for. Universal. See analysis.finding_actor_time."""
    try:
        from sift_sentinel.analysis.finding_actor_time import derive_actor
        return derive_actor(f) or ""
    except Exception:
        return ""


def _tool_hit_count(f: dict[str, Any], react_by_finding: dict | None = None) -> int:
    """Number of DISTINCT forensic tools that hit a finding, counted from the
    SAME fields the Tools Hit cell renders (source_tools / tools / tool_hits /
    producer_tools) plus any extra ReAct cross-check tools. Drives the
    'most-corroborated first' row ordering. Universal: tool identity only."""
    seen: set[str] = set()
    for key in ("source_tools", "tools", "tool_hits", "producer_tools"):
        raw = f.get(key)
        if isinstance(raw, list):
            seen |= {str(x).strip() for x in raw if x}
        elif isinstance(raw, str) and raw.strip():
            seen.add(raw.strip())
    for t in ((react_by_finding or {}).get(_finding_id(f)) or []):
        if t:
            seen.add(str(t).strip())
    seen.discard("")
    return len(seen)


def _sort_by_tool_hits(findings: Any, react_by_finding: dict | None = None) -> list:
    """Order findings most-tool-hits-first ("highest number of tool-hits at the
    top, always"). Stable: ties keep the caller's disposition order."""
    return sorted(
        [f for f in _as_list(findings) if isinstance(f, dict)],
        key=lambda f: _tool_hit_count(f, react_by_finding),
        reverse=True,
    )


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _severity_rank(f: dict[str, Any]) -> int:
    """A3: 4..1 for CRITICAL..LOW, 0 for unknown/absent (so severity-less rows
    keep their tool-hit order). Kill-switch SIFT_CONFIRMED_SEVERITY_SORT=0."""
    if os.environ.get("SIFT_CONFIRMED_SEVERITY_SORT", "1") == "0":
        return 0
    sev = str(f.get("severity") or f.get("confidence") or "").strip().upper()
    return _SEVERITY_RANK.get(sev, 0)


def _sort_confirmed_first(findings: Any, confirmed_fids, react_by_finding=None) -> list:
    """CONFIRMED findings at the very top, then by SEVERITY (CRITICAL>..>LOW),
    then most-tool-hits-first within each severity. A confirmed (proven-malicious)
    finding outranks ANY non-confirmed one regardless of corroboration breadth;
    within the confirmed tier the strongest evil leads (A3) so a reader/judge
    sees the most severe proven finding first. Severity-less rows fall back to
    tool-hit order. Universal: bucket membership + severity label, no case data."""
    cf = {str(x) for x in (confirmed_fids or ())}
    return sorted(
        [f for f in _as_list(findings) if isinstance(f, dict)],
        key=lambda f: (_finding_id(f) in cf, _severity_rank(f),
                       _tool_hit_count(f, react_by_finding)),
        reverse=True,
    )


# Plain-English glossary for the pipeline's OWN internal signal/fact vocabulary,
# so the customer-facing Details never leak identifiers. Universal: keyed on our
# category names (universal behavior categories), never on a case value. Listed
# longest-first so a specific token wins over a generic substring.
_DETAIL_GLOSSARY = [
    ("srum_high_volume_network_usage", "high-volume network activity recorded in SRUM"),
    ("srum_lolbin_app_usage", "a built-in Windows tool showing network activity in SRUM"),
    ("srum_staging_app_usage", "an app run from a staging folder showing network activity in SRUM"),
    ("scheduled_task_points_to_staging_path", "a scheduled task pointing to a staging folder"),
    ("registry_points_to_staging_path", "a registry entry pointing to a staging folder"),
    ("service_points_to_staging_path", "a service pointing to a staging folder"),
    ("match_executes_from_temp_path", "execution from a temporary/staging folder"),
    ("execution_from_staging_path", "execution from a temporary/staging folder"),
    ("process_from_staging_path", "a process run from a temporary/staging folder"),
    ("executes_from_temp_path", "execution from a temporary/staging folder"),
    ("admin_or_lolbin_artifact", "a built-in Windows admin tool used in a living-off-the-land way"),
    ("appcompatcache_execution_fact", "an AppCompatCache execution record"),
    ("process_relationship_fact", "a parent/child process relationship"),
    ("registry_persistence_fact", "a registry persistence entry"),
    ("filesystem_timeline_fact", "a filesystem-timeline record"),
    ("filesystem_listing_fact", "a filesystem listing"),
    ("environment_variable_fact", "an environment-variable record"),
    ("memory_injection_fact", "a memory-injection indicator"),
    ("powershell_command_fact", "a PowerShell command"),
    ("network_connection_fact", "a network connection"),
    ("scheduled_task_fact", "a scheduled task"),
    ("decoded_string_fact", "a decoded string"),
    ("file_execution_fact", "a file-execution record"),
    ("lnk_execution_fact", "a shortcut (LNK) execution record"),
    ("registry_persistence", "registry persistence"),
    ("ssdt_integrity_fact", "a kernel SSDT-integrity check"),
    ("rdp_artifact_fact", "an RDP-session artifact"),
    ("network_ioc_fact", "a network indicator"),
    ("user_account_fact", "a user-account record"),
    ("event_log_fact", "an event-log record"),
    ("srum_usage_context", "network activity recorded in SRUM"),
    ("srum_usage_fact", "network activity recorded in SRUM"),
    ("remote_access_context", "remote-access activity"),
    ("target_abs_path", "the target path"),
]

_SCORE_RE = re.compile(r"\s*\bwith\s+score\s+[\d.]+", re.IGNORECASE)
# Whole provenance-citation clauses a customer never needs. Removed BEFORE the
# glossary so the cand-/fact_id scaffolding (incl. plural "Candidates",
# "X through Y" ranges and comma lists) is consumed as a unit -- not left as
# orphan words ("Candidates through."). Leading whitespace only (never the prior
# sentence's period). Universal: structure-only, no case value.
_CAND_CITATION_RE = re.compile(
    r"\s*\bcandidates?\b(?:\s+ids?)?[:\s]*(?:cand-\d+|through|and|,|\s)*", re.IGNORECASE)
_FACT_CITATION_RE = re.compile(
    r"\s*\b(?:fact_ids?|supported by)\b[:\s]*[a-z0-9_]*_(?:fact|signal)\b\s*(?:records?|multiple)?",
    re.IGNORECASE)
_CAND_LEADIN_RE = re.compile(
    r"\bcandidate\s+cand-\d+\s+(?:indicates?|flagged|shows?|:)?\s*", re.IGNORECASE)
_CAND_REF_RE = re.compile(r"\bcandidate:?\s*cand-\d+\b\.?", re.IGNORECASE)
_CAND_BARE_RE = re.compile(r"\bcand-\d+\b", re.IGNORECASE)
# Empty / value-less candidate-id leak: "Candidate_id=.", "Candidate_id=,.",
# "candidate_id= indicates ...". Strip the whole "candidate_id=" token and any
# immediately-trailing punctuation. Universal: structure-only.
_CAND_ID_EQ_RE = re.compile(r"\bcandidate_?id\b\s*=\s*[.,;:]*", re.IGNORECASE)
# Missing space after a sentence-ending period before a continuation word
# ("paths.indicate", "(HTTPS).indicate", "network).flag", "staging.flags",
# "paths.show"). Keyed on a CLOSED set of English continuation words (the lookahead),
# so file extensions / versions / IPs / decimals (cmd.exe, v1.0, 203.0.113.20, 9.9) --
# none of which is a continuation word -- are never touched. No char-class lookbehind,
# so it also fires after ')' or a digit. Universal: linguistic, no case data.
_JOIN_WORD_RE = re.compile(
    r"\.(?=(?:indicat|document|support|reveal|show|confirm|suggest|demonstrat|"
    r"correlat|flag|these|this|multiple|evidence|activity|both|consistent)[a-z]*\b)",
    re.IGNORECASE)
# Internal zero-padded fact-index suffixes leaking into prose: "record-0000504",
# "process-0000131", "/-0002530", "connection-0000032". The LEADING ZERO after the dash
# is the discriminator -- it never matches a date (2012-04-06), port range (8081-8082),
# VAD (0x..-0x.., 456-789), version (3.0.0.638.4), or IP. Optional leading whitespace/
# slash consumes a "/-NNNN" / " -NNNN" ref but never a sentence period. The
# (?<![0-9-]) lookbehind keeps it OUT of hyphenated digit chains: an SID
# subauthority with a leading zero (S-1-5-...-0030300820-...) is DATA, not a
# fact citation, and must survive byte-identical. Universal, structural.
_FACT_ID_SUFFIX_RE = re.compile(r"(?<![0-9-])[\s/]*-0\d{5,}\b")
# D3: the RANGE/LIST citation idiom leaks the BARE second id ("fact-0000008
# through 0000011", "fact-0000005, 0000006"). Strip a zero-padded 6+ digit token
# only when joiner-led (through/and/to/comma) AND -- enforced by the caller --
# the text contained a minted fact citation, so a zero-padded registry value /
# serial in ordinary prose is never touched. A bare \b0\d{5,}\b stripper is
# forbidden here: it would eat SID/USN digit groups.
_FACT_ID_RANGE_RE = re.compile(r"(?:\b(?:through|and|to)\s+|,\s*)0\d{5,}\b(?![\d-])")
# the shapes that prove a minted fact citation was present in the ORIGINAL text
_HAD_FACT_REF_RE = re.compile(
    r"\b[a-z0-9_]+_(?:fact|signal)-0\d{5,}\b|\bfact_ids?\b", re.IGNORECASE)
# Any leftover internal token (foo_bar_fact / baz_signal / ..._usage) not in the
# glossary -- drop the suffix and de-underscore so no raw identifier survives.
_LEFTOVER_TOKEN_RE = re.compile(
    r"\b[a-z0-9]+(?:_[a-z0-9]+)*_(?:fact|signal|context|artifact|usage)\b", re.IGNORECASE)


def _sanitize_details(text: str) -> str:
    """Strip internal pipeline vocabulary (candidate IDs, raw fact/signal names,
    scores) from a customer-facing detail string and translate the known category
    names to plain English. Universal: no case literal; structure-only rewrite."""
    s = str(text or "")
    if not s.strip():
        return ""
    # D3: record BEFORE stripping whether the text carried a minted fact
    # citation -- only then may the joiner-led bare-id pass run below.
    _had_fact_ref = bool(_HAD_FACT_REF_RE.search(s))
    s = _SCORE_RE.sub("", s)
    s = _FACT_CITATION_RE.sub("", s)
    s = _CAND_CITATION_RE.sub("", s)
    s = _CAND_LEADIN_RE.sub("", s)
    s = _CAND_REF_RE.sub("", s)
    s = _CAND_BARE_RE.sub("", s)
    s = _CAND_ID_EQ_RE.sub("", s)          # empty "Candidate_id=." leak
    s = _JOIN_WORD_RE.sub(". ", s)         # "paths.indicate" -> "paths. indicate"
    s = _FACT_ID_SUFFIX_RE.sub("", s)
    if _had_fact_ref:
        s = _FACT_ID_RANGE_RE.sub(" ", s)  # "through 0000011" / ", 0000006" leak
    for key, plain in _DETAIL_GLOSSARY:
        # consume an optional trailing jargon word (signal/artifact/...) too
        s = re.sub(r"\b" + re.escape(key) + r"\b(?:\s+(?:signal|artifact|indicator|pattern|context))?",
                   plain, s, flags=re.IGNORECASE)

    def _pretty(m):
        tok = re.sub(r"_(?:fact|signal|context|artifact|usage)$", "", m.group(0), flags=re.IGNORECASE)
        return tok.replace("_", " ")

    s = _LEFTOVER_TOKEN_RE.sub(_pretty, s)
    # tidy: collapse whitespace, fix space-before-punctuation and doubled stops
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\s+([.,;:])", r"\1", s)
    s = re.sub(r"\.(?:\s*\.)+", ".", s)
    s = re.sub(r"^[\s.,;:]+", "", s).strip()
    # sentence-case only at sentence boundaries (a glossary phrase that now begins
    # a sentence after the removed candidate lead-in reads lowercase otherwise).
    s = re.sub(r"([.!?]\s+)([a-z])", lambda m: m.group(1) + m.group(2).upper(), s)
    return s


def _details_friendly(f: dict[str, Any]) -> str:
    # Junior/customer-friendly explanation: the AI's plain-English verdict reasoning,
    # else the finding description -- with internal pipeline vocabulary translated
    # to plain English so the customer never sees cand-IDs / *_fact / scores.
    _rt = (_react_text(f) or "").strip()
    _desc = str(f.get("description") or f.get("artifact") or "").strip()
    # Enrich: lead with WHAT was observed (the finding's own description) then the
    # AI's WHY (ReAct / inv3a reasoning), combined when both exist and neither already
    # contains the other -- so terse model output ("Process injection in X (PID n)")
    # still carries its adjudication rationale. Universal: the finding's own fields.
    def _cmp(s):
        return re.sub(r"\s+", " ", s.lower()).strip()
    if _rt and _desc and _cmp(_rt) != _cmp(_desc) and _cmp(_rt) not in _cmp(_desc) and _cmp(_desc) not in _cmp(_rt):
        txt = _desc + " — " + _rt
    else:
        txt = _rt or _desc
    txt = _sanitize_details(txt)
    return _clip_sentence(txt or "Evidence-backed observation.", 240)


def _colorize_benign_prefix(s: str) -> str:
    """Paint the leading 'Assessed benign:' label yellow so a reader's eye is
    drawn to WHY the pipeline cleared a scary-looking finding. Yellow only on a
    TTY (_Y is '' when writing the .md), so the markdown stays clean. Universal."""
    label = "Assessed benign:"
    if _Y and isinstance(s, str) and s.startswith(label):
        return _Y + label + _X + s[len(label):]
    return s


def _benign_explanation(f: dict[str, Any], in_benign_bucket: bool = False) -> str:
    """For a benign/false-positive finding, return a plain-English 'Assessed
    benign: ...' sentence explaining WHY -- or '' when the finding is not
    benign. Prefers the AI cross-check (ReAct) verdict text; when a finding was
    routed benign deterministically (FP-routing, weak/uncorroborated floor,
    JIT-RWX, tool-status noise) with no ReAct prose, derives the reason from the
    pipeline's own routing markers so EVERY benign row explains itself. A judge
    or customer must never see the generic malicious 'why it matters' on
    something the pipeline cleared. Universal: keyed on routing markers + reason
    grammar, no case data."""
    _rc = f.get("react_conclusion") if isinstance(f.get("react_conclusion"), dict) else {}
    _reasons = [str(r).lower() for r in (f.get("disposition_reasons") or [])]
    # Bucket membership is the renderer's own ground truth and outranks the
    # marker reconstruction below -- a benign-bucket row with no markers must
    # still explain itself, never fall through to the malicious significance.
    _is_benign = (
        in_benign_bucket
        or _rc.get("is_false_positive") is True
        or "benign" in str(_rc.get("verdict") or "").lower()
        or bool(f.get("_fp_routing_benign"))
        or bool(f.get("_jit_rwx_downgrade"))
        or bool(f.get("_tool_status_noise"))
        or str(f.get("final_disposition") or "") == "benign_or_false_positive"
        or any(r.startswith("benign:") or "fp_routing_benign" in r
               or "benign_jit_rwx" in r or "tool_status_noise" in r
               for r in _reasons)
    )
    if not _is_benign:
        return ""
    # 1) Prefer the AI cross-check's own words (richest explanation).
    _txt = str(_rc.get("text") or _rc.get("reason") or "").strip()
    _lw = _txt.lower()
    if _txt and "conclusion" not in _lw and "turn" not in _lw[:30]:
        return "Assessed benign: " + _clip_sentence(_txt, 360)
    # 2) Deterministic routing -> derive the reason from the marker.
    _blob = " ".join(_reasons) + " " + str(f.get("_fp_routing_reason") or "").lower()
    if "loopback" in _blob or "localhost" in _blob:
        return ("Assessed benign: the traffic was loopback / localhost only -- "
                "it never left this host, so it is not external communication.")
    if "entity_benign" in _blob or "benign_prop" in _blob:
        return ("Assessed benign: this refers to the same program the AI "
                "cross-check already verified as legitimate elsewhere, so the "
                "same benign conclusion applies here.")
    if "jit_rwx" in _blob or "managed" in _blob:
        return ("Assessed benign: this is a normal just-in-time / managed-"
                "runtime memory allocation (e.g. .NET, a browser), not injected "
                "code.")
    if "tool_status" in _blob:
        return ("Assessed benign: this row only reflects a tool's collection "
                "status (a timeout or empty result), not attacker activity.")
    if ("uncorroborated_weak" in _blob or "one_claim_weak" in _blob
            or "history_only" in _blob or "weak_or_history" in _blob):
        return ("Assessed benign: the only indicators were weak or purely "
                "historical, with no independent corroboration to support a "
                "malicious conclusion.")
    return ("Assessed benign: dispositioned as a false positive after the AI "
            "cross-check found no corroborating malicious evidence.")


def _details_for_display(f: dict[str, Any], in_benign_bucket: bool = False) -> str:
    """Detail text for a table/report cell: the WHAT+WHY from _details_friendly plus a
    plain-English explanation. A benign/FP finding explains WHY it is benign; every
    other finding gets a 'Why it matters' significance sentence keyed on its OS
    primitive (so a junior analyst or customer understands the significance without the
    jargon). Kept SEPARATE from _details_friendly so the title-derivation path never
    inherits the significance sentence. Universal: keyed on OS primitives + routing
    markers, no case data; appends nothing when neither is recognised."""
    base = (_details_friendly(f) or "").strip()
    try:
        from sift_sentinel.reporting.display_sanitize import clean_display_text
        base = clean_display_text(base) or base
    except Exception:
        pass
    # FALSE-POSITIVE / benign findings explain WHY they are benign -- never the
    # generic 'why this finding TYPE is dangerous', which is misleading for
    # something the pipeline concluded is NOT malicious.
    _benign = _colorize_benign_prefix(_benign_explanation(f, in_benign_bucket))
    if _benign:
        return base + "  " + _benign
    try:
        from sift_sentinel.reporting.finding_significance import plain_significance
        sig = plain_significance(f)
    except Exception:
        sig = ""
    if sig and sig.lower()[:40] not in base.lower():
        return base + "  Why it matters: " + sig
    return base


def _is_ai_self_corrected(f: dict[str, Any]) -> bool:
    """THE single definition of 'the agent revised its own conclusion', used everywhere
    (the summary count, the cyan finding-ID, and the Self-Correction Ledger) so they can
    never disagree: inv3a moved it (self_corrected), OR a ReAct cross-check flipped it to
    benign (is_false_positive / a benign verdict). Universal: structural markers only."""
    if f.get("self_corrected") is True:
        return True
    rc = f.get("react_conclusion")
    if isinstance(rc, dict):
        if rc.get("is_false_positive") is True:
            return True
        if "benign" in str(rc.get("verdict") or "").lower():
            return True
    return False


def _section_rows(buckets: dict[str, Any], bucket_names: list[str]) -> list[tuple[str, dict[str, Any]]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    for bucket in bucket_names:
        for f in _as_list(buckets.get(bucket)):
            if isinstance(f, dict):
                rows.append((bucket, f))
    return rows


def _react_tool_stats(state_dir, base_tools):
    import os, glob
    if not state_dir:
        return None
    latest = {}
    for p in glob.glob(os.path.join(str(state_dir), "inv3_*_turn*.md")):
        b = os.path.basename(p)
        try:
            fid = b.split("_")[1]
            t = int(b.split("turn")[1].split(".")[0])
        except Exception:
            continue
        if fid not in latest or t > latest[fid][0]:
            latest[fid] = (t, p)
    calls = 0
    tools = set()
    by_finding = {}
    for fid, (t, p) in latest.items():
        try:
            txt = open(p, errors="ignore").read()
        except Exception:
            continue
        ftools = set()
        for ln in txt.splitlines():
            s = ln.strip()
            if s.startswith("Turn ") and "->" in s and "records" in s and ":" in s:
                parts = s.split(":", 1)[1].split()
                if parts:
                    calls += 1
                    tools.add(parts[0])
                    ftools.add(parts[0])
        if ftools:
            by_finding[fid] = sorted(ftools)
    return {"findings": len(latest), "calls": calls,
            "distinct": len(tools), "new": sorted(tools - set(base_tools or [])),
            "by_finding": by_finding}


# Friendly one-word destination tier for the self-correction ledger.
_LEDGER_TIER = {
    "confirmed_malicious_atomic": "confirmed",
    "suspicious_needs_review": "needs-review",
    "inconclusive_unresolved": "inconclusive",
    "benign_or_false_positive": "benign",
    "synthesis_narrative": "context",
}


def _self_correction_ledger(buckets, limit: int = 14) -> str:
    """A visible 'the agent revised its own conclusions' ledger for C1: per-finding
    old→new disposition + the reason, from each finding's OWN inv3a-finalization or
    ReAct-cross-check metadata. Returns "" when nothing was self-corrected.

    Universal: keyed on structural self-correction markers (never a case value); the
    reason text is run through the same plain-English sanitizer as the Details."""
    rows: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for _items in (buckets or {}).values():
        for f in _as_list(_items):
            if not isinstance(f, dict):
                continue
            fid = _finding_id(f)
            if fid in seen or fid == "-":
                continue
            if not _is_ai_self_corrected(f):       # same gate as the count + the cyan ID
                continue
            sc = f.get("self_correction")
            rc = f.get("react_conclusion")
            if f.get("self_corrected") is True and isinstance(sc, dict):
                src = _LEDGER_TIER.get(f.get("_ai_finalize_from") or "", "flagged")
                dst = _LEDGER_TIER.get(f.get("_ai_finalize_to") or "", "reviewed")
                reason = _sanitize_details(str(sc.get("reason") or ""))
                rows.append((fid, src, dst, reason or "AI finalization"))
            else:
                reason = _sanitize_details(_react_text(f) or str((rc or {}).get("reasoning") or ""))
                rows.append((fid, "flagged", "benign", reason or "ReAct cross-check cleared it"))
            seen.add(fid)
    if not rows:
        return ""
    out = ["", "%sSELF-CORRECTION LEDGER%s  (how the agent revised its own conclusions)" % (_B, _X)]
    for fid, src, dst, reason in rows[:limit]:
        out.append("  %s%s%s  %s → %s%s%s   %s" % (
            _C, fid, _X, src, _B, dst, _X, _txt(reason, 92)))
    extra = len(rows) - limit
    if extra > 0:
        out.append("  %s… +%d more revisions in inv3a_finalize_ledger.json%s" % (_D, extra, _X))
    return "\n".join(out)


def render_findings_terminal(buckets, width=None, summary=None, image_path=None,
                             disk_path=None, disk_mount=None, state_dir=None,
                             sample=None):  # SIFT_TERMINAL_TABLE_V6
    """Investigation Summary box + closed-row tables (FINDINGS / AI
    SELF-CORRECTION / BENIGN-FP). Details carries a per-row trail tag derived
    from the real disposition_reasons. All values from real run data; pure
    stdlib, no ANSI."""
    import os as _os
    import json as _json
    import shutil as _shutil
    import textwrap as _textwrap
    if not isinstance(buckets, dict):
        return ""
    _envw = _os.environ.get("SIFT_TABLE_WIDTH", "").strip()
    if width is None and _envw.isdigit():
        width = int(_envw)
    if width is None:
        try:
            width = _shutil.get_terminal_size((140, 24)).columns
        except Exception:
            width = 140
    W = max(100, min(int(width or 140), 220))
    avail = (W - 19) - 2 - 5
    w_find = max(14, int(avail * 0.16))
    w_ioc = max(18, int(avail * 0.22))
    w_tools = max(16, int(avail * 0.18))
    w_det = avail - w_find - w_ioc - w_tools
    widths = [2, 7, w_find, w_ioc, w_tools, w_det]  # ID col: +2 for "● " glyph

    def _wrap(text, w):
        # Visible-width word wrap: packs whitespace-separated words by VISIBLE
        # length (ANSI color codes don't count and are never split, because each
        # colored token is a self-contained word). Long plain words are hard-broken
        # like textwrap. Keeps every colored cell box-aligned.
        w = max(6, w)
        s = str(text)
        if _vlen(s) <= w:
            return [s]
        out = []
        for para in (s.splitlines() or [""]):
            if _vlen(para) <= w:
                out.append(para)
                continue
            line = ""
            for word in para.split(" "):
                if word == "":
                    continue
                cand = word if not line else line + " " + word
                if _vlen(cand) <= w:
                    line = cand
                    continue
                if line:
                    out.append(line)
                # a single word wider than w: hard-break only if it carries no
                # color codes (tool/plain tokens); colored tokens are short.
                while _vlen(word) > w and not _ANSI_RE.search(word):
                    out.append(word[:w])
                    word = word[w:]
                line = word
            if line:
                out.append(line)
        return out or [""]

    def _rule(kind):
        l, m, r = {"t": ("\u250c", "\u252c", "\u2510"),
                   "m": ("\u251c", "\u253c", "\u2524"),
                   "b": ("\u2514", "\u2534", "\u2518")}[kind]
        return l + m.join("\u2500" * (w + 2) for w in widths) + r

    def _row(cells):
        col_lines = [_wrap(c, w) for c, w in zip(cells, widths)]
        h = max(len(x) for x in col_lines)
        out = []
        for i in range(h):
            segs = []
            for lns, w in zip(col_lines, widths):
                seg = lns[i] if i < len(lns) else ""
                segs.append(" " + _vljust(seg, w) + " ")
            out.append("\u2502" + "\u2502".join(segs) + "\u2502")
        return out

    def _table(rows):
        out = [_rule("t")]
        out += _row(["#", "ID", "Finding", "IOCs / Artifacts", "Tools Hit", "Details"])
        out.append(_rule("m"))
        if not rows:
            out += _row(["-", "-", "(none)", "-", "-", "-"])
            out.append(_rule("b"))
            return out
        for idx, r in enumerate(rows):
            out += _row(r)
            out.append(_rule("b") if idx == len(rows) - 1 else _rule("m"))
        return out

    _pretty = {
        "pid_or_process_existence_only": "PID/process existence only",
        "missing_raw_excerpt": "missing raw evidence",
        "confidence_speculative": "speculative confidence",
        "process_ancestry_violation": "weak ancestry signal",
        "null_or_empty_cmdline_on_executable": "null/empty cmdline",
        "no_validator_metadata": "no validator backing",
    }

    def _reason_pretty(tok):
        first = tok.split(",")[0].split(":")[-1].strip()
        return _pretty.get(first, first.replace("_", " "))

    def _trail(f):
        rs = [str(x) for x in (f.get("disposition_reasons") or [])]
        blob = " ".join(rs).lower()
        rc = f.get("react_conclusion") or {}
        rv = str(rc.get("verdict") or "").lower()
        if f.get("self_corrected") is True:
            return "Repaired: claims corrected & re-validated"
        if "benign" in rv or "override:benign_or_fp" in blob:
            return "AI self-corrected -> false positive"
        if "malicious" in rv:
            return "AI confirmed malicious"
        if "confirmed:all_gates_cleared" in blob:
            return "Confirmed -- all gates cleared"
        for r in rs:
            if r.startswith("gate:confirmed_ineligible["):
                return "Held for review -- " + _reason_pretty(r[len("gate:confirmed_ineligible["):].rstrip("]"))
        if "one_claim_unsupported" in blob:
            return "Blocked -- single unsupported claim"
        if "gate:validation_blocked" in blob:
            return "Blocked -- validation failed"
        if "override:inconclusive" in blob:
            return "Held -- inconclusive"
        if "synthesis[" in blob:
            return "Synthesized from related findings"
        return ""

    def _cells(f, n, in_benign=False):
        body = (_details_for_display(f, in_benign_bucket=in_benign) or "").strip() or _txt(f.get("description") or "", 240)
        det = body or "-"
        _when = _event_when(f)
        _who = _event_who(f)
        # Lead the Details with WHO did it + WHEN it happened -- both structural,
        # blank when not present; never fabricated. (When-only output is unchanged.)
        # When no human actor is derivable but the finding's process ran under a
        # built-in service identity, say so honestly ("SYSTEM/service context")
        # rather than leaving WHO blank -- set upstream by logon_actor. Universal.
        _ctx = str(f.get("execution_context") or "").strip()
        _lead = []
        # WHO-FIRST: every row leads with an account/identity. A derived user
        # first; else the honest service identity; else an explicit "not
        # attributed" for disk/host artifacts that have no live process owner --
        # never a silent blank. Kill-switch SIFT_WHO_FIRST_ALWAYS=0. Universal.
        if _who:
            _lead.append("Who: %s" % _who)
        elif _ctx:
            _lead.append("Who: %s" % _ctx)
        elif os.environ.get("SIFT_WHO_FIRST_ALWAYS", "1") != "0":
            _lead.append("Who: not attributed (disk/host artifact)")
        if _when:
            _lead.append("When: %s UTC" % _when)
        if _lead:
            det = " · ".join(_lead) + " -- " + det
        # (The disposition tier is NOT shown as a tag -- it orders the rows
        # instead; see the FINDINGS table sort below.)
        _base = _tools(f)
        _rt = _react_bf.get(_finding_id(f)) or []
        _seen = set(t.strip() for t in _base.split(",")) if (_base and _base != "-") else set()
        _extra = [t for t in _rt if t not in _seen]
        _toolcell = _base if (_base and _base != "-") else ""
        if _extra:
            # ReAct AI-Cross-Check corroborators -- colored green; each token is a
            # self-contained colored word so the visible-width wrap never splits a
            # color code mid-cell.
            _pre = (_G + "+ReAct:" + _X) if _toolcell else (_G + "ReAct:" + _X)
            _rxt = ", ".join(_G + _B + t + _X for t in _extra)
            _toolcell = (_toolcell + "  " + _pre + " " + _rxt) if _toolcell else (_pre + " " + _rxt)
        _fid = _finding_id(f) or "F?"
        _rc = f.get("react_conclusion")
        if _is_ai_self_corrected(f):
            _fid = _C + _B + _fid + _X            # AI self-corrected (inv3a or ReAct-to-benign) -> cyan
        elif isinstance(_rc, dict) and (_rc.get("verdict") or _rc.get("is_false_positive") is not None):
            _fid = _G + _B + _fid + _X            # ReAct-judged (non-benign) -> green
        # Finding label: when no descriptive title exists it would echo the ID
        # (e.g. "F010 | F010"); show a clear human label instead. Universal.
        _ttl = _title(f)
        if not _ttl or _ttl == _finding_id(f):
            # Derive a human label from the finding's OWN descriptive detail (first
            # clause) instead of an opaque '(untitled finding)'. This applies even when
            # the finding is self-corrected: the cyan ID + the Self-Correction Ledger
            # already convey the correction, so the TITLE must keep the real finding
            # name. Never stamp a blanket "AI self-corrected -> false positive" here --
            # that overwrote the real name AND mislabelled findings that were corrected
            # INTO needs-review (still suspicious), not into a false positive. Strip a
            # leading 'When: … -- ' and take the first clause. Universal: the finding's
            # own text, truncated; no case data.
            _df = re.split(r"\s+--\s+", (_details_friendly(f) or "").strip(), 1)[-1]
            _df = re.split(r"(?<=[a-z])[.;]\s", _df, 1)[0].strip()
            _ttl = _txt(_df, 72) or "(untitled finding)"
        # inv3a (Step 13AA) self-correction is signalled by the cyan finding-ID only
        # (set above). No inline "[AI-Self-Corrected -> tier]" badge: the pass moves
        # most ambiguous findings to needs-review, so a per-row badge was noise on
        # ~every row and its wrapping broke the table borders. Full per-finding moves
        # are in inv3a_finalize_ledger.json.
        # Lead the ID with a one-column severity bullet colored by the finding's
        # disposition tier (red/amber/green/grey) -- severity at a glance, border-safe.
        _glyph = _severity_glyph(_tier_by_fid.get(_finding_id(f), ""))
        return [str(n), _glyph + " " + _fid, _ttl,
                _ioc_bits(f) or "-", _toolcell or "-", det]

    real_keys = ["confirmed_malicious_atomic", "suspicious_needs_review",
                 "inconclusive_unresolved", "synthesis_narrative"]

    def _is_react_fp(f):
        rc = f.get("react_conclusion")
        if isinstance(rc, dict):
            if rc.get("is_false_positive") is True:
                return True
            v = str(rc.get("verdict") or "").lower()
            if "benign" in v and "ai" in str(rc.get("verdict_source") or "").lower():
                return True
        return False

    _all_rows = [f for _b, _it in buckets.items()
                 if isinstance(_it, list) for f in _it if isinstance(f, dict)]
    # self_corr (NARROW: inv3a-moved) drives the findings/FP table PARTITION. The
    # "AI self-corrected" headline count is a separate ANNOTATION (_n_self_corrected
    # below) that uses the same broad predicate as the ledger + the cyan ID, so the
    # count can never disagree with what the ledger lists -- without disturbing the
    # findings+FPs=total partition.
    self_corr = [f for f in _all_rows if f.get("self_corrected") is True]
    _n_self_corrected = sum(1 for f in _all_rows if _is_ai_self_corrected(f))
    _sc_fids = {_finding_id(f) for f in self_corr}
    real = []
    for k in real_keys:
        real += [f for f in _as_list(buckets.get(k))
                 if isinstance(f, dict) and _finding_id(f) not in _sc_fids]
    benign_all = [f for f in _as_list(buckets.get("benign_or_false_positive")) if isinstance(f, dict)]
    react_fp = [f for f in benign_all if _is_react_fp(f) and _finding_id(f) not in _sc_fids]
    plain = [f for f in benign_all if not _is_react_fp(f) and _finding_id(f) not in _sc_fids]

    # A self-corrected finding whose disposition is BENIGN (the AI corrected it to a
    # false positive) belongs with the FPs, not in FINDINGS. Split self_corr by
    # disposition here -- BEFORE the summary banner -- so the banner's findings/FP counts
    # match what the tables render (else a self-corrected-benign finding is counted as a
    # 'finding' in the banner but shown under FPs in the table: banner 7/13 vs table
    # 6/14). Universal: keyed on the benign bucket / final_disposition, no case data.
    _benign_fids = {_finding_id(f) for f in benign_all}
    _sc_benign = [f for f in self_corr
                  if _finding_id(f) in _benign_fids
                  or str(f.get("final_disposition") or "").strip().lower() == "benign_or_false_positive"
                  or _is_react_fp(f)]
    _sc_keep = [f for f in self_corr if f not in _sc_benign]

    _react_bf = ((_react_tool_stats(state_dir, (summary or {}).get("tools_run") or []) or {}).get("by_finding") or {})

    # (c) Order the FINDINGS section CONFIRMED-first, then most-tool-hits-first,
    # so proven-malicious findings lead the table (a confirmed finding with few
    # tools still outranks a many-tool needs-review/context one). FP/SC sections
    # have no confirmed members, so plain tool-hit order is fine there.
    _confirmed_fids = {_finding_id(f)
                       for f in _as_list(buckets.get("confirmed_malicious_atomic"))
                       if isinstance(f, dict)}
    real = _sort_confirmed_first(real, _confirmed_fids, _react_bf)
    self_corr = _sort_by_tool_hits(self_corr, _react_bf)

    # SC-blocked / unresolved findings are shown at the BOTTOM of the FINDINGS
    # table (never discarded, never parked in a separate UNRESOLVED row).
    # Universal: keyed on the held_out marker in summary, no case data.
    _seen_fids = {_finding_id(f) for f in real} | {_finding_id(f) for f in self_corr}
    _holdout = _sort_by_tool_hits(
        [f for f in _as_list((summary or {}).get("sc_unresolved_holdout"))
         if isinstance(f, dict) and _finding_id(f) not in _seen_fids], _react_bf)

    # Per-finding disposition TIER (from the bucket it landed in) so confirmed vs
    # downgraded-needs-review vs inconclusive is visible in the one FINDINGS table.
    _tier_by_fid = {}
    for _bk, _items in buckets.items():
        _lbl = _TIER_LABEL.get(_bk)
        if not _lbl:
            continue
        for _f in _as_list(_items):
            if isinstance(_f, dict):
                _tier_by_fid.setdefault(_finding_id(_f), _lbl)
    for _f in self_corr:
        _tier_by_fid[_finding_id(_f)] = "SELF-CORRECTED"
    for _f in _holdout:
        _tier_by_fid.setdefault(_finding_id(_f), "UNRESOLVED")
    _tier_color = {
        "CONFIRMED": _R + _B, "NEEDS-REVIEW": _Y + _B, "INCONCLUSIVE": _D,
        "CONTEXT": _D, "BENIGN": _G, "SELF-CORRECTED": _C, "UNRESOLVED": _D,
    }

    lines = []
    sm = summary if isinstance(summary, dict) else None
    if sm is not None:
        def _hms(v):
            try:
                v = int(round(float(v or 0)))
            except Exception:
                v = 0
            mm, ss = divmod(v, 60)
            hh, mm = divmod(mm, 60)
            return ("%dh %dm %ds" % (hh, mm, ss)) if hh else ("%dm %ds" % (mm, ss))

        if not sample:
            # The sample's COMMON NAME (shared stem of the memory + disk file names) plus
            # each artefact's size -- never the parent bucket folder. Universal helper.
            from sift_sentinel.reporting.sample_label import sample_label as _sample_label
            sample = _sample_label(summary, image_path, disk_path, disk_mount)
        sample = sample or "unknown"

        model = "unknown"
        try:
            if state_dir:
                d = _json.load(open(_os.path.join(str(state_dir), "inv2_ensemble_stats.json")))
                mem = d.get("members") or []
                models = [m.get("model") for m in mem if isinstance(m, dict) and m.get("model")]
                cnt = d.get("completed_member_count") or d.get("requested_member_count") or len(models)
                if models:
                    uniq = sorted(set(models))
                    base = uniq[0] if len(uniq) == 1 else " + ".join(uniq)
                    model = ("%s  (%d-member ensemble)" % (base, cnt)) if cnt else base
        except Exception:
            model = "unknown"
        if model == "unknown":
            env = _os.environ.get("SIFT_ENSEMBLE_MODELS", "").strip()
            if env:
                parts = [x.strip() for x in env.split(",") if x.strip()]
                uniq = sorted(set(parts))
                base = uniq[0] if len(uniq) == 1 else " + ".join(uniq)
                model = "%s  (%d-member ensemble)" % (base, len(parts))
            elif _os.environ.get("SIFT_FORCE_MODEL", "").strip():
                model = _os.environ["SIFT_FORCE_MODEL"].strip()

        trc = sm.get("tool_record_counts") or {}
        n_hit = sum(1 for v in trc.values() if isinstance(v, (int, float)) and v > 0)
        n_exec = sm.get("tools_count") or (len(trc) if trc else 0)
        th = sm.get("tool_health") or {}
        n_failed = th.get("failed", 0) or 0
        _had = {t for t, v in trc.items() if isinstance(v, (int, float)) and v > 0}
        _ref = set()
        for _f in (real + self_corr + _holdout + react_fp + plain):
            if not isinstance(_f, dict):
                continue
            for _k in ("source_tools", "claim_tools"):
                _ref |= {x for x in (_f.get(_k) or []) if isinstance(x, str)}
            for _c in (_f.get("claims") or []):
                if isinstance(_c, dict):
                    _ref |= {x for x in (_c.get("source_tools") or []) if isinstance(x, str)}
                    for _kk in ("source_tool", "tool", "claim_tool"):
                        _v = _c.get(_kk)
                        if isinstance(_v, str) and _v:
                            _ref.add(_v)
        n_data_only = len(_had - _ref)
        _react = _react_tool_stats(state_dir, sm.get("tools_run") or [])
        tu = sm.get("token_usage") or {}
        tin = int(tu.get("total_input", 0) or 0)
        tout = int(tu.get("total_output", 0) or 0)
        tcr = int(tu.get("total_cache_read", 0) or 0)
        tcc = int(tu.get("total_cache_creation", 0) or 0)
        # Rate defaults are MODEL-AWARE (the run was billed at the chosen model's
        # rate, not Haiku's). Opus 4.8 ~ $15/$75, Sonnet ~ $3/$15, Haiku ~ $1/$5 per
        # MTok. Still env-overridable (SIFT_PRICE_*) to pin exact billing. The figure
        # is an UNCACHED estimate -- prompt caching (a 4-member ensemble reuses one
        # cached prompt) makes the real billed cost lower.
        # Rate label is MODEL-AWARE via pricing.resolve_rates (Qwen, Opus,
        # Sonnet, Haiku, ...) so the printed rate always matches the cost figure
        # -- not a hardcoded Haiku fallback that mislabeled every Qwen run.
        try:
            from sift_sentinel.pricing import resolve_rates as _rr
            _ri, _ro = _rr(model)
            _d_in, _d_out = ("%g" % _ri), ("%g" % _ro)
        except Exception:
            _d_in, _d_out = "1.0", "5.0"
        p_in = _os.environ.get("SIFT_PRICE_INPUT_PER_MTOK", _d_in)
        p_out = _os.environ.get("SIFT_PRICE_OUTPUT_PER_MTOK", _d_out)
        # Cache-aware: when prompt caching was active (a 4-member ensemble re-reads one
        # cached prompt, billed ~10% of base), show the uncached figure AND the real
        # with-caching figure in brackets. Falls back to '~$X' when no cache was used.
        try:
            from sift_sentinel.pricing import format_cost as _fmt_cost
            _cost_str = _fmt_cost(model, uncached_input=tin, output=tout,
                                  cache_read=tcr, cache_creation=tcc)
        except Exception:
            try:
                _cost_str = "~$%.2f" % (tin / 1e6 * float(p_in) + tout / 1e6 * float(p_out))
            except Exception:
                _cost_str = "~$0.00"
        n_real, n_sc, n_fp, n_plain, n_held = (
            len(real), len(self_corr), len(react_fp), len(plain), len(_holdout))
        # Banner findings/FP split must match the TABLES: a self-corrected-benign finding
        # is rendered under FPs, so count it there (not as a 'finding'). total unchanged.
        n_sc_keep, n_sc_benign = len(_sc_keep), len(_sc_benign)
        total = n_real + n_sc + n_held + n_fp + n_plain
        status = str(sm.get("status", "") or "?")

        def _bar(kind):
            l, m, r = {"t": ("\u2554", "\u2550", "\u2557"),
                       "m": ("\u2560", "\u2550", "\u2563"),
                       "b": ("\u255a", "\u2550", "\u255d")}[kind]
            return l + m * (W - 2) + r

        def _bln(text):
            return "\u2551 " + str(text)[:W - 4].ljust(W - 4) + " \u2551"

        def _bln_c(text):
            # Colored box row: pad by VISIBLE length so the ANSI codes do not
            # count toward the width and the box stays aligned.
            s = str(text)[:W - 4]
            return "\u2551 " + _M + _B + s + _X + " " * (W - 4 - len(s)) + " \u2551"

        def _lv(label, value):
            return _bln("%-11s %s" % (label, value))

        def _lv_v(label, value):
            # box row padded by VISIBLE length so embedded ANSI color codes (the
            # legend dots) do not shift the box border.
            body = "%-11s %s" % (label, value)
            pad = max(0, (W - 4) - _vlen(body))
            return "\u2551 " + body + (" " * pad) + " \u2551"

        # Legend for the per-row severity dot (\u25cf) in the FINDINGS table below: the dot
        # is coloured by the finding's disposition tier. Keyed on the tier, no case data.
        _dot = "\u25cf"
        _legend = (
            _R + _dot + _X + " confirmed   "
            + _Y + _dot + _X + " needs-review   "
            + _G + _dot + _X + " ReAct AI-Cross-Check   "
            + _C + _dot + _X + " AI self-corrected"
        )

        lines += [_bar("t"),
                  _bln_c("SIFT-SENTINEL  \u00b7  Fully Autonomous Agentic-AI DFIR Platform"),
                  _bar("m"),
                  _lv("Sample", sample),
                  _lv("Runtime", "%s     Status: %s" % (_hms(sm.get("elapsed_s", 0)), status)),
                  _lv_v("Findings", "%d total  \u00b7  %d findings  \u00b7  %d AI-detected FPs  \u00b7  %s(%d AI self-corrected)%s"
                      % (total, n_real + n_sc_keep + n_held, n_fp + n_plain + n_sc_benign, _C, _n_self_corrected, _X)),
                  _lv("Tools", "%d swept  \u00b7  %d hit  \u00b7  %d failed  \u00b7  %d data-only"
                      % (n_exec, n_hit, n_failed, n_data_only)),
                  _lv("ReAct(Ai)", ("%d probes  \u00b7  %d tools (%d beyond sweep)  \u00b7  %d findings"
                                % (_react["calls"], _react["distinct"], len(_react["new"]), _react["findings"]))
                      if _react else "n/a"),
                  _lv("Model", model),
                  _lv("Tokens", ("{:,} uncached + {:,} cached in / {:,} out".format(tin, tcr + tcc, tout)
                                 if (tcr + tcc) else "{:,} in / {:,} out".format(tin, tout))),
                  _lv("Est. cost", "%s   (@ $%.2f / $%.2f per MTok)" % (_cost_str, float(p_in), float(p_out))),
                  _bar("m"),
                  _lv_v("Legend", _legend),
                  _bar("b")]

    # _sc_benign / _sc_keep were computed above (before the banner) so the banner counts
    # and these tables share one partition. _sc_benign -> FP section, _sc_keep -> FINDINGS.

    # ONE main FINDINGS table, ordered CONFIRMED-first then by descending tool-hit
    # count (most-corroborated at the top). The disposition tier orders the rows
    # but is NOT shown as a tag. Universal: confirmed flag + tool-hit count only.
    # CONFIRMED-first by actual confirmed-bucket membership, NOT _tier_by_fid:
    # inv3a-PROMOTED confirmations are also self_corrected, and the tier map
    # overrides their label to SELF-CORRECTED (line ~960) -- so keying on the
    # tier dropped every inv3a-promoted confirmed finding out of the top rows.
    _findings_rows = sorted(
        list(real) + list(_sc_keep) + list(_holdout),
        key=lambda _f: (
            0 if _finding_id(_f) in _confirmed_fids else 1,
            -_tool_hit_count(_f, _react_bf),
        ),
    )
    lines += ["", "FINDINGS  (%d)" % len(_findings_rows)]
    lines += _table([_cells(f, 1 + i) for i, f in enumerate(_findings_rows)])
    n = 1 + len(_findings_rows)
    # The single remaining table: ReAct-cross-checked FPs + benign + self-corrected-to-FP.
    fp_rows = _sort_by_tool_hits(react_fp + plain + _sc_benign, _react_bf)
    lines += ["", "AI-DETECTED FP/Benign (ReAct AI-Cross-Check)  (%d)" % len(fp_rows)]
    lines += _table([_cells(f, n + i, in_benign=True) for i, f in enumerate(fp_rows)])
    n += len(fp_rows)
    # SELF-CORRECTION LEDGER intentionally NOT appended after the table (operator
    # request): the self-correction signal is already shown by the cyan finding IDs
    # + the "(N AI self-corrected)" banner count + the per-finding details.
    return "\n".join(lines)


def build_bucket_faithful_customer_findings_table(
    buckets: dict[str, Any],
    *_args: Any,
    **_kwargs: Any,
) -> str:
    buckets = buckets if isinstance(buckets, dict) else {}

    counts = {
        key: len(_as_list(buckets.get(key)))
        for key in [
            "confirmed_malicious_atomic",
            "suspicious_needs_review",
            "inconclusive_unresolved",
            "benign_or_false_positive",
            "synthesis_narrative",
        ]
    }

    _benign_all = [f for f in _as_list(buckets.get("benign_or_false_positive")) if isinstance(f, dict)]
    _ai_sc = [f for f in _benign_all if _is_ai_self_corrected(f)]
    _plain_benign = [f for f in _benign_all if not _is_ai_self_corrected(f)]
    _n_findings = counts['confirmed_malicious_atomic'] + counts['suspicious_needs_review'] + counts['inconclusive_unresolved']
    lines: list[str] = [
        "SIFT Sentinel Customer Findings",
        "",
        "Customer view: findings first, the false positives the AI caught next, other benign / false-positive last.",
        f"Findings (confirmed + suspicious + inconclusive): {_n_findings}  (confirmed malicious: {counts['confirmed_malicious_atomic']})",
        f"AI self-correction — false positives the AI caught: {len(_ai_sc)}",
        f"Benign / false positive: {len(_plain_benign)}",
        "",
    ]

    _findings = [f for f in (
        _as_list(buckets.get("confirmed_malicious_atomic"))
        + _as_list(buckets.get("suspicious_needs_review"))
        + _as_list(buckets.get("inconclusive_unresolved"))
    ) if isinstance(f, dict)]
    n = 1
    for section, rows, _sec_benign in [
        ("Findings", _findings, False),
        # AI Self-Correction + Benign sections are both drawn from the benign
        # bucket (_benign_all) -- their rows must explain WHY they are benign.
        ("AI Self-Correction", _ai_sc, True),
        ("Benign / False Positive", _plain_benign, True),
    ]:  # SIFT_SECTIONS_V2
        if not rows:
            continue
        lines.append(f"## {section}")
        lines.append("| # | ID | Finding | IOCs / Artifacts | Tools Hit | Details |")
        lines.append("|---:|---|---|---|---|---|")
        for f in rows:
            lines.append(
                f"| {n} | {_txt(_finding_id(f), 24)} | {_title(f)} | "
                f"{_ioc_bits(f)} | {_tools(f)} | "
                f"{_details_for_display(f, in_benign_bucket=_sec_benign)} |"
            )
            n += 1
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _data_no_finding_footer(state: Path, buckets: dict[str, Any]) -> str:
    """data_no_finding_footer_v1: transparency line listing tools that produced
    data but drove no finding. Dataset-agnostic -- contributing tools are the
    union of source_tools across this run's own buckets; producing tools come
    from the run's tool_outputs/ envelopes (record_count > 0). No hardcoded
    list; adapts to whatever ran on the sample."""
    contributing = set()
    for _arr in (buckets or {}).values():
        if not isinstance(_arr, list):
            continue
        for f in _arr:
            if not isinstance(f, dict):
                continue
            for k in ("source_tools", "tools", "tool_hits", "producer_tools"):
                v = f.get(k)
                if isinstance(v, list):
                    contributing |= {str(x) for x in v if x}
            for c in (f.get("claims") or []):
                if isinstance(c, dict) and isinstance(c.get("source_tools"), list):
                    contributing |= {str(x) for x in c["source_tools"] if x}
    producing = {}
    try:
        _envs = list((state / "tool_outputs").glob("*.json"))
    except Exception:
        _envs = []
    for p in _envs:
        try:
            e = json.loads(p.read_text(errors="replace"))
        except Exception:
            continue
        if not isinstance(e, dict):
            continue
        rc = e.get("record_count")
        if isinstance(rc, int) and rc > 0:
            producing[str(e.get("tool") or p.stem)] = rc
    non_contrib = sorted(set(producing) - contributing)
    if not non_contrib:
        return ""
    listed = ", ".join("%s (%d records)" % (t, producing[t]) for t in non_contrib)
    return (
        "\n## Data Reviewed - No Finding\n"
        "%d tool(s) produced data that was examined and yielded no malicious "
        "finding (shown for completeness): %s\n"
        % (len(non_contrib), listed)
    )


def write_bucket_faithful_customer_findings_table(state_dir: str | Path) -> Path:
    state = Path(state_dir)
    buckets = _load_json(state / "finding_disposition_buckets.json")
    text = build_bucket_faithful_customer_findings_table(buckets if isinstance(buckets, dict) else {})
    text = text.rstrip() + _data_no_finding_footer(state, buckets if isinstance(buckets, dict) else {})
    out = state / "customer_findings_table.md"
    out.write_text(text)
    try:
        from sift_sentinel.analysis.investigation_answers import resolve, render
        import json as _ia_json
        _ia_db = _load_json(state / "evidence_db.json")
        _ia = resolve(_ia_db if isinstance(_ia_db, dict) else {},
                      buckets if isinstance(buckets, dict) else {})
        (state / "investigation_answers.md").write_text(render(_ia))
        (state / "investigation_answers.json").write_text(
            _ia_json.dumps(_ia, indent=2))
        # SIFT_PROMOTE_ANSWERS_INTO_TABLE_V1 -- lead the customer table with the
        # rendered investigation answers (WHO/WHAT/WHERE/HOW/WHEN); findings +
        # benign tables follow as supporting evidence. render(_ia) is fully
        # evidence-derived, so this stays dataset-agnostic.
        out.write_text(render(_ia) + "\n\n" + text)
    except Exception:
        pass
    return out


# SIFT_CUSTOMER_TABLE_BUCKET_FAITHFUL_EXPORT_COMPAT_V1E2
# Stable public names kept for existing tests/scripts while the explicit
# bucket-faithful implementation remains the canonical Step16/fresh-run writer.

def build_customer_findings_table(buckets, *args, **kwargs):
    """Compatibility alias for the bucket-faithful table builder."""
    return build_bucket_faithful_customer_findings_table(buckets, *args, **kwargs)


def _sift_write_bucket_table_text_v1e2(text, output_path):
    from pathlib import Path

    out = Path(output_path)
    if out.exists() and out.is_dir():
        out = out / "customer_findings_table.md"
    elif str(output_path).endswith(("/", "\\")):
        out.mkdir(parents=True, exist_ok=True)
        out = out / "customer_findings_table.md"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    return out


def write_customer_findings_table(target, output_path=None, buckets=None, *args, **kwargs):
    """Compatibility writer.

    Supported calling forms:
    - write_customer_findings_table(state_dir)
    - write_customer_findings_table(bucket_dict)
    - write_customer_findings_table(bucket_dict, output_path)
    - write_customer_findings_table(state_dir, bucket_dict)
    - write_customer_findings_table(state_dir_or_bucket_json, output_path)
    """

    from pathlib import Path

    if isinstance(target, dict):
        text = build_bucket_faithful_customer_findings_table(target, *args, **kwargs)
        if output_path is None:
            return text
        return _sift_write_bucket_table_text_v1e2(text, output_path)

    t = Path(target)

    if isinstance(output_path, dict):
        out = t / "customer_findings_table.md" if t.suffix.lower() != ".md" else t
        text = build_bucket_faithful_customer_findings_table(output_path, *args, **kwargs)
        return _sift_write_bucket_table_text_v1e2(text, out)

    if isinstance(buckets, dict):
        out = output_path
        if out is None:
            out = t / "customer_findings_table.md" if t.suffix.lower() != ".md" else t
        text = build_bucket_faithful_customer_findings_table(buckets, *args, **kwargs)
        return _sift_write_bucket_table_text_v1e2(text, out)

    if output_path is not None:
        data = _load_json(t / "finding_disposition_buckets.json") if t.is_dir() else _load_json(t)
        text = build_bucket_faithful_customer_findings_table(data if isinstance(data, dict) else {}, *args, **kwargs)
        return _sift_write_bucket_table_text_v1e2(text, output_path)

    if t.is_dir():
        return write_bucket_faithful_customer_findings_table(t)

    data = _load_json(t)
    return build_bucket_faithful_customer_findings_table(data if isinstance(data, dict) else {}, *args, **kwargs)


__all__ = [
    "build_bucket_faithful_customer_findings_table",
    "write_bucket_faithful_customer_findings_table",
    "build_customer_findings_table",
    "write_customer_findings_table",
]

