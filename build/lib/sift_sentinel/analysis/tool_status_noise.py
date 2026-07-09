"""Tool-status-noise suppressor (DOWNGRADE-ONLY) -- universal, conservative.

Some Inv2 findings merely narrate a forensic tool's own execution status -- "X
timed out", "Y returned empty" -- which is collection metadata (already surfaced
in TOOL HEALTH), not a forensic finding. A prior live run emitted 6 such
non-findings (four vol_hollowprocesses-timeout, two amcache-empty) that cluttered
the table and burned self-correction cycles.

``match_tool_status_noise`` fires ONLY when BOTH hold:
  * a tool-status SHAPE is present: a forensic-tool-name token (vol_/get_/parse_/
    run_/extract_/sleuthkit_ prefix) OR a ``<word>_timeout`` / ``<word>_empty``
    token, combined with an OS-agnostic status word (timeout / timed out / empty /
    failure / failed / no records / not available / plugin), AND
  * NO real evidence: no file path with an artifact extension, no hash, no real
    pid (>0), no named behavioral signal.

Universal / dataset-agnostic: tool-name SHAPE + generic status vocabulary; no
case path, process, or IOC literal. Downgrade-only: a match routes the finding to
benign (never deleted), so a mis-fire still leaves the finding visible.
"""
from __future__ import annotations

import re

# Forensic-tool-name shape (the collector families), not a specific tool list's
# semantics -- any vol_/get_/parse_/run_/extract_/sleuthkit_ token.
_TOOL_NAME_RE = re.compile(
    r"\b(?:vol|get|parse|run|extract|sleuthkit)_[a-z0-9_]+\b", re.IGNORECASE)

# A status token fused onto an identifier with an underscore (e.g.
# vol_hollowprocesses_timeout, amcache_empty). Underscores aren't word
# boundaries, so match the `_timeout` / `_empty` suffix directly.
_STATUS_COMPOUND_RE = re.compile(r"_(?:timeout|empty)\b", re.IGNORECASE)

# A data-source-absence phrase (the 'returned nothing' shape) that fires on its
# own -- no tool-name token required.
_ABSENCE_RE = re.compile(
    r"(?:empty database|empty amcache|registry\s*-\s*empty|"
    r"returned (?:no|empty|zero)|no execution records|\bno records\b|"
    r"\b(?:0|zero) entries\b)", re.IGNORECASE)

# OS-agnostic execution-status vocabulary.
_STATUS_RE = re.compile(
    r"\b(?:timeout|timed out|tool failure|tool_failure|failed|empty database|"
    r"empty|no records|returned no|not available|plugin|did not run|"
    r"no execution records|registry - empty)\b", re.IGNORECASE)

# Real-evidence guards -- if ANY present, it is a real finding, never suppress.
_PATH_EXT_RE = re.compile(
    r"[\\/][\w.\- ]+\.(?:exe|dll|sys|tmp|ps1|bat|cmd|vbs|js|scr|dat|hve|evtx|"
    r"lnk|job|xml|zip|7z|rar|docx?|xlsx?|pdf)\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{40}(?:[a-f0-9]{24})?\b", re.IGNORECASE)  # sha1/sha256
# Named behavioural signals -- structural, OS/technique primitives (not case data).
_BEHAVIOR_RE = re.compile(
    r"\b(?:srum_egress_outlier|anti_forensics_execution|high_risk_persistence|"
    r"executes_from_temp_path|c2_|dga_|lsass|mass_deletion|credential_dump)\w*",
    re.IGNORECASE)


def _text_of(finding: dict) -> str:
    parts = [str(finding.get(k) or "") for k in ("title", "description", "artifact", "raw_excerpt")]
    for c in finding.get("claims") or []:
        if isinstance(c, dict):
            parts.extend(str(c.get(k) or "") for k in ("value", "artifact", "text", "path", "registry_path"))
        elif isinstance(c, str):
            parts.append(c)
    return " ".join(parts)


def _has_real_pid(finding: dict) -> bool:
    for c in finding.get("claims") or []:
        if isinstance(c, dict) and str(c.get("type")) in ("pid", "connection"):
            try:
                if int(c.get("pid")) > 0:
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _has_hash_claim(finding: dict) -> bool:
    for c in finding.get("claims") or []:
        if isinstance(c, dict) and any(c.get(k) for k in ("hash", "sha1", "sha256", "md5")):
            return True
    return False


def match_tool_status_noise(finding) -> tuple[bool, str]:
    """(is_noise, reason). True only for a tool-status non-finding with no real
    evidence. Conservative: any real path/hash/pid/behavioral signal -> False."""
    if not isinstance(finding, dict):
        return False, "not_a_dict"
    text = _text_of(finding)
    low = text.lower()

    # real-evidence guards first (fail safe toward keeping findings)
    if _has_real_pid(finding) or _has_hash_claim(finding):
        return False, "has_real_pid_or_hash"
    if _HASH_RE.search(text) or _PATH_EXT_RE.search(text) or _BEHAVIOR_RE.search(low):
        return False, "has_real_evidence"

    # status shape
    has_compound = bool(_STATUS_COMPOUND_RE.search(low))
    has_tool_and_status = bool(_TOOL_NAME_RE.search(low) and _STATUS_RE.search(low))
    has_absence = bool(_ABSENCE_RE.search(low))
    if has_compound or has_tool_and_status or has_absence:
        return True, "tool_status_noise"
    return False, "not_tool_status"


def apply_tool_status_noise(findings) -> int:
    """In-place: flag tool-status-noise findings with ``_tool_status_noise``
    (honored by derive_final_disposition -> benign). Returns the count flagged."""
    n = 0
    for f in findings or []:
        if not isinstance(f, dict) or f.get("_tool_status_noise"):
            continue
        hit, reason = match_tool_status_noise(f)
        if hit:
            f["_tool_status_noise"] = True
            f["_tool_status_reason"] = reason
            n += 1
    return n


__all__ = ["match_tool_status_noise", "apply_tool_status_noise"]
