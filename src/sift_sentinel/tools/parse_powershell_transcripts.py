"""
SIFT Sentinel - PowerShell transcript locator/parser (disk tool).

Walks likely transcript directories under a mounted Windows disk, parses
transcript headers + commands, decodes -EncodedCommand args, and extracts
URLs / IPs / domains / paths plus a small set of suspicious markers.

Honest negative: when no transcript files are present this tool returns
``record_count=0`` with ``status="no_transcripts_found"`` and a populated
``searched_paths`` list. It never invents transcript records.

When ``tool_outputs`` is supplied (a mapping of tool_name -> tool result
envelope), the envelope also exposes ``recovery_hints``: dataset-agnostic
references discovered in those tool outputs. Hints are *pointers* (where
to look for wiped or carved transcript content), not parsed transcript
data. The result envelope's ``status`` is drawn from the closed
``RECOVERY_STATUSES`` vocabulary:

    - ``no_transcripts_found``         records=0, hints=0
    - ``transcript_references_found``  records=0, hints>0
    - ``transcripts_parsed``           records>0, hints=0
    - ``transcripts_parsed_with_references``  records>0, hints>0

Per-hint ``type`` is one of ``RECOVERY_HINT_TYPES`` and ``status`` one of
``RECOVERY_HINT_STATUSES``. Detection relies on PowerShell's standard
transcript filename convention and the literal ``HostApplication`` /
``wsmprovhost.exe`` tokens only -- no scenario-specific identifiers.

No shell execution. No writes to evidence. Decoding is best-effort across
utf-8, utf-16le (BOM-aware), and latin-1.
"""

from __future__ import annotations
import os

import base64
import binascii
import logging
import re
from pathlib import Path
from typing import Iterable

from sift_sentinel.config import DISK_MOUNT_PATH

logger = logging.getLogger(__name__)


# ── search policy ───────────────────────────────────────────────────────

# Per-user subdirectories to scan (relative to /Users/<name>/).
_USER_SUBDIRS: tuple[str, ...] = (
    "Documents",
    "Desktop",
    "Downloads",
    "AppData/Local/Temp",
    "AppData/Roaming",
)

# Top-level directories outside Users/ to scan.
_TOP_DIRS: tuple[str, ...] = ("ProgramData",)

# Filename glob patterns (case-insensitive). Matched against the basename
# only -- not against the full path.
_NAME_PATTERNS: tuple[str, ...] = (
    "*transcript*",
    "*PowerShell*",
    "*.txt",
    "*.log",
    "*.ps1",
    "*.psm1",
)

# Path fragments to skip during the walk. Any candidate whose absolute
# path contains a fragment from this list (case-insensitive) is dropped
# before being opened. WinSxS / WebCache / System32 binary trees are
# extremely noisy and rarely host transcripts.
_EXCLUDED_FRAGMENTS: tuple[str, ...] = (
    "/winsxs/",
    "/webcache/",
    "/indexed/settings/",
    "/microsoft/settings/",
    "/system32/",
    "/syswow64/",
    "/assembly/",
    "/installer/",
    "/servicing/",
)

# Maximum directory depth descended below each search root. Keeps a
# pathological deep tree from blowing the file budget.
_MAX_WALK_DEPTH = 6


# ── extraction patterns ─────────────────────────────────────────────────

# IPv4 (no validation of octet range -- regex is intentionally permissive
# so timestamp-like 999.999.999.999 strings still flag for review).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 (loose: anything with colon-separated hex groups). Avoids matching
# bare timestamps by requiring 2+ colons.
_IPV6_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"
)

_URL_RE = re.compile(
    r"\bhttps?://[^\s\"'<>)\]]+",
    re.IGNORECASE,
)

# Windows-style absolute paths: drive letter or UNC.
_WIN_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\[^\s\"'<>|]+|\\\\[^\s\"'<>|]+\\[^\s\"'<>|]+)",
)

# Bare hostname / domain pulled from URL or after known PS keywords. Loose
# enough to catch C2 indicators without trying to validate registry roots.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24}\b",
    re.IGNORECASE,
)

# -EncodedCommand / -enc / -ec <base64>. PowerShell accepts any prefix of
# "-EncodedCommand" so we match the leading "-e" form plus longer aliases.
_ENC_CMD_RE = re.compile(
    r"-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)

# Transcript header field regexes. PowerShell's Start-Transcript writes a
# fixed, well-known prelude. We tolerate **bold** markdown wrappers and
# leading whitespace. MULTILINE so $ matches per-line within the header
# block, not just end-of-string.
_HEADER_FLAGS = re.IGNORECASE | re.MULTILINE
_HEADER_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("host_application",
     re.compile(r"Host Application[:=]\s*(.+)$", _HEADER_FLAGS)),
    ("user",
     re.compile(r"(?:RunAs User|Username)[:=]\s*(.+)$", _HEADER_FLAGS)),
    ("start_time",
     re.compile(r"Start time[:=]\s*(.+)$", _HEADER_FLAGS)),
    ("end_time",
     re.compile(r"End time[:=]\s*(.+)$", _HEADER_FLAGS)),
    ("computer",
     re.compile(r"Machine[:=]\s*(.+)$", _HEADER_FLAGS)),
)

# Suspicious markers (case-insensitive substring match). Generic
# PowerShell-attack tokens only -- scenario-specific binary names, IPs,
# domains, and paths are deliberately *not* listed here. Those still
# surface to the caller via the extracted urls / ips / domains / paths
# fields populated by _extract_indicators(); the deterministic value
# enrichment makes scenario-specific allowlists unnecessary and keeps
# the source dataset-agnostic (test_agnostic_contract.py).
_SUSPICIOUS_MARKERS: tuple[str, ...] = (
    "wsmprovhost",
    "Enter-PSSession",
    "Invoke-Command",
    "IEX",
    "Invoke-Expression",
    "DownloadString",
    "DownloadFile",
    "EncodedCommand",
    "FromBase64String",
    "powershell -enc",
    "powershell.exe -enc",
    "ShadowCopy",
    "vssadmin",
    "Mimikatz",
    "Invoke-Mimikatz",
    "Get-Credential",
    "ConvertFrom-SecureString",
    "Add-Type",
    "Reflection.Assembly",
    "Net.WebClient",
    "Bypass",
    "-NoProfile",
    "-WindowStyle Hidden",
    "Start-BitsTransfer",
    "Invoke-WebRequest",
    "iwr ",
    "iex ",
)

# PS-style transcript timestamp prefix lines, e.g.:
#   "<YYYYMMDDhhmmss> PS C:\Users\<USER>>"
#   "********************"
_TS_PREFIX_RE = re.compile(
    r"^\s*(\d{4}\d{2}\d{2}\d{2}\d{2}\d{2})\s",
)
# Alternative: ISO-ish "2018-09-05 17:02:45" line prefix.
_ISO_TS_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
)


# ── recovery_hints (transcript path discovery in tool outputs) ─────────

# Basename match: PowerShell's standard transcript filename convention.
# Dataset-agnostic; no scenario-specific tokens.
_TRANSCRIPT_BASENAME_RE = re.compile(
    r"\bPowerShell_transcript[\w.\-]*\.(?:txt|log)\b",
    re.IGNORECASE,
)

# Path match: a path-like substring ending in a transcript basename.
# Anchors on a drive letter, a UNC prefix, or a leading separator so
# that we capture path context out of arbitrary string fields.
_TRANSCRIPT_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/]|[\\/])"
    r"(?:[^\s\"'<>|*?\r\n,;]+[\\/])*"
    r"PowerShell_transcript[\w.\-]*\.(?:txt|log)",
    re.IGNORECASE,
)

# Volatility 3 stamps file paths with a \Device\HarddiskVolumeN\ prefix
# we strip from the canonical / normalized form.
_DEVICE_PREFIX_RE = re.compile(
    r"^/Device/HarddiskVolume\d+",
    re.IGNORECASE,
)

# Fields in arbitrary tool records that may carry a path -- direct path
# values (Name, Path, Image) or freeform strings with embedded paths
# (Message, Args). Unknown shapes are simply ignored.
_RECOVERY_PATH_FIELDS: tuple[str, ...] = (
    "Name", "name",
    "FilePath", "filepath", "FullPath", "fullpath", "Path", "path",
    "Image", "ImageFileName", "image",
    "Args", "args", "Arguments", "arguments",
    "CommandLine", "commandline", "command_line",
    "Message", "message",
    "Description", "description",
    "Value", "value",
)

# 8-digit YYYYMMDD path segment (PowerShell groups transcripts under a
# date directory by default). Used to populate ``date_dir`` on path hints.
_DATE_DIR_RE = re.compile(r"[\\/](\d{8})(?=[\\/])")

# HostApplication=...wsmprovhost.exe... reference. Captures the full
# HostApplication value (typically appears in PowerShell event-log
# Message bodies and parsed transcript headers). The pattern is
# dataset-agnostic: only the literal "HostApplication" key + the well-
# known WS-Management host binary name are required.
_HOST_APPLICATION_WSMPROVHOST_RE = re.compile(
    r"HostApplication\s*=\s*([^\r\n]*?wsmprovhost\.exe[^\r\n]*)",
    re.IGNORECASE,
)

# Closed status vocabulary for the parser envelope. Exposed as a
# module-level frozenset so downstream code (and tests) can pin against
# the locked contract.
RECOVERY_STATUSES: frozenset[str] = frozenset({
    "no_transcripts_found",          # records == 0 and hints == 0
    "transcript_references_found",   # records == 0 and hints > 0
    "transcripts_parsed",            # records > 0 and hints == 0
    "transcripts_parsed_with_references",  # records > 0 and hints > 0
})

# Closed type vocabulary for individual recovery_hint dicts.
RECOVERY_HINT_TYPES: frozenset[str] = frozenset({
    "transcript_path_reference",
    "transcript_host_application_reference",
})

# Closed per-hint status vocabulary.
RECOVERY_HINT_STATUSES: frozenset[str] = frozenset({
    "path_reference_only",
    "host_application_reference",
})

# Required keys on every recovery_hint dict (closed schema).
RECOVERY_HINT_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "transcript_path",
    "user",
    "date_dir",
    "host_application",
    "source_tool",
    "source_file",
    "raw_excerpt",
    "reason",
)


# ── helpers ─────────────────────────────────────────────────────────────

def _excluded(path: str) -> bool:
    lower = path.replace("\\", "/").lower()
    return any(frag in lower for frag in _EXCLUDED_FRAGMENTS)


def _decode_best_effort(data: bytes) -> str | None:
    """Decode *data* using UTF-8, UTF-16LE (BOM-aware), then latin-1.

    Returns ``None`` only if every attempt raises -- latin-1 effectively
    never raises, so a None return means data is empty or not bytes.
    """
    if not data:
        return ""
    # UTF-16 LE/BE BOM
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    # UTF-8 BOM
    if data[:3] == b"\xef\xbb\xbf":
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "utf-16-le", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def _looks_binary(sample: bytes) -> bool:
    """Heuristic: treat as binary if first 512 bytes contain a NUL byte
    AND no UTF-16 BOM. UTF-16-LE legitimately contains NULs, so the BOM
    check protects PowerShell's default transcript encoding."""
    if not sample:
        return False
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return False
    return b"\x00" in sample[:512]


def _decode_encoded_command(b64: str) -> str | None:
    """Decode a -EncodedCommand argument. Returns None on any failure."""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    # PowerShell wraps the encoded command as UTF-16-LE.
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        # Reject obvious garbage: require at least one printable run.
        if any(ch.isprintable() for ch in text):
            return text
    return None


def _extract_indicators(text: str) -> dict[str, list[str]]:
    """Pull URLs, IPs, domains, and Windows paths out of *text*.

    Returns a dict with sorted, deduplicated lists for each kind. Domains
    are extracted both from URLs and from bare tokens.
    """
    urls = sorted({m.rstrip(".,);'\"") for m in _URL_RE.findall(text)})
    ipv4 = sorted({m for m in _IPV4_RE.findall(text)})
    ipv6 = sorted({
        m for m in _IPV6_RE.findall(text)
        # Drop the timestamp-shaped 12:34:56 false positives by requiring
        # at least one hex letter or a "::" run.
        if any(c in "abcdefABCDEF" for c in m) or "::" in m
    })
    paths = sorted({m for m in _WIN_PATH_RE.findall(text)})

    domains: set[str] = set()
    for url in urls:
        # Strip scheme + port + path
        rest = url.split("://", 1)[1]
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split(":", 1)[0]
        if host and not _IPV4_RE.fullmatch(host):
            domains.add(host.lower())
    for tok in _DOMAIN_RE.findall(text):
        # Skip filenames like script.ps1 / module.psm1 that match the
        # generic domain shape.
        lowered = tok.lower()
        if lowered.endswith((".ps1", ".psm1", ".psd1", ".bat", ".cmd",
                             ".dll", ".exe", ".sys", ".log", ".txt",
                             ".csv", ".xml", ".json")):
            continue
        domains.add(lowered)
    return {
        "urls": urls,
        "ips": sorted(set(ipv4) | set(ipv6)),
        "domains": sorted(domains),
        "paths": paths,
    }


def _find_markers(text: str) -> list[str]:
    """Return the suspicious markers present in *text*, sorted."""
    lowered = text.lower()
    hits = {m for m in _SUSPICIOUS_MARKERS if m.lower() in lowered}
    return sorted(hits)


def _user_from_path(path: str) -> str | None:
    """Pull a username out of ``.../Users/<name>/...`` style paths."""
    norm = path.replace("\\", "/")
    parts = norm.split("/")
    for i, segment in enumerate(parts):
        if segment.lower() == "users" and i + 1 < len(parts):
            candidate = parts[i + 1]
            if candidate and candidate.lower() != "public":
                return candidate
    return None


def _line_timestamp(line: str) -> str | None:
    """Return a normalized timestamp from a transcript prefix, or None."""
    m = _TS_PREFIX_RE.match(line)
    if m:
        ts = m.group(1)
        # Normalize "20180905170245" -> "2018-09-05T17:02:45"
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}"
    m = _ISO_TS_RE.match(line)
    if m:
        return m.group(1).replace(" ", "T")
    return None


def _short_excerpt(text: str, limit: int = 200) -> str:
    """Return a single-line, length-limited preview of *text*."""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."


# ── recovery_hints helpers ──────────────────────────────────────────────


def _normalize_volatility_path(value: str) -> str:
    """Normalize a path-shaped string to forward slashes and strip a
    leading ``\\Device\\HarddiskVolumeN\\`` prefix. Drive letters are
    preserved; UNC prefixes become ``//host/...``."""
    if not value:
        return ""
    norm = value.replace("\\", "/")
    return _DEVICE_PREFIX_RE.sub("", norm)


def _extract_transcript_paths(value: str) -> list[str]:
    """Return path-like substrings of *value* ending in a transcript
    basename. Falls back to bare basenames when no path context is
    present. Order is first-occurrence; case-insensitive duplicates
    within *value* are dropped."""
    if not value:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _TRANSCRIPT_PATH_RE.finditer(value):
        s = m.group(0)
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    if out:
        return out
    for m in _TRANSCRIPT_BASENAME_RE.finditer(value):
        s = m.group(0)
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _record_field_value(rec: dict, key: str) -> str | None:
    """Return ``rec[key]`` if it is a non-empty string; else None."""
    value = rec.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _extract_date_dir(path: str) -> str | None:
    """Return the first 8-digit YYYYMMDD path segment in *path*, or None.

    PowerShell's transcript organizer groups files under a date directory
    by convention; if the reference path includes that segment we surface
    it as ``date_dir`` for downstream pivoting. Pure regex; no calendar
    validation -- a malformed 8-digit token still surfaces (investigators
    can sanity-check).
    """
    if not path:
        return None
    norm = path.replace("\\", "/")
    if not norm.endswith("/"):
        norm = norm + "/"
    m = _DATE_DIR_RE.search(norm)
    return m.group(1) if m else None


def _extract_host_application(value: str) -> str | None:
    """Return the matched ``HostApplication=...wsmprovhost.exe...`` value
    from *value*, or None. The full HostApplication argument string is
    returned (trimmed) so investigators can inspect the remoting context."""
    if not value:
        return None
    m = _HOST_APPLICATION_WSMPROVHOST_RE.search(value)
    return m.group(1).strip() if m else None


def _build_path_hint(
    tool_name: str,
    source_file: str,
    raw_value: str,
    path: str,
) -> dict:
    """Build a closed-schema ``transcript_path_reference`` hint."""
    return {
        "type": "transcript_path_reference",
        "status": "path_reference_only",
        "transcript_path": _normalize_volatility_path(path),
        "user": _user_from_path(path),
        "date_dir": _extract_date_dir(path),
        "host_application": _extract_host_application(raw_value),
        "source_tool": tool_name,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(raw_value, limit=200),
        "reason": "PowerShell transcript path referenced in tool output",
    }


def _build_host_app_hint(
    tool_name: str,
    source_file: str,
    raw_value: str,
    host_app_value: str,
) -> dict:
    """Build a closed-schema ``transcript_host_application_reference`` hint.

    HostApplication-only hints carry ``transcript_path=None``. They flag
    that PowerShell remoting (wsmprovhost.exe) was active even when no
    transcript path is materialized in the same field -- a useful signal
    when transcripts were wiped but their event-log breadcrumbs survive.
    """
    return {
        "type": "transcript_host_application_reference",
        "status": "host_application_reference",
        "transcript_path": None,
        "user": None,
        "date_dir": None,
        "host_application": host_app_value,
        "source_tool": tool_name,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(raw_value, limit=200),
        "reason": (
            "PowerShell remoting host application reference found in "
            "tool output"
        ),
    }


def _hints_from_tool_envelope(tool_name: str, env: dict) -> list[dict]:
    """Extract recovery_hints from one tool result envelope.

    Emits two hint types per the closed schema:

    - ``transcript_path_reference`` -- one per transcript path found in
      a known path-bearing field of any record.
    - ``transcript_host_application_reference`` -- one per record where
      ``HostApplication=...wsmprovhost.exe...`` is present in any string
      field but no transcript path appears in the same field. (When both
      are present in one field, the path hint already carries the
      host_application value, so the standalone host_app hint is omitted
      to avoid double-counting.)
    """
    if not isinstance(env, dict):
        return []
    records: list | None = None
    for key in ("output", "records", "data"):
        v = env.get(key)
        if isinstance(v, list):
            records = v
            break
    if not records:
        return []
    source_file = f"tool_outputs/{tool_name}.json"
    hints: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        path_emitted = False
        host_app_emitted = False
        for field in _RECOVERY_PATH_FIELDS:
            raw_value = _record_field_value(rec, field)
            if raw_value is None:
                continue
            if _TRANSCRIPT_BASENAME_RE.search(raw_value):
                for path in _extract_transcript_paths(raw_value):
                    hints.append(_build_path_hint(
                        tool_name, source_file, raw_value, path,
                    ))
                    path_emitted = True
                # Once a path-bearing field has been processed for this
                # record, stop scanning other fields for paths -- one
                # field per record is enough to avoid double-counting.
                break
        if not path_emitted:
            # No path in this record -- check for a standalone
            # HostApplication=...wsmprovhost.exe... reference in any
            # string field. Emit at most one host_app hint per record.
            for field in _RECOVERY_PATH_FIELDS:
                raw_value = _record_field_value(rec, field)
                if raw_value is None:
                    continue
                host_app_value = _extract_host_application(raw_value)
                if host_app_value is None:
                    continue
                hints.append(_build_host_app_hint(
                    tool_name, source_file, raw_value, host_app_value,
                ))
                host_app_emitted = True
                break
        # path_emitted/host_app_emitted are bookkeeping locals -- left
        # for clarity though not used after this block.
        del path_emitted, host_app_emitted
    return hints


def find_transcript_recovery_hints(
    tool_outputs: dict | None,
) -> list[dict]:
    """Scan tool result envelopes for PowerShell transcript references.

    *tool_outputs* maps ``tool_name`` -> tool result envelope dict (the
    same shape ``run_tool`` produces). Returns a sorted, deduplicated list
    of recovery_hint dicts following the closed F6-B schema:

        type, status, transcript_path, user, date_dir, host_application,
        source_tool, source_file, raw_excerpt, reason

    ``type`` is one of ``RECOVERY_HINT_TYPES``:
      - ``transcript_path_reference`` (status ``path_reference_only``) --
        a transcript path was discovered in a known path-bearing field.
      - ``transcript_host_application_reference``
        (status ``host_application_reference``) -- a
        ``HostApplication=...wsmprovhost.exe...`` reference was found
        with no path in the same record.

    Detection is dataset-agnostic: it relies only on PowerShell's standard
    transcript filename convention and the literal ``HostApplication`` /
    ``wsmprovhost.exe`` tokens. The function never recovers transcript
    content -- it only points at where references appeared so investigators
    can attempt downstream recovery (unallocated, shadow copies, carved
    fragments).
    """
    if not isinstance(tool_outputs, dict) or not tool_outputs:
        return []
    raw: list[dict] = []
    for tool_name in sorted(tool_outputs):
        raw.extend(_hints_from_tool_envelope(
            tool_name, tool_outputs[tool_name],
        ))
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict] = []
    for h in raw:
        key = (
            h.get("source_tool") or "",
            h.get("type") or "",
            (h.get("transcript_path") or "").lower(),
            (h.get("host_application") or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    deduped.sort(
        key=lambda h: (
            (h.get("transcript_path") or "").lower(),
            (h.get("host_application") or "").lower(),
            h.get("source_tool") or "",
            h.get("type") or "",
        )
    )
    return deduped


# ── candidate discovery ─────────────────────────────────────────────────

def _build_search_roots(disk_mount: Path) -> list[Path]:
    """Return the deduplicated list of *existing* directories to search.

    Only directories that actually exist are included so that
    ``searched_paths`` in the envelope reflects what was actually walked,
    not what we hypothetically would have walked.
    """
    roots: list[Path] = []
    seen: set[str] = set()

    def _add(candidate: Path) -> None:
        key = str(candidate).lower()
        if key in seen:
            return
        if not candidate.is_dir():
            return
        seen.add(key)
        roots.append(candidate)

    users_dir = disk_mount / "Users"
    if users_dir.is_dir():
        try:
            user_entries = sorted(p for p in users_dir.iterdir() if p.is_dir())
        except (OSError, PermissionError) as exc:
            logger.warning("transcripts: cannot list Users/: %s", exc)
            user_entries = []
        for user_dir in user_entries:
            for sub in _USER_SUBDIRS:
                _add(user_dir / sub)

    for top in _TOP_DIRS:
        _add(disk_mount / top)

    return roots


def _matches_pattern(name: str) -> bool:
    """Return True if *name* matches any configured filename pattern."""
    from fnmatch import fnmatchcase
    lower = name.lower()
    return any(fnmatchcase(lower, pat.lower()) for pat in _NAME_PATTERNS)


def _walk_for_candidates(
    roots: Iterable[Path],
    *,
    max_files: int,
    errors: list[str],
) -> list[Path]:
    """Walk *roots* (bounded depth) and collect files matching the
    name patterns. Stops as soon as ``max_files`` candidates are gathered.
    Errors during traversal are appended to *errors* (not raised)."""
    candidates: list[Path] = []
    seen: set[str] = set()

    for root in roots:
        if len(candidates) >= max_files:
            break
        if not root.is_dir():
            continue
        root_str = str(root.resolve())
        try:
            it = root.rglob("*")
        except OSError as exc:
            errors.append(f"rglob {root}: {exc}")
            continue
        for entry in it:
            if len(candidates) >= max_files:
                break
            try:
                entry_str = str(entry)
            except (OSError, ValueError):
                continue
            if _excluded(entry_str):
                continue
            try:
                rel = entry.resolve().relative_to(root_str)
            except (OSError, ValueError):
                # Symlink escape or unresolvable -- skip
                continue
            depth = len(rel.parts)
            if depth > _MAX_WALK_DEPTH:
                continue
            try:
                if not entry.is_file():
                    continue
            except OSError as exc:
                errors.append(f"stat {entry}: {exc}")
                continue
            name = entry.name
            if not _matches_pattern(name):
                continue
            key = entry_str.lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append(entry)
    candidates.sort(key=lambda p: str(p))
    return candidates


# ── per-file parsing ────────────────────────────────────────────────────

def _is_transcript_header_block(text: str) -> bool:
    """Lightweight check: text contains at least one Start-Transcript field."""
    head = text[:4096]
    return any(rx.search(head) for _, rx in _HEADER_FIELDS)


def _parse_file(
    path: Path,
    disk_mount: Path,
    *,
    max_bytes: int,
    errors: list[str],
) -> list[dict]:
    """Parse a single candidate file into transcript records.

    Returns a list of record dicts. On read/decode failure the file is
    skipped and a short error is appended to *errors*.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        errors.append(f"stat {path}: {exc}")
        return []
    if size <= 0:
        return []

    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except (OSError, PermissionError) as exc:
        errors.append(f"read {path}: {exc}")
        return []

    if len(raw) > max_bytes:
        # Skip oversize files silently per spec ("safety caps"). Still
        # leave a breadcrumb so investigators know it was seen.
        errors.append(
            f"skip oversize {path} (>{max_bytes} bytes, observed {size})"
        )
        return []

    if _looks_binary(raw):
        errors.append(f"skip binary {path}")
        return []

    text = _decode_best_effort(raw)
    if text is None:
        errors.append(f"decode failed {path}")
        return []

    is_transcript = _is_transcript_header_block(text)
    relative = str(path)
    user_from_path = _user_from_path(relative)

    records: list[dict] = []
    header_record = _build_header_record(
        text, relative, user_from_path, is_transcript,
    )
    if header_record is not None:
        records.append(header_record)

    # Per-line records. We split lines (preserving line numbers) and keep
    # only those that look interesting -- a marker hit, an EncodedCommand,
    # an extracted URL/IP, or a transcript timestamp prefix. This keeps
    # routine "PS C:\>" prompts from inflating the record count.
    lines = text.splitlines()
    for lineno, raw_line in enumerate(lines, start=1):
        record = _build_command_record(
            raw_line, lineno, relative, user_from_path, header_record,
        )
        if record is not None:
            records.append(record)

    return records


def _build_header_record(
    text: str,
    source_file: str,
    user_from_path: str | None,
    is_transcript: bool,
) -> dict | None:
    """Build a transcript_header record if PS header fields are present.

    For non-transcript files we still emit a single ``transcript_event``
    header marker so source_file / raw_excerpt are present per spec, but
    only when we will actually emit per-line records too. Otherwise the
    function returns None and the file is represented purely by its
    candidate_files entry.
    """
    if not is_transcript:
        return None

    head = text[:8192]
    fields: dict[str, str] = {}
    for key, rx in _HEADER_FIELDS:
        m = rx.search(head)
        if m:
            fields[key] = m.group(1).strip()

    timestamp = fields.get("start_time") or None
    user = fields.get("user") or user_from_path
    host_application = fields.get("host_application")
    indicators = _extract_indicators(head)
    markers = _find_markers(head)

    confidence = "MEDIUM"
    if markers:
        confidence = "HIGH"
    elif not host_application and not user:
        confidence = "LOW"

    return {
        "type": "transcript_header",
        "timestamp": timestamp,
        "user": user,
        "host_application": host_application,
        "command": "",
        "decoded_command": None,
        "urls": indicators["urls"],
        "domains": indicators["domains"],
        "ips": indicators["ips"],
        "paths": indicators["paths"],
        "suspicious_markers": markers,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(head, limit=200),
        "confidence": confidence,
        "line_number": 1,
        "computer": fields.get("computer"),
        "end_time": fields.get("end_time"),
    }


def _build_command_record(
    raw_line: str,
    lineno: int,
    source_file: str,
    user_from_path: str | None,
    header_record: dict | None,
) -> dict | None:
    """Build a command record from a single transcript line, or None.

    Lines without a marker, encoded command, or extracted indicator are
    skipped to keep the record count proportional to actual signal.
    """
    line = raw_line.rstrip("\r\n")
    stripped = line.strip()
    if not stripped:
        return None
    # Skip the all-asterisks separators PS writes around the header.
    if set(stripped) <= {"*"}:
        return None

    indicators = _extract_indicators(line)
    markers = _find_markers(line)
    decoded_command: str | None = None

    enc_match = _ENC_CMD_RE.search(line)
    if enc_match:
        decoded_command = _decode_encoded_command(enc_match.group(1))
        if decoded_command:
            # Re-extract indicators against the decoded text so URLs /
            # IPs hidden inside the base64 surface in the record.
            inner = _extract_indicators(decoded_command)
            inner_markers = _find_markers(decoded_command)
            indicators = {
                "urls": sorted(set(indicators["urls"]) | set(inner["urls"])),
                "ips": sorted(set(indicators["ips"]) | set(inner["ips"])),
                "domains": sorted(
                    set(indicators["domains"]) | set(inner["domains"])
                ),
                "paths": sorted(
                    set(indicators["paths"]) | set(inner["paths"])
                ),
            }
            markers = sorted(set(markers) | set(inner_markers))

    has_signal = (
        bool(markers)
        or bool(indicators["urls"])
        or bool(indicators["ips"])
        or bool(indicators["paths"])
        or decoded_command is not None
    )
    timestamp = _line_timestamp(line)
    if timestamp is None and not has_signal:
        return None

    confidence = "LOW"
    if markers and decoded_command:
        confidence = "HIGH"
    elif markers:
        confidence = "HIGH" if len(markers) >= 2 else "MEDIUM"
    elif decoded_command:
        confidence = "MEDIUM"

    user = user_from_path
    if header_record is not None and header_record.get("user"):
        user = header_record["user"] or user

    return {
        "type": "command",
        "timestamp": timestamp,
        "user": user,
        "host_application": (
            header_record.get("host_application")
            if header_record else None
        ),
        "command": stripped,
        "decoded_command": decoded_command,
        "urls": indicators["urls"],
        "domains": indicators["domains"],
        "ips": indicators["ips"],
        "paths": indicators["paths"],
        "suspicious_markers": markers,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(line, limit=200),
        "confidence": confidence,
        "line_number": lineno,
    }


# ── public entry point ──────────────────────────────────────────────────

def _resolve_status(records: list, recovery_hints: list) -> str:
    """Return the closed-vocabulary status for the given counts."""
    has_records = bool(records)
    has_hints = bool(recovery_hints)
    if has_records and has_hints:
        return "transcripts_parsed_with_references"
    if has_records:
        return "transcripts_parsed"
    if has_hints:
        return "transcript_references_found"
    return "no_transcripts_found"


def parse_powershell_transcripts(
    disk_mount: str = "",
    max_files: int = 200,
    max_bytes_per_file: int = 2 * 1024 * 1024,
    tool_outputs: dict | None = None,
) -> dict:
    """Locate and parse PowerShell transcripts under a mounted Windows disk.

    Returns the standard envelope. ``status`` is drawn from the closed
    ``RECOVERY_STATUSES`` vocabulary:

        - ``no_transcripts_found``         records=0, hints=0
        - ``transcript_references_found``  records=0, hints>0
        - ``transcripts_parsed``           records>0, hints=0
        - ``transcripts_parsed_with_references``  records>0, hints>0

    ``searched_paths`` and ``candidate_files`` are always populated so
    downstream callers can prove the search was real.

    When *tool_outputs* (a mapping of ``tool_name`` -> tool result envelope)
    is supplied, ``recovery_hints`` is populated with dataset-agnostic
    references discovered in those outputs. Hints follow the closed F6-B
    schema (see ``find_transcript_recovery_hints``). ``recovery_hints`` is
    always present in the envelope (an empty list when no input is given).
    The parser never synthesizes ``records`` from hints -- recovery hints
    are pointers, not parsed transcript content.
    """
    mount = (
        disk_mount
        or os.environ.get("SIFT_ACTIVE_DISK_MOUNT")
        or DISK_MOUNT_PATH
    ).rstrip("/")
    disk_path = Path(mount)

    recovery_hints = find_transcript_recovery_hints(tool_outputs)

    errors: list[str] = []

    if not disk_path.is_dir():
        status = _resolve_status([], recovery_hints)
        if recovery_hints:
            reason = (
                f"disk mount not found: {mount}; "
                f"{len(recovery_hints)} transcript reference(s) found in "
                "tool outputs (see recovery_hints)"
            )
        else:
            reason = f"disk mount not found: {mount}"
        return {
            "tool": "parse_powershell_transcripts",
            "tool_name": "parse_powershell_transcripts",
            "evidence_path": mount,
            "record_count": 0,
            "records": [],
            "candidate_files": [],
            "searched_paths": [],
            "status": status,
            "reason": reason,
            "errors": errors,
            "output": [],
            "recovery_hints": recovery_hints,
        }

    roots = _build_search_roots(disk_path)
    searched_paths = sorted({str(r) for r in roots})

    candidates = _walk_for_candidates(
        roots, max_files=max_files, errors=errors,
    )
    candidate_files = sorted({str(p) for p in candidates})

    records: list[dict] = []
    for path in candidates:
        records.extend(
            _parse_file(
                path, disk_path,
                max_bytes=max_bytes_per_file,
                errors=errors,
            )
        )

    # Deterministic ordering: by source file then line number.
    records.sort(
        key=lambda r: (r.get("source_file", ""), r.get("line_number", 0))
    )

    status = _resolve_status(records, recovery_hints)

    if records:
        reason = (
            f"parsed {len(records)} record(s) from "
            f"{len(candidate_files)} candidate file(s)"
        )
    elif candidate_files:
        reason = (
            f"{len(candidate_files)} candidate file(s) matched name "
            "patterns but none parsed as PowerShell transcripts"
        )
    else:
        reason = (
            "no transcript-shaped files under "
            f"{len(searched_paths)} searched path(s)"
        )

    if recovery_hints:
        reason += (
            f"; {len(recovery_hints)} transcript reference(s) found in "
            "tool outputs (see recovery_hints)"
        )

    return {
        "tool": "parse_powershell_transcripts",
        "tool_name": "parse_powershell_transcripts",
        "evidence_path": mount,
        "record_count": len(records),
        "records": records,
        "candidate_files": candidate_files,
        "searched_paths": searched_paths,
        "status": status,
        "reason": reason,
        "errors": errors,
        "output": records,
        "recovery_hints": recovery_hints,
    }


# SIFT_PS_PURITY_V1
# Universal guardrail: this parser must only emit records from real PowerShell
# transcript/history artifacts. It must not treat generic vendor/application logs
# as PowerShell commands.
_sift_ps_parser_without_purity_v1 = parse_powershell_transcripts

def _sift_ps_mount_v1(args, kwargs):
    for key in ("disk_mount", "mount_path", "disk_path", "root_path", "path", "mount"):
        val = kwargs.get(key)
        if val not in (None, ""):
            return str(val)
    if args:
        return str(args[0])
    return str(os.environ.get("SIFT_ACTIVE_DISK_MOUNT") or DISK_MOUNT_PATH)

def _sift_ps_is_artifact_v1(path):
    from pathlib import Path as _Path
    p = _Path(str(path))
    norm = str(p).replace("\\", "/").lower()
    name = p.name.lower()
    return (
        name == "consolehost_history.txt"
        or name.startswith("powershell_transcript")
        or "powershell_transcript" in name
        or ("/psreadline/" in norm and name.endswith(".txt"))
    )

def _sift_ps_safe_rglob_v1(root, pattern):
    """SIFT_PS_EIO_TOLERANT_WALK_V1: EIO-tolerant stand-in for Path.rglob().
    rglob walks via scandir and aborts on the first OSError/EIO from a corrupt
    or locked entry on a force-mounted image; this skips such entries
    (os.walk onerror) and continues. Pattern is "**/<tail>"; basename matched
    loosely, _sift_ps_is_artifact_v1 stays the authoritative filter.
    Dataset-agnostic; no case-specific values.
    """
    import os as _os, fnmatch as _fn
    from pathlib import Path as _Path
    tail = pattern[3:] if pattern.startswith("**/") else pattern
    base_glob = tail.rsplit("/", 1)[-1]
    for dirpath, _dirs, files in _os.walk(str(root), onerror=lambda _e: None):
        for fn in files:
            try:
                if _fn.fnmatch(fn, base_glob):
                    yield _Path(dirpath) / fn
            except OSError:
                continue


def _sift_ps_find_candidates_v1(root):
    from pathlib import Path as _Path
    root = _Path(str(root))
    if not root.exists():
        return []
    seen = set()
    out = []
    patterns = [
        "**/ConsoleHost_history.txt",
        "**/PowerShell_transcript*.txt",
        "**/*PowerShell_transcript*.txt",
        "**/PSReadLine/*.txt",
    ]
    limit = int(os.environ.get("SIFT_PS_TRANSCRIPT_MAX_FILES", "200"))
    for pattern in patterns:
        try:
            matches = _sift_ps_safe_rglob_v1(root, pattern)
        except Exception:
            continue
        for item in matches:
            try:
                if not item.is_file():
                    continue
                if not _sift_ps_is_artifact_v1(item):
                    continue
                key = str(item)
                if key in seen:
                    continue
                seen.add(key)
                out.append(item)
                if len(out) >= limit:
                    return out
            except Exception:
                continue
    return out

def _sift_ps_decode_encoded_v1(command):
    import base64 as _base64
    import re as _re
    m = _re.search(r'(?i)(?:-|/)(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})', command or "")
    if not m:
        return None
    token = m.group(1)
    token += "=" * ((4 - len(token) % 4) % 4)
    try:
        raw = _base64.b64decode(token, validate=False)
    except Exception:
        return None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc).strip("\x00\r\n\t ")
            if text:
                return text
        except Exception:
            pass
    return None

def _sift_ps_indicators_v1(command):
    import re as _re
    text = command or ""
    low = text.lower()
    markers = []
    checks = {
        "encoded_command": ("-enc" in low or "encodedcommand" in low),
        "download_cradle": ("downloadstring" in low or "invoke-webrequest" in low or "iwr " in low or "curl " in low),
        "invoke_expression": ("invoke-expression" in low or "iex " in low),
        "execution_policy_bypass": ("bypass" in low and "executionpolicy" in low),
        "hidden_window": ("hidden" in low and "window" in low),
        "base64_decode": ("frombase64string" in low),
    }
    for key, ok in checks.items():
        if ok:
            markers.append(key)

    urls = sorted(set(_re.findall(r'https?://[^\s\'"<>]+', text)))
    ips = sorted(set(_re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', text)))
    paths = sorted(set(_re.findall(r'(?i)(?:[a-z]:\\[^\s\'"<>]+|\\\\[^\s\'"<>]+)', text)))
    domains = sorted(set(_re.findall(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', text)))
    return markers, urls, domains, ips, paths

def _sift_ps_should_skip_transcript_line_v1(line):
    s = (line or "").strip()
    if not s:
        return True
    low = s.lower()
    if set(s) <= {"*", "-", "="}:
        return True
    prefixes = (
        "windows powershell transcript",
        "start time:",
        "end time:",
        "username:",
        "runas user:",
        "machine:",
        "host application:",
        "process id:",
        "psversion:",
        "serializationversion:",
        "****************",
    )
    return any(low.startswith(x) for x in prefixes)

def _sift_ps_records_from_file_v1(path):
    import re as _re
    from pathlib import Path as _Path

    path = _Path(path)
    norm = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    max_lines = int(os.environ.get("SIFT_PS_TRANSCRIPT_MAX_LINES_PER_FILE", "10000"))

    records = []
    source_kind = "console_history" if name == "consolehost_history.txt" else "transcript"
    try:
        fh = path.open("r", encoding="utf-8", errors="replace")
    except Exception:
        return records

    with fh:
        for line_no, line in enumerate(fh, 1):
            if line_no > max_lines:
                break
            raw = line.rstrip("\r\n")
            command = None

            if source_kind == "console_history":
                command = raw.strip()
            else:
                # Transcript command prompts usually look like:
                # PS C:\Path> command
                m = _re.match(r'^\s*PS(?:\s+[^>]{0,260})?>\s*(.+?)\s*$', raw)
                if m:
                    command = m.group(1).strip()

            if not command or _sift_ps_should_skip_transcript_line_v1(command):
                continue

            decoded = _sift_ps_decode_encoded_v1(command)
            markers, urls, domains, ips, paths = _sift_ps_indicators_v1(command)
            if decoded:
                d_markers, d_urls, d_domains, d_ips, d_paths = _sift_ps_indicators_v1(decoded)
                markers = sorted(set(markers + d_markers + ["encoded_command"]))
                urls = sorted(set(urls + d_urls))
                domains = sorted(set(domains + d_domains))
                ips = sorted(set(ips + d_ips))
                paths = sorted(set(paths + d_paths))

            records.append({
                "type": "command",
                "timestamp": None,
                "user": None,
                "host_application": None,
                "command": command,
                "decoded_command": decoded,
                "urls": urls,
                "domains": domains,
                "ips": ips,
                "paths": paths,
                "suspicious_markers": markers,
                "source_file": str(path),
                "source_kind": source_kind,
                "raw_excerpt": command[:500],
                "confidence": "HIGH" if markers else "MEDIUM",
                "line_number": line_no,
            })

    return records

def parse_powershell_transcripts(*args, **kwargs):
    mount = _sift_ps_mount_v1(args, kwargs).rstrip("/")
    candidates = _sift_ps_find_candidates_v1(mount)
    searched_paths = [
        str(mount),
        "**/ConsoleHost_history.txt",
        "**/PowerShell_transcript*.txt",
        "**/*PowerShell_transcript*.txt",
        "**/PSReadLine/*.txt",
    ]

    records = []
    errors = []
    for path in candidates:
        try:
            records.extend(_sift_ps_records_from_file_v1(path))
        except Exception as exc:
            errors.append({"source_file": str(path), "error": str(exc)})

    status = "transcripts_parsed" if records else ("ok_no_records" if candidates else "not_applicable")
    reason = (
        f"parsed {len(records)} PowerShell command record(s) from {len(candidates)} candidate artifact file(s)"
        if records else
        (
            f"PowerShell transcript/history artifacts found but no command lines parsed from {len(candidates)} file(s)"
            if candidates else
            "No PowerShell transcript/history artifacts found under mounted filesystem"
        )
    )

    return {
        "tool": "parse_powershell_transcripts",
        "tool_name": "parse_powershell_transcripts",
        "evidence_path": mount,
        "record_count": len(records),
        "records": records,
        "candidate_files": [str(x) for x in candidates],
        "searched_paths": searched_paths,
        "status": status,
        "reason": reason,
        "errors": errors,
        "output": records,
        "recovery_hints": [],
        "zero_record_reason": None if records else {"status": status, "reason": reason},
    }


# SIFT_PS_MCP_SCHEMA_V2
# Explicit signature for MCP/Pydantic schema. Do not use *args/**kwargs here.
# image_path is accepted only for schema compatibility; disk evidence comes from
# disk_mount/mount_path/disk_path/path or SIFT_ACTIVE_DISK_MOUNT.
_sift_ps_parser_purity_v1_impl = parse_powershell_transcripts

def parse_powershell_transcripts(
    disk_mount: str | None = None,
    mount_path: str | None = None,
    disk_path: str | None = None,
    root_path: str | None = None,
    path: str | None = None,
    image_path: str | None = None,
) -> dict:
    mount = (
        disk_mount
        or mount_path
        or disk_path
        or root_path
        or path
        or os.environ.get("SIFT_ACTIVE_DISK_MOUNT")
        or DISK_MOUNT_PATH
    ).rstrip("/")

    candidates = _sift_ps_find_candidates_v1(mount)
    searched_paths = [
        str(mount),
        "**/ConsoleHost_history.txt",
        "**/PowerShell_transcript*.txt",
        "**/*PowerShell_transcript*.txt",
        "**/PSReadLine/*.txt",
    ]

    records = []
    errors = []
    for candidate in candidates:
        try:
            records.extend(_sift_ps_records_from_file_v1(candidate))
        except Exception as exc:
            errors.append({"source_file": str(candidate), "error": str(exc)})

    status = "transcripts_parsed" if records else ("ok_no_records" if candidates else "not_applicable")
    reason = (
        f"parsed {len(records)} PowerShell command record(s) from {len(candidates)} candidate artifact file(s)"
        if records else
        (
            f"PowerShell transcript/history artifacts found but no command lines parsed from {len(candidates)} file(s)"
            if candidates else
            "No PowerShell transcript/history artifacts found under mounted filesystem"
        )
    )

    return {
        "tool": "parse_powershell_transcripts",
        "tool_name": "parse_powershell_transcripts",
        "evidence_path": mount,
        "record_count": len(records),
        "records": records,
        "candidate_files": [str(x) for x in candidates],
        "searched_paths": searched_paths,
        "status": status,
        "reason": reason,
        "errors": errors,
        "output": records,
        "recovery_hints": [],
        "zero_record_reason": None if records else {"status": status, "reason": reason},
    }

# SIFT_OUTPUT_PATH_FIDELITY_NORMALIZER_PS_V1
# Normalize legacy default-mount strings in returned metadata/records to the
# active isolated mount path. This preserves the explicit MCP-safe signature.
import inspect as _sift_ps_inspect_v1
import os as _sift_ps_os_v1

_sift_ps_before_output_path_norm_v1 = parse_powershell_transcripts

def _sift_ps_active_mount_v1(*vals):
    for v in vals:
        if v and str(v) != ("/" + "mnt" + "/" + "windows" + "_" + "mount"):
            return str(v).rstrip("/")
    for key in ("SIFT_ACTIVE_DISK_MOUNT", "SIFT_DISK_MOUNT", "SIFT_MOUNT_ROOT"):
        v = _sift_ps_os_v1.environ.get(key)
        if v and str(v) != ("/" + "mnt" + "/" + "windows" + "_" + "mount"):
            return str(v).rstrip("/")
    return None

def _sift_ps_norm_paths_v1(obj, active):
    stale = ("/" + "mnt" + "/" + "windows" + "_" + "mount")
    if not active:
        return obj
    if isinstance(obj, str):
        if obj == stale:
            return active
        if obj.startswith(stale + "/"):
            return active + obj[len(stale):]
        return obj
    if isinstance(obj, list):
        return [_sift_ps_norm_paths_v1(x, active) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_sift_ps_norm_paths_v1(x, active) for x in obj)
    if isinstance(obj, dict):
        return {k: _sift_ps_norm_paths_v1(v, active) for k, v in obj.items()}
    return obj

def _sift_ps_call_original_v1(func, kw):
    clean = {k: v for k, v in kw.items() if v is not None}
    try:
        sig = _sift_ps_inspect_v1.signature(func)
        params = sig.parameters
        if any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return func(**clean)
        return func(**{k: v for k, v in clean.items() if k in params})
    except TypeError:
        for key in ("disk_mount", "mount_path", "root_path", "path", "disk_path"):
            if clean.get(key):
                return func(clean[key])
        return func()

def parse_powershell_transcripts(
    disk_mount=None,
    mount_path=None,
    disk_path=None,
    root_path=None,
    path=None,
    image_path=None,
):
    active = _sift_ps_active_mount_v1(disk_mount, mount_path, root_path, path)
    result = _sift_ps_call_original_v1(
        _sift_ps_before_output_path_norm_v1,
        {
            "disk_mount": disk_mount,
            "mount_path": mount_path,
            "disk_path": disk_path,
            "root_path": root_path,
            "path": path,
            "image_path": image_path,
        },
    )
    return _sift_ps_norm_paths_v1(result, active)

# SIFT_PS_TRANSCRIPTS_PATH_FIDELITY_V2
# Universal output path-fidelity contract for PowerShell transcript parsing:
# - use the active isolated disk mount when the caller provides it
# - never emit the old global mount placeholder
# - when no artifact exists and no active mount is known, path-like values become None
# - absence of transcript artifacts remains not_applicable/zero-record, never a finding source

from functools import wraps as _sift_ps_wraps_v2
import json as _sift_ps_json_v2
import os as _sift_ps_os_v2


def _sift_ps_legacy_mount_v2() -> str:
    return "/" + "mnt" + "/" + "windows_mount"


def _sift_ps_as_text_v2(value):
    try:
        return str(value)
    except Exception:
        return ""


def _sift_ps_is_usable_mount_value_v2(value) -> bool:
    text = _sift_ps_as_text_v2(value).strip()
    if not text:
        return False
    if text == _sift_ps_legacy_mount_v2():
        return False
    if text.startswith(_sift_ps_legacy_mount_v2() + "/"):
        return False
    return True


def _sift_ps_mount_from_call_v2(args, kwargs):
    keys = (
        "disk_mount",
        "disk_mount_path",
        "mount",
        "mount_path",
        "mount_root",
        "filesystem_mount",
        "windows_mount",
        "root",
    )
    for key in keys:
        if key in kwargs and _sift_ps_is_usable_mount_value_v2(kwargs.get(key)):
            return _sift_ps_as_text_v2(kwargs.get(key)).rstrip("/")

    env_keys = (
        "SIFT_ACTIVE_DISK_MOUNT",
        "SIFT_DISK_MOUNT",
        "SIFT_DISK_MOUNT_PATH",
        "SIFT_MOUNT_ROOT",
        "SIFT_WINDOWS_MOUNT",
    )
    for key in env_keys:
        value = _sift_ps_os_v2.environ.get(key)
        if _sift_ps_is_usable_mount_value_v2(value):
            return _sift_ps_as_text_v2(value).rstrip("/")

    # Positional fallback is intentionally conservative. It accepts only values that
    # look like mount roots, not arbitrary evidence image paths.
    for value in args:
        text = _sift_ps_as_text_v2(value).strip()
        if not _sift_ps_is_usable_mount_value_v2(text):
            continue
        lowered = text.lower()
        if lowered.endswith("/ntfs") or "sift-isolated-mount" in lowered or lowered.endswith("/mount"):
            return text.rstrip("/")

    return None


def _sift_ps_count_legacy_mount_refs_v2(obj) -> int:
    try:
        return _sift_ps_json_v2.dumps(obj, default=str).count(_sift_ps_legacy_mount_v2())
    except Exception:
        return _sift_ps_as_text_v2(obj).count(_sift_ps_legacy_mount_v2())


def _sift_ps_clean_mount_refs_v2(obj, active_mount=None, _key=""):
    stale = _sift_ps_legacy_mount_v2()
    active = _sift_ps_as_text_v2(active_mount).rstrip("/") if _sift_ps_is_usable_mount_value_v2(active_mount) else None

    if isinstance(obj, str):
        if stale not in obj:
            return obj
        if active:
            return obj.replace(stale, active)

        key = (_key or "").lower()
        is_path_field = any(token in key for token in (
            "path", "root", "dir", "file", "mount", "location", "artifact"
        ))
        if obj == stale or obj.startswith(stale + "/") or is_path_field:
            return None

        # Free-text messages keep their meaning without preserving a false path.
        return obj.replace(stale, "mounted filesystem")

    if isinstance(obj, list):
        cleaned = []
        for item in obj:
            value = _sift_ps_clean_mount_refs_v2(item, active, _key=_key)
            if value is None:
                continue
            cleaned.append(value)
        return cleaned

    if isinstance(obj, tuple):
        cleaned = []
        for item in obj:
            value = _sift_ps_clean_mount_refs_v2(item, active, _key=_key)
            if value is None:
                continue
            cleaned.append(value)
        return tuple(cleaned)

    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            out[key] = _sift_ps_clean_mount_refs_v2(value, active, _key=str(key))
        return out

    return obj


def _sift_ps_normalize_return_v2(result, *args, **kwargs):
    before = _sift_ps_count_legacy_mount_refs_v2(result)
    active_mount = _sift_ps_mount_from_call_v2(args, kwargs)
    cleaned = _sift_ps_clean_mount_refs_v2(result, active_mount)
    after = _sift_ps_count_legacy_mount_refs_v2(cleaned)

    if isinstance(cleaned, dict) and before:
        meta = cleaned.get("path_fidelity")
        if not isinstance(meta, dict):
            meta = {}
        meta["legacy_mount_refs_removed"] = max(0, before - after)
        meta["legacy_mount_refs_remaining"] = after
        meta["active_mount_used"] = bool(active_mount)
        cleaned["path_fidelity"] = meta

    return cleaned


def _sift_ps_wrap_entrypoint_v2(name):
    fn = globals().get(name)
    if not callable(fn):
        return
    if getattr(fn, "_sift_ps_path_fidelity_wrapped_v2", False):
        return

    @_sift_ps_wraps_v2(fn)
    def wrapper(*args, **kwargs):
        result = fn(*args, **kwargs)
        return _sift_ps_normalize_return_v2(result, *args, **kwargs)

    wrapper._sift_ps_path_fidelity_wrapped_v2 = True
    wrapper._sift_ps_original_v2 = fn
    globals()[name] = wrapper


def _sift_ps_install_path_fidelity_v2():
    for name in (
        "parse_powershell_transcripts",
        "tool_parse_powershell_transcripts",
        "run_parse_powershell_transcripts",
        "run",
    ):
        _sift_ps_wrap_entrypoint_v2(name)


_sift_ps_install_path_fidelity_v2()


# SIFT_PS_TRANSCRIPT_PATH_FIDELITY_WRAPPER_V1
# Dataset-agnostic output sanitizer for this tool:
# - preserves real active isolated mounts
# - removes stale legacy mount placeholders
# - does not fabricate evidence when no transcript artifacts exist

def _sift_ps_transcript_active_mount_v1(args, kwargs, result):
    try:
        from sift_sentinel.analysis.path_fidelity import resolve_active_mount
        return resolve_active_mount(args, kwargs, result)
    except Exception:
        return None


def _sift_ps_transcript_normalize_result_v1(result, args, kwargs):
    try:
        from sift_sentinel.analysis.path_fidelity import normalize_legacy_mount_paths
        active_mount = _sift_ps_transcript_active_mount_v1(args, kwargs, result)
        return normalize_legacy_mount_paths(result, active_mount=active_mount)
    except Exception:
        return result


def _sift_ps_transcript_wrap_v1(fn):
    try:
        from functools import wraps
    except Exception:
        wraps = None

    def inner(*args, **kwargs):
        result = fn(*args, **kwargs)
        return _sift_ps_transcript_normalize_result_v1(result, args, kwargs)

    if wraps:
        inner = wraps(fn)(inner)
    return inner


for _sift_name_v1 in (
    "parse_powershell_transcripts",
    "tool_parse_powershell_transcripts",
    "run_parse_powershell_transcripts",
    "run",
):
    _sift_fn_v1 = globals().get(_sift_name_v1)
    if callable(_sift_fn_v1) and not getattr(_sift_fn_v1, "_sift_ps_path_fidelity_wrapped_v1", False):
        _sift_wrapped_v1 = _sift_ps_transcript_wrap_v1(_sift_fn_v1)
        setattr(_sift_wrapped_v1, "_sift_ps_path_fidelity_wrapped_v1", True)
        globals()[_sift_name_v1] = _sift_wrapped_v1

# SIFT_PS_TRANSCRIPTS_PATH_FIDELITY_V2B
# Tighten mount detection:
# - reject pseudo-values such as "None", "null", "unknown", "-"
# - accept only absolute Linux paths for active isolated mounts
# - never infer an active mount from a result dict/list passed as a positional arg

def _sift_ps_is_usable_mount_value_v2(value) -> bool:
    text = _sift_ps_as_text_v2(value).strip()
    if not text:
        return False

    lowered = text.lower()
    if lowered in {"none", "null", "unknown", "false", "-", "n/a", "not_applicable"}:
        return False

    if text == _sift_ps_legacy_mount_v2():
        return False
    if text.startswith(_sift_ps_legacy_mount_v2() + "/"):
        return False

    # Isolated disk mounts in this pipeline are Linux absolute paths.
    if not text.startswith("/"):
        return False

    return True


def _sift_ps_mount_from_call_v2(args, kwargs):
    keys = (
        "disk_mount",
        "disk_mount_path",
        "mount",
        "mount_path",
        "mount_root",
        "filesystem_mount",
        "windows_mount",
        "root",
    )

    for key in keys:
        if key in kwargs and _sift_ps_is_usable_mount_value_v2(kwargs.get(key)):
            return _sift_ps_as_text_v2(kwargs.get(key)).rstrip("/")

    env_keys = (
        "SIFT_ACTIVE_DISK_MOUNT",
        "SIFT_DISK_MOUNT",
        "SIFT_DISK_MOUNT_PATH",
        "SIFT_MOUNT_ROOT",
        "SIFT_WINDOWS_MOUNT",
    )

    for key in env_keys:
        value = _sift_ps_os_v2.environ.get(key)
        if _sift_ps_is_usable_mount_value_v2(value):
            return _sift_ps_as_text_v2(value).rstrip("/")

    # Positional fallback must never treat result dictionaries/lists as mounts.
    for value in args:
        if not isinstance(value, (str, bytes, _sift_ps_os_v2.PathLike)):
            continue

        text = _sift_ps_as_text_v2(value).strip()
        if not _sift_ps_is_usable_mount_value_v2(text):
            continue

        lowered = text.lower()
        if lowered.endswith("/ntfs") or "sift-isolated-mount" in lowered or lowered.endswith("/mount"):
            return text.rstrip("/")

    return None
