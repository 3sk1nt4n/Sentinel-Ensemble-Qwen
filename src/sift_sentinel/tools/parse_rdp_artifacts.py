"""
SIFT Sentinel - RDP artifact locator/parser (disk tool, F7-A).

Dataset-agnostic extractor of Remote Desktop Protocol evidence. Emits
*raw evidence records only* -- no findings, no confidence, no attacker
labels, no session reconstruction, no cross-source joining. Each record
represents a single verbatim artifact from a single source;
``user`` / ``host_or_target`` / ``timestamp`` are populated only from
the same record's own fields.

Evidence sources:

- TerminalServices EVTX channels (``include_eventlogs=True``, requires
  python-evtx):
    - ``Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx``
    - ``Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx``
    - ``Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx``
- Default.rdp / ``*.rdp`` profile files under standard user profile
  directories (``include_default_rdp=True``).
- Registry MRU / Servers values (``include_registry=True``). Hive
  parsing requires ``python-registry``; when the library is absent the
  two registry sub-sources report ``library_unavailable`` so that a
  future integration (F7-B) can wire hive walking without schema drift.
  The helper ``normalize_registry_value[s]()`` is exported so callers
  that pre-extract values (e.g. via another tool) can normalize them
  into the same record schema.
- ``recovery_hints`` extracted from arbitrary ``tool_outputs`` envelopes
  for TerminalServices EVTX paths, Default.rdp files, and the canonical
  RDP binary names (mstsc.exe, termsrv.dll, rdpdr.sys, tsclient).

Disk input:

The parser reads from a mounted Windows filesystem (``mount_path``) or,
when only the E01 image is available, from an on-demand extraction via
``pyewf`` + ``pytsk3`` (``disk_image_path``). In E01 mode the three
TerminalServices ``.evtx`` files and each user's ``.rdp`` profiles are
copied read-only into ``staging_dir`` (auto-created tempdir when
``staging_dir`` is ``None``); the staging directory is then treated as
the effective mount. When the E01 libraries are not installed or the
image cannot be opened, the relevant sub-sources report
``library_unavailable`` or ``parse_error`` -- never a crash and never a
fake record.

Bitmap cache parsing (``bcache*.bmc``) is deliberately deferred.

Every sub-source reports its own status via ``sub_source_status`` so the
caller can distinguish "no records because the log didn't exist" from
"no records because python-evtx failed to parse" from "not scanned
because include_* was false". The top-level ``status`` is drawn from the
closed four-state vocabulary:

    - ``no_rdp_artifacts_found``                 records=0, hints=0
    - ``rdp_references_found``                   records=0, hints>0
    - ``rdp_artifacts_parsed``                   records>0, hints=0
    - ``rdp_artifacts_parsed_with_references``   records>0, hints>0

``recovery_hints`` are *pointers* (where to look for wiped or carved RDP
data), not parsed records -- they are kept strictly separate from
``records``.

No shell execution. No writes to evidence (staging_dir is working space
for extracted copies, never the evidence path itself).
"""

from __future__ import annotations

import logging
import re
import tempfile
import threading
from pathlib import Path
from typing import Iterable

from sift_sentinel.config import DISK_MOUNT_PATH

logger = logging.getLogger(__name__)


# ── closed vocabularies (locked contract) ──────────────────────────────

# Top-level envelope status. Mirrors the 4-state pattern used by
# parse_powershell_transcripts: zero/non-zero records crossed with
# zero/non-zero hints.
RDP_STATUSES: frozenset[str] = frozenset({
    "no_rdp_artifacts_found",
    "rdp_references_found",
    "rdp_artifacts_parsed",
    "rdp_artifacts_parsed_with_references",
})

# Allowed ``type`` values on emitted records. Tied one-to-one to an
# extraction path; ``normalize_*`` helpers are the only code paths that
# may assign these.
RDP_RECORD_TYPES: frozenset[str] = frozenset({
    "rdp_session_inbound",   # LSM EIDs 21/22/23/24/25/39/40
    "rdp_auth_event",        # RemoteConnectionManager EID 1149
    "rdp_session_outbound",  # RDPClient Operational client events
    "rdp_mru_entry",         # HKCU\...\Terminal Server Client\Default
    "rdp_server_entry",      # HKCU\...\Terminal Server Client\Servers\X
    "rdp_default_profile",   # Default.rdp / *.rdp text profile
})

# Allowed ``source_kind`` values on records. Deliberately coarse: the
# specific channel / hive / profile name goes into the record's
# ``channel`` or ``registry_key_path`` field, not into source_kind.
RDP_SOURCE_KINDS: frozenset[str] = frozenset({
    "evtx_file",
    "registry_hive",
    "rdp_profile_file",
})

# Allowed ``extraction_method`` values -- how the raw bytes became a
# record. Stable across releases; new methods require a schema bump.
RDP_EXTRACTION_METHODS: frozenset[str] = frozenset({
    "evtx_xml_event_record",
    "registry_value",
    "registry_subkey_values",
    "rdp_profile_directive",
})

# Per-source status reported on the envelope's ``sub_source_status`` map.
# Distinguishes "source not present" from "library missing" from "we
# tried and it raised". ``not_requested`` is used when the caller
# disables a source via ``include_*=False``.
RDP_SUB_SOURCE_STATUSES: frozenset[str] = frozenset({
    "ok",
    "not_found",
    "library_unavailable",
    "parse_error",
    "not_requested",
})

# recovery_hint closed vocabulary -- one type per detection kind, status
# mirrors the type for simple downstream filtering.
RDP_RECOVERY_HINT_TYPES: frozenset[str] = frozenset({
    "rdp_artifact_path_reference",
    "rdp_binary_reference",
})

RDP_RECOVERY_HINT_STATUSES: frozenset[str] = frozenset({
    "path_reference_only",
    "binary_reference_only",
})

# Required fields on every emitted record. Listed in a tuple (not a
# frozenset) so downstream consumers can iterate in a stable order.
RDP_RECORD_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "source_kind",
    "extraction_method",
    "source_file",
    "record_id",
    "raw_excerpt",
    "user",
    "host_or_target",
    "timestamp",
)

# Required fields on every emitted recovery_hint dict.
RDP_RECOVERY_HINT_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "path",
    "binary",
    "source_tool",
    "source_file",
    "raw_excerpt",
    "reason",
)

# Closed set of EVTX channel *kinds* the parser understands. These are
# internal discriminators passed to ``normalize_evtx_event`` -- they are
# NOT ``source_kind`` values. The human-readable Microsoft channel name
# ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
# is emitted on the record's ``channel`` field.
RDP_CHANNEL_KINDS: frozenset[str] = frozenset({
    "local_session_manager",
    "remote_connection_manager",
    "rdp_client_operational",
})

# Sub-source keys reported on ``sub_source_status``. Stable order
# (iterable) for deterministic output. These are diagnostic identifiers,
# not values of ``source_kind``.
RDP_SUB_SOURCE_KEYS: tuple[str, ...] = (
    "evtx_local_session_manager",
    "evtx_remote_connection_manager",
    "evtx_rdp_client",
    "registry_mru",
    "registry_servers",
    "rdp_profile",
)


# ── evtx channel mapping ───────────────────────────────────────────────

# Lower-cased canonical .evtx basenames → channel_kind discriminator.
_EVTX_BASENAME_TO_CHANNEL_KIND: dict[str, str] = {
    ("microsoft-windows-terminalservices-localsessionmanager"
     "%4operational.evtx"):
        "local_session_manager",
    ("microsoft-windows-terminalservices-remoteconnectionmanager"
     "%4operational.evtx"):
        "remote_connection_manager",
    ("microsoft-windows-terminalservices-rdpclient"
     "%4operational.evtx"):
        "rdp_client_operational",
}

# channel_kind → closed-vocab record type.
_CHANNEL_KIND_TO_RECORD_TYPE: dict[str, str] = {
    "local_session_manager": "rdp_session_inbound",
    "remote_connection_manager": "rdp_auth_event",
    "rdp_client_operational": "rdp_session_outbound",
}

# channel_kind → human-readable channel name used on the record.
_CHANNEL_KIND_TO_CHANNEL_NAME: dict[str, str] = {
    "local_session_manager": (
        "Microsoft-Windows-TerminalServices-"
        "LocalSessionManager/Operational"
    ),
    "remote_connection_manager": (
        "Microsoft-Windows-TerminalServices-"
        "RemoteConnectionManager/Operational"
    ),
    "rdp_client_operational": (
        "Microsoft-Windows-TerminalServices-RDPClient/Operational"
    ),
}

# channel_kind → sub_source_status key used in the envelope.
_CHANNEL_KIND_TO_SUB_SOURCE_KEY: dict[str, str] = {
    "local_session_manager": "evtx_local_session_manager",
    "remote_connection_manager": "evtx_remote_connection_manager",
    "rdp_client_operational": "evtx_rdp_client",
}

# channel_kind → closed whitelist of EventIDs that produce records.
# Events outside the whitelist are dropped (honest "we can't classify
# this" rather than a fake record). Per BRAIN-approved F7 design.
_CHANNEL_KIND_EID_WHITELIST: dict[str, frozenset[int]] = {
    "local_session_manager": frozenset({21, 22, 23, 24, 25, 39, 40}),
    "remote_connection_manager": frozenset({1149}),
    # RDPClient Operational client events: connect (1024), connect
    # established (1025), disconnect (1026), domain connected (1027),
    # domain disconnected (1028), user-hash (1029), multi-transport
    # init (1102), multi-transport connected (1103), multi-transport
    # disconnected (1105). Narrow enough to avoid misclassifying the
    # rarer non-client RDPClient events; broad enough to cover the
    # standard client session lifecycle.
    "rdp_client_operational": frozenset({
        1024, 1025, 1026, 1027, 1028, 1029, 1102, 1103, 1105,
    }),
}

# Priority lists for extracting user / host_or_target from EventData.
# Order matters -- first non-empty wins. Dataset-agnostic: these are the
# standard Microsoft EventData field names published in the Windows event
# schema, not scenario-specific tokens.
_EVTX_USER_KEYS: tuple[str, ...] = (
    "User",
    "TargetUserName",
    "UserName",
    "AccountName",
)

# Inbound RDP (LSM / RCM) publishes the remote client address in
# ``Source Network Address`` / ``SourceAddr`` / ``ClientAddress``.
# Outbound RDP (RDPClient) publishes the destination in
# ``ConnectionName`` / ``Name`` / ``DestinationName``.
_EVTX_HOST_KEYS: tuple[str, ...] = (
    "Source Network Address",
    "SourceAddr",
    "ClientAddress",
    "ClientIP",
    "ConnectionName",
    "Name",
    "DestinationName",
    "Address",
)


# ── registry key path classification ───────────────────────────────────

# The Terminal Server Client registry tree lives at
# HKCU\Software\Microsoft\Terminal Server Client\. We match
# case-insensitively on the trailing path suffix (so both HKCU-qualified
# and hive-relative key paths work).
_REG_MRU_KEY_SUFFIX = (
    "software/microsoft/terminal server client/default"
)
_REG_SERVERS_KEY_PREFIX = (
    "software/microsoft/terminal server client/servers"
)


# ── .rdp profile directives of interest ────────────────────────────────

# Directives whose value identifies user / host_or_target. Lower-case
# match; the profile file format permits any casing in practice.
_RDP_HOST_DIRECTIVES: tuple[str, ...] = (
    "full address",
    "alternate full address",
    "gatewayhostname",
    "loadbalanceinfo",
)
_RDP_USER_DIRECTIVES: tuple[str, ...] = (
    "username",
    "domain",
)


# ── recovery_hint patterns ─────────────────────────────────────────────

# Generic TerminalServices EVTX basename pattern (any channel, any
# suffix). Anchored on the literal "Microsoft-Windows-TerminalServices-"
# provider prefix + the standard %4Operational / %4Admin suffix shape.
_TERMINALSERVICES_BASENAME_RE = re.compile(
    r"\bMicrosoft-Windows-TerminalServices-[A-Za-z]+"
    r"(?:%4[A-Za-z]+)?\.evtx\b",
    re.IGNORECASE,
)

# A path-like substring ending in a TerminalServices EVTX basename.
_TERMINALSERVICES_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/]|[\\/])"
    r"(?:[^\s\"'<>|*?\r\n,;]+[\\/])*"
    r"Microsoft-Windows-TerminalServices-[A-Za-z]+"
    r"(?:%4[A-Za-z]+)?\.evtx",
    re.IGNORECASE,
)

# .rdp profile file basename / path.
_RDP_PROFILE_BASENAME_RE = re.compile(
    r"\b[A-Za-z0-9_\-. ]+\.rdp\b",
)
_RDP_PROFILE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/]|[\\/])"
    r"(?:[^\s\"'<>|*?\r\n,;]+[\\/])*"
    r"[A-Za-z0-9_\-. ]+\.rdp",
)

# Canonical RDP binary / UNC-root token names. Generic and dataset-
# agnostic -- every one is shipped as part of stock Windows.
_RDP_BINARY_TOKENS: tuple[str, ...] = (
    "mstsc.exe",
    "termsrv.dll",
    "rdpdr.sys",
    "tsclient",  # UNC root used for RDP drive redirection
)

# Volatility 3 stamps file paths with a ``\Device\HarddiskVolumeN\``
# prefix we strip from the canonical / normalized form.
_DEVICE_PREFIX_RE = re.compile(
    r"^/Device/HarddiskVolume\d+",
    re.IGNORECASE,
)

# Fields on arbitrary tool records that may carry a path / binary name.
# Unknown shapes are simply ignored.
_RECOVERY_FIELDS: tuple[str, ...] = (
    "Name", "name",
    "FilePath", "filepath", "FullPath", "fullpath", "Path", "path",
    "Image", "ImageFileName", "image",
    "Args", "args", "Arguments", "arguments",
    "CommandLine", "commandline", "command_line",
    "Message", "message",
    "Description", "description",
    "Value", "value",
)


# ── search policy for disk walk ────────────────────────────────────────

# .evtx files live under Windows\System32\winevt\Logs only. We hardcode
# the exact path so the walk is fast; the three TerminalServices logs
# have stable basenames across supported Windows versions.
_EVTX_RELATIVE_DIR = ("Windows", "System32", "winevt", "Logs")

# .rdp profiles commonly live in these user subdirs. The Default.rdp
# file created by mstsc.exe sits at Documents\Default.rdp by default.
_RDP_USER_SUBDIRS: tuple[str, ...] = (
    "Documents",
    "Desktop",
    "Downloads",
    "AppData/Local/Microsoft/Terminal Server Client",
    "AppData/Roaming/Microsoft/Terminal Server Client",
)

# Top-level directories to scan outside Users/ for shared .rdp profiles.
_RDP_TOP_DIRS: tuple[str, ...] = (
    "ProgramData",
    "Program Files/Microsoft/Terminal Server Client",
    "Program Files (x86)/Microsoft/Terminal Server Client",
)

# Bounded walk depth below each search root.
_MAX_WALK_DEPTH = 6

# Per-EVTX-file parse timeout. Matches parse_event_logs' budget.
_EVTX_PER_FILE_TIMEOUT_S = 10


# ── misc helpers ───────────────────────────────────────────────────────

def _short_excerpt(text: str, limit: int = 200) -> str:
    """Return a single-line, length-limited preview of *text*."""
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."


def _normalize_slashes(value: str) -> str:
    """Normalize a path-shaped string to forward slashes and strip a
    leading ``\\Device\\HarddiskVolumeN\\`` prefix. Drive letters are
    preserved; UNC prefixes become ``//host/...``."""
    if not value:
        return ""
    norm = value.replace("\\", "/")
    return _DEVICE_PREFIX_RE.sub("", norm)


def _user_from_path(path: str) -> str | None:
    """Pull a username out of ``.../Users/<name>/...`` style paths."""
    if not path:
        return None
    norm = path.replace("\\", "/")
    parts = norm.split("/")
    for i, segment in enumerate(parts):
        if segment.lower() == "users" and i + 1 < len(parts):
            candidate = parts[i + 1]
            if candidate and candidate.lower() != "public":
                return candidate
    return None


def _record_field_value(rec: dict, key: str) -> str | None:
    """Return ``rec[key]`` if it is a non-empty string; else None."""
    value = rec.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _pick_first(fields: dict, keys: Iterable[str]) -> str | None:
    """Return the first non-empty string value in *fields* keyed by
    *keys*. Keys are tried in order; matching is case-sensitive then
    case-insensitive. Returns None if no match."""
    if not isinstance(fields, dict):
        return None
    for k in keys:
        v = fields.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    lowered = {
        k.lower(): v for k, v in fields.items()
        if isinstance(k, str)
    }
    for k in keys:
        v = lowered.get(k.lower())
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


# ── public helper: evtx event normalization ────────────────────────────

_RDP_HOST_SHAPE_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}"
    r"|[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+)$"
)


def _looks_like_host(token: str | None) -> bool:
    """True when *token* is shaped like an IPv4 address or a dotted
    hostname/FQDN (no whitespace).

    Used to distinguish a real RDP target value from a descriptive EventData
    field label. Dataset-agnostic: keys on token shape only, never on specific
    host values.
    """
    tok = (token or "").strip()
    return bool(tok) and " " not in tok and bool(_RDP_HOST_SHAPE_RE.match(tok))


def normalize_evtx_event(
    event: dict,
    channel_kind: str,
    source_file: str,
    record_id: str | None = None,
) -> dict | None:
    """Normalize a parsed EVTX event dict into an RDP record.

    *event* is expected to resemble the parsed XML structure:

        {
            "EventID":        int | str,
            "TimeCreated":    str,              # SystemTime attribute
            "Channel":        str,              # optional (overrides
                                                #   the canonical channel
                                                #   name on the record)
            "Provider":       str,              # optional
            "Computer":       str,              # optional
            "EventRecordID":  int | str,        # optional, stable id
            "EventData":      {field: value},   # optional
            "raw_xml":        str,              # optional
        }

    *channel_kind* is the internal discriminator identifying which
    TerminalServices channel the event came from; it must be one of
    ``RDP_CHANNEL_KINDS`` (``local_session_manager`` /
    ``remote_connection_manager`` / ``rdp_client_operational``). The
    human-readable Microsoft channel name is written to the record's
    ``channel`` field, *not* to ``source_kind`` (per the approved F7
    schema, ``source_kind`` is always ``"evtx_file"`` here).

    Events whose ``EventID`` is not in the channel's closed whitelist
    (see ``_CHANNEL_KIND_EID_WHITELIST``) are dropped -- the parser
    never emits a record it cannot classify. Unrecognized *channel_kind*
    values, non-dict inputs, and events with missing / non-integer
    EventID all return ``None``.

    Returns a record dict conforming to ``RDP_RECORD_REQUIRED_FIELDS``
    (closed vocab on ``type``, ``source_kind``, ``extraction_method``)
    or ``None``. ``user`` / ``host_or_target`` / ``timestamp`` are set
    only from the event's own verbatim fields -- no cross-event joining.
    """
    if not isinstance(event, dict):
        return None
    if channel_kind not in _CHANNEL_KIND_TO_RECORD_TYPE:
        return None

    event_id_raw = event.get("EventID")
    try:
        event_id = int(event_id_raw) if event_id_raw is not None else None
    except (TypeError, ValueError):
        event_id = None

    whitelist = _CHANNEL_KIND_EID_WHITELIST.get(channel_kind, frozenset())
    if event_id is None or event_id not in whitelist:
        return None

    timestamp = event.get("TimeCreated")
    if isinstance(timestamp, str) and timestamp.strip():
        timestamp = timestamp.strip()
    else:
        timestamp = None

    event_data = event.get("EventData")
    if not isinstance(event_data, dict):
        event_data = {}

    user = _pick_first(event_data, _EVTX_USER_KEYS)
    host_or_target = _pick_first(event_data, _EVTX_HOST_KEYS)
    # RDPClient ClientActiveXCore events use a Name/Value idiom: the host label
    # ("Server Name"/"ServerAddress") lands in Name (matched by _EVTX_HOST_KEYS)
    # and the real destination in Value. When the picked host is that
    # descriptive Name label and Value is host-shaped, prefer Value so the
    # outbound lateral-movement target is captured instead of the field label.
    _name_field = event_data.get("Name")
    _value_field = event_data.get("Value")
    if (
        isinstance(_name_field, str)
        and isinstance(_value_field, str)
        and host_or_target == _name_field.strip()
        and _looks_like_host(_value_field)
    ):
        host_or_target = _value_field.strip()

    # record_id: explicit > EventRecordID > fallback stable composite.
    # Use channel_kind as the discriminator prefix so the same
    # EventRecordID across different channels produces different ids.
    if record_id is None:
        err_id = event.get("EventRecordID")
        if err_id is not None and str(err_id).strip():
            record_id = f"{channel_kind}:{err_id}"
        else:
            record_id = (
                f"{channel_kind}:"
                f"{event_id}:"
                f"{timestamp or 'X'}"
            )

    # raw_excerpt: prefer raw_xml, else a deterministic flatten of
    # EventID / TimeCreated / EventData pairs.
    raw_xml = event.get("raw_xml")
    if isinstance(raw_xml, str) and raw_xml.strip():
        excerpt = _short_excerpt(raw_xml, limit=200)
    else:
        parts: list[str] = []
        if event_id is not None:
            parts.append(f"EventID={event_id}")
        if timestamp:
            parts.append(f"TimeCreated={timestamp}")
        for k in sorted(event_data):
            v = event_data[k]
            if isinstance(v, (str, int, float, bool)):
                parts.append(f"{k}={v}")
        excerpt = _short_excerpt(" ".join(parts), limit=200)

    channel_name = _CHANNEL_KIND_TO_CHANNEL_NAME[channel_kind]
    channel_override = event.get("Channel")
    if isinstance(channel_override, str) and channel_override.strip():
        channel_name = channel_override.strip()

    provider = event.get("Provider")
    computer = event.get("Computer")

    return {
        "type": _CHANNEL_KIND_TO_RECORD_TYPE[channel_kind],
        "source_kind": "evtx_file",
        "extraction_method": "evtx_xml_event_record",
        "source_file": str(source_file or ""),
        "record_id": str(record_id),
        "raw_excerpt": excerpt,
        "user": user,
        "host_or_target": host_or_target,
        "timestamp": timestamp,
        "event_id": event_id,
        "channel": channel_name,
        "provider": provider if isinstance(provider, str) else None,
        "computer": computer if isinstance(computer, str) else None,
    }


# ── public helper: rdp profile parsing ─────────────────────────────────

# .rdp lines have the shape "<key>:<type>:<value>" where <type> is one
# of s / i / b. We deliberately accept any <key> characters (including
# spaces and hyphens).
_RDP_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9 _\-]+):([sib]):(.*)$",
)


def parse_rdp_profile_text(
    text: str,
    source_file: str,
    record_id: str | None = None,
) -> dict | None:
    """Parse a .rdp profile text blob into a single ``rdp_default_profile``
    record.

    Returns ``None`` if *text* contains no recognizable RDP directive.
    One record per profile file (not per directive) -- this keeps the
    noise proportional to the number of profiles, not the number of
    generic layout lines.

    ``user`` is populated from the ``username`` directive; ``domain`` is
    recorded in ``profile_directives`` but does not move into ``user``
    (those are separate verbatim fields on the profile and joining them
    would be synthesis).

    ``host_or_target`` is populated from the first host-bearing directive
    in ``_RDP_HOST_DIRECTIVES`` that is present. ``timestamp`` is ``None``
    -- .rdp files do not carry a connection timestamp; file mtime is
    *not* a verbatim field of the record and is intentionally omitted.
    """
    if not isinstance(text, str):
        return None

    directives: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        m = _RDP_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        dtype = m.group(2)
        value = m.group(3).rstrip("\r").strip()
        if not key:
            continue
        # First occurrence wins; duplicates in .rdp files are rare and
        # the first is typically authoritative.
        directives.setdefault(key, {"type": dtype, "value": value})

    if not directives:
        return None

    host_value: str | None = None
    for key in _RDP_HOST_DIRECTIVES:
        entry = directives.get(key)
        if entry and entry.get("value"):
            host_value = entry["value"]
            break

    user_value: str | None = None
    entry = directives.get("username")
    if entry and entry.get("value"):
        user_value = entry["value"]

    if record_id is None:
        record_id = f"rdp_default_profile:{source_file}"

    # Compact directives view for the raw_excerpt: key=value pairs, sorted.
    pairs = sorted(
        f"{k}={directives[k]['value']}" for k in directives
    )
    excerpt = _short_excerpt(" ".join(pairs), limit=200)

    return {
        "type": "rdp_default_profile",
        "source_kind": "rdp_profile_file",
        "extraction_method": "rdp_profile_directive",
        "source_file": str(source_file or ""),
        "record_id": str(record_id),
        "raw_excerpt": excerpt,
        "user": user_value,
        "host_or_target": host_value,
        "timestamp": None,
        "profile_directives": {
            k: v["value"] for k, v in directives.items()
        },
    }


# ── public helper: registry value normalization ────────────────────────

def _classify_registry_key(key_path: str) -> tuple[str, str, str] | None:
    """Return (record_type, extraction_method, sub_source_key) for a key
    path, or None if the key isn't an RDP Terminal Server Client key.

    Matches case-insensitively on the trailing suffix so HKCU- or
    hive-rooted paths both work. ``source_kind`` is always
    ``"registry_hive"`` on the emitted record -- it is not returned
    here because it does not vary per key.
    """
    if not isinstance(key_path, str) or not key_path.strip():
        return None
    norm = key_path.replace("\\", "/").lower().strip("/")
    # Strip leading HKCU\ / HKEY_CURRENT_USER\ so matching works on
    # the hive-relative tail.
    for prefix in (
        "hkey_current_user/",
        "hkcu/",
        "hkey_users/",
        "hku/",
    ):
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
            break
    # Some hive parsers include the SID / .DEFAULT root; strip one
    # path component if it starts with "s-" (SID).
    first, _, rest = norm.partition("/")
    if first.startswith("s-") and rest:
        norm = rest
    if norm.endswith(_REG_MRU_KEY_SUFFIX):
        return (
            "rdp_mru_entry",
            "registry_value",
            "registry_mru",
        )
    if _REG_SERVERS_KEY_PREFIX in norm:
        return (
            "rdp_server_entry",
            "registry_subkey_values",
            "registry_servers",
        )
    return None


def normalize_registry_value(
    entry: dict,
    source_file: str = "",
    record_id: str | None = None,
) -> dict | None:
    """Normalize a single pre-extracted registry value into an RDP record.

    *entry* shape (all string values, all fields optional except
    ``key_path``):

        {
            "key_path":     str,   # full hive-relative key path
            "value_name":   str,   # e.g. "MRU0", "UsernameHint"
            "value_data":   str,   # value contents (coerced to str)
            "subkey_name":  str,   # for Servers subkey: the server name
            "hive_file":    str,   # optional path of the source hive
            "timestamp":    str,   # optional, from the key's LastWrite time
        }

    Returns a record conforming to ``RDP_RECORD_REQUIRED_FIELDS`` or
    ``None`` when the key path is not an RDP Terminal Server Client key.
    ``host_or_target`` / ``user`` are extracted from the entry's own
    verbatim fields:

      - MRU: ``host_or_target`` = ``value_data``, ``user`` = None.
      - Servers: ``host_or_target`` = ``subkey_name``; if
        ``value_name`` == ``UsernameHint`` the value_data fills ``user``.

    No cross-lookups between MRU and Servers records.
    """
    if not isinstance(entry, dict):
        return None
    key_path = entry.get("key_path")
    classification = _classify_registry_key(key_path or "")
    if classification is None:
        return None
    record_type, extraction_method, _sub_source_key = classification

    value_name = entry.get("value_name") or ""
    value_data = entry.get("value_data")
    if value_data is not None and not isinstance(value_data, str):
        value_data = str(value_data)
    value_data = value_data or ""
    subkey_name = entry.get("subkey_name") or ""
    hive_file = entry.get("hive_file") or source_file or ""
    timestamp = entry.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        timestamp = None
    else:
        timestamp = timestamp.strip()

    user: str | None = None
    host_or_target: str | None = None

    if record_type == "rdp_mru_entry":
        host_or_target = value_data.strip() or None
    elif record_type == "rdp_server_entry":
        host_or_target = (subkey_name or "").strip() or None
        if value_name.lower() == "usernamehint" and value_data.strip():
            user = value_data.strip()

    if record_id is None:
        seed_parts = [record_type]
        if subkey_name:
            seed_parts.append(subkey_name)
        if value_name:
            seed_parts.append(value_name)
        if not subkey_name and not value_name:
            seed_parts.append(value_data[:32])
        record_id = ":".join(s for s in seed_parts if s)

    excerpt = _short_excerpt(
        f"{key_path}\\{value_name}={value_data}"
        + (f" (subkey={subkey_name})" if subkey_name else ""),
        limit=200,
    )

    return {
        "type": record_type,
        "source_kind": "registry_hive",
        "extraction_method": extraction_method,
        "source_file": str(hive_file),
        "record_id": str(record_id),
        "raw_excerpt": excerpt,
        "user": user,
        "host_or_target": host_or_target,
        "timestamp": timestamp,
        "registry_key_path": key_path,
        "registry_value_name": value_name or None,
        "registry_value_data": value_data or None,
        "registry_subkey_name": subkey_name or None,
    }


def normalize_registry_values(
    entries: list[dict] | None,
    source_file: str = "",
) -> list[dict]:
    """Normalize a list of pre-extracted registry values into records.

    Entries not matching an RDP key are silently dropped (a None record
    just means "not our key"). Ordering follows input order to keep the
    caller's provenance intact; callers that want deterministic output
    should sort their input.
    """
    if not isinstance(entries, list):
        return []
    out: list[dict] = []
    for entry in entries:
        rec = normalize_registry_value(entry, source_file=source_file)
        if rec is not None:
            out.append(rec)
    return out


# ── recovery_hints ─────────────────────────────────────────────────────

def _build_path_hint(
    tool_name: str,
    source_file: str,
    raw_value: str,
    path: str,
) -> dict:
    """Build a closed-schema ``rdp_artifact_path_reference`` hint."""
    return {
        "type": "rdp_artifact_path_reference",
        "status": "path_reference_only",
        "path": _normalize_slashes(path),
        "binary": None,
        "source_tool": tool_name,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(raw_value, limit=200),
        "reason": "RDP artifact path referenced in tool output",
    }


def _build_binary_hint(
    tool_name: str,
    source_file: str,
    raw_value: str,
    binary: str,
) -> dict:
    """Build a closed-schema ``rdp_binary_reference`` hint."""
    return {
        "type": "rdp_binary_reference",
        "status": "binary_reference_only",
        "path": None,
        "binary": binary,
        "source_tool": tool_name,
        "source_file": source_file,
        "raw_excerpt": _short_excerpt(raw_value, limit=200),
        "reason": "RDP binary / client token referenced in tool output",
    }


def _extract_paths(value: str) -> list[str]:
    """Return path-like substrings that reference RDP artifacts."""
    if not value:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for regex in (_TERMINALSERVICES_PATH_RE, _RDP_PROFILE_PATH_RE):
        for m in regex.finditer(value):
            s = m.group(0)
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
    if out:
        return out
    # Fallback: bare basenames when no path context is present.
    for regex in (_TERMINALSERVICES_BASENAME_RE, _RDP_PROFILE_BASENAME_RE):
        for m in regex.finditer(value):
            s = m.group(0)
            key = s.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
    return out


def _extract_binaries(value: str) -> list[str]:
    """Return RDP binary/token names present in *value*. Matches are
    case-insensitive; returns the canonical token form."""
    if not value:
        return []
    lowered = value.lower()
    out: list[str] = []
    for token in _RDP_BINARY_TOKENS:
        if token in lowered and token not in out:
            out.append(token)
    return out


def _hints_from_tool_envelope(tool_name: str, env: dict) -> list[dict]:
    """Extract recovery_hints from one tool result envelope."""
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
        for field in _RECOVERY_FIELDS:
            raw_value = _record_field_value(rec, field)
            if raw_value is None:
                continue
            paths = _extract_paths(raw_value)
            if not paths:
                continue
            for path in paths:
                hints.append(
                    _build_path_hint(
                        tool_name, source_file, raw_value, path,
                    )
                )
                path_emitted = True
            break
        if path_emitted:
            continue
        # No path in this record -- check for binary references.
        for field in _RECOVERY_FIELDS:
            raw_value = _record_field_value(rec, field)
            if raw_value is None:
                continue
            binaries = _extract_binaries(raw_value)
            if not binaries:
                continue
            for binary in binaries:
                hints.append(
                    _build_binary_hint(
                        tool_name, source_file, raw_value, binary,
                    )
                )
            break
    return hints


def find_rdp_recovery_hints(
    tool_outputs: dict | None,
) -> list[dict]:
    """Scan tool result envelopes for RDP-related references.

    *tool_outputs* maps ``tool_name`` -> tool result envelope dict.
    Returns a sorted, deduplicated list of recovery_hint dicts following
    the closed F7-A schema:

        type, status, path, binary, source_tool, source_file,
        raw_excerpt, reason

    Detection is dataset-agnostic: it matches only on the generic
    Microsoft-Windows-TerminalServices- EVTX basename shape, the
    ``.rdp`` extension, and the canonical RDP binary / client token
    names (``mstsc.exe``, ``termsrv.dll``, ``rdpdr.sys``, ``tsclient``).
    Hostnames / IPs / usernames from tool records are *not* surfaced as
    hints -- those are only emitted as parsed record fields when a real
    record exists.
    """
    if not isinstance(tool_outputs, dict) or not tool_outputs:
        return []
    raw: list[dict] = []
    for tool_name in sorted(tool_outputs):
        raw.extend(
            _hints_from_tool_envelope(tool_name, tool_outputs[tool_name])
        )
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict] = []
    for h in raw:
        key = (
            h.get("source_tool") or "",
            h.get("type") or "",
            (h.get("path") or "").lower(),
            (h.get("binary") or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    deduped.sort(
        key=lambda h: (
            (h.get("path") or "").lower(),
            (h.get("binary") or "").lower(),
            h.get("source_tool") or "",
            h.get("type") or "",
        )
    )
    return deduped


# ── disk walk: .rdp profile files ──────────────────────────────────────

def _build_rdp_profile_search_roots(disk_path: Path) -> list[Path]:
    """Return the deduplicated list of *existing* directories to scan
    for .rdp profiles."""
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

    users_dir = disk_path / "Users"
    if users_dir.is_dir():
        try:
            user_entries = sorted(
                p for p in users_dir.iterdir() if p.is_dir()
            )
        except (OSError, PermissionError) as exc:
            logger.warning(
                "rdp_artifacts: cannot list Users/: %s", exc,
            )
            user_entries = []
        for user_dir in user_entries:
            for sub in _RDP_USER_SUBDIRS:
                _add(user_dir / sub)

    for top in _RDP_TOP_DIRS:
        _add(disk_path / top)

    return roots


def _walk_rdp_profile_candidates(
    roots: Iterable[Path],
    *,
    max_files: int,
    errors: list[str],
) -> list[Path]:
    """Walk *roots* (bounded depth) and collect ``*.rdp`` files.

    31AG: walk with os.walk + an onerror hook so an unreadable directory on an
    incomplete or force-mounted image (OSError/EIO/EOVERFLOW during scandir) is
    logged and skipped instead of propagating out of a lazy rglob iterator and
    aborting the whole tool -- one bad path must not zero the entire RDP domain.
    Bounded depth, .rdp filter and dedup are unchanged; per-entry resolve() I/O
    is dropped (pure-path relative_to) to avoid a second EIO source.
    Dataset-agnostic: reacts only to I/O errors and the .rdp suffix.
    """
    import os
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if len(out) >= max_files:
            break
        root_str = str(root)

        def _walk_onerror(exc: OSError, _r: str = root_str) -> None:
            errors.append(f"walk {getattr(exc, 'filename', _r)}: {exc}")

        for dirpath, _dirnames, filenames in _sift_rdp_safe_oswalk_v1(root, _walk_onerror):
            if len(out) >= max_files:
                break
            for fn in filenames:
                if len(out) >= max_files:
                    break
                if not fn.lower().endswith(".rdp"):
                    continue
                entry = Path(dirpath) / fn
                try:
                    rel = entry.relative_to(root_str)
                except (OSError, ValueError):
                    continue
                if len(rel.parts) > _MAX_WALK_DEPTH:
                    continue
                key = str(entry).lower()
                if key in seen:
                    continue
                seen.add(key)
                out.append(entry)
    out.sort(key=lambda p: str(p))
    return out


def _sift_rdp_safe_oswalk_v1(root, onerror):
    """SIFT_RDP_SAFE_OSWALK_V1: os.walk wrapper that also swallows an OSError
    escaping the walk generator itself (ntfs-3g EIO surfacing mid-iteration
    under concurrent mount access), not only scandir errors os.walk routes to
    onerror. Ends the walk gracefully so the caller never sees an uncaught
    OSError. Dataset-agnostic; no case-specific values.
    """
    import os as _os
    _it = _os.walk(root, onerror=onerror)
    while True:
        try:
            _entry = next(_it)
        except StopIteration:
            return
        except OSError as _exc:
            if callable(onerror):
                onerror(_exc)
            return
        yield _entry


def _parse_rdp_profile_file(
    path: Path,
    *,
    max_bytes: int,
    errors: list[str],
) -> dict | None:
    """Read and parse one .rdp file into a profile record (or None)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        errors.append(f"stat {path}: {exc}")
        return None
    if size <= 0:
        return None
    if size > max_bytes:
        errors.append(f"skip oversize {path} (>{max_bytes} bytes)")
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except (OSError, PermissionError) as exc:
        errors.append(f"read {path}: {exc}")
        return None
    # Try utf-16 (BOM-aware), then utf-8, then latin-1. mstsc.exe
    # traditionally writes UTF-16-LE .rdp files, but user-edited ones
    # are often UTF-8.
    text: str | None = None
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = None
    if text is None and raw[:3] == b"\xef\xbb\xbf":
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = None
    if text is None:
        for enc in ("utf-8", "utf-16-le", "latin-1"):
            try:
                text = raw.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                text = None
    if text is None:
        errors.append(f"decode failed {path}")
        return None
    return parse_rdp_profile_text(text, str(path))


# ── disk walk: TerminalServices .evtx files ────────────────────────────

def _resolve_evtx_dir(disk_path: Path) -> Path:
    return disk_path.joinpath(*_EVTX_RELATIVE_DIR)


def _find_rdp_evtx_files(disk_path: Path) -> dict[str, Path | None]:
    """Return a mapping of channel_kind -> resolved .evtx path (or None).

    The search is case-insensitive on the basename so Windows' mixed-
    case volume presentations don't cause false negatives.
    """
    evtx_dir = _resolve_evtx_dir(disk_path)
    result: dict[str, Path | None] = {
        kind: None for kind in _EVTX_BASENAME_TO_CHANNEL_KIND.values()
    }
    if not evtx_dir.is_dir():
        return result
    try:
        entries = list(evtx_dir.iterdir())
    except (OSError, PermissionError):
        return result
    # Build case-insensitive basename → Path map.
    by_lower: dict[str, Path] = {}
    for entry in entries:
        try:
            if entry.is_file() and entry.suffix.lower() == ".evtx":
                by_lower[entry.name.lower()] = entry
        except OSError:
            continue
    for basename_lower, channel_kind in (
        _EVTX_BASENAME_TO_CHANNEL_KIND.items()
    ):
        match = by_lower.get(basename_lower)
        if match is not None:
            result[channel_kind] = match
    return result


def _parse_rdp_evtx_file(
    path: Path,
    channel_kind: str,
    *,
    max_records: int,
    errors: list[str],
) -> tuple[list[dict], str]:
    """Parse one TerminalServices .evtx file.

    Returns (records, sub_source_status) where sub_source_status is one
    of ``RDP_SUB_SOURCE_STATUSES``.
    """
    try:
        import Evtx.Evtx as evtx_mod  # noqa: F401
    except ImportError:
        return [], "library_unavailable"

    import xml.etree.ElementTree as ET

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    file_records: list[dict] = []
    exc_holder: list[BaseException] = []

    def _parse_one() -> None:
        try:
            import Evtx.Evtx as evtx  # type: ignore[import-not-found]
            with evtx.Evtx(str(path)) as log:
                for record in log.records():
                    if len(file_records) >= max_records:
                        break
                    try:
                        root = ET.fromstring(record.xml())
                    except ET.ParseError:
                        continue
                    system = root.find("e:System", ns)
                    if system is None:
                        continue
                    eid_el = system.find("e:EventID", ns)
                    time_el = system.find("e:TimeCreated", ns)
                    prov_el = system.find("e:Provider", ns)
                    chan_el = system.find("e:Channel", ns)
                    comp_el = system.find("e:Computer", ns)
                    rec_el = system.find("e:EventRecordID", ns)

                    event_data: dict[str, str] = {}
                    ed_node = root.find("e:EventData", ns)
                    if ed_node is not None:
                        for data_el in ed_node.findall("e:Data", ns):
                            name = data_el.get("Name") or ""
                            text = data_el.text or ""
                            if name and name not in event_data:
                                event_data[name] = text

                    event = {
                        "EventID": (
                            int(eid_el.text)
                            if eid_el is not None
                            and eid_el.text
                            and eid_el.text.isdigit()
                            else None
                        ),
                        "TimeCreated": (
                            time_el.get("SystemTime", "")
                            if time_el is not None else ""
                        ),
                        "Provider": (
                            prov_el.get("Name", "")
                            if prov_el is not None else ""
                        ),
                        "Channel": (
                            chan_el.text if chan_el is not None else ""
                        ),
                        "Computer": (
                            comp_el.text if comp_el is not None else ""
                        ),
                        "EventRecordID": (
                            rec_el.text if rec_el is not None else None
                        ),
                        "EventData": event_data,
                    }
                    normalized = normalize_evtx_event(
                        event, channel_kind, str(path),
                    )
                    if normalized is not None:
                        file_records.append(normalized)
        except BaseException as exc:  # noqa: BLE001
            exc_holder.append(exc)

    t = threading.Thread(target=_parse_one, daemon=True)
    t.start()
    t.join(timeout=_EVTX_PER_FILE_TIMEOUT_S)

    if t.is_alive():
        errors.append(
            f"evtx timeout after {_EVTX_PER_FILE_TIMEOUT_S}s: {path}"
        )
        return [], "parse_error"
    if exc_holder:
        errors.append(
            f"evtx parse error {path}: "
            f"{type(exc_holder[0]).__name__}: "
            f"{str(exc_holder[0])[:120]}"
        )
        return [], "parse_error"

    return file_records, "ok"


# ── status resolution ──────────────────────────────────────────────────

def _resolve_envelope_status(
    records: list[dict],
    recovery_hints: list[dict],
) -> str:
    has_records = bool(records)
    has_hints = bool(recovery_hints)
    if has_records and has_hints:
        return "rdp_artifacts_parsed_with_references"
    if has_records:
        return "rdp_artifacts_parsed"
    if has_hints:
        return "rdp_references_found"
    return "no_rdp_artifacts_found"


# ── E01 extraction (pyewf + pytsk3) ────────────────────────────────────

# Relative NTFS paths to extract. Backslash form matches pytsk3's
# directory walk semantics; we normalize to forward slashes before
# writing into staging_dir.
_E01_EVTX_FS_PATHS: tuple[str, ...] = tuple(
    "/Windows/System32/winevt/Logs/" + basename
    for basename in (
        "Microsoft-Windows-TerminalServices-"
        "LocalSessionManager%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-"
        "RemoteConnectionManager%4Operational.evtx",
        "Microsoft-Windows-TerminalServices-"
        "RDPClient%4Operational.evtx",
    )
)


def _prepare_e01_staging(
    disk_image_path: str,
    staging_dir: str | None,
    max_rdp_files_per_user: int,
    include_eventlogs: bool,
    include_default_rdp: bool,
    errors: list[str],
) -> tuple[Path | None, str | None]:
    """Extract RDP-relevant files from an E01 image into staging_dir.

    Returns ``(effective_mount_path, error_reason)``. On success
    ``error_reason`` is None. On failure the mount path is None and
    ``error_reason`` is one of:

        - ``"not_found"``        -- E01 file missing
        - ``"library_unavailable"`` -- pyewf or pytsk3 not importable
        - ``"open_error"``       -- pyewf/pytsk3 could not open image
        - ``"fs_error"``         -- no NTFS volume located
        - ``"parse_error"``      -- file walk / copy failure

    Only the specific TerminalServices ``.evtx`` files and per-user
    ``.rdp`` profiles are extracted; hives and unrelated files are never
    touched. When both ``include_eventlogs`` and ``include_default_rdp``
    are False we still succeed with an empty staging directory so that
    the caller can exercise other sources (registry, recovery_hints).
    """
    e01_path = Path(disk_image_path)
    if not e01_path.is_file():
        errors.append(f"E01 image not found: {disk_image_path}")
        return None, "not_found"

    try:
        import pyewf  # type: ignore[import-not-found]
        import pytsk3  # type: ignore[import-not-found]
    except ImportError as exc:
        errors.append(
            f"E01 libraries unavailable: {type(exc).__name__}: {exc}"
        )
        return None, "library_unavailable"

    if staging_dir is None:
        staging = Path(tempfile.mkdtemp(prefix="rdp_artifacts_e01_"))
    else:
        staging = Path(staging_dir)
        try:
            staging.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            errors.append(f"staging_dir unwritable: {exc}")
            return None, "parse_error"

    # Open the EWF handle and adapt to pytsk3.
    try:
        filenames = pyewf.glob(str(e01_path))
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
    except Exception as exc:  # noqa: BLE001 -- pyewf raises bare Exception
        errors.append(
            f"pyewf.open failed: {type(exc).__name__}: {str(exc)[:160]}"
        )
        return None, "open_error"

    class _EwfImgInfo(pytsk3.Img_Info):  # type: ignore[misc,valid-type]
        def __init__(self, handle):
            self._handle = handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):  # pragma: no cover - pytsk3 lifecycle hook
            pass

        def read(self, offset, size):
            self._handle.seek(offset)
            return self._handle.read(size)

        def get_size(self):
            return self._handle.get_media_size()

    try:
        img_info = _EwfImgInfo(ewf_handle)
    except Exception as exc:  # noqa: BLE001
        errors.append(
            f"pytsk3 Img_Info failed: {type(exc).__name__}: "
            f"{str(exc)[:160]}"
        )
        try:
            ewf_handle.close()
        except Exception:  # noqa: BLE001
            pass
        return None, "open_error"

    # Locate an NTFS partition. Some raw images have no partition table.
    fs_info = None
    try:
        try:
            vol_info = pytsk3.Volume_Info(img_info)
        except OSError:
            vol_info = None
        if vol_info is not None:
            for part in vol_info:
                if getattr(part, "len", 0) < 2048:
                    continue
                try:
                    fs_info = pytsk3.FS_Info(
                        img_info, offset=part.start * 512,
                    )
                    # Prefer the first partition that opens cleanly.
                    break
                except OSError:
                    continue
        if fs_info is None:
            # Try raw NTFS (no partition table).
            try:
                fs_info = pytsk3.FS_Info(img_info, offset=0)
            except OSError:
                fs_info = None
    except Exception as exc:  # noqa: BLE001
        errors.append(
            f"pytsk3 Volume/FS discovery failed: "
            f"{type(exc).__name__}: {str(exc)[:160]}"
        )
        try:
            ewf_handle.close()
        except Exception:  # noqa: BLE001
            pass
        return None, "fs_error"

    if fs_info is None:
        errors.append("no NTFS filesystem found in E01 image")
        try:
            ewf_handle.close()
        except Exception:  # noqa: BLE001
            pass
        return None, "fs_error"

    try:
        if include_eventlogs:
            for fs_path in _E01_EVTX_FS_PATHS:
                _extract_one_file(
                    fs_info, fs_path, staging, errors,
                )
        if include_default_rdp:
            _extract_user_rdp_profiles(
                fs_info, staging,
                max_rdp_files_per_user=max_rdp_files_per_user,
                errors=errors,
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(
            f"E01 extraction failed: {type(exc).__name__}: "
            f"{str(exc)[:160]}"
        )
        try:
            ewf_handle.close()
        except Exception:  # noqa: BLE001
            pass
        return None, "parse_error"
    finally:
        try:
            ewf_handle.close()
        except Exception:  # noqa: BLE001
            pass

    return staging, None


def _extract_one_file(
    fs_info,
    fs_path: str,
    staging: Path,
    errors: list[str],
) -> bool:
    """Extract ``fs_path`` from *fs_info* into *staging*, preserving the
    relative directory structure. Returns True on success."""
    try:
        file_obj = fs_info.open(fs_path)
    except OSError:
        return False
    try:
        meta = file_obj.info.meta
        if meta is None or meta.size is None:
            return False
        size = int(meta.size)
        if size <= 0:
            return False
        rel = fs_path.lstrip("/\\")
        dest = staging / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            errors.append(f"staging mkdir {dest.parent}: {exc}")
            return False
        # Read in chunks; pytsk3 File.read_random(offset, size).
        chunk = 1024 * 1024
        try:
            with open(dest, "wb") as out:
                remaining = size
                offset = 0
                while remaining > 0:
                    want = min(chunk, remaining)
                    data = file_obj.read_random(offset, want)
                    if not data:
                        break
                    out.write(data)
                    remaining -= len(data)
                    offset += len(data)
        except (OSError, PermissionError) as exc:
            errors.append(f"staging write {dest}: {exc}")
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        errors.append(
            f"extract {fs_path}: {type(exc).__name__}: "
            f"{str(exc)[:120]}"
        )
        return False


def _extract_user_rdp_profiles(
    fs_info,
    staging: Path,
    *,
    max_rdp_files_per_user: int,
    errors: list[str],
) -> None:
    """Walk /Users/<name>/<subdir> for ``*.rdp`` files and extract up to
    ``max_rdp_files_per_user`` per user into *staging*."""
    # Enumerate /Users first.
    try:
        users_dir = fs_info.open_dir("/Users")
    except OSError:
        return
    user_names: list[str] = []
    for entry in users_dir:
        try:
            name_bytes = entry.info.name.name
            if isinstance(name_bytes, bytes):
                name = name_bytes.decode("utf-8", errors="replace")
            else:
                name = str(name_bytes)
        except (AttributeError, UnicodeDecodeError):
            continue
        if name in (".", "..", ""):
            continue
        user_names.append(name)
    user_names.sort()
    for user in user_names:
        extracted = 0
        for sub in _RDP_USER_SUBDIRS:
            if extracted >= max_rdp_files_per_user:
                break
            user_sub = f"/Users/{user}/{sub}"
            try:
                walker = fs_info.open_dir(user_sub)
            except OSError:
                continue
            for entry in walker:
                if extracted >= max_rdp_files_per_user:
                    break
                try:
                    nm = entry.info.name.name
                    if isinstance(nm, bytes):
                        nm = nm.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    continue
                if not nm.lower().endswith(".rdp"):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                # Only regular files.
                fs_path = f"{user_sub}/{nm}"
                if _extract_one_file(fs_info, fs_path, staging, errors):
                    extracted += 1


# ── public entry point ─────────────────────────────────────────────────

def parse_rdp_artifacts(
    mount_path: str | None = None,
    disk_image_path: str | None = None,
    staging_dir: str | None = None,
    tool_outputs: dict | None = None,
    max_events_per_channel: int = 5000,
    max_records_per_source: int = 2000,
    max_rdp_files_per_user: int = 25,
    timeout_seconds_per_sub: int = 60,
    include_eventlogs: bool = True,
    include_registry: bool = True,
    include_default_rdp: bool = True,
) -> dict:
    """Locate and parse RDP evidence from a mounted disk or E01 image.

    The returned envelope is *evidence only*: it never contains
    findings, confidence scores, or attacker labels. Every record is a
    single verbatim artifact with the required closed-vocab fields.

    Disk inputs (evaluated in priority order):

    - *disk_image_path* -- path to a ``.E01`` image. When supplied, the
      three TerminalServices ``.evtx`` files plus per-user ``.rdp``
      profiles are extracted read-only into *staging_dir* (an auto
      tempdir when None) via ``pyewf`` + ``pytsk3``. If either library
      is absent, the EVTX / rdp_profile sub-sources report
      ``library_unavailable``; on open or walk failure they report
      ``parse_error``. Either way the caller receives a well-formed
      envelope -- no crashes, no fake records.
    - *mount_path* -- path to an already-mounted Windows filesystem. Used
      directly (and in preference over ``DISK_MOUNT_PATH``).

    *include_eventlogs* / *include_registry* / *include_default_rdp*
    gate the corresponding sub-sources. When False, each relevant key
    in ``sub_source_status`` reports ``not_requested``.

    *max_events_per_channel* bounds the records pulled from each EVTX
    channel. *max_records_per_source* bounds the total records a single
    source (all three EVTX channels combined, or the rdp_profile walker,
    or registry) can contribute. *max_rdp_files_per_user* bounds the
    E01 extraction per user. *timeout_seconds_per_sub* is reserved for
    sub-source walltime; per-EVTX-file parsing already uses its own
    internal budget.

    Top-level keys (always present):

        tool, tool_name, evidence_path, record_count, records, output,
        candidate_files, searched_paths, sub_source_status, status,
        reason, errors, recovery_hints

    ``status`` ∈ ``RDP_STATUSES``. Per-source status ∈
    ``RDP_SUB_SOURCE_STATUSES`` keyed by ``RDP_SUB_SOURCE_KEYS``.
    ``recovery_hints`` are pointers, kept strictly separate from
    ``records``.

    No shell execution. Evidence is read-only; writes only touch the
    caller-supplied (or auto-created) staging directory.
    """
    errors: list[str] = []
    records: list[dict] = []
    candidate_files: list[str] = []
    searched_paths: list[str] = []
    sub_source_status: dict[str, str] = {
        key: "not_requested" for key in RDP_SUB_SOURCE_KEYS
    }

    recovery_hints = find_rdp_recovery_hints(tool_outputs)

    # ── resolve disk context ─────────────────────────────────────────

    effective_mount: Path | None = None
    e01_error: str | None = None
    evidence_path_str: str

    if disk_image_path:
        evidence_path_str = str(disk_image_path)
        prepared, e01_error = _prepare_e01_staging(
            disk_image_path,
            staging_dir,
            max_rdp_files_per_user=max_rdp_files_per_user,
            include_eventlogs=include_eventlogs,
            include_default_rdp=include_default_rdp,
            errors=errors,
        )
        if prepared is not None:
            effective_mount = prepared
    else:
        if mount_path is not None:
            mp = str(mount_path)
        else:
            mp = DISK_MOUNT_PATH
        evidence_path_str = mp.rstrip("/")
        candidate = Path(evidence_path_str) if evidence_path_str else None
        if candidate is not None and candidate.is_dir():
            effective_mount = candidate

    # Map E01 error reason to a sub_source_status value that matches
    # the closed vocabulary. "not_found" (image missing) and generic
    # library/parse errors both warrant a truthful per-source status.
    def _e01_sub_status(reason: str | None) -> str:
        if reason is None:
            return "ok"  # success path -- caller resolves per-source below
        if reason == "library_unavailable":
            return "library_unavailable"
        if reason in ("not_found",):
            return "not_found"
        # open_error, fs_error, parse_error
        return "parse_error"

    # ── registry ────────────────────────────────────────────────────

    if include_registry:
        # F7-A does not parse NTUSER.DAT hives. Report honestly:
        # library_unavailable when python-registry cannot be imported,
        # not_found otherwise (a future F7-B integration will walk the
        # hive via normalize_registry_value[s]).
        try:
            import Registry  # type: ignore[import-not-found]  # noqa: F401
            registry_lib_available = True
        except ImportError:
            registry_lib_available = False
        reg_status = (
            "library_unavailable"
            if not registry_lib_available
            else "not_found"
        )
        sub_source_status["registry_mru"] = reg_status
        sub_source_status["registry_servers"] = reg_status

    # ── .rdp profiles ────────────────────────────────────────────────

    if include_default_rdp:
        if effective_mount is None:
            sub_source_status["rdp_profile"] = (
                _e01_sub_status(e01_error)
                if disk_image_path else "not_found"
            )
        else:
            # SIFT_RDP_INFUNC_EIO_GUARD_V1: in-function EIO guard (module-level wraps were shadowed by import/registry capture)
            try:
                profile_roots = _build_rdp_profile_search_roots(effective_mount)
            except OSError as _sift_rdp_eio:
                errors.append('rdp_profile root-build EIO (skipped): ' + str(_sift_rdp_eio))
                profile_roots = []
            for root in profile_roots:
                searched_paths.append(str(root))
            # Cap walker at max_records_per_source so we don't pre-read
            # more than the source will emit.
            try:
                profile_candidates = _walk_rdp_profile_candidates(
                    profile_roots,
                    max_files=max_records_per_source,
                    errors=errors,
                )
            except OSError as _sift_rdp_eio:
                errors.append('rdp_profile walk EIO (skipped): ' + str(_sift_rdp_eio))
                profile_candidates = []
            profile_records: list[dict] = []
            # SIFT_RDP_INFUNC_CONSUMPTION_GUARD_V1: blanket in-function guard over
            # candidate consumption + per-file parse. Any OSError from an unreadable
            # region on ANY disk degrades the .rdp sub-source gracefully; EVTX still
            # runs. Dataset-agnostic: keys on error type only, never on path values.
            try:
                for p in profile_candidates:
                    candidate_files.append(str(p))
                for path in profile_candidates:
                    if len(profile_records) >= max_records_per_source:
                        break
                    rec = _parse_rdp_profile_file(
                        path,
                        max_bytes=2 * 1024 * 1024,
                        errors=errors,
                    )
                    if rec is not None:
                        profile_records.append(rec)
            except OSError as _sift_rdp_eio:
                errors.append('rdp_profile consumption EIO (skipped): ' + str(_sift_rdp_eio))
            if profile_records:
                sub_source_status["rdp_profile"] = "ok"
            elif profile_candidates:
                sub_source_status["rdp_profile"] = "parse_error"
            else:
                sub_source_status["rdp_profile"] = "not_found"
            records.extend(profile_records)

    # ── TerminalServices .evtx ───────────────────────────────────────

    evtx_sub_source_keys = tuple(
        _CHANNEL_KIND_TO_SUB_SOURCE_KEY[ck]
        for ck in ("local_session_manager",
                   "remote_connection_manager",
                   "rdp_client_operational")
    )
    if include_eventlogs:
        if effective_mount is None:
            fallback = (
                _e01_sub_status(e01_error)
                if disk_image_path else "not_found"
            )
            for sk in evtx_sub_source_keys:
                sub_source_status[sk] = fallback
        else:
            evtx_dir = _resolve_evtx_dir(effective_mount)
            if evtx_dir.is_dir():
                searched_paths.append(str(evtx_dir))
            evtx_files = _find_rdp_evtx_files(effective_mount)
            evtx_source_records: list[dict] = []
            for channel_kind, path in evtx_files.items():
                sub_source_key = _CHANNEL_KIND_TO_SUB_SOURCE_KEY[
                    channel_kind
                ]
                if path is None:
                    sub_source_status[sub_source_key] = "not_found"
                    continue
                candidate_files.append(str(path))
                if len(evtx_source_records) >= max_records_per_source:
                    sub_source_status[sub_source_key] = "ok"
                    continue
                remaining_for_source = (
                    max_records_per_source - len(evtx_source_records)
                )
                per_channel_cap = min(
                    max_events_per_channel, remaining_for_source,
                )
                parsed_records, status_for_source = _parse_rdp_evtx_file(
                    path,
                    channel_kind,
                    max_records=max(0, per_channel_cap),
                    errors=errors,
                )
                sub_source_status[sub_source_key] = status_for_source
                if parsed_records:
                    if (
                        len(evtx_source_records) + len(parsed_records)
                        > max_records_per_source
                    ):
                        parsed_records = parsed_records[
                            : max_records_per_source
                            - len(evtx_source_records)
                        ]
                    evtx_source_records.extend(parsed_records)
            records.extend(evtx_source_records)

    # ── finalize ─────────────────────────────────────────────────────

    # Deterministic ordering: by source_file then record_id.
    records.sort(
        key=lambda r: (r.get("source_file", ""), r.get("record_id", ""))
    )
    candidate_files = sorted(set(candidate_files))
    searched_paths = sorted(set(searched_paths))

    status = _resolve_envelope_status(records, recovery_hints)

    # Counts dict -- always a dict, never None. Downstream consumers can
    # rely on this key existing and the inner breakdowns being present
    # even when the counts are all zero.
    records_by_type: dict[str, int] = {t: 0 for t in sorted(
        RDP_RECORD_TYPES
    )}
    records_by_source_kind: dict[str, int] = {s: 0 for s in sorted(
        RDP_SOURCE_KINDS
    )}
    for r in records:
        t = r.get("type")
        sk = r.get("source_kind")
        if isinstance(t, str) and t in records_by_type:
            records_by_type[t] += 1
        if isinstance(sk, str) and sk in records_by_source_kind:
            records_by_source_kind[sk] += 1
    hints_by_type: dict[str, int] = {t: 0 for t in sorted(
        RDP_RECOVERY_HINT_TYPES
    )}
    for h in recovery_hints:
        t = h.get("type")
        if isinstance(t, str) and t in hints_by_type:
            hints_by_type[t] += 1
    counts: dict = {
        "records": len(records),
        "records_by_type": records_by_type,
        "records_by_source_kind": records_by_source_kind,
        "recovery_hints": len(recovery_hints),
        "recovery_hints_by_type": hints_by_type,
        "candidate_files": len(candidate_files),
        "searched_paths": len(searched_paths),
        "errors": len(errors),
    }

    reason_parts: list[str] = []
    if records:
        reason_parts.append(
            f"parsed {len(records)} RDP record(s) from "
            f"{len(candidate_files)} candidate file(s)"
        )
    elif candidate_files:
        reason_parts.append(
            f"{len(candidate_files)} candidate RDP file(s) found but "
            "none yielded records"
        )
    elif disk_image_path and e01_error:
        reason_parts.append(
            f"E01 ingestion unavailable: {e01_error}"
        )
    else:
        reason_parts.append(
            f"no RDP candidate files under {len(searched_paths)} "
            "searched path(s)"
        )
    if recovery_hints:
        reason_parts.append(
            f"{len(recovery_hints)} RDP reference(s) in tool outputs"
        )
    else:
        # Honest explanation when hints are absent: either tool_outputs
        # wasn't provided, or it was but contained no RDP-shaped paths /
        # binary tokens. Downstream review of the reason text should
        # match one of these two states.
        if not tool_outputs:
            reason_parts.append(
                "no tool_outputs provided (recovery_hints requires "
                "tool_outputs input)"
            )
        else:
            reason_parts.append(
                "tool_outputs provided but contained no RDP artifact "
                "references"
            )

    return {
        "tool": "parse_rdp_artifacts",
        "tool_name": "parse_rdp_artifacts",
        "evidence_path": evidence_path_str,
        "record_count": len(records),
        "records": records,
        "output": records,
        "candidate_files": candidate_files,
        "searched_paths": searched_paths,
        "sub_source_status": sub_source_status,
        "counts": counts,
        "status": status,
        "reason": "; ".join(reason_parts),
        "errors": errors,
        "recovery_hints": recovery_hints,
    }


# SIFT_RDP_IO_SAFE_PARTIAL_FALLBACK_V1C
# Mounted forensic filesystems may return EIO/EACCES/ENOENT for individual
# paths. A single unreadable user-cache path must not zero all RDP evidence.
def _sift_rdp_mount_from_args_v1c(args, kwargs):
    for key in ("disk_mount", "mount_path", "root_path", "path", "mount"):
        val = kwargs.get(key)
        if val:
            return val
    if args:
        return args[0]
    return ""


def _sift_rdp_safe_partial_records_v1c(mount_path):
    from pathlib import Path as _Path
    import os as _os

    root = _Path(str(mount_path or ""))
    records = []
    logs = root / "Windows" / "System32" / "winevt" / "Logs"
    patterns = (
        "*TerminalServices*.evtx",
        "*RemoteDesktop*.evtx",
        "*RDP*.evtx",
        "*WinRM*.evtx",
    )
    seen = set()
    if logs.exists():
        for pat in patterns:
            try:
                for f in logs.glob(pat):
                    key = str(f)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        size = f.stat().st_size
                    except OSError:
                        size = 0
                    records.append({
                        "artifact_type": "rdp_related_event_log_file",
                        "path": key,
                        "file_name": f.name,
                        "size": size,
                        "source": "rdp_safe_partial_fallback",
                        "coverage_only": True,
                    })
            except OSError:
                continue

    # Lightweight registry/file presence checks without recursive user walk.
    for rel in (
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SOFTWARE",
        "Users",
    ):
        try:
            p = root / rel
            if p.exists():
                records.append({
                    "artifact_type": "rdp_context_path_present",
                    "path": str(p),
                    "source": "rdp_safe_partial_fallback",
                    "coverage_only": True,
                })
        except OSError:
            continue

    return records


if "parse_rdp_artifacts" in globals() and "_sift_parse_rdp_artifacts_core_v1c" not in globals():
    _sift_parse_rdp_artifacts_core_v1c = parse_rdp_artifacts

    import functools as _sift_rdp_functools_v1
    @_sift_rdp_functools_v1.wraps(_sift_parse_rdp_artifacts_core_v1c)
    def parse_rdp_artifacts(*args, **kwargs):
        try:
            return _sift_parse_rdp_artifacts_core_v1c(*args, **kwargs)
        except OSError as exc:
            mount = _sift_rdp_mount_from_args_v1c(args, kwargs)
            recs = _sift_rdp_safe_partial_records_v1c(mount)
            return {
                "output": recs,
                "records": recs,
                "record_count": len(recs),
                "status": "partial_ok" if recs else "not_applicable",
                "error": "" if recs else str(exc),
                "warning": f"skipped unreadable path after OSError: {exc}",
                "sift_contract": "SIFT_RDP_IO_SAFE_PARTIAL_FALLBACK_V1C",
                "coverage_only": True,
            }


# SIFT_RDP_CRASH_TRACE_V1: the RDP crash is concurrency-only (unreproducible
# single-process). Wrap the active entrypoint to (1) enforce the tool's
# documented "well-formed envelope, no crashes" contract and (2) capture the
# real traceback from the live pipeline crash. Dataset-agnostic; no case values.
def _sift_rdp_trace_wrap_v1(_fn):
    import functools, traceback as _tb
    @functools.wraps(_fn)
    def _wrapped(*a, **k):
        try:
            return _fn(*a, **k)
        except Exception as _exc:
            try:
                with open("/tmp/sift_rdp_crash_trace.txt", "a") as _f:
                    _f.write(_tb.format_exc() + "\n" + ("=" * 70) + "\n")
            except Exception:
                pass
            return {
                "tool": "parse_rdp_artifacts", "tool_name": "parse_rdp_artifacts",
                "evidence_path": "", "record_count": 0, "records": [], "output": [],
                "candidate_files": [], "searched_paths": [], "sub_source_status": {},
                "status": "parse_error",
                "reason": "uncaught " + type(_exc).__name__ + ": " + str(_exc),
                "errors": [str(_exc)], "recovery_hints": [],
            }
    return _wrapped


parse_rdp_artifacts = _sift_rdp_trace_wrap_v1(parse_rdp_artifacts)
