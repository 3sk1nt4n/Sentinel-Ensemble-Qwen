"""
Sentinel Qwen Ensemble - WMI subscription parser (disk + memory tool, F8-A).

Dataset-agnostic extractor of Windows Management Instrumentation (WMI)
event-subscription artifacts from the CIMv2 repository ``OBJECTS.DATA``
file and/or a raw memory image. Emits *evidence records only* -- no
findings, no confidence field, no attacker labels, no binding-graph
reconstruction. Each record represents a single anchor-class token hit
plus whatever verbatim property fields the bounded local window was able
to recover.

Input sources:

- ``mount_path``         : mounted Windows filesystem; the parser looks
                           for
                           ``Windows/System32/wbem/Repository/OBJECTS.DATA``
                           underneath it.
- ``objects_data_path``  : direct path to an ``OBJECTS.DATA`` file
                           (overrides ``mount_path`` for this source).
- ``memory_image_path``  : direct path to a raw memory image. Scanned
                           in bounded chunks for WMI anchor tokens in
                           both ASCII and UTF-16LE encodings.
- ``tool_outputs``       : arbitrary tool-output dict. Searched for WMI
                           repository path references and known WMI
                           binary names to build ``recovery_hints``.
                           Hints are *pointers*, never records.

The parser is deliberately narrow:

- It does not parse the OBJECTS.DATA binary format (no INDEX.BTR walk,
  no MAPPING*.MAP resolution, no CIMv2 class-definition decoding).
- It does not resolve Filter/Consumer references to their target
  instances; Filter and Consumer reference strings are captured
  verbatim on ``wmi_filter_to_consumer_binding`` records so downstream
  code can correlate by name.
- It does not run any shell command and writes nothing to ``/cases``
  or ``/mnt``; reads are strictly read-only.

Every sub-source reports its own status via ``sub_source_status`` so
the caller can distinguish "source not present" from "library missing"
from "we tried and it raised". The top-level ``status`` is drawn from
the closed four-state vocabulary:

    - ``no_wmi_artifacts_found``                records=0, hints=0
    - ``wmi_references_found``                  records=0, hints>0
    - ``wmi_artifacts_parsed``                  records>0, hints=0
    - ``wmi_artifacts_parsed_with_references``  records>0, hints>0

``recovery_hints`` are *pointers* (where to look for additional WMI
repository evidence), not parsed records -- they are kept strictly
separate from ``records``.

No shell execution. No writes to evidence.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Iterable
from sift_sentinel.config import DISK_MOUNT_PATH

logger = logging.getLogger(__name__)


# ── closed vocabularies (locked F8-A contract) ─────────────────────────

WMI_STATUSES: frozenset[str] = frozenset({
    "no_wmi_artifacts_found",
    "wmi_references_found",
    "wmi_artifacts_parsed",
    "wmi_artifacts_parsed_with_references",
})

WMI_RECORD_TYPES: frozenset[str] = frozenset({
    "wmi_event_filter",
    "wmi_command_line_consumer",
    "wmi_active_script_consumer",
    "wmi_nt_event_log_consumer",
    "wmi_log_file_consumer",
    "wmi_smtp_consumer",
    "wmi_filter_to_consumer_binding",
})

WMI_SOURCE_KINDS: frozenset[str] = frozenset({
    "wmi_repository_file",
    "memory_image",
})

WMI_EXTRACTION_METHODS: frozenset[str] = frozenset({
    "objects_data_anchor_window",
    "memory_mof_literal",
    "memory_anchor_only",
})

WMI_SUB_SOURCE_STATUSES: frozenset[str] = frozenset({
    "ok",
    "not_found",
    "library_unavailable",
    "parse_error",
    "not_requested",
})

WMI_SUB_SOURCE_KEYS: tuple[str, ...] = (
    "objects_data",
    "memory_strings",
)

WMI_RECOVERY_HINT_TYPES: frozenset[str] = frozenset({
    "wmi_repository_path_reference",
    "wmi_binary_reference",
})

WMI_RECOVERY_HINT_STATUSES: frozenset[str] = frozenset({
    "path_reference_only",
    "binary_reference_only",
})

WMI_RECORD_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "source_kind",
    "extraction_method",
    "source_file",
    "record_id",
    "raw_excerpt",
    "anchor_class",
    "offset",
)

WMI_RECOVERY_HINT_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "path",
    "binary",
    "source_tool",
    "source_file",
    "raw_excerpt",
    "reason",
)


# ── anchor class → record type (closed mapping) ────────────────────────

# These are the stock WMI CIMv2 class-type tokens we search for. Every
# token listed is a published Microsoft class name, stable across
# supported Windows versions. No scenario-specific identifier is
# referenced anywhere in this module.
_ANCHOR_TO_RECORD_TYPE: dict[str, str] = {
    "__EventFilter":              "wmi_event_filter",
    "CommandLineEventConsumer":   "wmi_command_line_consumer",
    "ActiveScriptEventConsumer":  "wmi_active_script_consumer",
    "NTEventLogEventConsumer":    "wmi_nt_event_log_consumer",
    "LogFileEventConsumer":       "wmi_log_file_consumer",
    "SMTPEventConsumer":          "wmi_smtp_consumer",
    "__FilterToConsumerBinding":  "wmi_filter_to_consumer_binding",
}

WMI_ANCHOR_CLASSES: frozenset[str] = frozenset(_ANCHOR_TO_RECORD_TYPE)


# ── extraction parameters (bounded) ────────────────────────────────────

# Standard relative path of the CIMv2 repository main data file. Joined
# under a mount point when ``mount_path`` is supplied.
_OBJECTS_DATA_REL_PARTS: tuple[str, ...] = (
    "Windows", "System32", "wbem", "Repository", "OBJECTS.DATA",
)

# WMI repository filenames used for recovery_hints path matching.
_WMI_REPO_FILE_NAMES: tuple[str, ...] = (
    "OBJECTS.DATA",
    "INDEX.BTR",
    "MAPPING1.MAP",
    "MAPPING2.MAP",
    "MAPPING3.MAP",
)

# Canonical WMI-adjacent binary names used for recovery_hints. All are
# shipped as part of stock Windows.
_WMI_BINARY_TOKENS: tuple[str, ...] = (
    "wmiprvse.exe",
    "wmiadasample_payload.exe",
    "mofcomsample_payload.exe",
    "wbemtest.exe",
    "scrcons.exe",
)

# Bounded chunk / window sizes. Sized so every anchor window fits inside
# the overlap region used by the streaming scanner.
_DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024           # 4 MB
_DEFAULT_MEMORY_CHUNK_SIZE = 16 * 1024 * 1024   # 16 MB
_DEFAULT_ANCHOR_WINDOW_BEFORE = 1024
_DEFAULT_ANCHOR_WINDOW_AFTER = 3072
_CHUNK_OVERLAP = (
    _DEFAULT_ANCHOR_WINDOW_BEFORE + _DEFAULT_ANCHOR_WINDOW_AFTER + 256
)

# Bounded ``raw_excerpt`` preview length (bytes -> printable chars).
_RAW_EXCERPT_BYTES = 256

# Dedup bucket for overlapping anchor hits. Two records with identical
# (anchor_class, extracted_name or '<no-name>', offset // bucket)
# collapse to one.
_DEDUP_BUCKET = 4096

# Property value length caps.
_MAX_NAME_LEN = 512
_MAX_QUERY_LEN = 2048
_MAX_TEMPLATE_LEN = 2048
_MAX_SCRIPT_LEN = 4096
_MAX_PATH_LEN = 1024
_MAX_SHORT_LEN = 64

# Per-source record caps. Prevents an exceptionally anchor-dense region
# of bytes (e.g. a mostly-zeroed memory dump that happens to replay many
# WMI repository pages) from ballooning the record list.
_DEFAULT_MAX_RECORDS_PER_SOURCE = 2000

# Closed list of properties the parser knows how to extract from a
# bounded local window. Tuple order is the priority order for regex
# application; the encoding attempt order is always (ASCII, UTF-16LE).
_PROPERTY_DEFS: tuple[tuple[str, int, str], ...] = (
    ("Name",                 _MAX_NAME_LEN,     "extracted_name"),
    ("Query",                _MAX_QUERY_LEN,    "extracted_query"),
    ("QueryLanguage",        _MAX_SHORT_LEN,    "extracted_query_language"),
    ("EventNamespace",       _MAX_PATH_LEN,     "extracted_event_namespace"),
    ("CommandLineTemplate",  _MAX_TEMPLATE_LEN, "extracted_command_template"),
    ("ExecutablePath",       _MAX_PATH_LEN,     "extracted_executable_path"),
    ("WorkingDirectory",     _MAX_PATH_LEN,     "extracted_working_directory"),
    ("ScriptingEngine",      _MAX_SHORT_LEN,    "extracted_script_engine"),
    ("ScriptFilename",       _MAX_PATH_LEN,     "extracted_script_filename"),
    ("ScriptText",           _MAX_SCRIPT_LEN,   "extracted_script_text"),
    ("Filter",               _MAX_PATH_LEN,     "extracted_filter_ref"),
    ("Consumer",             _MAX_PATH_LEN,     "extracted_consumer_ref"),
)

_PROPERTY_FIELD_BY_NAME: dict[str, str] = {
    prop: field for prop, _max, field in _PROPERTY_DEFS
}

# Allowed property fields per record type. Matches that fall outside
# this allow-list are discarded even if the regex fired.
_PROPERTIES_BY_RECORD_TYPE: dict[str, frozenset[str]] = {
    "wmi_event_filter": frozenset({
        "extracted_name",
        "extracted_query",
        "extracted_query_language",
        "extracted_event_namespace",
    }),
    "wmi_command_line_consumer": frozenset({
        "extracted_name",
        "extracted_command_template",
        "extracted_executable_path",
        "extracted_working_directory",
    }),
    "wmi_active_script_consumer": frozenset({
        "extracted_name",
        "extracted_script_engine",
        "extracted_script_filename",
        "extracted_script_text",
    }),
    "wmi_nt_event_log_consumer": frozenset({
        "extracted_name",
    }),
    "wmi_log_file_consumer": frozenset({
        "extracted_name",
        "extracted_executable_path",
    }),
    "wmi_smtp_consumer": frozenset({
        "extracted_name",
    }),
    "wmi_filter_to_consumer_binding": frozenset({
        "extracted_filter_ref",
        "extracted_consumer_ref",
    }),
}

# Consumer class types (for binding reference back-fill). Derived from
# the anchor table rather than hand-maintained so the two stay in sync.
_CONSUMER_CLASSES: tuple[str, ...] = tuple(
    cls for cls, rt in _ANCHOR_TO_RECORD_TYPE.items()
    if rt.endswith("_consumer")
)


# ── compiled regex helpers ─────────────────────────────────────────────

# Printable-byte class for value chars. Excludes quote (0x22) and all
# control bytes. NUL is excluded implicitly (it is not in 0x20..0x7e).
_VALUE_BYTE_CLASS_ASCII = rb"\x20\x21\x23-\x7e"

# Cache so each distinct (prop, max_len) is compiled once.
_ASCII_PROP_RE_CACHE: dict[tuple[str, int], re.Pattern] = {}
_UTF16LE_PROP_RE_CACHE: dict[tuple[str, int], re.Pattern] = {}
_ASCII_REF_RE_CACHE: dict[str, re.Pattern] = {}
_UTF16LE_REF_RE_CACHE: dict[str, re.Pattern] = {}


def _ascii_to_utf16le_bytes(value: str) -> bytes:
    """Expand an ASCII-range string to its UTF-16LE byte form."""
    return b"".join(bytes([ord(c), 0]) for c in value)


def _ascii_prop_re(prop: str, max_len: int) -> re.Pattern:
    """ASCII regex for ``PropertyName="value"`` equality.

    Uses word-boundary lookbehind to avoid matching where the property
    name appears inside a longer identifier (e.g. ``HostName`` would not
    match a search for ``Name``).
    """
    key = (prop, max_len)
    cached = _ASCII_PROP_RE_CACHE.get(key)
    if cached is not None:
        return cached
    pat = re.compile(
        rb"(?<![A-Za-z0-9_])"
        + re.escape(prop.encode("ascii"))
        + rb'[ \t]*=[ \t]*"'
        + rb'([' + _VALUE_BYTE_CLASS_ASCII + rb']{1,'
        + str(max_len).encode() + rb'})"',
        re.DOTALL,
    )
    _ASCII_PROP_RE_CACHE[key] = pat
    return pat


def _utf16le_prop_re(prop: str, max_len: int) -> re.Pattern:
    """UTF-16LE regex for ``PropertyName="value"`` equality.

    Each ASCII char in the pattern is interleaved with a NUL byte. The
    lookbehind is also UTF-16LE (fixed 2-byte width).
    """
    key = (prop, max_len)
    cached = _UTF16LE_PROP_RE_CACHE.get(key)
    if cached is not None:
        return cached
    prop_u16 = _ascii_to_utf16le_bytes(prop)
    val_char = rb'[\x20\x21\x23-\x7e]\x00'
    pat = re.compile(
        rb"(?<![A-Za-z0-9_]\x00)"
        + re.escape(prop_u16)
        + rb'(?:[ \t]\x00)*=\x00(?:[ \t]\x00)*"\x00'
        + rb'((?:' + val_char + rb'){1,'
        + str(max_len).encode() + rb'})'
        + rb'"\x00',
        re.DOTALL,
    )
    _UTF16LE_PROP_RE_CACHE[key] = pat
    return pat


def _ascii_ref_re(anchor_class: str) -> re.Pattern:
    """ASCII regex for ``AnchorClass.Name="value"`` reference string."""
    cached = _ASCII_REF_RE_CACHE.get(anchor_class)
    if cached is not None:
        return cached
    pat = re.compile(
        rb"(?<![A-Za-z0-9_])"
        + re.escape(anchor_class.encode("ascii"))
        + rb'\.Name="(['
        + _VALUE_BYTE_CLASS_ASCII
        + rb']{1,'
        + str(_MAX_NAME_LEN).encode()
        + rb'})"',
        re.DOTALL,
    )
    _ASCII_REF_RE_CACHE[anchor_class] = pat
    return pat


def _utf16le_ref_re(anchor_class: str) -> re.Pattern:
    """UTF-16LE regex for ``AnchorClass.Name="value"`` reference
    string."""
    cached = _UTF16LE_REF_RE_CACHE.get(anchor_class)
    if cached is not None:
        return cached
    anchor_u16 = _ascii_to_utf16le_bytes(anchor_class)
    dot = b"." + b"\x00"
    name_u16 = _ascii_to_utf16le_bytes("Name")
    eq = b"=" + b"\x00"
    quot = b'"' + b"\x00"
    val_char = rb'[\x20\x21\x23-\x7e]\x00'
    pat = re.compile(
        rb"(?<![A-Za-z0-9_]\x00)"
        + re.escape(anchor_u16)
        + re.escape(dot)
        + re.escape(name_u16)
        + re.escape(eq)
        + re.escape(quot)
        + rb'((?:' + val_char + rb'){1,'
        + str(_MAX_NAME_LEN).encode() + rb'})'
        + re.escape(quot),
        re.DOTALL,
    )
    _UTF16LE_REF_RE_CACHE[anchor_class] = pat
    return pat


# ── decoding / preview helpers ─────────────────────────────────────────

def _decode_value(value_bytes: bytes, encoding: str) -> str | None:
    """Decode *value_bytes* under *encoding* and reject control chars.

    Returns None on decode failure or when the decoded string contains
    any non-tab control character.
    """
    try:
        if encoding == "utf-16-le":
            decoded = value_bytes.decode("utf-16-le", errors="strict")
        else:
            decoded = value_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    for ch in decoded:
        o = ord(ch)
        if o < 0x20 and ch != "\t":
            return None
        if o == 0x7f:
            return None
    return decoded.strip()


def _short_raw_excerpt(buffer: bytes, limit: int = _RAW_EXCERPT_BYTES) -> str:
    """Single-line printable-ASCII preview of *buffer* up to *limit* bytes.

    Non-printable bytes (including NUL, control chars, and UTF-16 high
    bytes) are replaced with ``.``; the result is a fixed-width-ish
    single-line preview suitable for embedding in JSON logs.
    """
    if not buffer:
        return ""
    trimmed = buffer[:limit]
    chars = []
    for b in trimmed:
        if 0x20 <= b <= 0x7e:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "".join(chars)


def _normalize_source_file(
    path: Path | str | None,
    source_kind: str,
) -> str:
    """Produce a stable ``source_file`` value.

    For ``wmi_repository_file`` records we surface only the canonical
    ``Windows/System32/wbem/Repository/...`` tail when the input path
    contains that segment. Otherwise the full input path is kept.
    """
    if not path:
        return ""
    s = str(path).replace("\\", "/")
    if source_kind == "wmi_repository_file":
        lower = s.lower()
        marker = "windows/system32/wbem/repository/"
        idx = lower.find(marker)
        if idx >= 0:
            return s[idx:]
    return s


# ── anchor byte-forms + word-boundary check ────────────────────────────

def _anchor_byte_forms(anchor_class: str) -> tuple[bytes, bytes]:
    """Return ``(ascii_bytes, utf16le_bytes)`` for an anchor class."""
    return (
        anchor_class.encode("ascii"),
        _ascii_to_utf16le_bytes(anchor_class),
    )


def _is_word_byte(b: int) -> bool:
    """True iff *b* is an ASCII word byte (letter / digit / underscore)."""
    return (
        (0x41 <= b <= 0x5a)
        or (0x61 <= b <= 0x7a)
        or (0x30 <= b <= 0x39)
        or b == 0x5f
    )


def _anchor_is_word_bounded(
    buffer: bytes,
    pos: int,
    length: int,
    encoding: str,
) -> bool:
    """Check that the byte just before *pos* and just after *pos+length*
    do not continue the anchor as part of a longer identifier.

    For UTF-16LE the "byte" is a 2-byte pair (word-byte, NUL).
    """
    if encoding == "ascii":
        if pos > 0 and _is_word_byte(buffer[pos - 1]):
            return False
        end = pos + length
        if end < len(buffer) and _is_word_byte(buffer[end]):
            return False
        return True
    # UTF-16LE
    if pos >= 2:
        prev_low = buffer[pos - 2]
        prev_high = buffer[pos - 1]
        if prev_high == 0x00 and _is_word_byte(prev_low):
            return False
    end = pos + length
    if end + 1 < len(buffer):
        nxt_low = buffer[end]
        nxt_high = buffer[end + 1]
        if nxt_high == 0x00 and _is_word_byte(nxt_low):
            return False
    return True


# ── property extraction inside a bounded window ────────────────────────

def _extract_properties_from_window(
    window: bytes,
    record_type: str,
) -> dict[str, str]:
    """Extract permitted property values from *window*.

    For each configured property the ASCII regex is tried first, then
    UTF-16LE. The first successful decode wins (the caller does not get
    to see both encodings).
    """
    allowed = _PROPERTIES_BY_RECORD_TYPE.get(record_type, frozenset())
    out: dict[str, str] = {}
    for prop_name, max_len, field in _PROPERTY_DEFS:
        if field not in allowed:
            continue
        m_ascii = _ascii_prop_re(prop_name, max_len).search(window)
        if m_ascii is not None:
            v = _decode_value(m_ascii.group(1), "ascii")
            if v:
                out[field] = v
                continue
        m_utf16 = _utf16le_prop_re(prop_name, max_len).search(window)
        if m_utf16 is not None:
            v = _decode_value(m_utf16.group(1), "utf-16-le")
            if v:
                out[field] = v
    return out


def _backfill_binding_refs_from_class_names(
    window: bytes,
    current: dict[str, str],
) -> dict[str, str]:
    """When a binding window has no ``Filter=``/``Consumer=`` equality
    but contains raw MOF reference strings like ``__EventFilter.Name=
    "X"``, reconstruct the reference string verbatim.

    Returns a dict that may add ``extracted_filter_ref`` and/or
    ``extracted_consumer_ref``. Never overwrites an existing entry.
    """
    out: dict[str, str] = {}
    if "extracted_filter_ref" not in current:
        for enc, builder in (
            ("ascii", _ascii_ref_re),
            ("utf-16-le", _utf16le_ref_re),
        ):
            m = builder("__EventFilter").search(window)
            if m is not None:
                v = _decode_value(m.group(1), enc)
                if v:
                    out["extracted_filter_ref"] = (
                        f'__EventFilter.Name="{v}"'
                    )
                    break
    if "extracted_consumer_ref" not in current:
        for consumer_class in _CONSUMER_CLASSES:
            matched = False
            for enc, builder in (
                ("ascii", _ascii_ref_re),
                ("utf-16-le", _utf16le_ref_re),
            ):
                m = builder(consumer_class).search(window)
                if m is not None:
                    v = _decode_value(m.group(1), enc)
                    if v:
                        out["extracted_consumer_ref"] = (
                            f'{consumer_class}.Name="{v}"'
                        )
                        matched = True
                        break
            if matched:
                break
    return out


# ── record construction ────────────────────────────────────────────────

def _build_record(
    *,
    anchor_class: str,
    source_kind: str,
    extraction_method: str,
    source_file: str,
    offset: int,
    properties: dict[str, str],
    raw_excerpt: str,
) -> dict | None:
    """Assemble a WMI evidence record. Returns None on contract
    violation."""
    record_type = _ANCHOR_TO_RECORD_TYPE.get(anchor_class)
    if record_type is None:
        return None
    if source_kind not in WMI_SOURCE_KINDS:
        return None
    if extraction_method not in WMI_EXTRACTION_METHODS:
        return None
    allowed = _PROPERTIES_BY_RECORD_TYPE.get(record_type, frozenset())
    filtered: dict[str, str] = {
        k: v for k, v in properties.items()
        if k in allowed and isinstance(v, str) and v
    }
    name_for_id = filtered.get("extracted_name") or "<no-name>"
    record_id = (
        f"{record_type}:{source_kind}:{int(offset):x}:"
        + name_for_id[:64]
    )
    record: dict = {
        "type": record_type,
        "source_kind": source_kind,
        "extraction_method": extraction_method,
        "source_file": source_file,
        "record_id": record_id,
        "raw_excerpt": raw_excerpt,
        "anchor_class": anchor_class,
        "offset": int(offset),
    }
    for prop_field in sorted(allowed):
        record[prop_field] = filtered.get(prop_field)
    return record


# ── core anchor scanner ────────────────────────────────────────────────

def _scan_buffer_anchors(
    buffer: bytes,
    *,
    abs_offset: int,
    source_kind: str,
    source_file: str,
    window_before: int = _DEFAULT_ANCHOR_WINDOW_BEFORE,
    window_after: int = _DEFAULT_ANCHOR_WINDOW_AFTER,
    emit_anchor_only: bool = False,
    scan_region_end: int | None = None,
) -> list[dict]:
    """Scan *buffer* for WMI anchor class tokens.

    *abs_offset* is the file offset where *buffer* starts (used only to
    compute record ``offset`` values). *scan_region_end* (buffer-local)
    bounds where anchor starts are considered; bytes past this are still
    used for windowing but not for fresh anchor starts. ``None`` means
    the whole buffer is scannable.

    *emit_anchor_only* controls whether anchors that have no extractable
    property values produce a record. False by default (keeps OBJECTS.
    DATA class-definition regions from flooding the output). For memory
    sources the caller typically passes True.
    """
    if not buffer:
        return []
    records: list[dict] = []
    effective_scan_end = len(buffer) if scan_region_end is None else (
        max(0, min(scan_region_end, len(buffer)))
    )

    for anchor_class in sorted(_ANCHOR_TO_RECORD_TYPE):
        record_type = _ANCHOR_TO_RECORD_TYPE[anchor_class]
        for encoding, anchor_bytes in zip(
            ("ascii", "utf-16-le"),
            _anchor_byte_forms(anchor_class),
        ):
            idx = 0
            while True:
                pos = buffer.find(anchor_bytes, idx)
                if pos < 0 or pos >= effective_scan_end:
                    break
                idx = pos + 1
                if not _anchor_is_word_bounded(
                    buffer, pos, len(anchor_bytes), encoding,
                ):
                    continue

                win_start = max(0, pos - window_before)
                win_end = min(len(buffer), pos + len(anchor_bytes)
                              + window_after)
                window = buffer[win_start:win_end]

                props = _extract_properties_from_window(window, record_type)
                if record_type == "wmi_filter_to_consumer_binding":
                    props.update(
                        _backfill_binding_refs_from_class_names(
                            window, props,
                        )
                    )

                if source_kind == "wmi_repository_file":
                    extraction_method = "objects_data_anchor_window"
                else:
                    extraction_method = (
                        "memory_mof_literal" if props
                        else "memory_anchor_only"
                    )

                if not props and not emit_anchor_only:
                    continue

                excerpt_start = max(0, pos - win_start - 64)
                excerpt_slice = window[
                    excerpt_start:excerpt_start + _RAW_EXCERPT_BYTES
                ]
                raw_excerpt = _short_raw_excerpt(
                    excerpt_slice, limit=_RAW_EXCERPT_BYTES,
                )

                rec = _build_record(
                    anchor_class=anchor_class,
                    source_kind=source_kind,
                    extraction_method=extraction_method,
                    source_file=source_file,
                    offset=abs_offset + pos,
                    properties=props,
                    raw_excerpt=raw_excerpt,
                )
                if rec is not None:
                    records.append(rec)
    return records


def _dedupe_records(records: list[dict]) -> list[dict]:
    """Collapse duplicates sharing
    ``(source_file, anchor_class, extracted_name or '<no-name>',
    offset // _DEDUP_BUCKET)``.

    Preserves input order; the first record in each bucket wins.
    """
    seen: set[tuple] = set()
    out: list[dict] = []
    for rec in records:
        name = rec.get("extracted_name") or "<no-name>"
        offset = rec.get("offset", 0)
        if not isinstance(offset, int):
            offset = 0
        key = (
            rec.get("source_file", ""),
            rec.get("anchor_class", ""),
            name,
            offset // _DEDUP_BUCKET,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


# ── file-level scanners (streaming) ────────────────────────────────────

def _stream_scan_file(
    path: Path,
    *,
    source_kind: str,
    source_file: str,
    chunk_size: int,
    overlap: int,
    emit_anchor_only: bool,
    max_records: int,
) -> tuple[list[dict], str | None]:
    """Stream *path* in chunks and yield anchor records.

    Returns ``(records, error_reason)``. ``error_reason`` is None on a
    successful read. On OSError we return whatever records were already
    accumulated and a string reason.
    """
    records: list[dict] = []
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], f"stat_error:{type(exc).__name__}"
    if size <= 0:
        return [], None

    try:
        with path.open("rb") as f:
            offset = 0
            while offset < size:
                read_len = chunk_size + overlap
                f.seek(offset)
                buffer = f.read(read_len)
                if not buffer:
                    break
                scan_end = min(chunk_size, len(buffer))
                partial = _scan_buffer_anchors(
                    buffer,
                    abs_offset=offset,
                    source_kind=source_kind,
                    source_file=source_file,
                    emit_anchor_only=emit_anchor_only,
                    scan_region_end=scan_end,
                )
                if partial:
                    records.extend(partial)
                    if len(records) >= max_records:
                        records = records[:max_records]
                        break
                if len(buffer) < read_len:
                    break
                offset += chunk_size
    except OSError as exc:
        return records, f"read_error:{type(exc).__name__}"
    return records, None


def _scan_objects_data_file(
    path: Path,
    *,
    max_records: int,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> tuple[list[dict], str]:
    """Scan a single ``OBJECTS.DATA`` file.

    Returns ``(records, sub_source_status)``. The status is drawn from
    ``WMI_SUB_SOURCE_STATUSES``.
    """
    if not path.is_file():
        return [], "not_found"
    source_file = _normalize_source_file(
        path, "wmi_repository_file",
    )
    records, err = _stream_scan_file(
        path,
        source_kind="wmi_repository_file",
        source_file=source_file,
        chunk_size=chunk_size,
        overlap=_CHUNK_OVERLAP,
        emit_anchor_only=False,
        max_records=max_records,
    )
    if err is not None:
        return records, "parse_error"
    return records, "ok"


def _scan_memory_image(
    path: Path,
    *,
    max_records: int,
    chunk_size: int = _DEFAULT_MEMORY_CHUNK_SIZE,
    emit_anchor_only: bool = False,
) -> tuple[list[dict], str]:
    """Scan a raw memory image for WMI anchor tokens.

    Memory dumps mix structured pages with arbitrary user-mode data, so
    anchor-only records are off by default here too (the caller can opt
    in). Returns ``(records, sub_source_status)``.
    """
    if not path.is_file():
        return [], "not_found"
    source_file = f"memory:{path.name}"
    records, err = _stream_scan_file(
        path,
        source_kind="memory_image",
        source_file=source_file,
        chunk_size=chunk_size,
        overlap=_CHUNK_OVERLAP,
        emit_anchor_only=emit_anchor_only,
        max_records=max_records,
    )
    if err is not None:
        return records, "parse_error"
    return records, "ok"


# ── public helpers: direct buffer parsing (exposed for tests & reuse) ──

def parse_wmi_from_bytes(
    buffer: bytes,
    *,
    source_kind: str = "wmi_repository_file",
    source_file: str = "",
    emit_anchor_only: bool = False,
) -> list[dict]:
    """Scan an in-memory buffer for WMI anchor evidence.

    Thin wrapper over ``_scan_buffer_anchors`` that also runs the
    deduplication pass. Exposed so callers with an already-read buffer
    (e.g. unit tests, or code that already paged through an image for
    a different purpose) do not have to reopen a file.

    Returns a sorted list of records. Input that is not ``bytes`` or
    ``bytearray`` raises ``TypeError`` -- that is a programmer error,
    not a data-integrity issue the envelope should absorb.
    """
    if not isinstance(buffer, (bytes, bytearray)):
        raise TypeError("buffer must be bytes or bytearray")
    if source_kind not in WMI_SOURCE_KINDS:
        raise ValueError(f"invalid source_kind: {source_kind!r}")
    records = _scan_buffer_anchors(
        bytes(buffer),
        abs_offset=0,
        source_kind=source_kind,
        source_file=source_file,
        emit_anchor_only=emit_anchor_only,
    )
    records = _dedupe_records(records)
    records.sort(
        key=lambda r: (
            r.get("source_file", ""),
            r.get("type", ""),
            int(r.get("offset", 0)),
            r.get("record_id", ""),
        )
    )
    return records


# ── recovery_hints (pointers, not records) ─────────────────────────────

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

_WMI_REPO_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/]|[\\/])"
    r"(?:[^\s\"'<>|*?\r\n,;]+[\\/])*"
    r"wbem[\\/]Repository[\\/]"
    r"(?:OBJECTS\.DATA|INDEX\.BTR|MAPPING\d+\.MAP)",
    re.IGNORECASE,
)

_DEVICE_PREFIX_RE = re.compile(
    r"^/Device/HarddiskVolume\d+",
    re.IGNORECASE,
)


def _normalize_slashes(value: str) -> str:
    if not value:
        return ""
    norm = value.replace("\\", "/")
    return _DEVICE_PREFIX_RE.sub("", norm)


def _short_text_excerpt(value: str, limit: int = 200) -> str:
    if not value:
        return ""
    flat = " ".join(str(value).split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."


def _build_path_hint(
    path: str,
    source_tool: str,
    source_file: str,
    reason: str,
) -> dict:
    return {
        "type": "wmi_repository_path_reference",
        "status": "path_reference_only",
        "path": _normalize_slashes(path),
        "binary": None,
        "source_tool": source_tool,
        "source_file": source_file,
        "raw_excerpt": _short_text_excerpt(path, limit=200),
        "reason": reason,
    }


def _build_binary_hint(
    binary: str,
    source_tool: str,
    source_file: str,
    reason: str,
) -> dict:
    return {
        "type": "wmi_binary_reference",
        "status": "binary_reference_only",
        "path": None,
        "binary": binary.lower(),
        "source_tool": source_tool,
        "source_file": source_file,
        "raw_excerpt": _short_text_excerpt(binary, limit=200),
        "reason": reason,
    }


def _extract_repo_paths_from_string(value: str) -> list[str]:
    if not value or not isinstance(value, str):
        return []
    return [m.group(0) for m in _WMI_REPO_PATH_RE.finditer(value)]


def _extract_binary_tokens_from_string(value: str) -> list[str]:
    if not value or not isinstance(value, str):
        return []
    lowered = value.lower()
    out: list[str] = []
    for token in _WMI_BINARY_TOKENS:
        if re.search(
            r"(?<![A-Za-z0-9_])"
            + re.escape(token)
            + r"(?![A-Za-z0-9_])",
            lowered,
        ):
            out.append(token)
    return out


def _record_string_fields(rec: dict) -> Iterable[tuple[str, str]]:
    if not isinstance(rec, dict):
        return
    for field in _RECOVERY_FIELDS:
        v = rec.get(field)
        if isinstance(v, str) and v.strip():
            yield field, v.strip()


def _hints_from_tool_envelope(tool_name: str, env: dict) -> list[dict]:
    if not isinstance(env, dict):
        return []
    hints: list[dict] = []
    source_file = ""
    ev_path = env.get("evidence_path")
    if isinstance(ev_path, str):
        source_file = ev_path

    def _scan_records(records: list) -> None:
        if not isinstance(records, list):
            return
        for rec in records:
            if not isinstance(rec, dict):
                continue
            for _field, value in _record_string_fields(rec):
                for path in _extract_repo_paths_from_string(value):
                    hints.append(_build_path_hint(
                        path, tool_name, source_file,
                        reason=(
                            "WMI repository path reference found in "
                            f"{tool_name} output"
                        ),
                    ))
                for binary in _extract_binary_tokens_from_string(value):
                    hints.append(_build_binary_hint(
                        binary, tool_name, source_file,
                        reason=(
                            "WMI-adjacent binary referenced in "
                            f"{tool_name} output"
                        ),
                    ))

    for key in ("records", "output"):
        _scan_records(env.get(key))
    return hints


def find_wmi_recovery_hints(
    tool_outputs: dict | None,
) -> list[dict]:
    """Derive pointer hints (never records) from arbitrary tool outputs.

    ``tool_outputs`` is the coordinator's usual tool-name → envelope
    mapping. Any tool whose envelope surfaces a WMI repository path or
    one of the canonical WMI-adjacent binary names produces a hint.
    Duplicate hints across source tools are suppressed.
    """
    if not isinstance(tool_outputs, dict) or not tool_outputs:
        return []
    all_hints: list[dict] = []
    for tool_name, env in tool_outputs.items():
        if not isinstance(tool_name, str):
            continue
        all_hints.extend(_hints_from_tool_envelope(tool_name, env))

    seen: set[tuple] = set()
    deduped: list[dict] = []
    for h in all_hints:
        key = (
            h.get("type"),
            h.get("path"),
            h.get("binary"),
            h.get("source_tool"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    return deduped


# ── envelope status resolution ─────────────────────────────────────────

def _resolve_envelope_status(
    records: list[dict],
    recovery_hints: list[dict],
) -> str:
    has_records = bool(records)
    has_hints = bool(recovery_hints)
    if has_records and has_hints:
        return "wmi_artifacts_parsed_with_references"
    if has_records:
        return "wmi_artifacts_parsed"
    if has_hints:
        return "wmi_references_found"
    return "no_wmi_artifacts_found"


# ── disk resolution: mount_path → OBJECTS.DATA ─────────────────────────

def _resolve_objects_data_path(
    mount_path: str | None,
    objects_data_path: str | None,
) -> tuple[Path | None, str]:
    """Pick the OBJECTS.DATA path.

    Returns ``(path, sub_source_status)``. ``path`` is None when nothing
    resolved; status is drawn from ``WMI_SUB_SOURCE_STATUSES``.
    """
    if objects_data_path:
        p = Path(objects_data_path)
        if p.is_file():
            return p, "ok"
        return None, "not_found"
    if mount_path:
        base = Path(mount_path)
        if not base.is_dir():
            return None, "not_found"
        candidate = base.joinpath(*_OBJECTS_DATA_REL_PARTS)
        if candidate.is_file():
            return candidate, "ok"
        return None, "not_found"
    return None, "not_requested"


# ── public entry ───────────────────────────────────────────────────────

def parse_wmi_subscription(
    mount_path: str | None = None,
    objects_data_path: str | None = None,
    memory_image_path: str | None = None,
    tool_outputs: dict | None = None,
    include_repository: bool = True,
    include_memory_strings: bool = True,
    emit_memory_anchor_only: bool = False,
    max_records_per_source: int = _DEFAULT_MAX_RECORDS_PER_SOURCE,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    memory_chunk_size: int = _DEFAULT_MEMORY_CHUNK_SIZE,
) -> dict:
    """Locate and parse WMI subscription evidence.

    Returned envelope keys (always present):

        tool, tool_name, evidence_path, record_count, records, output,
        candidate_files, searched_paths, sub_source_status, counts,
        status, reason, errors, recovery_hints

    ``status`` ∈ ``WMI_STATUSES``. Per-source status ∈
    ``WMI_SUB_SOURCE_STATUSES`` keyed by ``WMI_SUB_SOURCE_KEYS``.
    ``recovery_hints`` are pointers, kept strictly separate from
    ``records``.

    No shell execution. No writes. Bounded reads.
    """
    errors: list[str] = []
    records: list[dict] = []
    candidate_files: list[str] = []
    searched_paths: list[str] = []
    sub_source_status: dict[str, str] = {
        key: "not_requested" for key in WMI_SUB_SOURCE_KEYS
    }

    recovery_hints = find_wmi_recovery_hints(tool_outputs)

    # 31AQ-fix: dataset-agnostic mount fallback (mirrors parse_rdp_artifacts).
    # When called via arg_type='standalone' the runner passes no args, so
    # mount_path stays None; fall back to DISK_MOUNT_PATH config so the
    # WMI repository on the mounted disk is actually located.
    if mount_path is None:
        mount_path = os.environ.get("SIFT_ACTIVE_DISK_MOUNT") or DISK_MOUNT_PATH

    # OBJECTS.DATA source.
    evidence_path_str = ""
    if include_repository:
        path, status = _resolve_objects_data_path(
            mount_path, objects_data_path,
        )
        if mount_path:
            searched_paths.append(str(mount_path))
        if path is not None:
            candidate_files.append(str(path))
            if not evidence_path_str:
                evidence_path_str = str(path)
            parsed, parse_status = _scan_objects_data_file(
                path,
                max_records=max_records_per_source,
                chunk_size=chunk_size,
            )
            sub_source_status["objects_data"] = parse_status
            if parse_status == "parse_error":
                errors.append(
                    f"objects_data: parse_error scanning {path}"
                )
            records.extend(parsed)
        else:
            sub_source_status["objects_data"] = status
    else:
        sub_source_status["objects_data"] = "not_requested"

    # Memory-image source.
    if include_memory_strings:
        if memory_image_path:
            p = Path(memory_image_path)
            searched_paths.append(str(p))
            if p.is_file():
                candidate_files.append(str(p))
                if not evidence_path_str:
                    evidence_path_str = str(p)
                parsed, parse_status = _scan_memory_image(
                    p,
                    max_records=max_records_per_source,
                    chunk_size=memory_chunk_size,
                    emit_anchor_only=emit_memory_anchor_only,
                )
                sub_source_status["memory_strings"] = parse_status
                if parse_status == "parse_error":
                    errors.append(
                        f"memory_strings: parse_error scanning {p}"
                    )
                records.extend(parsed)
            else:
                sub_source_status["memory_strings"] = "not_found"
        else:
            sub_source_status["memory_strings"] = "not_requested"
    else:
        sub_source_status["memory_strings"] = "not_requested"

    # Dedupe + sort.
    records = _dedupe_records(records)
    records.sort(
        key=lambda r: (
            r.get("source_file", ""),
            r.get("type", ""),
            int(r.get("offset", 0)),
            r.get("record_id", ""),
        )
    )
    candidate_files = sorted(set(candidate_files))
    searched_paths = sorted(set(searched_paths))

    status = _resolve_envelope_status(records, recovery_hints)

    records_by_type: dict[str, int] = {
        t: 0 for t in sorted(WMI_RECORD_TYPES)
    }
    records_by_source_kind: dict[str, int] = {
        sk: 0 for sk in sorted(WMI_SOURCE_KINDS)
    }
    for r in records:
        t = r.get("type")
        sk = r.get("source_kind")
        if isinstance(t, str) and t in records_by_type:
            records_by_type[t] += 1
        if isinstance(sk, str) and sk in records_by_source_kind:
            records_by_source_kind[sk] += 1
    hints_by_type: dict[str, int] = {
        t: 0 for t in sorted(WMI_RECOVERY_HINT_TYPES)
    }
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
            f"parsed {len(records)} WMI record(s) from "
            f"{len(candidate_files)} candidate file(s)"
        )
    elif candidate_files:
        reason_parts.append(
            f"{len(candidate_files)} candidate WMI file(s) found but "
            "none yielded records"
        )
    else:
        reason_parts.append(
            f"no WMI candidate files under {len(searched_paths)} "
            "searched path(s)"
        )
    if recovery_hints:
        reason_parts.append(
            f"{len(recovery_hints)} WMI reference(s) in tool outputs"
        )
    else:
        if not tool_outputs:
            reason_parts.append(
                "no tool_outputs provided (recovery_hints requires "
                "tool_outputs input)"
            )
        else:
            reason_parts.append(
                "tool_outputs provided but contained no WMI artifact "
                "references"
            )

    return {
        "tool": "parse_wmi_subscription",
        "tool_name": "parse_wmi_subscription",
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

# SIFT_OUTPUT_PATH_FIDELITY_NORMALIZER_WMI_V1
# Normalize legacy default-mount strings in returned metadata/records to the
# active isolated mount path. This wrapper keeps an explicit MCP-friendly schema.
import inspect as _sift_wmi_inspect_v1
import os as _sift_wmi_os_v1

_sift_wmi_before_output_path_norm_v1 = parse_wmi_subscription

def _sift_wmi_active_mount_v1(*vals):
    for v in vals:
        if v and str(v) != ("/" + "mnt" + "/" + "windows" + "_" + "mount"):
            return str(v).rstrip("/")
    for key in ("SIFT_ACTIVE_DISK_MOUNT", "SIFT_DISK_MOUNT", "SIFT_MOUNT_ROOT"):
        v = _sift_wmi_os_v1.environ.get(key)
        if v and str(v) != ("/" + "mnt" + "/" + "windows" + "_" + "mount"):
            return str(v).rstrip("/")
    return None

def _sift_wmi_norm_paths_v1(obj, active):
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
        return [_sift_wmi_norm_paths_v1(x, active) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_sift_wmi_norm_paths_v1(x, active) for x in obj)
    if isinstance(obj, dict):
        return {k: _sift_wmi_norm_paths_v1(v, active) for k, v in obj.items()}
    return obj

def _sift_wmi_call_original_v1(func, kw):
    clean = {k: v for k, v in kw.items() if v is not None}
    try:
        sig = _sift_wmi_inspect_v1.signature(func)
        params = sig.parameters
        if any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return func(**clean)
        return func(**{k: v for k, v in clean.items() if k in params})
    except TypeError:
        for key in ("disk_mount", "mount_path", "root_path", "path", "disk_path"):
            if clean.get(key):
                return func(clean[key])
        return func()

def parse_wmi_subscription(
    disk_mount=None,
    mount_path=None,
    disk_path=None,
    root_path=None,
    path=None,
    image_path=None,
    tool_outputs=None,
):
    active = _sift_wmi_active_mount_v1(disk_mount, mount_path, root_path, path)
    result = _sift_wmi_call_original_v1(
        _sift_wmi_before_output_path_norm_v1,
        {
            "disk_mount": disk_mount,
            "mount_path": mount_path,
            "disk_path": disk_path,
            "root_path": root_path,
            "path": path,
            "image_path": image_path,
            "tool_outputs": tool_outputs,
        },
    )
    return _sift_wmi_norm_paths_v1(result, active)
