"""Dataset-agnostic base64 / encoded-string decoder.

This module consumes already-provided runtime tool outputs (text-like
artifacts collected earlier in the run). It does not read from disk,
run commands, or make network calls, and it carries no run-specific
assumptions and no predetermined outputs.

It scans text values for base64-looking tokens, decodes the ones that
yield valid UTF-8 / UTF-16LE / ASCII payloads, and emits one record per
successful decode with the schema:

  source_tool, source_record, original_preview, decoded_preview,
  encoding, suspicious_keywords, confidence
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

TOOL_NAME = "decode_base64_strings"
EVIDENCE_TYPE = "decoded_encoded_string"

# Bounds keep this safe and fast regardless of input size.
_MAX_SCAN_CHARS = 600_000
_MAX_TOKENS = 4000
_MAX_RECORDS = 200
_PREVIEW_CHARS = 200
_MIN_TOKEN_LEN = 16
_MAX_TOKEN_LEN = 20_000

# A base64-looking run. Length / padding validity is checked on decode.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _MIN_TOKEN_LEN)

# Generic encoding / tradecraft indicators. These are well-known,
# non-dataset-specific tokens an analyst would look for in a decoded
# payload; they are not answers tied to any particular evidence set.
_SUSPICIOUS_KEYWORDS = (
    "powershell",
    "invoke-expression",
    "iex",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "webclient",
    "bitsadmin",
    "certutil",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "schtasks",
    "http://",
    "https://",
    "base64",
    "-enc",
    "-encodedcommand",
    "shellcode",
    "createremotethread",
    "virtualalloc",
)

_GENERIC_CONTAINER_KEYS = frozenset({
    "tool_name", "source_tools", "record_count", "status", "metadata",
    "errors", "failure_mode",
})


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(
        1 for ch in text
        if ch in ("\t", "\n", "\r") or 0x20 <= ord(ch) <= 0x7E
        or ord(ch) > 0xA0
    )
    return printable / len(text)


def _try_decode(raw: bytes) -> tuple[str, str] | None:
    """Return (decoded_text, encoding) for the first codec that yields
    mostly-printable text, else None."""
    for codec in ("utf-8", "utf-16-le", "ascii"):
        try:
            text = raw.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        text = text.replace("\x00", "")
        if text and _printable_ratio(text) >= 0.85:
            return text, codec
    return None


def _iter_strings(value: Any, depth: int = 0):
    """Yield string leaves from arbitrarily nested tool output."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if k in _GENERIC_CONTAINER_KEYS and isinstance(v, str):
                continue
            yield from _iter_strings(v, depth + 1)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_strings(item, depth + 1)


def _classify_confidence(
    decoded: str, keywords: list[str], ratio: float,
) -> str:
    if keywords and ratio >= 0.95:
        return "high"
    if keywords or ratio >= 0.95:
        return "medium"
    return "low"


def decode_base64_strings(tool_outputs: Any = None) -> dict:
    """Scan prior tool outputs for base64 tokens and decode them.

    ``tool_outputs`` is the mapping of ``tool_name -> envelope`` already
    produced this run. Returns a standard envelope; ``output`` is the
    list of decode records. Pure and dataset-agnostic: it only inspects
    the structure handed to it.
    """
    records: list[dict] = []
    scanned_chars = 0
    token_count = 0
    seen_tokens: set[str] = set()

    if isinstance(tool_outputs, dict):
        items = list(tool_outputs.items())
    elif isinstance(tool_outputs, (list, tuple)):
        items = list(enumerate(tool_outputs))
    else:
        items = []

    for source_tool, envelope in items:
        if len(records) >= _MAX_RECORDS or scanned_chars >= _MAX_SCAN_CHARS:
            break
        for idx, text in enumerate(_iter_strings(envelope)):
            if len(records) >= _MAX_RECORDS:
                break
            if scanned_chars >= _MAX_SCAN_CHARS:
                break
            scanned_chars += len(text)
            for match in _B64_RE.finditer(text):
                if token_count >= _MAX_TOKENS:
                    break
                token_count += 1
                token = match.group(0)
                if not (_MIN_TOKEN_LEN <= len(token) <= _MAX_TOKEN_LEN):
                    continue
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                try:
                    raw = base64.b64decode(token, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if len(raw) < 4:
                    continue
                decoded = _try_decode(raw)
                if decoded is None:
                    continue
                decoded_text, encoding = decoded
                lowered = decoded_text.lower()
                hits = [
                    kw for kw in _SUSPICIOUS_KEYWORDS if kw in lowered
                ]
                ratio = _printable_ratio(decoded_text)
                records.append({
                    "source_tool": str(source_tool),
                    "source_record": idx,
                    "original_preview": token[:_PREVIEW_CHARS],
                    "decoded_preview": decoded_text[:_PREVIEW_CHARS],
                    "encoding": encoding,
                    "suspicious_keywords": hits,
                    "confidence": _classify_confidence(
                        decoded_text, hits, ratio,
                    ),
                })
                if len(records) >= _MAX_RECORDS:
                    break

    return {
        "tool_name": TOOL_NAME,
        "output": records,
        "record_count": len(records),
        "status": "ok",
    }


__all__ = ["decode_base64_strings", "TOOL_NAME", "EVIDENCE_TYPE"]
