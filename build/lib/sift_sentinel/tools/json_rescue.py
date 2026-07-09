"""Structural JSON rescue utilities for token-cap-truncated AI responses.

No domain logic, no case-specific values, no saved state. Purely structural
JSON token scanning applicable to any AI response on any dataset.
"""
from __future__ import annotations
import json
import re

from sift_sentinel.json_repair import loads_lenient


def rescue_truncated_array_json(text: str, key: str = "findings") -> dict | None:
    """Salvage complete objects from a token-cap-truncated AI response array.

    When the output-token cap is hit mid-object, json.loads raises
    JSONDecodeError and the caller gets None -> 0 items. This function uses
    a balanced-brace walk to extract every COMPLETE object from the "<key>"
    array, even if the array and outer object are unterminated. Each object
    parses LENIENTLY (stray Windows-backslash escapes repaired -- the live
    13AA failure shape), and one unparseable object is SKIPPED so later
    complete objects still salvage (the old break discarded everything after
    the first bad object).

    Returns {key: [<complete objects>]} if any are found, else None.
    Dataset-agnostic: purely structural JSON token scanning, no domain logic.
    """
    if not text:
        return None
    # Strip markdown fences so the search starts on raw JSON text
    stripped = re.sub(r"^```[a-zA-Z]*\n?", "", text.lstrip())
    m = re.search(r'"%s"\s*:\s*\[' % re.escape(key), stripped)
    if not m:
        return None
    pos = m.end()
    items: list[dict] = []
    n = len(stripped)
    while pos < n:
        # Skip whitespace and separators
        while pos < n and stripped[pos] in ' \t\n\r,':
            pos += 1
        if pos >= n or stripped[pos] != '{':
            break
        # Balanced-brace walk: extract one complete {...} object
        depth = 0
        in_str = False
        escape = False
        end = pos
        while end < n:
            c = stripped[end]
            if escape:
                escape = False
            elif c == '\\' and in_str:
                escape = True
            elif c == '"':
                in_str = not in_str
            elif not in_str:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
            end += 1
        if depth != 0:
            break  # incomplete object — the truncation point; stop salvage
        try:
            obj = loads_lenient(stripped[pos:end])
            if isinstance(obj, dict):
                items.append(obj)
        except (json.JSONDecodeError, ValueError):
            pass  # one bad object never discards the rest
        pos = end
    return {key: items} if items else None


def rescue_truncated_findings_json(text: str) -> dict | None:
    """Back-compat wrapper: salvage the "findings" array shape (Inv2)."""
    return rescue_truncated_array_json(text, "findings")


def rescue_truncated_verdicts_json(text: str) -> dict | None:
    """Salvage the "verdicts" array shape (Inv3a finalize / adjudications)."""
    return rescue_truncated_array_json(text, "verdicts")
