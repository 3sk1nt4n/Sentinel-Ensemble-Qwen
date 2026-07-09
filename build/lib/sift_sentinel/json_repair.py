"""Lenient JSON loading for LLM replies (shared by every AI invocation).

The #1 way a model breaks JSON is an UNESCAPED backslash -- a Windows path written
inside a string (``"...HKLM\\System\\ControlSet001..."``) where ``\\S`` / ``\\C`` are not
valid JSON escapes, so ``json.loads`` rejects the WHOLE reply. Observed live: Inv3a moved
0/N on exactly this. ``repair_json_escapes`` doubles any backslash that does not begin a
valid escape; ``loads_lenient`` tries the text VERBATIM first (so well-formed JSON is
never altered) then the repaired form, and re-raises the ORIGINAL error if both fail so a
caller's existing ``except JSONDecodeError`` still fires.

Universal / structural -- no case data.
"""
from __future__ import annotations

import json
import re

# A backslash that does NOT start a valid JSON escape: \" \\ \/ \b \f \n \r \t \uXXXX.
_BAD_ESCAPE_RE = re.compile(r'\\(?![\\"/bfnrtu]|u[0-9a-fA-F]{4})')


def repair_json_escapes(s: str) -> str:
    """Double any backslash that isn't part of a valid JSON escape (an unescaped Windows
    path in a model-written string)."""
    return _BAD_ESCAPE_RE.sub(r'\\\\', s or "")


def loads_lenient(s):
    """``json.loads(s)``, retrying once with stray backslashes repaired. Re-raises the
    ORIGINAL ``JSONDecodeError`` when both attempts fail."""
    try:
        return json.loads(s)
    except json.JSONDecodeError as exc:
        try:
            return json.loads(repair_json_escapes(s))
        except json.JSONDecodeError:
            raise exc


__all__ = ["repair_json_escapes", "loads_lenient"]
