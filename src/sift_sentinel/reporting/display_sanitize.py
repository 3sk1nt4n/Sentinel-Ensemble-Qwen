"""Render-time display hygiene -- pure presentation, never changes a verdict.

A finding's title / IOC string must read cleanly for a human reviewer. Three
universal defects can leak into it (all observed live): the run-local SIFT mount
prefix, a raw ``artifact:[...]`` entity-key array, and trailing candidate-id
number runs. ``clean_display_text`` removes them by SHAPE -- mount-path grammar,
filename grammar, key:value grammar, number-run grammar -- never by case data.

Fail-safe: returns the input cleaned-or-unchanged and never raises. Kill-switch
SIFT_DISPLAY_SANITIZE=0.
"""
from __future__ import annotations

import os
import re

# The run-local read-only mount: <tmp>/sift-onboard-mnt/<case-id>/ ... -- strip
# up to and including the <case-id> segment so a Windows-relative path remains.
_MOUNT_RE = re.compile(r'\S*sift-onboard-mnt/[^/\s"\']+/', re.IGNORECASE)

# A recognizable file token inside an entity-key array.
_FILE_RE = re.compile(
    r'([A-Za-z0-9 _.\-]+\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|jse|wsf|scr|'
    r'com|dat|db|pf|lnk|tmp|log|txt|xml|json|zip|7z|rar|gz|reg|hive))',
    re.IGNORECASE)

# A key:value token (e.g. appid:1) -- the fallback label when no filename exists.
_KEYVAL_RE = re.compile(r'\b([a-z][a-z0-9_]{1,20}:[A-Za-z0-9._\-]{1,40})')

# Raw candidate-id leakage. The internal candidate counter is a 4-digit
# zero-padded id (0148, 0191). It leaks as: a 'Candidate_ids:' label run; a RUN
# of 2+ comma-separated 4-digit ids; or a single 4-digit id GLUED to a word by a
# stray '.'/'-' (e.g. "wiping.-0165", "cache.0191"). A STANDALONE 4-digit number
# (a year 2020, a port 8080) and a 3-digit finding-id ("F004") are preserved.
_CANDID_LABEL_RE = re.compile(r'\bcandidate_ids?\b\s*:[\s,.\d]*', re.IGNORECASE)
_CANDID_RUN_RE = re.compile(r'\b\d{4}\b(?:\s*,\s*\b\d{4}\b)+')
_CANDID_GLUE_RE = re.compile(r'(?<=[A-Za-z])\s*[.\-]+\d{4}\b')

_ARTIFACT_KEY_RE = re.compile(r'artifact\s*:\s*\[', re.IGNORECASE)
_WS_RE = re.compile(r'\s{2,}')


def _collapse_artifact_array(text: str) -> str:
    """Turn '<label>artifact:[...json...]' into '<label><recognizable token>'."""
    head, _, _tail = text.partition("artifact:")
    if not _tail:                                  # case-insensitive partition
        idx = text.lower().find("artifact:")
        head, _tail = text[:idx], text[idx + len("artifact:"):]
    body = _tail
    token = ""
    m = _FILE_RE.search(body)
    if m:
        token = m.group(1).strip().lstrip('\\/').split('\\')[-1].split('/')[-1]
    if not token:
        k = _KEYVAL_RE.search(body)
        if k:
            token = k.group(1)
    if not token:                                  # last resort: first quoted word
        q = re.search(r'"([^"{}\[\]]{1,40})"', body)
        token = (q.group(1).strip() if q else "").strip('\\"') or "(artifact)"
    label = head.strip()
    return (label + " " + token).strip() if label else token


def clean_display_text(s):
    """Clean a title/IOC/detail string for human display. Pure, fail-safe."""
    if not isinstance(s, str) or not s:
        return s
    if os.environ.get("SIFT_DISPLAY_SANITIZE", "1").strip().lower() in (
            "0", "false", "no", "off"):
        return s
    try:
        out = _MOUNT_RE.sub("", s)                 # drop the internal mount prefix
        if _ARTIFACT_KEY_RE.search(out):
            out = _collapse_artifact_array(out)
        out = _CANDID_LABEL_RE.sub("", out)
        out = _CANDID_RUN_RE.sub("", out)
        out = _CANDID_GLUE_RE.sub("", out)
        out = _WS_RE.sub(" ", out).strip()
        out = out.rstrip(" .,;:-")
        return out or s
    except Exception:
        return s
