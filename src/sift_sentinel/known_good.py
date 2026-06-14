"""Optional operator-provided process context.

Competition/default behavior is intentionally empty. The pipeline must
not contain a committed static process allowlist that can suppress or
bias findings.

Optional enterprise/local mode is double opt-in:
  SIFT_ENABLE_KNOWN_GOOD=1
  SIFT_KNOWN_GOOD_FILE=/path/to/local_gitignored_json

The external file must be a JSON object mapping process name -> note.
It is operator context only; it is not evidence and must not override
current-run tool output or validator/ReAct evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_ENABLE_ENV = "SIFT_ENABLE_KNOWN_GOOD"
_FILE_ENV = "SIFT_KNOWN_GOOD_FILE"


def _load_external_known_good() -> dict[str, str]:
    """Load optional local process context.

    Empty by default. A file path alone is insufficient; the operator must
    explicitly set SIFT_ENABLE_KNOWN_GOOD=1.
    """
    if os.environ.get(_ENABLE_ENV, "").strip() != "1":
        return {}

    path_s = os.environ.get(_FILE_ENV, "").strip()
    if not path_s:
        return {}

    try:
        data: Any = json.loads(Path(path_s).read_text())
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    cleaned: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not key.strip():
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        cleaned[key.strip().lower()] = value.strip()

    return cleaned


KNOWN_GOOD_PROCESSES: dict[str, str] = _load_external_known_good()
_LOOKUP: dict[str, str] = dict(KNOWN_GOOD_PROCESSES)


def _match_known_good(text: str) -> str | None:
    """Return optional local context if text references a configured name."""
    lower = str(text).lower()
    for name, desc in _LOOKUP.items():
        if name in lower:
            return desc
    return None


def flag_known_good(findings: list[dict]) -> list[dict]:
    """Annotate findings with optional local process context.

    With default environment this is a no-op except that it sets
    known_good=False and known_good_note="". Findings are never removed.
    """
    for finding in findings:
        note = _match_known_good(finding.get("artifact", ""))

        if note is None:
            for claim in finding.get("claims", []):
                if claim.get("type") == "pid":
                    note = _match_known_good(claim.get("process", ""))
                    if note:
                        break

        finding["known_good"] = note is not None
        finding["known_good_note"] = note or ""

    return findings


def render_known_good_block() -> str:
    """Return optional local context block for Inv2 prompts.

    Default is an empty string. When enabled, the block is explicitly
    labeled non-evidentiary and must not suppress evidence-supported
    findings.
    """
    if not KNOWN_GOOD_PROCESSES:
        return ""

    body = "\n".join(
        f"- {name}: {reason}"
        for name, reason in sorted(KNOWN_GOOD_PROCESSES.items())
    )
    return (
        "OPERATOR-PROVIDED PROCESS CONTEXT "
        "(external local file; non-evidentiary):\n"
        "This context is not evidence and must not be used to dismiss "
        "evidence-supported suspicious behavior.\n\n"
        f"{body}\n"
    )
