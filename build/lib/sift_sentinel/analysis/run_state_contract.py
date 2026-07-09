from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# SIFT_RUN_STATE_CONTRACT_V1
#
# Universal contract:
# - Never evaluate a completed run using a random latest /tmp state.
# - A completed run state must contain all core state files.
# - A log/state pair is valid only when the log references the exact state path.
# - Old logs should remain allowed for historical review, but gates must not
#   silently pair them with unrelated newer states.

REQUIRED_COMPLETED_STATE_FILES = (
    "all_outputs.json",
    "evidence_db.json",
    "finding_disposition_buckets.json",
)

STEP16_RE = re.compile(r"STEP 16: ANALYSIS COMPLETE|Step 16: Pipeline complete")
STATE_PATH_RE = re.compile(r"(/tmp/sift-sentinel-run-[A-Za-z0-9_.-]+)")


def read_text(path: str | Path | None) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return ""
    return p.read_text(errors="replace")


def state_has_completed_files(state: str | Path) -> tuple[bool, list[str]]:
    root = Path(state)
    missing = [name for name in REQUIRED_COMPLETED_STATE_FILES if not (root / name).exists()]
    return (not missing), missing


def extract_state_paths_from_log_text(log_text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in STATE_PATH_RE.finditer(log_text or ""):
        val = m.group(1).rstrip(".,;:)")
        if val not in seen:
            seen.add(val)
            out.append(val)
    return out


def log_mentions_state(log_text: str, state: str | Path) -> bool:
    return str(Path(state)) in (log_text or "")


def log_has_step16(log_text: str) -> bool:
    return bool(STEP16_RE.search(log_text or ""))


def validate_state_log_pair(
    state: str | Path,
    log: str | Path,
    *,
    require_completed_state: bool = True,
    require_step16: bool = False,
) -> dict[str, Any]:
    root = Path(state)
    log_path = Path(log)
    log_text = read_text(log_path)

    failures: list[str] = []
    warnings: list[str] = []

    if not root.exists() or not root.is_dir():
        failures.append(f"state_not_found:{root}")

    if not log_path.exists() or not log_path.is_file():
        failures.append(f"log_not_found:{log_path}")

    completed, missing = state_has_completed_files(root)
    if require_completed_state and missing:
        failures.append("missing_state_files=" + ",".join(missing))

    mentioned = extract_state_paths_from_log_text(log_text)
    if log_text and not log_mentions_state(log_text, root):
        failures.append("state_log_mismatch")
        if mentioned:
            warnings.append("log_mentions_state_candidates=" + ",".join(mentioned[:5]))

    if require_step16 and log_text and not log_has_step16(log_text):
        failures.append("missing_step16_marker")

    return {
        "ok": not failures,
        "state": str(root),
        "log": str(log_path),
        "completed_state": completed,
        "missing_state_files": missing,
        "log_has_step16": log_has_step16(log_text),
        "log_mentions_state": log_mentions_state(log_text, root),
        "log_state_candidates": mentioned,
        "failures": failures,
        "warnings": warnings,
    }


def find_logs_for_state(state: str | Path, logs_root: str | Path = "logs") -> list[Path]:
    state_s = str(Path(state))
    root = Path(logs_root)
    hits: list[Path] = []
    if not root.exists():
        return hits
    for p in root.glob("**/run.log"):
        try:
            if state_s in p.read_text(errors="replace"):
                hits.append(p)
        except Exception:
            continue
    hits.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return hits


def completed_states(tmp_root: str | Path = "/tmp") -> list[Path]:
    root = Path(tmp_root)
    states = [p for p in root.glob("sift-sentinel-run-*") if p.is_dir()]
    states = [p for p in states if state_has_completed_files(p)[0]]
    states.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return states
