from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

# SIFT_ACTIVE_STATE_RESOLVER_V1
#
# Universal contract:
# - gates must receive the active/current run state directory.
# - explicit state path wins.
# - otherwise, choose the most recent valid SIFT state, not a stale env value.
# - never pass None to Path() inside pre-report gates.

STATE_ENV_KEYS = (
    "SIFT_ACTIVE_STATE_DIR",
    "SIFT_LATEST_STATE_DIR",
    "SIFT_STATE_DIR",
    "SIFT_RUN_STATE_DIR",
    "SIFT_CURRENT_STATE_DIR",
)

STATE_MARKERS = (
    "all_outputs.json",
    "evidence_db.json",
    "finding_disposition_buckets.json",
    "findings_final.json",
    "findings_validated.json",
    "reference_set.json",
    "tool_outputs",
)

STRONG_MARKERS = (
    "all_outputs.json",
    "evidence_db.json",
    "finding_disposition_buckets.json",
    "tool_outputs",
)

def _to_path(value: Any) -> Path | None:
    if value is None:
        return None
    try:
        s = str(value).strip()
    except Exception:
        return None
    if not s or s.lower() in {"none", "null", "unknown", "-", "n/a"}:
        return None
    try:
        return Path(s)
    except Exception:
        return None

def _mtime(p: Path) -> float:
    mt = 0.0
    try:
        mt = max(mt, p.stat().st_mtime)
    except Exception:
        pass
    for name in STATE_MARKERS:
        try:
            q = p / name
            if q.exists():
                mt = max(mt, q.stat().st_mtime)
        except Exception:
            pass
    return mt

def _marker_count(p: Path) -> int:
    n = 0
    for name in STATE_MARKERS:
        try:
            if (p / name).exists():
                n += 1
        except Exception:
            pass
    return n

def _strong_count(p: Path) -> int:
    n = 0
    for name in STRONG_MARKERS:
        try:
            if (p / name).exists():
                n += 1
        except Exception:
            pass
    return n

def is_state_dir(value: Any, *, require_marker: bool = False) -> bool:
    p = _to_path(value)
    if not p or not p.exists() or not p.is_dir():
        return False
    if require_marker and _marker_count(p) == 0:
        return False
    return True

def _candidate_paths(extra: list[Any] | None = None) -> list[Path]:
    out: list[Path] = []

    def add(v: Any) -> None:
        p = _to_path(v)
        if p and p.exists() and p.is_dir() and p not in out:
            out.append(p)

    if extra:
        for v in extra:
            add(v)

    for key in STATE_ENV_KEYS:
        add(os.environ.get(key))

    for parent in (Path("/tmp"),):
        try:
            for p in parent.glob("sift-sentinel-run-*"):
                add(p)
        except Exception:
            pass

    return out

def choose_best_state_dir(candidates: list[Any]) -> str | None:
    paths = [p for p in (_to_path(c) for c in candidates) if p and p.exists() and p.is_dir()]
    if not paths:
        return None

    def score(p: Path) -> tuple[int, int, float, str]:
        return (
            1 if p.name.startswith("sift-sentinel-run-") else 0,
            _strong_count(p),
            _mtime(p),
            str(p),
        )

    # Strong-marker current run wins. Otherwise newest valid directory wins.
    paths = sorted(set(paths), key=score, reverse=True)
    return str(paths[0]) if paths else None

def resolve_state_dir(
    explicit: Any = None,
    *,
    require_existing: bool = True,
    require_marker: bool = False,
    extra_candidates: list[Any] | None = None,
) -> str | None:
    explicit_path = _to_path(explicit)
    if explicit_path:
        if not require_existing or explicit_path.exists():
            if not require_marker or _marker_count(explicit_path) > 0:
                return str(explicit_path)

    candidates: list[Any] = []
    if extra_candidates:
        candidates.extend(extra_candidates)
    candidates.extend(_candidate_paths())

    if require_marker:
        candidates = [
            c for c in candidates
            if is_state_dir(c, require_marker=True)
        ]
    elif require_existing:
        candidates = [
            c for c in candidates
            if is_state_dir(c, require_marker=False)
        ]

    return choose_best_state_dir(candidates)

def set_active_state_dir(value: Any) -> str | None:
    p = resolve_state_dir(value, require_existing=True, require_marker=False)
    if not p:
        return None
    os.environ["SIFT_ACTIVE_STATE_DIR"] = p
    os.environ["SIFT_LATEST_STATE_DIR"] = p
    return p

def state_debug(value: Any = None) -> dict[str, Any]:
    resolved = resolve_state_dir(value)
    p = Path(resolved) if resolved else None
    return {
        "resolved": resolved,
        "exists": bool(p and p.exists()),
        "markers": _marker_count(p) if p else 0,
        "strong_markers": _strong_count(p) if p else 0,
        "mtime": _mtime(p) if p else 0.0,
    }

def _selftest() -> None:
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="sift-state-resolver-test-"))
    older = root / "sift-sentinel-run-old"
    newer = root / "sift-sentinel-run-new"
    older.mkdir()
    newer.mkdir()
    (older / "all_outputs.json").write_text("{}")
    time.sleep(0.01)
    (newer / "all_outputs.json").write_text("{}")
    assert choose_best_state_dir([older, newer]) == str(newer)
    assert resolve_state_dir(str(newer)) == str(newer)

if __name__ == "__main__":
    _selftest()
    print("ACTIVE_STATE_RESOLVER_SELFTEST=PASS")
