"""
Sentinel Qwen Ensemble - Memory forensic tools (Phase 2).
vol_psscan, vol_handles, vol_envars, vol_getsids, vol_privileges.

Always runs Volatility 3 live against the evidence image.
Each returns a typed dict matching the standard JSON envelope schema (see ARCHITECTURE.md).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sift_sentinel.tools.common import (
    make_envelope, run_volatility, start_timer,
)

logger = logging.getLogger(__name__)


def _check_image_path(image_path: str) -> None:
    """Validate image_path for memory forensic tools."""
    if not image_path or not isinstance(image_path, str):
        raise FileNotFoundError(f"Invalid image path: {image_path}")
    p = Path(image_path)
    if not p.is_absolute():
        raise FileNotFoundError(f"Image path must be absolute: {image_path}")
    # SIFT_MEM_EXT_GATE_V1: defer to the contract's universal classifier
    # (rejects known DISK suffixes; accepts any designated memory image incl.
    # split/raw .001, extensionless, odd names) -- vol3 auto-detects format
    # from content, so a literal memory-suffix allowlist wrongly rejected .001.
    from sift_sentinel.analysis.volatility_arg_contract import (
        _looks_like_memory_image as _sift_is_mem,
    )
    if not _sift_is_mem(image_path, flagged_memory_arg=True):
        raise FileNotFoundError(
            f"Unrecognized memory image extension: {p.suffix}"
        )


def _strip_children(raw: list[dict]) -> list[dict]:
    """Remove __children key from flat Volatility output records."""
    return [{k: v for k, v in entry.items() if k != "__children"}
            for entry in raw]


# ── vol_psscan ────────────────────────────────────────────────────────

def vol_psscan(image_path: str) -> dict:
    """Hidden/unlinked process scan (DKOM detection).
    Finds processes not in active process list."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_psscan", image_path)
    except RuntimeError as exc:
        logger.warning("vol_psscan failed: %s", exc)
        raw = []
    return make_envelope("vol_psscan", image_path,
                         _strip_children(raw), ms)


# ── vol_handles ───────────────────────────────────────────────────────

def vol_handles(image_path: str, pid: Optional[int] = None) -> dict:
    """Open handles per process. Shows files, registry keys, mutexes.
    Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_handles", image_path)
    except RuntimeError as exc:
        logger.warning("vol_handles failed: %s", exc)
        raw = []
    handles = _strip_children(raw)
    if pid is not None:
        handles = [h for h in handles if h.get("PID") == pid]
    return make_envelope("vol_handles", image_path, handles, ms)


# ── vol_envars ────────────────────────────────────────────────────────

def vol_envars(image_path: str, pid: Optional[int] = None) -> dict:
    """Environment variables per process. Reveals USERNAME, PATH, etc.
    Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_envars", image_path)
    except RuntimeError as exc:
        logger.warning("vol_envars failed: %s", exc)
        raw = []
    envs = _strip_children(raw)
    if pid is not None:
        envs = [e for e in envs if e.get("PID") == pid]
    return make_envelope("vol_envars", image_path, envs, ms)


# ── vol_getsids ───────────────────────────────────────────────────────

def vol_getsids(image_path: str, pid: Optional[int] = None) -> dict:
    """Security identifiers per process. Maps PID to user/group.
    Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_getsids", image_path)
    except RuntimeError as exc:
        logger.warning("vol_getsids failed: %s", exc)
        raw = []
    sids = _strip_children(raw)
    if pid is not None:
        sids = [s for s in sids if s.get("PID") == pid]
    return make_envelope("vol_getsids", image_path, sids, ms)


# ── vol_privileges ────────────────────────────────────────────────────

def vol_privileges(image_path: str, pid: Optional[int] = None) -> dict:
    """Process privilege analysis. SeDebugPrivilege = suspicious.
    Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_privileges", image_path)
    except RuntimeError as exc:
        logger.warning("vol_privileges failed: %s", exc)
        raw = []
    privs = _strip_children(raw)
    if pid is not None:
        privs = [p for p in privs if p.get("PID") == pid]
    return make_envelope("vol_privileges", image_path, privs, ms)
