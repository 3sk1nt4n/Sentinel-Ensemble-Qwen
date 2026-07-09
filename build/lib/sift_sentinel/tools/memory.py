"""
SIFT Sentinel - Memory forensic tools (Phase 1).
vol_pstree, vol_netscan, vol_malfind, vol_cmdline, vol_dlllist.

Always runs Volatility 3 live against the evidence image.
Each returns a typed dict matching the standard JSON envelope schema (see ARCHITECTURE.md).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from sift_sentinel.tools.common import (
    make_envelope, run_volatility, start_timer,
)

logger = logging.getLogger(__name__)


def _flatten_tree(node: dict, acc: list[dict] | None = None) -> list[dict]:
    """Recursively flatten pstree nested __children into a flat list."""
    if acc is None:
        acc = []
    flat = {k: v for k, v in node.items() if k != "__children"}
    acc.append(flat)
    for child in node.get("__children", []):
        _flatten_tree(child, acc)
    return acc


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
    if not p.exists() and os.environ.get("SIFT_DRY_RUN") != "1":
        raise FileNotFoundError(f"Image path not found: {image_path}")


def _strip_children(raw: list[dict]) -> list[dict]:
    """Remove __children key from flat Volatility output records."""
    return [{k: v for k, v in entry.items() if k != "__children"}
            for entry in raw]


def _sift_apply_vol_exc_v1(env, exc):
    """OS/evidence incompatibility -> not_applicable; anything else -> error."""
    from sift_sentinel.tools.common import _is_vol_os_incompat_v1
    msg = str(exc)
    if _is_vol_os_incompat_v1(msg):
        env["status"] = "not_applicable"
        env["kind"] = "not_applicable"
        env["failure_mode"] = "not_applicable"
        env["reason"] = msg
        env.pop("error", None)
    else:
        env["error"] = msg
    return env


# ── vol_pstree ─────────────────────────────────────────────────────────

def vol_pstree(image_path: str) -> dict:
    """Every running process with parent-child relationships.
    Flattens the nested __children tree into a flat process list."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_pstree", image_path)
    except RuntimeError as exc:
        logger.warning("vol_pstree failed: %s", exc)
        env = make_envelope("vol_pstree", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env

    processes: list[dict] = []
    for root in raw:
        _flatten_tree(root, processes)

    return make_envelope("vol_pstree", image_path, processes, ms)


# ── vol_netscan ────────────────────────────────────────────────────────

def vol_netscan(image_path: str) -> dict:
    """All network connections by PID. C2 + lateral movement indicators."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_netscan", image_path)
    except RuntimeError as exc:
        logger.warning("vol_netscan failed: %s", exc)
        env = make_envelope("vol_netscan", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env
    return make_envelope("vol_netscan", image_path,
                         _strip_children(raw), ms)


# ── vol_malfind ────────────────────────────────────────────────────────

def vol_malfind(image_path: str) -> dict:
    """Injected code detection via VAD anomalies."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_malfind", image_path)
    except RuntimeError as exc:
        logger.warning("vol_malfind failed: %s", exc)
        env = make_envelope("vol_malfind", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env
    return make_envelope("vol_malfind", image_path,
                         _strip_children(raw), ms)


# ── vol_psxview ──────────────────────────────────────────────────────
# slot31AT-alpha: cross-view process listing for rootkit detection.

def vol_psxview(image_path: str) -> dict:
    """Cross-view process listing for rootkit detection.

    Compares multiple sources of process info (pslist, psscan, thrdproc,
    csrss, session, deskthrd). Processes visible in some sources but
    missing from others indicate DKOM-style rootkit hiding.
    """
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_psxview", image_path)
    except RuntimeError as exc:
        logger.warning("vol_psxview failed: %s", exc)
        env = make_envelope("vol_psxview", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env
    return make_envelope("vol_psxview", image_path,
                         _strip_children(raw), ms)


# ── vol_cmdline ────────────────────────────────────────────────────────

def vol_cmdline(image_path: str, pid: Optional[int] = None) -> dict:
    """Process command-line arguments. Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_cmdline", image_path)
    except RuntimeError as exc:
        logger.warning("vol_cmdline failed: %s", exc)
        env = make_envelope("vol_cmdline", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env
    cmds = _strip_children(raw)
    if pid is not None:
        cmds = [c for c in cmds if c.get("PID") == pid]
    return make_envelope("vol_cmdline", image_path, cmds, ms)


# ── vol_dlllist ────────────────────────────────────────────────────────

def vol_dlllist(image_path: str, pid: Optional[int] = None) -> dict:
    """Loaded DLLs per process. Optional PID filter."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_dlllist", image_path)
    except RuntimeError as exc:
        logger.warning("vol_dlllist failed: %s", exc)
        env = make_envelope("vol_dlllist", image_path, [], ms)
        _sift_apply_vol_exc_v1(env, exc)
        return env
    dlls = _strip_children(raw)
    if pid is not None:
        dlls = [d for d in dlls if d.get("PID") == pid]
    return make_envelope("vol_dlllist", image_path, dlls, ms)
