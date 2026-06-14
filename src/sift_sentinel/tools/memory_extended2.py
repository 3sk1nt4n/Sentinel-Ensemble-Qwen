"""
SIFT Sentinel - Memory forensic tools (Phase 3).
vol_svcscan, vol_sessions, vol_ssdt, vol_filescan, vol_reg_hivelist.

Always runs Volatility 3 live against the evidence image.
Each returns a typed dict matching the standard JSON envelope schema (see ARCHITECTURE.md).
"""

from __future__ import annotations

import logging
from pathlib import Path

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


# -- vol_svcscan ---------------------------------------------------------------

def vol_svcscan(image_path: str) -> dict:
    """Windows services analysis. Enumerates service records from memory.
    Reveals persistence mechanisms and attacker-installed services."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_svcscan", image_path)
    except RuntimeError as exc:
        logger.warning("vol_svcscan failed: %s", exc)
        raw = []
    return make_envelope("vol_svcscan", image_path,
                         _strip_children(raw), ms)


# -- vol_sessions --------------------------------------------------------------

def vol_sessions(image_path: str) -> dict:
    """Login session analysis. Maps sessions to users and processes.
    RDP sessions from unexpected sources = lateral movement."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_sessions", image_path)
    except RuntimeError as exc:
        logger.warning("vol_sessions failed: %s", exc)
        raw = []
    return make_envelope("vol_sessions", image_path,
                         _strip_children(raw), ms)


# -- vol_ssdt ------------------------------------------------------------------

def vol_ssdt(image_path: str) -> dict:
    """System Service Descriptor Table check. Hooked entries = rootkit.
    Must run BEFORE trusting any other process-based output."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_ssdt", image_path)
    except RuntimeError as exc:
        logger.warning("vol_ssdt failed: %s", exc)
        raw = []
    return make_envelope("vol_ssdt", image_path,
                         _strip_children(raw), ms)


# -- vol_filescan --------------------------------------------------------------

def vol_filescan(image_path: str) -> dict:
    """Find all file objects in memory. Reveals files opened by any process,
    including deleted or hidden files not visible on disk."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_filescan", image_path)
    except RuntimeError as exc:
        logger.warning("vol_filescan failed: %s", exc)
        raw = []
    return make_envelope("vol_filescan", image_path,
                         _strip_children(raw), ms)


# -- vol_mftscan ---------------------------------------------------------------

def vol_mftscan(image_path: str) -> dict:
    """Scan memory for MFT entries. Finds file metadata (names, timestamps,
    parent directories) directly from raw memory -- works WITHOUT kernel
    symbols on degraded profiles where pstree/cmdline fail."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_mftscan", image_path)
    except RuntimeError as exc:
        logger.warning("vol_mftscan failed: %s", exc)
        raw = []
    return make_envelope("vol_mftscan", image_path,
                         _strip_children(raw), ms)


# -- vol_reg_hivelist ----------------------------------------------------------

def vol_reg_hivelist(image_path: str) -> dict:
    """List loaded registry hives from memory. Shows SAM, SYSTEM, SOFTWARE,
    NTUSER.DAT locations for further registry analysis."""
    ms = start_timer()
    _check_image_path(image_path)
    try:
        raw = run_volatility("vol_reg_hivelist", image_path)
    except RuntimeError as exc:
        logger.warning("vol_reg_hivelist failed: %s", exc)
        raw = []
    return make_envelope("vol_reg_hivelist", image_path,
                         _strip_children(raw), ms)
