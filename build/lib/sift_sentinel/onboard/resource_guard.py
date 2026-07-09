"""Disk-scratch resource guardrail (universal, dataset-agnostic).

Onboarding copies multi-GB evidence into ``/tmp/sift-onboard-ex-*`` and every run
writes a ``/tmp/sift-sentinel-run-*`` state dir (GBs of tool output). Across a
multi-case session these accumulate and can fill the disk -- after which the next
run dies on ENOSPC. This module reclaims STALE scratch from FINISHED prior runs
(never an active one) and sizes a folder's true contents so a large extraction can
be refused UP FRONT instead of half-filling the disk first.

Pure stdlib, no case data. shutil.rmtree on our own ``/tmp/sift-*`` scratch is app
self-cleanup (not the hook-guarded bash ``rm``); it never touches /cases evidence.
"""
from __future__ import annotations

import glob
import os
import shutil
import tempfile
import time

# Our scratch families under the system temp dir.
_SCRATCH_GLOBS = ("sift-sentinel-run-*", "sift-onboard-ex-*", "sift-ewf-*",
                  "sift-join-*", "sift-rar-*", "sift-hive-*")


def _tmp() -> str:
    return tempfile.gettempdir()


def free_bytes(path: str | None = None) -> int:
    try:
        return shutil.disk_usage(path or _tmp()).free
    except OSError:
        return 0


def dir_size(path: str) -> int:
    """Total bytes under ``path`` (a folder of evidence), following nothing it can't
    stat. Used so the extract preflight sees the REAL size, not a 4 KB dir entry."""
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for f in files:
            try:
                fp = os.path.join(root, f)
                if not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def prune_stale_scratch(*, keep_active=None, min_age_s: float = 1800.0,
                        now: float | None = None) -> dict:
    """Remove FINISHED prior-run scratch dirs (mtime older than ``min_age_s``), never
    one in ``keep_active`` and never one younger than ``min_age_s`` (it may be an
    active run, possibly another agent's). Returns ``{removed, freed_bytes}``.

    Conservative by design: the age gate is what makes it safe to run unconditionally
    at launch -- it only ever reclaims scratch that has clearly outlived its run."""
    keep = {str(x) for x in (keep_active or ())}
    now = now if now is not None else time.time()
    removed, freed = 0, 0
    base = _tmp()
    for pat in _SCRATCH_GLOBS:
        for d in glob.glob(os.path.join(base, pat)):
            if d in keep or not os.path.isdir(d):
                continue
            try:
                age = now - os.path.getmtime(d)
            except OSError:
                continue
            if age < min_age_s:
                continue                       # too recent -> may be active, skip
            sz = dir_size(d)
            shutil.rmtree(d, ignore_errors=True)
            if not os.path.exists(d):
                removed += 1
                freed += sz
    return {"removed": removed, "freed_bytes": freed}


def ensure_space_for(need_bytes: int, target: str | None = None, *,
                     margin_mb: int = 512, keep_active=None) -> dict:
    """Make room for an extraction of ``need_bytes``: prune stale scratch, then check.
    Returns ``{ok, free_bytes, need_bytes, reclaimed}``; ``ok`` is False when even
    after pruning there isn't ``need + margin`` free, so the caller can refuse the
    extraction cleanly instead of filling the disk."""
    target = target or _tmp()
    reclaimed = prune_stale_scratch(keep_active=keep_active)
    free = free_bytes(target)
    need_total = int(need_bytes) + (int(margin_mb) << 20)
    return {"ok": free >= need_total, "free_bytes": free,
            "need_bytes": need_total, "reclaimed": reclaimed}
