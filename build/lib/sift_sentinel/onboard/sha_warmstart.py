"""Warm-SHA hand-off coordination: an in-progress marker + a bounded wait.

The onboarding step precomputes the evidence SHA256 in a background thread and
publishes the result file ATOMICALLY when done. The pipeline previously checked
that file ONCE at Step-1 and cold-re-hashed if it wasn't ready yet -- so on the
prior live run the in-flight warm hash (seconds from done) was wasted and 45 s was
spent re-hashing from zero.

This module lets the warm thread drop a ``<file>.inprogress`` marker while it runs,
and lets the pipeline WAIT for the atomic publish when a warm hash is in flight --
but never 2x-wait on a hash that failed (the marker is removed on failure too).
Pure + side-effect-free helpers (sleep/clock injected) -> unit testable.
"""
from __future__ import annotations

import os
import time


def inprogress_marker(precomputed_file: str) -> str:
    """Path of the in-flight marker for a precomputed-SHA file."""
    return str(precomputed_file) + ".inprogress"


def await_precomputed_file(
    precomputed_file: str,
    *,
    max_wait: float = 180.0,
    sleep=time.sleep,
    now=time.monotonic,
) -> bool:
    """Block until the precomputed-SHA file is published, only while a warm hash is
    actively in flight. Returns True iff the file exists when we return.

    Exits immediately when:
      * the file already exists (warm hash finished), or
      * there is no in-progress marker (no warm hash running / it failed).
    Otherwise polls until the file appears, the marker disappears (warm hash ended),
    or ``max_wait`` elapses. Bounded so a stuck marker can never hang the run.
    """
    if not precomputed_file:
        return False
    if os.path.exists(precomputed_file):
        return True
    marker = inprogress_marker(precomputed_file)
    if not os.path.exists(marker):
        return os.path.exists(precomputed_file)
    t0 = now()
    while now() - t0 < max_wait:
        if os.path.exists(precomputed_file):
            return True
        if not os.path.exists(marker):          # warm hash finished or failed
            return os.path.exists(precomputed_file)
        sleep(0.5)
    return os.path.exists(precomputed_file)


__all__ = ["inprogress_marker", "await_precomputed_file"]
