"""Force-stop the pipeline's child process trees on an interrupted run.

The MCP tool server is spawned start_new_session=True (its own session / process group),
so a terminal Ctrl-C reaches only the launcher's foreground group -- never the detached
server or the Volatility subprocesses it launched. The MCP SDK's async killpg cleanup
cannot run while a blocking `vol` subprocess is in flight, so without this the detached
tools grind the remaining batch to completion AFTER the launcher has already printed
'Goodbye' (and repeated Ctrl-C does nothing, because those processes never see it).

This reaps the whole descendant tree from the launcher. Evidence is mounted read-only,
so a hard kill is safe. Dependency: psutil (already a project dep); degrades to a no-op
if unavailable.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def kill_child_process_trees(grace_seconds: float = 1.0) -> int:
    """SIGTERM, then SIGKILL after a short grace, every descendant of THIS process.

    Returns the number of descendant processes that were signalled. A heavy, detached
    `vol` process rarely honours SIGTERM, so the SIGKILL escalation is what actually
    stops it -- but well-behaved children (e.g. the parser workers) get a clean SIGTERM
    first. Never raises.
    """
    try:
        import psutil
    except Exception:
        return 0
    try:
        kids = psutil.Process().children(recursive=True)
    except Exception:
        return 0
    if not kids:
        return 0
    for p in kids:
        try:
            p.terminate()
        except Exception:
            pass
    try:
        _gone, alive = psutil.wait_procs(kids, timeout=max(0.0, grace_seconds))
    except Exception:
        alive = kids
    for p in alive:
        try:
            p.kill()
        except Exception:
            pass
    return len(kids)
