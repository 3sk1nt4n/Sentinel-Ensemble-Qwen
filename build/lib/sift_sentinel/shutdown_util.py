"""Shared helper: is an exception (or ExceptionGroup) purely a benign shutdown signal?

Ctrl-C reaches the whole foreground process group, so the MCP server subprocess and the
local-first parser workers each receive SIGINT at the same instant as the launcher. anyio
then wraps the resulting cancellation / closed-pipe errors in a BaseExceptionGroup. This
predicate lets those subprocesses exit QUIETLY (the launcher owns the user-facing
shutdown) instead of dumping tracebacks over the 'Goodbye' line.

Dataset-agnostic and dependency-free: leaves are matched by type NAME, so we neither
import anyio/asyncio internals nor miss a vendored variant.
"""
from __future__ import annotations

# Leaf exception type-names that mean "we are shutting down / the peer hung up".
_BENIGN_SHUTDOWN_NAMES = frozenset({
    "KeyboardInterrupt",
    "BrokenPipeError",
    "ConnectionResetError",
    "CancelledError",          # asyncio / anyio task cancellation
    "ClosedResourceError",     # anyio: stream closed by the peer
    "EndOfStream",             # anyio: peer hung up
    "WouldBlock",
})


def is_benign_shutdown_exc(exc: BaseException | None) -> bool:
    """True iff *exc* is, or is a group whose every leaf is, a benign shutdown signal."""
    if exc is None:
        return False
    inner = getattr(exc, "exceptions", None)
    if inner:  # BaseExceptionGroup -> benign iff it is non-empty and EVERY leaf is benign
        return len(inner) > 0 and all(is_benign_shutdown_exc(e) for e in inner)
    return type(exc).__name__ in _BENIGN_SHUTDOWN_NAMES
