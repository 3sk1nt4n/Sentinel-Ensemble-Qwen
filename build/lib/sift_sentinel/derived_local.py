"""Step 6C local-bypass dispatch for pure derived tools.

Slot 31D-STEP6C-LOCAL: a handful of Step 6C "derived-after-raw" tools
are pure functions over the in-memory tool_outputs dict. They never
read disk, run subprocesses, or talk to the network. Routing them
through the MCP stdio transport adds tens of seconds of subprocess
spawn / list_tools / JSON round-trip overhead per tool with no
behavioural benefit.

This module exposes an allow-list and a small dispatcher so the
pipeline can run those specific tools in-process. The MCP path stays
in place as the universal fallback: if anything here raises, the
caller falls back to the MCP wrapper and the run continues.

Invariants:
  * Allow-listed tools must be pure and dataset-agnostic.
  * The local path consumes the same tool_outputs structure the MCP
    server would receive after JSON round-trip; the equivalence
    requirement is asserted by tests/regression/test_31d_step6c_local.
  * The local path does NOT touch state files, MCP, subprocess,
    filesystem, or network.
  * The local path does NOT mutate tool_outputs.
  * Result envelope is whatever the underlying tool returns, with
    ``tool_name`` guaranteed to be set so downstream
    ``_slot31c4_record_count`` and storage code keep working.
"""

from __future__ import annotations

from typing import Any, Callable

PURE_DERIVED_LOCAL_TOOLS: frozenset[str] = frozenset({
    "extract_network_iocs",
    "decode_base64_strings",
})


class PureDerivedLocalUnsupported(Exception):
    """Raised when a tool is not allow-listed for the local-bypass path.

    Callers must catch this and fall back to the existing MCP dispatch
    path. It is not an error condition: it simply signals "this tool
    is not eligible for local dispatch".
    """


class PureDerivedLocalError(Exception):
    """Raised when an allow-listed tool was selected but the local
    dispatch itself failed (import error, non-dict return, etc.).

    Callers must catch this and fall back to the existing MCP dispatch
    path so the run keeps making progress.
    """


def _load_tool_callable(short_name: str) -> Callable[..., dict]:
    if short_name == "extract_network_iocs":
        from sift_sentinel.tools.extract_network_iocs import (
            extract_network_iocs as _fn,
        )
        return _fn
    if short_name == "decode_base64_strings":
        from sift_sentinel.tools.decode_base64_strings import (
            decode_base64_strings as _fn,
        )
        return _fn
    raise PureDerivedLocalUnsupported(short_name)


def run_pure_derived_local(tool_name: str, *, tool_outputs: Any) -> dict:
    """Dispatch a pure derived Step 6C tool in-process.

    Parameters
    ----------
    tool_name:
        Short tool name (e.g. ``"extract_network_iocs"``) or the
        ``tool_`` prefixed MCP-exposed name. The leading ``tool_`` is
        stripped for the allow-list check.
    tool_outputs:
        The Step 6 ``all_outputs`` mapping (``short_name -> envelope``)
        already collected this run. Passed straight through to the
        target function. It is NOT copied; callers must not assume
        the call mutates it (the helper itself does not).

    Returns
    -------
    dict
        The envelope produced by the target tool, with ``tool_name``
        ensured to be set to the short tool name.

    Raises
    ------
    PureDerivedLocalUnsupported
        ``tool_name`` is not in :data:`PURE_DERIVED_LOCAL_TOOLS`.
    PureDerivedLocalError
        The target function raised, returned a non-dict, or could not
        be imported. Callers should fall back to the MCP path.
    """
    short = str(tool_name).replace("tool_", "", 1)
    if short not in PURE_DERIVED_LOCAL_TOOLS:
        raise PureDerivedLocalUnsupported(short)

    try:
        fn = _load_tool_callable(short)
    except PureDerivedLocalUnsupported:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise PureDerivedLocalError(
            f"failed to import local handler for {short}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    try:
        result = fn(tool_outputs=tool_outputs)
    except Exception as exc:
        raise PureDerivedLocalError(
            f"{short} raised during local dispatch: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if not isinstance(result, dict):
        raise PureDerivedLocalError(
            f"{short} returned non-dict envelope: {type(result).__name__}"
        )

    if "tool_name" not in result:
        result = dict(result)
        result["tool_name"] = short
    return result


__all__ = [
    "PURE_DERIVED_LOCAL_TOOLS",
    "PureDerivedLocalError",
    "PureDerivedLocalUnsupported",
    "run_pure_derived_local",
]
