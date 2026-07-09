"""Slot 31E-DB.5a-beta -- central beta gate registry.

Single production source of every beta gate identifier. Keeping the
bare gate strings here guarantees the slot static scan finds them in
production (BETA_GATE_PRODUCTION_EMISSION_GATE) instead of only in test
files.

ZEROFAKE: this module never prints ``GATE=PASS`` unconditionally. The
registry holds *names*; :func:`emit` evaluates a predicate the caller
supplies (derived from runtime or AST inspection) and prints PASS/FAIL
from that boolean. A name with no evaluable evidence prints nothing.
"""
from __future__ import annotations

from typing import Callable

# Re-export the gate identifiers owned by the behavioural modules so a
# single import covers the whole beta surface.
from sift_sentinel.react_discipline import (  # noqa: F401
    HIGH_COST_RAW_SCOPE_DEDUPE_GATE,
    HIGH_COST_TOOL_BUDGET_GATE,
    REACT_INFLIGHT_TOOL_DEDUPE_GATE,
    RESET_INVOKED_GATE,
    TIMEOUT_TOOL_RETRY_GATE,
    UNAVAILABLE_TOOL_RETRY_GATE,
    VOL_MEMMAP_TIMEOUT_RETRY_GATE,
)
from sift_sentinel.model_provenance import (  # noqa: F401
    CONFIGURED_MODEL_MATCH_GATE,
    FORCED_MODEL_ROUTING_GATE,
    MODEL_LOG_REDACTION_GATE,
    MODEL_NAME_NONPERSISTENCE_GATE,
    MODEL_PROVENANCE_PRESENT_GATE,
    MODEL_ROUTING_PROVENANCE_GATE,
)

# Gates owned here (wrapper / acceptance / static-flex / emission).
MODEL_FLEXIBILITY_STATIC_GATE = "MODEL_FLEXIBILITY_STATIC_GATE"
NO_HARDCODED_MODEL_EXPECTATION_GATE = "NO_HARDCODED_MODEL_EXPECTATION_GATE"
RAW_DISK_HASH_COMMAND_GATE = "RAW_DISK_HASH_COMMAND_GATE"
CLI_ARG_SUPPORT_GATE = "CLI_ARG_SUPPORT_GATE"
INV2_ENSEMBLE_PRESENT_GATE = "INV2_ENSEMBLE_PRESENT_GATE"
ENSEMBLE_STATE_METADATA_GATE = "ENSEMBLE_STATE_METADATA_GATE"
ALL_MODEL_METADATA_GATE = "ALL_MODEL_METADATA_GATE"
BETA_GATE_PRODUCTION_EMISSION_GATE = "BETA_GATE_PRODUCTION_EMISSION_GATE"
RAW_DISK_HASH_GATE = "RAW_DISK_HASH_GATE"

BETA_GATES: tuple[str, ...] = (
    MODEL_ROUTING_PROVENANCE_GATE,
    MODEL_PROVENANCE_PRESENT_GATE,
    CONFIGURED_MODEL_MATCH_GATE,
    FORCED_MODEL_ROUTING_GATE,
    MODEL_FLEXIBILITY_STATIC_GATE,
    NO_HARDCODED_MODEL_EXPECTATION_GATE,
    MODEL_NAME_NONPERSISTENCE_GATE,
    MODEL_LOG_REDACTION_GATE,
    UNAVAILABLE_TOOL_RETRY_GATE,
    TIMEOUT_TOOL_RETRY_GATE,
    VOL_MEMMAP_TIMEOUT_RETRY_GATE,
    REACT_INFLIGHT_TOOL_DEDUPE_GATE,
    HIGH_COST_RAW_SCOPE_DEDUPE_GATE,
    HIGH_COST_TOOL_BUDGET_GATE,
    RAW_DISK_HASH_COMMAND_GATE,
    CLI_ARG_SUPPORT_GATE,
    INV2_ENSEMBLE_PRESENT_GATE,
    ENSEMBLE_STATE_METADATA_GATE,
    ALL_MODEL_METADATA_GATE,
    BETA_GATE_PRODUCTION_EMISSION_GATE,
    RESET_INVOKED_GATE,
)


def emit(name: str, predicate: Callable[[], bool]) -> bool:
    """Evaluate *predicate* and print ``<name>=PASS|FAIL`` from it.

    ZEROFAKE: PASS is only printed when the supplied predicate (a
    runtime/AST inspection) returns True. Any exception is reported as
    FAIL, never swallowed into a spurious pass.
    """
    if name not in BETA_GATES:
        raise KeyError(f"unknown beta gate: {name}")
    try:
        ok = bool(predicate())
    except Exception as exc:  # noqa: BLE001
        print(f"{name}=FAIL ({type(exc).__name__}: {exc})")
        return False
    print(f"{name}={'PASS' if ok else 'FAIL'}")
    return ok
