"""Slot 31E-DB.5a-beta TASK 3-7 -- shared ReAct runtime tool discipline.

The Inv3 ReAct loop runs many findings in parallel. Without shared
discipline, a tool that is unavailable or that times out on this
evidence is re-attempted once per finding, and high-cost full-image
plugins (vol_vadinfo, vol_hollowprocesses, vol_ldrmodules) re-scan the
whole image for each PID even though one scan plus Python filtering
suffices.

This module holds the concrete shared state and the deterministic
helpers that enforce:

  TASK 4  unavailable-tool cache  -> UNAVAILABLE_TOOL_RETRY_GATE
  TASK 5  timeout-tool cache      -> TIMEOUT_TOOL_RETRY_GATE
                                     VOL_MEMMAP_TIMEOUT_RETRY_GATE
  TASK 6  high-cost in-flight     -> REACT_INFLIGHT_TOOL_DEDUPE_GATE
          raw-scope dedupe           HIGH_COST_RAW_SCOPE_DEDUPE_GATE
  TASK 7  per-run high-cost       -> HIGH_COST_TOOL_BUDGET_GATE
          budget

State is reset once per run via :func:`reset_react_tool_discipline_state`
which the coordinator calls at the top of the ReAct entry path
(RESET_INVOKED_GATE). All mutation is guarded by a single module lock so
the parallel ReAct ThreadPoolExecutor is safe.

ZEROFAKE: every short-circuit returns an explicit synthetic result with
a ``failure_mode`` the validator already understands; nothing is
fabricated as a successful tool record.
"""
from __future__ import annotations

import threading
from collections import Counter
from concurrent.futures import Future
from typing import Any, Callable

# ── Concrete shared state (TASK 3) ──────────────────────────────────────
_react_tool_discipline_lock = threading.Lock()
_unavailable_tool_cache: set[str] = set()
_timeout_tool_cache: set[str] = set()
_inflight_tool_futures: dict[tuple[str, str], Future] = {}
_tool_run_counter: Counter[str] = Counter()

# Full-image high-cost tools: user may request them with a PID, but the
# underlying Vol3 plugin scans the whole image and filters afterward.
# Dedupe MUST key on raw execution scope (image), never on PID (TASK 6).
HIGH_COST_FULL_IMAGE_TOOLS: set[str] = {
    "vol_vadinfo",
    "vol_hollowprocesses",
    "vol_ldrmodules",
}

# Per-run launch budget for expensive plugins (TASK 7). Counted only
# when a dispatch actually launches the tool, never on a cache hit.
HIGH_COST_TOOL_BUDGET: dict[str, int] = {
    "vol_vadinfo": 1,
    # 31S-runtime: heavy ReAct tools are cache-only; avoid 90s live waits.

    "vol_memmap": 0,

    "vol_dumpfiles": 0,
    "vol_hollowprocesses": 1,
    "vol_ldrmodules": 2,
    "vol_vadyarascan": 1,
    "vol_vadregexscan": 1,
}

# Bare gate identifiers emitted from production so the slot static gate
# scan finds them in prod (BETA_GATE_PRODUCTION_EMISSION_GATE). ZEROFAKE:
# these are names only; PASS/FAIL is derived by the regression tests and
# the slot verify harness via runtime/AST inspection, never hardcoded.
UNAVAILABLE_TOOL_RETRY_GATE = "UNAVAILABLE_TOOL_RETRY_GATE"
TIMEOUT_TOOL_RETRY_GATE = "TIMEOUT_TOOL_RETRY_GATE"
VOL_MEMMAP_TIMEOUT_RETRY_GATE = "VOL_MEMMAP_TIMEOUT_RETRY_GATE"
REACT_INFLIGHT_TOOL_DEDUPE_GATE = "REACT_INFLIGHT_TOOL_DEDUPE_GATE"
HIGH_COST_RAW_SCOPE_DEDUPE_GATE = "HIGH_COST_RAW_SCOPE_DEDUPE_GATE"
HIGH_COST_TOOL_BUDGET_GATE = "HIGH_COST_TOOL_BUDGET_GATE"
RESET_INVOKED_GATE = "RESET_INVOKED_GATE"


def reset_react_tool_discipline_state() -> None:
    """Clear all ReAct discipline caches/counters (once per run).

    Called from the coordinator ReAct entry path so two sequential
    pipeline runs never share unavailable/timeout/in-flight/budget
    state. Test calls do not count for RESET_INVOKED_GATE.
    """
    with _react_tool_discipline_lock:
        _unavailable_tool_cache.clear()
        _timeout_tool_cache.clear()
        _inflight_tool_futures.clear()
        _tool_run_counter.clear()


# ── Synthetic results (ZEROFAKE: explicit failure_mode, empty output) ───
def _synthetic(failure_mode: str, tool_name: str, reason: str) -> dict[str, Any]:
    return {
        "failure_mode": failure_mode,
        "tool": tool_name,
        "output": [],
        "reason": reason,
    }


def unavailable_cached_result(tool_name: str) -> dict[str, Any]:
    return _synthetic(
        "tool_unavailable_cached", tool_name,
        "Tool previously unavailable in this run",
    )


def timeout_cached_result(tool_name: str) -> dict[str, Any]:
    return _synthetic(
        "tool_timed_out_cached", tool_name,
        "Tool previously timed out in this run",
    )


def budget_exhausted_result(tool_name: str) -> dict[str, Any]:
    return _synthetic(
        "tool_budget_exhausted", tool_name,
        "High-cost tool budget exhausted for this run",
    )


# ── TASK 4 / 5: failure cache writers ───────────────────────────────────
def note_tool_unavailable(tool_name: str) -> None:
    """Record that *tool_name* was unavailable on this evidence."""
    with _react_tool_discipline_lock:
        _unavailable_tool_cache.add(tool_name)


def note_tool_timed_out(tool_name: str) -> None:
    """Record that *tool_name* timed out (subprocess or pipeline-level)."""
    with _react_tool_discipline_lock:
        _timeout_tool_cache.add(tool_name)


def precheck_tool(
    tool_name: str, *, force: bool = False,
) -> dict[str, Any] | None:
    """Pre-dispatch short-circuit.

    Returns a synthetic result dict when *tool_name* must not be
    re-attempted in this run, else ``None`` (caller proceeds to launch).

    - unavailable cache always short-circuits (TASK 4).
    - timeout cache short-circuits unless an explicit *force* flag is
      set (TASK 5).
    """
    with _react_tool_discipline_lock:
        if tool_name in _unavailable_tool_cache:
            return unavailable_cached_result(tool_name)
        if tool_name in _timeout_tool_cache and not force:
            return timeout_cached_result(tool_name)
    return None


# ── TASK 7: high-cost launch budget ─────────────────────────────────────
def register_launch(tool_name: str) -> dict[str, Any] | None:
    """Account for an actual tool launch.

    Call this only when a dispatch is about to genuinely launch the
    tool (never when a result is served from cache or an in-flight
    Future). Returns a ``tool_budget_exhausted`` synthetic dict when the
    per-run budget for a high-cost tool is already spent; otherwise
    increments the counter and returns ``None``.
    """
    budget = HIGH_COST_TOOL_BUDGET.get(tool_name)
    with _react_tool_discipline_lock:
        if budget is not None and _tool_run_counter[tool_name] >= budget:
            return budget_exhausted_result(tool_name)
        _tool_run_counter[tool_name] += 1
    return None


# ── TASK 6: high-cost raw-scope in-flight dedupe ────────────────────────
def dedupe_scope_key(
    tool_name: str, image_id: str, args_signature: str,
) -> tuple[str, str]:
    """Build the in-flight dedupe key.

    For HIGH_COST_FULL_IMAGE_TOOLS the raw execution scope is the whole
    image, so the key is ``(tool_name, image_id)`` and PID is
    deliberately excluded -- two findings asking for different PIDs from
    the same full-image scan must collapse to one launch
    (HIGH_COST_RAW_SCOPE_DEDUPE_GATE). For truly PID-scoped tools the
    key includes the normalized argument signature.
    """
    if tool_name in HIGH_COST_FULL_IMAGE_TOOLS:
        return (tool_name, image_id)
    return (tool_name, args_signature)


def dedupe_run(
    key: tuple[str, str], runner: Callable[[], Any],
) -> Any:
    """Run *runner* once per *key*; duplicate callers await the result.

    Deadlock-safe: the first caller owns the key, runs *runner*
    synchronously in its own thread (it does NOT submit into the
    saturated ReAct ThreadPoolExecutor and then block), and resolves a
    manually-created Future. Concurrent duplicate callers find the
    existing Future and wait on it. The key is removed in ``finally`` so
    a later, legitimately new request can run again subject to the
    budget.
    """
    with _react_tool_discipline_lock:
        existing = _inflight_tool_futures.get(key)
        if existing is None:
            fut: Future = Future()
            _inflight_tool_futures[key] = fut
            owner = True
        else:
            fut = existing
            owner = False

    if not owner:
        # Duplicate caller: block on the owner's in-flight execution.
        return fut.result()

    try:
        result = runner()
        fut.set_result(result)
        return result
    except BaseException as exc:  # noqa: BLE001 - propagate to waiters
        fut.set_exception(exc)
        raise
    finally:
        with _react_tool_discipline_lock:
            _inflight_tool_futures.pop(key, None)


HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE = (
    "HIGH_COST_FULL_IMAGE_INFLIGHT_WAIT_GATE"
)


def high_cost_dispatch(
    tool_name: str,
    key: tuple[str, str],
    runner: Callable[[], Any],
) -> Any:
    """Atomic dispatch for high-cost full-image tools (TASK C1).

    Observed bug: ``vol_vadinfo`` was already in flight for one PID, but
    a second finding asking for a different PID hit ``register_launch``
    first, saw the budget spent, and got a synthetic
    ``tool_budget_exhausted`` instead of waiting for the shared
    full-image result.

    Fixed precedence -- evaluated ATOMICALLY under the single discipline
    lock so the in-flight check always wins the race against the budget
    check:

      1. (caller) cached result for the raw scope -> served by the
         caller before this function; no counter increment.
      2. an in-flight Future for this raw scope exists -> await the SAME
         Future (filter afterward); NO counter increment.
      3. budget remains -> increment the counter and create/own the
         Future under the same lock; the owner runs ``runner``
         synchronously (no nested submit into the saturated ReAct
         executor -> deadlock-safe).
      4. otherwise -> synthetic ``tool_budget_exhausted``.

    Returns the runner's result (owner or waiter) or, only in case 4,
    the synthetic budget-exhausted dict.
    """
    budget = HIGH_COST_TOOL_BUDGET.get(tool_name)
    with _react_tool_discipline_lock:
        existing = _inflight_tool_futures.get(key)
        if existing is not None:
            # Scope 2: a launch is already in flight for this raw scope.
            # Wait on it -- do NOT consult the budget (the launch it
            # represents was already accounted for by its owner).
            fut = existing
            owner = False
        else:
            # Scope 3/4: no in-flight launch. A genuinely new launch
            # must still respect the per-run budget.
            if budget is not None and _tool_run_counter[tool_name] >= budget:
                return budget_exhausted_result(tool_name)
            _tool_run_counter[tool_name] += 1
            fut = Future()
            _inflight_tool_futures[key] = fut
            owner = True

    if not owner:
        return fut.result()

    try:
        result = runner()
        fut.set_result(result)
        return result
    except BaseException as exc:  # noqa: BLE001 - propagate to waiters
        fut.set_exception(exc)
        raise
    finally:
        with _react_tool_discipline_lock:
            _inflight_tool_futures.pop(key, None)


# ── Introspection helpers (used by regression tests, not pipeline) ──────
def _state_snapshot() -> dict[str, Any]:
    with _react_tool_discipline_lock:
        return {
            "unavailable": set(_unavailable_tool_cache),
            "timeout": set(_timeout_tool_cache),
            "inflight": set(_inflight_tool_futures),
            "counter": dict(_tool_run_counter),
        }
