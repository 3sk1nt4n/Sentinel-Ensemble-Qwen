"""Sentinel Qwen Ensemble - Slot 31X-lite drift + coverage fail-fast gate.

Lightweight, deterministic guard run *before* expensive Inv2/ReAct/SC
work. Two independent checks:

  1. Tool-surface drift -- registry / capability / high-value / resolver
     set consistency. Catches a tool registered without a capability,
     a high-value tool missing from the callable surface, or a
     high-value/resolver set mismatch that could make Step 6 silently
     skip a selected high-value tool.

  2. EvidenceDB coverage drift -- the typed EvidenceDB sidecar built at
     Step 7 must actually emit the deterministic fact families implied
     by the raw tool outputs it was given (e.g. raw vol_malfind records
     present => at least one memory_injection_fact). On a same-evidence
     re-run it also enforces per-family typed-count regression budgets.

Design contract:
  - Pure: deterministic, no I/O, no network, no fabrication, no API
    calls. Safe to import and run with API keys unset.
  - Dataset-agnostic: validation uses *set consistency* and structural
    expectations, never hardcoded counts, IPs, PIDs, paths, or hashes.
  - Sidecar only: this module changes no validator, report, prompt,
    ReAct, model-routing, or live-execution behavior. It only inspects
    already-built artifacts and returns JSON-safe verdicts.

Reverting the wiring restores Slot 31E-DB.3 behavior with no schema
migration and no state-dir / cached-evidence dependency.
"""

from __future__ import annotations

from typing import Any

from sift_sentinel.analysis.evidence_db import (
    FACT_TYPES,
    _TOOL_COMPILERS,
    _declared_record_count,
    _records,
)

VERSION = "31X-lite"


# ── Per-family same-evidence regression budgets ──────────────────────────
# Fraction of the previous typed count a family may legitimately lose on
# a *same-evidence* re-run before it is treated as a coverage regression.
# Deterministic families (memory injection, scheduled task) get 0.0:
# identical evidence must yield an identical fact count. Noisier families
# (event log, network IOC, file execution) get a wider budget because
# upstream tool ordering / dedup can legitimately wobble the count.
COVERAGE_REGRESSION_THRESHOLDS: dict[str, float] = {
    "memory_injection_fact": 0.0,
    "process_fact": 0.05,
    "process_relationship_fact": 0.05,
    "registry_persistence_fact": 0.05,
    "scheduled_task_fact": 0.0,
    "service_fact": 0.05,
    "event_log_fact": 0.10,
    "network_connection_fact": 0.10,
    "network_ioc_fact": 0.15,
    "file_execution_fact": 0.20,
}

# Threshold applied to any future fact family not listed above.
DEFAULT_COVERAGE_REGRESSION_THRESHOLD: float = 0.20

# Family -> raw source tools that deterministically *must* yield at least
# one typed fact of that family when the source tool produced records.
# A family is satisfied if *any* listed source produced records and the
# family is non-empty; it is a hard fail only when at least one source
# produced records and the family count is zero.
FAMILY_RAW_SOURCES: dict[str, tuple[str, ...]] = {
    "memory_injection_fact": ("vol_malfind",),
    "process_fact": ("vol_pstree", "vol_psscan"),
    "network_connection_fact": ("vol_netscan",),
    "event_log_fact": ("parse_event_logs",),
    "registry_persistence_fact": ("parse_registry_persistence",),
    "scheduled_task_fact": ("parse_scheduled_tasks_disk",),
    "network_ioc_fact": ("extract_network_iocs",),
    "file_execution_fact": ("get_amcache",),
    "filesystem_timeline_fact": ("extract_mft_timeline", "sleuthkit_mactime"),
}

# Tiny absolute tolerance so a drop landing exactly on the budget passes
# despite binary float representation of fractional thresholds.
_REGRESSION_EPS = 1e-9


# ── Summary-only tools (no typed-fact compiler by design) ───────────────
# A summary-only tool emits ONE non-fact summary record describing what
# it carved/scanned (e.g. bulk_extractor reports counts of carved
# emails/URLs/domains). It does not emit per-row typed facts and has no
# entity key, so it cannot enter candidate generation. Recording its
# absence from _TOOL_COMPILERS as "silent drop" was a coverage-gate
# false positive: nothing is being dropped because there are no facts
# to emit. This set is the explicit, dataset-agnostic allowlist of such
# tools; both `silent_dropped_tools_without_compiler` and
# `zero_typed_fact_families_for_nonempty_source_tools` honour it.
#
# Membership policy:
#   * Tool must emit a fixed shape of summary record(s) with no entity
#     key (no PID, path, hash, IP, registry value, etc.).
#   * Tool must NOT appear as a source in FAMILY_RAW_SOURCES.
#   * Tool's record_count must equal len(output) (i.e. it must not
#     overstate its records as a feature-sum: see 31D bulk_extractor).
# Do NOT use this set to silence a real silent-drop on a tool that
# could be emitting typed facts. The check stays strict for everything
# else.
_SUMMARY_ONLY_TOOLS: frozenset[str] = frozenset({
    "bulk_extractor",
})

# Cache-only corroborator tools: collected so ReAct can read their RAW output
# (e.g. vol_ldrmodules' unlinked/hidden-DLL signals to clear or confirm a
# malfind RWX/injection finding), but intentionally NOT compiled into typed
# facts. Their records are consumed from the tool cache, NOT silently dropped,
# so they are exempt from the missing-compiler silent-drop check -- exactly as
# compiler-backed tools are. Universal: structural, no case data. (If a compiler
# is later registered for one of these, the _TOOL_COMPILERS check already
# excludes it, so this set composes safely.)
_CACHE_ONLY_CORROBORATOR_TOOLS: frozenset[str] = frozenset({
    "vol_ldrmodules",
})


# ════════════════════════════════════════════════════════════════════════
# 1. Tool-surface snapshot
# ════════════════════════════════════════════════════════════════════════

def _default_tool_surface_inputs() -> tuple[dict, set, set, set]:
    """Resolve the live tool surface from coordinator + capabilities +
    high-value resolver modules. Imported lazily so this module stays
    importable in isolation (and so synthetic tests can bypass it)."""
    import sift_sentinel.coordinator as _coord
    from sift_sentinel.tools.capabilities import all_registered
    from sift_sentinel.runtime import high_value_tool_args as _hv

    registry = dict(getattr(_coord, "_TOOL_REGISTRY", {}) or {})
    capability_names = set(all_registered())
    high_value = set(getattr(_hv, "HIGH_VALUE_TOOLS", frozenset()))
    resolvers = set(getattr(_hv, "_RESOLVERS", {}) or {})
    return registry, capability_names, high_value, resolvers


def build_tool_surface_snapshot(
    *,
    registry: dict | None = None,
    capability_names: set | None = None,
    high_value_tools: set | None = None,
    resolver_names: set | None = None,
) -> dict:
    """Capture the registry / capability / high-value / resolver surface.

    All inputs are injectable so synthetic tests never touch the live
    coordinator. When an input is omitted, the live surface is read.

    Returns a JSON-safe dict. Production validation must reason about
    *set consistency* of the returned name lists, never absolute counts.
    """
    if (registry is None or capability_names is None
            or high_value_tools is None or resolver_names is None):
        d_reg, d_cap, d_hv, d_res = _default_tool_surface_inputs()
        if registry is None:
            registry = d_reg
        if capability_names is None:
            capability_names = d_cap
        if high_value_tools is None:
            high_value_tools = d_hv
        if resolver_names is None:
            resolver_names = d_res

    registered = set(registry or {})
    caps = set(capability_names or set())
    hv = set(high_value_tools or set())
    res = set(resolver_names or set())

    # A registered tool is only callable if it also carries a capability
    # declaration (coordinator Rule 2). Missing capability == drift.
    missing_capabilities = sorted(registered - caps)
    # High-value tool the AI may select but that is absent from the
    # callable surface (not registered, or registered without capability).
    missing_high_value_tools = sorted(
        t for t in hv if t not in registered or t not in caps
    )
    # High-value tool with no Step 6 resolver -> Step 6 would fall back
    # to legacy coarse arg logic and may silently skip it.
    high_value_without_resolver = sorted(hv - res)
    # Resolver wired for a name that is no longer high-value -> set drift.
    resolver_without_high_value = sorted(res - hv)

    return {
        "version": VERSION,
        "registry_tool_count": len(registered),
        "capability_tool_count": len(caps),
        "high_value_tool_count": len(hv),
        "resolver_count": len(res),
        "missing_capabilities": missing_capabilities,
        "missing_high_value_tools": missing_high_value_tools,
        "high_value_without_resolver": high_value_without_resolver,
        "resolver_without_high_value": resolver_without_high_value,
        "registered_tool_names": sorted(registered),
        "capability_tool_names": sorted(caps),
        "high_value_tool_names": sorted(hv),
        "resolver_tool_names": sorted(res),
    }


def _violation(gate: str, kind: str, severity: str, message: str,
                details: dict) -> dict:
    return {
        "gate": gate,
        "kind": kind,
        "severity": severity,
        "message": message,
        "details": details,
    }


def validate_tool_surface_snapshot(snapshot: dict) -> list[dict]:
    """Hard-fail violations for tool-surface drift.

    Set-consistency only -- never absolute counts. Returns a list of
    JSON-safe violation dicts; an empty list means the surface is sound.
    """
    out: list[dict] = []
    if not isinstance(snapshot, dict):
        return [_violation(
            "tool_surface", "malformed_snapshot", "error",
            "tool-surface snapshot is not a dict",
            {"type": type(snapshot).__name__})]

    missing_caps = snapshot.get("missing_capabilities") or []
    if missing_caps:
        out.append(_violation(
            "tool_surface", "registered_tool_missing_capability", "error",
            f"{len(missing_caps)} registered tool(s) have no capability "
            f"declaration; they are non-callable under Rule 2",
            {"tools": sorted(missing_caps)}))

    missing_hv = snapshot.get("missing_high_value_tools") or []
    if missing_hv:
        out.append(_violation(
            "tool_surface", "high_value_tool_missing_from_surface", "error",
            f"{len(missing_hv)} high-value tool(s) absent from the "
            f"registered/capability surface; AI could select an "
            f"uncallable tool",
            {"tools": sorted(missing_hv)}))

    hv_no_res = snapshot.get("high_value_without_resolver") or []
    if hv_no_res:
        out.append(_violation(
            "tool_surface", "high_value_tool_missing_resolver", "error",
            f"{len(hv_no_res)} high-value tool(s) have no Step 6 "
            f"resolver; a selected high-value tool could be silently "
            f"skipped or mis-argued",
            {"tools": sorted(hv_no_res)}))

    res_no_hv = snapshot.get("resolver_without_high_value") or []
    if res_no_hv:
        out.append(_violation(
            "tool_surface", "resolver_without_high_value", "error",
            f"{len(res_no_hv)} resolver(s) wired for names no longer in "
            f"the high-value set; resolver/high-value set drift",
            {"tools": sorted(res_no_hv)}))

    return out


# ════════════════════════════════════════════════════════════════════════
# 2. EvidenceDB coverage snapshot
# ════════════════════════════════════════════════════════════════════════

def _raw_record_count(envelope: Any) -> int:
    """Authoritative raw record count the typed compiler would see."""
    recs = _records(envelope)
    return _declared_record_count(envelope, len(recs))


def build_evidencedb_coverage_snapshot(
    evidence_db: dict,
    tool_outputs: dict,
    *,
    evidence_hashes: dict[str, str] | None = None,
) -> dict:
    """Summarize typed EvidenceDB coverage versus raw tool outputs.

    Pure function. ``evidence_db`` is the dict returned by
    ``build_typed_evidence_db``; ``tool_outputs`` is the raw envelope
    map. ``evidence_hashes`` is an opaque {label: sha256} map used only
    for same-evidence baseline eligibility (never inspected for content).
    """
    evidence_db = evidence_db if isinstance(evidence_db, dict) else {}
    tool_outputs = tool_outputs if isinstance(tool_outputs, dict) else {}

    coverage = evidence_db.get("coverage") or {}
    per_tool_src = coverage.get("per_tool") or {}
    totals = coverage.get("totals") or {}

    typed_counts: dict[str, int] = {}
    declared = totals.get("fact_type_counts")
    if isinstance(declared, dict) and declared:
        for ft in FACT_TYPES:
            typed_counts[ft] = int(declared.get(ft, 0) or 0)
    else:
        typed_facts = evidence_db.get("typed_facts") or {}
        for ft in FACT_TYPES:
            fl = typed_facts.get(ft)
            typed_counts[ft] = len(fl) if isinstance(fl, list) else 0

    # Defensive JSON-safe copy of per-tool coverage (fact_types already a
    # sorted list post-build; copy dicts so callers cannot mutate evdb).
    per_tool: dict[str, dict] = {}
    for tname, cov in per_tool_src.items():
        if isinstance(cov, dict):
            per_tool[tname] = dict(cov)

    raw_counts: dict[str, int] = {}
    for tname, env in tool_outputs.items():
        raw_counts[tname] = _raw_record_count(env)

    # Compiler-supported tool produced raw records but the typed layer
    # has no coverage entry for it at all (true coverage absence, not a
    # legitimate zero-yield -- zero-yield still produces a per_tool row).
    missing_coverage = sorted(
        tname for tname in tool_outputs
        if tname in _TOOL_COMPILERS
        and raw_counts.get(tname, 0) > 0
        and tname not in per_tool
    )

    # slot31AS: silent-drop - tools with records but NO compiler.
    # 31X-LITE COVERAGE FIX: summary-only tools (e.g. bulk_extractor)
    # are exempt by design -- they have no typed facts to emit and
    # therefore nothing is being silently dropped.
    silent_drops = sorted(
        tname for tname in tool_outputs
        if tname not in _TOOL_COMPILERS
        and tname not in _SUMMARY_ONLY_TOOLS
        and tname not in _CACHE_ONLY_CORROBORATOR_TOOLS
        and raw_counts.get(tname, 0) > 0
    )

    # Family-level deterministic expectation: a source tool produced
    # records but the family it must populate is empty.
    # Summary-only tools cannot drive a family expectation: by design
    # they emit no typed facts and have no entry in FAMILY_RAW_SOURCES
    # (enforced below as a structural invariant).
    zero_families: list[dict] = []
    for family, sources in FAMILY_RAW_SOURCES.items():
        nonempty = sorted(
            s for s in sources
            if s not in _SUMMARY_ONLY_TOOLS
            and raw_counts.get(s, 0) > 0
        )
        if nonempty and typed_counts.get(family, 0) == 0:
            zero_families.append({
                "fact_family": family,
                "nonempty_raw_sources": nonempty,
                "typed_count": 0,
            })

    reconciliation_failures = sorted(
        tname for tname, cov in per_tool.items()
        if cov.get("reconciliation_ok") is False
    )

    return {
        "version": VERSION,
        "evidence_hashes": dict(evidence_hashes or {}),
        "typed_counts": typed_counts,
        "per_tool": per_tool,
        "raw_tool_record_counts": raw_counts,
        "missing_coverage_for_nonempty_compiled_tools": missing_coverage,
        "silent_dropped_tools_without_compiler": silent_drops,
        "zero_typed_fact_families_for_nonempty_source_tools":
            zero_families,
        "reconciliation_failures": reconciliation_failures,
        "all_reconciled": not reconciliation_failures,
        "summary_only_tools": sorted(_SUMMARY_ONLY_TOOLS),
    }


# ── Same-evidence baseline eligibility ──────────────────────────────────

def evidence_baseline_match(
    current_evidence_hashes: dict[str, str],
    previous_snapshot: dict | None,
) -> tuple[bool, str]:
    """Decide whether the current run analyzes the *same evidence* as a
    previous coverage snapshot.

    The drift module determines eligibility itself from the SHA256 maps;
    callers must NOT pass a same_evidence flag (a caller cannot be
    trusted to compute this correctly, and a wrong flag would silently
    enable or suppress regression checks).
    """
    if not isinstance(previous_snapshot, dict):
        return False, "no_previous_snapshot"
    prev = previous_snapshot.get("evidence_hashes")
    if not isinstance(prev, dict) or not prev:
        return False, "previous_snapshot_missing_evidence_hashes"
    cur = current_evidence_hashes or {}
    if not cur:
        return False, "evidence_files_differ"
    for label, sha in cur.items():
        if label not in prev:
            return False, "evidence_files_differ"
        if prev.get(label) != sha:
            return False, f"hash_mismatch:{label}"
    return True, "all_hashes_match"


def _regression_threshold(family: str) -> float:
    return COVERAGE_REGRESSION_THRESHOLDS.get(
        family, DEFAULT_COVERAGE_REGRESSION_THRESHOLD)


def _typed_count_regressions(
    current: dict[str, int],
    previous: dict[str, int],
) -> list[dict]:
    """Per-family regressions: a same-evidence drop exceeding the budget.

    Fails iff (prev - cur) > prev * threshold (strictly greater, with a
    tiny float epsilon so an exactly-at-budget drop passes).
    """
    out: list[dict] = []
    for family, prev_c in previous.items():
        prev_i = int(prev_c or 0)
        cur_i = int((current or {}).get(family, 0) or 0)
        if prev_i <= 0 or cur_i >= prev_i:
            continue
        drop = prev_i - cur_i
        thr = _regression_threshold(family)
        allowed = prev_i * thr
        if drop - allowed > _REGRESSION_EPS:
            out.append({
                "fact_family": family,
                "previous_count": prev_i,
                "current_count": cur_i,
                "drop": drop,
                "threshold": thr,
                "allowed_drop": allowed,
            })
    return out


def validate_evidencedb_coverage_snapshot(
    snapshot: dict,
    *,
    previous_snapshot: dict | None = None,
) -> list[dict]:
    """Hard-fail violations for EvidenceDB coverage drift.

    Returns a mixed list of JSON-safe verdict dicts. ``severity`` is
    ``error`` for a hard fail and ``warning`` for an informational
    skip (e.g. regression check skipped because evidence differs).
    The envelope splits by severity; only ``error`` fails the gate.
    """
    out: list[dict] = []
    if not isinstance(snapshot, dict):
        return [_violation(
            "evidencedb_coverage", "malformed_snapshot", "error",
            "evidencedb coverage snapshot is not a dict",
            {"type": type(snapshot).__name__})]

    for tname in snapshot.get("reconciliation_failures") or []:
        out.append(_violation(
            "evidencedb_coverage", "coverage_reconciliation_failure",
            "error",
            f"typed coverage for {tname} did not reconcile "
            f"(record_count != compiled + dropped)",
            {"tool": tname}))

    for tname in (snapshot.get(
            "missing_coverage_for_nonempty_compiled_tools") or []):
        out.append(_violation(
            "evidencedb_coverage", "missing_compiler_coverage", "error",
            f"raw tool {tname} produced records but the typed "
            f"compiler emitted no coverage entry for it",
            {"tool": tname}))

    # slot31AS: silent-dropped tools (no compiler at all)
    for tname in (snapshot.get(
            "silent_dropped_tools_without_compiler") or []):
        out.append(_violation(
            "evidencedb_coverage",
            "missing_compiler_for_nonempty_tool", "error",
            f"raw tool {tname} produced records but no compiler "
            f"is registered in _TOOL_COMPILERS - records silently dropped",
            {"tool": tname}))

    for zf in (snapshot.get(
            "zero_typed_fact_families_for_nonempty_source_tools") or []):
        fam = zf.get("fact_family")
        srcs = zf.get("nonempty_raw_sources") or []
        out.append(_violation(
            "evidencedb_coverage", "zero_typed_fact_family", "error",
            f"raw source(s) {', '.join(srcs)} produced records but "
            f"typed family {fam} is empty",
            {"fact_family": fam, "nonempty_raw_sources": list(srcs)}))

    # Same-evidence typed-count regression. Eligibility is decided here
    # from the hashes, never from a caller flag.
    cur_hashes = snapshot.get("evidence_hashes") or {}
    matched, reason = evidence_baseline_match(cur_hashes, previous_snapshot)
    if not matched:
        out.append(_violation(
            "evidencedb_coverage", "regression_check_skipped", "warning",
            f"typed-count regression check skipped: {reason}",
            {"reason": reason}))
    else:
        prev_counts = (previous_snapshot or {}).get("typed_counts") or {}
        cur_counts = snapshot.get("typed_counts") or {}
        for reg in _typed_count_regressions(cur_counts, prev_counts):
            out.append(_violation(
                "evidencedb_coverage", "typed_count_regression", "error",
                f"same-evidence regression: {reg['fact_family']} "
                f"{reg['previous_count']} -> {reg['current_count']} "
                f"(drop {reg['drop']} exceeds budget "
                f"{reg['allowed_drop']:.4f})",
                reg))

    return out


# ════════════════════════════════════════════════════════════════════════
# 3. Combined gate envelope
# ════════════════════════════════════════════════════════════════════════

def _split(verdicts: list[dict]) -> tuple[list[dict], list[dict]]:
    errors = [v for v in verdicts if v.get("severity") == "error"]
    warnings = [v for v in verdicts if v.get("severity") != "error"]
    return errors, warnings


def run_31x_lite_gate(
    *,
    tool_surface_snapshot: dict | None = None,
    evidence_db: dict | None = None,
    tool_outputs: dict | None = None,
    evidence_hashes: dict[str, str] | None = None,
    previous_evidencedb_snapshot: dict | None = None,
    tool_surface_kwargs: dict | None = None,
) -> dict:
    """Run both drift checks and return a single JSON-safe envelope.

    Either pass a prebuilt ``tool_surface_snapshot`` or let it be built
    from the live surface (optionally via ``tool_surface_kwargs`` for
    synthetic injection). The EvidenceDB section is built only when both
    ``evidence_db`` and ``tool_outputs`` are supplied.
    """
    if tool_surface_snapshot is None:
        tool_surface_snapshot = build_tool_surface_snapshot(
            **(tool_surface_kwargs or {}))
    ts_verdicts = validate_tool_surface_snapshot(tool_surface_snapshot)

    if evidence_db is not None and tool_outputs is not None:
        evdb_snapshot = build_evidencedb_coverage_snapshot(
            evidence_db, tool_outputs,
            evidence_hashes=evidence_hashes)
    else:
        evdb_snapshot = None

    if evdb_snapshot is not None:
        evdb_verdicts = validate_evidencedb_coverage_snapshot(
            evdb_snapshot,
            previous_snapshot=previous_evidencedb_snapshot)
    else:
        evdb_verdicts = []

    ts_err, ts_warn = _split(ts_verdicts)
    ev_err, ev_warn = _split(evdb_verdicts)

    cur_hashes = (evdb_snapshot or {}).get("evidence_hashes") or {}
    matched, reason = evidence_baseline_match(
        cur_hashes, previous_evidencedb_snapshot)

    violations = ts_err + ev_err
    warnings = ts_warn + ev_warn

    return {
        "version": VERSION,
        "status": "fail" if violations else "pass",
        "tool_surface": tool_surface_snapshot,
        "evidencedb_coverage": evdb_snapshot or {},
        "violations": violations,
        "warnings": warnings,
        "baseline_match": {"matched": matched, "reason": reason},
    }


__all__ = [
    "VERSION",
    "COVERAGE_REGRESSION_THRESHOLDS",
    "DEFAULT_COVERAGE_REGRESSION_THRESHOLD",
    "build_tool_surface_snapshot",
    "validate_tool_surface_snapshot",
    "build_evidencedb_coverage_snapshot",
    "evidence_baseline_match",
    "validate_evidencedb_coverage_snapshot",
    "run_31x_lite_gate",
]
