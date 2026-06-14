#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# SIFT_FIRST10_ZERO_SEMANTICS_GATE_V2B_COMPAT
#
# Universal contract:
# - Selected/finding-capable tools with hard errors fail.
# - Zero tools with EvidenceDB facts pass as DB producers.
# - Missing zero reasons for selected zero tools fail.
# - Coverage-zero tools may not support final/public findings.
# - Legacy substrings are preserved for existing gate tests.

TOOL_PREFIXES = ("vol_", "parse_", "run_", "get_", "extract_", "decode_")
META_KEYS = {
    "gate", "schema_version", "selected_count", "missing_reason_tools",
    "output_source", "zero_record_tools", "tools", "summary", "generated_at",
}
HARD_ERROR_STATUSES = {"error", "failed", "exception", "timeout", "runtime_error", "crashed"}
HONEST_ZERO_STATUSES = {
    "not_applicable", "ok_no_records", "no_records", "zero_records",
    "unavailable", "tool_unavailable", "coverage_zero",
}
FINDING_CAPABLE_ZERO_HARD = {
    "parse_event_logs",
    "parse_rdp_artifacts",
    "vol_amcache",
}
RESOLVER_BUG_PATTERNS = (
    "no compatible resolver arguments",
    "current tool signature",
    "missing required argument",
    "missing disk_mount",
    "missing memory image",
    "no image path provided",
    "requires -f",
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def looks_like_tool(name: str) -> bool:
    return isinstance(name, str) and name.startswith(TOOL_PREFIXES)


def record_count_for(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("records", "data", "items", "rows", "results"):
            if isinstance(value.get(key), list):
                return len(value[key])
        if "record_count" in value:
            try:
                return int(value["record_count"])
            except Exception:
                return 0
    return 0


def normalize_zero_reasons(raw: Any) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not isinstance(raw, dict):
        return out

    zlist = raw.get("zero_record_tools")
    if isinstance(zlist, list):
        for row in zlist:
            if not isinstance(row, dict):
                continue
            tool = str(row.get("tool") or "").strip()
            if not looks_like_tool(tool):
                continue
            out[tool] = {
                "status": str(row.get("status") or "").strip(),
                "reason": str(row.get("reason") or "").strip(),
            }

    for key, value in raw.items():
        if key in META_KEYS or not looks_like_tool(key):
            continue
        if isinstance(value, dict):
            out[key] = {
                "status": str(value.get("status") or "").strip(),
                "reason": str(value.get("reason") or "").strip(),
            }
        elif isinstance(value, str):
            out[key] = {"status": "", "reason": value}

    return out


def selected_tools_from_log(text: str) -> set[str]:
    tools: set[str] = set()
    for pat in (
        r"\bSELECTED:\s+([A-Za-z0-9_]+)",
        r"\bCOLLECTED:\s+([A-Za-z0-9_]+)\s+--",
        r"\bZERO_RECORD_TOOL_RESULT\s+tool=([A-Za-z0-9_]+)",
        r"\bFAILED\s+tool_?([A-Za-z0-9_]+)",
    ):
        for m in re.finditer(pat, text):
            t = m.group(1).strip()
            if looks_like_tool(t):
                tools.add(t)
    return tools


def source_tool_counts(obj: Any) -> Counter[str]:
    counts: Counter[str] = Counter()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for key in ("source_tools", "tools"):
                v = x.get(key)
                if isinstance(v, str) and looks_like_tool(v):
                    counts[v] += 1
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and looks_like_tool(item):
                            counts[item] += 1
            for key in ("source_tool", "tool", "producer_tool"):
                v = x.get(key)
                if isinstance(v, str) and looks_like_tool(v):
                    counts[v] += 1
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(obj)
    return counts


def evidence_db_source_counts(state: Path) -> Counter[str]:
    return source_tool_counts(load_json(state / "evidence_db.json"))


def final_finding_source_counts(state: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for name in (
        "finding_disposition_buckets.json",
        "findings_final.json",
        "customer_findings_table.json",
    ):
        p = state / name
        if p.exists():
            counts.update(source_tool_counts(load_json(p)))
    return counts


def raw_draft_source_counts(state: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for name in (
        "inv2_ensemble_merged.json",
        "inv2_response.json",
        "findings_validated.json",
    ):
        p = state / name
        if p.exists():
            counts.update(source_tool_counts(load_json(p)))
    return counts


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_first10_zero_semantics_gate.py STATE [LOG]")
        return 2

    state = Path(argv[1])
    log_path = Path(argv[2]) if len(argv) > 2 else None
    log_text = log_path.read_text(errors="replace") if log_path and log_path.exists() else ""

    all_outputs = load_json(state / "all_outputs.json")
    if not isinstance(all_outputs, dict):
        print(f"FIRST10_ZERO_SEMANTICS_GATE=FAIL state={state} reason=missing_all_outputs")
        return 1

    zero_reasons = normalize_zero_reasons(load_json(state / "zero_record_reasons.json"))
    selected = selected_tools_from_log(log_text)

    tools: set[str] = set(selected)
    for key in all_outputs:
        if looks_like_tool(key):
            tools.add(key)
    tools.update(zero_reasons)

    ev_counts = evidence_db_source_counts(state)
    final_counts = final_finding_source_counts(state)
    raw_counts = raw_draft_source_counts(state)

    failures: list[str] = []
    warnings: list[str] = []
    rows: list[tuple[str, int, int, str, int, int, str]] = []

    for tool in sorted(tools):
        records = record_count_for(all_outputs.get(tool))
        ev_refs = ev_counts.get(tool, 0)
        zr = zero_reasons.get(tool, {})
        status = str(zr.get("status") or "").strip()
        reason = str(zr.get("reason") or "").strip()
        status_l = status.lower()
        reason_l = reason.lower()
        final_refs = final_counts.get(tool, 0)
        raw_refs = raw_counts.get(tool, 0)

        if records > 0:
            verdict = "PASS_RECORDS"
        elif ev_refs > 0:
            verdict = "PASS_DB_PRODUCER"
        else:
            verdict = "PASS_COVERAGE_ZERO"

            if status_l in HARD_ERROR_STATUSES:
                if tool in FINDING_CAPABLE_ZERO_HARD or tool in selected:
                    verdict = "FAIL_ZERO_HARD_ERROR"
                    failures.append(f"{tool}: hard-error zero reason; {tool}: hard-fail zero reason: {status} {reason}".strip())
                else:
                    verdict = "WARN_ZERO_REASON_UNCLASSIFIED"
                    warnings.append(f"{tool}: unclassified hard-error zero reason: {status} {reason}".strip())

            elif any(p in reason_l for p in RESOLVER_BUG_PATTERNS):
                verdict = "FAIL_RESOLVER_OR_ARGUMENT_BUG"
                failures.append(f"{tool}: resolver/argument bug zero reason: {reason}")

            elif status_l in HONEST_ZERO_STATUSES:
                verdict = "PASS_COVERAGE_ZERO"

            elif status or reason:
                verdict = "WARN_ZERO_REASON_UNCLASSIFIED"
                warnings.append(f"{tool}: unclassified zero reason: {status} {reason}".strip())

            else:
                if tool in selected or tool in FINDING_CAPABLE_ZERO_HARD:
                    verdict = "FAIL_ZERO_REASON_MISSING"
                    failures.append(f"{tool}: zero records without zero-record reason; missing zero-record reason for selected/finding-capable zero tool")
                else:
                    verdict = "WARN_ZERO_REASON_MISSING"
                    warnings.append(f"{tool}: zero records with no explicit zero-record reason")

            if final_refs > 0:
                verdict = "FAIL_ZERO_TOOL_REFERENCED_BY_FINAL_FINDING"
                failures.append(
                    f"{tool}: zero/nonproducer tool referenced by findings; "
                    f"referenced by final/public findings {final_refs} time(s)"
                )

            if raw_refs > 0 and final_refs == 0:
                warnings.append(
                    f"{tool}: zero/nonproducer tool appears in raw Inv2 draft refs "
                    f"{raw_refs} time(s); allowed only if withheld/removed before final output"
                )

        rows.append((tool, records, ev_refs, status or "-", raw_refs, final_refs, verdict))

    if "no image path provided" in log_text or "Vol3 requires -f <path>" in log_text:
        failures.append("volatility: missing memory image path error in log")

    if "MFT timeline window query returned no in-range" in log_text and "MFT_WINDOW_FALLBACK_APPLIED" not in log_text:
        failures.append("extract_mft_timeline: MFT window false-zero without fallback marker")

    print("# First-10 Zero Semantics Gate")
    print()
    print(f"- state: `{state}`")
    if log_path:
        print(f"- log: `{log_path}`")
    print(f"- selected_or_seen_tools: `{len(tools)}`")
    print()
    print("| Tool | Records | EvidenceDB refs | Status | Raw draft refs | Final refs | Verdict |")
    print("|---|---:|---:|---|---:|---:|---|")
    for row in sorted(rows, key=lambda r: (0 if r[-1].startswith("FAIL") else 1 if r[-1].startswith("WARN") else 2, r[0])):
        tool, records, ev_refs, status, raw_refs, final_refs, verdict = row
        print(f"| `{tool}` | {records} | {ev_refs} | `{status}` | {raw_refs} | {final_refs} | **{verdict}** |")

    print()
    print("## Warnings")
    if warnings:
        for w in warnings:
            print(f"- WARN: {w}")
    else:
        print("- none")

    print()
    print("## Failures")
    if failures:
        for f in failures:
            print(f"- FAIL: {f}")
        print()
        print(f"FIRST10_ZERO_SEMANTICS_GATE=FAIL state={state}")
        return 1

    print("- none")
    print()
    print(f"FIRST10_ZERO_SEMANTICS_GATE=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
