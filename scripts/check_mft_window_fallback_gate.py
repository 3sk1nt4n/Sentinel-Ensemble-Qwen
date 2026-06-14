#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# SIFT_MFT_WINDOW_FALLBACK_GATE_V1C2
#
# Modes:
#   no args      -> source-only gate for compile/unit tests.
#                   Prints both SOURCE marker and legacy generic marker.
#   STATE [LOG]  -> real state/log gate.
#                   Never prints generic PASS before evaluating real failures.

ROOT = Path(__file__).resolve().parents[1]
DISK_PY = ROOT / "src" / "sift_sentinel" / "tools" / "disk.py"


def _read(path: Path | None) -> str:
    if not path:
        return ""
    try:
        return path.read_text(errors="replace")
    except Exception:
        return ""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def _records_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("records", "output", "results", "data"):
            if isinstance(value.get(key), list):
                return len(value[key])
        try:
            return int(value.get("record_count") or 0)
        except Exception:
            return 0
    return 0


def source_gate(*, emit: bool = True) -> int:
    src = _read(DISK_PY)
    required = [
        "SIFT_MFT_WINDOW_FALLBACK_WRAPPER_V1",
        "MFT_WINDOW_FALLBACK_APPLIED",
        "MFT_WINDOW_FALLBACK_ZERO",
        "SIFT_MFT_TIMELINE_IGNORE_WINDOW",
    ]
    missing = [m for m in required if m not in src]

    if missing:
        if emit:
            for m in missing:
                print(f"FAIL: missing_source_marker={m}")
            print("MFT_WINDOW_FALLBACK_SOURCE_GATE=FAIL")
            print("MFT_WINDOW_FALLBACK_GATE=FAIL")
        return 1

    if emit:
        print("MFT_WINDOW_FALLBACK_SOURCE_GATE=PASS")
        print("MFT_WINDOW_FALLBACK_GATE=PASS")
    return 0


def state_gate(state: Path, log: Path | None = None) -> int:
    failures: list[str] = []
    warnings: list[str] = []

    source_rc = source_gate(emit=False)
    if source_rc != 0:
        failures.append("source markers missing from disk.py")

    all_outputs = _load_json(state / "all_outputs.json") or {}
    zero = _load_json(state / "zero_record_reasons.json") or {}
    log_text = _read(log)

    mft_out = all_outputs.get("extract_mft_timeline")
    mft_count = _records_count(mft_out)

    zr = zero.get("extract_mft_timeline") if isinstance(zero, dict) else None
    if isinstance(zr, dict):
        status = str(zr.get("status") or "")
        reason = str(zr.get("reason") or "")
    else:
        status = ""
        reason = ""

    resolver_bug_text = "no compatible resolver arguments for current tool signature"
    if resolver_bug_text in reason or resolver_bug_text in log_text:
        failures.append(f"resolver/signature bug: {resolver_bug_text}")

    if mft_count == 0:
        false_zero = (
            "MFT timeline window query returned no in-range" in reason
            or "MFT timeline window query returned no in-range" in log_text
        )
        has_marker = (
            "MFT_WINDOW_FALLBACK_APPLIED" in log_text
            or "MFT_WINDOW_FALLBACK_ZERO" in log_text
        )
        if false_zero and not has_marker:
            failures.append("MFT window false-zero without fallback marker")
        elif status in {"not_applicable", "ok_no_records"}:
            warnings.append(f"zero_mft_status={status} reason={reason or '-'}")
    else:
        if "MFT_WINDOW_FALLBACK_APPLIED" in log_text:
            warnings.append("fallback_applied_with_records")

    print("# MFT Window Fallback Gate\n")
    print(f"- state: `{state}`")
    if log:
        print(f"- log: `{log}`")
    print(f"- extract_mft_timeline_records: `{mft_count}`")
    print(f"- zero_status: `{status or '-'}`")
    print(f"- source_markers: `{'ok' if source_rc == 0 else 'missing'}`")

    if warnings:
        print("\n## Warnings")
        for w in warnings:
            print(f"- WARN: {w}")

    if failures:
        print("\n## Failures")
        for f in failures:
            print(f"- FAIL: {f}")
        print(f"\nMFT_WINDOW_FALLBACK_GATE=FAIL state={state}")
        return 1

    print(f"\nMFT_WINDOW_FALLBACK_GATE=PASS state={state}")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return source_gate(emit=True)
    if len(sys.argv) not in {2, 3}:
        print("usage: check_mft_window_fallback_gate.py [STATE [LOG]]")
        return 2
    state = Path(sys.argv[1])
    log = Path(sys.argv[2]) if len(sys.argv) == 3 else None
    return state_gate(state, log)


if __name__ == "__main__":
    raise SystemExit(main())
