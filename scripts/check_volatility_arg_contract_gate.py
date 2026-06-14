#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

BAD_PATTERNS = [
    "no image path provided (Vol3 requires -f <path>)",
    "no image path provided",
]


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(errors="replace"))
    except Exception:
        return default
    return default


def _walk(o: Any):
    if isinstance(o, dict):
        yield o
        for v in o.values():
            yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def main() -> int:
    args = list(sys.argv[1:])
    if not args:
        print("VOLATILITY_ARG_CONTRACT_GATE=FAIL reason=missing_state")
        return 2

    state = Path(args[0])
    log = Path(args[1]) if len(args) > 1 and args[1] else None

    failures: list[str] = []
    warnings: list[str] = []

    if not state.exists():
        failures.append(f"state_missing={state}")

    log_text = ""
    if log and log.exists():
        log_text = log.read_text(errors="replace")
        for pat in BAD_PATTERNS:
            if pat in log_text:
                failures.append(f"log_contains={pat!r}")
        wrong_os = re.findall(r"LIVE VOL: Running (vol_[a-z0-9_]+).*?\((linux|mac)\.", log_text, flags=re.I | re.S)
        if wrong_os:
            failures.append(f"wrong_os_vol_plugins={len(wrong_os)}")
    elif log:
        warnings.append(f"log_missing={log}")

    all_outputs = _load_json(state / "all_outputs.json", {})
    bad_tool_refs = []
    vol_zero_errors = []

    for d in _walk(all_outputs):
        tool = str(d.get("tool") or d.get("source_tool") or d.get("name") or "")
        blob = json.dumps(d, default=str).lower()
        if "no image path provided" in blob:
            bad_tool_refs.append(tool or "<unknown>")
        if tool.startswith("vol_") and "no image path provided" in blob:
            vol_zero_errors.append(tool)

    if bad_tool_refs:
        failures.append("state_contains_no_image_path=" + ",".join(sorted(set(bad_tool_refs))[:20]))
    if vol_zero_errors:
        failures.append("vol_tools_missing_image_path=" + ",".join(sorted(set(vol_zero_errors))[:20]))

    common = Path("src/sift_sentinel/tools/common.py").read_text(errors="replace")
    if "SIFT_VOLATILITY_ARG_CONTRACT_COMMON_INJECTION_V1" not in common:
        failures.append("common_missing_runtime_injection")
    if "resolve_volatility_image_path" not in common:
        failures.append("common_missing_resolver_import")

    if failures:
        for w in warnings:
            print(f"WARN: {w}")
        for f in failures:
            print(f"FAIL: {f}")
        print(f"VOLATILITY_ARG_CONTRACT_GATE=FAIL state={state}" + (f" log={log}" if log else ""))
        return 1

    for w in warnings:
        print(f"WARN: {w}")
    print(f"VOLATILITY_ARG_CONTRACT_GATE=PASS state={state}" + (f" log={log}" if log else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
