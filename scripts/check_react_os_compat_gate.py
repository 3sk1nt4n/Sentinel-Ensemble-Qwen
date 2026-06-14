#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.react_os_tool_compat import validate_log_text, resolve_vol_plugin

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", help="run.log, state dir, or repo root")
    args = ap.parse_args()

    checks = []

    # Synthetic invariant: the exact previous bug must never be allowed.
    d = resolve_vol_plugin(
        tool_name="vol_pslist",
        plugin_name="linux.pslist.PsList",
        evidence_os="windows",
    )
    if d.get("action") != "replace" or d.get("plugin") != "windows.pslist.PsList":
        print("REACT_OS_COMPAT_TOOL_GATE=FAIL reason=synthetic_windows_pslist_not_rewritten")
        return 1

    target = Path(args.path) if args.path else ROOT
    logs: list[Path] = []

    if target.is_file():
        logs = [target]
    elif target.is_dir():
        if (target / "run.log").exists():
            logs = [target / "run.log"]
        elif (target / "logs").exists():
            logs = sorted((target / "logs").glob("*/run.log"))[-25:]
        else:
            logs = []
    else:
        logs = []

    failed = []
    for log in logs:
        try:
            text = log.read_text(errors="replace")
        except Exception:
            continue
        result = validate_log_text(text)
        checks.append((log, result))
        if result.get("status") != "pass":
            failed.append((log, result))

    if failed:
        print(f"REACT_OS_COMPAT_TOOL_GATE=FAIL logs_checked={len(checks)} failed_logs={len(failed)}")
        for log, result in failed[:10]:
            print(f"{log}: evidence_os={result.get('evidence_os')} wrong_os_hits={result.get('wrong_os_hits')}")
            for item in result.get("mismatches", [])[:10]:
                print(
                    f"  tool={item.get('tool')} old_plugin={item.get('old_plugin')} "
                    f"replacement={item.get('plugin')} os={item.get('evidence_os')} "
                    f"reason={item.get('reason')}"
                )
        return 1

    print(f"REACT_OS_COMPAT_TOOL_GATE=PASS logs_checked={len(checks)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
