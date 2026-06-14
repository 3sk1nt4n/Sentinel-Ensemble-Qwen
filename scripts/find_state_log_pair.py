#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from sift_sentinel.analysis.run_state_contract import (
    completed_states,
    extract_state_paths_from_log_text,
    find_logs_for_state,
    read_text,
    state_has_completed_files,
    validate_state_log_pair,
)


def _emit(state: Path, log: Path) -> int:
    result = validate_state_log_pair(
        state,
        log,
        require_completed_state=True,
        require_step16=False,
    )
    if not result["ok"]:
        print("FAIL: invalid state/log pair")
        for f in result["failures"]:
            print(f"FAIL: {f}")
        for w in result["warnings"]:
            print(f"WARN: {w}")
        print(f"STATE={state}")
        print(f"LOG={log}")
        return 1
    print(f"STATE={state}")
    print(f"LOG={log}")
    return 0


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else None

    if target is None:
        for state in completed_states():
            logs = find_logs_for_state(state)
            if logs:
                return _emit(state, logs[0])
        print("FAIL: no completed state/log pair found")
        return 1

    if target.is_dir():
        ok, missing = state_has_completed_files(target)
        if not ok:
            print(f"FAIL: state is incomplete: {target}")
            print("missing_state_files=" + ",".join(missing))
            return 1
        logs = find_logs_for_state(target)
        if not logs:
            print(f"FAIL: no run.log references state={target}")
            return 1
        return _emit(target, logs[0])

    if target.is_file():
        text = read_text(target)
        candidates = [Path(p) for p in extract_state_paths_from_log_text(text)]
        completed = [p for p in candidates if p.exists() and state_has_completed_files(p)[0]]
        if not completed:
            print(f"FAIL: no completed state path found in log={target}")
            if candidates:
                print("candidates=" + ",".join(str(p) for p in candidates[:5]))
            return 1
        completed.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return _emit(completed[0], target)

    print(f"FAIL: target not found: {target}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
