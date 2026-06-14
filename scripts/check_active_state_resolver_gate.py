#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.state_dir_resolver import resolve_state_dir, state_debug

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir", nargs="?")
    args = ap.parse_args()

    resolved = resolve_state_dir(args.state_dir)
    if not resolved:
        print("ACTIVE_STATE_RESOLVER_GATE=FAIL reason=not_resolved")
        return 1

    info = state_debug(resolved)
    print(
        "ACTIVE_STATE_RESOLVER_GATE=PASS "
        f"state={resolved} markers={info.get('markers')} strong_markers={info.get('strong_markers')}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
