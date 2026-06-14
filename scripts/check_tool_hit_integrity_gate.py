#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sift_sentinel.analysis.tool_hit_integrity import enforce_state_tool_hit_integrity

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir", nargs="?", default=None)
    ap.add_argument("--repair", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = enforce_state_tool_hit_integrity(
        state_dir=args.state_dir,
        repair=args.repair,
        fail=False,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if args.repair:
            print(
                "TOOL_HIT_INTEGRITY_REPAIR "
                f"status={result.get('status')} "
                f"removed_refs={result.get('removed_refs', 0)} "
                f"canonicalized_refs={result.get('canonicalized_refs', 0)} "
                f"dropped_claims={result.get('dropped_claims', 0)} "
                f"routed_nohit={result.get('routed_nohit_to_inconclusive', 0)} "
                f"bad_refs={len(result.get('bad_refs') or [])}"
            )

        if result.get("status") == "pass":
            print(f"TOOL_HIT_INTEGRITY_GATE=PASS state={result.get('state')}")
        else:
            print(f"TOOL_HIT_INTEGRITY_GATE=FAIL state={result.get('state')} bad_refs={len(result.get('bad_refs') or [])}")
            for item in (result.get("bad_refs") or [])[:50]:
                print(json.dumps(item, sort_keys=True))

    return 0 if result.get("status") == "pass" else 1

if __name__ == "__main__":
    raise SystemExit(main())
