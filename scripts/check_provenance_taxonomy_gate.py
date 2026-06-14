#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.provenance_taxonomy import enforce_state_provenance_taxonomy


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir")
    ap.add_argument("--repair", action="store_true")
    ap.add_argument("--no-route", action="store_true")
    args = ap.parse_args()

    state = Path(args.state_dir)
    if not state.exists():
        print(f"PROVENANCE_TAXONOMY_GATE=FAIL reason=no_state state={state}")
        return 2

    result = enforce_state_provenance_taxonomy(
        state,
        repair=args.repair,
        route_nohit=not args.no_route,
    )

    if args.repair:
        print(
            "PROVENANCE_TAXONOMY_REPAIR "
            f"status={result.get('status')} "
            f"removed_refs={result.get('removed_refs', 0)} "
            f"canonicalized_refs={result.get('canonicalized_refs', 0)} "
            f"moved_non_tool_refs={result.get('moved_non_tool_refs', 0)} "
            f"routed_nohit={result.get('routed_nohit_to_inconclusive', 0)}"
        )

    if result.get("status") == "pass":
        print(
            "PROVENANCE_TAXONOMY_GATE=PASS "
            f"state={state} "
            f"producer_tools={len(result.get('producer_tools') or [])} "
            f"nonproducer_tools={len(result.get('nonproducer_tools') or [])}"
        )
        return 0

    bad = result.get("bad_refs") or result.get("post_repair_bad_refs") or []
    print(
        "PROVENANCE_TAXONOMY_GATE=FAIL "
        f"state={state} bad_refs={len(bad)}"
    )
    for item in bad[:25]:
        print(
            f"{item.get('file')}:{item.get('field')}: "
            f"{item.get('raw')} ({item.get('class')})"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
