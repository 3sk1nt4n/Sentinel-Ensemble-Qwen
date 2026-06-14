#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.zero_inference_contract import enforce_zero_inference_contract


def main(argv: list[str]) -> int:
    if not argv:
        print("ZERO_INFERENCE_CONTRACT_GATE=FAIL reason=no_state_dir")
        return 2

    state = Path(argv[0])
    repair = "--repair" in argv[1:]

    if not state.exists():
        print(f"ZERO_INFERENCE_CONTRACT_GATE=FAIL reason=missing_state state={state}")
        return 2

    result = enforce_zero_inference_contract(state, repair=repair)

    if result.get("status") == "pass":
        print(
            "ZERO_INFERENCE_CONTRACT_GATE=PASS "
            f"state={state} "
            f"producer_tools={len(result.get('producer_tools', []))} "
            f"nonproducer_tools={len(result.get('nonproducer_tools', []))}"
        )
        return 0

    print(
        "ZERO_INFERENCE_CONTRACT_GATE=FAIL "
        f"state={state} "
        f"violations={result.get('violation_count', len(result.get('violations', [])))}"
    )
    for v in result.get("violations", [])[:40]:
        print(
            f"{v.get('bucket')}:{v.get('id')} "
            f"reasons={','.join(v.get('reasons') or [])} "
            f"title={(v.get('title') or '')[:120]}"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
