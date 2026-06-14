#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.path_fidelity import count_legacy_mount_refs, repair_state_path_fidelity


def load_json(path: Path):
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir")
    ap.add_argument("--repair", action="store_true")
    ap.add_argument("--mount", default=None)
    args = ap.parse_args()

    state = Path(args.state_dir)
    if not state.is_dir():
        print("PATH_FIDELITY_GATE=FAIL reason=no_state_dir")
        return 2

    if args.repair:
        result = repair_state_path_fidelity(state, active_mount=args.mount)
        print(
            "PATH_FIDELITY_REPAIR "
            f"status={result.get('status')} "
            f"changed_files={result.get('changed_files')} "
            f"before_refs={result.get('before_refs')} "
            f"after_refs={result.get('after_refs')}"
        )

    total = 0
    bad_files = []

    targets = []
    for name in ("all_outputs.json", "evidence_db.json", "finding_disposition_buckets.json", "findings_final.json", "findings_validated.json"):
        p = state / name
        if p.exists():
            targets.append(p)

    tool_outputs = state / "tool_outputs"
    if tool_outputs.exists():
        targets.extend(sorted(tool_outputs.glob("*.json")))

    for p in targets:
        obj = load_json(p)
        if obj is None:
            continue
        count = count_legacy_mount_refs(obj)
        if count:
            total += count
            bad_files.append((p, count))

    if total:
        print(f"PATH_FIDELITY_GATE=FAIL hits={total} state={state}")
        for p, count in bad_files[:20]:
            print(f"{p}: stale_refs={count}")
        return 1

    print(f"PATH_FIDELITY_GATE=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
