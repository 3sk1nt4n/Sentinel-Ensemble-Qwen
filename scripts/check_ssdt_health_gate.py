#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sift_sentinel.analysis.ssdt_health import (
    classify_ssdt_output,
    load_ssdt_from_state,
    strip_failed_ssdt_from_finding,
)

BUCKET_FILES = [
    "finding_disposition_buckets.json",
    "findings_final.json",
    "findings_validated.json",
]

PROMOTED_BUCKETS = {
    "confirmed_malicious_atomic",
    "suspicious_needs_review",
}


def _load_json(p: Path, default):
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(errors="ignore"))
    except Exception:
        return default


def _dump_json(p: Path, obj) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True))


def _iter_findings_obj(obj):
    if isinstance(obj, list):
        for idx, f in enumerate(obj):
            if isinstance(f, dict):
                yield None, idx, f
    elif isinstance(obj, dict):
        for bucket, vals in obj.items():
            if isinstance(vals, list):
                for idx, f in enumerate(vals):
                    if isinstance(f, dict):
                        yield bucket, idx, f


def _mentions_ssdt(f: dict) -> bool:
    blob = json.dumps({
        "source_tools": f.get("source_tools"),
        "claim_tools": f.get("claim_tools"),
        "tools_hit": f.get("tools_hit"),
        "hit_tools": f.get("hit_tools"),
        "claims": f.get("claims"),
    }, default=str)
    return "vol_ssdt" in blob or "tool_vol_ssdt" in blob


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("state_dir")
    ap.add_argument("--repair", action="store_true")
    args = ap.parse_args()

    state = Path(args.state_dir)
    if not state.exists():
        print("SSDT_HEALTH_GATE=FAIL reason=no_state_dir")
        return 2

    ssdt_obj, ssdt_path = load_ssdt_from_state(state)
    health = classify_ssdt_output(ssdt_obj)

    violations = []
    repaired_refs = 0

    if not health["can_support_finding"]:
        for fname in BUCKET_FILES:
            p = state / fname
            obj = _load_json(p, None)
            if obj is None:
                continue

            changed = False

            if isinstance(obj, list):
                new_list = []
                for f in obj:
                    if isinstance(f, dict) and _mentions_ssdt(f):
                        if args.repair:
                            nf, n = strip_failed_ssdt_from_finding(f)
                            repaired_refs += n
                            new_list.append(nf)
                            changed = changed or n > 0
                        else:
                            violations.append(f"{fname}: finding={f.get('id')} cites failed/unknown vol_ssdt")
                            new_list.append(f)
                    else:
                        new_list.append(f)
                obj = new_list

            elif isinstance(obj, dict):
                for bucket, vals in list(obj.items()):
                    if not isinstance(vals, list):
                        continue
                    new_vals = []
                    for f in vals:
                        if isinstance(f, dict) and _mentions_ssdt(f):
                            if args.repair:
                                nf, n = strip_failed_ssdt_from_finding(f)
                                repaired_refs += n
                                changed = changed or n > 0

                                # If promoted finding loses all tools/claims, route to inconclusive.
                                if bucket in PROMOTED_BUCKETS:
                                    has_tools = bool(nf.get("source_tools") or nf.get("claim_tools") or nf.get("tools_hit"))
                                    has_claims = bool(nf.get("claims"))
                                    if not has_tools or not has_claims:
                                        nf["_ssdt_health_routed"] = {
                                            "from_bucket": bucket,
                                            "reason": health["reason"],
                                        }
                                        obj.setdefault("inconclusive_unresolved", []).append(nf)
                                        changed = True
                                        continue

                                new_vals.append(nf)
                            else:
                                violations.append(f"{fname}: bucket={bucket} finding={f.get('id')} cites failed/unknown vol_ssdt")
                                new_vals.append(f)
                        else:
                            new_vals.append(f)
                    obj[bucket] = new_vals

            if args.repair and changed:
                _dump_json(p, obj)

    if violations:
        print(
            "SSDT_HEALTH_GATE=FAIL "
            f"status={health['health_status']} reason={health['reason']} "
            f"record_count={health['record_count']} violations={len(violations)} "
            f"state={state}"
        )
        for v in violations[:40]:
            print(v)
        return 1

    if args.repair:
        print(
            "SSDT_HEALTH_REPAIR "
            f"status=pass repaired_refs={repaired_refs} "
            f"ssdt_status={health['health_status']} reason={health['reason']}"
        )

    print(
        "SSDT_HEALTH_GATE=PASS "
        f"status={health['health_status']} reason={health['reason']} "
        f"record_count={health['record_count']} "
        f"can_support_finding={str(health['can_support_finding']).lower()} "
        f"state={state}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
