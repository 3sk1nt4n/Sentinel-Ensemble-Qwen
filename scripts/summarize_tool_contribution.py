#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sift_sentinel.analysis.tool_hit_integrity import (
    build_hit_maps,
    canonical_tool_name,
)

TOOL_PREFIXES = ("vol_", "parse_", "run_", "get_", "extract_", "decode_", "tool_")
TOOL_REF_FIELDS = {
    "source_tool",
    "source_tools",
    "tool",
    "tools",
    "tools_hit",
    "hit_tools",
    "claim_tools",
    "evidence_tools",
    "validator_tools",
    "supporting_tools",
    "contributing_tools",
}

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="ignore"))

def load_outputs(state: Path) -> dict[str, Any]:
    outputs: dict[str, Any] = {}
    p = state / "all_outputs.json"
    if p.exists():
        obj = load_json(p)
        if isinstance(obj, dict):
            outputs.update(obj)
    td = state / "tool_outputs"
    if td.exists():
        for f in sorted(td.glob("*.json")):
            try:
                outputs[f.stem] = load_json(f)
            except Exception:
                pass
    return outputs

def state_files(state: Path) -> list[Path]:
    names = [
        "findings_final.json",
        "findings_validated.json",
        "finding_disposition_buckets.json",
        "pipeline_summary.json",
    ]
    return [state / n for n in names if (state / n).exists()]

def looks_like_tool(value: str, known: set[str]) -> bool:
    c = canonical_tool_name(value)
    return c in known or c.startswith(TOOL_PREFIXES) or "appcompatcacheparser" in c

def split_tool_string(value: str) -> list[str]:
    if "," in value:
        return [x.strip() for x in value.split(",") if x.strip()]
    return [value.strip()] if value.strip() else []

def collect_refs(obj: Any, known: set[str], out: Counter[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in TOOL_REF_FIELDS:
                vals = v if isinstance(v, list) else split_tool_string(v) if isinstance(v, str) else [v]
                for item in vals:
                    if isinstance(item, str) and looks_like_tool(item, known):
                        out[canonical_tool_name(item)] += 1
                continue
            collect_refs(v, known, out)
    elif isinstance(obj, list):
        for item in obj:
            collect_refs(item, known, out)

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize_tool_contribution.py STATE_DIR")
        return 2

    state = Path(sys.argv[1])
    outputs = load_outputs(state)
    hit_map, zero_map = build_hit_maps(outputs)

    known = set(hit_map) | set(zero_map)
    contributing = Counter()

    for f in state_files(state):
        try:
            collect_refs(load_json(f), known, contributing)
        except Exception as exc:
            print(f"WARN could_not_scan={f} error={exc}")

    hit_tools = sorted(hit_map)
    zero_tools = sorted(zero_map)
    contributing_tools = sorted(contributing)

    bad_zero_refs = sorted(t for t in contributing_tools if t in zero_map)
    bad_absent_refs = sorted(t for t in contributing_tools if t not in hit_map and t not in zero_map)
    noncontrib_data_tools = sorted(t for t in hit_tools if t not in contributing)

    print("===== TOOL CONTRIBUTION SUMMARY =====")
    print(f"state={state}")
    print(f"data_producing_tools={len(hit_tools)}")
    print(f"zero_or_nonhit_tools={len(zero_tools)}")
    print(f"contributing_tools_in_findings={len(contributing_tools)}")
    print()
    print("HIT_TOOLS_CONTRIBUTING=" + ",".join(contributing_tools))
    print("DATA_PRODUCING_NOT_IN_FINDINGS=" + ",".join(noncontrib_data_tools))
    print("ZERO_OR_NONHIT_TOOLS=" + ",".join(zero_tools))
    print()

    if bad_zero_refs or bad_absent_refs:
        print(f"TOOL_CONTRIBUTION_GATE=FAIL zero_refs={bad_zero_refs} absent_refs={bad_absent_refs}")
        return 1

    print("TOOL_CONTRIBUTION_GATE=PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
