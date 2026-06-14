#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from sift_sentinel.analysis.tool_hit_integrity import (
    build_hit_maps,
    canonical_tool_name,
)

def load_json(path: Path):
    return json.loads(path.read_text(errors="ignore"))

def load_outputs(state: Path) -> dict:
    outputs = {}
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

def render_table(state: Path) -> str:
    from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table
    return render_customer_findings_table(state_dir=str(state))

def tools_hit_cells(markdown: str) -> list[str]:
    cells = []
    for line in markdown.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if "---" in line or "Tools Hit" in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            cells.append(parts[5])
    return cells

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_customer_table_zero_hit_tools_gate.py STATE_DIR")
        return 2

    state = Path(sys.argv[1])
    outputs = load_outputs(state)
    _hit_map, zero_map = build_hit_maps(outputs)
    zero_tools = sorted(canonical_tool_name(k) for k in zero_map)

    text = render_table(state)
    bad = []
    for row, cell in enumerate(tools_hit_cells(text), 1):
        for tool in zero_tools:
            if tool and tool in cell:
                bad.append({"row": row, "tool": tool, "tools_hit_cell": cell})

    if bad:
        print(f"CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE=FAIL bad_refs={len(bad)} state={state}")
        for item in bad[:40]:
            print(json.dumps(item, sort_keys=True))
        return 1

    print(
        f"CUSTOMER_TABLE_ZERO_HIT_TOOL_GATE=PASS "
        f"zero_or_nonhit_tools={len(zero_tools)} state={state}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

# SIFT_CUSTOMER_ZERO_HIT_GATE_STRICT_FINDINGS_V5
# Side-car audit files may contain removed raw refs for auditability.
# Customer/final finding files must not contain zero/non-hit tool names in active
# provenance or per-finding metadata. This override intentionally scans only
# customer-visible/finding JSONs, not repair sidecars.
