#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# SIFT_CUSTOMER_TABLE_BUCKET_SECTION_GATE_V1E

SECTION_SPECS = [
    ("Actionable / Needs Review", ["confirmed_malicious_atomic", "suspicious_needs_review"]),
    ("Self-Correction / Inconclusive", ["inconclusive_unresolved"]),
    ("Narrative / Context", ["synthesis_narrative"]),
    ("Benign / False Positive", ["benign_or_false_positive"]),
]


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(errors="replace"))
    except Exception:
        return {}


def _ids_from_bucket(buckets: dict[str, Any], names: list[str]) -> list[str]:
    ids: list[str] = []
    for name in names:
        rows = buckets.get(name)
        if not isinstance(rows, list):
            continue
        for f in rows:
            if isinstance(f, dict):
                fid = str(f.get("finding_id") or f.get("id") or "").strip()
                if fid:
                    ids.append(fid)
    return ids


def _section_body(text: str, section: str) -> str:
    pat = re.compile(rf"^## {re.escape(section)}\s*$", re.M)
    m = pat.search(text)
    if not m:
        return ""
    start = m.end()
    m2 = re.search(r"^##\s+", text[start:], re.M)
    end = start + m2.start() if m2 else len(text)
    return text[start:end]


def _ids_from_table_section(text: str, section: str) -> list[str]:
    body = _section_body(text, section)
    ids: list[str] = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        parts = [p.strip().replace("\\|", "|") for p in line.strip().strip("|").split("|")]
        if len(parts) < 3:
            continue
        if parts[0] in {"#", "---:", "—"}:
            continue
        fid = parts[1]
        if re.match(r"^F\d+", fid) or fid.startswith("F_") or fid.startswith("FX"):
            ids.append(fid)
    return ids


def _write_repair(state: Path) -> Path:
    from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
        write_bucket_faithful_customer_findings_table,
    )
    return write_bucket_faithful_customer_findings_table(state)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_customer_table_bucket_section_gate.py <state_dir> [--repair]", file=sys.stderr)
        return 2

    state = Path(argv[1]).resolve()
    repair = "--repair" in argv[2:]

    table_path = state / "customer_findings_table.md"
    buckets_path = state / "finding_disposition_buckets.json"

    if repair:
        _write_repair(state)

    buckets = _load_json(buckets_path)
    if not isinstance(buckets, dict):
        buckets = {}

    text = table_path.read_text(errors="replace") if table_path.exists() else ""

    failures: list[str] = []
    expected_total = 0
    rendered_total = 0

    for section, bucket_names in SECTION_SPECS:
        expected = _ids_from_bucket(buckets, bucket_names)
        rendered = _ids_from_table_section(text, section)
        expected_total += len(expected)
        rendered_total += len(rendered)

        missing = sorted(set(expected) - set(rendered))
        extra = sorted(set(rendered) - set(expected))
        if missing:
            failures.append(f"{section}: missing ids {missing}")
        if extra:
            failures.append(f"{section}: extra ids {extra}")

    if "Confidence" in text or "Severity" in text:
        failures.append("customer table exposes forbidden confidence/severity wording")

    print("# Customer Table Bucket Section Gate")
    print()
    print(f"- state: `{state}`")
    print(f"- table: `{table_path}`")
    print(f"- expected_rows: `{expected_total}`")
    print(f"- rendered_rows: `{rendered_total}`")
    if repair:
        print("- repair: `attempted`")

    if failures:
        print()
        print("## Failures")
        for f in failures:
            print(f"- FAIL: {f}")
        print()
        print(f"CUSTOMER_TABLE_BUCKET_SECTION_GATE=FAIL state={state}")
        return 1

    print()
    print(f"CUSTOMER_TABLE_BUCKET_SECTION_GATE=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
