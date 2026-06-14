#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

from sift_sentinel.reporting.customer_findings_table import render_customer_findings_table


def latest_state():
    states = [
        p
        for p in Path("/tmp").glob("sift-sentinel-run-*")
        if (p / "finding_disposition_buckets.json").exists()
    ]
    if not states:
        return None
    return max(states, key=lambda p: p.stat().st_mtime)


def section(text, name):
    needle = f"## {name}"
    if needle not in text:
        return ""
    start = text.index(needle)
    rest = text[start + len(needle) :]
    next_pos = rest.find("\n## ")
    return rest[:next_pos] if next_pos >= 0 else rest


def ids_in_section(text, name):
    body = section(text, name)
    return re.findall(r"\|\s*\d+\s*\|\s*(F\d+)\s*\|", body)


def main(argv):
    if len(argv) > 1:
        state = Path(argv[1])
    else:
        state = latest_state()

    if not state:
        print("CUSTOMER_TABLE_TRUTH_GATE=SKIP no state")
        return 0

    path = state / "finding_disposition_buckets.json"
    if not path.exists():
        print(f"CUSTOMER_TABLE_TRUTH_GATE=SKIP no buckets path={path}")
        return 0

    buckets = json.loads(path.read_text(errors="replace"))
    text = render_customer_findings_table({"finding_disposition_buckets": buckets})

    problems = []
    if "Severity" in text or "Confidence" in text:
        problems.append("legacy_severity_or_confidence_header")

    actionable = section(text, "Actionable / Needs Review")
    if "Summary:" in actionable and len(buckets.get("confirmed_malicious_atomic") or []) == 0:
        problems.append("summary_synthesis_in_actionable_without_confirmed_atomic")

    # Benign/FP section must be last when present.
    fp_pos = text.find("## Benign / False Positive")
    sc_pos = text.find("## Self-Correction / Inconclusive")
    if fp_pos >= 0 and sc_pos >= 0 and fp_pos < sc_pos:
        problems.append("fp_section_not_last")

    print("state_dir=", state)
    print("actionable_ids=", ids_in_section(text, "Actionable / Needs Review"))
    print("narrative_ids=", ids_in_section(text, "Narrative / Context"))
    print("sc_ids=", ids_in_section(text, "Self-Correction / Inconclusive"))
    print("fp_ids_count=", len(ids_in_section(text, "Benign / False Positive")))
    print("render_chars=", len(text))

    if problems:
        print("CUSTOMER_TABLE_TRUTH_GATE=FAIL", problems)
        print(text[:5000])
        return 1

    print("CUSTOMER_TABLE_TRUTH_GATE=PASS")
    print(text[:2500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
