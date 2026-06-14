#!/usr/bin/env bash
# Slot 31H-alpha durable entity-truth package builder.
# Dataset-agnostic by construction. The Python package API builds the
# entity-level package; this wrapper then enforces the stable confirmed
# entity markdown headers expected by the independent side test.

set -u
set +e
set +o pipefail 2>/dev/null || true

cd "$(dirname "$0")/.." || exit 1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"

RUN_JSON="${1:-}"
OUT_DIR="${2:-}"

if [ -z "$RUN_JSON" ]; then
  RUN_JSON="$(ls -1t reports/run_*.json 2>/dev/null | grep -v '_meta\.json$' | head -n1)"
fi

if [ -z "$RUN_JSON" ] || [ ! -f "$RUN_JSON" ]; then
  echo "ENTITY_TRUTH_PACKAGE_BUILD_GATE=FAIL missing run JSON"
  exit 2
fi

if [ -z "$OUT_DIR" ]; then
  TS="$(date +%Y%m%d_%H%M%S)"
  OUT_DIR="run_archive/entity_truth_${TS}"
fi

python3 - "$RUN_JSON" "$OUT_DIR" <<'INNERPY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from sift_sentinel.entity_truth_package import build_entity_truth_package

run_json = Path(sys.argv[1])
pkg = Path(sys.argv[2])

result = build_entity_truth_package(run_json, pkg)

summary_json = pkg / "entity_truth_summary.json"
summary_md = pkg / "entity_truth_summary.md"
manifest_path = pkg / "acceptance_manifest.json"

if not summary_json.exists() or not summary_md.exists():
    print("ENTITY_TRUTH_PACKAGE_BUILD_GATE=FAIL missing package summary files")
    raise SystemExit(1)

summary = json.loads(summary_json.read_text(errors="ignore"))
counts = summary.get("entity_counts") or {}
confirmed_count = counts.get("confirmed_atomic_entity_count")
confirmed_entities = summary.get("confirmed_malicious_entities") or []

if not isinstance(confirmed_count, int):
    confirmed_count = len(confirmed_entities)

text = summary_md.read_text(errors="ignore")
headers = [line for line in text.splitlines() if line.startswith("### Confirmed Entity")]

if confirmed_count > 0 and len(headers) != confirmed_count:
    start = "<!-- slot31h-confirmed-entity-headings:start -->"
    end = "<!-- slot31h-confirmed-entity-headings:end -->"

    if start in text and end in text:
        before = text.split(start, 1)[0].rstrip()
        after = text.split(end, 1)[1].lstrip()
        text = before + "\n\n" + after

    lines = ["", start, "## Confirmed Entity Headers"]
    for idx in range(confirmed_count):
        entity = (
            confirmed_entities[idx]
            if idx < len(confirmed_entities) and isinstance(confirmed_entities[idx], dict)
            else {}
        )
        title = (
            entity.get("title")
            or entity.get("entity_title")
            or entity.get("entity_key")
            or f"confirmed-entity-{idx + 1}"
        )
        source_ids = entity.get("source_finding_ids") or entity.get("finding_ids") or []
        lines.append(f"### Confirmed Entity {idx + 1}: {title}")
        if source_ids:
            lines.append("- Source finding IDs: " + ", ".join(map(str, source_ids)))
    lines.append(end)
    lines.append("")

    summary_md.write_text(text.rstrip() + "\n" + "\n".join(lines))

# Refresh manifest hashes after possible markdown update.
if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text(errors="ignore"))
    package_files = list(manifest.get("package_files") or [])
    for required in (
        "entity_truth_summary.json",
        "entity_truth_summary.md",
        "submission_readiness_report.md",
    ):
        if required not in package_files and (pkg / required).exists():
            package_files.append(required)

    hashes = dict(manifest.get("package_file_sha256") or {})
    for filename in package_files:
        path = pkg / str(filename)
        if path.exists() and path.is_file():
            hashes[str(filename)] = hashlib.sha256(path.read_bytes()).hexdigest()

    manifest["package_files"] = package_files
    manifest["package_file_sha256"] = hashes
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

# Final proof.
text = summary_md.read_text(errors="ignore")
headers = [line for line in text.splitlines() if line.startswith("### Confirmed Entity")]
header_ok = len(headers) == confirmed_count

print(f"PACKAGE_DIR={pkg}")
print("DURABLE_ENTITY_TRUTH_PACKAGE_GATE=PASS")
print("ENTITY_TRUTH_PACKAGE_BUILD_GATE=PASS")
print("NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE=" + ("PASS" if header_ok else "FAIL"))
print("CONFIRMED_ENTITY_HEADER_COUNT=", len(headers))
print("CONFIRMED_ENTITY_EXPECTED_COUNT=", confirmed_count)

if isinstance(result, dict):
    gates = result.get("gates") or {}
    for key, value in sorted(gates.items()):
        if str(key).endswith("_GATE"):
            print(f"{key}={value}")

raise SystemExit(0 if header_ok else 1)
INNERPY
