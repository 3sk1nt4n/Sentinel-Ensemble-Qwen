#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# SIFT_OUTPUT_TRUTH_NOOP_GATE_V1
#
# Fresh pipeline outputs must already be clean. Repairs are allowed as migration
# tools, but a fresh successful run should not need mutation.

IGNORE_NAMES = {
    ".evidence_hash",
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_files(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        if p.name in IGNORE_NAMES:
            continue
        out[rel] = sha(p)
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_output_truth_noop_gate.py STATE")
        return 2

    state = Path(argv[1]).resolve()
    if not state.exists():
        print(f"OUTPUT_TRUTH_NOOP_GATE=FAIL state={state} reason=missing_state")
        return 1

    before = snapshot_files(state)

    with tempfile.TemporaryDirectory(prefix="sift-output-truth-noop-") as td:
        tmp = Path(td) / "state"
        shutil.copytree(state, tmp, symlinks=True)

        cmd = [
            sys.executable,
            "scripts/check_output_truth_gates.py",
            str(tmp),
            "--repair",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True)

        after = snapshot_files(tmp)
        changed = sorted(
            rel for rel in set(before) | set(after)
            if before.get(rel) != after.get(rel)
        )

        print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)

        if proc.returncode != 0:
            print(f"OUTPUT_TRUTH_NOOP_GATE=FAIL state={state} reason=truth_gates_failed rc={proc.returncode}")
            return 1

        if changed:
            print(f"OUTPUT_TRUTH_NOOP_GATE=FAIL state={state} changed_files={len(changed)}")
            for rel in changed[:40]:
                print(f"  changed={rel}")
            return 1

    print(f"OUTPUT_TRUTH_NOOP_GATE=PASS state={state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
