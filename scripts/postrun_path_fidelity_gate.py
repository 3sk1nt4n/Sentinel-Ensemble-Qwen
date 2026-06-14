#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# SIFT_POSTRUN_PATH_FIDELITY_RC_COMPAT_V3D
#
# Contract:
# - The authoritative path-fidelity implementation lives in check_path_fidelity_gate.py.
# - This legacy postrun wrapper preserves the historical stale-mount failure rc=2.
# - Output text is passed through unchanged so higher-level gates can still key on
#   PATH_FIDELITY_GATE=PASS / FAIL.
# - No dataset-specific paths are used here; the authoritative gate owns detection.

ROOT = Path(__file__).resolve().parents[1]
AUTHORITATIVE = ROOT / "scripts" / "check_path_fidelity_gate.py"


def main() -> int:
    if not AUTHORITATIVE.exists():
        print("PATH_FIDELITY_GATE=FAIL reason=authoritative_gate_missing")
        return 2

    proc = subprocess.run(
        [sys.executable, str(AUTHORITATIVE), *sys.argv[1:]],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    out = proc.stdout or ""
    if out:
        print(out, end="" if out.endswith("\n") else "\n")

    if proc.returncode == 0:
        return 0

    # Backward-compatible contract expected by existing P0 output truth tests.
    # A stale-path failure is still a path-fidelity failure, not an unexpected crash.
    if "PATH_FIDELITY_GATE=FAIL" in out:
        return 2

    return proc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
